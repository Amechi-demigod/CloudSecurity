"""Missing-device mode (docs/DEVICE_TRACKING.md#missing-device-mode).

An admin marks a Windows / macOS laptop or desktop as missing: the device turns on Lost mode (reusing the existing
`enable_lost_mode` command) and checks in every 5 minutes, so every change of internet address (city level) is
recorded by device tracking. "Mark as recovered" clears the flag, restores the check-in interval and can exit Lost
mode. Nothing here reads a device's GPS, camera, screen or Wi-Fi: the only location is the public IP address.

This module imports `service` (tracking) lazily: service.observe() calls into it.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AuditLog, Device, DeviceCommand, User, utcnow
from .models import DeviceLocation, TrackingOffice

log = logging.getLogger(__name__)

MISSING_CHECK_IN_SECONDS = 300
OFFLINE_ALERT_AFTER = timedelta(minutes=60)
LOCATIONS_LIMIT = 500  # sightings shown / printed (newest first when more exist)


class MissingError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def is_missing(device: Device) -> bool:
    return device.missing_since is not None and device.missing_recovered_at is None


def actor_label(user: User) -> str:
    """The name shown for who acted. MSP staff working inside a client arrive as a stand-in user whose name is
    "Managed security team" (app/auth.py), so the real person never appears in the client's console or report."""
    return (user.name or user.email or "")[:320]


# ----------------------------------------------------------------------------- hardware
def hardware_snapshot(device: Device) -> dict[str, Any]:
    inv = device.inventory or {}
    disks = [d.get("size_bytes") for d in (inv.get("disks") or []) if isinstance(d, dict)]
    return {"serial_number": device.serial_number or "", "manufacturer": device.manufacturer or "",
            "model": device.model or "", "cpu": inv.get("cpu") or "", "memory_bytes": inv.get("memory_bytes"),
            "disks": sorted(x for x in disks if isinstance(x, int))}


_HW_LABELS = {"serial_number": "serial number", "manufacturer": "manufacturer", "model": "model",
              "cpu": "processor", "memory_bytes": "memory", "disks": "disks"}


def hardware_changes(device: Device) -> list[str] | None:
    """What differs from the hardware seen when it was marked missing; None when there is nothing to compare."""
    base = device.missing_baseline
    if not isinstance(base, dict) or not base:
        return None
    now = hardware_snapshot(device)
    return [_HW_LABELS[k] for k in _HW_LABELS if k in base and base[k] != now[k]]


# ----------------------------------------------------------------------------- reconnect + sightings hooks
def on_contact(db: Session, device: Device, now: datetime) -> None:
    """Called for every check-in / command poll (tracking.service.observe). While the device is missing, notes the
    contact and raises ONE alert when it connects again after more than an hour offline. Never raises."""
    try:
        if not is_missing(device):
            return
        prev = device.missing_last_contact_at or device.missing_since
        device.missing_last_contact_at = now
        if prev is not None and now - prev > OFFLINE_ALERT_AFTER:
            _notify_online(db, device, now, now - prev)
    except Exception:
        log.exception("missing-device contact handling failed for %s (ignored)", getattr(device, "id", "?"))


def stamp_signed_in(db: Session, device: Device) -> None:
    """Remember who is signed in (latest check-in data) on the newest sighting; only while the device is missing."""
    try:
        if not is_missing(device) or not device.location_id:
            return
        loc = db.get(DeviceLocation, device.location_id)
        users = [str(u) for u in ((device.inventory or {}).get("logged_in_users") or [])][:5]
        if loc is not None and users:
            loc.signed_in = ", ".join(users)[:255]
    except Exception:
        log.exception("stamping the signed-in user failed for %s (ignored)", getattr(device, "id", "?"))


def _notify_online(db: Session, device: Device, now: datetime, offline: timedelta) -> None:
    from ..notifications import device_source
    from ..notifications.events import Event, emit

    place = ""
    loc = db.get(DeviceLocation, device.location_id) if device.location_id else None
    if loc is not None and (loc.city or loc.country):
        place = f" Approximate area: {', '.join(x for x in (loc.city, loc.country) if x)}."
    hours = offline.total_seconds() / 3600
    away = f"{hours:.1f} hours" if hours < 48 else f"{hours / 24:.1f} days"
    emit(db, Event(
        source=device_source.DEVICE, event_type=device_source.MISSING_DEVICE_ONLINE, severity="high",
        title=f"Missing device {device.hostname} is online again",
        summary=f"It was offline for {away} and has just connected.{place}",
        entity_id=device.id, group_key=f"{device_source.DEVICE}:{device.id}:missing_online:{now:%Y%m%d%H%M%S}",
        rule_id=device_source.MISSING_DEVICE_ONLINE, link_path=device_source._link(device.id),
        attributes=device_source._attrs(device, offline_seconds=int(offline.total_seconds()),
                                        missing_since=device.missing_since.isoformat() + "Z"
                                        if device.missing_since else None)))


# ----------------------------------------------------------------------------- mark / recover
def _new_command(db, device, user, cmd_type, params, reason, ip):
    from ..auth import audit
    from ..services import devices as svc

    cmd = svc.new_command(db, device, cmd_type, params, reason, requested_by_id=user.id,
                          requested_by_email=user.email)
    audit(db, "device_command_created", actor=user, target=f"device:{device.id}", ip=ip, hostname=device.hostname,
          command_id=cmd.id, type=cmd.type, params=params, reason=reason, via="missing_device")
    return cmd


def mark(db: Session, device: Device, user: User, *, reason: str, confirm_hostname: str, message: str | None,
         phone: str | None, ip: str | None) -> dict[str, Any]:
    """Mark `device` missing (admin; the caller commits). Raises MissingError."""
    from ..auth import audit
    from ..services import devices as svc
    from . import service

    if device.os_family == "linux" or not service.qualifies(device):
        raise MissingError(409, "missing-device mode is for Windows and macOS laptops and desktops only "
                                "(not Linux machines, servers or domain controllers)")
    st = service.get_settings(db, create=False)
    if not (st and st.enabled):
        raise MissingError(409, "device tracking is off: turn it on in Settings > Device tracking first")
    if is_missing(device):
        raise MissingError(409, "this device is already marked missing")
    if (confirm_hostname or "").strip().lower() != device.hostname.lower():
        raise MissingError(422, f"type the device name ({device.hostname}) to confirm")
    if device.wipe_status in svc.WIPE_PENDING_STATES:
        raise MissingError(409, "a remote wipe of this device is in progress")
    if device.lost_mode_status in ("enabling", "disabling"):
        raise MissingError(409, f"lost mode is already {device.lost_mode_status}; wait for the device or cancel "
                                "the pending command")
    now = utcnow()
    lost_params = None
    lost_note = None
    if device.lost_mode_status is not None:
        lost_note = "already_on"
    elif device.isolation_status is not None:
        lost_note = "sign_in_suspended"  # lost mode and suspended sign-in cannot run together
    else:
        try:
            lost_params = svc.validate_params("enable_lost_mode", {"message": message or "", "phone": phone or ""})
        except ValueError as e:
            raise MissingError(422, str(e)) from None
    note = f"Missing device: {reason}"[:500]
    cmds: dict[str, str] = {}
    if lost_params is not None:
        cmds["lost_mode"] = _new_command(db, device, user, "enable_lost_mode", lost_params, note, ip).id
    previous = device.check_in_interval_seconds
    if previous != MISSING_CHECK_IN_SECONDS:
        cmds["interval"] = _new_command(db, device, user, "update_check_in_interval",
                                        {"interval_seconds": MISSING_CHECK_IN_SECONDS}, note, ip).id
    device.missing_since, device.missing_by_id, device.missing_by_label = now, user.id, actor_label(user)
    device.missing_reason, device.missing_previous_check_in_seconds = reason, previous
    device.missing_recovered_at = device.missing_recovered_by_id = device.missing_recovered_by_label = None
    device.missing_last_contact_at = now
    device.missing_baseline = hardware_snapshot(device)
    audit(db, "device_missing_marked", actor=user, target=f"device:{device.id}", ip=ip, hostname=device.hostname,
          reason=reason, lost_mode=lost_note or "queued", commands=cmds, previous_interval_seconds=previous)
    return {"lost_mode_action": lost_note or "queued", "commands": cmds}


def recover(db: Session, device: Device, user: User, *, exit_lost_mode: bool, ip: str | None) -> dict[str, Any]:
    """Mark `device` recovered (admin; the caller commits): restore the interval, optionally exit Lost mode."""
    from ..auth import audit
    from ..services import devices as svc

    if not is_missing(device):
        raise MissingError(409, "this device is not marked missing")
    now = utcnow()
    cmds: dict[str, str] = {}
    # Interval: drop a still-pending change to 5 minutes, else queue the previous value back.
    for c in db.scalars(select(DeviceCommand).where(
            DeviceCommand.device_id == device.id, DeviceCommand.status == "pending",
            DeviceCommand.type == "update_check_in_interval")):
        c.status, c.completed_at, c.output = "cancelled", now, f"cancelled: device recovered ({actor_label(user)})"
    prev = device.missing_previous_check_in_seconds
    interval = "unchanged"
    if prev is not None and prev != device.check_in_interval_seconds:
        cmds["interval"] = _new_command(db, device, user, "update_check_in_interval", {"interval_seconds": prev},
                                        "Device recovered: restore the check-in interval", ip).id
        interval = "restore_queued"
    lost = "kept" if not exit_lost_mode else "not_on"
    if exit_lost_mode:
        status = device.lost_mode_status
        if status == "active":
            cmds["lost_mode"] = _new_command(db, device, user, "disable_lost_mode", {},
                                             "Device recovered: exit lost mode", ip).id
            lost = "exit_queued"
        elif status == "enabling":
            pending = db.scalar(select(DeviceCommand).where(
                DeviceCommand.device_id == device.id, DeviceCommand.type == "enable_lost_mode",
                DeviceCommand.status == "pending").order_by(DeviceCommand.created_at.desc()).limit(1))
            if pending is not None:  # never delivered: just cancel it
                pending.status, pending.completed_at = "cancelled", now
                pending.output = f"cancelled: device recovered ({actor_label(user)})"
                svc.command_finished(device, pending)
                lost = "cancelled"
            else:
                lost = "still_enabling"  # the device is turning it on now: exit it from the device page afterwards
        elif status == "disabling":
            lost = "already_exiting"
    device.missing_recovered_at, device.missing_recovered_by_id = now, user.id
    device.missing_recovered_by_label = actor_label(user)
    audit(db, "device_missing_recovered", actor=user, target=f"device:{device.id}", ip=ip, hostname=device.hostname,
          lost_mode=lost, interval=interval, commands=cmds, missing_since=device.missing_since.isoformat() + "Z")
    return {"lost_mode_action": lost, "interval_action": interval, "commands": cmds}


# ----------------------------------------------------------------------------- views
def _zone(name: str):
    try:
        return ZoneInfo(name)
    except Exception:
        return ZoneInfo("UTC")


def sightings(db: Session, device: Device, *, full: bool) -> list[dict[str, Any]]:
    """Every location row seen since the device went missing (until it was recovered), oldest first."""
    from . import service

    if device.missing_since is None:
        return []
    offices = {o.id: o for o in service.offices(db)}
    stmt = (select(DeviceLocation).where(DeviceLocation.device_id == device.id,
                                         DeviceLocation.last_seen_at >= device.missing_since)
            .order_by(DeviceLocation.first_seen_at).limit(LOCATIONS_LIMIT))
    out = []
    end = device.missing_recovered_at
    for r in db.scalars(stmt):
        if end is not None and r.first_seen_at > end:
            continue
        office = offices.get(r.office_id) if r.office_id else None
        row = {"when": max(r.first_seen_at, device.missing_since), "last_seen_at": r.last_seen_at,
               "city": r.city, "country": r.country, "country_code": r.country_code, "is_private": r.is_private,
               "office": office.name if office else None, "timezone": service.effective_timezone(db, office),
               "signed_in": r.signed_in}
        if full:
            row.update(ip=r.ip, provider=r.provider, region=r.region)
        out.append(row)
    return out


def info(device: Device) -> dict[str, Any]:
    return {"missing": is_missing(device), "since": device.missing_since, "by": device.missing_by_label,
            "reason": device.missing_reason, "recovered_at": device.missing_recovered_at,
            "recovered_by": device.missing_recovered_by_label,
            "check_in_seconds": MISSING_CHECK_IN_SECONDS if is_missing(device) else None,
            "previous_check_in_seconds": device.missing_previous_check_in_seconds}


def view(db: Session, device: Device, *, full: bool) -> dict[str, Any]:
    """The device page's missing panel. `full`=False (viewers): city and country only, no address or provider."""
    from . import service
    from .service import qualifies

    st = service.get_settings(db, create=False)
    out: dict[str, Any] = {**info(device), "eligible": qualifies(device), "tracking_enabled": bool(st and st.enabled),
                           "detail": "full" if full else "basic", "timezone": st.timezone if st else "UTC",
                           "lost_mode": {"status": device.lost_mode_status, "message": device.lost_mode_message,
                                         "phone": device.lost_mode_phone},
                           "sightings": [], "last_seen": None, "hardware_changes": None}
    if device.missing_since is None:
        return out
    out["sightings"] = sightings(db, device, full=full)
    loc = db.get(DeviceLocation, device.location_id) if device.location_id else None
    if loc is not None:
        office = db.get(TrackingOffice, loc.office_id) if loc.office_id else None
        last = {"when": loc.last_seen_at, "city": loc.city, "country": loc.country, "is_private": loc.is_private,
                "office": office.name if office else None, "timezone": service.effective_timezone(db, office)}
        if full:
            last.update(provider=loc.provider, ip=loc.ip, region=loc.region)
        out["last_seen"] = last
    out["hardware_changes"] = hardware_changes(device)
    return out


# ----------------------------------------------------------------------------- report data
ACTION_LABELS = {"enable_lost_mode": "Lost mode turned on", "disable_lost_mode": "Lost mode exit requested",
                 "isolate_host": "Sign-in suspended", "restore_host": "Sign-in restored",
                 "lock_device": "Device locked"}
APPROVAL_LABELS = {"device_approval_requested": "requested", "device_approval_approved": "approved",
                   "device_approval_rejected": "rejected", "device_approval_cancelled": "cancelled",
                   "device_approval_expired": "expired", "device_approval_failed": "failed"}


def actions_since(db: Session, device: Device) -> list[dict[str, Any]]:
    """What was done to the device since it was marked missing, from the audit log (oldest first)."""
    if device.missing_since is None:
        return []
    rows = db.scalars(select(AuditLog).where(AuditLog.target == f"device:{device.id}",
                                             AuditLog.timestamp >= device.missing_since - timedelta(seconds=2))
                      .order_by(AuditLog.id).limit(1000))
    out: list[dict[str, Any]] = []
    for a in rows:
        d = a.detail or {}
        if a.via_partner_org_id:
            who = "Managed security team"
        else:
            who = a.actor_email or "system"
        label = None
        if a.action == "device_missing_marked":
            label = "Marked as missing"
        elif a.action == "device_missing_recovered":
            label = "Marked as recovered"
        elif a.action == "device_command_created" and d.get("type") in ACTION_LABELS:
            label = ACTION_LABELS[d["type"]]
            if d.get("via") == "missing_device" and d["type"] == "enable_lost_mode":
                label += " (with missing mode)"
        elif a.action in APPROVAL_LABELS and d.get("requested_action") == "wipe_device":
            label = f"Remote wipe {APPROVAL_LABELS[a.action]}"
        elif a.action in ("host_isolation_requested", "host_restore_requested"):
            continue  # the matching device_command_created row says it
        if label:
            out.append({"at": a.timestamp, "action": label, "by": who, "reason": d.get("reason")})
    return out


def report_data(db: Session, device: Device, *, org_name: str, generated_at: datetime) -> dict[str, Any]:
    """Everything the PDF prints (analyst / admin: addresses and providers included)."""
    from . import service

    if device.missing_since is None:
        raise MissingError(409, "this device has never been marked missing")
    st = service.get_settings(db, create=False)
    inv = device.inventory or {}
    return {
        "organization": org_name, "generated_at": generated_at, "timezone": st.timezone if st else "UTC",
        "device": {"hostname": device.hostname, "serial_number": device.serial_number, "manufacturer": device.manufacturer,
                   "model": device.model, "os": f"{device.os_name or ''} {device.os_version or ''}".strip(),
                   "os_family": device.os_family, "agent_version": device.agent_version,
                   "last_check_in": device.last_checkin_at,
                   "owner": ", ".join(str(u) for u in (inv.get("logged_in_users") or [])[:5]) or None},
        "missing": info(device), "lost_mode": {"status": device.lost_mode_status, "phone": device.lost_mode_phone},
        "sightings": sightings(db, device, full=True), "actions": actions_since(db, device),
        "hardware_changes": hardware_changes(device),
    }
