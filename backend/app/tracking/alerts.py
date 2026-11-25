"""Device tracking alerts (docs/DEVICE_TRACKING.md#alerts).

Event driven (from `service.observe`, on every check-in and command poll): outside allowed countries, away from
offices after hours, hardware changed, automatic lost mode, and the bookkeeping the agent-stopped alert needs.
Time driven (`worker.TrackingAlertWorker`, leader-elected): not seen for N days, agent stopped.

Every alert: is controlled by its stored toggle, runs only while tracking is on and the organisation has the
Endpoints & servers module, is tenant scoped (the session's organisation), fires once per occurrence, is rate
limited, writes a row into the device's location history and queues a notification (source "device_tracking").
Nothing here may fail a check-in: callers wrap everything in try/except.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .. import config, modules
from ..auth import audit
from ..models import Device, utcnow
from ..notifications import device_tracking_source as notes
from ..services import devices as dev_svc
from . import service
from .alert_models import DeviceTrackingEvent, DeviceTrackingState
from .models import DeviceLocation, DeviceTrackingSettings

log = logging.getLogger(__name__)

KIND_LABELS = {
    "outside_countries": "Outside allowed countries", "not_seen": "Not seen for days",
    "after_hours": "Away from offices after hours", "hardware_changed": "Hardware changed",
    "agent_stopped": "Agent stopped", "auto_lost_mode": "Locked automatically (lost mode)"}
# Minimum time between two alerts of one kind for one device (rate limit on top of the once-per-occurrence rule).
MIN_GAP = {"outside_countries": timedelta(hours=6), "not_seen": timedelta(hours=12), "after_hours": timedelta(hours=12),
           "hardware_changed": timedelta(hours=1), "agent_stopped": timedelta(hours=6),
           "auto_lost_mode": timedelta(hours=1)}
MAX_ALERTS_PER_ORG_HOUR = 100  # a flood guard (e.g. a whole fleet going quiet at once): the rest is dropped
REGULAR_POLL_GAP = timedelta(seconds=180)  # the agent polls about every 60 s
REGULAR_POLLS_NEEDED = 5
AGENT_STOPPED_AFTER = timedelta(hours=2)
FORGET_AFTER = timedelta(days=180)  # devices quiet for longer are not alerted on (retired machines)
STOPPED_WINDOW = timedelta(days=30)
DISK_STABLE_AFTER = timedelta(hours=24)  # a disk seen for less than this (a USB stick) is not "removed" later
DISK_RESIZE_TOLERANCE = 0.05
AUTO_LOST_MESSAGE = ("This computer was locked automatically because it connected from outside the countries your "
                     "organisation allows. Please contact your IT team.")
AUTO_LOST_REASON = "Automatic: outside allowed countries"
AUTO_LOST_ACTOR = "Automatic: device tracking"


# ----------------------------------------------------------------------------- helpers
def alerts_active(db: Session, st: DeviceTrackingSettings | None) -> bool:
    return bool(st and st.enabled and modules.has_module(db, modules.ENDPOINTS, st.organization_id))


def any_alert_on(st: DeviceTrackingSettings) -> bool:
    return bool(st.alert_outside_countries or st.alert_not_seen_days or st.alert_after_hours
                or st.alert_hardware_changed or st.alert_agent_stopped or st.auto_lost_mode_outside_countries)


def get_state(db: Session, device: Device, create: bool = True) -> DeviceTrackingState | None:
    row = db.get(DeviceTrackingState, device.id)
    if row is None and create:
        row = DeviceTrackingState(device_id=device.id, organization_id=device.organization_id, regular_polls=0)
        db.add(row)
        db.flush()
    return row


def place(city: str | None, country: str | None) -> str:
    return ", ".join(x for x in (city, country) if x) or "an unknown place"


def outside_allowed(st: DeviceTrackingSettings, loc: DeviceLocation | None) -> bool:
    """The location's country is known, not an office, and not in the (non-empty) allowed list."""
    return bool(loc is not None and st.allowed_countries and loc.country_code and not loc.is_private
                and not loc.office_id and loc.country_code not in st.allowed_countries)


def raise_alert(db: Session, device: Device, kind: str, title: str, now: datetime, *, summary: str = "",
                loc: DeviceLocation | None = None) -> bool:
    """Write the history event and queue the notification, unless rate limited. True when raised."""
    since = now - MIN_GAP[kind]
    if db.scalar(select(func.count(DeviceTrackingEvent.id)).where(
            DeviceTrackingEvent.device_id == device.id, DeviceTrackingEvent.kind == kind,
            DeviceTrackingEvent.at >= since)):
        return False
    if (db.scalar(select(func.count(DeviceTrackingEvent.id)).where(
            DeviceTrackingEvent.at >= now - timedelta(hours=1))) or 0) >= MAX_ALERTS_PER_ORG_HOUR:
        log.warning("device tracking alert rate limit reached for organisation %s", device.organization_id)
        return False
    sev = notes.SEVERITY[kind]
    db.add(DeviceTrackingEvent(device_id=device.id, organization_id=device.organization_id, at=now, kind=kind,
                               severity=sev, title=title[:255], city=loc.city if loc else None,
                               country_code=loc.country_code if loc else None, country=loc.country if loc else None))
    notes.notify(db, device, kind, title, summary, city=loc.city if loc else None,
                 country=loc.country if loc else None)
    return True


# ----------------------------------------------------------------------------- after hours
def _hhmm(text: str):
    h, m = text.split(":")
    return int(h), int(m)


def night_key(now: datetime, tz_name: str, start: str, end: str, weekdays: list[int]) -> str | None:
    """The night (its starting date, in `tz_name`) `now` falls in, or None outside the window / on other weekdays.
    A window like 19:00-07:00 crosses midnight; the night belongs to the day it started on."""
    try:
        local = now.replace(tzinfo=UTC).astimezone(ZoneInfo(tz_name))
    except Exception:
        local = now.replace(tzinfo=UTC)
    t, s, e = (local.hour, local.minute), _hhmm(start), _hhmm(end)
    day = local.date()
    if s == e:
        return None
    if s < e:
        if not s <= t < e:
            return None
    elif t >= s:
        pass
    elif t < e:
        day = day - timedelta(days=1)
    else:
        return None
    return day.isoformat() if day.weekday() in (weekdays or []) else None


def after_hours_zone(db: Session, device: Device) -> str:
    """The time zone of the last office the device was at, else the organisation's."""
    office_id = db.scalar(select(DeviceLocation.office_id).where(
        DeviceLocation.device_id == device.id, DeviceLocation.office_id.is_not(None))
        .order_by(DeviceLocation.last_seen_at.desc()).limit(1))
    office = next((o for o in service.offices(db) if o.id == office_id), None) if office_id else None
    return service.effective_timezone(db, office)


def _check_after_hours(db: Session, device: Device, st: DeviceTrackingSettings, state: DeviceTrackingState,
                       cur: DeviceLocation | None, now: datetime) -> None:
    if not st.alert_after_hours or cur is None or cur.office_id or cur.is_private:
        return
    night = night_key(now, after_hours_zone(db, device), st.after_hours_start, st.after_hours_end,
                      st.after_hours_weekdays or [])
    if night is None or state.after_hours_night == night:
        return
    state.after_hours_night = night
    raise_alert(db, device, "after_hours", f"{device.hostname} is away from offices after hours "
                                           f"({place(cur.city, cur.country)})", now, loc=cur)


# ----------------------------------------------------------------------------- hardware
def hardware_snapshot(device: Device, now: datetime, previous: dict | None) -> dict[str, Any]:
    """What the agent reports that identifies the machine: serial number, system maker / model, memory, disks.
    (The agent does not report the motherboard; maker + model stand in for it.) Disks keep the time they were
    first seen so a USB stick is never reported as a removed disk."""
    inv = device.inventory or {}
    old_disks = (previous or {}).get("disks") or {}
    disks: dict[str, dict[str, Any]] = {}
    for d in inv.get("disks") or []:
        mount, size = d.get("mount"), d.get("size_bytes")
        if not mount or not size:
            continue
        disks[mount] = {"size": size, "since": (old_disks.get(mount) or {}).get("since") or now.isoformat()}
    return {"serial": (device.serial_number or "").strip(), "maker": (device.manufacturer or "").strip(),
            "model": (device.model or "").strip(), "memory": inv.get("memory_bytes") or None, "disks": disks}


def _gb(n: int) -> str:
    return f"{n / 1024 ** 3:.0f} GB"


def hardware_changes(old: dict, new: dict, now: datetime) -> list[str]:
    out: list[str] = []
    if old.get("serial") and new["serial"] and old["serial"] != new["serial"]:
        out.append("serial number changed")
    if (old.get("maker") and new["maker"] and old["maker"] != new["maker"]) or (
            old.get("model") and new["model"] and old["model"] != new["model"]):
        out.append("system maker or model changed")
    if old.get("memory") and new["memory"] and new["memory"] < old["memory"]:
        out.append(f"memory decreased ({_gb(old['memory'])} to {_gb(new['memory'])})")
    for mount, o in (old.get("disks") or {}).items():
        n = new["disks"].get(mount)
        if n is None:
            since = datetime.fromisoformat(o["since"]) if o.get("since") else now
            if now - since >= DISK_STABLE_AFTER:
                out.append(f"disk {mount} removed")
        elif abs(n["size"] - o["size"]) > DISK_RESIZE_TOLERANCE * o["size"]:
            out.append(f"disk {mount} size changed ({_gb(o['size'])} to {_gb(n['size'])})")
    return out


def _check_hardware(db: Session, device: Device, state: DeviceTrackingState, now: datetime) -> None:
    new = hardware_snapshot(device, now, state.hardware)
    old = state.hardware
    if old is not None:
        changes = hardware_changes(old, new, now)
        if changes:
            raise_alert(db, device, "hardware_changed", f"{device.hostname}: {'; '.join(changes)}"[:255], now,
                        summary="; ".join(changes))
    if new != old:
        state.hardware = new


# ----------------------------------------------------------------------------- automatic lost mode
def _auto_lost_mode(db: Session, device: Device, st: DeviceTrackingSettings, state: DeviceTrackingState,
                    cur: DeviceLocation, now: datetime) -> None:
    """Queue the existing enable_lost_mode command (never a wipe) once; skipped while lost mode is on, being
    turned on, or a wipe is pending. A person turning it off clears the way for the next trip outside."""
    if not (st.auto_lost_mode_outside_countries and st.auto_lost_mode_phone):
        return
    if device.status != "active" or device.lost_mode_status is not None \
            or device.wipe_status in dev_svc.WIPE_PENDING_STATES:
        return
    params = {"message": AUTO_LOST_MESSAGE, "phone": st.auto_lost_mode_phone}
    cmd = dev_svc.new_command(db, device, "enable_lost_mode", params, AUTO_LOST_REASON, requested_by_id=None,
                              requested_by_email=AUTO_LOST_ACTOR,
                              ttl=timedelta(hours=config.settings.device_command_ttl_hours))
    state.auto_lost_at = now
    audit(db, "device_command_created", actor_email=AUTO_LOST_ACTOR, target=f"device:{device.id}",
          hostname=device.hostname, command_id=cmd.id, type=cmd.type, params=params, reason=AUTO_LOST_REASON,
          automatic=True)
    raise_alert(db, device, "auto_lost_mode", f"{device.hostname} was locked automatically (lost mode): "
                                              f"connected from {place(cur.city, cur.country)}", now, loc=cur)


# ----------------------------------------------------------------------------- entry point from service.observe
def on_observe(db: Session, device: Device, st: DeviceTrackingSettings, prev: DeviceLocation | None,
               cur: DeviceLocation | None, changed: bool, now: datetime) -> None:
    """Called after the location was recorded (tracking on, module on, device qualifies)."""
    if not any_alert_on(st):
        return
    state = get_state(db, device)
    if st.alert_agent_stopped:
        gap = (now - state.last_obs_at) if state.last_obs_at else None
        state.regular_polls = min((state.regular_polls or 0) + 1, 1000) if gap is not None and gap <= REGULAR_POLL_GAP \
            else 0
        state.last_obs_at = now
    if cur is None:
        return
    if changed and outside_allowed(st, cur) and (prev is None or prev.country_code != cur.country_code):
        if st.alert_outside_countries:
            raise_alert(db, device, "outside_countries",
                        f"{device.hostname} connected from {place(cur.city, cur.country)}", now, loc=cur)
        _auto_lost_mode(db, device, st, state, cur, now)
    _check_after_hours(db, device, st, state, cur, now)
    if st.alert_hardware_changed:
        _check_hardware(db, device, state, now)


# ----------------------------------------------------------------------------- time driven checks
def _location(db: Session, device: Device) -> DeviceLocation | None:
    return db.get(DeviceLocation, device.location_id) if device.location_id else None


def check_absences(db: Session, now: datetime | None = None) -> dict[str, int]:
    """Not seen for N days and agent stopped, for the session's organisation. Returns counts raised."""
    now = now or utcnow()
    out = {"not_seen": 0, "agent_stopped": 0}
    st = service.get_settings(db, create=False)
    if not alerts_active(db, st):
        return out
    if st.alert_not_seen_days:
        cutoff = now - timedelta(days=st.alert_not_seen_days)
        for d in db.scalars(select(Device).where(
                Device.status == "active", Device.os_family.in_(("windows", "macos")),
                Device.last_seen_at.is_not(None), Device.last_seen_at < cutoff,
                Device.last_seen_at > now - FORGET_AFTER).order_by(Device.last_seen_at).limit(5000)):
            if not service.qualifies(d):
                continue
            state = get_state(db, d)
            if state.not_seen_alert_for == d.last_seen_at:
                continue
            loc = _location(db, d)
            days = (now - d.last_seen_at).days
            state.not_seen_alert_for = d.last_seen_at
            if raise_alert(db, d, "not_seen", f"{d.hostname} has not been seen for {days} days"
                           + (f" (last seen in {place(loc.city, loc.country)})" if loc and loc.country else ""),
                           now, loc=loc):
                out["not_seen"] += 1
    if st.alert_agent_stopped:
        rows = db.scalars(select(DeviceTrackingState).where(
            DeviceTrackingState.last_obs_at.is_not(None), DeviceTrackingState.last_obs_at < now - AGENT_STOPPED_AFTER,
            DeviceTrackingState.last_obs_at > now - STOPPED_WINDOW,
            DeviceTrackingState.regular_polls >= REGULAR_POLLS_NEEDED).limit(5000))
        for state in list(rows):
            if state.stopped_alert_for == state.last_obs_at:
                continue
            d = db.get(Device, state.device_id)
            if d is None or not service.qualifies(d):  # revoked / removed devices are not alerted on
                continue
            state.stopped_alert_for = state.last_obs_at
            if raise_alert(db, d, "agent_stopped", f"{d.hostname}: the agent stopped reporting", now,
                           summary="The agent was polling about every minute and has been silent for over 2 hours.",
                           loc=_location(db, d)):
                out["agent_stopped"] += 1
    return out


def prune_events(db: Session, now: datetime | None = None) -> int:
    cutoff = (now or utcnow()) - timedelta(days=config.settings.device_location_retention_days)
    res = db.execute(delete(DeviceTrackingEvent).where(DeviceTrackingEvent.at < cutoff)
                     .execution_options(synchronize_session=False))
    return res.rowcount or 0


def history_events(db: Session, device: Device, since: datetime) -> list[dict[str, Any]]:
    """The device's alerts as location-history events (city and country only, so safe for every role)."""
    rows = db.scalars(select(DeviceTrackingEvent).where(
        DeviceTrackingEvent.device_id == device.id, DeviceTrackingEvent.at >= since)
        .order_by(DeviceTrackingEvent.at.desc()).limit(200))
    return [{"kind": r.kind, "alert": True, "at": r.at, "title": r.title, "severity": r.severity, "city": r.city,
             "country": r.country, "country_code": r.country_code} for r in rows]
