"""Endpoint devices as a notification source.

Push events (same transaction as the change):
  * a posture issue appears on a check-in (disk encryption / firewall / antivirus
    off, AV signatures outdated, OS updates overdue, ...): event type = issue code
  * the agent reports the result of a remote action: command_succeeded /
    command_failed / command_rejected

Pull events (time based, so nothing happens on a request): a device that stops
checking in becomes `stale` and later `inactive`. The dispatcher leader polls
for those transitions; the first poll only records a baseline so enabling
notifications does not flood channels with already-quiet devices.

Imports of the device modules are deferred: this module is loaded while
`app.models` is still being imported (models -> notifications.models).
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from urllib.parse import quote

from sqlalchemy.orm import Session

from .events import Event, EventSource, emit, register_source

log = logging.getLogger(__name__)

DEVICE = "device"

# Issue codes from app.services.devices.ISSUE_DEFS that are raised on check-in.
CHECKIN_ISSUES = (
    "disk_encryption_off", "firewall_off", "antivirus_off", "av_signatures_outdated", "os_updates_pending",
    "screen_lock_off", "sip_disabled", "gatekeeper_off", "secure_boot_off",
)
CONNECTIVITY_ISSUES = ("stale", "inactive")
COMMAND_RESULTS = {"succeeded": "command_succeeded", "failed": "command_failed", "rejected": "command_rejected"}
EVENT_TYPES = CHECKIN_ISSUES + CONNECTIVITY_ISSUES + tuple(COMMAND_RESULTS.values())
POLL_SECONDS = 300.0
MAX_TRACKED = 20000


def _link(device_id: str) -> str:
    return f"/devices/{quote(str(device_id), safe='')}"


def _attrs(device, **extra: Any) -> dict[str, Any]:
    return {"asset_type": "device", "asset_name": device.hostname, "hostname": device.hostname,
            "os_family": device.os_family, "os_version": device.os_version, "serial_number": device.serial_number,
            **extra}


def _issue_event(device, issue: dict[str, str]) -> Event:
    code = issue["code"]
    detail = issue.get("detail") or ""
    return Event(
        source=DEVICE, event_type=code, severity=issue["severity"],
        title=f"{issue['title']} on {device.hostname}", summary=detail,
        entity_id=device.id, group_key=f"{DEVICE}:{device.id}:{code}", rule_id=code,
        link_path=_link(device.id), attributes=_attrs(device, issue=code, detail=detail),
    )


def issues_raised(db: Session, device, issues: list[dict[str, str]], previous_codes: set[str] | None) -> int:
    """Emit one event per check-in issue that was not present at the previous
    check-in (`previous_codes` None = first check-in). Returns the count."""
    prev = previous_codes or set()
    n = 0
    for issue in issues:
        if issue["code"] in CHECKIN_ISSUES and issue["code"] not in prev:
            try:
                ev = _issue_event(device, issue)
            except Exception:  # notifications must never break a check-in
                log.exception("failed to build device notification event")
                continue
            if emit(db, ev) is not None:
                n += 1
    return n


def command_completed(db: Session, device, cmd) -> None:
    event_type = COMMAND_RESULTS.get(cmd.status)
    if event_type is None:
        return
    try:
        _command_completed(db, device, cmd, event_type)
    except Exception:  # notifications must never break the agent API
        log.exception("failed to queue device command notification")


def _command_completed(db: Session, device, cmd, event_type: str) -> None:
    ok = cmd.status == "succeeded"
    action = cmd.type.replace("_", " ")
    emit(db, Event(
        source=DEVICE, event_type=event_type, severity="low" if ok else "medium",
        title=f"Remote action {action} {cmd.status} on {device.hostname}",
        summary=(cmd.output or "")[:1000], entity_id=cmd.id,
        group_key=f"{DEVICE}:{device.id}:command:{cmd.id}", rule_id=cmd.type, link_path=_link(device.id),
        attributes=_attrs(device, command_id=cmd.id, command_type=cmd.type, status=cmd.status,
                          requested_by=cmd.requested_by_email),
    ))


def poll_connectivity(db: Session, state: dict, now: datetime) -> tuple[list[Event], dict]:
    """Notify when an enrolled device becomes stale or inactive (once per transition)."""
    from sqlalchemy import select

    from ..models import Device
    from ..services import devices as svc

    seen: dict[str, str] = dict(state.get("conn") or {})
    current: dict[str, str] = {}
    events: list[Event] = []
    rows = db.scalars(select(Device).where(Device.status == "active", Device.last_seen_at.is_not(None))
                      .order_by(Device.last_seen_at).limit(MAX_TRACKED))
    for d in rows:
        conn = svc.connectivity(d, now)
        if conn not in CONNECTIVITY_ISSUES:
            continue
        current[d.id] = conn
        if state.get("initialized") and seen.get(d.id) != conn:
            issue = next((i for i in svc.device_issues(d, now) if i["code"] == conn), None)
            if issue is not None:
                last = d.last_seen_at.strftime("%Y-%m-%d %H:%M UTC")
                issue = {**issue, "detail": f"last check-in {last}"}
                events.append(_issue_event(d, issue))
    # Devices that check in again are forgotten, so they notify again if they go quiet.
    return events, {"initialized": True, "conn": current}


register_source(EventSource(
    DEVICE, "Endpoint device", EVENT_TYPES,
    "Device posture issues (encryption, firewall, antivirus, updates), devices that stop checking in, "
    "and remote action results.",
    poll=poll_connectivity, poll_interval=lambda: POLL_SECONDS))
