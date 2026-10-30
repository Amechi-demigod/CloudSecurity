"""Attended remote sessions as a notification source (route them to Teams,
Slack or email like any other source).

Events:
  * session_requested: an analyst or admin asked for a remote session
  * session_started: the user allowed it and the viewer is connected
  * session_denied: the user clicked Deny or did not answer in time
  * session_ended: the session ended (viewer, user, admin, limits, device state)
  * session_failed: it never started (no signed-in user, unsupported platform,
    the device did not connect in time, ...)

Only metadata: never frame content or keystrokes.
"""
from __future__ import annotations

import logging
from urllib.parse import quote

from sqlalchemy.orm import Session

from .events import Event, EventSource, emit, register_source

log = logging.getLogger(__name__)

SOURCE = "remote_session"
EVENT_TYPES = ("session_requested", "session_started", "session_denied", "session_ended", "session_failed")
SEVERITY = {
    "session_requested": "low",
    "session_started": "medium",
    "session_denied": "low",
    "session_ended": "info",
    "session_failed": "low",
}
TITLES = {
    "session_requested": "Remote session requested",
    "session_started": "Remote session started",
    "session_denied": "Remote session denied by the user",
    "session_ended": "Remote session ended",
    "session_failed": "Remote session failed",
}
MODE_LABELS = {"view": "View only", "control": "View and control"}


def _link(device_id: str) -> str:
    return f"/devices/{quote(str(device_id), safe='')}"


def notify(db: Session, device, rs, event_type: str, detail: str = "") -> None:
    if event_type not in EVENT_TYPES:
        return
    try:
        lines = [f"Requested by {rs.requested_by_email}", f"Mode: {MODE_LABELS.get(rs.mode, rs.mode)}"]
        if rs.reason:
            lines.append(f"Reason: {rs.reason}")
        if rs.end_reason:
            lines.append(f"End reason: {rs.end_reason}")
        if rs.error_code:
            lines.append(f"Error: {rs.error_code}")
        if detail:
            lines.append(detail)
        emit(db, Event(
            source=SOURCE,
            event_type=event_type,
            severity=SEVERITY.get(event_type, "info"),
            title=f"{TITLES.get(event_type, event_type)} on {device.hostname}",
            summary="\n".join(lines)[:1000],
            entity_id=device.id,
            group_key=f"{SOURCE}:{rs.id}:{event_type}",
            rule_id=event_type,
            link_path=_link(device.id),
            attributes={
                "asset_type": "device",
                "asset_name": device.hostname,
                "hostname": device.hostname,
                "os_family": device.os_family,
                "action": event_type,
                "actor": rs.requested_by_email,
                "reason": rs.reason,
                "session_id": rs.id,
                "mode": rs.mode,
                "end_reason": rs.end_reason,
                "error_code": rs.error_code,
            },
        ))
    except Exception:  # notifications must never break the session flow
        log.exception("failed to queue remote session notification")


register_source(EventSource(
    SOURCE,
    "Remote sessions",
    EVENT_TYPES,
    "Attended remote desktop sessions: requested, started (user allowed), denied, ended and failed.",
))
