"""Suspend sign-in (internal name: host isolation) as a notification source.

Events:
  * isolation_requested: an analyst or admin queued Suspend sign-in
  * host_isolated: the agent successfully suspended interactive sign-in on the host
  * restore_requested: an admin queued Restore sign-in
  * host_restored: the agent successfully restored interactive sign-in
  * isolation_failed: Suspend sign-in failed on the agent
  * restore_failed: Restore sign-in failed on the agent
  * preflight_blocked_no_local_admin: Suspend sign-in was blocked because no
    local admin would remain able to sign in
  * rolled_back_after_crash: the agent rolled back an unconfirmed suspend
    after an agent restart (see signin.Manager.OnStart); the matching audit
    action is the longer, unambiguous host_isolation_rolled_back_after_crash
  * completed_after_crash: the agent finished applying a suspend after an
    agent restart (audit action: host_isolation_completed_after_crash)
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

from sqlalchemy.orm import Session

from .events import Event, EventSource, emit, register_source

log = logging.getLogger(__name__)

SOURCE = "host_isolation"
EVENT_TYPES = (
    "isolation_requested",
    "host_isolated",
    "restore_requested",
    "host_restored",
    "isolation_failed",
    "restore_failed",
    "preflight_blocked_no_local_admin",
    "rolled_back_after_crash",
    "completed_after_crash",
)
SEVERITY = {
    "isolation_requested": "medium",
    "host_isolated": "high",
    "restore_requested": "low",
    "host_restored": "low",
    "isolation_failed": "high",
    "restore_failed": "high",
    "preflight_blocked_no_local_admin": "critical",
    "rolled_back_after_crash": "high",
    "completed_after_crash": "high",
}
TITLES = {
    "isolation_requested": "Suspend sign-in requested",
    "host_isolated": "Sign-in suspended",
    "restore_requested": "Restore sign-in requested",
    "host_restored": "Sign-in restored",
    "isolation_failed": "Suspend sign-in failed",
    "restore_failed": "Restore sign-in failed",
    "preflight_blocked_no_local_admin": "Suspend sign-in blocked - no local admin would remain",
    "rolled_back_after_crash": "Sign-in suspension rolled back after a crash",
    "completed_after_crash": "Sign-in suspension completed after a crash",
}


def _link(device_id: str) -> str:
    return f"/devices/{quote(str(device_id), safe='')}"


def notify(db: Session, device, event_type: str, actor: str | None = None, reason: str = "",
           detail: str = "", data: dict[str, Any] | None = None, incident_id: str | None = None) -> None:
    if event_type not in EVENT_TYPES:
        return
    data = data or {}
    try:
        lines = []
        if actor:
            lines.append(f"Requested by {actor}" if "requested" in event_type else f"Actor: {actor}")
        if incident_id:
            lines.append(f"Incident: {incident_id}")
        if reason:
            lines.append(f"Reason: {reason}")
        if data.get("error_code") == "ERR_NO_LOCAL_ADMIN_PRESENT":
            lines.append("No local admin would remain able to sign in.")
        if data.get("local_admins"):
            lines.append(f"Local admins found: {', '.join(data['local_admins'])}")
        if data.get("recovery_outcome") in ("rolled_back", "completed"):
            lines.append(f"Recovered after an agent restart: {data['recovery_outcome']}")
        if detail:
            lines.append(detail)
        emit(db, Event(
            source=SOURCE,
            event_type=event_type,
            severity=SEVERITY.get(event_type, "medium"),
            title=f"{TITLES.get(event_type, event_type)} on {device.hostname}",
            summary="\n".join(lines)[:1000],
            entity_id=device.id,
            group_key=f"{SOURCE}:{device.id}:{event_type}",
            rule_id=event_type,
            link_path=_link(device.id),
            attributes={
                "asset_type": "device",
                "asset_name": device.hostname,
                "hostname": device.hostname,
                "os_family": device.os_family,
                "action": event_type,
                "actor": actor,
                "reason": reason,
                "incident_id": incident_id,
                "isolation_status": getattr(device, "isolation_status", None),
                "result_data": data,
            },
        ))
    except Exception:  # notifications must never break the command flow
        log.exception("failed to queue host isolation notification")


register_source(EventSource(
    SOURCE,
    "Suspend sign-in",
    EVENT_TYPES,
    "Suspend sign-in lifecycle events: requested, suspended, restoration requested, restored, "
    "pre-flight blocked (no local admin would remain), and crash-recovery outcomes.",
))
