"""Host isolation as a notification source.

Events:
  * isolation_requested: an analyst or admin queued host isolation
  * host_isolated: the agent successfully suspended interactive sign-in on the host
  * restore_requested: an admin queued restoration of interactive sign-in
  * host_restored: the agent successfully restored interactive sign-in
  * isolation_failed: host isolation failed on the agent
  * restore_failed: host restoration failed on the agent
"""
from __future__ import annotations

import logging
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
)
SEVERITY = {
    "isolation_requested": "medium",
    "host_isolated": "high",
    "restore_requested": "low",
    "host_restored": "low",
    "isolation_failed": "high",
    "restore_failed": "high",
}
TITLES = {
    "isolation_requested": "Host isolation requested",
    "host_isolated": "Host isolated",
    "restore_requested": "Host restoration requested",
    "host_restored": "Host restored",
    "isolation_failed": "Host isolation failed",
    "restore_failed": "Host restoration failed",
}


def _link(device_id: str) -> str:
    return f"/devices/{quote(str(device_id), safe='')}"


def notify(db: Session, device, event_type: str, actor: str | None = None, reason: str = "",
           detail: str = "") -> None:
    if event_type not in EVENT_TYPES:
        return
    try:
        lines = []
        if actor:
            lines.append(f"Requested by {actor}" if "requested" in event_type else f"Actor: {actor}")
        if reason:
            lines.append(f"Reason: {reason}")
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
                "isolation_status": getattr(device, "isolation_status", None),
            },
        ))
    except Exception:  # notifications must never break the command flow
        log.exception("failed to queue host isolation notification")


register_source(EventSource(
    SOURCE,
    "Host isolation",
    EVENT_TYPES,
    "Host isolation lifecycle events: isolation requested, host isolated, restoration requested, "
    "and interactive sign-in restored.",
))
