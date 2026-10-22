"""On-prem server updates as a notification source: `cnapp-ctl update` (manual
or the optional nightly auto-update timer) failed or rolled back automatically.

cnapp-ctl raises these through `python -m app.cli notify-server-update`, so they
are routed by the existing notification rules like any other event.
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from .events import Event, EventSource, emit, register_source

log = logging.getLogger(__name__)

SOURCE = "server_update"
EVENT_TYPES = ("update_rolled_back", "update_failed", "updated")
SEVERITY = {"update_rolled_back": "high", "update_failed": "high", "updated": "info"}
TITLES = {"update_rolled_back": "Server update rolled back", "update_failed": "Server update failed",
          "updated": "Server updated"}


def server_update_event(db: Session, status: str, from_tag: str, to_tag: str, detail: str = "",
                        automatic: bool = False) -> bool:
    """Queue one server-update event (the caller commits). Returns False for an unknown status."""
    event_type = status if status in EVENT_TYPES else f"update_{status}"
    if event_type not in EVENT_TYPES:
        return False
    short = (to_tag or "?")[:12]
    how = "automatic" if automatic else "manual"
    try:
        emit(db, Event(
            source=SOURCE, event_type=event_type, severity=SEVERITY[event_type],
            title=f"{TITLES[event_type]} ({how}): {(from_tag or '?')[:12]} -> {short}",
            summary=(detail or "")[:1000], entity_id=f"server-update:{to_tag}"[:64],
            group_key=f"{SOURCE}:{event_type}:{to_tag}"[:255], rule_id=event_type,
            attributes={"asset_type": "server", "asset_name": "cnapp-server", "from_tag": from_tag,
                        "to_tag": to_tag, "status": event_type, "automatic": automatic},
        ))
    except Exception:  # notifications must never break the update
        log.exception("failed to queue server update notification")
        return False
    return True


register_source(EventSource(
    SOURCE, "Server updates", EVENT_TYPES,
    "On-prem server updates run by cnapp-ctl (manually or by the optional nightly auto-update): an update "
    "that failed its health check and was rolled back automatically, an update that failed, and successful "
    "updates."))
