"""Directory discovery as a notification source (docs/DIRECTORY_DISCOVERY.md).

Events:
  * sync_failed: a directory sync failed (collector offline or unable to reach /
    bind to the directory, the run stalled, ...). Grouped per source, so a
    directory that keeps failing does not flood a channel (the dispatcher's
    grouping / rule cooldowns apply).
  * not_managed_changed: the number of enabled, recently used directory
    computers without an agent changed after a sync. Raised only when the
    count differs from the last one notified, never on periodic re-evaluation.
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from .events import Event, EventSource, emit, register_source

log = logging.getLogger(__name__)

SOURCE = "directory_source"
EVENT_TYPES = ("sync_failed", "not_managed_changed")


def sync_failed(db: Session, src, run) -> None:
    try:
        emit(db, Event(
            source=SOURCE, event_type="sync_failed", severity="high",
            title=f"Directory sync failed: {src.name}",
            summary=(run.error or "the sync failed")[:1000],
            entity_id=src.id, group_key=f"{SOURCE}:{src.id}:sync_failed", rule_id="sync_failed",
            link_path="/connectors#directories",
            attributes={"asset_type": "directory", "asset_name": src.name, "directory_type": src.type,
                        "domain": (src.config or {}).get("domain"), "run_id": run.id, "trigger": run.trigger,
                        "collector_device_id": run.device_id},
        ))
    except Exception:  # notifications must never break a sync
        log.exception("failed to queue directory sync notification")


def not_managed_changed(db: Session, src, previous: int | None, current: int) -> None:
    try:
        if previous is None:
            summary = f"{current} enabled computer(s) sign in to {src.name} but have no agent."
        else:
            summary = f"Computers without an agent in {src.name}: {previous} -> {current}."
        emit(db, Event(
            source=SOURCE, event_type="not_managed_changed",
            severity="medium" if previous is None or current > previous else "low",
            title=f"Unmanaged directory computers: {current} ({src.name})",
            summary=summary, entity_id=src.id, group_key=f"{SOURCE}:{src.id}:not_managed", rule_id="not_managed",
            link_path="/it-assets/discovery?type=not_managed",
            attributes={"asset_type": "directory", "asset_name": src.name, "directory_type": src.type,
                        "domain": (src.config or {}).get("domain"), "previous": previous, "current": current},
        ))
    except Exception:
        log.exception("failed to queue directory coverage notification")


register_source(EventSource(
    SOURCE,
    "Directory discovery",
    EVENT_TYPES,
    "Directory (Active Directory) syncs that fail, and changes in the number of directory computers "
    "that have no agent.",
))
