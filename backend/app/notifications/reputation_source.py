"""Reputation findings as a notification source (`reputation_finding`): one push event when a run finds a new (or
re-opened) high finding. Only queued for organisations with the `external` module."""
from __future__ import annotations

from .events import Event, EventSource, emit, register_source

SOURCE = "reputation_finding"

register_source(EventSource(SOURCE, "Reputation findings", ("created",),
                            "New high-severity reputation findings (email security, blocklists, look-alike domains)"))


def finding_created(db, f) -> None:
    emit(db, Event(source=SOURCE, event_type="created", severity=f.severity,
                   title=f"{f.severity.title()} reputation finding on {f.domain}: {f.title}"[:255],
                   summary=f"REP-{f.seq:04d} on {f.domain}.", entity_id=f.id, group_key=f"{SOURCE}:{f.id}",
                   rule_id=f.check_id, link_path=f"/attack-surface/reputation/{f.id}",
                   attributes={"asset_type": "domain", "asset_name": f.domain}))
