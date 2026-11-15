"""Attack surface & pre-ASV findings as a notification source (`external_finding`): one push event when a scan finds a
new (or re-opened) critical or high external finding. Only queued for organisations with the `external` module."""
from __future__ import annotations

from .events import Event, EventSource, emit, register_source

SOURCE = "external_finding"

register_source(EventSource(SOURCE, "Attack surface findings", ("created",),
                            "New critical or high findings from the external attack-surface scan"))


def finding_created(db, f) -> None:
    """Queue the event for ExternalFinding `f` (same transaction as the scan result)."""
    emit(db, Event(source=SOURCE, event_type="created", severity=f.severity,
                   title=f"{f.severity.title()} external finding on {f.host}: {f.title}"[:255],
                   summary=f"EXT-{f.seq:04d} on {f.host}" + (f":{f.port}" if f.port else "") + f", CVSS {f.cvss:g}.",
                   entity_id=f.id, group_key=f"{SOURCE}:{f.id}", rule_id=f.check_id,
                   link_path=f"/attack-surface/findings/{f.id}",
                   attributes={"asset_type": "external_host", "asset_name": f.host}))
