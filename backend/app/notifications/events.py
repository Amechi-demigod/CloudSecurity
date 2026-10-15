"""Generic notification event model and event-source registry.

Any part of the platform can raise a notification by calling `emit()` inside
its own database transaction (push sources), or by registering a pull source
whose `poll()` the dispatcher calls periodically. `emit()` only inserts one row
into `notification_events`; rule matching, throttling and sending happen later
in the background dispatcher, so producers (request handlers, the detection
pipeline) are never slowed down or blocked by a slow webhook.

Adding a new source (e.g. endpoint device posture) needs no change here:

    from app.notifications import Event, EventSource, emit, register_source

    register_source(EventSource(
        name="device", label="Device posture",
        event_types=("encryption_off", "stale"),
        description="Endpoint agent posture issues"))

    emit(db, Event(source="device", event_type="encryption_off", severity="high",
                   title="Disk encryption is off on LAPTOP-42", entity_id=device.id,
                   group_key=f"device:{device.id}:encryption_off",
                   link_path=f"/devices/{device.id}",
                   attributes={"subscription_id": None, "tags": {"team": "finance"}}))

Rules can then select it by source / event type / severity / tags like any
built-in source.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

log = logging.getLogger(__name__)

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
STATUS_CHANGED = "status_changed"
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


@dataclass
class Event:
    source: str
    event_type: str
    severity: str
    title: str
    summary: str = ""
    entity_id: str | None = None
    # Events with the same group key are de-duplicated / throttled together.
    group_key: str | None = None
    asset_id: str | None = None
    rule_id: str | None = None
    mitre_technique_id: str | None = None
    # Path in the web UI (joined with PUBLIC_BASE_URL), e.g. "/threats?alert=<id>".
    link_path: str | None = None
    # Free-form context. Recognised keys for matching when there is no asset:
    # subscription_id, asset_type, asset_name, tags (dict).
    attributes: dict[str, Any] = field(default_factory=dict)


PollFn = Callable[[Session, dict, datetime], tuple[list[Event], dict]]


@dataclass
class EventSource:
    name: str
    label: str
    event_types: tuple[str, ...] = ("created",)
    description: str = ""
    # Pull sources: poll(db, state, now) -> (new events, new state), run by the
    # dispatcher leader every `poll_interval()` seconds.
    poll: PollFn | None = None
    poll_interval: Callable[[], float] | None = None


_SOURCES: dict[str, EventSource] = {}


def register_source(src: EventSource) -> EventSource:
    if not _NAME_RE.match(src.name):
        raise ValueError(f"invalid event source name {src.name!r}")
    _SOURCES[src.name] = src
    return src


def get_source(name: str) -> EventSource | None:
    return _SOURCES.get(name)


def sources() -> list[EventSource]:
    return list(_SOURCES.values())


def normalize_severity(sev: str | None) -> str:
    s = (sev or "info").strip().lower()
    return s if s in SEV_RANK else "info"


def emit(db: Session, ev: Event):
    """Queue `ev` in the caller's transaction (the caller commits). Never raises."""
    from .models import NotificationEvent

    try:
        if not _NAME_RE.match(ev.source):
            raise ValueError(f"invalid event source {ev.source!r}")
        row = NotificationEvent(
            source=ev.source, event_type=(ev.event_type or "created")[:32], severity=normalize_severity(ev.severity),
            title=(ev.title or ev.source)[:255], summary=(ev.summary or "")[:4000],
            entity_id=ev.entity_id[:512] if ev.entity_id else None,
            group_key=(ev.group_key or f"{ev.source}:{ev.entity_id or ev.title}")[:255],
            asset_id=ev.asset_id, rule_id=(ev.rule_id or None) and ev.rule_id[:64],
            mitre_technique_id=(ev.mitre_technique_id or None) and ev.mitre_technique_id[:16],
            link_path=ev.link_path[:1024] if ev.link_path else None, attributes=dict(ev.attributes or {}),
        )
        db.add(row)
        return row
    except Exception:  # notifications must never break the producer
        log.exception("failed to queue notification event from %s", getattr(ev, "source", "?"))
        return None
