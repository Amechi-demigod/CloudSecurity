"""IT asset lifecycle as a notification source (`asset_lifecycle`).

Pull events (the dispatcher leader polls every ASSET_NOTIFICATION_POLL_SECONDS,
1 h by default), each raised once per condition and asset:
  * retrieval_overdue: a leaver's asset is still "retrieval pending" after its due date
  * warranty_expiring: the warranty ends within the warning window (default 30 days)
  * device_unseen: the asset's agent device has not checked in for the idle
    window (default 30 days); raised again if it comes back and goes quiet again

Push event (same transaction as the change):
  * lost_or_stolen: an asset was marked lost or stolen

Imports of the asset modules are deferred: this module is loaded while
`app.models` is still being imported.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote

from sqlalchemy.orm import Session

from .events import Event, EventSource, emit, register_source

log = logging.getLogger(__name__)

SOURCE = "asset_lifecycle"
EVENT_TYPES = ("retrieval_overdue", "warranty_expiring", "device_unseen", "lost_or_stolen")
MAX_TRACKED = 20000


def _link(asset_id: str) -> str:
    return f"/it-assets/{quote(str(asset_id), safe='')}"


def _attrs(asset, **extra: Any) -> dict[str, Any]:
    return {"asset_type": f"it_{asset.asset_type}", "asset_name": asset.asset_tag, "asset_tag": asset.asset_tag,
            "serial_number": asset.serial_number, "model": " ".join(p for p in (asset.manufacturer, asset.model) if p),
            "assignee_email": asset.assignee_email or None, "location": asset.location or None, **extra}


def _event(asset, event_type: str, severity: str, title: str, summary: str, key: str, **extra: Any) -> Event:
    return Event(source=SOURCE, event_type=event_type, severity=severity, title=title[:255], summary=summary,
                 entity_id=asset.id, group_key=f"{SOURCE}:{asset.id}:{event_type}:{key}", rule_id=event_type,
                 link_path=_link(asset.id), attributes=_attrs(asset, **extra))


def poll(db: Session, state: dict, now: datetime) -> tuple[list[Event], dict]:
    from sqlalchemy import select

    from ..asset_lifecycle import service as svc
    from ..asset_lifecycle.models import ItAsset
    from ..models import Device

    st = svc.get_settings(db)
    on = now.date()
    events: list[Event] = []
    seen_overdue = dict(state.get("overdue") or {})
    seen_warranty = dict(state.get("warranty") or {})
    seen_unseen = dict(state.get("unseen") or {})
    overdue: dict[str, str] = {}
    warranty: dict[str, str] = {}
    unseen: dict[str, str] = {}

    rows = db.scalars(select(ItAsset).where(ItAsset.status == "retrieval_pending", ItAsset.retrieval_due < on)
                      .order_by(ItAsset.retrieval_due).limit(MAX_TRACKED))
    for a in rows:
        key = a.retrieval_due.isoformat()
        overdue[a.id] = key
        if seen_overdue.get(a.id) != key:
            days = (on - a.retrieval_due).days
            who = a.assignee_name or a.assignee_email or "a leaver"
            events.append(_event(a, "retrieval_overdue", "medium",
                                 f"Asset {a.asset_tag} not retrieved from {who} ({days} day(s) overdue)",
                                 f"Retrieval was due {key}.", key, retrieval_due=key, days_overdue=days))

    horizon = on + timedelta(days=st["warranty_warning_days"])
    rows = db.scalars(select(ItAsset).where(ItAsset.status.not_in(svc.INACTIVE_STATUSES),
                                            ItAsset.warranty_end.is_not(None), ItAsset.warranty_end >= on,
                                            ItAsset.warranty_end <= horizon)
                      .order_by(ItAsset.warranty_end).limit(MAX_TRACKED))
    for a in rows:
        key = a.warranty_end.isoformat()
        warranty[a.id] = key
        if seen_warranty.get(a.id) != key:
            days = (a.warranty_end - on).days
            events.append(_event(a, "warranty_expiring", "low",
                                 f"Warranty of {a.asset_tag} ends in {days} day(s)",
                                 f"Warranty end date {key}; refresh due {a.refresh_date or 'not set'}.", key,
                                 warranty_end=key, days_left=days))

    rows = db.execute(select(ItAsset, Device).join(Device, Device.id == ItAsset.device_id)
                      .where(ItAsset.status.not_in(svc.INACTIVE_STATUSES), Device.status == "active")
                      .limit(MAX_TRACKED)).all()
    for a, d in rows:
        if not svc.is_idle(d, now, st["idle_days"]):
            continue
        last = d.last_seen_at or d.enrolled_at
        key = last.strftime("%Y-%m-%dT%H:%M")
        unseen[a.id] = key
        if seen_unseen.get(a.id) != key:
            events.append(_event(a, "device_unseen", "low",
                                 f"{a.asset_tag} ({d.hostname}) has not checked in for {st['idle_days']}+ days",
                                 f"Last seen {last:%Y-%m-%d %H:%M} UTC: idle candidate (reassign, retrieve "
                                 "or check the agent).", key, hostname=d.hostname, device_id=d.id,
                                 last_seen=last.isoformat() + "Z"))
    return events, {"overdue": overdue, "warranty": warranty, "unseen": unseen}


def lost_or_stolen(db: Session, asset, actor: str, notes: str) -> None:
    try:
        emit(db, _event(asset, "lost_or_stolen", "high", f"Asset {asset.asset_tag} marked {asset.status}",
                        (notes or "")[:1000] or f"Marked {asset.status} by {actor}.",
                        f"{asset.status}:{asset.updated_at:%Y%m%d%H%M%S}", reported_by=actor,
                        device_id=asset.device_id))
    except Exception:  # notifications must never break the request
        log.exception("failed to queue asset lifecycle notification")


def _interval() -> float:
    from .. import config

    return max(60.0, config.settings.asset_notification_poll_seconds)


register_source(EventSource(
    SOURCE, "IT asset lifecycle", EVENT_TYPES,
    "Leavers' assets not retrieved by the due date, warranties about to expire, agent devices not seen "
    "for the idle window, and assets marked lost or stolen.",
    poll=poll, poll_interval=_interval))
