"""Recent tracking alerts across all computers (docs/DEVICE_TRACKING.md#recent-alerts): the Map view's side panel.

Reads the alert rows (alert_models.DeviceTrackingEvent), newest first. They hold a city and country only, never an
address, coordinates or provider, so the same fields are safe for every role; `detail` still reports which level
the caller gets, like the fleet data. Everything runs in the session's organisation (app/tenancy.py).
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import config
from ..models import Device, utcnow
from ..notifications import device_tracking_source as notes
from ..notifications.models import NotificationChannel, NotificationRule
from . import alerts, service
from .alert_models import DeviceTrackingEvent

# Filter chips of the console -> alert kinds.
KIND_GROUPS = {"outside_countries": ("outside_countries",), "not_seen": ("not_seen",), "hardware": ("hardware_changed",),
               "locked": ("auto_lost_mode",), "after_hours": ("after_hours",), "agent_stopped": ("agent_stopped",)}
DEFAULT_DAYS = 7
MAX_LIMIT = 200


def notified(db: Session) -> bool:
    """True when at least one enabled rule sends device tracking alerts to at least one enabled channel.
    A rule with an empty source list does not count (it is not a rule made for these alerts)."""
    rules = [r for r in db.scalars(select(NotificationRule).where(NotificationRule.enabled.is_(True)))
             if notes.SOURCE in (r.sources or []) and r.channel_ids]
    if not rules:
        return False
    live = set(db.scalars(select(NotificationChannel.id).where(NotificationChannel.enabled.is_(True))))
    return any(live.intersection(r.channel_ids) for r in rules)


def _detail(kind: str, city: str | None, country: str | None) -> str:
    label = alerts.KIND_LABELS.get(kind, kind)
    where = ", ".join(x for x in (city, country) if x)
    return f"{label} · {where}" if where else label


def recent(db: Session, *, full: bool, days: int = DEFAULT_DAYS, group: str | None = None, limit: int = 20,
           now: datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    days = max(1, min(days, config.settings.device_location_retention_days))
    limit = max(1, min(limit, MAX_LIMIT))
    st = service.get_settings(db, create=False)
    out: dict[str, Any] = {"enabled": bool(st and st.enabled), "detail": "full" if full else "basic", "days": days,
                           "group": group, "count_24h": 0, "total": 0, "notified": False, "items": []}
    if not out["enabled"]:
        return out
    where = [DeviceTrackingEvent.at >= now - timedelta(days=days)]
    if group:
        where.append(DeviceTrackingEvent.kind.in_(KIND_GROUPS[group]))
    out["count_24h"] = db.scalar(select(func.count(DeviceTrackingEvent.id)).where(
        DeviceTrackingEvent.at >= now - timedelta(hours=24))) or 0
    out["total"] = db.scalar(select(func.count(DeviceTrackingEvent.id)).where(*where)) or 0
    rows = db.execute(
        select(DeviceTrackingEvent, Device.hostname).join(Device, Device.id == DeviceTrackingEvent.device_id)
        .where(*where).order_by(DeviceTrackingEvent.at.desc(), DeviceTrackingEvent.id).limit(limit)).all()
    out["items"] = [{
        "id": e.id, "kind": e.kind, "severity": e.severity, "title": e.title,
        "detail_line": _detail(e.kind, e.city, e.country), "at": e.at, "device_id": e.device_id, "hostname": host,
        "city": e.city, "country": e.country, "country_code": e.country_code} for e, host in rows]
    out["notified"] = notified(db)
    return out
