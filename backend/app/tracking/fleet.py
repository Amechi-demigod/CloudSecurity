"""Fleet map data (docs/DEVICE_TRACKING.md#map-view): where the organisation's laptops and desktops are, aggregated
per city, plus one row per computer for the side panel and the summary tiles.

Roles: analysts and admins get coordinates (a marker per city). Viewers get city and country only: no coordinates,
no internet address, so the console shows the same cities as a grouped list instead of a map (the simplest safe
option; no centroid lookup is done for them).
Tenancy: everything runs in the session's organisation (app/tenancy.py).
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config, geoip
from ..models import Device, utcnow
from ..services import devices as dev_svc
from . import alerts, service
from .models import DeviceLocation

MAX_DEVICES = 5000
STATUSES = ("active", "stale", "inactive")


def missing_count(devices: list[Device]) -> int:
    """The "Missing" tile.

    TODO(PR C #150, missing-device mode): once C is merged, replace the body with
    `sum(1 for d in devices if missing.is_missing(d))` (missing_since set and missing_recovered_at null).
    For now: computers in lost mode.
    """
    return sum(1 for d in devices if d.lost_mode_status in ("enabling", "active"))


def _status(d: Device, now: datetime) -> str:
    c = dev_svc.connectivity(d, now)
    return "inactive" if c == "never" else c


def fleet(db: Session, *, full: bool, group: str | None = None, status: str | None = None,
          not_seen: bool = False, now: datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    st = service.get_settings(db, create=False)
    days = (st.alert_not_seen_days if st and st.alert_not_seen_days else 7)
    out: dict[str, Any] = {
        "enabled": bool(st and st.enabled), "detail": "full" if full else "basic", "tile_url": config.settings.map_tile_url,
        "database_available": geoip.database_available(), "not_seen_days": days, "timezone": st.timezone if st else "UTC",
        "tiles": {"at_office": 0, "away": 0, "outside_countries": 0, "missing": 0, "unlocated": 0},
        "groups": [], "cities": [], "devices": [], "truncated": False}
    if not out["enabled"]:
        return out
    rows = db.execute(
        select(Device, DeviceLocation).outerjoin(DeviceLocation, Device.location_id == DeviceLocation.id)
        .where(Device.status == "active", Device.os_family.in_(("windows", "macos")))
        .order_by(Device.hostname).limit(MAX_DEVICES + 1)).all()
    out["truncated"] = len(rows) > MAX_DEVICES
    rows = [(d, loc) for d, loc in rows[:MAX_DEVICES] if service.qualifies(d)]
    offices = {o.id: o.name for o in service.offices(db)}
    out["groups"] = sorted({d.device_group for d, _ in rows if d.device_group})
    out["tiles"]["missing"] = missing_count([d for d, _ in rows])
    cutoff = now - timedelta(days=days)
    cities: dict[tuple[str, str], dict[str, Any]] = {}
    for d, loc in rows:
        placed = loc is not None and not loc.is_private and bool(loc.city or loc.country)
        outside = alerts.outside_allowed(st, loc)
        unseen = d.last_seen_at is None or d.last_seen_at < cutoff
        # Tiles count every tracked computer, whatever the filters.
        if loc is None:
            out["tiles"]["unlocated"] += 1
        elif loc.office_id:
            out["tiles"]["at_office"] += 1
        else:
            out["tiles"]["away"] += 1
        if outside:
            out["tiles"]["outside_countries"] += 1
        if (group and d.device_group != group) or (status and _status(d, now) != status) or (not_seen and not unseen):
            continue
        kind = "unlocated" if loc is None else service.network_kind(loc)
        place = None
        if placed:
            key = ((loc.city or "").strip(), loc.country_code or "")
            place = cities.get(key)
            if place is None:
                place = cities[key] = {"city": loc.city, "country": loc.country, "country_code": loc.country_code,
                                       "count": 0, "flagged": False, "device_ids": [], "_lat": [], "_lon": []}
            place["count"] += 1
            place["flagged"] = place["flagged"] or outside or unseen
            place["device_ids"].append(d.id)
            if loc.latitude is not None and loc.longitude is not None:
                place["_lat"].append(loc.latitude)
                place["_lon"].append(loc.longitude)
        office = offices.get(loc.office_id) if loc and loc.office_id else None
        out["devices"].append({
            "id": d.id, "hostname": d.hostname, "group": d.device_group, "network": kind, "office": office,
            "city": loc.city if loc else None, "country": loc.country if loc else None,
            "country_code": loc.country_code if loc else None, "last_seen_at": d.last_seen_at,
            "status": _status(d, now), "outside_countries": outside, "not_seen": unseen,
            "lost_mode": d.lost_mode_status in ("enabling", "active")})
    for p in cities.values():
        lat, lon = p.pop("_lat"), p.pop("_lon")
        if full and lat:
            p["latitude"], p["longitude"] = sum(lat) / len(lat), sum(lon) / len(lon)
        out["cities"].append(p)
    out["cities"].sort(key=lambda c: (-c["count"], c["city"] or ""))
    return out
