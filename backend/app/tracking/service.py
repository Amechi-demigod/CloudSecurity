"""Device tracking logic (docs/DEVICE_TRACKING.md): qualifying devices, office matching, location history,
retention, and the role-filtered views. Everything runs in the session's organisation (app/tenancy.py)."""
from __future__ import annotations

import ipaddress
import logging
import time
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo, available_timezones

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from .. import config, device_class, geoip, modules, tenancy
from ..models import Device, utcnow
from . import missing
from .models import DeviceLocation, DeviceTrackingSettings, TrackingOffice

log = logging.getLogger(__name__)

MAX_NETWORKS = 50
ONLINE_WINDOW = timedelta(hours=2)  # "computers there now": checked in within this long
PRUNE_EVERY_SECONDS = 3600.0
_last_prune: dict[str, float] = {}


def qualifies(device: Device) -> bool:
    """Laptops and desktops on Windows and macOS only: never Linux, servers or domain controllers."""
    return (device.os_family in ("windows", "macos") and device.status == "active"
            and not device_class.is_server_class(device.device_class))


# ----------------------------------------------------------------------------- validation
def valid_timezone(name: str) -> bool:
    try:
        ZoneInfo(name)
    except Exception:
        return False
    return name in available_timezones() or name == "UTC"


def normalize_networks(values: list[str]) -> list[str]:
    """Canonical, de-duplicated list of IPs / CIDRs; ValueError when something is not one (or too broad)."""
    out: list[str] = []
    for raw in values:
        text = raw.strip()
        if not text:
            continue
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise ValueError(f"'{text}' is not an internet address or range") from None
        if net.prefixlen < (8 if net.version == 4 else 32):
            raise ValueError(f"'{text}' is too broad a range")
        s = str(net.network_address) if net.num_addresses == 1 else str(net)
        if s not in out:
            out.append(s)
    if len(out) > MAX_NETWORKS:
        raise ValueError(f"at most {MAX_NETWORKS} addresses or ranges per office")
    return out


# ----------------------------------------------------------------------------- settings / offices
def get_settings(db: Session, create: bool = True) -> DeviceTrackingSettings | None:
    org_id = tenancy.require_org(db)
    row = db.get(DeviceTrackingSettings, org_id)
    if row is None and create:
        row = DeviceTrackingSettings(organization_id=org_id, enabled=False, timezone="UTC", allowed_countries=[],
                                     alert_not_seen_days=7, after_hours_weekdays=[0, 1, 2, 3, 4, 5, 6],
                                     updated_at=utcnow())
        db.add(row)
        db.flush()
    return row


def offices(db: Session) -> list[TrackingOffice]:
    return list(db.scalars(select(TrackingOffice).order_by(TrackingOffice.name)))


def match_office(office_list: list[TrackingOffice], ip: str) -> TrackingOffice | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    for o in office_list:
        for n in o.networks or []:
            try:
                if addr in ipaddress.ip_network(n, strict=False):
                    return o
            except ValueError:
                continue
    return None


def devices_now(db: Session, now: datetime | None = None) -> dict[str, int]:
    """Office id -> computers currently there (latest location is in the office and the device checked in lately)."""
    since = (now or utcnow()) - ONLINE_WINDOW
    rows = db.execute(
        select(DeviceLocation.office_id, func.count(Device.id))
        .join(Device, Device.location_id == DeviceLocation.id)
        .where(DeviceLocation.office_id.is_not(None), Device.last_seen_at >= since, Device.status == "active")
        .group_by(DeviceLocation.office_id)).all()
    return {oid: n for oid, n in rows}


# ----------------------------------------------------------------------------- recording
def observe(db: Session, device: Device, now: datetime | None = None) -> None:
    """Record where the device was seen (its public address as the server saw it). Cheap when tracking is off and
    NEVER raises: a tracking problem must not fail a check-in or a command poll."""
    try:
        if not qualifies(device) or not device.last_ip:
            return
        org_id = device.organization_id
        st = db.get(DeviceTrackingSettings, org_id)
        if st is None or not st.enabled or not modules.has_module(db, modules.ENDPOINTS, org_id):
            return
        now = now or utcnow()
        geo = geoip.lookup(device.last_ip)
        with db.begin_nested():
            prev, cur, changed = _record(db, device, geo, now)
            missing.stamp_signed_in(db, device)
            _maybe_prune(db, org_id, now)
        _raise_alerts(db, device, st, prev, cur, changed, now)
        missing.on_contact(db, device, now)  # missing-device mode: reconnect alert (no-op otherwise)
    except Exception:
        log.exception("device tracking failed for device %s (ignored)", getattr(device, "id", "?"))


def _raise_alerts(db: Session, device: Device, st: DeviceTrackingSettings, prev, cur, changed: bool,
                  now: datetime) -> None:
    """Alerts (app/tracking/alerts.py) in their own savepoint: a failing alert never loses the location."""
    try:
        from . import alerts  # (imports this module)

        with db.begin_nested():
            alerts.on_observe(db, device, st, prev, cur, changed, now)
    except Exception:
        log.exception("device tracking alerts failed for device %s (ignored)", getattr(device, "id", "?"))


def _record(db: Session, device: Device, geo: geoip.GeoResult, now: datetime):
    """Returns (previous row, current row, changed): `changed` is True when a new history row was written."""
    office = match_office(offices(db), geo.ip)
    latest = db.get(DeviceLocation, device.location_id) if device.location_id else None
    if (latest is not None and latest.ip == geo.ip and latest.office_id == (office.id if office else None)
            and latest.city == geo.city and latest.country_code == geo.country_code):
        latest.last_seen_at = now
        return latest, latest, False
    row = DeviceLocation(device_id=device.id, first_seen_at=now, last_seen_at=now, ip=geo.ip[:64],
                         country_code=geo.country_code, country=geo.country, region=geo.region, city=geo.city,
                         latitude=geo.latitude, longitude=geo.longitude, accuracy_km=geo.accuracy_km, asn=geo.asn,
                         provider=(geo.provider or None) and geo.provider[:255],
                         office_id=office.id if office else None, is_private=geo.is_private)
    db.add(row)
    db.flush()
    device.location_id = row.id
    return latest, row, True


def prune(db: Session, now: datetime | None = None, days: int | None = None) -> int:
    """Delete history older than the retention (config DEVICE_LOCATION_RETENTION_DAYS); returns rows removed."""
    cutoff = (now or utcnow()) - timedelta(days=days or config.settings.device_location_retention_days)
    old = select(DeviceLocation.id).where(DeviceLocation.last_seen_at < cutoff)
    db.execute(update(Device).where(Device.location_id.in_(old)).values(location_id=None)
               .execution_options(synchronize_session=False))
    res = db.execute(delete(DeviceLocation).where(DeviceLocation.last_seen_at < cutoff)
                     .execution_options(synchronize_session=False))
    return res.rowcount or 0


def _maybe_prune(db: Session, org_id: str, now: datetime) -> None:
    t = time.monotonic()
    if t - _last_prune.get(org_id, -1e9) < PRUNE_EVERY_SECONDS:
        return
    _last_prune[org_id] = t
    prune(db, now)


# ----------------------------------------------------------------------------- views
def effective_timezone(db: Session, office: TrackingOffice | None) -> str:
    if office is not None and office.timezone:
        return office.timezone
    st = get_settings(db, create=False)
    return st.timezone if st else "UTC"


def network_kind(loc: DeviceLocation) -> str:
    return "office" if loc.office_id else ("private" if loc.is_private else "away")


def _view(loc: DeviceLocation, office_name: str | None, full: bool) -> dict[str, Any]:
    out: dict[str, Any] = {
        "first_seen_at": loc.first_seen_at, "last_seen_at": loc.last_seen_at, "city": loc.city,
        "country": loc.country, "country_code": loc.country_code, "is_private": loc.is_private,
        "network": network_kind(loc), "office": office_name}
    if full:
        out.update(region=loc.region, ip=loc.ip, latitude=loc.latitude, longitude=loc.longitude,
                   accuracy_km=loc.accuracy_km, asn=loc.asn, provider=loc.provider)
    return out


def device_location(db: Session, device: Device, *, days: int, full: bool) -> dict[str, Any]:
    """Current location and history events of one device. `full`=False (viewers): city and country only."""
    st = get_settings(db, create=False)
    retention = config.settings.device_location_retention_days
    days = max(1, min(days, retention))
    out: dict[str, Any] = {
        "enabled": bool(st and st.enabled), "eligible": qualifies(device), "detail": "full" if full else "basic",
        "timezone": st.timezone if st else "UTC", "tile_url": config.settings.map_tile_url,
        "retention_days": retention, "days": days, "database_available": geoip.database_available(),
        "current": None, "history": []}
    if not out["enabled"] or not out["eligible"]:
        return out
    names = {o.id: o for o in offices(db)}
    cur = db.get(DeviceLocation, device.location_id) if device.location_id else None
    if cur is not None:
        office = names.get(cur.office_id) if cur.office_id else None
        out["current"] = _view(cur, office.name if office else None, full)
        out["current"]["timezone"] = effective_timezone(db, office)
        if not geoip.database_available() and not cur.country_code and not cur.is_private:
            out["current"]["available"] = False
        else:
            out["current"]["available"] = True
    since = utcnow() - timedelta(days=days)
    rows = list(db.scalars(select(DeviceLocation).where(DeviceLocation.device_id == device.id)
                           .order_by(DeviceLocation.first_seen_at)))
    events: list[dict[str, Any]] = []
    prev: DeviceLocation | None = None
    for r in rows:
        kind = None
        if prev is None or r.office_id != prev.office_id:
            kind = "arrived" if r.office_id else ("private" if r.is_private else "away")
        if prev is not None and r.country_code and r.country_code != prev.country_code and not r.office_id:
            kind = "new_country"
        elif prev is not None and r.office_id == prev.office_id and not r.office_id and r.city != prev.city \
                and not r.is_private:
            kind = "away"
        prev = r
        if kind and r.first_seen_at >= since:
            o = names.get(r.office_id) if r.office_id else None
            ev = _view(r, o.name if o else None, full)
            ev["kind"] = kind
            ev["at"] = r.first_seen_at
            events.append(ev)
    from . import alerts  # (imports this module)

    events.extend(alerts.history_events(db, device, since))
    out["history"] = sorted(events, key=lambda e: e["at"], reverse=True)
    return out
