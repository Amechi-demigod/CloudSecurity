"""Device tracking API (docs/DEVICE_TRACKING.md). Module: Endpoints & servers; scoped to the session's organisation.

analyst : read settings, offices' names via the location view, "Locate now"
admin   : change settings, manage offices
viewer  : a device's location as city and country only (no internet address, coordinates or provider)
"""
from __future__ import annotations

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from sqlalchemy import update
from sqlalchemy.orm import Session

from .. import config, geoip, modules
from ..auth import ROLE_RANK, audit, client_ip, current_user, require_admin, require_analyst
from ..db import get_db
from ..geoip.countries import COUNTRIES
from ..models import Device, User
from ..services import devices as dev_svc
from . import service
from .models import DeviceLocation, DeviceTrackingSettings, TrackingOffice

router = APIRouter(prefix="/api/device-tracking", tags=["device-tracking"],
                   dependencies=[Depends(modules.require_module(modules.ENDPOINTS))])
device_router = APIRouter(prefix="/api/devices", tags=["device-tracking"],
                          dependencies=[Depends(modules.require_module(modules.ENDPOINTS))])
OfficeId = Path(pattern=r"^[0-9a-f]{32}$")
DeviceId = Path(pattern=r"^[0-9a-f]{32}$")
Tz = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
HHMM = Annotated[str, StringConstraints(pattern=r"^([01]\d|2[0-3]):[0-5]\d$")]


def _tz(v: str | None) -> str | None:
    if v is not None and not service.valid_timezone(v):
        raise ValueError("unknown time zone")
    return v


class SettingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    timezone: Tz | None = None
    allowed_countries: list[Annotated[str, StringConstraints(to_upper=True, min_length=2, max_length=2)]] | None = \
        Field(None, max_length=300)
    alert_outside_countries: bool | None = None
    alert_not_seen_days: int | None = Field(None, ge=1, le=365)
    alert_after_hours: bool | None = None
    after_hours_start: HHMM | None = None
    after_hours_end: HHMM | None = None
    after_hours_weekdays: list[Annotated[int, Field(ge=0, le=6)]] | None = Field(None, max_length=7)
    alert_hardware_changed: bool | None = None
    alert_agent_stopped: bool | None = None
    auto_lost_mode_outside_countries: bool | None = None

    _check_tz = field_validator("timezone")(_tz)

    @field_validator("allowed_countries")
    @classmethod
    def _countries(cls, v):
        if v is None:
            return v
        bad = [c for c in v if c not in COUNTRIES]
        if bad:
            raise ValueError(f"unknown country code: {bad[0]}")
        return sorted(set(v))


class OfficeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
    networks: list[Annotated[str, StringConstraints(strip_whitespace=True, max_length=64)]] = Field(max_length=200)
    timezone: Tz | None = None

    _check_tz = field_validator("timezone")(_tz)


class OfficePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)] | None = None
    networks: list[Annotated[str, StringConstraints(strip_whitespace=True, max_length=64)]] | None = \
        Field(None, max_length=200)
    timezone: Tz | None = None
    clear_timezone: bool = False

    _check_tz = field_validator("timezone")(_tz)


SETTING_FIELDS = ("enabled", "timezone", "allowed_countries", "alert_outside_countries", "alert_not_seen_days",
                  "alert_after_hours", "after_hours_start", "after_hours_end", "after_hours_weekdays",
                  "alert_hardware_changed", "alert_agent_stopped", "auto_lost_mode_outside_countries")


def _settings_out(st: DeviceTrackingSettings) -> dict:
    s = config.settings
    return {**{f: getattr(st, f) for f in SETTING_FIELDS}, "updated_by": st.updated_by, "updated_at": st.updated_at,
            "retention_days": s.device_location_retention_days, "tile_url": s.map_tile_url,
            "database_available": geoip.database_available()}


def _office_out(o: TrackingOffice, counts: dict[str, int]) -> dict:
    return {"id": o.id, "name": o.name, "networks": o.networks or [], "timezone": o.timezone,
            "devices_now": counts.get(o.id, 0), "created_at": o.created_at, "updated_at": o.updated_at}


@router.get("/settings")
def get_settings(_: User = Depends(require_analyst), db: Session = Depends(get_db)):
    st = service.get_settings(db)
    db.commit()
    return _settings_out(st)


@router.put("/settings")
def put_settings(body: SettingsIn, request: Request, admin: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    st = service.get_settings(db)
    changes: dict[str, list] = {}
    for f in SETTING_FIELDS:
        v = getattr(body, f)
        if v is None and f != "alert_not_seen_days":
            continue
        if f == "alert_not_seen_days" and f not in body.model_fields_set:
            continue
        if v != getattr(st, f):
            changes[f] = [getattr(st, f), v]
            setattr(st, f, v)
    if changes:
        st.updated_by, st.updated_at = admin.email, dev_svc.utcnow()
        audit(db, "device_tracking_settings_changed", actor=admin, target="device-tracking", ip=client_ip(request),
              changes=changes)
    db.commit()
    return _settings_out(st)


@router.get("/countries")
def countries():
    return [{"code": c, "name": n} for c, n in sorted(COUNTRIES.items(), key=lambda kv: kv[1])]


@router.get("/offices")
def list_offices(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    counts = service.devices_now(db)
    return [_office_out(o, counts) for o in service.offices(db)]


def _clean_networks(values: list[str]) -> list[str]:
    try:
        return service.normalize_networks(values)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None


def _name_taken(db: Session, name: str, except_id: str | None = None) -> bool:
    return any(o.name.lower() == name.lower() and o.id != except_id for o in service.offices(db))


@router.post("/offices", status_code=201)
def create_office(body: OfficeIn, request: Request, admin: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    if _name_taken(db, body.name):
        raise HTTPException(409, "an office with this name already exists")
    o = TrackingOffice(name=body.name, networks=_clean_networks(body.networks), timezone=body.timezone)
    db.add(o)
    db.flush()
    audit(db, "tracking_office_created", actor=admin, target=f"tracking-office:{o.id}", ip=client_ip(request),
          name=o.name, networks=o.networks, timezone=o.timezone)
    db.commit()
    return _office_out(o, {})


def _get_office(db: Session, office_id: str) -> TrackingOffice:
    o = db.get(TrackingOffice, office_id)
    if o is None:
        raise HTTPException(404, "office not found")
    return o


@router.patch("/offices/{office_id}")
def patch_office(body: OfficePatch, request: Request, office_id: str = OfficeId, admin: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    o = _get_office(db, office_id)
    changes: dict[str, list] = {}
    if body.name is not None and body.name != o.name:
        if _name_taken(db, body.name, o.id):
            raise HTTPException(409, "an office with this name already exists")
        changes["name"], o.name = [o.name, body.name], body.name
    if body.networks is not None:
        nets = _clean_networks(body.networks)
        if nets != o.networks:
            changes["networks"], o.networks = [o.networks, nets], nets
    tz = None if body.clear_timezone else body.timezone
    if (body.clear_timezone or body.timezone is not None) and tz != o.timezone:
        changes["timezone"], o.timezone = [o.timezone, tz], tz
    if changes:
        o.updated_at = dev_svc.utcnow()
        audit(db, "tracking_office_changed", actor=admin, target=f"tracking-office:{o.id}", ip=client_ip(request),
              name=o.name, changes=changes)
    db.commit()
    return _office_out(o, service.devices_now(db))


@router.delete("/offices/{office_id}", status_code=204)
def delete_office(request: Request, office_id: str = OfficeId, admin: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    o = _get_office(db, office_id)
    db.execute(update(DeviceLocation).where(DeviceLocation.office_id == o.id).values(office_id=None)
               .execution_options(synchronize_session=False))
    audit(db, "tracking_office_deleted", actor=admin, target=f"tracking-office:{o.id}", ip=client_ip(request),
          name=o.name)
    db.delete(o)
    db.commit()


# ----------------------------------------------------------------------------- per device
def _device(db: Session, device_id: str) -> Device:
    d = db.get(Device, device_id)
    if d is None:
        raise HTTPException(404, "device not found")
    return d


@device_router.get("/{device_id}/location")
def device_location(device_id: str = DeviceId, days: int = Query(7, ge=1, le=3650),
                    user: User = Depends(current_user), db: Session = Depends(get_db)):
    d = _device(db, device_id)
    full = ROLE_RANK.get(user.role, -1) >= ROLE_RANK["analyst"]
    return service.device_location(db, d, days=days, full=full)


@device_router.post("/{device_id}/location/refresh", status_code=202)
def locate_now(request: Request, device_id: str = DeviceId, user: User = Depends(require_analyst),
               db: Session = Depends(get_db)):
    d = _device(db, device_id)
    st = service.get_settings(db, create=False)
    if not (st and st.enabled):
        raise HTTPException(409, "device tracking is off")
    if not service.qualifies(d):
        raise HTTPException(409, "location tracking is for Windows and macOS laptops and desktops only")
    cmd = dev_svc.new_command(db, d, "recheck_posture", {}, "Locate now", requested_by_id=user.id,
                              requested_by_email=user.email,
                              ttl=timedelta(hours=config.settings.device_command_ttl_hours))
    audit(db, "device_command_created", actor=user, target=f"device:{d.id}", ip=client_ip(request),
          hostname=d.hostname, command_id=cmd.id, type=cmd.type, params={}, reason="Locate now")
    db.commit()
    return {"command_id": cmd.id, "status": "queued"}

