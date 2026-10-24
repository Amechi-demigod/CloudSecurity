"""IT asset lifecycle domain logic: settings, agent-device sync, custody events,
assignment / return / status / disposal / offboarding, utilization and the
dashboard summary. API handlers (api.py) call these and add the audit record."""
from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import config, tenancy
from ..models import Device, utcnow
from .models import ItAsset, ItAssetEvent, ItAssetOffboarding, ItAssetSettings

log = logging.getLogger(__name__)

SYSTEM = "system"
# Statuses in which an asset is still "in the fleet" (counted for value, warranty, idle).
INACTIVE_STATUSES = frozenset({"disposed", "lost", "stolen"})
# Statuses from which an asset can be (re)assigned.
ASSIGNABLE_FROM = frozenset({"in_stock", "assigned", "in_repair", "retrieved"})
# Statuses whose holder must return the asset when they leave.
HELD_STATUSES = frozenset({"assigned", "in_repair"})


class AssetError(ValueError):
    """A request that conflicts with the asset's current state (HTTP 409)."""


# --------------------------------------------------------------------------- settings
def settings_row(db: Session) -> ItAssetSettings:
    oid = tenancy.require_org(db)
    row = db.get(ItAssetSettings, oid)
    if row is None:
        row = ItAssetSettings(organization_id=oid, data={})
        db.add(row)
        try:
            db.flush()
        except IntegrityError:  # created concurrently
            db.rollback()
            row = db.get(ItAssetSettings, oid)
    return row


def get_settings(db: Session) -> dict[str, Any]:
    """Effective settings: stored overrides on top of the ASSET_* env defaults."""
    s = config.settings
    row = db.get(ItAssetSettings, tenancy.require_org(db))
    stored = (row.data if row else {}) or {}
    return {
        "default_currency": stored.get("default_currency") or s.asset_default_currency,
        "locations": list(stored.get("locations") or []),
        "custom_fields": list(stored.get("custom_fields") or []),
        "idle_days": int(stored.get("idle_days") or s.asset_idle_days),
        "warranty_warning_days": int(stored.get("warranty_warning_days") or s.asset_warranty_warning_days),
        "retrieval_due_days": int(stored["retrieval_due_days"]) if stored.get("retrieval_due_days") is not None
        else s.asset_retrieval_due_days,
        "certificate_max_bytes": s.asset_certificate_max_bytes,
        "import_max_bytes": s.asset_import_max_bytes,
        "import_max_rows": s.asset_import_max_rows,
    }


def today() -> date:
    return utcnow().date()


# --------------------------------------------------------------------------- events
def record(db: Session, asset: ItAsset, event_type: str, actor: str | None, *, notes: str = "",
           from_status: str | None = None, to_status: str | None = None, from_assignee: str | None = None,
           to_assignee: str | None = None, **detail: Any) -> ItAssetEvent:
    ev = ItAssetEvent(asset_id=asset.id, at=utcnow(), actor_email=actor, event_type=event_type, notes=notes or "",
                      from_status=from_status, to_status=to_status, from_assignee=from_assignee or None,
                      to_assignee=to_assignee or None, detail=_jsonable(detail))
    db.add(ev)
    return ev


def _jsonable(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, list | tuple):
        return [_jsonable(x) for x in v]
    if isinstance(v, date | datetime):
        return v.isoformat()
    if isinstance(v, Decimal):
        return str(v)
    return v


# --------------------------------------------------------------------------- utilization
def is_idle(device: Device | None, now: datetime, idle_days: int) -> bool:
    """An agent device not seen for `idle_days` (or never, if enrolled that long ago)."""
    if device is None or device.status != "active":
        return False
    seen = device.last_seen_at or device.enrolled_at
    return seen is not None and now - seen > timedelta(days=idle_days)


def warranty_expiring(asset: ItAsset, on: date, days: int) -> bool:
    return (asset.status not in INACTIVE_STATUSES and asset.warranty_end is not None
            and on <= asset.warranty_end <= on + timedelta(days=days))


def retrieval_overdue(asset: ItAsset, on: date) -> bool:
    return asset.status == "retrieval_pending" and asset.retrieval_due is not None and asset.retrieval_due < on


def to_out(asset: ItAsset, device: Device | None, st: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    on = now.date()
    return {
        **{c.name: getattr(asset, c.name) for c in ItAsset.__table__.columns},
        "purchase_cost": float(asset.purchase_cost) if asset.purchase_cost is not None else None,
        "custom_fields": dict(asset.custom_fields or {}),
        "device_hostname": device.hostname if device else None,
        "device_last_seen_at": device.last_seen_at if device else None,
        "idle": asset.status not in INACTIVE_STATUSES and is_idle(device, now, st["idle_days"]),
        "warranty_expiring": warranty_expiring(asset, on, st["warranty_warning_days"]),
        "retrieval_overdue": retrieval_overdue(asset, on),
    }


def devices_for(db: Session, assets: list[ItAsset]) -> dict[str, Device]:
    ids = [a.device_id for a in assets if a.device_id]
    if not ids:
        return {}
    out: dict[str, Device] = {}
    for i in range(0, len(ids), 500):
        out.update({d.id: d for d in db.scalars(select(Device).where(Device.id.in_(ids[i:i + 500])))})
    return out


# --------------------------------------------------------------------------- agent device sync
_LAPTOP = re.compile(r"macbook|laptop|notebook|thinkpad|latitude|xps|elitebook|probook|zbook|surface (laptop|book|pro)"
                     r"|yoga|ideapad|vivobook|zenbook|spectre|envy|pavilion x|precision \d{4}|inspiron 1[3-7]", re.I)
_DESKTOP = re.compile(r"imac|mac ?mini|mac ?pro|mac ?studio|optiplex|thinkcentre|elitedesk|prodesk|vostro \d+ desktop"
                      r"|desktop|tower|workstation|all-in-one", re.I)


def guess_type(manufacturer: str, model: str) -> str:
    text = f"{manufacturer} {model}"
    if _LAPTOP.search(text):
        return "laptop"
    if _DESKTOP.search(text):
        return "desktop"
    return "computer"


def _auto_tag(db: Session, device: Device) -> str:
    base = f"AGT-{device.id[:8].upper()}"
    tag, n = base, 1
    while db.scalar(select(func.count()).select_from(ItAsset).where(ItAsset.asset_tag == tag)):
        n += 1
        tag = f"{base}-{n}"
    return tag


def sync_devices(db: Session, *, limit: int = 2000) -> int:
    """Give every enrolled agent device an asset record and fill blanks from its inventory.

    * A device without an asset is linked to an existing unlinked asset with the
      same serial number (e.g. a laptop added by hand before it was enrolled),
      otherwise a new asset is created (status in_stock, source agent).
    * Serial, make and model are copied into empty asset fields.
    Commits; safe to run concurrently (a duplicate link loses the unique constraint race)."""
    linked = select(ItAsset.device_id).where(ItAsset.device_id.is_not(None))
    devices = list(db.scalars(select(Device).where(Device.id.not_in(linked)).order_by(Device.enrolled_at).limit(limit)))
    created = 0
    for d in devices:
        serial = (d.serial_number or "").strip()
        asset = None
        if serial:
            asset = db.scalars(select(ItAsset).where(func.lower(ItAsset.serial_number) == serial.lower(),
                                                     ItAsset.device_id.is_(None)).limit(1)).first()
        try:
            if asset is not None:
                asset.device_id = d.id
                asset.updated_at = utcnow()
                _fill_from_device(asset, d)
                record(db, asset, "device_linked", SYSTEM, notes=f"matched agent device {d.hostname} by serial number",
                       device_id=d.id, hostname=d.hostname)
            else:
                asset = ItAsset(asset_tag=_auto_tag(db, d), device_id=d.id, source="agent", status="in_stock",
                                asset_type=guess_type(d.manufacturer, d.model), serial_number=serial[:128],
                                manufacturer=(d.manufacturer or "")[:128], model=(d.model or "")[:128],
                                currency=get_settings(db)["default_currency"], custom_fields={},
                                created_by=SYSTEM, created_at=utcnow(), updated_at=utcnow())
                db.add(asset)
                db.flush()
                record(db, asset, "created", SYSTEM, to_status="in_stock",
                       notes=f"created from agent device {d.hostname}", device_id=d.id, hostname=d.hostname)
                created += 1
            db.commit()
        except IntegrityError:
            db.rollback()  # another request linked it first
    # Fill blanks of linked assets (serial may only arrive with a later check-in).
    rows = db.execute(select(ItAsset, Device).join(Device, Device.id == ItAsset.device_id)
                      .where(or_(ItAsset.serial_number == "", ItAsset.manufacturer == "", ItAsset.model == ""))
                      .limit(limit)).all()
    changed = False
    for asset, d in rows:
        changed |= _fill_from_device(asset, d)
    if changed:
        db.commit()
    return created


def _fill_from_device(asset: ItAsset, d: Device) -> bool:
    changed = False
    for field, value in (("serial_number", d.serial_number), ("manufacturer", d.manufacturer), ("model", d.model)):
        value = (value or "").strip()[:128]
        if value and not getattr(asset, field):
            setattr(asset, field, value)
            changed = True
    return changed


# --------------------------------------------------------------------------- validation helpers
def check_custom_fields(values: dict[str, str], st: dict[str, Any]) -> None:
    allowed = {d["key"] for d in st["custom_fields"]}
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise ValueError(f"unknown custom field(s): {', '.join(unknown)} (define them under IT assets > Settings)")


def check_dates(purchase_date: date | None, warranty_end: date | None, refresh_date: date | None) -> None:
    if purchase_date and purchase_date > today() + timedelta(days=366):
        raise ValueError("purchase date is too far in the future")
    for name, d in (("purchase_date", purchase_date), ("warranty_end", warranty_end), ("refresh_date", refresh_date)):
        if d is not None and not (date(1990, 1, 1) <= d <= date(2100, 12, 31)):
            raise ValueError(f"{name} must be between 1990-01-01 and 2100-12-31")
    if purchase_date and warranty_end and warranty_end < purchase_date:
        raise ValueError("warranty end is before the purchase date")


# --------------------------------------------------------------------------- lifecycle actions
def assign(db: Session, asset: ItAsset, actor: str, *, name: str, email: str, department: str, notes: str) -> None:
    if asset.status not in ASSIGNABLE_FROM:
        raise AssetError(f"an asset that is {asset.status.replace('_', ' ')} cannot be assigned")
    prev_status, prev_owner = asset.status, asset.assignee_email
    asset.assignee_name, asset.assignee_email = name, email
    if department or prev_owner != email:
        asset.assignee_department = department
    asset.assigned_at = utcnow()
    asset.status = "assigned"
    asset.retrieval_due = None
    asset.offboarding_id = None
    asset.updated_at = utcnow()
    record(db, asset, "assigned", actor, notes=notes, from_status=prev_status, to_status="assigned",
           from_assignee=prev_owner, to_assignee=email, assignee_name=name, department=asset.assignee_department)


def return_asset(db: Session, asset: ItAsset, actor: str, *, notes: str, status: str | None,
                 location: str | None) -> None:
    if asset.status not in {"assigned", "retrieval_pending", "in_repair", "lost", "stolen"}:
        raise AssetError(f"an asset that is {asset.status.replace('_', ' ')} cannot be returned")
    if asset.status in {"in_repair"} and not asset.assignee_email:
        raise AssetError("this asset is not assigned to anyone")
    prev_status, prev_owner = asset.status, asset.assignee_email
    new = status or ("retrieved" if prev_status == "retrieval_pending" else "in_stock")
    offboarding_id = asset.offboarding_id
    asset.status = new
    asset.assignee_name = asset.assignee_email = asset.assignee_department = ""
    asset.assigned_at = None
    asset.retrieval_due = None
    if location is not None:
        asset.location = location
    asset.updated_at = utcnow()
    record(db, asset, "returned", actor, notes=notes, from_status=prev_status, to_status=new,
           from_assignee=prev_owner, offboarding_id=offboarding_id)
    if offboarding_id:
        db.flush()
        _maybe_complete_offboarding(db, offboarding_id)


def change_status(db: Session, asset: ItAsset, actor: str, *, status: str, notes: str,
                  retrieval_due: date | None) -> None:
    if asset.status == "disposed":
        raise AssetError("a disposed asset cannot change status")
    if status == asset.status and status != "retrieval_pending":
        raise AssetError(f"the asset is already {status.replace('_', ' ')}")
    prev_status, prev_owner = asset.status, asset.assignee_email
    if status == "retrieval_pending":
        if not asset.assignee_email:
            raise AssetError("only an assigned asset can be marked for retrieval")
        asset.retrieval_due = retrieval_due or today() + timedelta(days=get_settings(db)["retrieval_due_days"])
    else:
        asset.retrieval_due = None
    if status in {"in_stock", "retrieved"}:
        asset.assignee_name = asset.assignee_email = asset.assignee_department = ""
        asset.assigned_at = None
    asset.status = status
    asset.updated_at = utcnow()
    offboarding_id = asset.offboarding_id
    record(db, asset, "status_changed", actor, notes=notes, from_status=prev_status, to_status=status,
           from_assignee=prev_owner, to_assignee=asset.assignee_email or None,
           retrieval_due=asset.retrieval_due)
    if status in {"lost", "stolen"}:
        from ..notifications import asset_lifecycle_source

        asset_lifecycle_source.lost_or_stolen(db, asset, actor, notes)
    if offboarding_id and status != "retrieval_pending":
        db.flush()
        _maybe_complete_offboarding(db, offboarding_id)


def dispose(db: Session, asset: ItAsset, actor: str, *, method: str, disposal_date: date, vendor: str,
            notes: str) -> None:
    if asset.status == "disposed":
        raise AssetError("the asset is already disposed")
    if asset.status in {"assigned", "retrieval_pending"}:
        raise AssetError("return or retrieve the asset before disposing of it")
    if disposal_date > today() + timedelta(days=1):
        raise ValueError("disposal date cannot be in the future")
    if asset.purchase_date and disposal_date < asset.purchase_date:
        raise ValueError("disposal date is before the purchase date")
    prev_status = asset.status
    asset.status = "disposed"
    asset.disposal_method, asset.disposal_date = method, disposal_date
    asset.disposal_vendor, asset.disposal_notes = vendor, notes
    asset.assignee_name = asset.assignee_email = asset.assignee_department = ""
    asset.assigned_at = asset.retrieval_due = None
    asset.updated_at = utcnow()
    record(db, asset, "disposed", actor, notes=notes, from_status=prev_status, to_status="disposed",
           method=method, disposal_date=disposal_date, vendor=vendor)


def start_offboarding(db: Session, actor: str, *, email: str, name: str, department: str, leave_date: date,
                      retrieval_due: date | None, notes: str) -> tuple[ItAssetOffboarding, list[ItAsset]]:
    if db.scalar(select(func.count()).select_from(ItAssetOffboarding).where(
            ItAssetOffboarding.person_email == email, ItAssetOffboarding.status == "open")):
        raise AssetError(f"{email} already has an open offboarding")
    st = get_settings(db)
    due = retrieval_due or leave_date + timedelta(days=st["retrieval_due_days"])
    if due < leave_date - timedelta(days=60):
        raise ValueError("retrieval due date is long before the leave date")
    assets = list(db.scalars(select(ItAsset).where(func.lower(ItAsset.assignee_email) == email,
                                                   ItAsset.status.in_(HELD_STATUSES))))
    if not name and assets:
        name = assets[0].assignee_name
    if not department and assets:
        department = assets[0].assignee_department
    ob = ItAssetOffboarding(person_email=email, person_name=name, department=department, leave_date=leave_date,
                            retrieval_due=due, notes=notes, created_by=actor, created_at=utcnow(),
                            status="open" if assets else "completed", closed_at=None if assets else utcnow())
    db.add(ob)
    db.flush()
    for a in assets:
        prev = a.status
        a.status, a.retrieval_due, a.offboarding_id, a.updated_at = "retrieval_pending", due, ob.id, utcnow()
        record(db, a, "offboarding", actor, notes=notes, from_status=prev, to_status="retrieval_pending",
               from_assignee=a.assignee_email, to_assignee=a.assignee_email, offboarding_id=ob.id,
               leave_date=leave_date, retrieval_due=due)
    return ob, assets


def cancel_offboarding(db: Session, ob: ItAssetOffboarding, actor: str, notes: str) -> int:
    if ob.status != "open":
        raise AssetError(f"the offboarding is already {ob.status}")
    n = 0
    for a in db.scalars(select(ItAsset).where(ItAsset.offboarding_id == ob.id, ItAsset.status == "retrieval_pending")):
        a.status, a.retrieval_due, a.offboarding_id, a.updated_at = "assigned", None, None, utcnow()
        record(db, a, "offboarding_cancelled", actor, notes=notes, from_status="retrieval_pending",
               to_status="assigned", from_assignee=a.assignee_email, to_assignee=a.assignee_email,
               offboarding_id=ob.id)
        n += 1
    ob.status, ob.closed_at = "cancelled", utcnow()
    return n


def _maybe_complete_offboarding(db: Session, offboarding_id: str) -> None:
    ob = db.get(ItAssetOffboarding, offboarding_id)
    if ob is None or ob.status != "open":
        return
    outstanding = db.scalar(select(func.count()).select_from(ItAsset).where(
        ItAsset.offboarding_id == offboarding_id, ItAsset.status == "retrieval_pending"))
    if not outstanding:
        ob.status, ob.closed_at = "completed", utcnow()


def offboarding_counts(db: Session, ids: list[str]) -> dict[str, tuple[int, int]]:
    """offboarding id -> (assets linked, assets still pending)."""
    if not ids:
        return {}
    wanted = set(ids)
    pending: Counter[str] = Counter()
    rows = db.execute(select(ItAsset.offboarding_id, func.count()).where(
        ItAsset.offboarding_id.in_(ids), ItAsset.status == "retrieval_pending").group_by(ItAsset.offboarding_id))
    for oid, n in rows:
        pending[oid] = n
    # Total = assets put into retrieval by the offboarding (from the custody history:
    # an asset reassigned later is no longer linked to it).
    total: Counter[str] = Counter()
    for (detail,) in db.execute(select(ItAssetEvent.detail).where(ItAssetEvent.event_type == "offboarding")):
        oid = (detail or {}).get("offboarding_id")
        if oid in wanted:
            total[oid] += 1
    return {i: (total[i], pending[i]) for i in ids}


# --------------------------------------------------------------------------- dashboard
def summary(db: Session) -> dict[str, Any]:
    st = get_settings(db)
    now = utcnow()
    on = now.date()
    assets = list(db.scalars(select(ItAsset)))
    devices = devices_for(db, assets)
    by_status = Counter(a.status for a in assets)
    by_type = Counter(a.asset_type for a in assets if a.status not in INACTIVE_STATUSES)
    value: dict[str, Decimal] = defaultdict(Decimal)
    for a in assets:
        if a.status not in INACTIVE_STATUSES and a.purchase_cost is not None:
            value[a.currency] += a.purchase_cost
    expiring = sorted((a for a in assets if warranty_expiring(a, on, st["warranty_warning_days"])),
                      key=lambda a: a.warranty_end)
    overdue = sorted((a for a in assets if retrieval_overdue(a, on)), key=lambda a: a.retrieval_due)
    idle = [a for a in assets if a.status not in INACTIVE_STATUSES and is_idle(devices.get(a.device_id or ""), now,
                                                                                    st["idle_days"])]
    refresh_due = [a for a in assets if a.status not in INACTIVE_STATUSES and a.refresh_date
                   and a.refresh_date <= on + timedelta(days=90)]

    def brief(a: ItAsset) -> dict[str, Any]:
        d = devices.get(a.device_id or "")
        return {"id": a.id, "asset_tag": a.asset_tag, "asset_type": a.asset_type, "model": a.model,
                "assignee_name": a.assignee_name, "assignee_email": a.assignee_email,
                "warranty_end": a.warranty_end, "retrieval_due": a.retrieval_due,
                "device_hostname": d.hostname if d else None, "device_last_seen_at": d.last_seen_at if d else None}

    return {
        "total": len(assets),
        "active": sum(1 for a in assets if a.status not in INACTIVE_STATUSES),
        "by_status": {s: by_status.get(s, 0) for s in
                      ("in_stock", "assigned", "in_repair", "retrieval_pending", "retrieved", "lost", "stolen",
                       "disposed")},
        "by_type": dict(by_type.most_common()),
        "with_agent": sum(1 for a in assets if a.device_id),
        "value_by_currency": {k: float(v) for k, v in sorted(value.items())},
        "default_currency": st["default_currency"],
        "warranty_warning_days": st["warranty_warning_days"],
        "idle_days": st["idle_days"],
        "warranty_expiring": len(expiring),
        "warranty_expiring_assets": [brief(a) for a in expiring[:10]],
        "retrieval_overdue": len(overdue),
        "retrieval_overdue_assets": [brief(a) for a in overdue[:10]],
        "idle": len(idle),
        "idle_assets": [brief(a) for a in idle[:10]],
        "refresh_due_90d": len(refresh_due),
    }
