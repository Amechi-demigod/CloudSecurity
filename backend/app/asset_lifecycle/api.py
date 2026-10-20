"""IT asset lifecycle API (/api/it-assets/*), session-authenticated with RBAC.

viewer  : read everything (list, dashboard, detail, custody timeline,
          offboardings, settings), CSV export
analyst : + create / edit assets, assign, return, change status, offboard
          people, dispose, upload and download certificates, CSV import
admin   : + settings (sites, custom fields, currency, thresholds), delete
          assets and certificates

Every change is written to the asset's custody timeline and the audit log.
"""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Path, Query, Request, Response
from pydantic import ValidationError
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..auth import audit, client_ip, require_admin, require_analyst, require_viewer
from ..db import get_db
from ..models import Device, User, utcnow
from . import csvio
from . import service as svc
from .models import ASSET_STATUSES, ASSET_TYPES, DISPOSAL_METHODS, ItAsset, ItAssetCertificate, ItAssetEvent, ItAssetOffboarding
from .schemas import (
    AssetCreate,
    AssetOut,
    AssetUpdate,
    AssignIn,
    CancelIn,
    CertificateOut,
    DisposeIn,
    EventOut,
    OffboardingIn,
    OffboardingOut,
    ReturnIn,
    SettingsIn,
    StatusIn,
    clean_email,
    clean_text,
)

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/it-assets", tags=["it-assets"], dependencies=[Depends(require_viewer)])
def Id32():  # noqa: N802 - a fresh Path() per parameter (FastAPI binds it to the name)
    return Path(pattern=r"^[0-9a-f]{32}$")
UPLOAD_PREFIXES = ("/api/it-assets/import", "/api/it-assets/certificates/")

# Accepted certificate types: declared Content-Type -> magic bytes.
CERT_TYPES = {
    "application/pdf": (b"%PDF-",),
    "image/png": (b"\x89PNG\r\n\x1a\n",),
    "image/jpeg": (b"\xff\xd8\xff",),
}
CERT_EXT = {"application/pdf": ".pdf", "image/png": ".png", "image/jpeg": ".jpg"}
_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._ -]+")


def _get(db: Session, asset_id: str) -> ItAsset:
    a = db.get(ItAsset, asset_id)
    if a is None:
        raise HTTPException(404, "asset not found")
    return a


def _out(db: Session, a: ItAsset) -> dict[str, Any]:
    device = db.get(Device, a.device_id) if a.device_id else None
    return svc.to_out(a, device, svc.get_settings(db))


def _conflict(e: Exception) -> HTTPException:
    return HTTPException(409 if isinstance(e, svc.AssetError) else 422, str(e))


def _target(a: ItAsset) -> str:
    return f"it-asset:{a.id}"


# ----------------------------------------------------------------------------- list / dashboard
def _filtered(db: Session, *, q: str | None, status: str | None, asset_type: str | None, location: str | None,
              assignee: str | None, department: str | None, agent: str | None) -> list[ItAsset]:
    stmt = select(ItAsset)
    if status == "active":
        stmt = stmt.where(ItAsset.status.not_in(svc.INACTIVE_STATUSES))
    elif status:
        stmt = stmt.where(ItAsset.status == status)
    if asset_type:
        stmt = stmt.where(ItAsset.asset_type == asset_type)
    if location:
        stmt = stmt.where(ItAsset.location == location)
    if assignee:
        stmt = stmt.where(func.lower(ItAsset.assignee_email) == assignee.strip().lower())
    if department:
        stmt = stmt.where(func.lower(ItAsset.assignee_department) == department.strip().lower())
    if agent == "yes":
        stmt = stmt.where(ItAsset.device_id.is_not(None))
    elif agent == "no":
        stmt = stmt.where(ItAsset.device_id.is_(None))
    if q:
        like = f"%{q.strip().lower()}%"
        hosts = select(Device.id).where(func.lower(Device.hostname).like(like))
        stmt = stmt.where(or_(func.lower(ItAsset.asset_tag).like(like), func.lower(ItAsset.serial_number).like(like),
                              func.lower(ItAsset.model).like(like), func.lower(ItAsset.manufacturer).like(like),
                              func.lower(ItAsset.assignee_name).like(like),
                              func.lower(ItAsset.assignee_email).like(like),
                              func.lower(ItAsset.location).like(like), ItAsset.device_id.in_(hosts)))
    return list(db.scalars(stmt.order_by(ItAsset.asset_tag)))


def _list_filters(q: str | None = Query(None, max_length=255),
                  status: str | None = Query(None, pattern="^(active|" + "|".join(ASSET_STATUSES) + ")$"),
                  type: str | None = Query(None, pattern="^(" + "|".join(ASSET_TYPES) + ")$"),
                  location: str | None = Query(None, max_length=128),
                  assignee: str | None = Query(None, max_length=320),
                  department: str | None = Query(None, max_length=128),
                  agent: str | None = Query(None, pattern="^(yes|no)$"),
                  flag: str | None = Query(None, pattern="^(idle|warranty_expiring|retrieval_overdue)$")) -> dict:
    return {"q": q, "status": status, "asset_type": type, "location": location, "assignee": assignee,
            "department": department, "agent": agent, "flag": flag}


def _rows(db: Session, f: dict) -> list[dict[str, Any]]:
    svc.sync_devices(db)
    flag = f.pop("flag", None)
    assets = _filtered(db, **f)
    devices = svc.devices_for(db, assets)
    st = svc.get_settings(db)
    now = utcnow()
    out = [svc.to_out(a, devices.get(a.device_id or ""), st, now) for a in assets]
    if flag:
        out = [r for r in out if r[flag]]
    return out


@router.get("", response_model=list[AssetOut])
def list_assets(f: dict = Depends(_list_filters), limit: int = Query(1000, ge=1, le=10000),
                offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    return _rows(db, f)[offset:offset + limit]


@router.get("/summary")
def asset_summary(db: Session = Depends(get_db)):
    svc.sync_devices(db)
    return svc.summary(db)


@router.get("/export.csv")
def export_assets(request: Request, f: dict = Depends(_list_filters), user: User = Depends(require_viewer),
                  db: Session = Depends(get_db)):
    rows = _rows(db, dict(f))
    ids = [r["id"] for r in rows]
    assets = {a.id: a for a in db.scalars(select(ItAsset).where(ItAsset.id.in_(ids)))} if ids else {}
    devices = svc.devices_for(db, list(assets.values()))
    keys = [d["key"] for d in svc.get_settings(db)["custom_fields"]]
    body = csvio.export_csv([(assets[i], devices.get(assets[i].device_id or "")) for i in ids], keys)
    audit(db, "it_assets_exported", actor=user, ip=client_ip(request), rows=len(ids),
          filters={k: v for k, v in f.items() if v})
    db.commit()
    return Response(content=body.encode("utf-8"), media_type="text/csv; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="it-assets-{utcnow():%Y%m%d}.csv"'})


@router.get("/by-device/{device_id}", response_model=AssetOut)
def asset_for_device(device_id: str = Id32, db: Session = Depends(get_db)):
    svc.sync_devices(db)
    a = db.scalars(select(ItAsset).where(ItAsset.device_id == device_id)).first()
    if a is None:
        raise HTTPException(404, "no asset record for this device")
    return _out(db, a)


# ----------------------------------------------------------------------------- settings
@router.get("/settings")
def get_settings(db: Session = Depends(get_db)):
    st = svc.get_settings(db)
    return {**st, "statuses": list(ASSET_STATUSES), "types": list(ASSET_TYPES),
            "disposal_methods": list(DISPOSAL_METHODS), "certificate_types": list(CERT_TYPES)}


@router.put("/settings")
def put_settings(body: SettingsIn, request: Request, admin: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    row = svc.settings_row(db)
    before = dict(row.data or {})
    data = dict(before)
    changes = body.model_dump(exclude_unset=True)
    if "custom_fields" in changes and changes["custom_fields"] is not None:
        changes["custom_fields"] = [{"key": d["key"], "label": d["label"]} for d in changes["custom_fields"]]
    for k, v in changes.items():
        if v is None:
            data.pop(k, None)  # back to the env default
        else:
            data[k] = v
    row.data, row.updated_by, row.updated_at = data, admin.email, utcnow()
    audit(db, "it_asset_settings_updated", actor=admin, target="it-asset-settings", ip=client_ip(request),
          before=before, after=data)
    db.commit()
    return get_settings(db)


# ----------------------------------------------------------------------------- CSV import
@router.post("/import")
def import_assets(request: Request, data: bytes = Body(..., media_type="text/csv"),
                  dry_run: bool = Query(False), user: User = Depends(require_analyst),
                  db: Session = Depends(get_db)):
    """Create or update assets from CSV (matched by asset_tag). All-or-nothing:
    any invalid row rejects the whole file (422 with per-row errors). Empty cells
    leave existing values unchanged. `dry_run=true` only validates."""
    st = svc.get_settings(db)
    if len(data) > st["import_max_bytes"]:
        raise HTTPException(413, f"CSV file exceeds {st['import_max_bytes']} bytes")
    try:
        headers, rows = csvio.parse_csv(data, st["import_max_rows"])
    except csvio.CsvError as e:
        raise HTTPException(422, str(e)) from None
    defined = {d["key"] for d in st["custom_fields"]}
    bad_custom = [h for h in headers if h.startswith(csvio.CUSTOM_PREFIX) and h[len(csvio.CUSTOM_PREFIX):] not in defined]
    if bad_custom:
        raise HTTPException(422, f"undefined custom field column(s): {', '.join(bad_custom)}")
    errors: list[dict[str, Any]] = []
    created = updated = unchanged = 0
    seen: set[str] = set()
    now = utcnow()
    for i, row in enumerate(rows, start=2):
        try:
            result = _import_row(db, row, st, user.email, seen)
        except (ValueError, ValidationError, svc.AssetError) as e:
            msg = "; ".join(f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in e.errors()) \
                if isinstance(e, ValidationError) else str(e)
            errors.append({"row": i, "asset_tag": row.get("asset_tag", ""), "error": msg[:500]})
            if len(errors) >= 200:
                break
            continue
        created += result == "created"
        updated += result == "updated"
        unchanged += result == "unchanged"
    summary = {"rows": len(rows), "created": created, "updated": updated, "unchanged": unchanged,
               "errors": errors, "dry_run": dry_run or bool(errors)}
    if errors or dry_run:
        db.rollback()
        if errors:
            raise HTTPException(422, {"message": f"{len(errors)} row(s) have errors; nothing was imported",
                                      **summary})
        return summary
    audit(db, "it_assets_imported", actor=user, ip=client_ip(request), rows=len(rows), created=created,
          updated=updated, sha256=hashlib.sha256(data).hexdigest(), at=now.isoformat() + "Z")
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "the import conflicts with a concurrent change; try again") from None
    return summary


def _import_row(db: Session, row: dict[str, str], st: dict, actor: str, seen: set[str]) -> str:
    tag = row.get("asset_tag", "").strip()
    if not tag:
        raise ValueError("asset_tag is required")
    if tag.lower() in seen:
        raise ValueError(f"asset tag {tag} appears more than once in the file")
    seen.add(tag.lower())
    fields: dict[str, Any] = {}
    for col in ("serial_number", "asset_type", "manufacturer", "model", "location", "supplier", "currency", "notes",
                "assignee_department"):
        if row.get(col):
            fields[col] = row[col]
    for col in ("purchase_date", "warranty_end", "refresh_date"):
        if row.get(col):
            fields[col] = csvio.parse_date(row[col])
    if row.get("purchase_cost"):
        fields["purchase_cost"] = csvio.parse_cost(row["purchase_cost"])
    custom = {h[len(csvio.CUSTOM_PREFIX):]: v for h, v in row.items() if h.startswith(csvio.CUSTOM_PREFIX) and v}
    status = row.get("status", "").strip().lower() or None
    if status and status not in csvio.IMPORT_STATUSES:
        raise ValueError(f"status {status!r} cannot be set by import (allowed: {', '.join(csvio.IMPORT_STATUSES)}); "
                         "use offboarding / disposal for the others")
    email = clean_email(row.get("assignee_email", ""))
    name = clean_text(row.get("assignee_name", ""))
    if len(name) > 128:
        raise ValueError("assignee_name is longer than 128 characters")

    existing = db.scalars(select(ItAsset).where(func.lower(ItAsset.asset_tag) == tag.lower())).first()
    if existing is None:
        body = AssetCreate.model_validate({"asset_tag": tag, **fields, "custom_fields": custom or {},
                                           "assignee_name": name, "assignee_email": email})
        svc.check_custom_fields(body.custom_fields or {}, st)
        svc.check_dates(body.purchase_date, body.warranty_end, body.refresh_date)
        status = status or ("assigned" if email else "in_stock")
        if status == "assigned" and not email:
            raise ValueError("status assigned needs an assignee_email")
        a = _new_asset(body, st, actor, source="import")
        a.status = status
        if email and status in {"assigned", "in_repair", "lost", "stolen"}:
            a.assigned_at = utcnow()
        else:
            a.assignee_name = a.assignee_email = a.assignee_department = ""
        db.add(a)
        db.flush()
        svc.record(db, a, "imported", actor, to_status=a.status, to_assignee=a.assignee_email, notes="created by CSV import")
        return "created"

    body = AssetUpdate.model_validate({**fields, "custom_fields": custom or None})
    changes = _apply_update(existing, body, st)
    prev_status, prev_owner = existing.status, existing.assignee_email
    if existing.status in {"disposed", "retrieval_pending"} and (status and status != existing.status
                                                                   or email and email != prev_owner):
        raise ValueError(f"asset is {existing.status.replace('_', ' ')}: change it in the app, not by import")
    if email and email != prev_owner:
        if existing.status not in svc.ASSIGNABLE_FROM:
            raise ValueError(f"an asset that is {existing.status} cannot be assigned")
        existing.assignee_email, existing.assignee_name, existing.assigned_at = email, name, utcnow()
        if "assignee_department" not in fields:
            existing.assignee_department = ""
        changes["assignee_email"] = [prev_owner, email]
        status = status or "assigned"
    elif name and email == prev_owner and name != existing.assignee_name:
        changes["assignee_name"] = [existing.assignee_name, name]
        existing.assignee_name = name
    if status and status != existing.status:
        if status == "assigned" and not existing.assignee_email:
            raise ValueError("status assigned needs an assignee_email")
        if status in {"in_stock", "retrieved"}:
            existing.assignee_name = existing.assignee_email = existing.assignee_department = ""
            existing.assigned_at = None
        existing.status = status
        changes["status"] = [prev_status, status]
    if not changes:
        return "unchanged"
    existing.updated_at = utcnow()
    svc.record(db, existing, "imported", actor, from_status=prev_status, to_status=existing.status,
               from_assignee=prev_owner, to_assignee=existing.assignee_email, notes="updated by CSV import",
               changes=changes)
    return "updated"


# ----------------------------------------------------------------------------- offboarding
def _offboarding_out(db: Session, obs: list[ItAssetOffboarding]) -> list[dict[str, Any]]:
    counts = svc.offboarding_counts(db, [o.id for o in obs])
    on = svc.today()
    return [{**OffboardingOut.model_validate(o).model_dump(), "assets_total": counts[o.id][0],
             "assets_outstanding": counts[o.id][1],
             "overdue": o.status == "open" and o.retrieval_due < on and counts[o.id][1] > 0} for o in obs]


@router.get("/offboardings", response_model=list[OffboardingOut])
def list_offboardings(status: str | None = Query(None, pattern="^(open|completed|cancelled)$"),
                      db: Session = Depends(get_db)):
    stmt = select(ItAssetOffboarding)
    if status:
        stmt = stmt.where(ItAssetOffboarding.status == status)
    return _offboarding_out(db, list(db.scalars(stmt.order_by(ItAssetOffboarding.leave_date.desc()).limit(2000))))


@router.post("/offboardings", status_code=201)
def create_offboarding(body: OffboardingIn, request: Request, user: User = Depends(require_analyst),
                       db: Session = Depends(get_db)):
    """Mark a person as leaving: their assigned assets go to retrieval pending."""
    try:
        ob, assets = svc.start_offboarding(db, user.email, email=body.person_email, name=body.person_name,
                                           department=body.department, leave_date=body.leave_date,
                                           retrieval_due=body.retrieval_due, notes=body.notes)
    except (svc.AssetError, ValueError) as e:
        db.rollback()
        raise _conflict(e) from None
    audit(db, "it_asset_offboarding_created", actor=user, target=f"it-asset-offboarding:{ob.id}",
          ip=client_ip(request), person_email=ob.person_email, leave_date=ob.leave_date.isoformat(),
          retrieval_due=ob.retrieval_due.isoformat(), assets=[a.asset_tag for a in assets])
    db.commit()
    return {**_offboarding_out(db, [ob])[0], "assets": [_out(db, a) for a in assets]}


@router.get("/offboardings/{offboarding_id}")
def offboarding_detail(offboarding_id: str = Id32, db: Session = Depends(get_db)):
    ob = db.get(ItAssetOffboarding, offboarding_id)
    if ob is None:
        raise HTTPException(404, "offboarding not found")
    ids = {(e.detail or {}).get("offboarding_id") == ob.id and e.asset_id for e in db.scalars(
        select(ItAssetEvent).where(ItAssetEvent.event_type == "offboarding"))} - {False}
    assets = list(db.scalars(select(ItAsset).where(or_(ItAsset.offboarding_id == ob.id, ItAsset.id.in_(ids)))
                             .order_by(ItAsset.asset_tag)))
    devices = svc.devices_for(db, assets)
    st = svc.get_settings(db)
    return {**_offboarding_out(db, [ob])[0], "assets": [svc.to_out(a, devices.get(a.device_id or ""), st)
                                                       for a in assets]}


@router.post("/offboardings/{offboarding_id}/cancel")
def cancel_offboarding(body: CancelIn, request: Request, offboarding_id: str = Id32,
                       user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    ob = db.get(ItAssetOffboarding, offboarding_id)
    if ob is None:
        raise HTTPException(404, "offboarding not found")
    try:
        n = svc.cancel_offboarding(db, ob, user.email, body.notes)
    except svc.AssetError as e:
        raise _conflict(e) from None
    audit(db, "it_asset_offboarding_cancelled", actor=user, target=f"it-asset-offboarding:{ob.id}",
          ip=client_ip(request), person_email=ob.person_email, assets_restored=n, notes=body.notes)
    db.commit()
    return _offboarding_out(db, [ob])[0]


# ----------------------------------------------------------------------------- certificates (upload)
def _safe_filename(name: str | None, content_type: str) -> str:
    base = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    base = _FILENAME_SAFE.sub("_", base).strip(" .")[:100]
    if not base:
        base = "certificate"
    ext = CERT_EXT[content_type]
    stem = base.rsplit(".", 1)[0] if "." in base else base
    return f"{stem or 'certificate'}{ext}"


@router.post("/certificates/{asset_id}", response_model=CertificateOut, status_code=201)
def upload_certificate(request: Request, asset_id: str = Id32,
                       data: bytes = Body(..., media_type="application/octet-stream"),
                       content_type: str = Header("", alias="Content-Type"),
                       filename: str | None = Query(None, max_length=255),
                       user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    """Upload a wipe / destruction certificate (raw body; PDF, PNG or JPEG)."""
    a = _get(db, asset_id)
    st = svc.get_settings(db)
    ctype = content_type.split(";", 1)[0].strip().lower()
    if ctype not in CERT_TYPES:
        raise HTTPException(415, "certificates must be PDF, PNG or JPEG (Content-Type application/pdf, image/png "
                                 "or image/jpeg)")
    if not data:
        raise HTTPException(422, "the file is empty")
    if len(data) > st["certificate_max_bytes"]:
        raise HTTPException(413, f"certificate exceeds {st['certificate_max_bytes']} bytes")
    if not any(data.startswith(m) for m in CERT_TYPES[ctype]):
        raise HTTPException(415, f"the file content is not a valid {ctype.split('/')[1].upper()} file")
    cert = ItAssetCertificate(asset_id=a.id, filename=_safe_filename(filename, ctype), content_type=ctype,
                              size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), data=data,
                              uploaded_by=user.email, uploaded_at=utcnow())
    db.add(cert)
    db.flush()
    svc.record(db, a, "certificate_uploaded", user.email, notes=cert.filename, certificate_id=cert.id,
               sha256=cert.sha256, size_bytes=cert.size_bytes, content_type=ctype)
    audit(db, "it_asset_certificate_uploaded", actor=user, target=_target(a), ip=client_ip(request),
          asset_tag=a.asset_tag, certificate_id=cert.id, filename=cert.filename, sha256=cert.sha256,
          size_bytes=cert.size_bytes, content_type=ctype)
    db.commit()
    return cert


# ----------------------------------------------------------------------------- create
def _new_asset(body: AssetCreate, st: dict, actor: str, source: str = "manual") -> ItAsset:
    now = utcnow()
    return ItAsset(asset_tag=body.asset_tag, serial_number=body.serial_number or "", asset_type=body.asset_type,
                   manufacturer=body.manufacturer or "", model=body.model or "", status=body.status,
                   source=source, assignee_name=body.assignee_name, assignee_email=body.assignee_email,
                   assignee_department=body.assignee_department or "", location=body.location or "",
                   purchase_date=body.purchase_date, supplier=body.supplier or "", purchase_cost=body.purchase_cost,
                   currency=body.currency or st["default_currency"], warranty_end=body.warranty_end,
                   refresh_date=body.refresh_date, notes=body.notes or "", custom_fields=body.custom_fields or {},
                   created_by=actor, created_at=now, updated_at=now)


def _tag_taken(db: Session, tag: str, exclude: str | None = None) -> bool:
    stmt = select(func.count()).select_from(ItAsset).where(func.lower(ItAsset.asset_tag) == tag.lower())
    if exclude:
        stmt = stmt.where(ItAsset.id != exclude)
    return bool(db.scalar(stmt))


def _check_device_link(db: Session, device_id: str, asset_id: str | None = None) -> Device:
    d = db.get(Device, device_id)
    if d is None:
        raise HTTPException(422, "device not found")
    other = db.scalars(select(ItAsset).where(ItAsset.device_id == device_id)).first()
    if other is not None and other.id != asset_id:
        raise HTTPException(409, f"the device is already linked to asset {other.asset_tag}")
    return d


@router.post("", response_model=AssetOut, status_code=201)
def create_asset(body: AssetCreate, request: Request, user: User = Depends(require_analyst),
                 db: Session = Depends(get_db)):
    st = svc.get_settings(db)
    try:
        svc.check_custom_fields(body.custom_fields or {}, st)
        svc.check_dates(body.purchase_date, body.warranty_end, body.refresh_date)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    if body.status == "assigned" and not body.assignee_email:
        raise HTTPException(422, "an assigned asset needs an assignee email")
    if _tag_taken(db, body.asset_tag):
        raise HTTPException(409, f"asset tag {body.asset_tag} already exists")
    if body.device_id:
        _check_device_link(db, body.device_id)
    a = _new_asset(body, st, user.email)
    a.device_id = body.device_id
    if body.status != "assigned" and body.status != "in_repair":
        a.assignee_name = a.assignee_email = a.assignee_department = ""
    elif a.assignee_email:
        a.assigned_at = utcnow()
    db.add(a)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "asset tag or device link already in use") from None
    svc.record(db, a, "created", user.email, to_status=a.status, to_assignee=a.assignee_email or None)
    audit(db, "it_asset_created", actor=user, target=_target(a), ip=client_ip(request), asset_tag=a.asset_tag,
          asset_type=a.asset_type, status=a.status, assignee=a.assignee_email or None, device_id=a.device_id)
    db.commit()
    return _out(db, a)


# ----------------------------------------------------------------------------- one asset
@router.get("/{asset_id}", response_model=AssetOut)
def asset_detail(asset_id: str = Id32, db: Session = Depends(get_db)):
    return _out(db, _get(db, asset_id))


@router.get("/{asset_id}/events", response_model=list[EventOut])
def asset_events(asset_id: str = Id32, limit: int = Query(500, ge=1, le=5000), db: Session = Depends(get_db)):
    _get(db, asset_id)
    return list(db.scalars(select(ItAssetEvent).where(ItAssetEvent.asset_id == asset_id)
                           .order_by(ItAssetEvent.at.desc(), ItAssetEvent.id.desc()).limit(limit)))


_PLAIN_FIELDS = ("serial_number", "asset_type", "manufacturer", "model", "location", "purchase_date", "supplier",
                 "purchase_cost", "currency", "warranty_end", "refresh_date", "notes", "assignee_department")


def _apply_update(a: ItAsset, body: AssetUpdate, st: dict) -> dict[str, list[Any]]:
    """Apply the set fields of `body`; returns {field: [before, after]} for changed ones."""
    data = body.model_dump(exclude_unset=True)
    changes: dict[str, list[Any]] = {}
    if data.get("custom_fields") is not None:
        svc.check_custom_fields(data["custom_fields"], st)
    svc.check_dates(data.get("purchase_date", a.purchase_date), data.get("warranty_end", a.warranty_end),
                    data.get("refresh_date", a.refresh_date))
    for f in _PLAIN_FIELDS:
        if f not in data:
            continue
        v = data[f]
        if v is None and f in {"serial_number", "asset_type", "manufacturer", "model", "location", "supplier",
                               "currency", "notes", "assignee_department"}:
            continue  # explicit null on a non-nullable text field: leave unchanged
        if f == "currency" and not v:
            continue
        before = getattr(a, f)
        if before != v:
            setattr(a, f, v)
            changes[f] = [before, v]
    if data.get("custom_fields") is not None:
        merged = data["custom_fields"]
        if merged != (a.custom_fields or {}):
            changes["custom_fields"] = [dict(a.custom_fields or {}), merged]
            a.custom_fields = merged
    return changes


@router.patch("/{asset_id}", response_model=AssetOut)
def update_asset(body: AssetUpdate, request: Request, asset_id: str = Id32, user: User = Depends(require_analyst),
                 db: Session = Depends(get_db)):
    a = _get(db, asset_id)
    st = svc.get_settings(db)
    data = body.model_dump(exclude_unset=True)
    if body.asset_tag is not None and body.asset_tag != a.asset_tag and _tag_taken(db, body.asset_tag, a.id):
        raise HTTPException(409, f"asset tag {body.asset_tag} already exists")
    try:
        changes = _apply_update(a, body, st)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    if body.asset_tag is not None and body.asset_tag != a.asset_tag:
        changes["asset_tag"] = [a.asset_tag, body.asset_tag]
        a.asset_tag = body.asset_tag
    if "device_id" in data:
        new = data["device_id"] or None
        if new != a.device_id:
            if new:
                d = _check_device_link(db, new, a.id)
                svc.record(db, a, "device_linked", user.email, notes=body.note, device_id=new, hostname=d.hostname)
            changes["device_id"] = [a.device_id, new]
            a.device_id = new
    if not changes:
        return _out(db, a)
    a.updated_at = utcnow()
    svc.record(db, a, "updated", user.email, notes=body.note, changes=changes)
    audit(db, "it_asset_updated", actor=user, target=_target(a), ip=client_ip(request), asset_tag=a.asset_tag,
          changes=svc._jsonable(changes), note=body.note)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "asset tag or device link already in use") from None
    return _out(db, a)


def _lifecycle(request: Request, db: Session, a: ItAsset, user: User, action: str, fn, **audit_detail) -> dict:
    prev_status, prev_owner = a.status, a.assignee_email
    try:
        fn()
    except (svc.AssetError, ValueError) as e:
        db.rollback()
        raise _conflict(e) from None
    audit(db, action, actor=user, target=_target(a), ip=client_ip(request), asset_tag=a.asset_tag,
          from_status=prev_status, to_status=a.status, from_assignee=prev_owner or None,
          to_assignee=a.assignee_email or None, **svc._jsonable(audit_detail))
    db.commit()
    return _out(db, a)


@router.post("/{asset_id}/assign", response_model=AssetOut)
def assign_asset(body: AssignIn, request: Request, asset_id: str = Id32, user: User = Depends(require_analyst),
                 db: Session = Depends(get_db)):
    a = _get(db, asset_id)
    return _lifecycle(request, db, a, user, "it_asset_assigned", lambda: svc.assign(
        db, a, user.email, name=body.assignee_name, email=body.assignee_email,
        department=body.assignee_department, notes=body.notes), notes=body.notes)


@router.post("/{asset_id}/return", response_model=AssetOut)
def return_asset(body: ReturnIn, request: Request, asset_id: str = Id32, user: User = Depends(require_analyst),
                 db: Session = Depends(get_db)):
    a = _get(db, asset_id)
    return _lifecycle(request, db, a, user, "it_asset_returned", lambda: svc.return_asset(
        db, a, user.email, notes=body.notes, status=body.status, location=body.location), notes=body.notes)


@router.post("/{asset_id}/status", response_model=AssetOut)
def set_status(body: StatusIn, request: Request, asset_id: str = Id32, user: User = Depends(require_analyst),
               db: Session = Depends(get_db)):
    a = _get(db, asset_id)
    return _lifecycle(request, db, a, user, "it_asset_status_changed", lambda: svc.change_status(
        db, a, user.email, status=body.status, notes=body.notes, retrieval_due=body.retrieval_due),
        notes=body.notes, retrieval_due=body.retrieval_due)


@router.post("/{asset_id}/dispose", response_model=AssetOut)
def dispose_asset(body: DisposeIn, request: Request, asset_id: str = Id32, user: User = Depends(require_analyst),
                  db: Session = Depends(get_db)):
    a = _get(db, asset_id)
    return _lifecycle(request, db, a, user, "it_asset_disposed", lambda: svc.dispose(
        db, a, user.email, method=body.method, disposal_date=body.disposal_date, vendor=body.vendor,
        notes=body.notes), method=body.method, disposal_date=body.disposal_date, vendor=body.vendor)


@router.delete("/{asset_id}", status_code=204)
def delete_asset(request: Request, asset_id: str = Id32, reason: str = Query(..., min_length=3, max_length=500),
                 admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Remove the record, its custody history and certificates (prefer disposal for real assets)."""
    a = _get(db, asset_id)
    audit(db, "it_asset_deleted", actor=admin, target=_target(a), ip=client_ip(request), asset_tag=a.asset_tag,
          serial_number=a.serial_number, status=a.status, device_id=a.device_id, reason=reason.strip())
    db.delete(a)
    db.commit()


# ----------------------------------------------------------------------------- certificates
@router.get("/{asset_id}/certificates", response_model=list[CertificateOut])
def list_certificates(asset_id: str = Id32, db: Session = Depends(get_db)):
    _get(db, asset_id)
    cols = [c for c in ItAssetCertificate.__table__.columns if c.name != "data"]
    rows = db.execute(select(*cols).where(ItAssetCertificate.asset_id == asset_id)
                      .order_by(ItAssetCertificate.uploaded_at.desc())).mappings().all()
    return [dict(r) for r in rows]


def _get_cert(db: Session, asset_id: str, cert_id: str) -> ItAssetCertificate:
    c = db.get(ItAssetCertificate, cert_id)
    if c is None or c.asset_id != asset_id:
        raise HTTPException(404, "certificate not found")
    return c


@router.get("/{asset_id}/certificates/{cert_id}")
def download_certificate(request: Request, asset_id: str = Id32, cert_id: str = Id32,
                         user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    c = _get_cert(db, asset_id, cert_id)
    audit(db, "it_asset_certificate_downloaded", actor=user, target=f"it-asset:{asset_id}", ip=client_ip(request),
          certificate_id=c.id, sha256=c.sha256)
    db.commit()
    return Response(content=c.data, media_type=c.content_type, headers={
        "Content-Disposition": f'attachment; filename="{c.filename}"', "X-Content-SHA256": c.sha256,
        # Never render it in the app's origin.
        "Content-Security-Policy": "default-src 'none'; sandbox"})


@router.delete("/{asset_id}/certificates/{cert_id}", status_code=204)
def delete_certificate(request: Request, asset_id: str = Id32, cert_id: str = Id32,
                       reason: str = Query(..., min_length=3, max_length=500),
                       admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    a = _get(db, asset_id)
    c = _get_cert(db, asset_id, cert_id)
    svc.record(db, a, "certificate_deleted", admin.email, notes=reason.strip(), certificate_id=c.id,
               filename=c.filename, sha256=c.sha256)
    audit(db, "it_asset_certificate_deleted", actor=admin, target=_target(a), ip=client_ip(request),
          certificate_id=c.id, filename=c.filename, sha256=c.sha256, reason=reason.strip())
    db.delete(c)
    db.commit()

