"""Missing-device mode API (docs/DEVICE_TRACKING.md#missing-device-mode). Module: Endpoints & servers.

viewer  : the missing panel as city and country only
analyst : + the full panel (address, provider) and the PDF report
admin   : mark missing / mark recovered
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response
from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator
from sqlalchemy.orm import Session

from .. import modules, tenancy
from ..auth import ROLE_RANK, RateLimiter, audit, client_ip, current_user, require_admin, require_analyst
from ..db import get_db
from ..models import Device, User, utcnow
from . import missing, report_pdf

router = APIRouter(prefix="/api/devices", tags=["device-tracking"],
                   dependencies=[Depends(modules.require_module(modules.ENDPOINTS))])
DeviceId = Path(pattern=r"^[0-9a-f]{32}$")
pdf_limiter = RateLimiter()
PDF_LIMIT, PDF_WINDOW = 10, 600.0  # per user


class MarkMissing(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=500)]
    confirm_hostname: Annotated[str, StringConstraints(max_length=255)]
    # Lost mode text; needed only when lost mode is not on yet.
    message: Annotated[str, StringConstraints(max_length=1000)] | None = None
    phone: Annotated[str, StringConstraints(max_length=64)] | None = None
    email: Annotated[str, StringConstraints(max_length=320)] | None = None

    @field_validator("reason")
    @classmethod
    def _no_controls(cls, v: str) -> str:
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in v):
            raise ValueError("must not contain control characters")
        return v


class MarkRecovered(BaseModel):
    model_config = ConfigDict(extra="forbid")

    exit_lost_mode: bool = True


def _device(db: Session, device_id: str) -> Device:
    d = db.get(Device, device_id)
    if d is None:
        raise HTTPException(404, "device not found")
    return d


@router.get("/{device_id}/missing")
def get_missing(device_id: str = DeviceId, user: User = Depends(current_user), db: Session = Depends(get_db)):
    d = _device(db, device_id)
    return missing.view(db, d, full=ROLE_RANK.get(user.role, -1) >= ROLE_RANK["analyst"])


@router.post("/{device_id}/missing", status_code=201)
def mark_missing(body: MarkMissing, request: Request, device_id: str = DeviceId,
                 admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    d = _device(db, device_id)
    try:
        res = missing.mark(db, d, admin, reason=body.reason, confirm_hostname=body.confirm_hostname,
                           message=body.message, phone=body.phone, email=body.email, ip=client_ip(request))
    except missing.MissingError as e:
        db.rollback()
        raise HTTPException(e.status, e.detail) from None
    db.commit()
    return {**res, **missing.view(db, d, full=True)}


@router.post("/{device_id}/missing/recover")
def mark_recovered(body: MarkRecovered, request: Request, device_id: str = DeviceId,
                   admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    d = _device(db, device_id)
    try:
        res = missing.recover(db, d, admin, exit_lost_mode=body.exit_lost_mode, ip=client_ip(request))
    except missing.MissingError as e:
        db.rollback()
        raise HTTPException(e.status, e.detail) from None
    db.commit()
    return {**res, **missing.view(db, d, full=True)}


@router.get("/{device_id}/missing/report.pdf")
def missing_report(request: Request, device_id: str = DeviceId, user: User = Depends(require_analyst),
                   db: Session = Depends(get_db)):
    d = _device(db, device_id)
    if not pdf_limiter.hit(f"user:{user.id}", PDF_LIMIT, PDF_WINDOW):
        raise HTTPException(429, "too many report downloads: try again in a few minutes",
                            headers={"Retry-After": "60"})
    org = tenancy.get_org(db, tenancy.require_org(db))
    try:
        data = missing.report_data(db, d, org_name=org.name if org else "", generated_at=utcnow())
    except missing.MissingError as e:
        raise HTTPException(e.status, e.detail) from None
    blob = report_pdf.render(data)
    audit(db, "device_missing_report_downloaded", actor=user, target=f"device:{d.id}", ip=client_ip(request),
          hostname=d.hostname, sightings=len(data["sightings"]))
    db.commit()
    return Response(content=blob, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="missing-device-{d.id[:8]}-{utcnow():%Y%m%d}.pdf"',
        "Cache-Control": "no-store"})
