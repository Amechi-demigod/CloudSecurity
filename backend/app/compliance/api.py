"""Compliance reports API (/api/compliance/*), session-authenticated with RBAC.

viewer : framework posture, control evidence, trend, CSV / PDF export, schedules (read)
admin  : create / edit / delete scheduled email reports, Send now

Everything is scoped to the session's organisation (another organisation's
schedule ids answer 404). Optional report scope: one cloud account
(`account`) or one device group (`device_group`), not both. Exports,
schedule changes and sent reports are audited; PDF exports and Send now are
rate-limited. Reports are evidence to support an assessment, never a
certification (docs/COMPLIANCE.md).
"""
from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import mailer
from ..auth import RateLimiter, audit, client_ip, require_admin, require_viewer
from ..db import get_db
from ..models import User, utcnow
from . import catalog, checks, reports, service
from .models import FREQUENCIES, ComplianceReportSchedule

router = APIRouter(prefix="/api/compliance", tags=["compliance"], dependencies=[Depends(require_viewer)])
pdf_limiter = RateLimiter()
send_limiter = RateLimiter()
PDF_LIMIT, PDF_WINDOW = 10, 600.0  # per user
SEND_LIMIT, SEND_WINDOW = 5, 3600.0  # Send now, per organisation

AccountQ = Query(None, max_length=64, pattern=r"^[A-Za-z0-9._:/\-]+$",
                 description="Cloud account scope: Azure subscription, AWS account or GCP project id")
GroupQ = Query(None, max_length=64, description="Device group scope")
FrameworkId = Path(pattern=r"^[a-z0-9.\-]{1,64}$")


def _scope(account: str | None, device_group: str | None) -> checks.Scope:
    if account and device_group:
        raise HTTPException(422, "choose a cloud account or a device group, not both")
    return checks.Scope(account=account or None, device_group=(device_group or "").strip() or None)


def _framework(fid: str) -> catalog.Framework:
    fw = catalog.get(fid)
    if fw is None:
        raise HTTPException(404, "unknown framework")
    return fw


@router.get("/frameworks")
def list_frameworks(account: str | None = AccountQ, device_group: str | None = GroupQ,
                    db: Session = Depends(get_db)):
    scope = _scope(account, device_group)
    return {"frameworks": service.overview(db, scope), "scopes": service.scopes(db),
            "disclaimer": service.DISCLAIMER}


@router.get("/frameworks/{framework_id}")
def framework_posture(framework_id: str = FrameworkId, account: str | None = AccountQ,
                      device_group: str | None = GroupQ, db: Session = Depends(get_db)):
    fw = _framework(framework_id)
    scope = _scope(account, device_group)
    service.ensure_today(db, scope)
    return service.posture(db, fw, scope)


@router.get("/frameworks/{framework_id}/trend")
def framework_trend(framework_id: str = FrameworkId, account: str | None = AccountQ,
                    device_group: str | None = GroupQ, days: int = Query(90, ge=7, le=service.TREND_DAYS_MAX),
                    db: Session = Depends(get_db)):
    fw = _framework(framework_id)
    scope = _scope(account, device_group)
    return {"framework": fw.id, "mapping_version": fw.mapping_version,
            "points": service.trend(db, fw.id, scope, days)}


@router.get("/frameworks/{framework_id}/export.csv")
def export_csv(request: Request, framework_id: str = FrameworkId, account: str | None = AccountQ,
               device_group: str | None = GroupQ, user: User = Depends(require_viewer),
               db: Session = Depends(get_db)):
    fw = _framework(framework_id)
    scope = _scope(account, device_group)
    data = service.to_csv(service.posture(db, fw, scope))
    audit(db, "compliance_report_exported", actor=user, ip=client_ip(request), format="csv", frameworks=[fw.id],
          scope=scope.key)
    db.commit()
    return Response(content=data, media_type="text/csv; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="compliance-{fw.id}-{utcnow():%Y%m%d}.csv"'})


@router.get("/report.pdf")
def export_pdf(request: Request, frameworks: str = Query(..., max_length=400,
                                                         description="Comma-separated framework ids"),
               account: str | None = AccountQ, device_group: str | None = GroupQ,
               user: User = Depends(require_viewer), db: Session = Depends(get_db)):
    ids = list(dict.fromkeys(f.strip() for f in frameworks.split(",") if f.strip()))
    if not ids or len(ids) > len(catalog.frameworks()):
        raise HTTPException(422, "choose at least one framework")
    for f in ids:
        _framework(f)
    scope = _scope(account, device_group)
    if not pdf_limiter.hit(f"user:{user.id}", PDF_LIMIT, PDF_WINDOW):
        raise HTTPException(429, "too many PDF exports; try again later", headers={"Retry-After": "60"})
    data, _ = reports.build_pdf(db, ids, scope)
    audit(db, "compliance_report_exported", actor=user, ip=client_ip(request), format="pdf", frameworks=ids,
          scope=scope.key, size_bytes=len(data))
    db.commit()
    return Response(content=data, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="compliance-report-{utcnow():%Y%m%d}.pdf"',
        "Cache-Control": "no-store"})


# ----------------------------------------------------------------------------- schedules
Email = Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, max_length=320)]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
Scope64 = Annotated[str, StringConstraints(strip_whitespace=True, max_length=64)]


def _known_frameworks(v: list[str] | None) -> list[str] | None:
    if v is None:
        return v
    v = list(dict.fromkeys(v))
    unknown = [f for f in v if catalog.get(f) is None]
    if unknown:
        raise ValueError(f"unknown framework(s): {', '.join(unknown)}")
    return v


def _valid_emails(v: list[str] | None) -> list[str] | None:
    if v is None:
        return v
    v = list(dict.fromkeys(v))
    bad = [e for e in v if not reports.EMAIL_RE.match(e)]
    if bad:
        raise ValueError(f"not an email address: {bad[0]}")
    return v


class ScheduleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Name
    enabled: bool = True
    frameworks: list[str] = Field(min_length=1, max_length=8)
    frequency: Literal["weekly", "monthly"] = "monthly"
    # weekly: 0 = Monday .. 6 = Sunday; monthly: 1-28
    day: int = Field(1, ge=0, le=28)
    hour: int = Field(6, ge=0, le=23)
    recipients: list[Email] = Field(min_length=1, max_length=reports.MAX_RECIPIENTS)
    account: Scope64 | None = None
    device_group: Scope64 | None = None

    _known = field_validator("frameworks")(_known_frameworks)
    _emails = field_validator("recipients")(_valid_emails)


class ScheduleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Name | None = None
    enabled: bool | None = None
    frameworks: list[str] | None = Field(None, min_length=1, max_length=8)
    frequency: Literal["weekly", "monthly"] | None = None
    day: int | None = Field(None, ge=0, le=28)
    hour: int | None = Field(None, ge=0, le=23)
    recipients: list[Email] | None = Field(None, min_length=1, max_length=reports.MAX_RECIPIENTS)
    account: Scope64 | None = None
    device_group: Scope64 | None = None

    _known = field_validator("frameworks")(_known_frameworks)
    _emails = field_validator("recipients")(_valid_emails)


def _schedule_out(s: ComplianceReportSchedule) -> dict[str, Any]:
    return {"id": s.id, "name": s.name, "enabled": s.enabled, "frameworks": list(s.frameworks or []),
            "frequency": s.frequency, "day": s.day, "hour": s.hour, "recipients": list(s.recipients or []),
            "account": s.account, "device_group": s.device_group, "next_run_at": s.next_run_at,
            "last_run_at": s.last_run_at, "last_status": s.last_status, "last_error": s.last_error,
            "created_at": s.created_at, "created_by": s.created_by, "updated_at": s.updated_at,
            "updated_by": s.updated_by}


def _get_schedule(db: Session, schedule_id: str) -> ComplianceReportSchedule:
    s = db.get(ComplianceReportSchedule, schedule_id)
    if s is None:
        raise HTTPException(404, "schedule not found")
    return s


def _validate(db: Session, s: ComplianceReportSchedule) -> None:
    if s.frequency not in FREQUENCIES:
        raise HTTPException(422, "frequency must be weekly or monthly")
    if s.frequency == "weekly" and not 0 <= s.day <= 6:
        raise HTTPException(422, "weekly reports: day is 0 (Monday) to 6 (Sunday)")
    if s.frequency == "monthly" and not 1 <= s.day <= 28:
        raise HTTPException(422, "monthly reports: day of month is 1 to 28")
    if s.account and s.device_group:
        raise HTTPException(422, "choose a cloud account or a device group, not both")
    members = reports.member_emails(db)
    outsiders = [r for r in s.recipients if r not in members]
    if outsiders:
        raise HTTPException(422, f"{outsiders[0]} is not an active member of this organisation; reports are "
                                 "only sent to members (invite them first)")


SID = Path(pattern=r"^[0-9a-f]{32}$")


@router.get("/schedules")
def list_schedules(db: Session = Depends(get_db)):
    rows = db.scalars(select(ComplianceReportSchedule).order_by(ComplianceReportSchedule.created_at))
    return {"items": [_schedule_out(s) for s in rows], "mail_configured": mailer.configured(),
            "max_schedules": reports.MAX_SCHEDULES}


@router.get("/recipients", dependencies=[Depends(require_admin)])
def recipients(db: Session = Depends(get_db)):
    """Who reports can be sent to: active members of the organisation."""
    return {"emails": sorted(reports.member_emails(db))}


@router.post("/schedules", status_code=201)
def create_schedule(body: ScheduleIn, request: Request, admin: User = Depends(require_admin),
                    db: Session = Depends(get_db)):
    if reports.count(db) >= reports.MAX_SCHEDULES:
        raise HTTPException(409, f"at most {reports.MAX_SCHEDULES} scheduled reports per organisation")
    now = utcnow()
    s = ComplianceReportSchedule(name=body.name, enabled=body.enabled, frameworks=body.frameworks,
                                 frequency=body.frequency, day=body.day, hour=body.hour,
                                 recipients=body.recipients, account=body.account or None,
                                 device_group=body.device_group or None, created_by=admin.email, created_at=now,
                                 updated_by=admin.email, updated_at=now)
    _validate(db, s)
    s.next_run_at = reports.next_run(s.frequency, s.day, s.hour, now)
    db.add(s)
    db.flush()
    audit(db, "compliance_schedule_created", actor=admin, target=f"compliance-schedule:{s.id}",
          ip=client_ip(request), name=s.name, frameworks=s.frameworks, frequency=s.frequency,
          recipients=len(s.recipients), scope=checks.Scope(s.account, s.device_group).key)
    db.commit()
    return _schedule_out(s)


@router.patch("/schedules/{schedule_id}")
def update_schedule(body: ScheduleUpdate, request: Request, schedule_id: str = SID,
                    admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    s = _get_schedule(db, schedule_id)
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(s, k, (v or None) if k in ("account", "device_group") else v)
    _validate(db, s)
    now = utcnow()
    s.updated_by, s.updated_at = admin.email, now
    if {"frequency", "day", "hour", "enabled"} & changes.keys():
        s.next_run_at = reports.next_run(s.frequency, s.day, s.hour, now)
    audit(db, "compliance_schedule_updated", actor=admin, target=f"compliance-schedule:{s.id}",
          ip=client_ip(request), fields=sorted(changes))
    db.commit()
    return _schedule_out(s)


@router.delete("/schedules/{schedule_id}", status_code=204)
def delete_schedule(request: Request, schedule_id: str = SID, admin: User = Depends(require_admin),
                    db: Session = Depends(get_db)):
    s = _get_schedule(db, schedule_id)
    audit(db, "compliance_schedule_deleted", actor=admin, target=f"compliance-schedule:{s.id}",
          ip=client_ip(request), name=s.name)
    db.delete(s)
    db.commit()
    return Response(status_code=204)


@router.post("/schedules/{schedule_id}/send")
def send_now(schedule_id: str = SID, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    s = _get_schedule(db, schedule_id)
    if not send_limiter.hit(f"org:{s.organization_id}", SEND_LIMIT, SEND_WINDOW):
        raise HTTPException(429, "too many reports sent; try again later", headers={"Retry-After": "300"})
    out = reports.send_report(db, s, actor=admin, trigger="manual")
    return {"status": out.status, "sent": out.sent, "errors": out.errors, "schedule": _schedule_out(s)}
