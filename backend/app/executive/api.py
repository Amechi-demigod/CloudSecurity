"""Executive report API (/api/reports/executive/*), docs/EXECUTIVE_REPORT.md.

viewer : the on-screen report (preview) and the PDF download
admin  : subscriptions, recipients and "send now" (only organisation admins manage who receives the report;
         MSP staff acting inside a client do so with the stand-in identity like any admin)

Everything is scoped to the session's organisation (another organisation's ids answer 404). Recipient list changes,
sends and downloads are audit-logged; downloads and sends are rate-limited. The unsubscribe endpoints are public:
the signed token is the credential, it names one recipient of one subscription and grants nothing else.
"""
from __future__ import annotations

import html
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config, mailer, tenancy
from ..auth import RateLimiter, audit, client_ip, require_admin, require_viewer
from ..compliance.reports import EMAIL_RE
from ..db import get_db
from ..models import Organization, User, utcnow
from . import data, delivery, pdf
from .models import ExecReportRecipient, ExecReportSubscription

router = APIRouter(prefix="/api/reports/executive", tags=["executive-report"], dependencies=[Depends(require_viewer)])
public_router = APIRouter(prefix="/api/reports/executive", tags=["executive-report"])
pdf_limiter = RateLimiter()
send_limiter = RateLimiter()
unsub_limiter = RateLimiter()
PDF_LIMIT, PDF_WINDOW = 10, 600.0  # per user
SEND_LIMIT, SEND_WINDOW = 5, 3600.0  # send now, per organisation

Period = Literal["daily", "weekly", "monthly", "quarterly"]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
PersonName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
Title = Annotated[str, StringConstraints(strip_whitespace=True, max_length=120)]
Email = Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, max_length=320)]
SID = Path(pattern=r"^[0-9a-f]{32}$")
RID = Path(pattern=r"^[0-9a-f]{32}$")


def _no_controls(v: str | None) -> str | None:
    if v is not None and any(ord(ch) < 32 or ord(ch) == 127 for ch in v):
        raise ValueError("must not contain control characters")
    return v


# ----------------------------------------------------------------------------- the report
@router.get("")
def preview(period: Period = Query("monthly"), db: Session = Depends(get_db)):
    """The report as data (the console page renders it)."""
    return data.build(db, period)


@router.get("/pdf")
def download(request: Request, period: Period = Query("monthly"), user: User = Depends(require_viewer),
             db: Session = Depends(get_db)):
    if not pdf_limiter.hit(f"user:{user.id}", PDF_LIMIT, PDF_WINDOW):
        raise HTTPException(429, "too many downloads; try again later", headers={"Retry-After": "60"})
    report = data.build(db, period)
    blob = pdf.render(report)
    audit(db, "exec_report_downloaded", actor=user, ip=client_ip(request), period=period, size_bytes=len(blob))
    db.commit()
    return Response(content=blob, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="executive-report-{utcnow():%Y%m%d}.pdf"',
        "Cache-Control": "no-store"})


# ----------------------------------------------------------------------------- subscriptions
class SubscriptionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Name
    enabled: bool = True
    frequency: Period = "monthly"
    day: int = Field(1, ge=0, le=28)  # weekly 0 = Monday .. 6; monthly / quarterly 1-28; daily unused
    hour: int = Field(6, ge=0, le=23)

    _nc = field_validator("name")(_no_controls)


class SubscriptionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Name | None = None
    enabled: bool | None = None
    frequency: Period | None = None
    day: int | None = Field(None, ge=0, le=28)
    hour: int | None = Field(None, ge=0, le=23)

    _nc = field_validator("name")(_no_controls)


def _recipient_out(r: ExecReportRecipient, admins: dict[str, User]) -> dict[str, Any]:
    if r.kind == "admin":
        u = admins.get(r.user_id or "")
        state = "unsubscribed" if r.unsubscribed_at else ("active" if u else "not_admin")
        return {"id": r.id, "kind": "admin", "user_id": r.user_id, "name": u.name if u else r.name,
                "email": u.email if u else r.email, "job_title": r.job_title, "state": state,
                "created_at": r.created_at}
    return {"id": r.id, "kind": "external", "user_id": None, "name": r.name, "email": r.email,
            "job_title": r.job_title, "state": "unsubscribed" if r.unsubscribed_at else "active",
            "created_at": r.created_at}


def _sub_out(db: Session, s: ExecReportSubscription, admins: dict[str, User] | None = None) -> dict[str, Any]:
    admins = admins if admins is not None else delivery.active_admins(db)
    rows = db.scalars(select(ExecReportRecipient).where(ExecReportRecipient.subscription_id == s.id)
                      .order_by(ExecReportRecipient.created_at))
    return {"id": s.id, "name": s.name, "enabled": s.enabled, "frequency": s.frequency, "day": s.day, "hour": s.hour,
            "next_run_at": s.next_run_at, "last_run_at": s.last_run_at, "last_status": s.last_status,
            "last_error": s.last_error, "created_by": s.created_by, "updated_at": s.updated_at,
            "recipients": [_recipient_out(r, admins) for r in rows]}


def _get_sub(db: Session, sid: str) -> ExecReportSubscription:
    s = db.get(ExecReportSubscription, sid)
    if s is None:
        raise HTTPException(404, "scheduled report not found")
    return s


def _validate_slot(frequency: str, day: int) -> None:
    if frequency == "weekly" and not 0 <= day <= 6:
        raise HTTPException(422, "weekly reports: day is 0 (Monday) to 6 (Sunday)")
    if frequency in ("monthly", "quarterly") and not 1 <= day <= 28:
        raise HTTPException(422, "monthly and quarterly reports: day of month is 1 to 28")


@router.get("/subscriptions", dependencies=[Depends(require_admin)])
def list_subscriptions(db: Session = Depends(get_db)):
    admins = delivery.active_admins(db)
    rows = db.scalars(select(ExecReportSubscription).order_by(ExecReportSubscription.created_at))
    return {"items": [_sub_out(db, s, admins) for s in rows], "mail_configured": mailer.configured(),
            "max_subscriptions": delivery.MAX_SUBSCRIPTIONS, "max_recipients": delivery.MAX_RECIPIENTS,
            "admins": sorted(({"id": u.id, "name": u.name, "email": u.email} for u in admins.values()),
                             key=lambda a: a["email"])}


@router.post("/subscriptions", status_code=201)
def create_subscription(body: SubscriptionIn, request: Request, admin: User = Depends(require_admin),
                        db: Session = Depends(get_db)):
    if delivery.count(db) >= delivery.MAX_SUBSCRIPTIONS:
        raise HTTPException(409, f"at most {delivery.MAX_SUBSCRIPTIONS} scheduled reports per organisation")
    _validate_slot(body.frequency, body.day)
    now = utcnow()
    s = ExecReportSubscription(name=body.name, enabled=body.enabled, frequency=body.frequency, day=body.day,
                               hour=body.hour, created_by=admin.email, created_at=now, updated_by=admin.email,
                               updated_at=now, next_run_at=delivery.next_run(body.frequency, body.day, body.hour, now))
    db.add(s)
    db.flush()
    audit(db, "exec_report_subscription_created", actor=admin, target=f"exec-report:{s.id}", ip=client_ip(request),
          name=s.name, frequency=s.frequency)
    db.commit()
    return _sub_out(db, s)


@router.patch("/subscriptions/{sid}")
def update_subscription(body: SubscriptionUpdate, request: Request, sid: str = SID,
                        admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    s = _get_sub(db, sid)
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        if v is None:
            raise HTTPException(422, f"{k} cannot be empty")
        setattr(s, k, v)
    _validate_slot(s.frequency, s.day)
    now = utcnow()
    s.updated_by, s.updated_at = admin.email, now
    if {"frequency", "day", "hour", "enabled"} & changes.keys():
        s.next_run_at = delivery.next_run(s.frequency, s.day, s.hour, now)
    audit(db, "exec_report_subscription_updated", actor=admin, target=f"exec-report:{s.id}", ip=client_ip(request),
          fields=sorted(changes))
    db.commit()
    return _sub_out(db, s)


@router.delete("/subscriptions/{sid}", status_code=204, dependencies=[Depends(require_admin)])
def delete_subscription(request: Request, sid: str = SID, admin: User = Depends(require_admin),
                        db: Session = Depends(get_db)):
    s = _get_sub(db, sid)
    audit(db, "exec_report_subscription_deleted", actor=admin, target=f"exec-report:{s.id}", ip=client_ip(request),
          name=s.name)
    for r in db.scalars(select(ExecReportRecipient).where(ExecReportRecipient.subscription_id == s.id)):
        db.delete(r)
    db.delete(s)
    db.commit()
    return Response(status_code=204)


# ----------------------------------------------------------------------------- recipients
class RecipientIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["admin", "external"]
    user_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")] | None = None  # kind admin
    name: PersonName | None = None  # kind external
    email: Email | None = None  # kind external
    job_title: Title | None = None

    _nc = field_validator("name", "job_title")(_no_controls)


@router.post("/subscriptions/{sid}/recipients", status_code=201)
def add_recipient(body: RecipientIn, request: Request, sid: str = SID, admin: User = Depends(require_admin),
                  db: Session = Depends(get_db)):
    s = _get_sub(db, sid)
    existing = list(db.scalars(select(ExecReportRecipient).where(ExecReportRecipient.subscription_id == s.id)))
    if len(existing) >= delivery.MAX_RECIPIENTS:
        raise HTTPException(409, f"at most {delivery.MAX_RECIPIENTS} recipients per scheduled report")
    if body.kind == "admin":
        u = delivery.active_admins(db).get(body.user_id or "")
        if u is None:
            raise HTTPException(422, "choose an active administrator of this organisation")
        email, name = u.email.lower(), u.name or ""
        rec = ExecReportRecipient(subscription_id=s.id, kind="admin", user_id=u.id, name=name, email=email,
                                  job_title=body.job_title or None, created_by=admin.email)
    else:
        if not body.name or not body.email:
            raise HTTPException(422, "a name and an email address are required")
        if not EMAIL_RE.match(body.email):
            raise HTTPException(422, f"not an email address: {body.email}")
        email = body.email
        rec = ExecReportRecipient(subscription_id=s.id, kind="external", name=body.name, email=email,
                                  job_title=body.job_title or None, created_by=admin.email)
    if any(r.email.lower() == email for r in existing):
        raise HTTPException(409, f"{email} already receives this report")
    db.add(rec)
    db.flush()
    audit(db, "exec_report_recipient_added", actor=admin, target=f"exec-report:{s.id}", ip=client_ip(request),
          recipient=email, kind=rec.kind)
    db.commit()
    return _sub_out(db, s)


@router.delete("/subscriptions/{sid}/recipients/{rid}", dependencies=[Depends(require_admin)])
def remove_recipient(request: Request, sid: str = SID, rid: str = RID, admin: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    s = _get_sub(db, sid)
    r = db.get(ExecReportRecipient, rid)
    if r is None or r.subscription_id != s.id:
        raise HTTPException(404, "recipient not found")
    audit(db, "exec_report_recipient_removed", actor=admin, target=f"exec-report:{s.id}", ip=client_ip(request),
          recipient=r.email, kind=r.kind)
    db.delete(r)
    db.commit()
    return _sub_out(db, s)


@router.post("/subscriptions/{sid}/send")
def send_now(sid: str = SID, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    s = _get_sub(db, sid)
    if not send_limiter.hit(f"org:{s.organization_id}", SEND_LIMIT, SEND_WINDOW):
        raise HTTPException(429, "too many reports sent; try again later", headers={"Retry-After": "300"})
    out = delivery.send_subscription(db, s, actor=admin, trigger="manual")
    return {"status": out.status, "sent": out.sent, "errors": out.errors, "subscription": _sub_out(db, s)}


# ----------------------------------------------------------------------------- unsubscribe (public)
def _page(title: str, message: str, form_action: str | None = None) -> HTMLResponse:
    brand = html.escape(config.settings.brand_name)
    form = (f'<form method="post" action="{html.escape(form_action, quote=True)}"><button type="submit" '
            'style="margin-top:16px;padding:10px 18px;font-size:15px;cursor:pointer">Stop sending me this report'
            "</button></form>" if form_action else "")
    body = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" "
            f"content=\"width=device-width,initial-scale=1\"><title>{html.escape(title)}</title></head>"
            "<body style=\"font-family:Arial,Helvetica,sans-serif;max-width:480px;margin:48px auto;padding:0 16px;"
            f"color:#111827\"><p style=\"font-weight:bold;color:#374151\">{brand}</p><h1 style=\"font-size:22px\">"
            f"{html.escape(title)}</h1><p>{html.escape(message)}</p>{form}</body></html>")
    return HTMLResponse(body, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
                                       "X-Robots-Tag": "noindex"})


def _find(db: Session, token: str) -> tuple[ExecReportRecipient, Organization] | None:
    """The external recipient a genuine token names, in its own organisation only."""
    ids = delivery.read_token(token)
    if ids is None:
        return None
    org_id, rid = ids
    with tenancy.unscoped(db):
        org = db.get(Organization, org_id)
    if org is None or org.status != "active":
        return None
    tenancy.set_org(db, org.id)
    r = db.get(ExecReportRecipient, rid)
    if r is None or r.kind != "external":  # admins are managed in the console, never through a link
        return None
    return r, org


def _limit(request: Request) -> None:
    if not unsub_limiter.hit(f"ip:{client_ip(request)}", 30, 600.0):
        raise HTTPException(429, "too many requests", headers={"Retry-After": "60"})


@public_router.get("/unsubscribe", response_class=HTMLResponse, include_in_schema=False)
def unsubscribe_page(request: Request, token: str = Query("", max_length=300), db: Session = Depends(get_db)):
    """The link in the email: shows a confirmation button (a mail scanner opening the link changes nothing)."""
    _limit(request)
    found = _find(db, token)
    if found is None:
        return _page("This link is not valid", "The link is invalid or has expired. If you still receive the report, "
                                              "ask the sender to remove you.")
    r, org = found
    if r.unsubscribed_at is not None:
        return _page("You are unsubscribed", f"You will no longer receive this report from {org.name}.")
    return _page("Stop receiving this report?", f"You are about to stop receiving the security report of {org.name}.",
                 f"/api/reports/executive/unsubscribe?token={html.escape(token, quote=True)}")


@public_router.post("/unsubscribe", response_class=HTMLResponse, include_in_schema=False)
def unsubscribe(request: Request, token: str = Query("", max_length=300), db: Session = Depends(get_db)):
    _limit(request)
    found = _find(db, token)
    if found is None:
        return _page("This link is not valid", "The link is invalid or has expired.")
    r, org = found
    if r.unsubscribed_at is None:
        r.unsubscribed_at = utcnow()
        audit(db, "exec_report_unsubscribed", actor_email=r.email, target=f"exec-report:{r.subscription_id}",
              ip=client_ip(request), recipient=r.email)
        db.commit()
    return _page("You are unsubscribed", f"You will no longer receive this report from {org.name}.")
