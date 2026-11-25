"""Scheduled and manual delivery of the executive report (docs/EXECUTIVE_REPORT.md).

Follows app/compliance/reports.py: a leader-elected worker sends what is due through the platform mailer with the
PDF attached; a missed slot is sent once on the next tick. Recipients are console admins who opted in (resolved at
send time: only while they are still active admins) and named people without an account (CEO, directors), each of
whom gets a personal unsubscribe link (signed token, org-scoped; it can only switch that one subscription off).
"""
from __future__ import annotations

import base64
import calendar
import hashlib
import hmac
import html
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import config, mailer, tenancy
from ..auth import audit
from ..locks import LeaderLock
from ..models import OrganizationMembership, User, utcnow
from ..notifications.channels import _clip, _header_safe
from . import data, pdf
from .models import ExecReportRecipient, ExecReportSubscription

log = logging.getLogger(__name__)
MAX_SUBSCRIPTIONS = 10
MAX_RECIPIENTS = 25
QUARTER_MONTHS = (1, 4, 7, 10)
_DEV_SECRET = b"executive-report-dev-secret"


def next_run(frequency: str, day: int, hour: int, after: datetime) -> datetime:
    """The first slot strictly after `after` (UTC, naive)."""
    if frequency == "daily":
        cand = after.replace(hour=hour, minute=0, second=0, microsecond=0)
        return cand if cand > after else cand + timedelta(days=1)
    if frequency == "weekly":
        base = after.replace(hour=hour, minute=0, second=0, microsecond=0)
        cand = base + timedelta(days=(day - base.weekday()) % 7)
        return cand if cand > after else cand + timedelta(days=7)
    y, m = after.year, after.month
    for _ in range(14):
        if frequency == "monthly" or m in QUARTER_MONTHS:
            cand = datetime(y, m, min(day, calendar.monthrange(y, m)[1]), hour)
            if cand > after:
                return cand
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    raise AssertionError("unreachable")


# ----------------------------------------------------------------------------- unsubscribe tokens
def _key() -> bytes:
    s = config.settings.session_secret
    return s.encode() if s else _DEV_SECRET


def _sig(payload: str) -> str:
    return hmac.new(_key(), b"exec-report-unsubscribe|" + payload.encode(), hashlib.sha256).hexdigest()[:40]


def make_token(org_id: str, recipient_id: str) -> str:
    payload = base64.urlsafe_b64encode(f"{org_id}:{recipient_id}".encode()).decode().rstrip("=")
    return f"{payload}.{_sig(payload)}"


def read_token(token: str) -> tuple[str, str] | None:
    """(organisation id, recipient id) of a genuine token, else None."""
    payload, _, sig = (token or "")[:300].partition(".")
    if not payload or not sig or not hmac.compare_digest(sig, _sig(payload)):
        return None
    try:
        org_id, _, rid = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode().partition(":")
    except Exception:
        return None
    return (org_id, rid) if org_id and rid else None


def unsubscribe_url(org_id: str, recipient_id: str) -> str | None:
    base = (config.settings.public_base_url or "").rstrip("/")
    return f"{base}/api/reports/executive/unsubscribe?token={make_token(org_id, recipient_id)}" if base else None


# ----------------------------------------------------------------------------- recipients
@dataclass
class Target:
    email: str
    name: str
    recipient_id: str
    external: bool


def active_admins(db: Session) -> dict[str, User]:
    """Active admins of the session's organisation by user id."""
    rows = db.scalars(select(User).join(OrganizationMembership, OrganizationMembership.user_id == User.id)
                      .where(User.is_active.is_(True), OrganizationMembership.role == "admin"))
    return {u.id: u for u in rows}


def resolve(db: Session, sub: ExecReportSubscription) -> tuple[list[Target], int]:
    """(who gets the report now, how many recipients were skipped)."""
    rows = list(db.scalars(select(ExecReportRecipient).where(ExecReportRecipient.subscription_id == sub.id)
                           .order_by(ExecReportRecipient.created_at)))
    admins = active_admins(db)
    out: list[Target] = []
    skipped = 0
    seen: set[str] = set()
    for r in rows:
        if r.unsubscribed_at is not None:
            skipped += 1
            continue
        if r.kind == "admin":
            u = admins.get(r.user_id or "")
            if u is None:  # no longer an active admin of this organisation
                skipped += 1
                continue
            email, name = u.email.lower(), u.name or ""
        else:
            email, name = r.email.lower(), r.name
        if email in seen:
            continue
        seen.add(email)
        out.append(Target(email, name, r.id, r.kind == "external"))
    return out[:MAX_RECIPIENTS], skipped


# ----------------------------------------------------------------------------- email
def render_email(*, org: str, report: dict, name: str, link: str | None, unsub: str | None,
                 recipient: str) -> tuple[str, str, str]:
    brand = _clip(_header_safe(config.settings.brand_name), 64)
    org = _clip(_header_safe(org), 200)
    period = report["period"]
    subject = _clip(f"{period['name']} security report for {org}", 200)
    head = report["headline"]["text"]
    top = [t["title"] for t in report["top_risks"][:3]]
    greet = f"Hello {_header_safe(recipient)}," if recipient else "Hello,"
    text = "\n".join([greet, "", f"The {period['name'].lower()} security report for {org} covering "
                      f"{period['label']} is attached (PDF).", "", head, "",
                      *(["Biggest risks:", *[f"- {t}" for t in top], ""] if top else []),
                      *([f"Open in {brand}: {link}", ""] if link else []), "--", brand,
                      "This report is confidential. You receive it because an administrator of your organisation "
                      "added you as a recipient.",
                      *([f"Stop receiving it: {unsub}"] if unsub else [])]) + "\n"
    e = html.escape
    rows = "".join(f"<li style=\"margin:0 0 6px\">{e(t)}</li>" for t in top)
    body = (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>{e(subject)}</title></head><body style=\"margin:0;padding:0;background:#f4f5f7\">"
        "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" "
        "style=\"background:#f4f5f7\"><tr><td align=\"center\" style=\"padding:24px 12px\">"
        "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" "
        "style=\"max-width:560px;background:#ffffff;border:1px solid #e5e7eb;border-radius:8px\">"
        "<tr><td style=\"padding:32px;font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:22px;"
        "color:#111827\">"
        f"<p style=\"margin:0 0 20px;font-size:13px;font-weight:bold;color:#374151\">{e(brand)}</p>"
        f"<h1 style=\"margin:0 0 16px;font-size:20px;line-height:28px\">{e(period['name'])} security report</h1>"
        f"<p style=\"margin:0 0 16px\">{e(greet)}<br>The report for <strong>{e(org)}</strong> covering "
        f"{e(period['label'])} is attached (PDF).</p>"
        f"<p style=\"margin:0 0 16px;font-weight:bold\">{e(head)}</p>"
        + (f"<p style=\"margin:0 0 6px\">Biggest risks:</p><ul style=\"margin:0 0 16px;padding-left:20px\">{rows}</ul>"
           if top else "")
        + (f"<p style=\"margin:0\"><a href=\"{e(link, quote=True)}\" style=\"color:#2563eb\">Open in {e(brand)}</a></p>"
           if link else "")
        + "</td></tr></table>"
        "<p style=\"margin:16px 0 0;font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#6b7280\">"
        f"{e(brand)}<br>This report is confidential. You receive it because an administrator of your organisation "
        "added you as a recipient."
        + (f"<br><a href=\"{e(unsub, quote=True)}\" style=\"color:#6b7280\">Stop receiving this report</a>"
           if unsub else "")
        + "</p></td></tr></table></body></html>")
    return subject, text, body


# ----------------------------------------------------------------------------- sending
@dataclass
class SendOutcome:
    status: str  # sent | partial | failed
    sent: int = 0
    errors: list[str] = field(default_factory=list)
    size: int = 0


def send_subscription(db: Session, sub: ExecReportSubscription, *, now: datetime | None = None,
                      actor: User | None = None, trigger: str = "scheduled") -> SendOutcome:
    """Build the report, email it with the PDF attached to each current recipient, record and audit. Commits."""
    now = now or utcnow()
    targets, skipped = resolve(db, sub)
    out = SendOutcome("failed")
    if not targets:
        out.errors.append("no recipient to send to (add someone, or they have unsubscribed)")
    elif not mailer.configured():
        out.errors.append("no platform mail server configured (PLATFORM_SMTP_HOST)")
    else:
        try:
            report = data.build(db, sub.frequency, now)
            blob = pdf.render(report)
        except Exception:
            log.exception("building executive report %s failed", sub.id)
            report, blob = {}, b""
            out.errors.append("building the report failed; see the server log")
        out.size = len(blob)
        if blob and len(blob) > config.settings.compliance_report_max_bytes:
            out.errors.append(f"report is {len(blob)} bytes, over the size limit")
        elif blob:
            base = (config.settings.public_base_url or "").rstrip("/")
            org_id = tenancy.require_org(db)
            fname = f"executive-report-{now:%Y%m%d}.pdf"
            for t in targets:
                subject, text, body = render_email(
                    org=report["organization"], report=report, name=sub.name, recipient=t.name,
                    link=None if t.external or not base else f"{base}/executive-report",
                    unsub=unsubscribe_url(org_id, t.recipient_id) if t.external else None)
                res = mailer.send(t.email, subject, text, body, attachments=[(fname, "application/pdf", blob)])
                if res.sent:
                    out.sent += 1
                else:
                    out.errors.append(f"{t.email.split('@')[-1]}: {res.error}")
    if out.sent and out.sent == len(targets):
        out.status = "sent"
    elif out.sent:
        out.status = "partial"
    if skipped:
        out.errors.append(f"{skipped} recipient(s) skipped (unsubscribed or no longer an admin)")
    sub.last_run_at = now
    sub.last_status = out.status
    sub.last_error = "; ".join(out.errors)[:2000] or None
    if trigger == "scheduled":
        sub.next_run_at = next_run(sub.frequency, sub.day, sub.hour, now)
    audit(db, "exec_report_sent" if out.sent else "exec_report_failed", actor=actor,
          actor_email=None if actor else "system", target=f"exec-report:{sub.id}", trigger=trigger,
          frequency=sub.frequency, recipients=out.sent, status=out.status, size_bytes=out.size, errors=out.errors[:5])
    db.commit()
    return out


def run_due(db: Session, now: datetime) -> int:
    due = list(db.scalars(select(ExecReportSubscription).where(
        ExecReportSubscription.enabled.is_(True), ExecReportSubscription.next_run_at.is_not(None),
        ExecReportSubscription.next_run_at <= now).order_by(ExecReportSubscription.next_run_at)))
    for s in due:
        send_subscription(db, s, now=now)
    return len(due)


def count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(ExecReportSubscription)) or 0


@dataclass
class ReportTick:
    leader: bool
    sent: dict[str, int] = field(default_factory=dict)  # organisation id -> subscriptions processed


class ExecReportWorker:
    """Leader-elected like the compliance report worker; `tick()` takes `now` so tests can drive it."""

    LOCK_NAME = "executive-reports"

    def __init__(self, tick_seconds: float = 300.0, clock: Callable[[], datetime] = utcnow):
        self.tick_seconds = tick_seconds
        self.clock = clock
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._leader = LeaderLock(self.LOCK_NAME)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="executive-reports", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
        if not (self._thread and self._thread.is_alive()):
            self._leader.release()

    def tick(self, now: datetime | None = None) -> ReportTick:
        leader = self._leader.held() if self._leader.acquired else self._leader.try_acquire()
        if not leader:
            return ReportTick(False)
        now = now or self.clock()
        result = ReportTick(True)
        for org_id, db in tenancy.for_each_active_org():
            try:
                n = run_due(db, now)
                if n:
                    result.sent[org_id] = n
            except Exception:
                db.rollback()
                log.exception("executive reports of organisation %s failed", org_id)
        return result

    def _run(self) -> None:
        while True:
            try:
                self.tick()
            except Exception:
                log.exception("executive report tick failed")
            if self._stop.wait(self.tick_seconds):
                return
