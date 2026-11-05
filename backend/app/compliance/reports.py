"""Scheduled compliance reports: emailed PDF (docs/COMPLIANCE.md#scheduled-reports).

An admin configures, per organisation, the frameworks, weekly or monthly
delivery (day and hour, UTC) and recipients, who must be active members of the
organisation (a report describes the organisation's weaknesses: it is not sent
to arbitrary addresses). The leader-elected worker sends what is due through
the platform mailer (app/mailer.py, BRAND_NAME) with the PDF attached. A
missed slot (server down) is sent once on the next tick, never repeated for
every missed period.
"""
from __future__ import annotations

import calendar
import html
import logging
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import config, mailer, tenancy
from ..auth import audit
from ..locks import LeaderLock
from ..models import Organization, OrganizationMembership, User, utcnow
from ..notifications.channels import _clip, _header_safe
from . import catalog, checks, pdf, service
from .models import ComplianceReportSchedule

log = logging.getLogger(__name__)
MAX_SCHEDULES = 10
MAX_RECIPIENTS = 20
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")


def next_run(frequency: str, day: int, hour: int, after: datetime) -> datetime:
    """The first slot strictly after `after` (UTC, naive)."""
    if frequency == "weekly":
        base = after.replace(hour=hour, minute=0, second=0, microsecond=0)
        cand = base + timedelta(days=(day - base.weekday()) % 7)
        return cand if cand > after else cand + timedelta(days=7)
    y, m = after.year, after.month
    for _ in range(3):
        cand = datetime(y, m, min(day, calendar.monthrange(y, m)[1]), hour)
        if cand > after:
            return cand
        y, m = (y + 1, 1) if m == 12 else (y, m + 1)
    raise AssertionError("unreachable")


def member_emails(db: Session) -> set[str]:
    """Lower-case emails of the active members of the session's organisation."""
    return {e.lower() for e in db.scalars(select(User.email).join(
        OrganizationMembership, OrganizationMembership.user_id == User.id).where(User.is_active.is_(True)))}


def org_name(db: Session) -> str:
    oid = tenancy.org_id(db)
    org = db.get(Organization, oid) if oid else None
    return org.name if org is not None else ""


def build_pdf(db: Session, framework_ids: list[str], scope: checks.Scope, *, name: str = "",
              now: datetime | None = None) -> tuple[bytes, list[dict]]:
    """(PDF, per-framework summaries) for the session's organisation."""
    now = now or utcnow()
    fws = [fw for fid in framework_ids if (fw := catalog.get(fid)) is not None]
    results = service.evaluate_frameworks(db, fws, scope, now)
    postures = [service.posture(db, fw, scope, results, now) for fw in fws]
    data = pdf.render(postures, org_name=org_name(db), generated_at=now, scope_label=scope.label(),
                      report_name=name)
    return data, [{"name": p["framework"]["name"], **p["summary"]} for p in postures]


def render_email(*, org: str, report: str, summaries: list[dict], link: str | None) -> tuple[str, str, str]:
    brand = _clip(_header_safe(config.settings.brand_name), 64)
    org, report = _clip(_header_safe(org), 200), _clip(_header_safe(report), 128)
    subject = _clip(f"{report}: compliance report for {org}", 200)
    lines = [f"{s['name']}: score {_pct(s['score'])}, automated coverage {_pct(s['coverage'])}, "
             f"{s['fail']} control(s) failing" for s in summaries]
    text = "\n".join([f"{report} ({org})", "", "The compliance report is attached (PDF).", "", *lines, "",
                      service.DISCLAIMER, *(["", f"Open in {brand}: {link}"] if link else []), "", "--", brand,
                      "You receive this because an administrator of your organisation scheduled it."]) + "\n"
    e = html.escape
    rows = "".join(f"<li style=\"margin:0 0 6px\">{e(x)}</li>" for x in lines)
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
        f"<h1 style=\"margin:0 0 16px;font-size:20px;line-height:28px\">{e(report)}</h1>"
        f"<p style=\"margin:0 0 16px\">The compliance report for <strong>{e(org)}</strong> is attached (PDF).</p>"
        f"<ul style=\"margin:0 0 16px;padding-left:20px\">{rows}</ul>"
        f"<p style=\"margin:0 0 16px;font-size:13px;color:#92400e\">{e(service.DISCLAIMER)}</p>"
        + (f"<p style=\"margin:0\"><a href=\"{e(link, quote=True)}\" style=\"color:#2563eb\">Open in {e(brand)}</a>"
           "</p>" if link else "")
        + "</td></tr></table>"
        "<p style=\"margin:16px 0 0;font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#6b7280\">"
        f"{e(brand)}<br>You receive this because an administrator of your organisation scheduled it.</p>"
        "</td></tr></table></body></html>")
    return subject, text, body


def _pct(v) -> str:
    return "n/a" if v is None else f"{v:g}%"


@dataclass
class SendOutcome:
    status: str  # sent | partial | failed
    sent: int = 0
    errors: list[str] = field(default_factory=list)
    size: int = 0


def send_report(db: Session, sched: ComplianceReportSchedule, *, now: datetime | None = None,
                actor: User | None = None, trigger: str = "scheduled") -> SendOutcome:
    """Build the PDF, email it to the schedule's recipients who are still members, record and audit. Commits."""
    now = now or utcnow()
    members = member_emails(db)
    recipients = [r for r in sched.recipients or [] if r in members][:MAX_RECIPIENTS]
    dropped = len(sched.recipients or []) - len(recipients)
    out = SendOutcome("failed")
    scope = checks.Scope(account=sched.account or None, device_group=sched.device_group or None)
    fids = [f for f in sched.frameworks or [] if catalog.get(f)]
    if not recipients:
        out.errors.append("no recipient is an active member of the organisation")
    elif not fids:
        out.errors.append("no known framework selected")
    elif not mailer.configured():
        out.errors.append("no platform mail server configured (PLATFORM_SMTP_HOST)")
    else:
        try:
            data, summaries = build_pdf(db, fids, scope, name=sched.name, now=now)
        except Exception:
            log.exception("building compliance report %s failed", sched.id)
            data, summaries = b"", []
            out.errors.append("building the report failed; see the server log")
        out.size = len(data)
        if data and len(data) > config.settings.compliance_report_max_bytes:
            out.errors.append(f"report is {len(data)} bytes, over COMPLIANCE_REPORT_MAX_BYTES; "
                              "narrow it to fewer frameworks or one scope")
        elif data:
            base = (config.settings.public_base_url or "").rstrip("/")
            subject, text, body = render_email(org=org_name(db), report=sched.name,
                                               summaries=summaries, link=f"{base}/compliance" if base else None)
            fname = f"compliance-report-{now:%Y%m%d}.pdf"
            for r in recipients:
                res = mailer.send(r, subject, text, body, attachments=[(fname, "application/pdf", data)])
                if res.sent:
                    out.sent += 1
                else:
                    out.errors.append(f"{r.split('@')[-1]}: {res.error}")
    if out.sent and out.sent == len(recipients):
        out.status = "sent"
    elif out.sent:
        out.status = "partial"
    if dropped:
        out.errors.append(f"{dropped} recipient(s) skipped: no longer members of the organisation")
    sched.last_run_at = now
    sched.last_status = out.status
    sched.last_error = "; ".join(out.errors)[:2000] or None
    if trigger == "scheduled":
        sched.next_run_at = next_run(sched.frequency, sched.day, sched.hour, now)
    audit(db, "compliance_report_sent" if out.sent else "compliance_report_failed", actor=actor,
          actor_email=None if actor else "system", target=f"compliance-schedule:{sched.id}", trigger=trigger,
          frameworks=fids, recipients=out.sent, status=out.status, size_bytes=out.size,
          errors=out.errors[:5])
    db.commit()
    return out


def run_due(db: Session, now: datetime) -> int:
    due = list(db.scalars(select(ComplianceReportSchedule).where(
        ComplianceReportSchedule.enabled.is_(True), ComplianceReportSchedule.next_run_at.is_not(None),
        ComplianceReportSchedule.next_run_at <= now).order_by(ComplianceReportSchedule.next_run_at)))
    for s in due:
        send_report(db, s, now=now)
    return len(due)


def count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(ComplianceReportSchedule)) or 0


@dataclass
class ReportTick:
    leader: bool
    sent: dict[str, int] = field(default_factory=dict)  # organisation id -> reports processed


class ComplianceReportWorker:
    """Leader-elected like the dashboard snapshot job; `tick()` takes `now` so tests can drive it."""

    LOCK_NAME = "compliance-reports"

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
        self._thread = threading.Thread(target=self._run, name="compliance-reports", daemon=True)
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
                log.exception("compliance reports of organisation %s failed", org_id)
        return result

    def _run(self) -> None:
        while True:
            try:
                self.tick()
            except Exception:
                log.exception("compliance report tick failed")
            if self._stop.wait(self.tick_seconds):
                return
