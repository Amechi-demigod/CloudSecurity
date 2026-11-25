"""Reputation runs: start (limits, cooldown, audit), execute, store findings with the external module's lifecycle
(open / resolved automatically when a later run no longer sees it / accepted) and the per-domain summary.
All functions work in the session's organisation (callers commit) unless stated otherwise."""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ... import config, tenancy
from ... import db as dbmod
from ...auth import audit
from ...locks import advisory_lock
from ...models import ReputationDomain, ReputationFinding, ReputationRun, User, utcnow
from ...notifications import reputation_source
from .. import service as ext
from . import assess
from .hits import Hit
from .lookup import Dns, Query

log = logging.getLogger(__name__)
ExternalError = ext.ExternalError
SEVERITY_ORDER = ext.SEVERITY_ORDER
DNS_QUERY: Query | None = None  # tests replace it (None = the real resolver)
PENALTY = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
ORPHAN_AFTER = timedelta(hours=2)


def grade(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 50 else "F"


def score_of(open_by_severity: dict[str, int]) -> int:
    return max(0, 100 - sum(PENALTY.get(s, 0) * n for s, n in open_by_severity.items()))


def finding_ref(f: ReputationFinding) -> str:
    return f"REP-{f.seq:04d}"


def verified_domains(db: Session) -> list[str]:
    return sorted(ext._verified_domains(db))


# ----------------------------------------------------------------------------- starting runs
def recover_orphans(db: Session, now: datetime) -> None:
    for r in db.scalars(select(ReputationRun).where(ReputationRun.status == "running",
                                                    ReputationRun.started_at < now - ORPHAN_AFTER)):
        r.status, r.finished_at, r.message = "failed", now, "The run stopped unexpectedly."


def cooldown_left(db: Session, now: datetime | None = None) -> int:
    """Seconds until the next manual run is allowed (0 = now)."""
    now = now or utcnow()
    last = db.scalar(select(ReputationRun.started_at).where(ReputationRun.trigger == "manual")
                     .order_by(ReputationRun.started_at.desc()).limit(1))
    if last is None:
        return 0
    return max(0, int((last + timedelta(seconds=config.settings.reputation_cooldown_seconds) - now).total_seconds()))


def create_run(db: Session, trigger: str, actor: User | None, ip: str | None = None, only_domain: str | None = None,
               now: datetime | None = None) -> ReputationRun:
    """Create the run record (status running) after the checks; start it with `launch`. Only verified domains are
    ever assessed. Manual runs have a per-organisation cooldown and are audit-logged."""
    now = now or utcnow()
    domains = verified_domains(db)
    if only_domain is not None:
        only_domain = only_domain.strip().lower().rstrip(".")
        if only_domain not in domains:
            raise ExternalError(f"{only_domain} is not a verified domain of this organisation: prove ownership first", 422)
        domains = [only_domain]
    if not domains:
        raise ExternalError("no verified domains yet: add a domain in Attack surface and prove you own it", 409)
    with advisory_lock("reputation_run_start"):
        recover_orphans(db, now)
        db.flush()
        if db.scalar(select(ReputationRun.id).where(ReputationRun.status == "running").limit(1)):
            raise ext.Busy("a reputation run of this organisation is already running", 409)
        if trigger == "manual":
            left = cooldown_left(db, now)
            if left > 0:
                raise ExternalError(f"a reputation run was started recently: try again in {left} seconds", 429)
        run = ReputationRun(trigger=trigger, started_at=now, started_by=actor.email if actor else None, domains=domains)
        db.add(run)
        db.flush()
        if trigger == "manual":
            audit(db, "reputation_run_started", actor=actor, target=f"reputation_run:{run.id}", ip=ip, domains=domains)
        db.commit()
    return run


def _launch_thread(org_id: str, run_id: str) -> None:
    def main() -> None:
        try:
            execute(org_id, run_id)
        except Exception:
            log.exception("reputation run %s crashed", run_id)

    threading.Thread(target=main, name=f"reputation-{run_id[:6]}", daemon=True).start()


LAUNCHER = _launch_thread  # tests replace it to run inline


def launch(db: Session, run: ReputationRun) -> None:
    LAUNCHER(tenancy.require_org(db), run.id)


# ----------------------------------------------------------------------------- running
def execute(org_id: str, run_id: str) -> None:
    with dbmod.get_session(org_id) as db:
        run = db.get(ReputationRun, run_id)
        if run is None:
            return
        dns = Dns(DNS_QUERY, config.settings.reputation_dns_rate)
        errors: list[str] = []
        try:
            own = set(verified_domains(db))
            for domain in run.domains:
                try:
                    row = _domain_row(db, domain)
                    a = assess.run(domain, dns, dict(row.known_issuers or {}), utcnow(), own - {domain})
                    persist(db, run, row, a)
                    errors += a.notes
                    db.commit()
                except Exception as e:
                    db.rollback()
                    log.exception("reputation run %s: %s failed", run_id, domain)
                    errors.append(f"{domain}: failed ({type(e).__name__})")
            run = db.get(ReputationRun, run_id)
            run.status = "partial" if errors else "succeeded"
        except Exception as e:
            db.rollback()
            log.exception("reputation run %s failed", run_id)
            run = db.get(ReputationRun, run_id)
            run.status = "failed"
            errors.append(f"The run failed: {type(e).__name__}")
        run.finished_at = utcnow()
        run.findings_open = db.scalar(select(func.count()).select_from(ReputationFinding)
                                      .where(ReputationFinding.status == "open")) or 0
        run.message = "; ".join(errors[:5])[:1000]
        db.commit()


def _domain_row(db: Session, domain: str) -> ReputationDomain:
    row = db.scalar(select(ReputationDomain).where(ReputationDomain.domain == domain))
    if row is None:
        row = ReputationDomain(domain=domain)
        db.add(row)
        db.flush()
    return row


def _fields(h: Hit) -> dict[str, Any]:
    return {"check_id": h.check_id, "category": h.category, "domain": h.domain, "title": h.title[:255],
            "severity": h.severity, "detail": {"description": h.description, "fix": h.fix}, "evidence": h.evidence}


def persist(db: Session, run: ReputationRun, row: ReputationDomain, a: assess.Assessment) -> None:
    """Store one domain's result. A domain that did not answer DNS at all concludes nothing (no finding is closed)."""
    now = utcnow()
    if a.skipped:
        row.last_run_id, row.last_run_at = run.id, now
        return
    existing = {f.key: f for f in db.scalars(select(ReputationFinding).where(ReputationFinding.domain == a.domain))}
    by_key: dict[str, Hit] = {}
    for h in a.hits:
        by_key.setdefault(h.key, h)
    created: list[ReputationFinding] = []
    seq = db.scalar(select(func.max(ReputationFinding.seq))) or 0
    for key, h in by_key.items():
        f = existing.get(key)
        reopened = False
        if f is None:
            seq += 1
            f = ReputationFinding(seq=seq, key=key, first_seen=now, status="open")
            db.add(f)
            created.append(f)
        elif f.status == "resolved":
            f.status, f.resolved_at, reopened = "open", None, True
            created.append(f)
        for k, v in _fields(h).items():
            setattr(f, k, v)
        f.last_seen, f.last_run_id = now, run.id
        if reopened:
            f.status_note = "Re-opened: seen again by the latest run."
    for key, f in existing.items():  # not seen this time, in a category that ran to completion
        if key not in by_key and f.status != "resolved" and f.category in a.checked:
            f.status, f.resolved_at, f.last_run_id = "resolved", now, run.id
            f.status_note = "Resolved: no longer seen by the latest run."
    db.flush()
    for f in created:
        if f.severity in ("critical", "high"):
            reputation_source.finding_created(db, f)
    if a.known_issuers is not None:
        row.known_issuers = a.known_issuers
    counts = {s: 0 for s in SEVERITY_ORDER}
    for sev in db.scalars(select(ReputationFinding.severity).where(ReputationFinding.domain == a.domain,
                                                                   ReputationFinding.status == "open")):
        counts[sev] = counts.get(sev, 0) + 1
    row.counts, row.details = counts, a.details
    row.score = score_of(counts)
    row.grade = grade(row.score)
    row.last_run_id, row.last_run_at = run.id, now


# ----------------------------------------------------------------------------- findings
def accept_risk(db: Session, f: ReputationFinding, reason: str, actor: User, ip: str | None) -> None:
    if not reason.strip():
        raise ExternalError("a reason is required")
    f.status, f.status_note, f.status_by = "accepted", reason.strip()[:1000], actor.email
    audit(db, "reputation_finding_risk_accepted", actor=actor, target=f"reputation_finding:{finding_ref(f)}", ip=ip,
          reason=reason.strip()[:500])
    _rescore(db, f.domain)


def reopen(db: Session, f: ReputationFinding, actor: User, ip: str | None) -> None:
    f.status, f.status_note, f.status_by, f.resolved_at = "open", None, actor.email, None
    audit(db, "reputation_finding_reopened", actor=actor, target=f"reputation_finding:{finding_ref(f)}", ip=ip)
    _rescore(db, f.domain)


def _rescore(db: Session, domain: str) -> None:
    db.flush()
    row = db.scalar(select(ReputationDomain).where(ReputationDomain.domain == domain))
    if row is None or row.score is None:
        return
    counts = {s: 0 for s in SEVERITY_ORDER}
    for sev in db.scalars(select(ReputationFinding.severity).where(ReputationFinding.domain == domain,
                                                                   ReputationFinding.status == "open")):
        counts[sev] = counts.get(sev, 0) + 1
    row.counts, row.score = counts, score_of(counts)
    row.grade = grade(row.score)


# ----------------------------------------------------------------------------- serializers
def finding_out(f: ReputationFinding, *, full: bool = False) -> dict[str, Any]:
    out = {"id": f.id, "ref": finding_ref(f), "check_id": f.check_id, "category": f.category, "domain": f.domain,
           "title": f.title, "severity": f.severity, "status": f.status, "first_seen": f.first_seen,
           "last_seen": f.last_seen, "resolved_at": f.resolved_at, "description": f.detail.get("description"),
           "fix": f.detail.get("fix")}
    if full:
        out.update({"evidence": f.evidence, "status_note": f.status_note, "status_by": f.status_by})
    return out


def run_out(r: ReputationRun) -> dict[str, Any]:
    return {"id": r.id, "trigger": r.trigger, "status": r.status, "started_at": r.started_at,
            "finished_at": r.finished_at, "started_by": r.started_by, "domains": r.domains,
            "findings_open": r.findings_open, "message": r.message}


def domain_out(domain: str, row: ReputationDomain | None, *, full: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {"domain": domain, "score": row.score if row else None, "grade": row.grade if row else None,
                           "counts": row.counts if row else {}, "last_run_at": row.last_run_at if row else None,
                           "last_run_id": row.last_run_id if row else None}
    if full:
        out["details"] = row.details if row else {}
    return out


def summary(db: Session, now: datetime | None = None) -> dict[str, Any]:
    rows = {r.domain: r for r in db.scalars(select(ReputationDomain))}
    last = db.scalar(select(ReputationRun).order_by(ReputationRun.started_at.desc()).limit(1))
    return {"domains": [domain_out(d, rows.get(d)) for d in verified_domains(db)],
            "last_run": run_out(last) if last else None, "cooldown_seconds_left": cooldown_left(db, now),
            "checks": {"blocklists_enabled": bool(config.settings.reputation_dnsbl_zones
                                                  or config.settings.reputation_dnsbl_domain_zones),
                       "certificate_transparency_enabled": config.settings.reputation_ct_enabled}}
