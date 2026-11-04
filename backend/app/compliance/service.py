"""Per-organisation compliance posture, snapshots and CSV (docs/COMPLIANCE.md).

`posture()` evaluates every check a framework maps once (checks.evaluate) and
derives each control's status (scoring.control_status). Everything reads the
session's organisation only (tenant-scoped session).
"""
from __future__ import annotations

import csv
import io
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..asset_lifecycle.csvio import safe_cell
from ..models import Device, utcnow
from ..services import dashboards
from . import catalog, checks, scoring
from .models import ComplianceSnapshot

DISCLAIMER = ("Automated evidence to support an assessment, not an audit opinion or a certification. "
              "Controls marked \"manual\" are not assessed automatically; \"partial\" means the automated checks "
              "pass but the control also needs manual evidence.")
TREND_DAYS_MAX = 365
CHECK_ORDER = {"fail": 0, "pass": 1, "no_data": 2, "out_of_scope": 3}


def device_groups(db: Session) -> list[str]:
    return sorted(g for g in db.scalars(select(Device.device_group).where(Device.status == "active",
                                                                        Device.device_group.is_not(None))
                                        .distinct()) if g)


def scopes(db: Session) -> dict[str, Any]:
    return {"accounts": dashboards.accounts(db), "device_groups": device_groups(db)}


def evaluate_frameworks(db: Session, fws: list[catalog.Framework], scope: checks.Scope,
                        now: datetime | None = None) -> dict[str, checks.Result]:
    ids = {c for fw in fws for ctl in fw.controls for c in ctl.checks}
    return checks.evaluate(db, ids, scope, now)


def posture(db: Session, fw: catalog.Framework, scope: checks.Scope = checks.Scope(),
            results: dict[str, checks.Result] | None = None, now: datetime | None = None) -> dict[str, Any]:
    """The framework's controls with their status and evidence, plus the summary."""
    now = now or utcnow()
    results = results if results is not None else evaluate_frameworks(db, [fw], scope, now)
    groups = []
    statuses = []
    for g in fw.groups:
        controls = []
        for c in g.controls:
            # failing evidence first, then passing, then checks with nothing to evaluate
            rs = sorted((results[x] for x in c.checks), key=lambda r: CHECK_ORDER.get(r.status, 9))
            status = scoring.control_status(c.coverage, [r.status for r in rs])
            statuses.append(status)
            controls.append({"id": c.id, "title": c.title, "status": status, "coverage": c.coverage,
                             "note": c.note, "failing": sum(r.failing for r in rs if r.status == "fail"),
                             "checks": [r.out() for r in rs]})
        groups.append({"id": g.id, "title": g.title, "controls": controls})
    return {"framework": fw.meta(), "scope": {"account": scope.account, "device_group": scope.device_group,
                                              "label": scope.label()},
            "generated_at": now, "summary": scoring.summarize(statuses), "groups": groups,
            "disclaimer": DISCLAIMER}


def overview(db: Session, scope: checks.Scope = checks.Scope(), now: datetime | None = None) -> list[dict[str, Any]]:
    """Summary of every framework (one evaluation of all their checks)."""
    fws = list(catalog.frameworks().values())
    results = evaluate_frameworks(db, fws, scope, now)
    out = []
    for fw in fws:
        p = posture(db, fw, scope, results, now)
        out.append({**fw.meta(), "summary": p["summary"]})
    return out


# ----------------------------------------------------------------------------- snapshots
def write_snapshots(db: Session, scope: checks.Scope = checks.Scope(), day: date | None = None,
                    now: datetime | None = None) -> int:
    """The day's summary of every framework for this scope (idempotent). Commits."""
    day = day or utcnow().date()
    have = set(db.scalars(select(ComplianceSnapshot.framework).where(ComplianceSnapshot.day == day,
                                                                    ComplianceSnapshot.scope == scope.key)))
    fws = [fw for fw in catalog.frameworks().values() if fw.id not in have]
    if not fws:
        return 0
    results = evaluate_frameworks(db, fws, scope, now)
    for fw in fws:
        db.add(ComplianceSnapshot(day=day, framework=fw.id, scope=scope.key, mapping_version=fw.mapping_version,
                                  summary=posture(db, fw, scope, results, now)["summary"]))
    try:
        db.commit()
    except IntegrityError:  # another worker / request wrote them first
        db.rollback()
        return 0
    return len(fws)


def snapshot_all(db: Session, day: date | None = None) -> int:
    """Whole organisation, each cloud account and each device group (daily job)."""
    n = write_snapshots(db, checks.Scope(), day)
    for a in dashboards.accounts(db):
        n += write_snapshots(db, checks.Scope(account=a["id"]), day)
    for g in device_groups(db):
        n += write_snapshots(db, checks.Scope(device_group=g), day)
    return n


def ensure_today(db: Session, scope: checks.Scope) -> None:
    today = utcnow().date()
    exists = db.scalar(select(func.count()).select_from(ComplianceSnapshot).where(
        ComplianceSnapshot.day == today, ComplianceSnapshot.scope == scope.key))
    if not exists:
        write_snapshots(db, scope, today)


def trend(db: Session, framework_id: str, scope: checks.Scope, days: int = 90) -> list[dict[str, Any]]:
    days = max(1, min(days, TREND_DAYS_MAX))
    start = utcnow().date() - timedelta(days=days - 1)
    rows = db.execute(select(ComplianceSnapshot.day, ComplianceSnapshot.summary, ComplianceSnapshot.mapping_version)
                      .where(ComplianceSnapshot.framework == framework_id, ComplianceSnapshot.scope == scope.key,
                             ComplianceSnapshot.day >= start).order_by(ComplianceSnapshot.day)).all()
    return [{"day": d.isoformat(), "mapping_version": mv, **{k: (s or {}).get(k) for k in
                                                             ("score", "coverage", "pass", "fail", "partial",
                                                              "no_data", "manual", "assessed", "total")}}
            for d, s, mv in rows]


# ----------------------------------------------------------------------------- CSV
CSV_COLUMNS = ["framework", "group", "control", "title", "status", "coverage", "check", "check_title",
               "check_status", "failing", "evaluated", "detail", "note"]


def to_csv(p: dict[str, Any]) -> bytes:
    """One row per (control, check); manual controls get one row without a check."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["# " + p["disclaimer"]])
    w.writerow(["# scope: " + p["scope"]["label"], "generated: " + p["generated_at"].strftime("%Y-%m-%d %H:%M UTC")])
    w.writerow(CSV_COLUMNS)
    fw = p["framework"]["short_name"]
    for g in p["groups"]:
        for c in g["controls"]:
            base = [fw, g["title"], c["id"], c["title"], c["status"], c["coverage"] or "manual"]
            if not c["checks"]:
                w.writerow([safe_cell(v) for v in base + ["", "", "", "", "", "", c["note"]]])
            for ch in c["checks"]:
                w.writerow([safe_cell(v) for v in base + [ch["id"], ch["title"], ch["status"], ch["failing"],
                                                          ch["total"], ch["detail"], c["note"]]])
    return buf.getvalue().encode("utf-8")
