"""Vulnerabilities with runtime context."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..engine.risk import noise_reduction
from ..models import Vulnerability
from ..schemas import VulnerabilityOut

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


def vuln_out(v: Vulnerability) -> VulnerabilityOut:
    o = VulnerabilityOut.model_validate(v)
    o.asset_name, o.asset_type = v.asset.name, v.asset.type
    return o


@router.get("", response_model=list[VulnerabilityOut])
def list_vulns(
    db: Session = Depends(get_db),
    in_use: bool | None = None,
    internet_exposed: bool | None = None,
    priority: str | None = None,
    severity: str | None = None,
    asset_id: str | None = None,
    cve_id: str | None = None,
    sort: str = Query("risk", pattern="^(risk|cvss)$"),
    limit: int = Query(500, le=5000),
):
    stmt = select(Vulnerability).where(Vulnerability.status == "open")
    if in_use is not None:
        stmt = stmt.where(Vulnerability.in_use.is_(in_use))
    if internet_exposed is not None:
        stmt = stmt.where(Vulnerability.internet_exposed.is_(internet_exposed))
    if priority:
        stmt = stmt.where(Vulnerability.priority == priority)
    if severity:
        stmt = stmt.where(Vulnerability.severity == severity)
    if asset_id:
        stmt = stmt.where(Vulnerability.asset_id == asset_id)
    if cve_id:
        stmt = stmt.where(Vulnerability.cve_id == cve_id)
    order = Vulnerability.risk_score.desc() if sort == "risk" else Vulnerability.cvss.desc()
    return [vuln_out(v) for v in db.scalars(stmt.order_by(order, Vulnerability.cvss.desc()).limit(limit))]


@router.get("/stats")
def vuln_stats(db: Session = Depends(get_db)):
    vulns = list(db.scalars(select(Vulnerability).where(Vulnerability.status == "open")))
    nr = noise_reduction(v.in_use for v in vulns)
    crit_cvss = [v for v in vulns if v.severity == "critical"]
    return {
        "noise_reduction": nr,
        "by_severity": {s: sum(1 for v in vulns if v.severity == s) for s in ("critical", "high", "medium", "low")},
        "by_priority": {s: sum(1 for v in vulns if v.priority == s) for s in ("critical", "high", "medium", "low")},
        "critical_cvss_total": len(crit_cvss),
        "critical_cvss_in_use": sum(1 for v in crit_cvss if v.in_use),
        "in_use_and_exposed": sum(1 for v in vulns if v.in_use and v.internet_exposed),
        "exploitable_in_use": sum(1 for v in vulns if v.in_use and v.exploit_available),
    }
