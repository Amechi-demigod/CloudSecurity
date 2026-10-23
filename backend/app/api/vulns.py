"""Vulnerabilities with runtime context: cloud / sensor assets and endpoint devices."""
from __future__ import annotations

from collections import Counter, defaultdict

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import config
from ..auth import audit, client_ip, require_analyst
from ..db import get_db
from ..engine.risk import noise_reduction
from ..models import Device, User, Vulnerability, VulnFeedStatus, VulnMatchState, utcnow
from ..schemas import VulnerabilityOut
from ..vulnmatch import worker as vuln_worker
from ..vulnmatch.mapping import RULES
from ..vulnmatch.state import ASSET, DEVICE

router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])

SEV_ORDER = ("critical", "high", "medium", "low", "info")
FEEDS = (
    ("nvd", "NVD CVE API (CPE matching of endpoint software)", "services.nvd.nist.gov"),
    ("osv", "OSV.dev (Linux packages reported by the runtime sensor)", "api.osv.dev"),
    ("kev", "CISA Known Exploited Vulnerabilities", "www.cisa.gov"),
    ("epss", "FIRST EPSS exploit prediction", "api.first.org"),
)


def z(dt) -> str | None:
    """Naive-UTC datetime -> ISO 8601 with Z (for plain dict responses)."""
    return dt.isoformat() + "Z" if dt is not None else None


def device_names(db: Session, ids) -> dict[str, str]:
    ids = {i for i in ids if i}
    if not ids:
        return {}
    return {i: h for i, h in db.execute(select(Device.id, Device.hostname).where(Device.id.in_(ids)))}


def vuln_out(v: Vulnerability, names: dict[str, str] | None = None) -> VulnerabilityOut:
    o = VulnerabilityOut.model_validate(v)
    if v.asset is not None:
        o.asset_name, o.asset_type = v.asset.name, v.asset.type
    if v.device_id:
        o.device_name = (names or {}).get(v.device_id)
        o.asset_type = "device"
    return o


def _filtered(stmt, *, status: str, scope: str | None, in_use, internet_exposed, priority, severity, asset_id,
              device_id, cve_id, kev, package, source):
    if status != "all":
        stmt = stmt.where(Vulnerability.status == status)
    if scope == "device":
        stmt = stmt.where(Vulnerability.device_id.is_not(None))
    elif scope == "asset":
        stmt = stmt.where(Vulnerability.asset_id.is_not(None))
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
    if device_id:
        stmt = stmt.where(Vulnerability.device_id == device_id)
    if cve_id:
        stmt = stmt.where(Vulnerability.cve_id == cve_id)
    if kev is not None:
        stmt = stmt.where(Vulnerability.kev.is_(True)) if kev else stmt.where(
            or_(Vulnerability.kev.is_(False), Vulnerability.kev.is_(None)))
    if package:
        stmt = stmt.where(func.lower(Vulnerability.package).like(f"%{package.lower()}%"))
    if source:
        stmt = stmt.where(Vulnerability.source == source)
    return stmt


class Filters:
    def __init__(self, status: str = Query("open", pattern="^(open|resolved|all)$"),
                 scope: str | None = Query(None, pattern="^(asset|device)$",
                                           description="asset (cloud / sensor hosts) or device (laptops)"),
                 in_use: bool | None = None, internet_exposed: bool | None = None, priority: str | None = None,
                 severity: str | None = None, asset_id: str | None = None, device_id: str | None = None,
                 cve_id: str | None = None, kev: bool | None = None,
                 package: str | None = Query(None, max_length=128, description="software / package name contains"),
                 source: str | None = Query(None, pattern="^(simulated|nvd|osv|eol)$")):
        self.kw = dict(status=status, scope=scope, in_use=in_use, internet_exposed=internet_exposed,
                       priority=priority, severity=severity, asset_id=asset_id, device_id=device_id, cve_id=cve_id,
                       kev=kev, package=package, source=source)


@router.get("", response_model=list[VulnerabilityOut])
def list_vulns(db: Session = Depends(get_db), f: Filters = Depends(),
               sort: str = Query("risk", pattern="^(risk|cvss|epss|recent)$"), limit: int = Query(500, le=5000)):
    stmt = _filtered(select(Vulnerability), **f.kw)
    order = {"risk": Vulnerability.risk_score.desc(), "cvss": Vulnerability.cvss.desc(),
             "epss": func.coalesce(Vulnerability.epss, -1.0).desc(), "recent": Vulnerability.first_seen.desc()}[sort]
    vulns = list(db.scalars(stmt.order_by(order, Vulnerability.cvss.desc(), Vulnerability.id).limit(limit)))
    names = device_names(db, (v.device_id for v in vulns))
    return [vuln_out(v, names) for v in vulns]


def _sev_max(sevs) -> str:
    sevs = list(sevs)
    return min(sevs, key=lambda s: SEV_ORDER.index(s) if s in SEV_ORDER else 9) if sevs else "info"


@router.get("/by-cve")
def vulns_by_cve(db: Session = Depends(get_db), f: Filters = Depends(), limit: int = Query(500, le=5000)):
    """Fleet view: one row per CVE with the devices / assets it affects."""
    vulns = list(db.scalars(_filtered(select(Vulnerability), **f.kw)))
    names = device_names(db, (v.device_id for v in vulns))
    groups: dict[str, list[Vulnerability]] = defaultdict(list)
    for v in vulns:
        groups[v.cve_id].append(v)
    out = []
    for cve, vs in groups.items():
        out.append({
            "cve_id": cve, "title": max((v.title for v in vs), key=len), "cvss": max(v.cvss for v in vs),
            "severity": _sev_max(v.severity for v in vs), "kev": any(v.kev for v in vs),
            "epss": max((v.epss for v in vs if v.epss is not None), default=None),
            "max_risk": max(v.risk_score for v in vs),
            "packages": sorted({v.package for v in vs}),
            "fixed_versions": sorted({v.fixed_version for v in vs if v.fixed_version}),
            "devices": sorted({names.get(v.device_id, v.device_id) for v in vs if v.device_id}),
            "assets": sorted({v.asset.name for v in vs if v.asset is not None}),
            "device_count": len({v.device_id for v in vs if v.device_id}),
            "asset_count": len({v.asset_id for v in vs if v.asset_id}),
            "sources": sorted({v.source for v in vs}),
        })
    out.sort(key=lambda g: (not g["kev"], SEV_ORDER.index(g["severity"]) if g["severity"] in SEV_ORDER else 9,
                            -(g["device_count"] + g["asset_count"]), -g["cvss"]))
    return out[:limit]


@router.get("/by-software")
def vulns_by_software(db: Session = Depends(get_db), f: Filters = Depends(), limit: int = Query(500, le=5000)):
    """Fleet view: one row per software / package (what to update first)."""
    vulns = list(db.scalars(_filtered(select(Vulnerability), **f.kw)))
    groups: dict[str, list[Vulnerability]] = defaultdict(list)
    for v in vulns:
        groups[v.package].append(v)
    out = []
    for pkg, vs in groups.items():
        out.append({
            "package": pkg, "cve_count": len({v.cve_id for v in vs}),
            "kev_count": len({v.cve_id for v in vs if v.kev}),
            "severity": _sev_max(v.severity for v in vs),
            "by_severity": dict(Counter(v.severity for v in vs)),
            "versions": sorted({v.version for v in vs})[:50],
            "fixed_versions": sorted({v.fixed_version for v in vs if v.fixed_version})[-5:],
            "device_count": len({v.device_id for v in vs if v.device_id}),
            "asset_count": len({v.asset_id for v in vs if v.asset_id}),
            "max_risk": max(v.risk_score for v in vs),
        })
    out.sort(key=lambda g: (-g["kev_count"], SEV_ORDER.index(g["severity"]) if g["severity"] in SEV_ORDER else 9,
                            -g["cve_count"]))
    return out[:limit]


@router.get("/stats")
def vuln_stats(db: Session = Depends(get_db)):
    vulns = list(db.scalars(select(Vulnerability).where(Vulnerability.status == "open")))
    # Noise reduction is about runtime context, which only workloads (assets) have.
    workload = [v for v in vulns if v.asset_id]
    nr = noise_reduction(v.in_use for v in workload)
    crit_cvss = [v for v in workload if v.severity == "critical"]
    devices = [v for v in vulns if v.device_id]
    return {
        "noise_reduction": nr,
        "by_severity": {s: sum(1 for v in vulns if v.severity == s) for s in ("critical", "high", "medium", "low")},
        "by_priority": {s: sum(1 for v in vulns if v.priority == s) for s in ("critical", "high", "medium", "low")},
        "critical_cvss_total": len(crit_cvss),
        "critical_cvss_in_use": sum(1 for v in crit_cvss if v.in_use),
        "in_use_and_exposed": sum(1 for v in workload if v.in_use and v.internet_exposed),
        "exploitable_in_use": sum(1 for v in workload if v.in_use and v.exploit_available),
        "total": len(vulns),
        "assets": {"open": len(workload), "affected": len({v.asset_id for v in workload})},
        "devices": {"open": len(devices), "affected": len({v.device_id for v in devices})},
        "kev": {"open": sum(1 for v in vulns if v.kev), "cves": len({v.cve_id for v in vulns if v.kev})},
    }


@router.get("/status")
def vuln_status(db: Session = Depends(get_db)):
    """Data sources, feed freshness / errors and matching coverage ("not checked")."""
    s = config.settings
    feeds = {f.feed: f for f in db.scalars(select(VulnFeedStatus))}
    states = list(db.scalars(select(VulnMatchState)))
    not_checked: Counter = Counter()
    reasons: dict[str, str] = {}
    for st in states:
        if st.target_type != DEVICE:
            continue
        for item in st.not_checked or []:
            not_checked[item.get("name", "?")] += 1
            reasons.setdefault(item.get("name", "?"), item.get("reason", ""))

    def counts(tt: str) -> dict:
        sts = [x for x in states if x.target_type == tt]
        return {"total": len(sts), "matched": sum(1 for x in sts if x.matched_at is not None),
                "pending": sum(1 for x in sts if x.requested_at is not None),
                "errors": sum(1 for x in sts if x.error),
                "last_matched_at": z(max((x.matched_at for x in sts if x.matched_at), default=None))}

    return {
        "enabled": s.vuln_matching_enabled,
        "worker_running": vuln_worker.get_worker() is not None,
        "nvd_api_key_configured": bool(s.nvd_api_key),
        "rematch_interval_hours": s.vuln_rematch_interval_hours,
        "feeds": [{"feed": k, "label": label, "host": host,
                   "last_success_at": z(feeds[k].last_success_at) if k in feeds else None,
                   "last_attempt_at": z(feeds[k].last_attempt_at) if k in feeds else None,
                   "last_error": feeds[k].last_error if k in feeds else None,
                   "items": feeds[k].items if k in feeds else None} for k, label, host in FEEDS],
        "devices": counts(DEVICE), "assets": counts(ASSET),
        "software_checked": sum(len(st.checked or []) for st in states if st.target_type == DEVICE),
        "software_not_checked": sum(not_checked.values()),
        "not_checked_top": [{"name": n, "devices": c, "reason": reasons.get(n, "")}
                            for n, c in not_checked.most_common(50)],
        "mapping_rules": len(RULES),
    }



@router.post("/rematch", status_code=202)
def rematch(request: Request, user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    """Queue every device and asset for matching now (the background worker runs it)."""
    if not config.settings.vuln_matching_enabled:
        raise HTTPException(409, "vulnerability matching is disabled (VULN_MATCHING_ENABLED=false)")
    now = utcnow()
    n = 0
    for st in db.scalars(select(VulnMatchState)):
        st.requested_at = now.replace(year=now.year - 1)  # past the debounce window
        n += 1
    audit(db, "vulnerability_rematch", actor=user, ip=client_ip(request), targets=n)
    db.commit()
    w = vuln_worker.get_worker()
    if w is not None:
        w.wake()
    return {"queued": n, "worker_running": w is not None}
