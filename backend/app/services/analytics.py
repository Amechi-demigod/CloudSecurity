"""Read-side aggregations: attack paths, dashboard, compliance."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..engine import posture
from ..engine.attack_paths import compute_attack_paths
from ..engine.risk import noise_reduction, overall_risk_score
from ..models import Alert, Asset, Finding, Relationship, RuntimeEvent, Vulnerability, utcnow

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def attack_paths(db: Session, limit: int = 20, include_unconfirmed: bool = True):
    """Top attack paths (confirmed first). `include_unconfirmed=False`: confirmed paths only."""
    assets = {a.id: {"id": a.id, "name": a.name, "type": a.type, "internet_exposed": a.internet_exposed,
                     "sensitive_data": a.sensitive_data, "properties": a.properties or {}}
              for a in db.scalars(select(Asset))}
    rels = [{"source_id": r.source_id, "target_id": r.target_id, "type": r.type, "properties": r.properties or {}}
            for r in db.scalars(select(Relationship))]
    vulns: dict[str, list] = defaultdict(list)
    for v in db.scalars(select(Vulnerability).where(Vulnerability.status == "open",
                                                    Vulnerability.asset_id.is_not(None))):
        vulns[v.asset_id].append({"cve_id": v.cve_id, "package": v.package, "cvss": v.cvss, "in_use": v.in_use,
                                  "exploit_available": v.exploit_available, "risk_score": v.risk_score})
    findings: dict[str, list] = defaultdict(list)
    for f in db.scalars(select(Finding).where(Finding.status == "open")):
        findings[f.asset_id].append({"severity": f.severity, "title": f.title, "rule_id": f.rule_id})
    return compute_attack_paths(assets, rels, vulns, findings, limit=limit, include_unconfirmed=include_unconfirmed)


def compliance_summary(db: Session) -> list[dict]:
    """Per framework: controls passing vs failing (a control fails if any mapped rule has an open finding)."""
    failing_rules = {r for (r,) in db.execute(select(Finding.rule_id).where(Finding.status == "open").distinct())}
    frameworks: dict[str, dict] = {}
    for control, rule_ids in posture.compliance_controls().items():
        fw = " ".join(control.split(" ")[:2])  # e.g. "CIS Azure", "CIS AKS"
        d = frameworks.setdefault(fw, {"framework": fw, "controls": 0, "passing": 0, "failing_controls": []})
        d["controls"] += 1
        if any(r in failing_rules for r in rule_ids):
            d["failing_controls"].append(control)
        else:
            d["passing"] += 1
    out = []
    for d in frameworks.values():
        d["score"] = round(100.0 * d["passing"] / d["controls"], 1) if d["controls"] else 100.0
        d["failing_controls"].sort()
        out.append(d)
    return sorted(out, key=lambda d: d["framework"])


def dashboard(db: Session) -> dict:
    asset_count = db.scalar(select(func.count()).select_from(Asset)) or 0
    exposed = db.scalar(select(func.count()).select_from(Asset).where(Asset.internet_exposed.is_(True))) or 0
    open_findings = list(db.execute(select(Finding.severity).where(Finding.status == "open")).scalars())
    by_sev = Counter(open_findings)
    vulns = list(db.scalars(select(Vulnerability).where(Vulnerability.status == "open")))
    open_alerts = list(db.execute(select(Alert.severity).where(Alert.status != "resolved")).scalars())
    paths = attack_paths(db, limit=50)

    score = overall_risk_score(open_findings, [v.risk_score for v in vulns], open_alerts,
                               attack_path_count=sum(1 for p in paths if p.severity in ("critical", "high")),
                               asset_count=asset_count)

    # Alerts over time: last 24h hourly buckets by severity.
    now = utcnow().replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(hours=23)
    buckets = {(start + timedelta(hours=i)): Counter() for i in range(24)}
    for first_seen, sev in db.execute(select(Alert.first_seen, Alert.severity).where(Alert.first_seen >= start)):
        k = first_seen.replace(minute=0, second=0, microsecond=0)
        if k in buckets:
            buckets[k][sev] += 1
    alerts_over_time = [{"hour": k.isoformat() + "Z", **{s: c.get(s, 0) for s in SEV_ORDER[:4]}}
                        for k, c in sorted(buckets.items())]

    events_24h = db.scalar(select(func.count()).select_from(RuntimeEvent).where(RuntimeEvent.timestamp >= start)) or 0

    # Workload (asset) vulnerabilities carry runtime context; endpoint devices
    # have their own page, so they count in totals but not in "top risks".
    workload = [v for v in vulns if v.asset_id]
    top_vulns = sorted(workload, key=lambda v: -v.risk_score)[:5]
    crit_findings = list(db.scalars(select(Finding).where(Finding.status == "open",
                                                          Finding.severity.in_(["critical", "high"]))
                                    .order_by(Finding.severity, Finding.first_seen.desc()).limit(50)))
    crit_findings.sort(key=lambda f: SEV_ORDER.index(f.severity))
    top_risks = []
    for p in [p for p in paths if p.confirmed][:3]:
        top_risks.append({"kind": "attack_path", "id": p.id, "title": p.title, "severity": p.severity,
                          "score": p.score, "asset_id": p.entry_id})
    for v in top_vulns:
        top_risks.append({"kind": "vulnerability", "id": v.id, "title": f"{v.cve_id} in {v.package} on {v.asset.name}",
                          "severity": v.priority, "score": v.risk_score, "asset_id": v.asset_id})
    for f in crit_findings[:5]:
        top_risks.append({"kind": "finding", "id": f.id, "title": f"{f.title} ({f.asset.name})",
                          "severity": f.severity, "score": None, "asset_id": f.asset_id})

    assets_by_type = Counter(t for (t,) in db.execute(select(Asset.type)))
    return {
        "risk_score": score,
        "assets": {"total": asset_count, "internet_exposed": exposed, "by_type": dict(assets_by_type)},
        "findings_by_severity": {s: by_sev.get(s, 0) for s in SEV_ORDER[:4]},
        "open_findings": len(open_findings),
        "vulnerabilities": {
            "total": len(vulns),
            "prioritized": sum(1 for v in vulns if v.priority in ("critical", "high")),
            "by_priority": {s: sum(1 for v in vulns if v.priority == s) for s in SEV_ORDER[:4]},
            "noise_reduction": noise_reduction(v.in_use for v in workload),
            "on_devices": sum(1 for v in vulns if v.device_id),
            "kev": sum(1 for v in vulns if v.kev),
        },
        "alerts": {"open": len(open_alerts), "by_severity": dict(Counter(open_alerts)), "events_24h": events_24h},
        "alerts_over_time": alerts_over_time,
        "attack_paths": {"total": sum(1 for p in paths if p.confirmed),
                         "critical": sum(1 for p in paths if p.severity == "critical"),
                         "exposure": sum(1 for p in paths if not p.confirmed)},
        "top_risks": top_risks,
        "compliance": compliance_summary(db),
    }
