"""Persist connector output and run the posture rules engine."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..connectors.base import CollectionResult
from ..engine import posture
from ..engine.risk import cvss_severity, priority_for, vuln_risk_score
from ..models import Asset, Finding, Relationship, Vulnerability, new_id, utcnow
from ..notifications import builtin as notify


def ingest_collection(db: Session, result: CollectionResult, source: str) -> dict:
    """Upsert assets / relationships / vulns from a connector, then evaluate posture.

    Findings previously opened by the same source on re-scanned assets that now
    pass are marked `resolved`. Suppressed findings are left suppressed.
    """
    now = utcnow()
    seen_ids: set[str] = set()
    for rec in result.assets:
        aid = rec.id
        seen_ids.add(aid)
        a = db.get(Asset, aid)
        if a is None:
            a = Asset(id=aid, first_seen=now)
            db.add(a)
        a.name = rec.name
        a.type = rec.type
        a.provider = rec.provider
        a.subscription_id = rec.subscription_id
        a.subscription_name = rec.subscription_name
        a.resource_group = rec.resource_group
        a.region = rec.region
        a.tags = dict(rec.tags or {})
        a.internet_exposed = rec.internet_exposed
        a.sensitive_data = rec.sensitive_data
        a.properties = dict(rec.properties or {})
        a.source = source
        a.last_seen = now
    db.flush()

    for rel in result.relationships:
        if rel.source_id not in seen_ids and db.get(Asset, rel.source_id) is None:
            continue
        if rel.target_id not in seen_ids and db.get(Asset, rel.target_id) is None:
            continue
        exists = db.scalar(
            select(Relationship).where(
                Relationship.source_id == rel.source_id,
                Relationship.target_id == rel.target_id,
                Relationship.type == rel.type,
            )
        )
        if exists is None:
            db.add(Relationship(source_id=rel.source_id, target_id=rel.target_id, type=rel.type,
                                properties=rel.properties, source=source))
    db.flush()

    for v in result.vulnerabilities:
        vuln = Vulnerability(id=new_id(), asset_id=v.asset_id, cve_id=v.cve_id, package=v.package,
                             version=v.version, fixed_version=v.fixed_version, title=v.title, cvss=v.cvss,
                             severity=cvss_severity(v.cvss), exploit_available=v.exploit_available,
                             in_use=v.in_use, source=source)
        db.add(vuln)
        notify.vulnerability_found(db, vuln)
    db.flush()
    if result.vulnerabilities:
        rescore_vulnerabilities(db)

    stats = evaluate_posture(db, [db.get(Asset, i) for i in seen_ids], source)
    db.commit()
    return {"assets": len(seen_ids), **stats}


def asset_to_dict(a: Asset) -> dict:
    return {
        "id": a.id, "name": a.name, "type": a.type, "provider": a.provider,
        "region": a.region, "tags": a.tags or {}, "internet_exposed": a.internet_exposed,
        "sensitive_data": a.sensitive_data, "properties": a.properties or {},
    }


def evaluate_posture(db: Session, assets: list[Asset], source: str) -> dict:
    now = utcnow()
    opened = resolved = 0
    for a in assets:
        if a is None:
            continue
        failures = {r.id: (r, ev) for r, ev in posture.evaluate_asset(asset_to_dict(a))}
        existing = {f.rule_id: f for f in db.scalars(select(Finding).where(Finding.asset_id == a.id))}
        for rid, (r, ev) in failures.items():
            f = existing.get(rid)
            if f is None:
                f = Finding(id=new_id(), rule_id=rid, asset_id=a.id, title=r.title, description=r.description,
                            severity=r.severity, remediation=r.remediation, compliance=list(r.compliance),
                            evidence=ev, source=source, first_seen=now, last_seen=now)
                db.add(f)
                notify.finding_opened(db, f)
                opened += 1
            else:
                f.last_seen = now
                f.evidence = ev
                if f.status == "resolved":  # regression
                    f.status = "open"
                    f.resolved_at = None
                    notify.finding_opened(db, f, regression=True)
                    opened += 1
        for rid, f in existing.items():
            if rid not in failures and f.status == "open":
                f.status = "resolved"
                f.resolved_at = now
                resolved += 1
    db.flush()
    return {"findings_opened": opened, "findings_resolved": resolved}


def rescore_vulnerabilities(db: Session) -> None:
    """Recompute runtime context + risk score for every vulnerability.

    Exposure and sensitive-data access are derived from the asset and its
    graph neighbours (identity -> data store).
    """
    assets = {a.id: a for a in db.scalars(select(Asset))}
    rels = list(db.scalars(select(Relationship)))
    out: dict[str, list[tuple[str, str]]] = {}
    parents: dict[str, list[str]] = {}
    for r in rels:
        out.setdefault(r.source_id, []).append((r.target_id, r.type))
        if r.type == "contains":
            parents.setdefault(r.target_id, []).append(r.source_id)

    def reaches_sensitive(aid: str, depth: int = 0, seen: set | None = None) -> bool:
        seen = seen or set()
        if depth > 3 or aid in seen:
            return False
        seen.add(aid)
        for t, typ in out.get(aid, []):
            if typ in {"uses_identity", "has_access", "connects_to"}:
                ta = assets.get(t)
                if ta is not None and ta.sensitive_data:
                    return True
                if reaches_sensitive(t, depth + 1, seen):
                    return True
        return False

    for v in db.scalars(select(Vulnerability)):
        a = assets.get(v.asset_id)
        if a is None:
            continue
        v.internet_exposed = bool(a.internet_exposed)
        v.sensitive_data_access = bool(a.sensitive_data) or reaches_sensitive(a.id)
        v.risk_score = vuln_risk_score(v.cvss, v.in_use, v.internet_exposed, v.exploit_available,
                                       v.sensitive_data_access)
        v.priority = priority_for(v.risk_score)
    db.flush()
