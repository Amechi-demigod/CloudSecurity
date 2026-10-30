"""Inventory, posture findings and rule catalog endpoints."""
from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..auth import audit, client_ip, require_analyst
from ..db import get_db
from ..engine import posture
from ..engine.detection import DETECTION_RULES
from ..models import Alert, Asset, Finding, Relationship, User, Vulnerability, get_asset, utcnow
from ..notifications import builtin as notify
from ..schemas import (
    AlertOut,
    AssetOut,
    AssetRef,
    AssetSummary,
    FindingOut,
    FindingUpdate,
    RelationshipOut,
    VulnerabilityOut,
)
from ..services import dashboards

router = APIRouter(prefix="/api", tags=["inventory"])
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def finding_out(f: Finding) -> FindingOut:
    o = FindingOut.model_validate(f)
    o.asset_name, o.asset_type = f.asset.name, f.asset.type
    return o


@router.get("/assets", response_model=list[AssetSummary])
def list_assets(
    db: Session = Depends(get_db),
    type: str | None = None,
    provider: str | None = None,
    source: str | None = None,
    subscription_id: str | None = None,
    region: str | None = None,
    internet_exposed: bool | None = None,
    q: str | None = Query(None, description="Substring match on name / id"),
):
    stmt = select(Asset)
    if type:
        stmt = stmt.where(Asset.type == type)
    if provider:
        stmt = stmt.where(Asset.provider == provider)
    if source:
        stmt = stmt.where(Asset.source == source)
    if subscription_id:
        stmt = stmt.where(Asset.subscription_id == subscription_id)
    if region:
        stmt = stmt.where(Asset.region == region)
    if internet_exposed is not None:
        stmt = stmt.where(Asset.internet_exposed.is_(internet_exposed))
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(Asset.name).like(like), Asset.id.like(like)))
    assets = list(db.scalars(stmt.order_by(Asset.type, Asset.name)))

    nf = Counter(a for (a,) in db.execute(select(Finding.asset_id).where(Finding.status == "open")))
    nv: Counter = Counter()
    mr: dict[str, float] = {}
    for aid, score in db.execute(select(Vulnerability.asset_id, Vulnerability.risk_score)
                                 .where(Vulnerability.asset_id.is_not(None), Vulnerability.status == "open")):
        nv[aid] += 1
        mr[aid] = max(mr.get(aid, 0.0), score)
    na = Counter(a for (a,) in db.execute(select(Alert.asset_id).where(Alert.status != "resolved")))
    out = []
    for a in assets:
        s = AssetSummary.model_validate(a)
        s.open_findings, s.vulnerabilities, s.max_risk, s.open_alerts = nf[a.id], nv[a.id], mr.get(a.id, 0.0), na[a.id]
        out.append(s)
    return out


@router.get("/assets/facets")
def asset_facets(db: Session = Depends(get_db)):
    def distinct(col):
        return sorted(v for (v,) in db.execute(select(col).distinct()) if v)

    subs = sorted({(s, n, p) for s, n, p in db.execute(
        select(Asset.subscription_id, Asset.subscription_name, Asset.provider).distinct()) if s},
        key=lambda x: (x[2] or "", x[1] or ""))
    return {
        "types": distinct(Asset.type),
        "providers": distinct(Asset.provider),
        "sources": distinct(Asset.source),
        "regions": distinct(Asset.region),
        # Azure subscriptions, AWS accounts and GCP projects
        "subscriptions": [{"id": s, "name": n or s, "provider": p} for s, n, p in subs],
    }


@router.get("/assets/detail")
def asset_detail(id: str, db: Session = Depends(get_db)):
    """Asset detail. (`id` is a query param because ARM ids contain slashes.)"""
    a = get_asset(db, id)
    if a is None:
        raise HTTPException(404, "asset not found")
    rels = []
    for r in db.scalars(select(Relationship).where(or_(Relationship.source_id == id, Relationship.target_id == id))):
        other_id, direction = (r.target_id, "out") if r.source_id == id else (r.source_id, "in")
        other = get_asset(db, other_id)
        if other is not None:
            rels.append(RelationshipOut(type=r.type, direction=direction,
                                        asset=AssetRef(id=other.id, name=other.name, type=other.type)))
    findings = sorted(db.scalars(select(Finding).where(Finding.asset_id == id)),
                      key=lambda f: (f.status != "open", SEV_RANK.get(f.severity, 9)))
    vulns = list(db.scalars(select(Vulnerability).where(Vulnerability.asset_id == id)
                            .order_by(Vulnerability.risk_score.desc())))
    alerts = list(db.scalars(select(Alert).where(Alert.asset_id == id).order_by(Alert.last_seen.desc()).limit(50)))
    return {
        "asset": AssetOut.model_validate(a),
        "relationships": rels,
        "findings": [finding_out(f) for f in findings],
        "vulnerabilities": [VulnerabilityOut.model_validate(v) for v in vulns],
        "alerts": [AlertOut.model_validate(x) for x in alerts],
    }


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    db: Session = Depends(get_db),
    severity: str | None = None,
    status: str | None = Query("open", description="open|resolved|suppressed|all"),
    rule_id: str | None = None,
    asset_id: str | None = None,
    source: str | None = None,
    provider: str | None = Query(None, description="Cloud of the affected asset: azure|aws|gcp"),
    subscription_id: str | None = Query(None, description="Azure subscription, AWS account or GCP project"),
    compliance: str | None = Query(None, description="Substring of a compliance control, e.g. 'CIS Azure 6'"),
    category: str | None = Query(None, description="Dashboard category: Network, Storage, Identity, Databases, "
                                                   "Kubernetes, Secrets, Compute or Other"),
    limit: int = Query(500, le=5000),
):
    stmt = select(Finding)
    if category:
        if category not in dashboards.CATEGORIES:
            raise HTTPException(422, f"category must be one of {', '.join(dashboards.CATEGORIES)}")
        stmt = stmt.where(dashboards.category_filter(category))
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if status and status != "all":
        stmt = stmt.where(Finding.status == status)
    if rule_id:
        stmt = stmt.where(Finding.rule_id == rule_id)
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if source:
        stmt = stmt.where(Finding.source == source)
    if provider or subscription_id:
        stmt = stmt.join(Asset, Finding.asset_id == Asset.id)
        if provider:
            stmt = stmt.where(Asset.provider == provider)
        if subscription_id:
            stmt = stmt.where(Asset.subscription_id == subscription_id)
    rows = list(db.scalars(stmt).unique())
    if compliance:
        rows = [f for f in rows if any(compliance.lower() in c.lower() for c in f.compliance or [])]
    rows.sort(key=lambda f: (SEV_RANK.get(f.severity, 9), f.rule_id, f.asset_id))
    return [finding_out(f) for f in rows[:limit]]


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(404, "finding not found")
    return finding_out(f)


@router.patch("/findings/{finding_id}", response_model=FindingOut)
def update_finding(finding_id: str, body: FindingUpdate, request: Request, user: User = Depends(require_analyst),
                   db: Session = Depends(get_db)):
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(404, "finding not found")
    if f.status != body.status:
        audit(db, "finding_updated", actor=user, target=f.id, ip=client_ip(request),
              rule_id=f.rule_id, status=[f.status, body.status])
        notify.finding_status_changed(db, f, f.status, body.status, actor=user.email)
    f.status = body.status
    f.resolved_at = utcnow() if body.status == "resolved" else None
    db.commit()
    return finding_out(f)


@router.get("/rules/posture")
def posture_rules():
    return [{"id": r.id, "title": r.title, "severity": r.severity, "resource_type": r.resource_type,
             "description": r.description, "remediation": r.remediation, "compliance": r.compliance}
            for r in posture.RULES]


@router.get("/rules/detection")
def detection_rules():
    return [{"id": r.id, "title": r.title, "severity": r.severity, "description": r.description,
             "mitre_tactic": r.mitre_tactic, "mitre_technique_id": r.mitre_technique_id,
             "mitre_technique_name": r.mitre_technique_name} for r in DETECTION_RULES]
