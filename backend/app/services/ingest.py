"""Persist connector output and run the posture rules engine."""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..connectors.base import CollectionResult
from ..engine import posture
from ..engine.risk import cvss_severity, priority_for, vuln_risk_score
from ..models import Asset, Finding, Relationship, Vulnerability, get_asset, new_id, utcnow
from ..notifications import builtin as notify
from .eol_vulns import sync_eol_vulnerabilities

log = logging.getLogger(__name__)

EOL_VULN_TYPES = {"web_app", "function_app", "postgresql_server", "mysql_server", "redis_cache"}


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
        a = get_asset(db, aid)
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

    # A connector can report the same edge more than once in one scan (e.g. an
    # identity granted two data roles on the same key vault). The session doesn't
    # autoflush, so track this scan's edges here instead of relying on the query.
    pending: dict[tuple[str, str, str], Relationship] = {}
    for rel in result.relationships:
        key = (rel.source_id, rel.target_id, rel.type)
        if key in pending:
            _merge_relationship_properties(pending[key], rel.properties)
            continue
        if rel.source_id not in seen_ids and get_asset(db, rel.source_id) is None:
            continue
        if rel.target_id not in seen_ids and get_asset(db, rel.target_id) is None:
            continue
        exists = db.scalar(
            select(Relationship).where(
                Relationship.source_id == rel.source_id,
                Relationship.target_id == rel.target_id,
                Relationship.type == rel.type,
            )
        )
        if exists is None:
            exists = Relationship(source_id=rel.source_id, target_id=rel.target_id, type=rel.type,
                                  properties=dict(rel.properties or {}), source=source)
            db.add(exists)
        else:  # re-reported by this scan: its properties (role, NSG level...) reflect the current state
            exists.properties = dict(rel.properties or {})
        pending[key] = exists
    db.flush()

    _upsert_vulnerabilities(db, result, source, seen_ids, now)

    scanned = [get_asset(db, i) for i in seen_ids]
    stats = evaluate_posture(db, scanned, source)
    # end-of-life runtimes / database engines also land on the Vulnerabilities page
    eol_assets = [a for a in scanned if a is not None and a.type in EOL_VULN_TYPES]
    if eol_assets:
        stats.update(sync_eol_vulnerabilities(db, eol_assets, now))
        rescore_vulnerabilities(db)
    db.commit()
    return {"assets": len(seen_ids), **stats}


def _vuln_key(asset_id: str | None, cve_id: str, package: str) -> tuple[str | None, str, str]:
    return asset_id, cve_id, package


def _upsert_vulnerabilities(db: Session, result: CollectionResult, source: str, seen_ids: set[str],
                            now) -> None:
    """Connector vulnerabilities are upserted per (asset, CVE, package) of this source,
    so a re-scan updates the existing rows instead of adding a copy of each one.

    * reported again: fields refreshed, `last_seen` set; a resolved one is reopened;
    * new: inserted and notified;
    * open but no longer reported for a re-scanned asset: resolved;
    * duplicates of one key left by older versions (every scan used to insert
      the whole list again) are removed, keeping the oldest row.
    """
    existing: dict[tuple, Vulnerability] = {}
    duplicates: list[Vulnerability] = []
    if seen_ids:
        rows = db.scalars(select(Vulnerability).where(Vulnerability.source == source,
                                                      Vulnerability.asset_id.in_(list(seen_ids)))
                          .order_by(Vulnerability.first_seen, Vulnerability.id))
        for row in rows:
            key = _vuln_key(row.asset_id, row.cve_id, row.package)
            if key in existing:
                duplicates.append(row)
            else:
                existing[key] = row
    for dup in duplicates:
        db.delete(dup)
    if duplicates:
        log.info("removed %d duplicate %s vulnerabilities left by earlier scans", len(duplicates), source)

    reported: set[tuple] = set()
    for v in result.vulnerabilities:
        key = _vuln_key(v.asset_id, v.cve_id, v.package)
        if key in reported:
            continue
        reported.add(key)
        vuln = existing.get(key)
        if vuln is None:
            vuln = Vulnerability(id=new_id(), asset_id=v.asset_id, cve_id=v.cve_id, package=v.package,
                                 version=v.version, fixed_version=v.fixed_version, title=v.title, cvss=v.cvss,
                                 severity=cvss_severity(v.cvss), exploit_available=v.exploit_available,
                                 in_use=v.in_use, source=source, first_seen=now, last_seen=now)
            db.add(vuln)
            notify.vulnerability_found(db, vuln)
            continue
        vuln.version = v.version
        vuln.fixed_version = v.fixed_version
        vuln.title = v.title
        vuln.cvss = v.cvss
        vuln.severity = cvss_severity(v.cvss)
        vuln.exploit_available = v.exploit_available
        if vuln.in_use_source is None:  # runtime evidence from a sensor wins over the connector's flag
            vuln.in_use = v.in_use
        vuln.last_seen = now
        if vuln.status != "open":
            vuln.status, vuln.resolved_at = "open", None
    for key, vuln in existing.items():
        if key not in reported and vuln.status == "open":
            vuln.status, vuln.resolved_at = "resolved", now
    db.flush()
    if result.vulnerabilities or existing:
        rescore_vulnerabilities(db)


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
            # a rule can give a specific title (e.g. "Runtime PHP 7.4 is end-of-life since 2022-11-28")
            ev = dict(ev)
            title = str(ev.pop("_title", "") or r.title)
            f = existing.get(rid)
            if f is None:
                f = Finding(id=new_id(), rule_id=rid, asset_id=a.id, title=title, description=r.description,
                            severity=r.severity, remediation=r.remediation, compliance=list(r.compliance),
                            evidence=ev, source=source, first_seen=now, last_seen=now)
                db.add(f)
                notify.finding_opened(db, f)
                opened += 1
            else:
                f.last_seen = now
                f.evidence = ev
                f.title = title
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


def _merge_relationship_properties(rel: Relationship, extra: dict | None) -> None:
    """Fold a duplicate edge's properties into the first one; a differing `role` becomes `roles`."""
    if not extra:
        return
    props = dict(rel.properties or {})
    for k, v in extra.items():
        if k not in props:
            props[k] = v
        elif k == "role" and props[k] != v:
            props["roles"] = sorted(set(props.get("roles") or [props[k]]) | {v})
    rel.properties = props
