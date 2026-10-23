"""Cloud exposure view: every internet-reachable asset across Azure, AWS and GCP and how it is reached.

Built from what the connectors store on assets (`exposure_methods`,
`effective_ports`, `partial_exposure`, `public_endpoint`, `network_controls`...)
plus the relationship graph (protecting network controls, private endpoints),
open findings / vulnerabilities and the attack paths starting at or passing
through the asset. Connectors that do not report exposure methods (AWS, GCP,
simulated data) are described from their `exposure` text and, for workloads
with normalized `security_rules`, the ports those rules open to the internet.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..engine import nsg
from ..models import Asset, Finding, Relationship, Vulnerability
from . import analytics

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
# Ports a PaaS / managed endpoint listens on when the connector does not list them.
DEFAULT_PORTS = {"storage_account": ["443"], "key_vault": ["443"], "sql_server": ["1433"], "s3_bucket": ["443"],
                 "gcs_bucket": ["443"], "rds_instance": [], "cloud_sql_instance": [], "function_app": ["443"],
                 "web_app": ["443"], "lambda_function": ["443"], "cloud_run_service": ["443"],
                 "cloud_function": ["443"], "aks_cluster": ["443"], "eks_cluster": ["443"], "gke_cluster": ["443"]}
CONTROL_LABEL = {"nsg": "NSG", "security_group": "security group", "gcp_firewall_rule": "firewall rule"}
METHOD_LABEL = {"public_ip": "Public IP on NIC", "load_balancer": "Public load balancer rule",
                "lb_nat": "Public load balancer NAT", "app_gateway": "Application Gateway",
                "firewall_dnat": "Azure Firewall DNAT", "firewall_dnat_frontend": "Azure Firewall DNAT (frontend)",
                "public_endpoint": "Public endpoint (PaaS)", "app_service": "App Service public endpoint"}


def _ports(item_ports: list[str]) -> nsg.PortRanges:
    return nsg.parse_ports(item_ports)


def _level(a: Asset) -> str | None:
    p = a.properties or {}
    if a.internet_exposed:
        return "open"
    lvl = p.get("exposure_level")
    if lvl in ("open", "restricted"):
        return "restricted" if lvl == "restricted" else "open"
    if p.get("public_endpoint") in ("open", "restricted"):
        return p["public_endpoint"]
    return None


def _fallback(a: Asset) -> tuple[list[dict], list[str]]:
    """Exposure methods + ports for assets whose connector does not report `exposure_methods`."""
    p = a.properties or {}
    ports: list[str] = []
    if p.get("security_rules"):  # AWS instances / GCP VMs carry the rules that apply to them
        exp = nsg.evaluate_rules(p["security_rules"], azure_defaults=a.type == "nsg")
        ports = nsg.format_ports(exp.open_ports())
    if not ports:
        ports = list(DEFAULT_PORTS.get(a.type, []))
    if p.get("public_ips"):
        kind = "public_ip"
        detail = p.get("exposure") or f"public IP {', '.join(map(str, p['public_ips']))}"
    else:
        kind = "public_endpoint"
        detail = p.get("exposure") or "public endpoint"
    return [{"kind": kind, "detail": detail, "ports": ports, "level": "open" if a.internet_exposed else "restricted",
             "partial": []}], ports


def exposure_items(db: Session, provider: str | None = None, subscription: str | None = None,
                   type_: str | None = None, port: int | None = None, level: str | None = None,
                   with_paths: bool = True) -> dict[str, Any]:
    assets = {a.id: a for a in db.scalars(select(Asset))}
    exposed = {aid: lvl for aid, a in assets.items() if (lvl := _level(a))}

    controls: dict[str, list[dict]] = defaultdict(list)
    private_eps: dict[str, list[str]] = defaultdict(list)
    for r in db.scalars(select(Relationship).where(Relationship.target_id.in_(list(exposed)))):
        src = assets.get(r.source_id)
        if src is None:
            continue
        if r.type == "protects":
            levels = (r.properties or {}).get("levels") or ([r.properties["level"]] if (r.properties or {}).get("level")
                                                            else [])
            controls[r.target_id].append({"id": src.id, "name": src.name, "type": src.type, "levels": levels})
        elif r.type == "connects_to" and src.type == "private_endpoint":
            private_eps[r.target_id].append(src.name)

    findings: dict[str, list[Finding]] = defaultdict(list)
    for f in db.scalars(select(Finding).where(Finding.status == "open", Finding.asset_id.in_(list(exposed)))):
        findings[f.asset_id].append(f)
    vulns: dict[str, list[Vulnerability]] = defaultdict(list)
    for v in db.scalars(select(Vulnerability).where(Vulnerability.status == "open",
                                                    Vulnerability.asset_id.in_(list(exposed)))):
        vulns[v.asset_id].append(v)
    paths: dict[str, list[dict]] = defaultdict(list)
    if with_paths:
        for p in analytics.attack_paths(db, limit=100):
            for i, s in enumerate(p.steps):
                if s.asset_id in exposed:
                    paths[s.asset_id].append({"id": p.id, "title": p.title, "severity": p.severity,
                                              "confirmed": p.confirmed, "score": p.score,
                                              "role": "entry" if i == 0 else "target" if s.asset_id == p.target_id
                                              else "hop"})

    items = []
    for aid, lvl in exposed.items():
        a = assets[aid]
        p = a.properties or {}
        methods = p.get("exposure_methods")
        if methods:
            ports = list(p.get("effective_ports") or [])
            if not ports and lvl == "open":
                ports = list(DEFAULT_PORTS.get(a.type, []))
        else:
            methods, ports = _fallback(a)
        partial = p.get("partial_exposure") or [x for m in methods for x in m.get("partial") or []]
        fs = sorted(findings.get(aid, []), key=lambda f: SEV_ORDER.index(f.severity) if f.severity in SEV_ORDER else 9)
        vs = sorted(vulns.get(aid, []), key=lambda v: -(v.risk_score or 0))
        via = [assets[v].name for v in p.get("exposed_only_via") or [] if v in assets]
        items.append({
            "id": a.id, "name": a.name, "type": a.type, "provider": a.provider, "subscription_id": a.subscription_id,
            "subscription_name": a.subscription_name, "resource_group": a.resource_group, "region": a.region,
            "level": lvl, "attack_path_entry": bool(a.internet_exposed) and not via,
            "exposure": p.get("exposure"), "exposed_only_via": via,
            "methods": [{**m, "label": METHOD_LABEL.get(m.get("kind", ""), m.get("kind"))} for m in methods],
            "effective_ports": ports, "partial_exposure": partial,
            "network_controls": list(p.get("network_controls") or []) or [
                f"{CONTROL_LABEL.get(c['type'], c['type'])} {c['name']}"
                + (f" ({', '.join(c['levels'])})" if c["levels"] else "") for c in controls.get(aid, [])],
            "controls": controls.get(aid, []),
            "private_endpoints": sorted(set(private_eps.get(aid, []) + list(p.get("private_endpoints") or []))),
            "public_endpoint": p.get("public_endpoint"), "public_network_access": p.get("public_network_access"),
            "sensitive_data": a.sensitive_data, "data_classification": p.get("data_classification"),
            "egress": p.get("egress"),
            "findings": {"count": len(fs), "by_severity": dict(Counter(f.severity for f in fs)),
                         "top": [{"id": f.id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity}
                                 for f in fs[:5]]},
            "vulnerabilities": {"count": len(vs), "prioritized": sum(1 for v in vs if v.priority in ("critical", "high")),
                                "top": [{"id": v.id, "cve_id": v.cve_id, "package": v.package,
                                         "severity": v.priority or v.severity} for v in vs[:3]]},
            "attack_paths": sorted(paths.get(aid, []), key=lambda x: (not x["confirmed"], -x["score"]))[:5],
        })

    facets = {"providers": sorted({i["provider"] for i in items if i["provider"]}),
              "subscriptions": sorted({i["subscription_id"] for i in items if i["subscription_id"]}),
              "types": sorted({i["type"] for i in items}),
              "ports": sorted({x for i in items for x in i["effective_ports"]}, key=lambda s: (len(s), s))}

    def keep(i: dict) -> bool:
        if provider and i["provider"] != provider:
            return False
        if subscription and i["subscription_id"] != subscription:
            return False
        if type_ and i["type"] != type_:
            return False
        if level and i["level"] != level:
            return False
        if port is not None:
            ranges = _ports(i["effective_ports"]) + [r for x in i["partial_exposure"] for r in _ports(x.get("ports") or [])]
            if not nsg.contains(ranges, port):
                return False
        return True

    items = [i for i in items if keep(i)]
    items.sort(key=lambda i: (i["level"] != "open", not i["attack_path_entry"],
                              -sum(1 for x in i["attack_paths"] if x["confirmed"]),
                              -i["findings"]["by_severity"].get("critical", 0) - i["findings"]["by_severity"].get("high", 0),
                              i["name"]))
    return {"items": items, "facets": facets, "summary": summarize(items)}


def summarize(items: list[dict]) -> dict[str, Any]:
    risky = {22, 3389, 5985, 5986, 445, 1433, 3306, 5432, 6379, 27017}
    return {
        "total": len(items),
        "open": sum(1 for i in items if i["level"] == "open"),
        "restricted": sum(1 for i in items if i["level"] == "restricted"),
        "attack_path_entries": sum(1 for i in items if i["attack_path_entry"]),
        "risky_ports_open": sum(1 for i in items if i["level"] == "open"
                                and any(nsg.contains(_ports(i["effective_ports"]), p) for p in risky)),
        "with_private_endpoint": sum(1 for i in items if i["private_endpoints"]),
        "sensitive": sum(1 for i in items if i["sensitive_data"]),
        "by_provider": dict(Counter(i["provider"] for i in items)),
        "by_method": dict(Counter(m.get("kind") for i in items for m in i["methods"] if m.get("level") != "blocked")),
    }


def exposure_summary(db: Session) -> dict[str, Any]:
    """Counts for the dashboard tile (no attack-path computation)."""
    return summarize(exposure_items(db, with_paths=False)["items"])
