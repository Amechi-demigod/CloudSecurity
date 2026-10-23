"""Attack path analysis over the asset relationship graph.

A path is: Internet -> internet-exposed asset -> ... -> asset holding sensitive
data, following `contains`, `connects_to`, `uses_identity` and `has_access`
edges.

Every such chain is reported, in one of two flavours:

* **confirmed** (`confirmed=True`): some hop carries an exploitable weakness:
  an in-use high-severity vulnerability on a workload, a high/critical
  misconfiguration on the entry point or a data store, an internet-exposed data
  store, or (for the entry point) a high/critical inbound-exposure finding on a
  network control that `protects` it (Azure NSG on the NIC or subnet, AWS
  security group, GCP firewall rule). Scored as before.
* **exposure path** (`confirmed=False`): the chain exists but no exploitable
  weakness was found yet. Kept so real exposure chains are visible, but scored
  lower and capped at medium severity.

Network-control attribution is generic: any asset that `protects` the entry
point and carries normalized `security_rules` is analysed with the shared rule
evaluator (`engine/nsg.py`: priority order, first match wins, Deny rules and the
Azure default rules, destination application security groups). Edges may carry a `level`
(or `levels`) property; when controls sit at several levels (Azure NIC + subnet
NSGs) a port only counts as exposed if every level allows it, while controls at
the same level (several AWS security groups) are combined. Only risky ports
(admin / database, see EXPOSURE_PORTS) count, and only if the internet can reach
them: directly via a public IP, or - for an asset reported without a public IP,
e.g. behind a public load balancer - via the backend ports in its
`forwarded_ports` property.

Entry points reached only *through* another entry point (a VM behind an Azure
Firewall DNAT rule lists the firewall in `exposed_only_via`) are not separate
entries: their paths start at the firewall, which `connects_to` them.

Findings of rules flagged `weakness` (end-of-life runtimes / engines) count as
exploitable on any hop, like an in-use vulnerability.

The engine works on plain dicts so it is easy to unit test.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from . import nsg
from .posture import RULES

TRAVERSABLE = {"contains", "connects_to", "uses_identity", "has_access"}
WORKLOAD_TYPES = {"vm", "vmss", "pod", "function_app", "web_app",
                  "ec2_instance", "lambda_function",  # AWS
                  "gce_instance", "cloud_function", "cloud_run_service"}  # GCP
DATA_TYPES = {"storage_account", "sql_server", "sql_database", "key_vault",
              "postgresql_server", "mysql_server", "cosmos_account", "redis_cache", "sql_managed_instance",
              "s3_bucket", "rds_instance",  # AWS
              "gcs_bucket", "cloud_sql_instance"}  # GCP
IDENTITY_TYPES = {"identity", "iam_role", "iam_user", "gcp_service_account"}
PRIVILEGED_ROLES = {"Owner", "Contributor", "User Access Administrator", "Storage Blob Data Owner",
                    "Key Vault Administrator", "Storage Blob Data Contributor", "Key Vault Secrets User",
                    "Cosmos DB Built-in Data Contributor", "DocumentDB Account Contributor",
                    "Redis Cache Contributor", "Entra administrator",
                    # AWS managed policies / customer policies allowing *:*
                    "AdministratorAccess", "PowerUserAccess", "IAMFullAccess", "AmazonS3FullAccess",
                    "AmazonRDSFullAccess", "*:* (customer/inline policy)",
                    # GCP roles
                    "roles/owner", "roles/editor", "roles/storage.admin", "roles/storage.objectAdmin",
                    "roles/cloudsql.admin", "roles/iam.serviceAccountTokenCreator", "roles/iam.securityAdmin"}
# Identity scopes that cover a whole subscription / account / project.
BROAD_SCOPES = {"subscription", "account", "project", "organization"}
FINDING_W = {"critical": 10, "high": 6, "medium": 2, "low": 0.5}
INTERNET_NODE = "internet"
MAX_DEPTH = 6
# Safety valve for very dense graphs (wide RBAC fan-out): stop expanding after this many DFS steps.
MAX_EXPANSIONS = 200_000

# Network controls whose findings are attributed to the assets they protect. Any
# other asset type with normalized `security_rules` is treated the same way.
NETWORK_CONTROL_LABEL = {"nsg": "NSG", "security_group": "security group", "gcp_firewall_rule": "firewall rule"}
# Ports worth naming in a reason (None = "all ports").
EXPOSURE_PORTS: list[tuple[int | None, str]] = [
    (None, "all ports"), (22, "SSH"), (3389, "RDP"), (5985, "WinRM"), (5986, "WinRM"), (23, "Telnet"),
    (445, "SMB"), (1433, "SQL Server"), (3306, "MySQL"), (5432, "PostgreSQL"), (6379, "Redis"),
    (27017, "MongoDB"), (9200, "Elasticsearch"),
]
UNCONFIRMED_NOTE = "No exploitable weakness found yet"
# Exposure paths (no confirmed weakness) are scored at this fraction, capped below "high".
UNCONFIRMED_FACTOR = 0.6
UNCONFIRMED_MAX_SCORE = 54.0


@dataclass
class Step:
    asset_id: str
    name: str
    type: str
    reasons: list[str] = field(default_factory=list)
    #: this hop carries a confirmed exploitable weakness
    weak: bool = False


@dataclass
class AttackPath:
    id: str
    title: str
    score: float
    severity: str
    entry_id: str
    target_id: str
    steps: list[Step]
    edges: list[dict]
    #: True if some hop carries an exploitable weakness; False for a plain exposure path
    confirmed: bool = True
    #: short labels of the weaknesses found along the path
    weaknesses: list[str] = field(default_factory=list)
    #: why an exposure path is not confirmed (None for confirmed paths)
    note: str | None = None


def _severity(score: float) -> str:
    return "critical" if score >= 75 else "high" if score >= 55 else "medium" if score >= 35 else "low"


def _is_network_control(a: dict[str, Any]) -> bool:
    return a["type"] in NETWORK_CONTROL_LABEL or bool((a.get("properties") or {}).get("security_rules"))


def _open_ports(a: dict[str, Any], target_asgs: list[str] | None = None) -> set[int | None]:
    """Ports from EXPOSURE_PORTS (None = all ports) that the control's rules open to the internet."""
    try:
        exp = nsg.asset_exposure(a, target_asgs=target_asgs)
    except Exception:  # noqa: BLE001 - malformed rules never break path analysis
        return set()
    return {port for port, _ in EXPOSURE_PORTS if exp.rules_for(port)}


def _port_label(port: int | None) -> str:
    if port is None:
        return "all ports"
    name = next(n for p, n in EXPOSURE_PORTS if p == port)
    return f"{name} ({port})"


def _high(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [f for f in findings if f.get("severity") in ("critical", "high")]


def direct_reachability(asset: dict[str, Any]) -> set[int] | None:
    """Ports the internet can reach on the asset's own interfaces.

    None = unrestricted (it has a public IP, or the connector does not report
    public IPs). An asset reported with no public IP (e.g. only behind a load
    balancer) is reachable only on the backend ports the connector lists in
    `forwarded_ports`.
    """
    props = asset.get("properties") or {}
    if props.get("public_ips") or props.get("per_instance_public_ip") or "public_ips" not in props:
        return None
    return {int(p) for p in props.get("forwarded_ports") or [] if str(p).isdigit()}


def network_exposure(
    target_id: str,
    assets: dict[str, dict[str, Any]],
    protectors: dict[str, list[tuple[str, dict]]],
    findings_by_asset: dict[str, list[dict[str, Any]]],
) -> tuple[float, list[str]]:
    """Weakness inherited from network controls that `protect` `target_id`.

    Returns (score, reasons); no reasons means no attributable inbound exposure.
    Only controls with an open high/critical finding count (a suppressed finding
    therefore also silences the attribution). When rules are available, the
    exposed risky ports (EXPOSURE_PORTS) are derived from them, honouring the
    level semantics described in the module docstring and the target's
    reachability (`direct_reachability`); otherwise the finding titles are used.
    """
    prots = [(pid, props or {}) for pid, props in protectors.get(target_id, []) if pid in assets]
    flagged = {pid for pid, _ in prots if _high(findings_by_asset.get(pid, []))}
    if not flagged:
        return 0.0, []
    reachable = direct_reachability(assets[target_id])
    score = min(15.0, sum(FINDING_W.get(f["severity"], 0) for pid in flagged
                          for f in _high(findings_by_asset.get(pid, []))))
    with_rules = [(pid, props) for pid, props in prots if (assets[pid].get("properties") or {}).get("security_rules")]
    if not with_rules:
        if reachable is not None:
            return 0.0, []  # behind a load balancer and no rules to tell which ports matter
        reasons = []
        for pid in sorted(flagged):
            a = assets[pid]
            worst = sorted(_high(findings_by_asset[pid]), key=lambda f: -FINDING_W.get(f["severity"], 0))[0]
            label = NETWORK_CONTROL_LABEL.get(a["type"], a["type"])
            reasons.append(f"Exposed via {label} {a['name']}: {worst['title']}")
        return score, reasons

    asgs = (assets[target_id].get("properties") or {}).get("asgs")
    open_by_ctrl = {pid: _open_ports(assets[pid], asgs) for pid, _ in with_rules}
    levels: dict[str, set[str]] = {}
    for pid, props in with_rules:
        lv = props.get("levels") or [props.get("level") or "_"]
        for level in lv:
            levels.setdefault(str(level), set()).add(pid)

    def level_allows(level_ctrls: set[str], port: int | None) -> bool:
        return any(port in open_by_ctrl[c] or None in open_by_ctrl[c] for c in level_ctrls)

    risky = [p for p, _ in EXPOSURE_PORTS if p is not None]
    if reachable is None and all(level_allows(cs, None) for cs in levels.values()):
        exposed: list[int | None] = [None]  # every level opens all ports: just say so
    else:
        exposed = [p for p in risky if (reachable is None or p in reachable)
                   and all(level_allows(cs, p) for cs in levels.values())]
    if not exposed:
        return 0.0, []  # e.g. NIC NSG allows SSH but the subnet NSG does not
    reasons = []
    for pid in sorted(flagged & set(open_by_ctrl)):
        mine = [p for p in exposed if p in open_by_ctrl[pid] or None in open_by_ctrl[pid]]
        if not mine:
            continue
        a = assets[pid]
        label = NETWORK_CONTROL_LABEL.get(a["type"], a["type"])
        ports = ", ".join(_port_label(p) for p in mine[:4]) + (" ..." if len(mine) > 4 else "")
        reasons.append(f"Exposed via {label} {a['name']}: {ports} open to Internet")
    return (score, reasons) if reasons else (0.0, [])


def compute_attack_paths(
    assets: dict[str, dict[str, Any]],
    relationships: list[dict[str, Any]],
    vulns_by_asset: dict[str, list[dict[str, Any]]],
    findings_by_asset: dict[str, list[dict[str, Any]]],
    limit: int = 20,
    include_unconfirmed: bool = True,
) -> list[AttackPath]:
    """Top attack paths: confirmed paths first, then exposure paths, each by score.

    `include_unconfirmed=False` drops exposure paths (no confirmed weakness).
    """
    adj: dict[str, list[tuple[str, str]]] = {}
    protectors: dict[str, list[tuple[str, dict]]] = {}
    for r in relationships:
        if r["source_id"] not in assets or r["target_id"] not in assets:
            continue
        if r["type"] in TRAVERSABLE:
            adj.setdefault(r["source_id"], []).append((r["target_id"], r["type"]))
        elif r["type"] == "protects" and _is_network_control(assets[r["source_id"]]):
            protectors.setdefault(r["target_id"], []).append((r["source_id"], r.get("properties") or {}))

    cache: dict[tuple[str, bool], tuple[float, list[str], list[str]]] = {}
    weakness_rules = {r.id for r in RULES if r.weakness}

    def node_eval(aid: str, is_entry: bool) -> tuple[float, list[str], list[str]]:
        """Return (score contribution, reasons, weaknesses). Non-empty weaknesses = exploitable hop."""
        key = (aid, is_entry)
        if key in cache:
            return cache[key]
        a = assets[aid]
        reasons: list[str] = []
        weak: list[str] = []
        score = 0.0
        if is_entry:
            exp = (a.get("properties") or {}).get("exposure") or "public endpoint"
            reasons.append(f"Internet-exposed ({exp})")
            score += 15
            controls = (a.get("properties") or {}).get("network_controls") or []
            if controls:
                reasons.append(f"Network controls: {', '.join(controls[:4])}")
            n_score, n_reasons = network_exposure(aid, assets, protectors, findings_by_asset)
            if n_reasons:
                reasons += n_reasons
                weak += n_reasons
                score += n_score
        elif a.get("internet_exposed") and (a.get("properties") or {}).get("exposed_only_via"):
            # reached through an upstream entry (e.g. an Azure Firewall DNAT rule)
            exp = (a.get("properties") or {}).get("exposure")
            if exp:
                reasons.append(f"Internet-exposed ({exp})")
        if a["type"] in WORKLOAD_TYPES:
            vulns = [v for v in vulns_by_asset.get(aid, []) if v.get("in_use") and v.get("cvss", 0) >= 7]
            if vulns:
                top = max(vulns, key=lambda v: v.get("risk_score", 0))
                tag = ", exploit available" if top.get("exploit_available") else ""
                r = f"Vulnerable: {top['cve_id']} in {top['package']} (loaded at runtime{tag})"
                reasons.append(r)
                weak.append(r)
                score += 0.35 * float(top.get("risk_score", 0))
        eol = [f for f in findings_by_asset.get(aid, []) if f.get("rule_id") in weakness_rules]
        for f in eol[:2]:
            r = f"Vulnerable: {f['title']}"
            reasons.append(r)
            weak.append(r)
            score += FINDING_W.get(f.get("severity", "high"), 0)
        fs = [f for f in _high(findings_by_asset.get(aid, [])) if f.get("rule_id") not in weakness_rules]
        if fs:
            worst = sorted(fs, key=lambda f: -FINDING_W.get(f["severity"], 0))[0]
            r = f"Misconfigured: {worst['title']}"
            reasons.append(r)
            score += min(15.0, sum(FINDING_W.get(f["severity"], 0) for f in fs))
            if is_entry or a["type"] in DATA_TYPES:
                weak.append(r)
        if a["type"] in IDENTITY_TYPES:
            roles = [r for r in (a.get("properties") or {}).get("roles", []) if r in PRIVILEGED_ROLES]
            if roles:
                scope = (a.get("properties") or {}).get("scope", "resource")
                reasons.append(f"Identity with {', '.join(roles)} ({scope.replace('_', ' ')} scope)")
                score += 15 if scope in BROAD_SCOPES else 8
        if a.get("sensitive_data"):
            cls = (a.get("properties") or {}).get("data_classification") or "sensitive data"
            reasons.append(f"Holds {cls}")
            score += 15
            if is_entry and a["type"] in DATA_TYPES:
                weak.append(f"Sensitive data store exposed to the Internet ({cls})")
        cache[key] = (score, reasons, weak)
        return cache[key]

    exposed = {aid for aid, a in assets.items() if a.get("internet_exposed")}

    def only_via_other_entry(a: dict[str, Any]) -> bool:
        via = (a.get("properties") or {}).get("exposed_only_via") or []
        return bool(via) and all(v in exposed for v in via)

    entries = [aid for aid in exposed if not only_via_other_entry(assets[aid])]
    best: dict[tuple[str, str], AttackPath] = {}
    budget = [MAX_EXPANSIONS]

    def dfs(path: list[str], edge_types: list[str]):
        budget[0] -= 1
        if budget[0] < 0:
            return
        cur = path[-1]
        if len(path) > 1 or assets[cur]["type"] in DATA_TYPES:
            if assets[cur].get("sensitive_data"):
                record(path, edge_types)
        if len(path) >= MAX_DEPTH:
            return
        for nxt, et in adj.get(cur, []):
            if nxt not in path:
                dfs(path + [nxt], edge_types + [et])

    def rank(p: AttackPath) -> tuple[bool, float]:
        return (p.confirmed, p.score)

    def record(path: list[str], edge_types: list[str]):
        total = 0.0
        weaknesses: list[str] = []
        steps = []
        for i, aid in enumerate(path):
            s, reasons, w = node_eval(aid, i == 0)
            total += s
            weaknesses += w
            a = assets[aid]
            steps.append(Step(aid, a["name"], a["type"], list(reasons), bool(w)))
        confirmed = bool(weaknesses)
        if not confirmed and not include_unconfirmed:
            return
        total -= 2.0 * max(0, len(path) - 3)  # longer paths are harder to traverse
        score = max(0.0, min(100.0, total))
        if not confirmed:
            score = min(UNCONFIRMED_MAX_SCORE, score * UNCONFIRMED_FACTOR)
        score = round(score, 1)
        severity = _severity(score)
        if not confirmed and severity in ("critical", "high"):  # defensive: the score cap already ensures this
            severity = "medium"
        key = (path[0], path[-1])
        cand_rank = (confirmed, score)
        if key in best and rank(best[key]) >= cand_rank:
            return
        edges = [{"source": INTERNET_NODE, "target": path[0], "type": "exposes"}]
        edges += [{"source": path[i], "target": path[i + 1], "type": edge_types[i]} for i in range(len(path) - 1)]
        title = "Internet -> " + " -> ".join(assets[p]["name"] for p in path)
        best[key] = AttackPath(
            id=hashlib.sha1(f"{path[0]}|{path[-1]}".encode(), usedforsecurity=False).hexdigest()[:12],
            title=title,
            score=score,
            severity=severity,
            entry_id=path[0],
            target_id=path[-1],
            steps=steps,
            edges=edges,
            confirmed=confirmed,
            weaknesses=list(dict.fromkeys(weaknesses)),
            note=None if confirmed else UNCONFIRMED_NOTE,
        )

    for e in entries:
        dfs([e], [])

    return sorted(best.values(), key=lambda p: (not p.confirmed, -p.score))[:limit]
