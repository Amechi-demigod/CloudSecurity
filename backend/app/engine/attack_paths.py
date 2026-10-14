"""Attack path analysis over the asset relationship graph.

A path is: Internet -> internet-exposed asset -> ... -> asset holding sensitive
data, following `contains`, `connects_to`, `uses_identity` and `has_access`
edges. A path is only reported if it is *exploitable*: some hop carries an
in-use high-severity vulnerability or a high/critical misconfiguration, or the
entry point itself is a data store exposed to the internet.

The engine works on plain dicts so it is easy to unit test.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

TRAVERSABLE = {"contains", "connects_to", "uses_identity", "has_access"}
WORKLOAD_TYPES = {"vm", "pod", "function_app"}
DATA_TYPES = {"storage_account", "sql_server", "sql_database", "key_vault"}
PRIVILEGED_ROLES = {"Owner", "Contributor", "User Access Administrator", "Storage Blob Data Owner",
                    "Key Vault Administrator", "Storage Blob Data Contributor", "Key Vault Secrets User"}
FINDING_W = {"critical": 10, "high": 6, "medium": 2, "low": 0.5}
INTERNET_NODE = "internet"
MAX_DEPTH = 6


@dataclass
class Step:
    asset_id: str
    name: str
    type: str
    reasons: list[str] = field(default_factory=list)


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


def _severity(score: float) -> str:
    return "critical" if score >= 75 else "high" if score >= 55 else "medium" if score >= 35 else "low"


def compute_attack_paths(
    assets: dict[str, dict[str, Any]],
    relationships: list[dict[str, Any]],
    vulns_by_asset: dict[str, list[dict[str, Any]]],
    findings_by_asset: dict[str, list[dict[str, Any]]],
    limit: int = 20,
) -> list[AttackPath]:
    adj: dict[str, list[tuple[str, str]]] = {}
    for r in relationships:
        if r["type"] in TRAVERSABLE and r["source_id"] in assets and r["target_id"] in assets:
            adj.setdefault(r["source_id"], []).append((r["target_id"], r["type"]))

    def node_eval(aid: str, is_entry: bool) -> tuple[float, list[str], bool]:
        """Return (score contribution, reasons, is_weakness)."""
        a = assets[aid]
        reasons: list[str] = []
        score = 0.0
        weak = False
        if is_entry:
            exp = (a.get("properties") or {}).get("exposure") or "public endpoint"
            reasons.append(f"Internet-exposed ({exp})")
            score += 15
        if a["type"] in WORKLOAD_TYPES:
            vulns = [v for v in vulns_by_asset.get(aid, []) if v.get("in_use") and v.get("cvss", 0) >= 7]
            if vulns:
                top = max(vulns, key=lambda v: v.get("risk_score", 0))
                tag = ", exploit available" if top.get("exploit_available") else ""
                reasons.append(f"Vulnerable: {top['cve_id']} in {top['package']} (loaded at runtime{tag})")
                score += 0.35 * float(top.get("risk_score", 0))
                weak = True
        fs = [f for f in findings_by_asset.get(aid, []) if f.get("severity") in ("critical", "high")]
        if fs:
            worst = sorted(fs, key=lambda f: -FINDING_W.get(f["severity"], 0))[0]
            reasons.append(f"Misconfigured: {worst['title']}")
            score += min(15.0, sum(FINDING_W.get(f["severity"], 0) for f in fs))
            weak = weak or is_entry or a["type"] in DATA_TYPES
        if a["type"] == "identity":
            roles = [r for r in (a.get("properties") or {}).get("roles", []) if r in PRIVILEGED_ROLES]
            if roles:
                scope = (a.get("properties") or {}).get("scope", "resource")
                reasons.append(f"Identity with {', '.join(roles)} ({scope} scope)")
                score += 15 if scope == "subscription" else 8
        if a.get("sensitive_data"):
            cls = (a.get("properties") or {}).get("data_classification") or "sensitive data"
            reasons.append(f"Holds {cls}")
            score += 15
            if is_entry and a["type"] in DATA_TYPES:
                weak = True
        return score, reasons, weak

    entries = [aid for aid, a in assets.items() if a.get("internet_exposed")]
    best: dict[tuple[str, str], AttackPath] = {}

    def dfs(path: list[str], edge_types: list[str]):
        cur = path[-1]
        if len(path) > 1 or assets[cur]["type"] in DATA_TYPES:
            if assets[cur].get("sensitive_data"):
                record(path, edge_types)
        if len(path) >= MAX_DEPTH:
            return
        for nxt, et in adj.get(cur, []):
            if nxt not in path:
                dfs(path + [nxt], edge_types + [et])

    def record(path: list[str], edge_types: list[str]):
        total = 0.0
        weak = False
        steps = []
        for i, aid in enumerate(path):
            s, reasons, w = node_eval(aid, i == 0)
            total += s
            weak = weak or w
            a = assets[aid]
            steps.append(Step(aid, a["name"], a["type"], reasons))
        if not weak:
            return
        total -= 2.0 * max(0, len(path) - 3)  # longer paths are harder to traverse
        score = round(max(0.0, min(100.0, total)), 1)
        key = (path[0], path[-1])
        if key in best and best[key].score >= score:
            return
        edges = [{"source": INTERNET_NODE, "target": path[0], "type": "exposes"}]
        edges += [{"source": path[i], "target": path[i + 1], "type": edge_types[i]} for i in range(len(path) - 1)]
        title = "Internet -> " + " -> ".join(assets[p]["name"] for p in path)
        best[key] = AttackPath(
            id=hashlib.sha1(f"{path[0]}|{path[-1]}".encode()).hexdigest()[:12],
            title=title,
            score=score,
            severity=_severity(score),
            entry_id=path[0],
            target_id=path[-1],
            steps=steps,
            edges=edges,
        )

    for e in entries:
        dfs([e], [])

    return sorted(best.values(), key=lambda p: -p.score)[:limit]
