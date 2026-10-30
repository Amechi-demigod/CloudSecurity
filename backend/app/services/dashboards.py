"""Dashboards: one response per tab (Overview, Vulnerabilities, External exposure,
Identities, Endpoints) for the "Dashboards" page.

Every query runs in the request's organisation session (app/tenancy.py adds the
organisation to every ORM statement), aggregates in SQL where the database can
do it portably (SQLite and PostgreSQL) and never issues per-row queries.

Filters
  range    7d | 30d | 90d: the period for trends, "new vs resolved", mean time
           to resolve and the "vs previous period" changes.
  account  a cloud account scope (Azure subscription, AWS account or GCP
           project id, `Asset.subscription_id`). Findings, vulnerabilities,
           alerts and attack paths are kept to the assets of that account;
           endpoint devices are not tied to a cloud account and are never
           filtered (their vulnerabilities are left out of an account view).

Changes ("vs previous period")
  * Flow metrics (mean time to resolve, SLA met) compare the current window
    with the previous window of the same length, from `first_seen` /
    `resolved_at`.
  * Point-in-time counts (open issues, exposed assets, risk score, compliance
    %...) compare today's value with the daily snapshot (`DashboardSnapshot`)
    taken `range` days ago (or up to SNAPSHOT_TOLERANCE_DAYS before that). With
    no such snapshot the change is `null` and the UI hides it: numbers are never
    invented. Snapshots start on the day this version is deployed, so changes
    and snapshot-based trends fill in from then on.

Category mapping (findings by category) - see `category_of`:
  the service code of the rule id (AZ-STG-001 -> STG) decides; rules whose
  service code is not listed fall back to the affected asset's type.
    Network     NSG, SG, FW, VNET, APPGW          | nsg, security_group, vnet, azure_firewall, ...
    Storage     STG, S3, GCS                      | storage_account, s3_bucket, gcs_bucket
    Identity    ID, IAM, SUB                      | identity, iam_user, iam_role, gcp_service_account, ...
    Databases   SQL, SQLMI, MYSQL, PG, COSMOS, REDIS, RDS | sql_server, rds_instance, ...
    Kubernetes  AKS, EKS, GKE, POD                | aks_cluster, eks_cluster, gke_cluster, pod
    Secrets     KV, KMS                           | key_vault, kms_key, gcp_kms_key
    Compute     VM, VMSS, EC2, GCE, FN, LMB, RUN, APP | vm, ec2_instance, function_app, lambda_function, ...
    Other       anything else (e.g. AWS-CT CloudTrail logging)

SLA targets (mean time to resolve tile): DASHBOARD_SLA_CRITICAL_DAYS (default
7) and DASHBOARD_SLA_HIGH_DAYS (default 30); "SLA met" is the share of the
critical and high findings resolved in the period that were resolved within
their target.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import and_, case, extract, func, not_, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import config
from ..engine import nsg, posture
from ..engine.attack_paths import AttackPath
from ..engine.risk import noise_reduction, overall_risk_score
from ..models import (
    AgentRelease,
    Alert,
    Asset,
    DashboardSnapshot,
    Device,
    Finding,
    Vulnerability,
    utcnow,
)
from . import analytics
from . import devices as device_svc
from . import exposure as exposure_svc
from .agent_updates import version_sort_key

RANGES: dict[str, int] = {"7d": 7, "30d": 30, "90d": 90}
DEFAULT_RANGE = "30d"
SEVERITIES = ["critical", "high", "medium", "low"]
# A comparison snapshot may be this many days older than the exact comparison
# day (the job missed a day); never newer.
SNAPSHOT_TOLERANCE_DAYS = 2
TABS = ("overview", "vulnerabilities", "exposure", "identities", "endpoints")


def sla_days() -> dict[str, float]:
    s = config.settings
    return {"critical": s.dashboard_sla_critical_days, "high": s.dashboard_sla_high_days}


# ----------------------------------------------------------------------------- mappings
CATEGORIES = ["Network", "Storage", "Identity", "Databases", "Kubernetes", "Secrets", "Compute", "Other"]
SERVICE_CATEGORY: dict[str, str] = {
    **dict.fromkeys(("NSG", "SG", "FW", "VNET", "APPGW"), "Network"),
    **dict.fromkeys(("STG", "S3", "GCS"), "Storage"),
    **dict.fromkeys(("ID", "IAM", "SUB"), "Identity"),
    **dict.fromkeys(("SQL", "SQLMI", "MYSQL", "PG", "COSMOS", "REDIS", "RDS"), "Databases"),
    **dict.fromkeys(("AKS", "EKS", "GKE", "POD"), "Kubernetes"),
    **dict.fromkeys(("KV", "KMS"), "Secrets"),
    **dict.fromkeys(("VM", "VMSS", "EC2", "GCE", "FN", "LMB", "RUN", "APP"), "Compute"),
}
TYPE_CATEGORY: dict[str, str] = {
    **dict.fromkeys(("nsg", "security_group", "gcp_firewall_rule", "vnet", "azure_firewall", "firewall_policy",
                     "private_endpoint", "load_balancer", "app_gateway"), "Network"),
    **dict.fromkeys(("storage_account", "s3_bucket", "gcs_bucket"), "Storage"),
    **dict.fromkeys(("identity", "iam_user", "iam_role", "gcp_service_account", "subscription", "aws_account",
                     "gcp_project"), "Identity"),
    **dict.fromkeys(("sql_server", "sql_database", "sql_managed_instance", "postgresql_server", "cosmos_account",
                     "redis_cache", "rds_instance", "cloud_sql_instance"), "Databases"),
    **dict.fromkeys(("aks_cluster", "eks_cluster", "gke_cluster", "pod"), "Kubernetes"),
    **dict.fromkeys(("key_vault", "kms_key", "gcp_kms_key"), "Secrets"),
    **dict.fromkeys(("vm", "vmss", "ec2_instance", "gce_instance", "function_app", "web_app", "app_service_plan",
                     "lambda_function", "cloud_function", "cloud_run_service"), "Compute"),
}


def service_code(rule_id: str) -> str | None:
    """"AZ-STG-001" -> "STG"; "AWS-S3-002" -> "S3"; None when the id has no service part."""
    parts = (rule_id or "").split("-")
    if len(parts) >= 3:
        return "-".join(parts[1:-1]).upper()
    if len(parts) == 2 and not parts[1].isdigit():
        return parts[1].upper()
    return None


def category_of(rule_id: str, asset_type: str | None) -> str:
    cat = SERVICE_CATEGORY.get(service_code(rule_id) or "")
    if cat:
        return cat
    return TYPE_CATEGORY.get(asset_type or "", "Other")


def category_filter(category: str):
    """SQL condition on Finding selecting one category (same rules as `category_of`)."""
    known = [Finding.rule_id.like(f"%-{code}-%") for code in SERVICE_CATEGORY]
    mine = [Finding.rule_id.like(f"%-{code}-%") for code, c in SERVICE_CATEGORY.items() if c == category]
    types = [t for t, c in TYPE_CATEGORY.items() if c == category]
    by_type = Finding.asset_id.in_(select(Asset.id).where(Asset.type.in_(types))) if types else None
    if category == "Other":
        unknown_type = Finding.asset_id.not_in(select(Asset.id).where(Asset.type.in_(list(TYPE_CATEGORY))))
        return and_(not_(or_(*known)), unknown_type)
    fallback = and_(not_(or_(*known)), by_type) if by_type is not None else None
    return or_(*mine, fallback) if fallback is not None else or_(*mine)


# Asset types grouped for composition bars (fixed order; the UI colours them in this order).
ASSET_GROUPS: list[tuple[str, str, tuple[str, ...]]] = [
    ("vms", "VMs", ("vm", "vmss", "ec2_instance", "gce_instance")),
    ("functions", "Functions & apps", ("function_app", "web_app", "lambda_function", "cloud_function",
                                      "cloud_run_service", "app_service_plan")),
    ("kubernetes", "Kubernetes", ("aks_cluster", "eks_cluster", "gke_cluster", "pod")),
    ("storage", "Storage", ("storage_account", "s3_bucket", "gcs_bucket")),
    ("databases", "Databases", ("sql_server", "sql_database", "sql_managed_instance", "postgresql_server",
                                "cosmos_account", "redis_cache", "rds_instance", "cloud_sql_instance")),
    ("secrets", "Key vaults", ("key_vault", "kms_key", "gcp_kms_key")),
    ("network", "Network", ("nsg", "security_group", "gcp_firewall_rule", "vnet", "azure_firewall",
                            "firewall_policy", "private_endpoint", "load_balancer", "app_gateway")),
    ("identities", "Identities", ("identity", "iam_user", "iam_role", "gcp_service_account")),
]
TYPE_GROUP = {t: key for key, _, types in ASSET_GROUPS for t in types}
GROUP_LABEL = {key: label for key, label, _ in ASSET_GROUPS} | {"other": "Other"}
TYPE_LABEL: dict[str, str] = {
    "vm": "Virtual machines", "vmss": "VM scale sets", "ec2_instance": "EC2 instances", "gce_instance": "GCE VMs",
    "function_app": "Function apps", "web_app": "Web apps", "lambda_function": "Lambda functions",
    "cloud_function": "Cloud Functions", "cloud_run_service": "Cloud Run services", "aks_cluster": "AKS clusters",
    "eks_cluster": "EKS clusters", "gke_cluster": "GKE clusters", "pod": "Kubernetes pods",
    "storage_account": "Storage accounts", "s3_bucket": "S3 buckets", "gcs_bucket": "Cloud Storage buckets",
    "sql_server": "SQL servers", "sql_database": "SQL databases", "sql_managed_instance": "SQL managed instances",
    "postgresql_server": "PostgreSQL servers", "cosmos_account": "Cosmos DB", "redis_cache": "Redis caches",
    "rds_instance": "RDS instances", "cloud_sql_instance": "Cloud SQL", "key_vault": "Key vaults",
    "kms_key": "KMS keys", "gcp_kms_key": "Cloud KMS keys", "nsg": "NSGs", "security_group": "Security groups",
    "identity": "Managed identities", "iam_user": "IAM users", "iam_role": "IAM roles",
    "gcp_service_account": "Service accounts", "load_balancer": "Load balancers", "app_gateway": "App gateways",
    "azure_firewall": "Azure firewalls", "private_endpoint": "Private endpoints", "subscription": "Subscriptions",
}

DATA_STORE_GROUPS = ("storage", "databases", "secrets")
MANAGEMENT_PORTS: list[tuple[str, str, tuple[int, ...]]] = [
    ("ssh", "SSH 22", (22,)), ("rdp", "RDP 3389", (3389,)), ("winrm", "WinRM 5985/5986", (5985, 5986)),
]
IDENTITY_TYPES = ("identity", "iam_user", "iam_role", "gcp_service_account")
PRIVILEGED_ROLES = {"Owner", "Contributor", "User Access Administrator", "roles/owner", "roles/editor"}

# Workload groups for "impact by workload type" (vulnerabilities).
WORKLOAD_GROUPS: list[tuple[str, str, tuple[str, ...]]] = [
    ("pods", "Kubernetes pods", ("pod",)),
    ("clusters", "Kubernetes clusters", ("aks_cluster", "eks_cluster", "gke_cluster")),
    ("vms", "Virtual machines", ("vm", "vmss", "ec2_instance", "gce_instance")),
    ("functions", "Functions & apps", ("function_app", "web_app", "lambda_function", "cloud_function",
                                      "cloud_run_service")),
]
WORKLOAD_OF = {t: key for key, _, types in WORKLOAD_GROUPS for t in types}
WORKLOAD_LABEL = {key: label for key, label, _ in WORKLOAD_GROUPS} | {"endpoints": "Endpoints",
                                                                      "other": "Other workloads"}

# Top risky assets: the asset's risk is the higher of its riskiest open
# vulnerability (0-100, engine/risk.py: CVSS x runtime use x internet exposure /
# exploit / sensitive data) and a floor set by its worst open finding. Ties go
# to the asset with more critical, then high findings, then more vulnerabilities.
FINDING_FLOOR = {"critical": 85.0, "high": 65.0, "medium": 40.0, "low": 15.0}


# ----------------------------------------------------------------------------- window
@dataclass(frozen=True)
class Window:
    range: str
    days: int
    now: datetime
    today: date
    start: datetime
    prev_start: datetime
    account: str | None

    @property
    def compare_day(self) -> date:
        return self.today - timedelta(days=self.days)

    def buckets(self) -> list[tuple[date, date]]:
        """Chart buckets ending today: daily up to 30 days, weekly beyond."""
        if self.days <= 30:
            return [(self.today - timedelta(days=i), self.today - timedelta(days=i)) for i in range(self.days - 1, -1, -1)]
        n = math.ceil(self.days / 7)
        out = []
        for i in range(n - 1, -1, -1):
            end = self.today - timedelta(days=7 * i)
            out.append((end - timedelta(days=6), end))
        return out

    @property
    def bucket(self) -> str:
        return "day" if self.days <= 30 else "week"


def window(range_: str | None = None, account: str | None = None, now: datetime | None = None) -> Window:
    r = range_ if range_ in RANGES else DEFAULT_RANGE
    days = RANGES[r]
    now = now or utcnow()
    start = now - timedelta(days=days)
    return Window(r, days, now, now.date(), start, start - timedelta(days=days), account or None)


def _end_of(d: date, w: Window) -> datetime:
    """Point in time a bucket ending on day `d` represents (now for today)."""
    return w.now if d >= w.today else datetime.combine(d + timedelta(days=1), datetime.min.time())


# ----------------------------------------------------------------------------- scoping
def _account_assets(account: str):
    return select(Asset.id).where(Asset.subscription_id == account)


def _f(stmt, w: Window):
    return stmt.where(Finding.asset_id.in_(_account_assets(w.account))) if w.account else stmt


def _v(stmt, w: Window):
    return stmt.where(Vulnerability.asset_id.in_(_account_assets(w.account))) if w.account else stmt


def _al(stmt, w: Window):
    return stmt.where(Alert.asset_id.in_(_account_assets(w.account))) if w.account else stmt


def _a(stmt, w: Window):
    return stmt.where(Asset.subscription_id == w.account) if w.account else stmt


def _day(v: Any) -> str:
    return str(v)[:10]


def _days_between(db: Session, end, start):
    """SQL expression: days from `start` to `end` (fractional), on SQLite and PostgreSQL."""
    if db.get_bind().dialect.name == "postgresql":
        return extract("epoch", end - start) / 86400.0
    return func.julianday(end) - func.julianday(start)


def _fixable():
    """1 if a fix is known (fixed_version set), else 0 (for SUM)."""
    return case((func.coalesce(Vulnerability.fixed_version, "") != "", 1), else_=0)


def _sev_counts(rows) -> dict[str, int]:
    out = dict.fromkeys(SEVERITIES, 0)
    for sev, n in rows:
        if sev in out:
            out[sev] += int(n or 0)
    return out


# ----------------------------------------------------------------------------- shared aggregates
def open_findings_by_severity(db: Session, w: Window) -> dict[str, int]:
    return _sev_counts(db.execute(_f(select(Finding.severity, func.count()).where(Finding.status == "open")
                                     .group_by(Finding.severity), w)))


def open_alerts_by_severity(db: Session, w: Window) -> dict[str, int]:
    return _sev_counts(db.execute(_al(select(Alert.severity, func.count()).where(Alert.status != "resolved")
                                      .group_by(Alert.severity), w)))


def scoped_paths(db: Session, w: Window, limit: int = 500) -> list[AttackPath]:
    paths = analytics.attack_paths(db, limit=limit)
    if not w.account:
        return paths
    ids = set(db.scalars(_account_assets(w.account)))
    return [p for p in paths if any(s.asset_id in ids for s in p.steps)]


def _sensitive_ids(db: Session) -> set[str]:
    return set(db.scalars(select(Asset.id).where(Asset.sensitive_data.is_(True))))


def risk_score(db: Session, w: Window, findings: dict[str, int], alerts: dict[str, int],
               paths: list[AttackPath]) -> float:
    asset_count = db.scalar(_a(select(func.count()).select_from(Asset), w)) or 0
    vuln_scores = list(db.scalars(_v(select(Vulnerability.risk_score).where(Vulnerability.status == "open",
                                                                           Vulnerability.risk_score >= 70), w)))
    return overall_risk_score([s for s, n in findings.items() for _ in range(n)], vuln_scores,
                              [s for s, n in alerts.items() for _ in range(n)],
                              attack_path_count=sum(1 for p in paths if p.severity in ("critical", "high")),
                              asset_count=asset_count)


def exposure_items(db: Session, w: Window) -> list[dict]:
    return exposure_svc.exposure_items(db, subscription=w.account, with_paths=False)["items"]


def _item_open_ports(item: dict, controls: dict[str, dict]) -> set[int]:
    """Management ports open to the internet on an exposed item: its effective
    ports when the connector reports them, else what the network controls that
    protect it (NSG / security group / firewall rule) open at every level (the
    attack-path engine's rule; app/engine/attack_paths.py)."""
    wanted = [p for _, _, ports in MANAGEMENT_PORTS for p in ports]
    if item["level"] != "open":
        return set()
    if item["effective_ports"]:
        ranges = nsg.parse_ports(item["effective_ports"])
        return {p for p in wanted if nsg.contains(ranges, p)}
    by_level: dict[str, list[str]] = defaultdict(list)
    for c in item.get("controls") or []:
        if c["id"] in controls:
            for level in c.get("levels") or ["_"]:
                by_level[str(level)].append(c["id"])
    if not by_level:
        return set()
    opened: dict[str, set[int]] = {}
    for cid in {cid for ids in by_level.values() for cid in ids}:
        try:
            exp = nsg.asset_exposure(controls[cid])
        except Exception:  # noqa: BLE001 - malformed rules never break the dashboard
            opened[cid] = set()
            continue
        opened[cid] = {p for p in wanted if exp.rules_for(p)}
    return {p for p in wanted if all(any(p in opened[c] for c in ids) for ids in by_level.values())}


def management_ports(db: Session, items: list[dict]) -> dict[str, int]:
    """Exposed assets with SSH / RDP / WinRM open to the internet, per protocol."""
    ctrl_ids = {c["id"] for i in items for c in i.get("controls") or []}
    controls = {a.id: {"id": a.id, "type": a.type, "properties": a.properties or {}}
                for a in db.scalars(select(Asset).where(Asset.id.in_(list(ctrl_ids))))} if ctrl_ids else {}
    out = {key: 0 for key, _, _ in MANAGEMENT_PORTS}
    for i in items:
        ports = _item_open_ports(i, controls)
        for key, _, mine in MANAGEMENT_PORTS:
            if ports & set(mine):
                out[key] += 1
    return out


def _group_parts(types: Counter, groups: tuple[str, ...] | None = None, max_parts: int = 3) -> list[dict]:
    """Composition parts by asset group: the biggest `max_parts` groups, the rest as "Other"."""
    by_group: Counter = Counter()
    for t, n in types.items():
        g = TYPE_GROUP.get(t, "other")
        if groups is not None and g not in groups:
            g = "other"
        by_group[g] += n
    ranked = [g for g, _ in sorted(by_group.items(), key=lambda x: (x[0] == "other", -x[1], x[0]))]
    main = [g for g in ranked if g != "other"][:max_parts]
    rest = sum(n for g, n in by_group.items() if g not in main)
    parts = [{"key": g, "label": GROUP_LABEL[g], "count": by_group[g],
              "types": [t for t in types if TYPE_GROUP.get(t, "other") == g]} for g in main]
    if rest:
        parts.append({"key": "other", "label": "Other", "count": rest,
                      "types": [t for t in types if TYPE_GROUP.get(t, "other") not in main]})
    return parts


def crown_jewel_paths(paths: list[AttackPath], sensitive: set[str]) -> list[AttackPath]:
    return [p for p in paths if p.confirmed and p.target_id in sensitive]


def is_privileged(a: Asset) -> bool:
    p = a.properties or {}
    if p.get("admin") is True or p.get("admin_roles"):
        return True
    roles = set(p.get("roles") or [])
    return bool(roles & PRIVILEGED_ROLES) and p.get("scope", "subscription") in ("subscription", "account", "project")


def compliance(db: Session, w: Window) -> list[dict[str, Any]]:
    """Compliance posture per framework (analytics.compliance_summary), limited to
    the frameworks that apply to the asset types present in scope: a framework
    with no assets to check (e.g. CIS AWS without AWS accounts) is left out
    rather than shown as 100% passing."""
    types = set(db.scalars(_a(select(Asset.type).distinct(), w)))
    rule_type = {r.id: r.resource_type for r in posture.RULES}
    relevant = {" ".join(control.split(" ")[:2]) for control, rule_ids in posture.compliance_controls().items()
                if any(rule_type.get(r) in types for r in rule_ids)}
    return [c for c in analytics.compliance_summary(db, account=w.account) if c["framework"] in relevant]


def _latest_agent_version(db: Session, fleet_versions: list[str]) -> str | None:
    """Newest imported, not withdrawn agent release; else the newest version in the fleet."""
    versions = list(db.scalars(select(AgentRelease.version).where(AgentRelease.withdrawn_at.is_(None))))
    candidates = [v for v in versions if version_sort_key(v)[0]] or [v for v in fleet_versions if version_sort_key(v)[0]]
    return max(candidates, key=version_sort_key) if candidates else None


CONNECTIVITY_ISSUES = {"stale", "inactive", "revoked"}


def endpoint_stats(db: Session) -> dict[str, Any]:
    """Managed (active) devices: health, posture issues, suspended sign-in, outdated agent."""
    now = utcnow()
    devices = list(db.scalars(select(Device).where(Device.status == "active")))
    latest = _latest_agent_version(db, [d.agent_version for d in devices])
    by_os: Counter = Counter()
    by_health: Counter = Counter()
    issues: Counter = Counter()
    connectivity: Counter = Counter()
    versions: Counter = Counter()
    failing = suspended = outdated = 0
    for d in devices:
        iss = device_svc.device_issues(d, now)
        health = device_svc.health_from_issues(d, iss)
        by_os[d.os_family] += 1
        by_health[health] += 1
        connectivity[device_svc.connectivity(d, now)] += 1
        versions[d.agent_version or "unknown"] += 1
        posture = [i for i in iss if i["code"] not in CONNECTIVITY_ISSUES]
        for i in posture:
            issues[i["code"]] += 1
        failing += bool(posture)
        suspended += d.isolation_status in device_svc.ISOLATION_STATES
        if latest and version_sort_key(d.agent_version)[0] and version_sort_key(d.agent_version) < version_sort_key(latest):
            outdated += 1
    return {
        "managed": len(devices), "healthy": by_health.get("healthy", 0), "failing": failing,
        "suspended": suspended, "outdated": outdated, "latest_agent_version": latest,
        "by_os": dict(by_os), "by_health": {k: by_health.get(k, 0) for k in ("healthy", "warning", "critical",
                                                                               "unknown")},
        "connectivity": {k: connectivity.get(k, 0) for k in ("active", "stale", "inactive", "never")},
        "issues": [{"code": c, "title": device_svc.ISSUE_DEFS[c][1], "severity": device_svc.ISSUE_DEFS[c][0],
                    "devices": n} for c, n in sorted(issues.items(), key=lambda x: (-x[1], x[0]))],
        "agent_versions": [{"version": v, "devices": n}
                           for v, n in sorted(versions.items(), key=lambda x: version_sort_key(x[0]), reverse=True)],
    }


# ----------------------------------------------------------------------------- snapshots
def current_metrics(db: Session, account: str | None = None) -> dict[str, Any]:
    """Point-in-time metrics stored in the daily snapshot (and compared against)."""
    w = window(account=account)
    findings = open_findings_by_severity(db, w)
    alerts = open_alerts_by_severity(db, w)
    paths = scoped_paths(db, w)
    confirmed = [p for p in paths if p.confirmed]
    items = exposure_items(db, w)
    sensitive = _sensitive_ids(db)
    # (severity, kev, in_use, priority, count, fixable count)
    vuln_rows = db.execute(_v(select(Vulnerability.severity, Vulnerability.kev, Vulnerability.in_use,
                                     Vulnerability.priority, func.count(), func.sum(_fixable()))
                              .where(Vulnerability.status == "open")
                              .group_by(Vulnerability.severity, Vulnerability.kev, Vulnerability.in_use,
                                        Vulnerability.priority), w)).all()
    vuln_rows = [(r[0], r[1], r[2], r[3], int(r[4] or 0), int(r[5] or 0)) for r in vuln_rows]
    vtotal = sum(r[4] for r in vuln_rows)
    fixable = sum(r[5] for r in vuln_rows)
    identities = list(db.scalars(_a(select(Asset).where(Asset.type.in_(IDENTITY_TYPES)), w)))
    ident_findings = db.scalar(_f(select(func.count()).select_from(Finding)
                                  .where(Finding.status == "open", category_filter("Identity")), w)) or 0
    m: dict[str, Any] = {
        "open_issues": sum(findings.values()),
        **{f"open_{s}": findings[s] for s in SEVERITIES},
        "critical_high": findings["critical"] + findings["high"],
        "exposed_assets": len(items),
        "runtime_threats": sum(alerts.values()),
        "attack_paths": len(confirmed),
        "risk_score": risk_score(db, w, findings, alerts, paths),
        "compliance": {c["framework"]: c["score"] for c in compliance(db, w)},
        "vulns_open": vtotal,
        "vulns_critical": sum(r[4] for r in vuln_rows if r[0] == "critical"),
        "vulns_high": sum(r[4] for r in vuln_rows if r[0] == "high"),
        "vulns_kev": sum(r[4] for r in vuln_rows if r[1]),
        "vulns_in_use": sum(r[4] for r in vuln_rows if r[2]),
        "vulns_prioritized": sum(r[4] for r in vuln_rows if r[3] in ("critical", "high")),
        "vulns_fix_pct": round(100.0 * fixable / vtotal, 1) if vtotal else None,
        "mgmt_ports": sum(management_ports(db, items).values()),
        "exposed_data_stores": sum(1 for i in items if TYPE_GROUP.get(i["type"]) in DATA_STORE_GROUPS),
        "crown_jewel_paths": len(crown_jewel_paths(paths, sensitive)),
        "identities": len(identities),
        "privileged_identities": sum(1 for a in identities if is_privileged(a)),
        "identity_findings": ident_findings,
    }
    if not account:  # endpoints are not tied to a cloud account
        ep = endpoint_stats(db)
        m.update({"devices_managed": ep["managed"], "devices_healthy": ep["healthy"], "devices_failing": ep["failing"],
                  "devices_suspended": ep["suspended"], "devices_outdated": ep["outdated"]})
    return m


def write_snapshot(db: Session, account: str | None = None, day: date | None = None,
                   metrics: dict[str, Any] | None = None) -> DashboardSnapshot:
    """Today's (or `day`'s) snapshot for the session's organisation and `account`
    ("" / None = all accounts); idempotent: an existing row is returned unchanged.
    Commits."""
    day = day or utcnow().date()
    scope = account or ""
    existing = db.scalar(select(DashboardSnapshot).where(DashboardSnapshot.day == day,
                                                         DashboardSnapshot.account == scope))
    if existing is not None:
        return existing
    row = DashboardSnapshot(day=day, account=scope, metrics=metrics if metrics is not None
                            else current_metrics(db, account or None))
    db.add(row)
    try:
        db.commit()
    except IntegrityError:  # another worker / request wrote it first
        db.rollback()
        row = db.scalar(select(DashboardSnapshot).where(DashboardSnapshot.day == day,
                                                        DashboardSnapshot.account == scope))
        assert row is not None
    return row


def accounts(db: Session) -> list[dict[str, str]]:
    rows = db.execute(select(Asset.provider, Asset.subscription_id, func.max(Asset.subscription_name))
                      .where(Asset.subscription_id.is_not(None))
                      .group_by(Asset.provider, Asset.subscription_id)).all()
    return sorted(({"id": sid, "name": name or sid, "provider": prov} for prov, sid, name in rows if sid),
                  key=lambda a: (a["provider"], a["name"].lower()))


def snapshot_all(db: Session, day: date | None = None) -> int:
    """Write the day's snapshots of the session's organisation: all accounts plus
    each cloud account. Returns the number of rows written (0 if all existed)."""
    day = day or utcnow().date()
    have = set(db.scalars(select(DashboardSnapshot.account).where(DashboardSnapshot.day == day)))
    written = 0
    for scope in [""] + [a["id"] for a in accounts(db)]:
        if scope in have:
            continue
        write_snapshot(db, scope, day)
        written += 1
    return written


def baseline(db: Session, w: Window) -> dict[str, Any] | None:
    """Metrics of the comparison snapshot (`range` days ago), or None."""
    row = db.scalar(select(DashboardSnapshot)
                    .where(DashboardSnapshot.account == (w.account or ""),
                           DashboardSnapshot.day <= w.compare_day,
                           DashboardSnapshot.day >= w.compare_day - timedelta(days=SNAPSHOT_TOLERANCE_DAYS))
                    .order_by(DashboardSnapshot.day.desc()).limit(1))
    return row.metrics if row is not None else None


def history_since(db: Session, w: Window) -> str | None:
    d = db.scalar(select(func.min(DashboardSnapshot.day)).where(DashboardSnapshot.account == (w.account or "")))
    return _day(d) if d is not None else None


def delta(current: float | int | None, base: dict[str, Any] | None, key: str) -> float | int | None:
    """current - snapshot value, or None if either side is unknown."""
    if current is None or base is None:
        return None
    prev = base.get(key)
    if prev is None or not isinstance(prev, int | float):
        return None
    d = current - prev
    return round(d, 1) if isinstance(d, float) else d


def ensure_today(db: Session, w: Window, metrics: dict[str, Any] | None = None) -> None:
    """Lazily write today's snapshot for this scope on the first read of the day."""
    exists = db.scalar(select(func.count()).select_from(DashboardSnapshot)
                       .where(DashboardSnapshot.day == w.today, DashboardSnapshot.account == (w.account or "")))
    if not exists:
        write_snapshot(db, w.account, w.today, metrics)


def snapshot_series(db: Session, w: Window, keys: list[str]) -> list[dict[str, Any]]:
    """Per chart bucket, the snapshot value of each key at the bucket's last day (None if no snapshot)."""
    buckets = w.buckets()
    rows = db.execute(select(DashboardSnapshot.day, DashboardSnapshot.metrics)
                      .where(DashboardSnapshot.account == (w.account or ""),
                             DashboardSnapshot.day >= buckets[0][0], DashboardSnapshot.day <= w.today)).all()
    by_day = {_day(d): m for d, m in rows}
    out = []
    for start, end in buckets:
        # last snapshot inside the bucket
        m = next((by_day[_day(end - timedelta(days=i))] for i in range((end - start).days + 1)
                  if _day(end - timedelta(days=i)) in by_day), None)
        out.append({"start": _day(start), "end": _day(end), **{k: (m or {}).get(k) for k in keys}})
    return out


# ----------------------------------------------------------------------------- overview
def _mttr(db: Session, start: datetime, end: datetime, w: Window) -> dict[str, Any]:
    days = _days_between(db, Finding.resolved_at, Finding.first_seen)
    sla = sla_days()
    met = case(*[(and_(Finding.severity == s, days <= d), 1) for s, d in sla.items()], else_=0)
    rows = db.execute(_f(select(Finding.severity, func.count(), func.avg(days), func.sum(met))
                         .where(Finding.status == "resolved", Finding.resolved_at.is_not(None),
                                Finding.resolved_at >= start, Finding.resolved_at < end)
                         .group_by(Finding.severity), w)).all()
    n = sum(r[1] for r in rows)
    total_days = sum(float(r[2] or 0) * r[1] for r in rows)
    by = {r[0]: (round(float(r[2]), 1) if r[2] is not None else None) for r in rows}
    sla_n = sum(r[1] for r in rows if r[0] in sla)
    sla_met = sum(int(r[3] or 0) for r in rows if r[0] in sla)
    return {"value": round(total_days / n, 1) if n else None, "resolved": n,
            "critical": by.get("critical"), "high": by.get("high"),
            "sla_met_pct": round(100.0 * sla_met / sla_n, 1) if sla_n else None}


def _issue_trend(db: Session, w: Window) -> dict[str, Any]:
    new = db.execute(_f(select(func.date(Finding.first_seen), func.count())
                        .where(Finding.first_seen >= datetime.combine(w.buckets()[0][0], datetime.min.time()))
                        .group_by(func.date(Finding.first_seen)), w)).all()
    resolved = db.execute(_f(select(func.date(Finding.resolved_at), func.count())
                             .where(Finding.status == "resolved", Finding.resolved_at.is_not(None),
                                    Finding.resolved_at >= datetime.combine(w.buckets()[0][0], datetime.min.time()))
                             .group_by(func.date(Finding.resolved_at)), w)).all()
    new_by = {_day(d): n for d, n in new}
    res_by = {_day(d): n for d, n in resolved}
    points = []
    for start, end in w.buckets():
        days = [_day(start + timedelta(days=i)) for i in range((end - start).days + 1)]
        points.append({"start": _day(start), "end": _day(end), "new": sum(new_by.get(d, 0) for d in days),
                       "resolved": sum(res_by.get(d, 0) for d in days)})
    return {"bucket": w.bucket, "points": points}


AGE_BUCKETS = [("0-7", "0–7 d", 0, 7), ("8-30", "8–30 d", 7, 30), ("31-90", "31–90 d", 30, 90),
               ("90+", "90 d+", 90, None)]


def _age(db: Session, w: Window) -> list[dict[str, Any]]:
    now = w.now
    bucket = case(*[(Finding.first_seen >= now - timedelta(days=lo if hi is None else hi), key)
                    for key, _, lo, hi in AGE_BUCKETS if hi is not None], else_="90+")
    # Bucket in a subquery, group outside: GROUP BY on an expression with bound
    # parameters is not portable (PostgreSQL compares the parameters by position).
    sub = _f(select(bucket.label("bucket"), Finding.severity.label("severity")).where(Finding.status == "open"),
             w).subquery()
    rows = db.execute(select(sub.c.bucket, sub.c.severity, func.count())
                      .group_by(sub.c.bucket, sub.c.severity)).all()
    out = {key: {"bucket": key, "label": label, **dict.fromkeys(SEVERITIES, 0)} for key, label, _, _ in AGE_BUCKETS}
    for key, sev, n in rows:
        if key in out and sev in SEVERITIES:
            out[key][sev] += n
    return list(out.values())


def _categories(db: Session, w: Window) -> list[dict[str, Any]]:
    rows = db.execute(_f(select(Finding.rule_id, Asset.type, Finding.severity, func.count())
                         .join(Asset, and_(Asset.organization_id == Finding.organization_id,
                                           Asset.id == Finding.asset_id), isouter=True)
                         .where(Finding.status == "open")
                         .group_by(Finding.rule_id, Asset.type, Finding.severity), w)).all()
    cats: dict[str, dict[str, int]] = {c: dict.fromkeys(SEVERITIES, 0) for c in CATEGORIES}
    for rule_id, atype, sev, n in rows:
        if sev in SEVERITIES:
            cats[category_of(rule_id, atype)][sev] += n
    out = [{"category": c, "total": sum(v.values()), **v} for c, v in cats.items()]
    return sorted([c for c in out if c["total"]], key=lambda c: (-c["total"], CATEGORIES.index(c["category"])))


def _top_assets(db: Session, w: Window, limit: int = 5) -> list[dict[str, Any]]:
    frows = db.execute(_f(select(Finding.asset_id, Finding.severity, func.count()).where(Finding.status == "open")
                          .group_by(Finding.asset_id, Finding.severity), w)).all()
    vrows = db.execute(_v(select(Vulnerability.asset_id, func.max(Vulnerability.risk_score), func.count())
                          .where(Vulnerability.status == "open", Vulnerability.asset_id.is_not(None))
                          .group_by(Vulnerability.asset_id), w)).all()
    per: dict[str, dict[str, Any]] = defaultdict(lambda: {"floor": 0.0, "vuln": 0.0, "critical": 0, "high": 0,
                                                          "findings": 0, "vulns": 0})
    for aid, sev, n in frows:
        p = per[aid]
        p["floor"] = max(p["floor"], FINDING_FLOOR.get(sev, 0.0))
        p["findings"] += n
        if sev in ("critical", "high"):
            p[sev] += n
    for aid, mx, n in vrows:
        per[aid]["vuln"] = float(mx or 0)
        per[aid]["vulns"] = n
    if not per:
        return []
    assets = {a.id: a for a in db.scalars(select(Asset).where(Asset.id.in_(list(per))))}
    out = []
    for aid, p in per.items():
        a = assets.get(aid)
        if a is None:
            continue
        score = max(p["floor"], p["vuln"])
        out.append({"id": aid, "name": a.name, "type": a.type, "type_label": TYPE_LABEL.get(a.type, a.type),
                    "risk": round(min(100.0, score)), "critical": p["critical"], "high": p["high"],
                    "findings": p["findings"], "vulnerabilities": p["vulns"],
                    "internet_exposed": bool(a.internet_exposed), "sensitive_data": bool(a.sensitive_data)})
    out.sort(key=lambda x: (-x["risk"], -x["critical"], -x["high"], -x["vulnerabilities"], x["name"]))
    return out[:limit]


def _path_parts(paths: list[AttackPath]) -> dict[str, int]:
    return _sev_counts(Counter(p.severity for p in paths).items())


def overview(db: Session, w: Window) -> dict[str, Any]:
    findings = open_findings_by_severity(db, w)
    alerts = open_alerts_by_severity(db, w)
    paths = scoped_paths(db, w)
    confirmed = [p for p in paths if p.confirmed]
    items = exposure_items(db, w)
    score = risk_score(db, w, findings, alerts, paths)
    ensure_today(db, w)
    base = baseline(db, w)
    mttr = _mttr(db, w.start, w.now, w)
    prev_mttr = _mttr(db, w.prev_start, w.start, w)
    frameworks = compliance(db, w)
    base_compliance = (base or {}).get("compliance") or {}
    open_n = sum(findings.values())
    sev = "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"
    out = {
        "risk_score": {"value": score, "delta": delta(score, base, "risk_score"), "severity": sev,
                       "critical_findings": findings["critical"],
                       "critical_paths": sum(1 for p in confirmed if p.severity == "critical")},
        "kpis": {
            "open_issues": {"value": open_n, "delta": delta(open_n, base, "open_issues"), "parts": findings},
            "critical_high": {"value": findings["critical"] + findings["high"],
                              "delta": delta(findings["critical"] + findings["high"], base, "critical_high"),
                              "parts": {"critical": findings["critical"], "high": findings["high"]}},
            "mttr": {**mttr, "delta": (round(mttr["value"] - prev_mttr["value"], 1)
                                       if mttr["value"] is not None and prev_mttr["value"] is not None else None),
                     "sla_days": sla_days()},
            "exposed_assets": {"value": len(items), "delta": delta(len(items), base, "exposed_assets"),
                               "parts": _group_parts(Counter(i["type"] for i in items))},
            "runtime_threats": {"value": sum(alerts.values()), "delta": delta(sum(alerts.values()), base,
                                                                             "runtime_threats"),
                                "parts": alerts},
            "attack_paths": {"value": len(confirmed), "delta": delta(len(confirmed), base, "attack_paths"),
                             "parts": _path_parts(confirmed)},
        },
        "issue_trend": _issue_trend(db, w),
        "compliance": [{**c, "delta": (round(c["score"] - base_compliance[c["framework"]], 1)
                                       if isinstance(base_compliance.get(c["framework"]), int | float) else None)}
                       for c in frameworks],
        "age": _age(db, w),
        "categories": _categories(db, w),
        "top_assets": _top_assets(db, w),
        "endpoints": endpoint_stats(db),
    }
    return out


# ----------------------------------------------------------------------------- vulnerabilities
def _vuln_over_time(db: Session, w: Window) -> list[dict[str, Any]]:
    """Open critical / high vulnerabilities at the end of each bucket, from first_seen / resolved_at."""
    buckets = w.buckets()
    cols = []
    for _, end in buckets:
        t = _end_of(end, w)
        open_at = and_(Vulnerability.first_seen <= t,
                       or_(Vulnerability.resolved_at > t,
                           and_(Vulnerability.resolved_at.is_(None), Vulnerability.status == "open")))
        cols.append(func.sum(case((open_at, 1), else_=0)))
    rows = db.execute(_v(select(Vulnerability.severity, *cols)
                         .where(Vulnerability.severity.in_(("critical", "high")))
                         .group_by(Vulnerability.severity), w)).all()
    by = {r[0]: [int(x or 0) for x in r[1:]] for r in rows}
    snaps = snapshot_series(db, w, ["vulns_prioritized"])
    return [{"start": _day(s), "end": _day(e), "critical": by.get("critical", [0] * len(buckets))[i],
             "high": by.get("high", [0] * len(buckets))[i], "prioritized": snaps[i]["vulns_prioritized"]}
            for i, (s, e) in enumerate(buckets)]


def vulnerabilities(db: Session, w: Window) -> dict[str, Any]:
    ensure_today(db, w)
    base = baseline(db, w)
    fixable = _fixable()
    # (severity, kev, in_use, count, fixable count)
    rows = [(r[0], r[1], r[2], int(r[3] or 0), int(r[4] or 0)) for r in db.execute(
        _v(select(Vulnerability.severity, Vulnerability.kev, Vulnerability.in_use, func.count(), func.sum(fixable))
           .where(Vulnerability.status == "open")
           .group_by(Vulnerability.severity, Vulnerability.kev, Vulnerability.in_use), w))]
    total = sum(r[3] for r in rows)
    fix_n = sum(r[4] for r in rows)
    crit = [r for r in rows if r[0] == "critical"]
    kev = _sev_counts((r[0], r[3]) for r in rows if r[1])
    in_use = _sev_counts((r[0], r[3]) for r in rows if r[2])
    fix_pct = round(100.0 * fix_n / total, 1) if total else None
    base_fix = (base or {}).get("vulns_fix_pct")

    by_sev = db.execute(_v(select(Vulnerability.severity, func.count(), func.count(func.distinct(Vulnerability.cve_id)),
                                  func.count(func.distinct(func.coalesce(Vulnerability.asset_id,
                                                                         Vulnerability.device_id))))
                           .where(Vulnerability.status == "open").group_by(Vulnerability.severity), w)).all()
    sev_rows = {r[0]: r for r in by_sev}
    workload_in_use = db.execute(_v(select(Vulnerability.in_use, func.count())
                                    .where(Vulnerability.status == "open", Vulnerability.asset_id.is_not(None))
                                    .group_by(Vulnerability.in_use), w)).all()

    wl_rows = db.execute(_v(select(Asset.type, Vulnerability.device_id.is_not(None), Vulnerability.severity, func.count())
                            .select_from(Vulnerability)
                            .join(Asset, and_(Asset.organization_id == Vulnerability.organization_id,
                                              Asset.id == Vulnerability.asset_id), isouter=True)
                            .where(Vulnerability.status == "open")
                            .group_by(Asset.type, Vulnerability.device_id.is_not(None), Vulnerability.severity),
                            w)).all()
    workloads: dict[str, dict[str, Any]] = {}
    for atype, on_device, sev, n in wl_rows:
        key = "endpoints" if on_device else WORKLOAD_OF.get(atype or "", "other")
        wl = workloads.setdefault(key, {"key": key, "label": WORKLOAD_LABEL[key], "types": set(),
                                        **dict.fromkeys(SEVERITIES, 0)})
        if atype:
            wl["types"].add(atype)
        if sev in SEVERITIES:
            wl[sev] += n
    wl_out = [{**v, "types": sorted(v["types"]), "total": sum(v[s] for s in SEVERITIES)} for v in workloads.values()]
    wl_out.sort(key=lambda x: -x["total"])

    sev_rank = case((Vulnerability.severity == "critical", 4), (Vulnerability.severity == "high", 3),
                    (Vulnerability.severity == "medium", 2), (Vulnerability.severity == "low", 1), else_=0)
    flag = lambda col: func.max(case((col.is_(True), 1), else_=0))  # noqa: E731 - portable bool_or
    cves = db.execute(_v(select(Vulnerability.cve_id, func.min(Vulnerability.package), func.min(Vulnerability.version),
                                func.max(sev_rank), func.max(Vulnerability.epss), flag(Vulnerability.kev),
                                flag(Vulnerability.in_use), flag(Vulnerability.internet_exposed),
                                func.max(case((Vulnerability.device_id.is_not(None), 1), else_=0)),
                                func.count(func.distinct(func.coalesce(Vulnerability.asset_id, Vulnerability.device_id))),
                                func.max(Vulnerability.risk_score), func.max(Vulnerability.cvss),
                                func.max(fixable))
                         .where(Vulnerability.status == "open")
                         .group_by(Vulnerability.cve_id), w)).all()
    rank_sev = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
    top = [{"cve_id": c[0], "package": c[1], "version": c[2], "severity": rank_sev.get(int(c[3] or 0), "info"),
            "epss": c[4], "kev": bool(c[5]), "runtime": bool(c[6]), "internet": bool(c[7]), "endpoint": bool(c[8]),
            "assets": c[9], "risk": c[10], "cvss": c[11], "fix_available": bool(c[12])} for c in cves]
    top.sort(key=lambda c: (-c["kev"], -(c["runtime"] and c["internet"]), -(c["epss"] or 0), -(c["risk"] or 0),
                            -(c["cvss"] or 0), c["cve_id"]))
    crit_total = sum(r[3] for r in crit)
    crit_fix = sum(r[4] for r in crit)
    return {
        "kpis": {
            "critical": {"value": crit_total, "delta": delta(crit_total, base, "vulns_critical"),
                         "fix_available": crit_fix, "no_fix": crit_total - crit_fix},
            "kev": {"value": sum(kev.values()), "delta": delta(sum(kev.values()), base, "vulns_kev"), "parts": kev},
            "in_use": {"value": sum(in_use.values()), "delta": delta(sum(in_use.values()), base, "vulns_in_use"),
                       "parts": in_use},
            "fix_available": {"value": fix_pct, "delta": (round(fix_pct - base_fix, 1) if fix_pct is not None
                                                          and isinstance(base_fix, int | float) else None),
                              "fixable": fix_n, "no_fix": total - fix_n},
        },
        "total": total,
        "over_time": {"bucket": w.bucket, "points": _vuln_over_time(db, w)},
        "by_severity": [{"severity": s, "vulns": sev_rows[s][1] if s in sev_rows else 0,
                         "cves": sev_rows[s][2] if s in sev_rows else 0,
                         "assets": sev_rows[s][3] if s in sev_rows else 0} for s in SEVERITIES],
        "noise_reduction": noise_reduction(bool(f) for f, n in workload_in_use for _ in range(n)),
        "workloads": wl_out,
        "top_cves": top[:8],
    }


# ----------------------------------------------------------------------------- exposure
def _path_row(p: AttackPath) -> dict[str, Any]:
    return {"id": p.id, "title": p.title, "severity": p.severity, "score": p.score, "confirmed": p.confirmed,
            "entry": {"id": p.entry_id, "name": p.steps[0].name if p.steps else p.entry_id,
                      "detail": (p.steps[0].reasons[0] if p.steps and p.steps[0].reasons else None)},
            "target": {"id": p.target_id, "name": p.steps[-1].name if p.steps else p.target_id},
            "steps": [{"id": s.asset_id, "name": s.name, "type": s.type} for s in p.steps],
            "weaknesses": p.weaknesses[:4]}


def exposure(db: Session, w: Window) -> dict[str, Any]:
    ensure_today(db, w)
    base = baseline(db, w)
    items = exposure_items(db, w)
    types = Counter(i["type"] for i in items)
    ports = management_ports(db, items)
    stores = Counter(i["type"] for i in items if TYPE_GROUP.get(i["type"]) in DATA_STORE_GROUPS)
    paths = scoped_paths(db, w)
    sensitive = _sensitive_ids(db)
    jewels = crown_jewel_paths(paths, sensitive)
    exposed_ids = {i["id"] for i in items if i["level"] == "open"}
    internet_paths = [p for p in paths if p.entry_id in exposed_ids]
    internet_paths.sort(key=lambda p: (not p.confirmed, -p.score))
    return {
        "kpis": {
            "exposed_assets": {"value": len(items), "delta": delta(len(items), base, "exposed_assets"),
                               "parts": _group_parts(types)},
            "mgmt_ports": {"value": sum(ports.values()), "delta": delta(sum(ports.values()), base, "mgmt_ports"),
                           "parts": [{"key": k, "label": label, "count": ports[k], "port": p[0]}
                                     for k, label, p in MANAGEMENT_PORTS if ports[k]]},
            "data_stores": {"value": sum(stores.values()), "delta": delta(sum(stores.values()), base,
                                                                         "exposed_data_stores"),
                            "parts": _group_parts(stores, groups=DATA_STORE_GROUPS)},
            "crown_jewels": {"value": len(jewels), "delta": delta(len(jewels), base, "crown_jewel_paths"),
                             "parts": _path_parts(jewels)},
        },
        "by_type": [{"type": t, "label": TYPE_LABEL.get(t, t), "group": TYPE_GROUP.get(t, "other"), "count": n}
                    for t, n in sorted(types.items(), key=lambda x: (-x[1], x[0]))],
        "levels": {"open": sum(1 for i in items if i["level"] == "open"),
                   "restricted": sum(1 for i in items if i["level"] == "restricted")},
        "trend": {"bucket": w.bucket, "points": snapshot_series(db, w, ["exposed_assets", "crown_jewel_paths"])},
        "history_since": history_since(db, w),
        "paths": [_path_row(p) for p in internet_paths[:10]],
        "paths_total": len(internet_paths),
    }


# ----------------------------------------------------------------------------- identities
def identities(db: Session, w: Window) -> dict[str, Any]:
    ensure_today(db, w)
    base = baseline(db, w)
    idents = list(db.scalars(_a(select(Asset).where(Asset.type.in_(IDENTITY_TYPES)), w)))
    ids = {a.id for a in idents}
    privileged = [a for a in idents if is_privileged(a)]
    frows = db.execute(_f(select(Finding.rule_id, Finding.title, Finding.severity, func.count(),
                                 func.count(func.distinct(Finding.asset_id)))
                          .where(Finding.status == "open", category_filter("Identity"))
                          .group_by(Finding.rule_id, Finding.title, Finding.severity), w)).all()
    by_sev = _sev_counts((r[2], r[3]) for r in frows)
    findings_of: dict[str, int] = {}
    if ids:
        findings_of = dict(db.execute(select(Finding.asset_id, func.count())
                                      .where(Finding.status == "open", Finding.asset_id.in_(list(ids)))
                                      .group_by(Finding.asset_id)).all())
    confirmed = [p for p in scoped_paths(db, w) if p.confirmed]
    on_paths: dict[str, str] = {}
    order = {s: i for i, s in enumerate(SEVERITIES)}
    for p in confirmed:
        for s in p.steps:
            if s.asset_id in ids and (s.asset_id not in on_paths or order.get(p.severity, 9) < order.get(
                    on_paths[s.asset_id], 9)):
                on_paths[s.asset_id] = p.severity
    rows = []
    for a in idents:
        p = a.properties or {}
        roles = [r for r in (p.get("admin_roles") or p.get("roles") or [])][:4]
        rows.append({"id": a.id, "name": a.name, "type": a.type, "type_label": TYPE_LABEL.get(a.type, a.type),
                     "provider": a.provider, "principal_type": p.get("principal_type"), "privileged": is_privileged(a),
                     "roles": roles, "scope": p.get("scope"), "findings": findings_of.get(a.id, 0),
                     "attack_path": on_paths.get(a.id)})
    rows.sort(key=lambda r: (r["attack_path"] is None, order.get(r["attack_path"] or "", 9), not r["privileged"],
                             -r["findings"], r["name"]))
    type_counts = Counter(a.type for a in idents)
    return {
        "kpis": {
            "identities": {"value": len(idents), "delta": delta(len(idents), base, "identities"),
                           "parts": [{"key": t, "label": TYPE_LABEL.get(t, t), "count": n}
                                     for t, n in sorted(type_counts.items(), key=lambda x: -x[1])]},
            "privileged": {"value": len(privileged), "delta": delta(len(privileged), base, "privileged_identities"),
                           "parts": [{"key": t, "label": TYPE_LABEL.get(t, t), "count": n} for t, n in
                                     sorted(Counter(a.type for a in privileged).items(), key=lambda x: -x[1])]},
            "findings": {"value": sum(by_sev.values()), "delta": delta(sum(by_sev.values()), base,
                                                                      "identity_findings"),
                         "parts": by_sev},
            "on_paths": {"value": len(on_paths), "parts": _sev_counts(Counter(on_paths.values()).items())},
        },
        "findings_by_severity": by_sev,
        "rules": sorted([{"rule_id": r[0], "title": r[1], "severity": r[2], "findings": r[3], "identities": r[4]}
                         for r in frows], key=lambda r: (order.get(r["severity"], 9), -r["findings"]))[:8],
        "identities": rows[:12],
        "total": len(idents),
    }


# ----------------------------------------------------------------------------- endpoints
def endpoints(db: Session, w: Window) -> dict[str, Any]:
    # Devices are not tied to a cloud account: always the whole organisation.
    all_w = window(w.range, None, w.now)
    ensure_today(db, all_w)
    base = baseline(db, all_w)
    ep = endpoint_stats(db)
    dv = _sev_counts(db.execute(select(Vulnerability.severity, func.count())
                                .where(Vulnerability.status == "open", Vulnerability.device_id.is_not(None))
                                .group_by(Vulnerability.severity)))
    dv_kev = db.scalar(select(func.count()).select_from(Vulnerability)
                       .where(Vulnerability.status == "open", Vulnerability.device_id.is_not(None),
                              Vulnerability.kev.is_(True))) or 0
    return {
        **ep,
        "kpis": {
            "managed": {"value": ep["managed"], "delta": delta(ep["managed"], base, "devices_managed"),
                        "parts": ep["by_os"]},
            "failing": {"value": ep["failing"], "delta": delta(ep["failing"], base, "devices_failing")},
            "suspended": {"value": ep["suspended"], "delta": delta(ep["suspended"], base, "devices_suspended")},
            "outdated": {"value": ep["outdated"], "delta": delta(ep["outdated"], base, "devices_outdated")},
        },
        "vulnerabilities": {"total": sum(dv.values()), "kev": dv_kev, "by_severity": dv},
        "account_filter_applies": False,
    }


# ----------------------------------------------------------------------------- meta
def meta(db: Session, w: Window) -> dict[str, Any]:
    """Tab badges, the account picker and settings (one cheap call for the page frame)."""
    vulns = db.scalar(_v(select(func.count()).select_from(Vulnerability).where(Vulnerability.status == "open"), w))
    idents = db.scalar(_a(select(func.count()).select_from(Asset).where(Asset.type.in_(IDENTITY_TYPES)), w))
    managed = db.scalar(select(func.count()).select_from(Device).where(Device.status == "active"))
    return {
        "tabs": {"vulnerabilities": vulns or 0, "exposure": len(exposure_items(db, w)), "identities": idents or 0,
                 "endpoints": managed or 0},
        "accounts": accounts(db),
        "ranges": list(RANGES),
        "sla_days": sla_days(),
        "history_since": history_since(db, w),
    }
