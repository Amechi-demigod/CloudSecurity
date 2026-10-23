"""Declarative CSPM rules engine.

Each rule is a small, declarative record: id, title, severity, the resource type
it applies to, a pure `check` function that receives the normalized asset
(a dict) and returns either `None` (pass) or an evidence dict (fail), plus
remediation text and compliance mappings.

Rules operate only on *normalized* properties, so the same rules apply to the
simulated environment and to real Azure scans (the Azure connector maps SDK
objects onto these property names). AWS and GCP rules live in
`posture_aws.py` / `posture_gcp.py` and register into the same catalog.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}

Evidence = dict[str, Any] | None
CheckFn = Callable[[dict[str, Any]], Evidence]


@dataclass(frozen=True)
class PostureRule:
    id: str
    title: str
    severity: str
    resource_type: str
    check: CheckFn
    description: str
    remediation: str
    compliance: list[str] = field(default_factory=list)

    def evaluate(self, asset: dict[str, Any]) -> Evidence:
        if asset.get("type") != self.resource_type:
            return None
        try:
            return self.check(asset)
        except Exception:  # a broken rule must never break a scan
            return None


RULES: list[PostureRule] = []


def rule(**kwargs) -> Callable[[CheckFn], CheckFn]:
    """Decorator registering a check function as a posture rule."""

    def deco(fn: CheckFn) -> CheckFn:
        RULES.append(PostureRule(check=fn, **kwargs))
        return fn

    return deco


def _p(asset: dict, key: str, default=None):
    return (asset.get("properties") or {}).get(key, default)


# --------------------------------------------------------------------------- helpers
INTERNET_SOURCES = {"*", "0.0.0.0/0", "internet", "any", "::/0", "0.0.0.0"}


def _port_matches(port_range: str, port: int | None) -> bool:
    """`port=None` means "all ports" must be open."""
    pr = str(port_range).strip()
    if pr in {"*", "0-65535", "any"}:
        return True
    if port is None:
        return False
    for part in pr.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            if lo.isdigit() and hi.isdigit() and int(lo) <= port <= int(hi):
                return True
        elif part.isdigit() and int(part) == port:
            return True
    return False


def open_to_internet(asset: dict, port: int | None) -> list[str]:
    """Names of inbound Allow rules exposing `port` (or all ports) to the internet."""
    hits = []
    for r in _p(asset, "security_rules", []) or []:
        if str(r.get("direction", "")).lower() != "inbound" or str(r.get("access", "")).lower() != "allow":
            continue
        sources = r.get("source_prefixes") or [r.get("source", "")]
        if not any(str(s).lower() in INTERNET_SOURCES for s in sources):
            continue
        ports = r.get("port_ranges") or [r.get("port_range", "")]
        if any(_port_matches(pr, port) for pr in ports):
            hits.append(r.get("name", "?"))
    return hits


# --------------------------------------------------------------------------- storage
@rule(
    id="AZ-STG-001",
    title="Storage account allows public blob access",
    severity="high",
    resource_type="storage_account",
    description="Anonymous public read access to blobs/containers is permitted on this account.",
    remediation="Set 'Allow Blob anonymous access' to Disabled: "
    "az storage account update -n <name> -g <rg> --allow-blob-public-access false",
    compliance=["CIS Azure 3.7"],
)
def _stg_public(a):
    return {"allow_blob_public_access": True} if _p(a, "allow_blob_public_access") else None


@rule(
    id="AZ-STG-002",
    title="Storage account does not require secure transfer (HTTPS)",
    severity="medium",
    resource_type="storage_account",
    description="Requests over plain HTTP are accepted.",
    remediation="az storage account update -n <name> -g <rg> --https-only true",
    compliance=["CIS Azure 3.1"],
)
def _stg_https(a):
    return {"https_only": False} if _p(a, "https_only") is False else None


@rule(
    id="AZ-STG-003",
    title="Storage account minimum TLS version below 1.2",
    severity="medium",
    resource_type="storage_account",
    description="Clients can negotiate deprecated TLS 1.0/1.1.",
    remediation="az storage account update -n <name> -g <rg> --min-tls-version TLS1_2",
    compliance=["CIS Azure 3.15"],
)
def _stg_tls(a):
    v = str(_p(a, "min_tls_version") or "TLS1_0")
    return {"min_tls_version": v} if v.upper() in {"TLS1_0", "TLS1_1"} else None


# --------------------------------------------------------------------------- network
@rule(
    id="AZ-NSG-001",
    title="NSG allows SSH (22) from the internet",
    severity="high",
    resource_type="nsg",
    description="An inbound Allow rule exposes TCP/22 to 0.0.0.0/0.",
    remediation="Restrict the source to known admin ranges or use Azure Bastion / JIT VM access.",
    compliance=["CIS Azure 6.2"],
)
def _nsg_ssh(a):
    hits = open_to_internet(a, 22)
    return {"rules": hits, "port": 22} if hits else None


@rule(
    id="AZ-NSG-002",
    title="NSG allows RDP (3389) from the internet",
    severity="high",
    resource_type="nsg",
    description="An inbound Allow rule exposes TCP/3389 to 0.0.0.0/0.",
    remediation="Restrict the source to known admin ranges or use Azure Bastion / JIT VM access.",
    compliance=["CIS Azure 6.1"],
)
def _nsg_rdp(a):
    hits = open_to_internet(a, 3389)
    return {"rules": hits, "port": 3389} if hits else None


@rule(
    id="AZ-NSG-003",
    title="NSG allows all ports from the internet",
    severity="critical",
    resource_type="nsg",
    description="An inbound Allow rule exposes every port to 0.0.0.0/0.",
    remediation="Remove the any/any rule and allow only required ports from required sources.",
    compliance=["CIS Azure 6.1", "CIS Azure 6.2"],
)
def _nsg_any(a):
    hits = open_to_internet(a, None)
    return {"rules": hits, "port": "*"} if hits else None


# --------------------------------------------------------------------------- compute
@rule(
    id="AZ-VM-001",
    title="Virtual machine has a public IP address",
    severity="medium",
    resource_type="vm",
    description="The VM is directly reachable from the internet via a public IP.",
    remediation="Remove the public IP and front the workload with a load balancer/App Gateway, or use Bastion.",
    compliance=["CIS Azure 7.1"],
)
def _vm_pip(a):
    ips = _p(a, "public_ips") or []
    return {"public_ips": ips} if ips else None


@rule(
    id="AZ-VM-002",
    title="Virtual machine disks are not encrypted (ADE / host / CMK)",
    severity="medium",
    resource_type="vm",
    description="Neither Azure Disk Encryption, encryption-at-host nor a customer-managed key is configured.",
    remediation="Enable encryption at host or Azure Disk Encryption with a Key Vault-backed key.",
    compliance=["CIS Azure 7.2", "CIS Azure 7.3"],
)
def _vm_enc(a):
    return {"disk_encryption": False} if _p(a, "disk_encryption") is False else None


@rule(
    id="AZ-VMSS-001",
    title="Scale set instances get public IP addresses",
    severity="medium",
    resource_type="vmss",
    description="Every instance of the scale set is directly reachable from the internet via its own public IP.",
    remediation="Remove the public IP configuration and front the scale set with a load balancer/App Gateway.",
    compliance=["CIS Azure 7.1"],
)
def _vmss_pip(a):
    return {"per_instance_public_ip": True} if _p(a, "per_instance_public_ip") else None


@rule(
    id="AZ-VMSS-002",
    title="Scale set disks are not encrypted (host / CMK)",
    severity="medium",
    resource_type="vmss",
    description="Neither encryption-at-host nor a customer-managed key is configured for the scale set's disks.",
    remediation="Enable encryption at host or a disk encryption set on the scale set model and upgrade instances.",
    compliance=["CIS Azure 7.2", "CIS Azure 7.3"],
)
def _vmss_enc(a):
    return {"disk_encryption": False} if _p(a, "disk_encryption") is False else None


# --------------------------------------------------------------------------- sql
@rule(
    id="AZ-SQL-001",
    title="SQL server allows public network access",
    severity="medium",
    resource_type="sql_server",
    description="The logical SQL server accepts connections from public networks.",
    remediation="Disable public network access and use Private Endpoints.",
    compliance=["CIS Azure 4.1.2"],
)
def _sql_public(a):
    return {"public_network_access": "Enabled"} if _p(a, "public_network_access") else None


@rule(
    id="AZ-SQL-002",
    title="SQL server auditing is disabled",
    severity="medium",
    resource_type="sql_server",
    description="Server-level auditing is not enabled.",
    remediation="Enable server auditing to a Log Analytics workspace or storage account.",
    compliance=["CIS Azure 4.1.1"],
)
def _sql_audit(a):
    return {"auditing_enabled": False} if _p(a, "auditing_enabled") is False else None


@rule(
    id="AZ-SQL-003",
    title="SQL server firewall allows all IPs (0.0.0.0-255.255.255.255)",
    severity="critical",
    resource_type="sql_server",
    description="A firewall rule allows the entire IPv4 internet to reach the server.",
    remediation="Delete the 0.0.0.0-255.255.255.255 rule; allow specific client IPs or use Private Endpoints.",
    compliance=["CIS Azure 4.1.2"],
)
def _sql_fw(a):
    bad = [
        r.get("name")
        for r in _p(a, "firewall_rules", []) or []
        if r.get("start_ip") == "0.0.0.0" and r.get("end_ip") == "255.255.255.255"
    ]
    return {"rules": bad} if bad else None


# --------------------------------------------------------------------------- key vault
@rule(
    id="AZ-KV-001",
    title="Key Vault soft delete is disabled",
    severity="medium",
    resource_type="key_vault",
    description="Deleted vaults/secrets cannot be recovered.",
    remediation="Enable soft delete (now mandatory for new vaults; migrate legacy vaults).",
    compliance=["CIS Azure 8.5"],
)
def _kv_soft(a):
    return {"soft_delete": False} if _p(a, "soft_delete") is False else None


@rule(
    id="AZ-KV-002",
    title="Key Vault purge protection is disabled",
    severity="medium",
    resource_type="key_vault",
    description="A malicious insider could permanently purge keys and secrets.",
    remediation="az keyvault update -n <name> --enable-purge-protection true",
    compliance=["CIS Azure 8.5"],
)
def _kv_purge(a):
    return {"purge_protection": False} if not _p(a, "purge_protection") else None


# --------------------------------------------------------------------------- AKS
@rule(
    id="AZ-AKS-001",
    title="AKS cluster has Kubernetes RBAC disabled",
    severity="high",
    resource_type="aks_cluster",
    description="Without RBAC every authenticated identity has broad access to the cluster.",
    remediation="Recreate the cluster with --enable-rbac (RBAC cannot be enabled in place).",
    compliance=["CIS AKS 4.1.1"],
)
def _aks_rbac(a):
    return {"rbac_enabled": False} if _p(a, "rbac_enabled") is False else None


@rule(
    id="AZ-AKS-002",
    title="AKS API server is publicly accessible without IP restrictions",
    severity="high",
    resource_type="aks_cluster",
    description="The control plane is reachable from any internet address.",
    remediation="Use a private cluster or set --api-server-authorized-ip-ranges.",
    compliance=["CIS AKS 5.4.1"],
)
def _aks_public(a):
    if _p(a, "private_cluster"):
        return None
    if _p(a, "authorized_ip_ranges"):
        return None
    return {"private_cluster": False, "authorized_ip_ranges": []}


@rule(
    id="AZ-POD-001",
    title="Container runs privileged",
    severity="high",
    resource_type="pod",
    description="Privileged containers can escape to the node.",
    remediation="Remove securityContext.privileged and enforce the 'restricted' Pod Security Standard.",
    compliance=["CIS AKS 4.2.1"],
)
def _pod_priv(a):
    return {"privileged": True} if _p(a, "privileged") else None


# --------------------------------------------------------------------------- functions / identity
@rule(
    id="AZ-FN-001",
    title="Function app does not enforce HTTPS",
    severity="medium",
    resource_type="function_app",
    description="The function app accepts plain-HTTP requests.",
    remediation="az functionapp update -n <name> -g <rg> --set httpsOnly=true",
    compliance=["CIS Azure 9.2"],
)
def _fn_https(a):
    return {"https_only": False} if _p(a, "https_only") is False else None


@rule(
    id="AZ-ID-001",
    title="Managed identity has Owner/Contributor at subscription scope",
    severity="high",
    resource_type="identity",
    description="A workload identity holds a broad, subscription-wide privileged role.",
    remediation="Replace with a narrowly scoped built-in or custom role on the specific resources needed.",
    compliance=["CIS Azure 1.23"],
)
def _id_priv(a):
    roles = [r for r in _p(a, "roles", []) or [] if r in {"Owner", "Contributor", "User Access Administrator"}]
    return {"privileged_roles": roles} if roles and _p(a, "scope", "subscription") == "subscription" else None


@rule(
    id="AZ-SUB-001",
    title="Too many subscription Owners",
    severity="medium",
    resource_type="subscription",
    description="More than 3 principals hold the Owner role on the subscription.",
    remediation="Reduce standing Owner assignments; use PIM for just-in-time elevation.",
    compliance=["CIS Azure 1.x"],
)
def _sub_owners(a):
    n = int(_p(a, "owner_count", 0) or 0)
    return {"owner_count": n} if n > 3 else None


@rule(
    id="AZ-SUB-002",
    title="Large number of privileged (Owner/Contributor) assignments",
    severity="low",
    resource_type="subscription",
    description="More than 10 principals hold Owner or Contributor on the subscription.",
    remediation="Review role assignments and move to least-privilege roles.",
    compliance=["CIS Azure 1.x"],
)
def _sub_contrib(a):
    n = int(_p(a, "owner_count", 0) or 0) + int(_p(a, "contributor_count", 0) or 0)
    return {"privileged_count": n} if n > 10 else None


def rules_for(resource_type: str) -> list[PostureRule]:
    return [r for r in RULES if r.resource_type == resource_type]


def evaluate_asset(asset: dict[str, Any]) -> list[tuple[PostureRule, dict]]:
    """Run every applicable rule; return list of (rule, evidence) for failures."""
    out = []
    for r in rules_for(asset.get("type", "")):
        ev = r.evaluate(asset)
        if ev is not None:
            out.append((r, ev))
    return out


def get_rule(rule_id: str) -> PostureRule | None:
    return next((r for r in RULES if r.id == rule_id), None)


def compliance_controls() -> dict[str, list[str]]:
    """Map compliance control -> rule ids."""
    m: dict[str, list[str]] = {}
    for r in RULES:
        for c in r.compliance:
            m.setdefault(c, []).append(r.id)
    return m


# Provider rule packs register themselves into RULES on import (kept last: they
# use the helpers above).
from . import posture_aws, posture_gcp  # noqa: E402,F401
