"""GCP posture rules (CIS Google Cloud Platform Foundation Benchmark v3.0, CIS GKE).

They evaluate the normalized properties produced by `app/connectors/gcp.py`.
A property that could not be read is absent or None and never produces a finding.
"""
from __future__ import annotations

from .posture import _p, open_to_internet, rule


# --------------------------------------------------------------------------- IAM
@rule(
    id="GCP-IAM-001",
    title="Service account has admin privileges",
    severity="high",
    resource_type="gcp_service_account",
    description="The service account holds Owner, Editor or an *Admin role on the project.",
    remediation="Replace the binding with narrowly scoped predefined roles: "
    "gcloud projects remove-iam-policy-binding <project> --member serviceAccount:<email> --role <role>",
    compliance=["CIS GCP 1.5"],
)
def _sa_admin(a):
    roles = _p(a, "admin_roles") or []
    return {"admin_roles": roles} if roles else None


@rule(
    id="GCP-IAM-002",
    title="Service account key not rotated in 90 days",
    severity="medium",
    resource_type="gcp_service_account",
    description="A user-managed service account key is older than 90 days.",
    remediation="Create a new key, roll it out, then delete the old one "
    "(gcloud iam service-accounts keys delete <key-id> --iam-account <email>); prefer keyless auth.",
    compliance=["CIS GCP 1.7"],
)
def _sa_key_age(a):
    old = [k for k in _p(a, "user_managed_keys", []) or [] if (k.get("age_days") or 0) > 90]
    return {"keys": old} if old else None


@rule(
    id="GCP-IAM-003",
    title="Project IAM grants a role to allUsers / allAuthenticatedUsers",
    severity="critical",
    resource_type="gcp_project",
    description="Anyone on the internet (or any Google account) holds a role on the project.",
    remediation="Remove the allUsers / allAuthenticatedUsers members from the project IAM policy.",
    compliance=["CIS GCP 1.x"],
)
def _proj_public(a):
    pub = _p(a, "public_bindings") or []
    return {"public_bindings": pub} if pub else None


@rule(
    id="GCP-IAM-004",
    title="Users can impersonate service accounts project-wide",
    severity="medium",
    resource_type="gcp_project",
    description="Users or groups hold Service Account User / Token Creator at project level, so they can act as "
    "every service account in the project.",
    remediation="Grant these roles on individual service accounts instead of the project.",
    compliance=["CIS GCP 1.6"],
)
def _proj_sa_user(a):
    b = _p(a, "sa_impersonation_bindings") or []
    return {"bindings": b} if b else None


@rule(
    id="GCP-IAM-005",
    title="Too many basic Owner role holders",
    severity="medium",
    resource_type="gcp_project",
    description="More than 3 principals hold the basic (primitive) Owner role on the project.",
    remediation="Reduce Owner bindings; use predefined roles and just-in-time elevation.",
    compliance=["CIS GCP 1.x"],
)
def _proj_owners(a):
    owners = _p(a, "owners") or []
    return {"owner_count": len(owners), "owners": owners} if len(owners) > 3 else None


# --------------------------------------------------------------------------- firewall
@rule(
    id="GCP-FW-001",
    title="Firewall rule allows SSH (22) from the internet",
    severity="high",
    resource_type="gcp_firewall_rule",
    description="An enabled ingress allow rule exposes TCP/22 to 0.0.0.0/0.",
    remediation="Restrict sourceRanges to admin ranges or use IAP TCP forwarding (35.235.240.0/20).",
    compliance=["CIS GCP 3.6"],
)
def _fw_ssh(a):
    hits = open_to_internet(a, 22)
    return {"rules": hits, "port": 22} if hits else None


@rule(
    id="GCP-FW-002",
    title="Firewall rule allows RDP (3389) from the internet",
    severity="high",
    resource_type="gcp_firewall_rule",
    description="An enabled ingress allow rule exposes TCP/3389 to 0.0.0.0/0.",
    remediation="Restrict sourceRanges to admin ranges or use IAP TCP forwarding.",
    compliance=["CIS GCP 3.7"],
)
def _fw_rdp(a):
    hits = open_to_internet(a, 3389)
    return {"rules": hits, "port": 3389} if hits else None


@rule(
    id="GCP-FW-003",
    title="Firewall rule allows all ports from the internet",
    severity="critical",
    resource_type="gcp_firewall_rule",
    description="An enabled ingress allow rule exposes every port to 0.0.0.0/0.",
    remediation="Delete the rule; allow only required ports from required sources.",
    compliance=["CIS GCP 3.6", "CIS GCP 3.7"],
)
def _fw_any(a):
    hits = open_to_internet(a, None)
    return {"rules": hits, "port": "*"} if hits else None


# --------------------------------------------------------------------------- compute
@rule(
    id="GCP-GCE-001",
    title="Compute instance has an external IP address",
    severity="medium",
    resource_type="gce_instance",
    description="The VM is directly reachable from the internet via an external IP.",
    remediation="Remove the access config and use Cloud NAT for egress and IAP / a load balancer for ingress.",
    compliance=["CIS GCP 4.9"],
)
def _gce_ip(a):
    ips = _p(a, "external_ips") or []
    return {"external_ips": ips} if ips else None


@rule(
    id="GCP-GCE-002",
    title="Instance uses the default service account with full API access",
    severity="high",
    resource_type="gce_instance",
    description="The default Compute Engine service account (Editor by default) with the cloud-platform scope "
    "gives code on the VM broad access to the project.",
    remediation="Attach a dedicated least-privilege service account and limit access scopes.",
    compliance=["CIS GCP 4.2"],
)
def _gce_default_sa(a):
    if _p(a, "default_service_account") and _p(a, "full_api_access"):
        return {"service_account": _p(a, "service_account"), "scopes": _p(a, "scopes")}
    return None


# --------------------------------------------------------------------------- storage
@rule(
    id="GCP-GCS-001",
    title="Cloud Storage bucket is publicly accessible",
    severity="critical",
    resource_type="gcs_bucket",
    description="The bucket IAM policy grants a role to allUsers or allAuthenticatedUsers.",
    remediation="Remove the public members and enforce public access prevention: "
    "gcloud storage buckets update gs://<bucket> --public-access-prevention",
    compliance=["CIS GCP 5.1"],
)
def _gcs_public(a):
    m = _p(a, "public_members") or []
    return {"public_members": m} if m else None


@rule(
    id="GCP-GCS-002",
    title="Cloud Storage bucket does not use uniform bucket-level access",
    severity="medium",
    resource_type="gcs_bucket",
    description="Object ACLs can grant access independently of bucket IAM.",
    remediation="gcloud storage buckets update gs://<bucket> --uniform-bucket-level-access",
    compliance=["CIS GCP 5.2"],
)
def _gcs_uniform(a):
    return {"uniform_access": False} if _p(a, "uniform_access") is False else None


# --------------------------------------------------------------------------- GKE
@rule(
    id="GCP-GKE-001",
    title="GKE legacy authorization (ABAC) is enabled",
    severity="high",
    resource_type="gke_cluster",
    description="Legacy ABAC grants broad, static permissions that bypass Kubernetes RBAC.",
    remediation="gcloud container clusters update <name> --no-enable-legacy-authorization",
    compliance=["CIS GKE 5.8.4"],
)
def _gke_abac(a):
    return {"legacy_abac": True} if _p(a, "legacy_abac") else None


@rule(
    id="GCP-GKE-002",
    title="GKE control plane is public without authorized networks",
    severity="high",
    resource_type="gke_cluster",
    description="The Kubernetes API endpoint is reachable from any internet address.",
    remediation="Enable control plane authorized networks or the private endpoint: "
    "gcloud container clusters update <name> --enable-master-authorized-networks --master-authorized-networks <cidr>",
    compliance=["CIS GKE 5.6.3"],
)
def _gke_public(a):
    if _p(a, "private_endpoint") is not False:  # private, or unknown
        return None
    cidrs = _p(a, "authorized_cidrs") or []
    if _p(a, "master_authorized_networks") and not any(c in {"0.0.0.0/0", "::/0"} for c in cidrs):
        return None
    return {"private_endpoint": False, "master_authorized_networks": bool(_p(a, "master_authorized_networks")),
            "authorized_cidrs": cidrs}


@rule(
    id="GCP-GKE-003",
    title="GKE nodes have public IP addresses",
    severity="medium",
    resource_type="gke_cluster",
    description="Private nodes are not enabled, so every node gets an external IP.",
    remediation="Create node pools in a private cluster (--enable-private-nodes) and use Cloud NAT for egress.",
    compliance=["CIS GKE 5.6.5"],
)
def _gke_nodes(a):
    return {"private_nodes": False} if _p(a, "private_nodes") is False else None


@rule(
    id="GCP-GKE-004",
    title="GKE Workload Identity is disabled",
    severity="medium",
    resource_type="gke_cluster",
    description="Pods use the node's service account (metadata server) instead of per-workload identities.",
    remediation="gcloud container clusters update <name> --workload-pool=<project>.svc.id.goog",
    compliance=["CIS GKE 5.2.2"],
)
def _gke_wi(a):
    return {"workload_identity": False} if _p(a, "workload_identity") is False else None


# --------------------------------------------------------------------------- Cloud SQL
@rule(
    id="GCP-SQL-001",
    title="Cloud SQL instance allows connections from 0.0.0.0/0",
    severity="critical",
    resource_type="cloud_sql_instance",
    description="An authorized network opens the public IP to the whole internet.",
    remediation="Remove the 0.0.0.0/0 authorized network; use private IP or the Cloud SQL Auth Proxy.",
    compliance=["CIS GCP 6.5"],
)
def _sql_all(a):
    return {"authorized_networks": _p(a, "authorized_networks")} if _p(a, "public_ip") and _p(a, "open_to_all") else None


@rule(
    id="GCP-SQL-002",
    title="Cloud SQL instance has a public IP address",
    severity="medium",
    resource_type="cloud_sql_instance",
    description="The instance is assigned a public IPv4 address.",
    remediation="gcloud sql instances patch <name> --no-assign-ip (configure private IP first).",
    compliance=["CIS GCP 6.6"],
)
def _sql_public(a):
    return {"public_ip": True} if _p(a, "public_ip") else None


@rule(
    id="GCP-SQL-003",
    title="Cloud SQL instance does not require SSL/TLS",
    severity="medium",
    resource_type="cloud_sql_instance",
    description="Unencrypted client connections are accepted.",
    remediation="gcloud sql instances patch <name> --ssl-mode=ENCRYPTED_ONLY",
    compliance=["CIS GCP 6.4"],
)
def _sql_ssl(a):
    return {"ssl_required": False, "ssl_mode": _p(a, "ssl_mode")} if _p(a, "ssl_required") is False else None


@rule(
    id="GCP-SQL-004",
    title="Cloud SQL automated backups are disabled",
    severity="medium",
    resource_type="cloud_sql_instance",
    description="No automated daily backups are taken.",
    remediation="gcloud sql instances patch <name> --backup-start-time=03:00",
    compliance=["CIS GCP 6.7"],
)
def _sql_backup(a):
    return {"backups_enabled": False} if _p(a, "backups_enabled") is False else None


# --------------------------------------------------------------------------- KMS / serverless
@rule(
    id="GCP-KMS-001",
    title="Cloud KMS key is not rotated at least every 90 days",
    severity="medium",
    resource_type="gcp_kms_key",
    description="The symmetric encryption key has no rotation period, or one longer than 90 days.",
    remediation="gcloud kms keys update <key> --keyring <ring> --location <loc> --rotation-period 90d "
    "--next-rotation-time <time>",
    compliance=["CIS GCP 1.10"],
)
def _kms_rot(a):
    if _p(a, "purpose") != "ENCRYPT_DECRYPT":
        return None
    days = _p(a, "rotation_period_days")
    return {"rotation_period_days": days} if days is None or days > 90 else None


@rule(
    id="GCP-RUN-001",
    title="Cloud Run service allows unauthenticated invocations from the internet",
    severity="high",
    resource_type="cloud_run_service",
    description="allUsers / allAuthenticatedUsers hold the invoker role and ingress is open to all traffic.",
    remediation="Remove the allUsers invoker binding (or restrict ingress to internal / load balancer) "
    "unless the service is intentionally public.",
    compliance=["CIS GCP 1.x"],
)
def _run_public(a):
    if _p(a, "public_invoker") and _p(a, "ingress", "INGRESS_TRAFFIC_ALL") == "INGRESS_TRAFFIC_ALL":
        return {"public_invoker": _p(a, "public_invoker"), "ingress": _p(a, "ingress")}
    return None


@rule(
    id="GCP-FN-001",
    title="Cloud Function allows unauthenticated invocations from the internet",
    severity="high",
    resource_type="cloud_function",
    description="allUsers / allAuthenticatedUsers can invoke the function and ingress allows all traffic.",
    remediation="Remove the allUsers invoker binding or set ingress to internal-only, unless intentionally public.",
    compliance=["CIS GCP 1.x"],
)
def _fn_public(a):
    return {"public_invoker": _p(a, "public_invoker"), "ingress": _p(a, "ingress")} \
        if _p(a, "allows_unauthenticated") else None
