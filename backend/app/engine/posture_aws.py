"""AWS posture rules (CIS AWS Foundations Benchmark v3.0, CIS EKS, AWS FSBP).

They evaluate the normalized properties produced by `app/connectors/aws.py`.
A property that could not be read (missing permission, failed API call) is
absent or None and never produces a finding.
"""
from __future__ import annotations

from .posture import _p, open_to_internet, rule

ADMIN_PORTS = (22, 3389)


def _admin_ports_open(a) -> dict | None:
    hits = {p: open_to_internet(a, p) for p in ADMIN_PORTS}
    hits = {p: h for p, h in hits.items() if h}
    allp = open_to_internet(a, None)
    if allp:
        hits["*"] = allp
    return hits or None


# --------------------------------------------------------------------------- IAM / account
@rule(
    id="AWS-IAM-001",
    title="Root user has no MFA",
    severity="critical",
    resource_type="aws_account",
    description="The account's root user can sign in with a password alone.",
    remediation="Sign in as root and enable a (hardware) MFA device: IAM > Security credentials > Assign MFA.",
    compliance=["CIS AWS 1.5"],
)
def _root_mfa(a):
    return {"root_mfa_enabled": False} if _p(a, "root_mfa_enabled") is False else None


@rule(
    id="AWS-IAM-002",
    title="Root user has active access keys",
    severity="critical",
    resource_type="aws_account",
    description="Programmatic access keys exist for the root user, which cannot be restricted by IAM policies.",
    remediation="Delete the root user's access keys (IAM > Security credentials as root); use IAM roles instead.",
    compliance=["CIS AWS 1.4"],
)
def _root_keys(a):
    return {"root_access_keys": True} if _p(a, "root_access_keys") else None


@rule(
    id="AWS-IAM-003",
    title="IAM password policy is missing or allows passwords shorter than 14 characters",
    severity="medium",
    resource_type="aws_account",
    description="The account password policy does not enforce a minimum length of 14.",
    remediation="aws iam update-account-password-policy --minimum-password-length 14 --password-reuse-prevention 24",
    compliance=["CIS AWS 1.8"],
)
def _pw_policy(a):
    props = a.get("properties") or {}
    if "password_policy" not in props:
        return None  # unknown
    pp = props["password_policy"]
    if pp is None:
        return {"password_policy": None}
    n = int(pp.get("minimum_length") or 0)
    return {"minimum_length": n} if n < 14 else None


@rule(
    id="AWS-IAM-004",
    title="IAM user with console password has no MFA",
    severity="high",
    resource_type="iam_user",
    description="The user can sign in to the AWS console without a second factor.",
    remediation="Enable MFA for the user (IAM > Users > Security credentials) and enforce it with an IAM policy.",
    compliance=["CIS AWS 1.10"],
)
def _user_mfa(a):
    if _p(a, "console_access") and _p(a, "mfa_active") is False:
        return {"console_access": True, "mfa_active": False}
    return None


@rule(
    id="AWS-IAM-005",
    title="IAM access key not rotated in 90 days",
    severity="medium",
    resource_type="iam_user",
    description="An active access key is older than 90 days.",
    remediation="Create a new key, switch the workload to it, then deactivate and delete the old key.",
    compliance=["CIS AWS 1.14"],
)
def _key_age(a):
    old = [k for k in _p(a, "access_keys", []) or [] if (k.get("age_days") or 0) > 90]
    return {"keys": [{"slot": k.get("slot"), "age_days": k.get("age_days")} for k in old]} if old else None


@rule(
    id="AWS-IAM-006",
    title="IAM user has full administrative (*:*) privileges",
    severity="high",
    resource_type="iam_user",
    description="AdministratorAccess or a policy allowing Action '*' on Resource '*' applies to this user.",
    remediation="Grant least-privilege permissions through groups / roles; keep admin access in break-glass roles.",
    compliance=["CIS AWS 1.16"],
)
def _user_admin(a):
    return {"admin_via": _p(a, "admin_via", [])} if _p(a, "admin") else None


@rule(
    id="AWS-IAM-007",
    title="IAM role has full administrative (*:*) privileges",
    severity="high",
    resource_type="iam_role",
    description="AdministratorAccess or a policy allowing Action '*' on Resource '*' is attached to this role; "
    "any workload or principal that can assume it controls the whole account.",
    remediation="Replace with a least-privilege policy scoped to what the workload needs.",
    compliance=["CIS AWS 1.16"],
)
def _role_admin(a):
    if not _p(a, "admin"):
        return None
    return {"admin_via": _p(a, "admin_via", []), "trusted_principals": _p(a, "trusted_principals", [])}


# --------------------------------------------------------------------------- S3
@rule(
    id="AWS-S3-001",
    title="S3 bucket is publicly accessible",
    severity="critical",
    resource_type="s3_bucket",
    description="The bucket policy or ACL grants access to everyone, and Block Public Access does not stop it.",
    remediation="Enable S3 Block Public Access on the bucket (and account) and remove public grants: "
    "aws s3api put-public-access-block --bucket <name> --public-access-block-configuration "
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
    compliance=["CIS AWS 2.1.4"],
)
def _s3_public(a):
    if not _p(a, "is_public"):
        return None
    return {"policy_public": _p(a, "policy_public"), "acl_public": _p(a, "acl_public")}


@rule(
    id="AWS-S3-002",
    title="S3 Block Public Access is not fully enabled",
    severity="medium",
    resource_type="s3_bucket",
    description="Not all four Block Public Access settings are on for this bucket (bucket or account level).",
    remediation="aws s3api put-public-access-block --bucket <name> --public-access-block-configuration "
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
    compliance=["CIS AWS 2.1.4"],
)
def _s3_pab(a):
    if _p(a, "public_access_block_enabled") is not False:
        return None
    return {"public_access_block": _p(a, "public_access_block")}


@rule(
    id="AWS-S3-003",
    title="S3 bucket policy does not deny HTTP (non-TLS) requests",
    severity="low",
    resource_type="s3_bucket",
    description="No bucket policy statement denies requests where aws:SecureTransport is false.",
    remediation="Add a Deny statement for s3:* with Condition Bool aws:SecureTransport=false.",
    compliance=["CIS AWS 2.1.1"],
)
def _s3_tls(a):
    return {"denies_insecure_transport": False} if _p(a, "denies_insecure_transport") is False else None


# --------------------------------------------------------------------------- EC2 / security groups
@rule(
    id="AWS-EC2-001",
    title="EC2 instance exposes SSH/RDP (or all ports) to the internet",
    severity="high",
    resource_type="ec2_instance",
    description="The instance has a public IP and an attached security group allows 0.0.0.0/0 or ::/0 "
    "to remote administration ports.",
    remediation="Remove the public IP or restrict the security group; use SSM Session Manager or a bastion.",
    compliance=["CIS AWS 5.2", "CIS AWS 5.3"],
)
def _ec2_admin(a):
    if not _p(a, "public_ip"):
        return None
    hits = _admin_ports_open(a)
    return {"public_ip": _p(a, "public_ip"), "open": {str(k): v for k, v in hits.items()}} if hits else None


@rule(
    id="AWS-EC2-002",
    title="EC2 instance allows IMDSv1",
    severity="medium",
    resource_type="ec2_instance",
    description="The instance metadata service accepts unauthenticated IMDSv1 requests (SSRF credential theft).",
    remediation="aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required",
    compliance=["CIS AWS 5.6"],
)
def _ec2_imds(a):
    return {"imdsv2_required": False} if _p(a, "imdsv2_required") is False else None


@rule(
    id="AWS-SG-001",
    title="Security group allows SSH (22) or RDP (3389) from the internet",
    severity="high",
    resource_type="security_group",
    description="An ingress rule allows 0.0.0.0/0 or ::/0 to a remote administration port.",
    remediation="Restrict the source to admin ranges or remove the rule; use SSM Session Manager.",
    compliance=["CIS AWS 5.2", "CIS AWS 5.3"],
)
def _sg_admin(a):
    hits = {p: open_to_internet(a, p) for p in ADMIN_PORTS}
    hits = {str(p): h for p, h in hits.items() if h}
    return {"rules": hits} if hits else None


@rule(
    id="AWS-SG-002",
    title="Security group allows all ports from the internet",
    severity="critical",
    resource_type="security_group",
    description="An ingress rule allows all traffic (or every port) from 0.0.0.0/0 or ::/0.",
    remediation="Remove the rule; allow only required ports from required sources.",
    compliance=["CIS AWS 5.2", "CIS AWS 5.3"],
)
def _sg_any(a):
    hits = open_to_internet(a, None)
    return {"rules": hits, "port": "*"} if hits else None


@rule(
    id="AWS-SG-003",
    title="Default security group allows traffic",
    severity="low",
    resource_type="security_group",
    description="The VPC's default security group has ingress rules; resources launched without a group get them.",
    remediation="Remove every inbound and outbound rule from the default security group.",
    compliance=["CIS AWS 5.4"],
)
def _sg_default(a):
    if _p(a, "is_default") and _p(a, "security_rules"):
        return {"ingress_rules": len(_p(a, "security_rules"))}
    return None


# --------------------------------------------------------------------------- RDS
@rule(
    id="AWS-RDS-001",
    title="RDS instance is publicly accessible",
    severity="high",
    resource_type="rds_instance",
    description="The database has a public endpoint (PubliclyAccessible=true).",
    remediation="aws rds modify-db-instance --db-instance-identifier <id> --no-publicly-accessible --apply-immediately",
    compliance=["CIS AWS 2.3.3"],
)
def _rds_public(a):
    return {"publicly_accessible": True} if _p(a, "publicly_accessible") else None


@rule(
    id="AWS-RDS-002",
    title="RDS instance storage is not encrypted",
    severity="medium",
    resource_type="rds_instance",
    description="Encryption at rest is disabled for the database storage, backups and snapshots.",
    remediation="Restore an encrypted copy (encrypt a snapshot copy with KMS, then restore) and switch over.",
    compliance=["CIS AWS 2.3.1"],
)
def _rds_enc(a):
    return {"storage_encrypted": False} if _p(a, "storage_encrypted") is False else None


@rule(
    id="AWS-RDS-003",
    title="RDS automated backups disabled or kept less than 7 days",
    severity="medium",
    resource_type="rds_instance",
    description="Point-in-time recovery is unavailable or too short.",
    remediation="aws rds modify-db-instance --db-instance-identifier <id> --backup-retention-period 7",
    compliance=["AWS FSBP RDS.11"],
)
def _rds_backup(a):
    days = _p(a, "backup_retention_days")
    return {"backup_retention_days": days} if days is not None and int(days) < 7 else None


# --------------------------------------------------------------------------- EKS
@rule(
    id="AWS-EKS-001",
    title="EKS API endpoint is public and unrestricted",
    severity="high",
    resource_type="eks_cluster",
    description="The Kubernetes API endpoint is reachable from any internet address.",
    remediation="Enable the private endpoint and disable public access, or restrict publicAccessCidrs.",
    compliance=["CIS EKS 5.4.2"],
)
def _eks_public(a):
    if not _p(a, "endpoint_public_access"):
        return None
    cidrs = _p(a, "public_access_cidrs") or []
    if cidrs and not any(c in {"0.0.0.0/0", "::/0"} for c in cidrs):
        return None
    return {"endpoint_public_access": True, "public_access_cidrs": cidrs}


@rule(
    id="AWS-EKS-002",
    title="EKS control plane audit logging is disabled",
    severity="medium",
    resource_type="eks_cluster",
    description="Kubernetes API audit logs are not sent to CloudWatch Logs.",
    remediation="aws eks update-cluster-config --name <name> --logging "
    "'{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\"],\"enabled\":true}]}'",
    compliance=["CIS EKS 2.1.1"],
)
def _eks_logs(a):
    return {"logging_enabled_types": _p(a, "logging_enabled_types", [])} if _p(a, "audit_logging") is False else None


# --------------------------------------------------------------------------- KMS / CloudTrail / Lambda
@rule(
    id="AWS-KMS-001",
    title="KMS customer managed key rotation is disabled",
    severity="medium",
    resource_type="kms_key",
    description="Automatic yearly rotation is off for a symmetric customer managed key.",
    remediation="aws kms enable-key-rotation --key-id <key-id>",
    compliance=["CIS AWS 3.6"],
)
def _kms_rot(a):
    return {"rotation_enabled": False} if _p(a, "rotation_enabled") is False else None


@rule(
    id="AWS-CT-001",
    title="No multi-region CloudTrail trail is logging",
    severity="high",
    resource_type="aws_account",
    description="API activity in some regions is not recorded by an active multi-region trail.",
    remediation="aws cloudtrail create-trail --name org-trail --s3-bucket-name <bucket> --is-multi-region-trail "
    "--enable-log-file-validation && aws cloudtrail start-logging --name org-trail",
    compliance=["CIS AWS 3.1"],
)
def _ct_multi(a):
    v = _p(a, "cloudtrail_multi_region_logging")
    return {"cloudtrail_multi_region_logging": False} if v is False else None


@rule(
    id="AWS-CT-002",
    title="CloudTrail log file validation is disabled",
    severity="medium",
    resource_type="cloudtrail_trail",
    description="Tampering with delivered log files cannot be detected.",
    remediation="aws cloudtrail update-trail --name <trail> --enable-log-file-validation",
    compliance=["CIS AWS 3.2"],
)
def _ct_validation(a):
    return {"log_file_validation": False} if _p(a, "log_file_validation") is False else None


@rule(
    id="AWS-LMB-001",
    title="Lambda function URL allows unauthenticated access",
    severity="high",
    resource_type="lambda_function",
    description="The function has a public function URL with AuthType NONE.",
    remediation="Set the function URL AuthType to AWS_IAM, or front it with API Gateway + an authorizer.",
    compliance=["AWS FSBP Lambda.1"],
)
def _lambda_url(a):
    return {"function_url": _p(a, "function_url"), "auth_type": "NONE"} if _p(a, "public_url") else None
