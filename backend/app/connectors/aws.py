"""Real AWS posture connector (opt-in, READ-ONLY).

Uses boto3 to inventory one or more AWS accounts (optionally by assuming a
read-only role in each) and normalizes the resources into `AssetRecord`s the
posture rules engine and attack-path analysis understand (`source="aws"`).

Safety: every boto3 client is wrapped in `ReadOnlyAwsClient`, which only lets
`describe_*` / `list_*` / `get_*` operations (and the single extra read call
`generate_credential_report`) through, blocks the few read-looking calls that
return data or secrets (S3 objects, Lambda code, SSM parameters, Secrets
Manager values, EC2 password data...) and raises `ReadOnlyViolation` on
anything else. The IAM principal should additionally only hold the AWS managed
policies **SecurityAudit** and **ViewOnlyAccess** (docs/CONNECT_AWS.md).

Throttling is handled by botocore's adaptive retry mode; every list call is
paginated; a failing account, region or service is recorded in
`CollectionResult.errors` and the rest of the scan continues.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import time
import urllib.parse
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

from ..config import Settings
from .base import AssetRecord, CollectionResult, Connector, RelationshipRecord, ScopeAccessError, sensitive_from_tags

log = logging.getLogger(__name__)

READ_PREFIXES = ("describe_", "list_", "get_")
# iam:GenerateCredentialReport only (re)builds the account's credential report
# server-side; it is part of the SecurityAudit policy and changes no resource.
EXTRA_READ_OPERATIONS = {"generate_credential_report"}
# Read-looking operations a posture scanner never needs: they return customer
# data, code or secrets.
BLOCKED_OPERATIONS = {
    "get_object", "get_object_acl", "get_object_attributes", "get_object_torrent", "get_object_retention",
    "get_function", "get_layer_version", "get_password_data", "get_console_output", "get_console_screenshot",
    "get_parameter", "get_parameters", "get_parameters_by_path", "get_parameter_history", "get_waiter",
    "get_query_results", "get_export", "get_sdk", "get_template", "get_launch_template_data",
}
SECRET_MARKERS = ("secret", "password", "token", "credentials", "session", "decrypt", "plaintext", "private_key",
                  "presigned", "download")
# Reads whose names contain a marker but return only settings, never a secret.
MARKER_FALSE_POSITIVES = {"get_account_password_policy"}

ADMIN_POLICY_NAMES = {"AdministratorAccess"}
# AWS managed policies that reach data in S3 / RDS (for has_access edges).
S3_DATA_POLICIES = {"AdministratorAccess", "PowerUserAccess", "AmazonS3FullAccess", "AmazonS3ReadOnlyAccess",
                    "ReadOnlyAccess"}
RDS_DATA_POLICIES = {"AdministratorAccess", "PowerUserAccess", "AmazonRDSFullAccess", "AmazonRDSDataFullAccess"}
INLINE_ADMIN = "*:* (customer/inline policy)"
PUBLIC_ACL_GROUPS = ("http://acs.amazonaws.com/groups/global/AllUsers",
                     "http://acs.amazonaws.com/groups/global/AuthenticatedUsers")


class ReadOnlyViolation(PermissionError):
    pass


def check_operation(service: str, op: str) -> None:
    """Raise `ReadOnlyViolation` unless `op` (a boto3 method name) is a permitted read."""
    if op in BLOCKED_OPERATIONS or (not op.startswith(READ_PREFIXES) and op not in EXTRA_READ_OPERATIONS):
        raise ReadOnlyViolation(f"Blocked non read-only AWS call: {service}.{op}")
    if op not in MARKER_FALSE_POSITIVES and any(m in op for m in SECRET_MARKERS):
        raise ReadOnlyViolation(f"Blocked secret-returning AWS call: {service}.{op}")


class ReadOnlyAwsClient:
    """Proxy around a boto3 client allowing only read operations (and paginators over them)."""

    def __init__(self, client: Any, service: str):
        self._client = client
        self._service = service

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(f"private AWS client attribute not exposed: {self._service}.{name}")
        if name == "exceptions":
            return self._client.exceptions
        if name == "can_paginate":
            return self._client.can_paginate
        if name == "get_paginator":
            return self._get_paginator
        if name == "meta":  # meta.client / meta.events are escape hatches around the guard
            raise ReadOnlyViolation(f"Blocked raw AWS client access: {self._service}.meta")
        check_operation(self._service, name)
        return getattr(self._client, name)

    def _get_paginator(self, op: str) -> Any:
        check_operation(self._service, op)
        return self._client.get_paginator(op)


def boto_config() -> Any:
    from botocore.config import Config

    return Config(retries={"mode": "adaptive", "max_attempts": 10}, connect_timeout=10, read_timeout=60,
                  user_agent_extra="cloudsecurity-cnapp-readonly")


AUTH_MODES = ("auto", "access_key", "default")


def resolve_auth_mode(settings: Settings) -> str | None:
    """Which credential the scanner uses, or None if none is configured.

    auto: the access key if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set,
    else boto3's default credential chain if AWS_USE_DEFAULT_CREDENTIALS=true.
    """
    s = settings
    mode = s.aws_auth_mode if s.aws_auth_mode in AUTH_MODES else "auto"
    has_key = bool(s.aws_access_key_id and s.aws_secret_access_key)
    if mode == "access_key":
        return mode if has_key else None
    if mode == "default":
        return mode
    if has_key:
        return "access_key"
    if s.aws_use_default_credentials:
        return "default"
    return None


def build_base_session(settings: Settings) -> Any:
    import boto3

    mode = resolve_auth_mode(settings)
    if mode == "access_key":
        return boto3.Session(aws_access_key_id=settings.aws_access_key_id,
                             aws_secret_access_key=settings.aws_secret_access_key,
                             region_name=settings.aws_home_region)
    if mode == "default":
        return boto3.Session(region_name=settings.aws_home_region)
    raise RuntimeError("AWS connector is not configured: set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY "
                       "or AWS_USE_DEFAULT_CREDENTIALS=true")


def assume_role_session(base: Any, role_arn: str, external_id: str | None, region: str) -> Any:
    """boto3 session for `role_arn` whose credentials refresh themselves (long scans)."""
    import boto3
    from botocore.credentials import RefreshableCredentials
    from botocore.session import get_session

    # sts:AssumeRole is authentication (like fetching an Azure token), not a
    # resource operation, so it uses a plain STS client outside the guard.
    sts = base.client("sts", region_name=region, config=boto_config())

    def refresh() -> dict:
        kw: dict[str, Any] = {"RoleArn": role_arn, "RoleSessionName": "cnapp-readonly-scan", "DurationSeconds": 3600}
        if external_id:
            kw["ExternalId"] = external_id
        c = sts.assume_role(**kw)["Credentials"]
        return {"access_key": c["AccessKeyId"], "secret_key": c["SecretAccessKey"], "token": c["SessionToken"],
                "expiry_time": c["Expiration"].isoformat()}

    creds = RefreshableCredentials.create_from_metadata(metadata=refresh(), refresh_using=refresh,
                                                        method="sts-assume-role")
    bs = get_session()
    bs._credentials = creds  # documented pattern for refreshable assumed-role sessions
    return boto3.Session(botocore_session=bs, region_name=region)


class AwsClients:
    """Read-only-wrapped boto3 clients for one account, cached per (service, region)."""

    def __init__(self, session: Any):
        self.session = session
        self._cache: dict[tuple[str, str], ReadOnlyAwsClient] = {}
        self._config = boto_config()

    def __call__(self, service: str, region: str) -> ReadOnlyAwsClient:
        key = (service, region)
        if key not in self._cache:
            self._cache[key] = ReadOnlyAwsClient(
                self.session.client(service, region_name=region, config=self._config), service)
        return self._cache[key]


# ----------------------------------------------------------------------------- helpers
def _error_code(exc: Exception) -> str:
    return str(getattr(exc, "response", {}).get("Error", {}).get("Code", "")) if hasattr(exc, "response") else ""


def _opt(fn: Callable[[], Any], *codes: str) -> Any:
    """Call fn; return None if it fails with one of the given AWS error codes ("not configured")."""
    try:
        return fn()
    except ReadOnlyViolation:
        raise
    except Exception as exc:
        if _error_code(exc) in codes:
            return None
        raise


def _paginate(client: ReadOnlyAwsClient, op: str, key: str, **kw) -> Iterable[dict]:
    for page in client.get_paginator(op).paginate(**kw):
        yield from page.get(key, []) or []


def _tags(tag_list: Iterable[dict] | None) -> dict[str, str]:
    return {str(t.get("Key")): str(t.get("Value", "")) for t in (tag_list or []) if t.get("Key") is not None}


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, list | tuple) else [v]


def _policy_doc(doc: Any) -> dict:
    """IAM policy documents arrive as dicts (boto3 decodes them) or URL-encoded JSON strings."""
    if isinstance(doc, dict):
        return doc
    if not doc:
        return {}
    try:
        return json.loads(urllib.parse.unquote(str(doc)))
    except ValueError:
        return {}


def is_admin_policy(doc: Any) -> bool:
    """CIS AWS 1.16: an Allow statement with Action "*" on Resource "*" (no condition)."""
    for st in _as_list(_policy_doc(doc).get("Statement")):
        if not isinstance(st, dict) or st.get("Effect") != "Allow" or st.get("Condition"):
            continue
        actions = [str(a) for a in _as_list(st.get("Action"))]
        resources = [str(r) for r in _as_list(st.get("Resource"))]
        if any(a in {"*", "*:*"} for a in actions) and "*" in resources:
            return True
    return False


def denies_insecure_transport(doc: Any) -> bool:
    """CIS AWS 2.1.1: the bucket policy denies requests where aws:SecureTransport is false."""
    for st in _as_list(_policy_doc(doc).get("Statement")):
        if not isinstance(st, dict) or st.get("Effect") != "Deny":
            continue
        for op, cond in (st.get("Condition") or {}).items():
            if op.lower() != "bool" or not isinstance(cond, dict):
                continue
            for k, v in cond.items():
                if k.lower() == "aws:securetransport" and str(_as_list(v)[0]).lower() == "false":
                    return True
    return False


def sg_rules(group_id: str, permissions: Iterable[dict]) -> list[dict]:
    """Security group ingress -> the normalized rule shape `posture.open_to_internet` understands."""
    out = []
    for i, p in enumerate(permissions or []):
        proto = str(p.get("IpProtocol", "-1")).lower()
        fp, tp = p.get("FromPort"), p.get("ToPort")
        if proto in {"-1", "all"}:
            ports = ["*"]
        elif proto in {"tcp", "udp", "6", "17"}:
            if fp in (None, -1) or (fp == 0 and tp in (None, 65535, -1)):
                ports = ["*"]
            else:
                ports = [str(fp) if fp == tp else f"{fp}-{tp}"]
        else:  # icmp & co: no ports
            ports = ["none"]
        sources = [r.get("CidrIp", "") for r in p.get("IpRanges", []) or []]
        sources += [r.get("CidrIpv6", "") for r in p.get("Ipv6Ranges", []) or []]
        sources += [f"sg:{g.get('GroupId', '')}" for g in p.get("UserIdGroupPairs", []) or []]
        sources += [f"pl:{x.get('PrefixListId', '')}" for x in p.get("PrefixListIds", []) or []]
        out.append({"name": f"{group_id}#{i} {('all' if proto == '-1' else proto)}/{ports[0]}",
                    "direction": "Inbound", "access": "Allow", "protocol": proto,
                    "source_prefixes": sources, "port_ranges": ports})
    return out


INTERNET = {"0.0.0.0/0", "::/0"}


def internet_rules(rules: Iterable[dict]) -> list[str]:
    return [r["name"] for r in rules if any(s in INTERNET for s in r.get("source_prefixes", []))
            and r.get("port_ranges") != ["none"]]


def _age_days(ts: str | None, now: datetime) -> int | None:
    if not ts or ts in {"N/A", "not_supported", "no_information"}:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return max(0, (now - dt).days)


class AwsConnector(Connector):
    name = "aws"
    provider = "aws"
    description = "Read-only AWS posture scan via boto3 (SecurityAudit + ViewOnlyAccess)."
    setup_hint = ("set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY of a dedicated read-only IAM user (or "
                  "AWS_USE_DEFAULT_CREDENTIALS=true), optionally AWS_ROLE_ARNS + AWS_EXTERNAL_ID for other "
                  "accounts; see docs/CONNECT_AWS.md")

    def __init__(self, settings: Settings, session_factory: Callable[[], Any] | None = None,
                 sleep: Callable[[float], None] = time.sleep, now: Callable[[], datetime] | None = None):
        self.settings = settings
        self._session_factory = session_factory
        self._sleep = sleep
        self._now = now or (lambda: datetime.now(UTC))

    def is_configured(self) -> bool:
        return resolve_auth_mode(self.settings) is not None or self._session_factory is not None

    def scope(self) -> list[str]:
        if self.settings.aws_role_arns:
            return [a.split(":")[4] for a in self.settings.aws_role_arns if a.count(":") >= 5]
        return ["(account of the credentials)"] if self.is_configured() else []

    def info(self) -> dict:
        s = self.settings
        return {**super().info(), "auth_mode": resolve_auth_mode(s),
                "regions": list(s.aws_regions) or ["all enabled"]}

    def check_access(self, max_scopes: int = 10) -> list[dict[str, str]]:
        """Connection test per account: sts:GetCallerIdentity (the key works) and
        iam:ListAccountAliases (SecurityAudit is attached)."""
        from botocore.config import Config

        cfg = Config(retries={"mode": "standard", "max_attempts": 2}, connect_timeout=5, read_timeout=10,
                     user_agent_extra="cloudsecurity-cnapp-readonly")
        home = self.settings.aws_home_region
        try:
            base = self._session_factory() if self._session_factory else build_base_session(self.settings)
        except Exception as exc:
            raise ScopeAccessError("credentials", exc) from exc
        targets: list[tuple[str, Callable[[], Any]]] = [
            (arn, lambda arn=arn: assume_role_session(base, arn, self.settings.aws_external_id, home))
            for arn in self.settings.aws_role_arns[:max_scopes]] or [("credentials", lambda: base)]
        reached = []
        for label, make_session in targets:
            try:
                session = make_session()
                ident = ReadOnlyAwsClient(session.client("sts", region_name=home, config=cfg), "sts").get_caller_identity()
                aliases = ReadOnlyAwsClient(session.client("iam", region_name=home, config=cfg),
                                            "iam").list_account_aliases(MaxItems=1).get("AccountAliases") or []
            except ReadOnlyViolation:
                raise
            except Exception as exc:
                raise ScopeAccessError(label, exc) from exc
            reached.append({"id": str(ident["Account"]), "name": aliases[0] if aliases else str(ident["Account"])})
        return reached

    # ------------------------------------------------------------------ main entry
    def collect(self) -> CollectionResult:
        res = CollectionResult()
        try:
            base = self._session_factory() if self._session_factory else build_base_session(self.settings)
        except Exception as exc:
            res.errors.append(f"credentials: {type(exc).__name__}: {exc}")
            return res
        home = self.settings.aws_home_region
        targets: list[tuple[str, Callable[[], Any]]]
        if self.settings.aws_role_arns:
            targets = [(arn, lambda arn=arn: assume_role_session(base, arn, self.settings.aws_external_id, home))
                       for arn in self.settings.aws_role_arns]
        else:
            targets = [("default account", lambda: base)]
        for label, make_session in targets:
            try:
                self._collect_account(AwsClients(make_session()), res)
            except ReadOnlyViolation:
                raise
            except Exception as exc:  # keep scanning the other accounts
                log.warning("AWS scan failed for %s: %s", label, exc)
                res.errors.append(f"{label}: {type(exc).__name__}: {exc}")
        return res

    def _step(self, res: CollectionResult, label: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except ReadOnlyViolation:
            raise
        except Exception as exc:
            log.warning("AWS %s failed: %s", label, exc)
            res.errors.append(f"{label}: {type(exc).__name__}: {exc}")

    def _collect_account(self, c: AwsClients, res: CollectionResult) -> None:  # noqa: C901 - one flow per service
        home = self.settings.aws_home_region
        ident = c("sts", home).get_caller_identity()
        acct = ident["Account"]
        part = str(ident.get("Arn", "arn:aws:")).split(":")[1] or "aws"
        now = self._now()
        assets: dict[str, AssetRecord] = {}
        rels: list[RelationshipRecord] = []

        def add(a: AssetRecord) -> AssetRecord:
            assets[a.id] = a
            return a

        alias = None
        try:
            alias = next(iter(c("iam", home).list_account_aliases().get("AccountAliases") or []), None)
        except ReadOnlyViolation:
            raise
        except Exception as exc:  # noqa: BLE001 - cosmetic only
            log.debug("account alias unavailable: %s", exc)
        base = dict(provider="aws", subscription_id=acct, subscription_name=alias or acct)
        account = add(AssetRecord(id=f"aws:account:{acct}", name=alias or acct, type="aws_account",
                                  region="global", **base,
                                  properties={"account_id": acct, "partition": part, "alias": alias}))

        # ----------------------------------------------------------- IAM
        profile_to_role: dict[str, str] = {}
        identities: list[AssetRecord] = []
        users_by_name: dict[str, AssetRecord] = {}

        def principal_props(attached: list[dict], inline_docs: list[Any], extra_docs: list[Any]) -> dict:
            names = sorted({p.get("PolicyName", "") for p in attached})
            admin_via = [n for n in names if n in ADMIN_POLICY_NAMES]
            if any(is_admin_policy(d) for d in inline_docs + extra_docs):
                admin_via.append(INLINE_ADMIN)
            roles = names + ([INLINE_ADMIN] if INLINE_ADMIN in admin_via else [])
            return {"policies": names, "roles": roles, "admin": bool(admin_via), "admin_via": admin_via,
                    "scope": "account" if admin_via else "resource",
                    "s3_access": bool(admin_via) or bool(set(names) & S3_DATA_POLICIES),
                    "rds_access": bool(admin_via) or bool(set(names) & RDS_DATA_POLICIES)}

        def iam():
            cl = c("iam", home)
            summary = cl.get_account_summary().get("SummaryMap", {})
            account.properties["root_mfa_enabled"] = bool(summary.get("AccountMFAEnabled"))
            account.properties["root_access_keys"] = bool(summary.get("AccountAccessKeysPresent"))
            pp = _opt(lambda: cl.get_account_password_policy()["PasswordPolicy"], "NoSuchEntity")
            account.properties["password_policy"] = (
                {"minimum_length": pp.get("MinimumPasswordLength"), "reuse_prevention": pp.get("PasswordReusePrevention")}
                if pp else None)
            local_docs: dict[str, Any] = {}
            groups: dict[str, dict] = {}
            users: list[dict] = []
            roles: list[dict] = []
            for page in cl.get_paginator("get_account_authorization_details").paginate(
                    Filter=["User", "Role", "Group", "LocalManagedPolicy"]):
                users += page.get("UserDetailList", [])
                roles += page.get("RoleDetailList", [])
                for g in page.get("GroupDetailList", []):
                    groups[g["GroupName"]] = g
                for p in page.get("Policies", []):
                    for v in p.get("PolicyVersionList", []):
                        if v.get("IsDefaultVersion"):
                            local_docs[p["Arn"]] = v.get("Document")
            for r in roles:
                if str(r.get("Path", "")).startswith("/aws-service-role/"):
                    continue  # service-linked roles are owned and scoped by AWS
                attached = r.get("AttachedManagedPolicies", [])
                inline = [p.get("PolicyDocument") for p in r.get("RolePolicyList", [])]
                props = principal_props(attached, inline, [local_docs.get(p["PolicyArn"]) for p in attached])
                trust = _policy_doc(r.get("AssumeRolePolicyDocument"))
                principals = []
                for st in _as_list(trust.get("Statement")):
                    pr = st.get("Principal") if isinstance(st, dict) else None
                    if isinstance(pr, dict):
                        for v in pr.values():
                            principals += [str(x) for x in _as_list(v)]
                    elif pr:
                        principals.append(str(pr))
                for ip in r.get("InstanceProfileList", []):
                    profile_to_role[ip["Arn"]] = r["Arn"]
                identities.append(add(AssetRecord(
                    id=r["Arn"], name=r["RoleName"], type="iam_role", region="global", **base,
                    tags=_tags(r.get("Tags")),
                    properties={**props, "principal_type": "Role", "path": r.get("Path"),
                                "trusted_principals": sorted(set(principals)),
                                "last_used": str((r.get("RoleLastUsed") or {}).get("LastUsedDate") or "") or None})))
            for u in users:
                attached = list(u.get("AttachedManagedPolicies", []))
                inline = [p.get("PolicyDocument") for p in u.get("UserPolicyList", [])]
                for gname in u.get("GroupList", []):
                    g = groups.get(gname, {})
                    attached += g.get("AttachedManagedPolicies", [])
                    inline += [p.get("PolicyDocument") for p in g.get("GroupPolicyList", [])]
                props = principal_props(attached, inline, [local_docs.get(p["PolicyArn"]) for p in attached])
                direct = bool(u.get("AttachedManagedPolicies") or u.get("UserPolicyList"))
                users_by_name[u["UserName"]] = add(AssetRecord(
                    id=u["Arn"], name=u["UserName"], type="iam_user", region="global", **base,
                    tags=_tags(u.get("Tags")),
                    properties={**props, "principal_type": "User", "groups": list(u.get("GroupList", [])),
                                "direct_policies": direct, "console_access": None, "mfa_active": None,
                                "access_keys": []}))
                identities.append(users_by_name[u["UserName"]])

        self._step(res, f"{acct}/iam", iam)

        def credential_report():
            cl = c("iam", home)
            for _ in range(15):
                if cl.generate_credential_report().get("State") == "COMPLETE":
                    break
                self._sleep(2)
            content = cl.get_credential_report()["Content"]
            text = content.decode("utf-8") if isinstance(content, bytes | bytearray) else str(content)
            for row in csv.DictReader(io.StringIO(text)):
                user = row.get("user", "")
                keys = []
                for n in ("1", "2"):
                    if str(row.get(f"access_key_{n}_active", "")).lower() == "true":
                        keys.append({"slot": int(n), "active": True,
                                     "age_days": _age_days(row.get(f"access_key_{n}_last_rotated"), now),
                                     "last_used": row.get(f"access_key_{n}_last_used_date") or None})
                if user == "<root_account>":
                    account.properties["root_mfa_enabled"] = str(row.get("mfa_active", "")).lower() == "true"
                    account.properties["root_access_keys"] = bool(keys)
                    continue
                a = users_by_name.get(user)
                if a is None:
                    continue
                a.properties["console_access"] = str(row.get("password_enabled", "")).lower() == "true"
                a.properties["mfa_active"] = str(row.get("mfa_active", "")).lower() == "true"
                a.properties["access_keys"] = keys
                a.properties["password_last_used"] = row.get("password_last_used") or None

        self._step(res, f"{acct}/iam credential report", credential_report)

        # ----------------------------------------------------------- S3 (global list, per-bucket region)
        buckets: list[AssetRecord] = []

        def s3():
            s3c = c("s3", home)
            acct_pab = _opt(lambda: c("s3control", home).get_public_access_block(AccountId=acct)
                            ["PublicAccessBlockConfiguration"], "NoSuchPublicAccessBlockConfiguration") or {}
            account.properties["s3_account_public_access_block"] = acct_pab or None
            listing = (list(_paginate(s3c, "list_buckets", "Buckets")) if s3c.can_paginate("list_buckets")
                       else s3c.list_buckets().get("Buckets", []))
            for b in listing:
                name = b["Name"]
                try:
                    buckets.append(add(self._bucket(c, home, acct, part, name, acct_pab, base)))
                except ReadOnlyViolation:
                    raise
                except Exception as exc:
                    res.errors.append(f"{acct}/s3 {name}: {type(exc).__name__}: {exc}")

        self._step(res, f"{acct}/s3", s3)

        # ----------------------------------------------------------- regions
        regions = list(self.settings.aws_regions)
        if not regions:
            try:
                regions = sorted(r["RegionName"] for r in c("ec2", home).describe_regions().get("Regions", []))
            except ReadOnlyViolation:
                raise
            except Exception as exc:
                res.errors.append(f"{acct}/regions: {type(exc).__name__}: {exc} (scanning {home} only)")
                regions = [home]

        rds_assets: list[AssetRecord] = []
        trails: dict[str, AssetRecord] = {}

        def cloudtrail(region: str, shadow: bool):
            ct = c("cloudtrail", region)
            for t in ct.describe_trails(includeShadowTrails=shadow).get("trailList", []):
                arn = t["TrailARN"]
                if arn in trails:
                    continue
                st = ct.get_trail_status(Name=arn)
                trails[arn] = add(AssetRecord(
                    id=arn, name=t.get("Name", arn), type="cloudtrail_trail", region=t.get("HomeRegion", region),
                    **base, properties={"is_multi_region": bool(t.get("IsMultiRegionTrail")),
                                        "is_logging": bool(st.get("IsLogging")),
                                        "log_file_validation": bool(t.get("LogFileValidationEnabled")),
                                        "kms_key_id": t.get("KmsKeyId"), "s3_bucket": t.get("S3BucketName"),
                                        "is_organization_trail": bool(t.get("IsOrganizationTrail"))}))

        ct_ok = [False]

        def ct_home():
            cloudtrail(home, True)
            ct_ok[0] = True

        self._step(res, f"{acct}/{home}/cloudtrail", ct_home)

        for region in regions:
            sgs: dict[str, AssetRecord] = {}

            def ec2(region=region, sgs=sgs):
                e = c("ec2", region)
                for g in _paginate(e, "describe_security_groups", "SecurityGroups"):
                    gid = g["GroupId"]
                    rules = sg_rules(gid, g.get("IpPermissions", []))
                    open_rules = internet_rules(rules)
                    sgs[gid] = add(AssetRecord(
                        id=f"arn:{part}:ec2:{region}:{acct}:security-group/{gid}", name=f"{g.get('GroupName', gid)}",
                        type="security_group", region=region, resource_group=g.get("VpcId"),
                        tags=_tags(g.get("Tags")), **base,
                        properties={"group_id": gid, "vpc_id": g.get("VpcId"), "is_default": g.get("GroupName") == "default",
                                    "security_rules": rules, "internet_ingress": open_rules}))
                for r in _paginate(e, "describe_instances", "Reservations"):
                    for i in r.get("Instances", []):
                        state = (i.get("State") or {}).get("Name", "")
                        if state in {"terminated", "shutting-down"}:
                            continue
                        iid = i["InstanceId"]
                        tags = _tags(i.get("Tags"))
                        sg_ids = [g["GroupId"] for g in i.get("SecurityGroups", [])]
                        rules = [rule for gid in sg_ids if gid in sgs for rule in sgs[gid].properties["security_rules"]]
                        pub = i.get("PublicIpAddress")
                        open_rules = internet_rules(rules)
                        exposed = bool(pub) and bool(open_rules)
                        md = i.get("MetadataOptions") or {}
                        imds_v2 = md.get("HttpTokens") == "required" or md.get("HttpEndpoint") == "disabled"
                        profile = (i.get("IamInstanceProfile") or {}).get("Arn")
                        role = profile_to_role.get(profile) if profile else None
                        aid = f"arn:{part}:ec2:{region}:{acct}:instance/{iid}"
                        sens, cls = sensitive_from_tags(tags)
                        add(AssetRecord(
                            id=aid, name=tags.get("Name") or iid, type="ec2_instance", region=region,
                            resource_group=i.get("VpcId"), tags=tags, internet_exposed=exposed, sensitive_data=sens,
                            **base,
                            properties={"instance_id": iid, "instance_type": i.get("InstanceType"), "state": state,
                                        "public_ip": pub, "public_ips": [pub] if pub else [],
                                        "private_ip": i.get("PrivateIpAddress"), "security_groups": sg_ids,
                                        "security_rules": rules, "internet_ingress": open_rules,
                                        "imdsv2_required": imds_v2, "instance_profile": profile, "iam_role": role,
                                        "platform": i.get("PlatformDetails"), "data_classification": cls,
                                        "exposure": (f"public IP {pub}, open to the internet via "
                                                     f"{', '.join(open_rules[:3])}") if exposed else None}))
                        for gid in sg_ids:
                            if gid in sgs:
                                rels.append(RelationshipRecord(sgs[gid].id, aid, "protects"))
                        if role:
                            rels.append(RelationshipRecord(aid, role, "uses_identity"))

            self._step(res, f"{acct}/{region}/ec2", ec2)

            def eks(region=region):
                ek = c("eks", region)
                for name in _paginate(ek, "list_clusters", "clusters"):
                    cl = ek.describe_cluster(name=name)["cluster"]
                    vpc = cl.get("resourcesVpcConfig") or {}
                    public = bool(vpc.get("endpointPublicAccess", True))
                    cidrs = list(vpc.get("publicAccessCidrs") or [])
                    unrestricted = public and (not cidrs or any(x in INTERNET for x in cidrs))
                    log_types = sorted({t for s in (cl.get("logging") or {}).get("clusterLogging", [])
                                        if s.get("enabled") for t in s.get("types", [])})
                    add(AssetRecord(
                        id=cl.get("arn") or f"arn:{part}:eks:{region}:{acct}:cluster/{name}", name=name,
                        type="eks_cluster", region=region, resource_group=vpc.get("vpcId"),
                        tags=dict(cl.get("tags") or {}), internet_exposed=unrestricted, **base,
                        properties={"kubernetes_version": cl.get("version"), "endpoint_public_access": public,
                                    "endpoint_private_access": bool(vpc.get("endpointPrivateAccess")),
                                    "public_access_cidrs": cidrs, "logging_enabled_types": log_types,
                                    "audit_logging": "audit" in log_types,
                                    "secrets_encryption": bool(cl.get("encryptionConfig")),
                                    "exposure": "public API endpoint open to 0.0.0.0/0" if unrestricted else None}))

            self._step(res, f"{acct}/{region}/eks", eks)

            def rds(region=region, sgs=sgs):
                rd = c("rds", region)
                for d in _paginate(rd, "describe_db_instances", "DBInstances"):
                    sg_ids = [v["VpcSecurityGroupId"] for v in d.get("VpcSecurityGroups", [])]
                    open_rules = [n for gid in sg_ids if gid in sgs for n in sgs[gid].properties["internet_ingress"]]
                    public = bool(d.get("PubliclyAccessible"))
                    tags = _tags(d.get("TagList"))
                    _, cls = sensitive_from_tags(tags)
                    aid = d["DBInstanceArn"]
                    rds_assets.append(add(AssetRecord(
                        id=aid, name=d["DBInstanceIdentifier"], type="rds_instance", region=region,
                        resource_group=(d.get("DBSubnetGroup") or {}).get("VpcId"), tags=tags,
                        internet_exposed=public and bool(open_rules), sensitive_data=True, **base,
                        properties={"engine": d.get("Engine"), "engine_version": d.get("EngineVersion"),
                                    "publicly_accessible": public, "storage_encrypted": bool(d.get("StorageEncrypted")),
                                    "backup_retention_days": int(d.get("BackupRetentionPeriod") or 0),
                                    "multi_az": bool(d.get("MultiAZ")), "security_groups": sg_ids,
                                    "iam_auth": bool(d.get("IAMDatabaseAuthenticationEnabled")),
                                    "deletion_protection": bool(d.get("DeletionProtection")),
                                    "data_classification": cls or "database",
                                    "exposure": ("publicly accessible, open via " + ", ".join(open_rules[:3]))
                                    if public and open_rules else None})))
                    for gid in sg_ids:
                        if gid in sgs:
                            rels.append(RelationshipRecord(sgs[gid].id, aid, "protects"))

            self._step(res, f"{acct}/{region}/rds", rds)

            def lam(region=region):
                lm = c("lambda", region)
                for f in _paginate(lm, "list_functions", "Functions"):
                    arn = f["FunctionArn"]
                    url = _opt(lambda arn=arn: lm.get_function_url_config(FunctionName=arn),
                               "ResourceNotFoundException") or {}
                    auth = url.get("AuthType")
                    public = auth == "NONE"
                    add(AssetRecord(
                        id=arn, name=f["FunctionName"], type="lambda_function", region=region,
                        internet_exposed=public, **base,
                        properties={"runtime": f.get("Runtime") or f.get("PackageType"), "role": f.get("Role"),
                                    "function_url": url.get("FunctionUrl"), "url_auth_type": auth,
                                    "public_url": public,
                                    "exposure": f"function URL {url.get('FunctionUrl')} (AuthType NONE)" if public else None}))
                    if f.get("Role"):
                        rels.append(RelationshipRecord(arn, f["Role"], "uses_identity"))

            self._step(res, f"{acct}/{region}/lambda", lam)

            def kms(region=region):
                km = c("kms", region)
                aliases: dict[str, str] = {}
                for al in _paginate(km, "list_aliases", "Aliases"):
                    if al.get("TargetKeyId"):
                        aliases.setdefault(al["TargetKeyId"], al["AliasName"])
                for k in _paginate(km, "list_keys", "Keys"):
                    md = km.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                    if md.get("KeyManager") != "CUSTOMER" or md.get("KeyState") in {"PendingDeletion", "PendingReplicaDeletion"}:
                        continue
                    symmetric = md.get("KeySpec", md.get("CustomerMasterKeySpec")) == "SYMMETRIC_DEFAULT"
                    rotation = None
                    if symmetric and md.get("Origin") == "AWS_KMS" and md.get("KeyState") == "Enabled":
                        rotation = bool(km.get_key_rotation_status(KeyId=k["KeyId"]).get("KeyRotationEnabled"))
                    add(AssetRecord(
                        id=md["Arn"], name=aliases.get(k["KeyId"], k["KeyId"]), type="kms_key", region=region, **base,
                        properties={"key_id": k["KeyId"], "key_state": md.get("KeyState"), "key_spec": md.get("KeySpec"),
                                    "origin": md.get("Origin"), "symmetric": symmetric, "rotation_enabled": rotation}))

            self._step(res, f"{acct}/{region}/kms", kms)

            if region != home:
                self._step(res, f"{acct}/{region}/cloudtrail", lambda region=region: cloudtrail(region, False))

        if ct_ok[0]:
            account.properties["cloudtrail_multi_region_logging"] = any(
                t.properties["is_multi_region"] and t.properties["is_logging"] for t in trails.values())

        # ----------------------------------------------------------- identity -> data store edges
        for ident_asset in identities:
            p = ident_asset.properties
            via = ", ".join(p.get("admin_via") or p.get("policies") or [])
            if p.get("s3_access"):
                rels.extend(RelationshipRecord(ident_asset.id, b.id, "has_access", {"via": via}) for b in buckets)
            if p.get("rds_access"):
                rels.extend(RelationshipRecord(ident_asset.id, d.id, "has_access", {"via": via}) for d in rds_assets)

        res.assets.extend(assets.values())
        res.relationships.extend(r for r in rels if r.source_id in assets and r.target_id in assets)

    def _bucket(self, c: AwsClients, home: str, acct: str, part: str, name: str, acct_pab: dict,
                base: dict) -> AssetRecord:
        s3c = c("s3", home)
        loc = s3c.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
        region = {"EU": "eu-west-1"}.get(loc, loc)
        bc = c("s3", region)
        pab = _opt(lambda: bc.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"],
                   "NoSuchPublicAccessBlockConfiguration") or {}
        keys = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
        effective = {k: bool(pab.get(k)) or bool(acct_pab.get(k)) for k in keys}
        status = _opt(lambda: bc.get_bucket_policy_status(Bucket=name)["PolicyStatus"], "NoSuchBucketPolicy") or {}
        policy = _opt(lambda: bc.get_bucket_policy(Bucket=name)["Policy"], "NoSuchBucketPolicy")
        acl = _opt(lambda: bc.get_bucket_acl(Bucket=name), "AccessDenied") or {}
        acl_public = any((g.get("Grantee") or {}).get("URI") in PUBLIC_ACL_GROUPS for g in acl.get("Grants", []))
        enc = _opt(lambda: bc.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"],
                   "ServerSideEncryptionConfigurationNotFoundError") or {}
        algos = [((r.get("ApplyServerSideEncryptionByDefault") or {}).get("SSEAlgorithm")) for r in enc.get("Rules", [])]
        ver = bc.get_bucket_versioning(Bucket=name)
        tagging = _opt(lambda: bc.get_bucket_tagging(Bucket=name)["TagSet"], "NoSuchTagSet") or []
        tags = _tags(tagging)
        sens, cls = sensitive_from_tags(tags)
        policy_public = bool(status.get("IsPublic")) and not effective["RestrictPublicBuckets"]
        acl_public_eff = acl_public and not effective["IgnorePublicAcls"]
        public = policy_public or acl_public_eff
        why = [w for w, on in (("bucket policy", policy_public),
                               ("ACL grants AllUsers/AuthenticatedUsers", acl_public_eff)) if on]
        return AssetRecord(
            id=f"arn:{part}:s3:::{name}", name=name, type="s3_bucket", region=region, tags=tags,
            internet_exposed=public, sensitive_data=sens, **base,
            properties={"public_access_block": effective, "public_access_block_enabled": all(effective.values()),
                        "policy_public": policy_public, "acl_public": acl_public_eff, "is_public": public,
                        "encryption": next((a for a in algos if a), None),
                        "versioning": ver.get("Status") or "Disabled", "mfa_delete": ver.get("MFADelete") == "Enabled",
                        "has_policy": policy is not None,
                        "denies_insecure_transport": denies_insecure_transport(policy) if policy else False,
                        "data_classification": cls,
                        "exposure": "public via " + " and ".join(why) if public else None})
