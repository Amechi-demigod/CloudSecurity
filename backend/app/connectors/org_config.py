"""Per-organisation cloud connector settings (docs/MULTI_TENANCY.md).

Connectors take a `Settings` object (app/config.py). `org_settings()` builds
the one an organisation scans with:

* the default organisation keeps the environment (AZURE_* / AWS_* / GCP_*):
  the Wakanow / on-prem deployment works unchanged. A connector it configures
  in the console overrides the environment for that provider.
* every other organisation starts with all cloud settings empty and only
  scans what its admins configure in the console. It can never use the
  server's ambient identity (managed identity, DefaultAzureCredential, boto3's
  default chain, GCP application default credentials) or the environment's
  keys: those belong to the platform operator.

Secret fields are encrypted at rest with the notification channel key
(NOTIFICATIONS_ENCRYPTION_KEY, app/notifications/crypto.py) and never returned
by the API (only a masked hint).
"""
from __future__ import annotations

import dataclasses
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config, tenancy
from ..config import AWS_EXTERNAL_ID_RE, AWS_REGION_RE, AWS_ROLE_ARN_RE, GCP_PROJECT_RE, Settings
from ..models import ConnectorConfig, utcnow

PROVIDERS = ("azure", "aws", "gcp")

#: Non-secret fields per provider: (name, kind) with kind "str" or "list".
FIELDS: dict[str, tuple[tuple[str, str], ...]] = {
    "azure": (("tenant_id", "str"), ("client_id", "str"), ("subscription_ids", "list")),
    "aws": (("access_key_id", "str"), ("role_arns", "list"), ("external_id", "str"), ("regions", "list"),
            ("home_region", "str")),
    "gcp": (("project_ids", "list"), ("organization_id", "str")),
}
SECRETS: dict[str, tuple[str, ...]] = {
    "azure": ("client_secret",),
    "aws": ("secret_access_key",),
    "gcp": ("credentials_json",),
}

# Cloud settings an organisation other than the default never inherits.
_CLOUD_FIELDS = {f.name for f in dataclasses.fields(Settings)
                 if f.name.startswith(("azure_", "aws_", "gcp_"))}


class ConnectorConfigError(ValueError):
    pass


def _blank_cloud(s: Settings) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name in _CLOUD_FIELDS:
        cur = getattr(s, name)
        out[name] = [] if isinstance(cur, list) else (False if isinstance(cur, bool) else None)
    out.update(azure_auth_mode="client_secret", aws_auth_mode="access_key", aws_home_region="us-east-1")
    return out


def _apply(provider: str, cfg: dict, secrets: dict) -> dict[str, Any]:
    if provider == "azure":
        return dict(azure_tenant_id=cfg.get("tenant_id") or None, azure_client_id=cfg.get("client_id") or None,
                    azure_client_secret=secrets.get("client_secret") or None,
                    azure_subscription_ids=list(cfg.get("subscription_ids") or []),
                    azure_auth_mode="client_secret", azure_use_default_credential=False,
                    azure_managed_identity_client_id=None)
    if provider == "aws":
        return dict(aws_access_key_id=cfg.get("access_key_id") or None,
                    aws_secret_access_key=secrets.get("secret_access_key") or None,
                    aws_role_arns=list(cfg.get("role_arns") or []), aws_external_id=cfg.get("external_id") or None,
                    aws_regions=list(cfg.get("regions") or []), aws_home_region=cfg.get("home_region") or "us-east-1",
                    aws_auth_mode="access_key", aws_use_default_credentials=False)
    return dict(gcp_credentials_json=secrets.get("credentials_json") or None, gcp_credentials_file=None,
                gcp_use_default_credentials=False, gcp_project_ids=list(cfg.get("project_ids") or []),
                gcp_organization_id=cfg.get("organization_id") or None)


def rows(db: Session) -> dict[str, ConnectorConfig]:
    """Stored connector configs of the session's organisation, by provider."""
    return {r.provider: r for r in db.scalars(select(ConnectorConfig))}


def org_settings(db: Session, org_id: str | None = None) -> Settings:
    """The settings the organisation's connectors scan with (see module doc)."""
    from ..notifications import crypto

    oid = org_id or tenancy.require_org(db)
    base = config.settings
    overrides: dict[str, Any] = {}
    if not tenancy.is_default(oid):
        # Demo data (SIMULATION_MODE) belongs to the default organisation.
        overrides.update(_blank_cloud(base), simulation_mode=False, simulated_connector_available=False)
    stored = db.scalars(select(ConnectorConfig).where(ConnectorConfig.organization_id == oid)
                        .execution_options(tenant_unscoped=True))
    for row in stored:
        if row.provider not in PROVIDERS:
            continue
        if not row.enabled:
            overrides.update(_apply(row.provider, {}, {}))
            continue
        try:
            secrets = crypto.decrypt_secrets(row.secret_ciphertext)
        except (crypto.DecryptionFailed, crypto.EncryptionUnavailable):
            secrets = {}
        overrides.update(_apply(row.provider, row.config or {}, secrets))
    return dataclasses.replace(base, **overrides) if overrides else base


# ----------------------------------------------------------------------------- console API
def _clean_list(v: Any, field: str) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        v = [p for p in v.replace(";", ",").replace("\n", ",").split(",")]
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ConnectorConfigError(f"{field} must be a list of strings")
    out = [x.strip() for x in v if x.strip()]
    if len(out) > 200:
        raise ConnectorConfigError(f"{field}: at most 200 entries")
    return out


def _validate(provider: str, cfg: dict, secrets: dict) -> list[str]:
    problems = []
    if provider == "azure":
        for sub in cfg["subscription_ids"]:
            if len(sub) != 36:
                problems.append(f"subscription_ids: {sub!r} is not a subscription id (GUID)")
    elif provider == "aws":
        for arn in cfg["role_arns"]:
            if not AWS_ROLE_ARN_RE.match(arn):
                problems.append(f"role_arns: {arn!r} is not an IAM role ARN")
        if cfg.get("external_id") and not AWS_EXTERNAL_ID_RE.match(cfg["external_id"]):
            problems.append("external_id must be 2-1224 characters of letters, digits and +=,.@:/-")
        for r in cfg["regions"] + ([cfg["home_region"]] if cfg.get("home_region") else []):
            if not AWS_REGION_RE.match(r):
                problems.append(f"{r!r} is not a region name (e.g. eu-west-1)")
    elif provider == "gcp":
        for p in cfg["project_ids"]:
            if not GCP_PROJECT_RE.match(p):
                problems.append(f"project_ids: {p!r} is not a project ID")
        if cfg.get("organization_id") and not str(cfg["organization_id"]).isdigit():
            problems.append("organization_id must be the numeric organization ID")
        if secrets.get("credentials_json"):
            try:
                key = json.loads(secrets["credentials_json"])
                if not isinstance(key, dict) or key.get("type") not in ("service_account", "external_account"):
                    raise ValueError
            except ValueError:
                problems.append("credentials_json must be a service-account key (or workload identity "
                                "federation config) JSON file")
    return problems


def _hint(name: str, value: str) -> str:
    if name == "credentials_json":
        try:
            email = json.loads(value).get("client_email") or ""
        except ValueError:
            email = ""
        return f"key for {email}" if email else "key file stored"
    return (value[:4] + "••••••") if len(value) > 8 else "••••••"


def prepare(db: Session, provider: str, *, config_in: dict, secrets_in: dict) -> tuple[dict, dict]:
    """Validated (config, secrets) the stored row would hold after this change:
    secrets not sent are kept from the stored row, an empty string removes one."""
    from ..notifications import crypto

    if provider not in PROVIDERS:
        raise ConnectorConfigError(f"unknown provider {provider!r}")
    cfg: dict[str, Any] = {}
    for name, kind in FIELDS[provider]:
        v = config_in.get(name)
        if kind == "list":
            cfg[name] = _clean_list(v, name)
        else:
            if v is not None and not isinstance(v, str):
                raise ConnectorConfigError(f"{name} must be a string")
            cfg[name] = (v or "").strip()[:1224] or None
    unknown = set(config_in) - {n for n, _ in FIELDS[provider]}
    unknown |= set(secrets_in) - set(SECRETS[provider])
    if unknown:
        raise ConnectorConfigError(f"unknown field(s) for {provider}: {', '.join(sorted(unknown))}")
    row = rows(db).get(provider)
    try:
        current = crypto.decrypt_secrets(row.secret_ciphertext) if row is not None else {}
    except crypto.DecryptionFailed:
        current = {}
    for name in SECRETS[provider]:
        if name in secrets_in:
            v = secrets_in[name]
            if v is not None and not isinstance(v, str):
                raise ConnectorConfigError(f"{name} must be a string")
            if v:
                current[name] = v.strip() if name != "credentials_json" else v
            else:
                current.pop(name, None)
    problems = _validate(provider, cfg, current)
    if problems:
        raise ConnectorConfigError("; ".join(problems))
    return cfg, current


def probe_settings(provider: str, cfg: dict, secrets: dict) -> Settings:
    """Settings for a connection test of `provider` with exactly these values:
    every cloud setting blank except the provider's own explicit credentials
    (never the environment, the server's identity or demo data)."""
    return dataclasses.replace(config.settings, **{**_blank_cloud(config.settings), **_apply(provider, cfg, secrets)},
                               simulation_mode=False, simulated_connector_available=False)


def upsert(db: Session, provider: str, *, config_in: dict, secrets_in: dict, enabled: bool = True,
           actor: str) -> ConnectorConfig:
    """Create or update the session organisation's connector config. Secrets
    not sent are kept; an empty string removes one. Caller commits."""
    from ..notifications import crypto

    cfg, current = prepare(db, provider, config_in=config_in, secrets_in=secrets_in)
    row = rows(db).get(provider)
    try:
        ciphertext = crypto.encrypt_secrets(current) if current else None
    except crypto.EncryptionUnavailable as e:
        raise ConnectorConfigError(str(e)) from None
    if row is None:
        row = ConnectorConfig(provider=provider)
        db.add(row)
    row.config, row.enabled = cfg, enabled
    row.secret_ciphertext = ciphertext
    row.secret_hints = {k: _hint(k, v) for k, v in current.items()}
    row.updated_at, row.updated_by = utcnow(), actor
    return row


def public_view(row: ConnectorConfig | None, provider: str) -> dict:
    """What the console shows: settings and masked secret hints, never secrets."""
    return {
        "provider": provider,
        "stored": row is not None,
        "enabled": bool(row.enabled) if row else False,
        "config": dict(row.config or {}) if row else {},
        "secrets": {n: (row.secret_hints or {}).get(n) for n in SECRETS[provider]} if row else
                   dict.fromkeys(SECRETS[provider]),
        "updated_at": row.updated_at if row else None,
        "updated_by": row.updated_by if row else None,
    }


def rotate_secrets(db: Session) -> int:
    """Re-encrypt every stored connector secret with the primary key (any session mode)."""
    from ..notifications import crypto

    n = 0
    for row in db.scalars(select(ConnectorConfig).execution_options(tenant_unscoped=True)):
        if row.secret_ciphertext:
            row.secret_ciphertext = crypto.rotate(row.secret_ciphertext)
            n += 1
    return n
