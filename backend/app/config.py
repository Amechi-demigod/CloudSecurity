"""Application settings, loaded from environment variables.

Everything is configured through env vars so that no secrets ever need to live
in the repository. See `.env.example` at the repo root for the full reference.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _checked_float(name: str, default: float) -> float:
    """Float setting that is range-checked later: a malformed value becomes NaN,
    so the startup check reports it by name instead of crashing on import."""
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return float("nan")


def _list(name: str) -> list[str]:
    raw = os.getenv(name, "")
    return [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]


def _mapping(name: str) -> dict[str, str]:
    """"a=x,b=y" -> {"a": "x", "b": "y"} (keys keep their case, values are lower-cased)."""
    out: dict[str, str] = {}
    for item in _list(name):
        key, sep, value = item.partition("=")
        if sep and key.strip():
            out[key.strip()] = value.strip().lower()
    return out


PRODUCTION_ENVS = {"production", "prod"}

# Bounds of the scheduled-scan settings (also enforced on console changes).
MIN_INTERVAL_HOURS = 0.25
MAX_INTERVAL_HOURS = 168.0
MAX_STARTUP_DELAY_SECONDS = 3600

AWS_ACCESS_KEY_RE = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{12,124}$")
AWS_ROLE_ARN_RE = re.compile(r"^arn:aws(-[a-z]+)*:iam::\d{12}:role/[\w+=,.@/-]{1,512}$")
AWS_EXTERNAL_ID_RE = re.compile(r"^[\w+=,.@:/-]{2,1224}$")
AWS_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d{1,2}$")
GCP_PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


@dataclass
class Settings:
    # "development" (default) or "production". Production turns on the hardening
    # checks in `production_problems()` (the app refuses to start if any fail),
    # JSON logs, HSTS, and disables the interactive API docs.
    environment: str = field(default_factory=lambda: (os.getenv("APP_ENV") or "development").strip().lower())
    debug: bool = field(default_factory=lambda: _bool("DEBUG", False))
    # "json" or "text"; defaults to json in production and text otherwise.
    log_format: str = field(default_factory=lambda: (os.getenv("LOG_FORMAT") or "").strip().lower())
    log_level: str = field(default_factory=lambda: (os.getenv("LOG_LEVEL") or "INFO").strip().upper())

    # SQLite (default, local) or PostgreSQL, e.g.
    #   postgresql://user:pass@host:5432/cnapp?sslmode=require
    # (postgres:// and postgresql:// are mapped to the psycopg 3 driver).
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./cnapp.db"))
    # Apply schema changes on startup: Alembic `upgrade head` on PostgreSQL,
    # create_all + additive columns on SQLite. Guarded by a cross-replica lock.
    db_auto_migrate: bool = field(default_factory=lambda: _bool("DB_AUTO_MIGRATE", True))
    db_pool_size: int = field(default_factory=lambda: int(os.getenv("DB_POOL_SIZE", "5")))
    db_max_overflow: int = field(default_factory=lambda: int(os.getenv("DB_MAX_OVERFLOW", "5")))

    # Simulated data mode (default ON): seeds a fake multi-subscription Azure
    # environment on first start and runs a background runtime-event simulator.
    simulation_mode: bool = field(default_factory=lambda: _bool("SIMULATION_MODE", True))
    simulator_enabled: bool = field(default_factory=lambda: _bool("SIMULATOR_ENABLED", True))
    simulator_interval_seconds: float = field(
        default_factory=lambda: float(os.getenv("SIMULATOR_INTERVAL_SECONDS", "15"))
    )
    # Probability that a simulator tick also plays out an attack scenario.
    simulator_attack_probability: float = field(
        default_factory=lambda: float(os.getenv("SIMULATOR_ATTACK_PROBABILITY", "0.05"))
    )
    seed: int = field(default_factory=lambda: int(os.getenv("SEED", "42")))
    # Internal (not from the environment): False in the settings of
    # organisations other than the default (app/connectors/org_config.py).
    simulated_connector_available: bool = field(default=True)

    # Shared secret required on POST /api/runtime/events (sensor ingest) as
    # "Authorization: Bearer <token>". The sensor sends it from SENSOR_API_TOKEN.
    # RUNTIME_INGEST_TOKEN is accepted as a legacy alias.
    ingest_api_token: str | None = field(
        default_factory=lambda: os.getenv("INGEST_API_TOKEN") or os.getenv("RUNTIME_INGEST_TOKEN") or None
    )
    # Ingest is fail-closed: with no token configured the endpoint returns 503
    # unless this is explicitly enabled (local development only).
    ingest_allow_unauthenticated: bool = field(
        default_factory=lambda: _bool("INGEST_ALLOW_UNAUTHENTICATED", False)
    )
    # Hard cap on request body size (bytes) for every endpoint.
    max_request_bytes: int = field(default_factory=lambda: int(os.getenv("MAX_REQUEST_BYTES", str(1024 * 1024))))
    max_events_per_request: int = field(default_factory=lambda: int(os.getenv("MAX_EVENTS_PER_REQUEST", "1000")))

    # Browser origins allowed to call the API cross-origin. The UI normally
    # reaches the API same-origin through its /api proxy, so production only
    # needs the deployed frontend origin (or nothing). Development defaults to
    # the Vite dev server.
    cors_origins: list[str] = field(
        default_factory=lambda: _list("CORS_ORIGINS") or (
            [] if (os.getenv("APP_ENV") or "").strip().lower() in PRODUCTION_ENVS
            else ["http://localhost:5173", "http://127.0.0.1:5173"]
        )
    )

    # Azure read-only posture connector (opt-in).
    azure_tenant_id: str | None = field(default_factory=lambda: os.getenv("AZURE_TENANT_ID") or None)
    azure_client_id: str | None = field(default_factory=lambda: os.getenv("AZURE_CLIENT_ID") or None)
    azure_client_secret: str | None = field(default_factory=lambda: os.getenv("AZURE_CLIENT_SECRET") or None)
    azure_subscription_ids: list[str] = field(default_factory=lambda: _list("AZURE_SUBSCRIPTION_IDS"))
    # When true, fall back to DefaultAzureCredential (az login, managed identity, ...)
    # if no client secret is provided.
    azure_use_default_credential: bool = field(
        default_factory=lambda: _bool("AZURE_USE_DEFAULT_CREDENTIAL", False)
    )
    # How the Azure scanner authenticates:
    #   auto (default)     client secret if set, else managed identity if
    #                      AZURE_MANAGED_IDENTITY_CLIENT_ID is set, else
    #                      DefaultAzureCredential if AZURE_USE_DEFAULT_CREDENTIAL
    #   client_secret      ClientSecretCredential (local / outside Azure)
    #   managed_identity   ManagedIdentityCredential (Container Apps, VMs, ...)
    #   default            DefaultAzureCredential (env, workload/managed identity, az login)
    azure_auth_mode: str = field(default_factory=lambda: (os.getenv("AZURE_AUTH_MODE") or "auto").strip().lower())
    # Client ID of the user-assigned managed identity to scan with (omit for a
    # system-assigned identity together with AZURE_AUTH_MODE=managed_identity).
    azure_managed_identity_client_id: str | None = field(
        default_factory=lambda: os.getenv("AZURE_MANAGED_IDENTITY_CLIENT_ID") or None
    )

    # --- Scheduled cloud posture scans (app/services/scan_schedule.py) ----------
    # Scan every configured cloud connector automatically (one scan run per
    # connector). Defaults for a new installation: admins can change both in the
    # console (Connectors & scans), which overrides these until reset.
    scan_schedule_enabled: bool = field(default_factory=lambda: _bool("SCAN_SCHEDULE_ENABLED", True))
    # Hours between scheduled scans of a connector, counted from the start of its
    # previous scheduled scan (fractions allowed, 0.25 to 168).
    scan_interval_hours: float = field(default_factory=lambda: _checked_float("SCAN_INTERVAL_HOURS", 6.0))
    # After a (re)start, wait this long before the first scheduled scan, so a
    # deployment that is restarting settles first (0 to 3600).
    scan_startup_delay_seconds: float = field(
        default_factory=lambda: _checked_float("SCAN_STARTUP_DELAY_SECONDS", 120.0))
    # Internal: run the (leader-elected) scheduler thread in this process. Tests
    # turn it off; to stop scheduled scans use SCAN_SCHEDULE_ENABLED instead.
    scan_scheduler_worker_enabled: bool = field(default_factory=lambda: _bool("SCAN_SCHEDULER_WORKER_ENABLED", True))

    # Dashboards (app/services/dashboards.py). Remediation SLA targets in days
    # for the "Mean time to resolve" tile's "SLA met" share: a critical / high
    # finding resolved within this many days of first being seen meets its SLA.
    dashboard_sla_critical_days: float = field(default_factory=lambda: _checked_float("DASHBOARD_SLA_CRITICAL_DAYS", 7.0))
    dashboard_sla_high_days: float = field(default_factory=lambda: _checked_float("DASHBOARD_SLA_HIGH_DAYS", 30.0))
    # Internal: run the (leader-elected) daily dashboard snapshot thread in this
    # process. Tests turn it off and drive the job explicitly.
    dashboard_snapshot_worker_enabled: bool = field(
        default_factory=lambda: _bool("DASHBOARD_SNAPSHOT_WORKER_ENABLED", True))

    # AWS read-only posture connector (opt-in, docs/CONNECT_AWS.md). Needs the
    # AWS managed policies SecurityAudit + ViewOnlyAccess on every scanned account.
    # How the scanner authenticates:
    #   auto (default)  access key if AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY are
    #                   set, else the default credential chain if
    #                   AWS_USE_DEFAULT_CREDENTIALS=true
    #   access_key      the dedicated IAM user's access key
    #   default         boto3's default chain (instance role, ECS/EKS role, profile, SSO...)
    aws_auth_mode: str = field(default_factory=lambda: (os.getenv("AWS_AUTH_MODE") or "auto").strip().lower())
    aws_access_key_id: str | None = field(default_factory=lambda: os.getenv("AWS_ACCESS_KEY_ID") or None)
    aws_secret_access_key: str | None = field(default_factory=lambda: os.getenv("AWS_SECRET_ACCESS_KEY") or None,
                                              repr=False)
    aws_use_default_credentials: bool = field(default_factory=lambda: _bool("AWS_USE_DEFAULT_CREDENTIALS", False))
    # Cross-account: assume one read-only role per target account (comma list).
    # Empty: scan only the account the credentials belong to.
    aws_role_arns: list[str] = field(default_factory=lambda: _list("AWS_ROLE_ARNS"))
    aws_external_id: str | None = field(default_factory=lambda: os.getenv("AWS_EXTERNAL_ID") or None, repr=False)
    # Regions to scan; empty = every region enabled in the account (ec2:DescribeRegions).
    aws_regions: list[str] = field(default_factory=lambda: _list("AWS_REGIONS"))
    # Region for global APIs (IAM, STS, S3 bucket list, DescribeRegions). Change
    # for GovCloud (us-gov-west-1) or China (cn-north-1).
    aws_home_region: str = field(default_factory=lambda: (os.getenv("AWS_HOME_REGION") or "us-east-1").strip())

    # GCP read-only posture connector (opt-in, docs/CONNECT_GCP.md). Needs
    # roles/viewer + roles/iam.securityReviewer on the projects (or organization).
    # Service account key JSON or workload identity federation config; on-prem it
    # is mounted read-only from /opt/cnapp/secrets/gcp (cnapp-ctl gcp-key install).
    gcp_credentials_file: str | None = field(default_factory=lambda: os.getenv("GCP_CREDENTIALS_FILE") or None)
    # Service-account key JSON content (never from the environment: set for an
    # organisation's console-configured GCP connector, app/connectors/org_config.py).
    gcp_credentials_json: str | None = field(default=None, repr=False)
    # Use Application Default Credentials (GOOGLE_APPLICATION_CREDENTIALS, GCE
    # metadata server, gcloud ADC) when no credentials file is set.
    gcp_use_default_credentials: bool = field(default_factory=lambda: _bool("GCP_USE_DEFAULT_CREDENTIALS", False))
    gcp_project_ids: list[str] = field(default_factory=lambda: _list("GCP_PROJECT_IDS"))
    # Discover every ACTIVE project under this organization (recursively through folders).
    gcp_organization_id: str | None = field(
        default_factory=lambda: (os.getenv("GCP_ORGANIZATION_ID") or "").strip().removeprefix("organizations/") or None)

    # --- Organisations (multi-tenancy, docs/MULTI_TENANCY.md) ---------------
    # Name of the organisation existing data is migrated into (the installation
    # operator's own organisation; it keeps using the environment-configured
    # connectors, ingest token and SSO). Only used when it is first created.
    default_org_name: str = field(
        default_factory=lambda: (os.getenv("DEFAULT_ORG_NAME") or "Default organisation").strip()[:128])
    # Platform owners ("super admins"): manage organisations in the platform
    # console, in addition to users flagged with `python -m app.cli platform-admin`.
    platform_admin_emails: list[str] = field(
        default_factory=lambda: [e.lower() for e in _list("PLATFORM_ADMIN_EMAILS")])
    # Product branding shown on the sign-in page, in the console, in emails and
    # notifications (public: GET /api/health returns it before sign-in).
    brand_name: str = field(default_factory=lambda: (os.getenv("BRAND_NAME") or "").strip()[:64] or "CloudSecurity")
    brand_tagline: str = field(
        default_factory=lambda: (os.getenv("BRAND_TAGLINE") or "").strip()[:120] or "Runtime-first CNAPP")
    # Invitations (invite-only sign-up): link lifetime, and the platform mail
    # server for transactional email (invitations). Without one, the console
    # shows the invitation link for the inviter to pass on.
    invite_ttl_hours: float = field(default_factory=lambda: _checked_float("INVITE_TTL_HOURS", 72.0))
    platform_smtp_host: str | None = field(default_factory=lambda: (os.getenv("PLATFORM_SMTP_HOST") or "").strip() or None)
    platform_smtp_port: int = field(default_factory=lambda: int(os.getenv("PLATFORM_SMTP_PORT") or "587"))
    # starttls (587) or tls (implicit, 465)
    platform_smtp_security: str = field(
        default_factory=lambda: (os.getenv("PLATFORM_SMTP_SECURITY") or "starttls").strip().lower())
    platform_smtp_username: str | None = field(default_factory=lambda: os.getenv("PLATFORM_SMTP_USERNAME") or None)
    platform_smtp_password: str | None = field(default_factory=lambda: os.getenv("PLATFORM_SMTP_PASSWORD") or None,
                                               repr=False)
    platform_smtp_from: str | None = field(default_factory=lambda: (os.getenv("PLATFORM_SMTP_FROM") or "").strip() or None)
    # Alternative: Azure Communication Services Email (connection string + verified sender).
    platform_acs_connection_string: str | None = field(
        default_factory=lambda: os.getenv("PLATFORM_ACS_CONNECTION_STRING") or None, repr=False)
    platform_acs_sender: str | None = field(default_factory=lambda: (os.getenv("PLATFORM_ACS_SENDER") or "").strip() or None)

    # --- User authentication ------------------------------------------------
    # First admin, created on startup only when the users table is empty.
    admin_email: str | None = field(default_factory=lambda: os.getenv("ADMIN_EMAIL") or None)
    admin_password: str | None = field(default_factory=lambda: os.getenv("ADMIN_PASSWORD") or None)
    admin_name: str = field(default_factory=lambda: os.getenv("ADMIN_NAME") or "Administrator")
    # Session cookie. Secure is on by default; browsers treat http://localhost as
    # a secure context, and GitHub Codespaces forwards ports over https, so it
    # only needs turning off for plain-http access via a non-localhost hostname.
    session_cookie_name: str = field(default_factory=lambda: os.getenv("SESSION_COOKIE_NAME", "cnapp_session"))
    cookie_secure: bool = field(default_factory=lambda: _bool("COOKIE_SECURE", True))
    session_max_age_hours: float = field(default_factory=lambda: float(os.getenv("SESSION_MAX_AGE_HOURS", "8")))
    session_idle_minutes: float = field(default_factory=lambda: float(os.getenv("SESSION_IDLE_MINUTES", "30")))
    # Brute-force protection.
    login_max_failures: int = field(default_factory=lambda: int(os.getenv("LOGIN_MAX_FAILURES", "5")))
    login_lockout_minutes: float = field(default_factory=lambda: float(os.getenv("LOGIN_LOCKOUT_MINUTES", "15")))
    login_rate_limit: int = field(default_factory=lambda: int(os.getenv("LOGIN_RATE_LIMIT", "20")))
    login_rate_window_seconds: float = field(
        default_factory=lambda: float(os.getenv("LOGIN_RATE_WINDOW_SECONDS", "300"))
    )
    # Use the right-most X-Forwarded-For entry as the client IP (only behind a
    # reverse proxy you control, e.g. the bundled nginx).
    trust_proxy_headers: bool = field(default_factory=lambda: _bool("TRUST_PROXY_HEADERS", False))
    # Optional, used with TRUST_PROXY_HEADERS: CIDRs of your proxies (e.g. the
    # Container Apps ingress and the frontend nginx, which live on private
    # addresses). X-Forwarded-For is then honoured only when the direct peer is
    # one of them, and the client IP is the right-most entry that is NOT a
    # trusted proxy, so a client cannot spoof its address by sending the header.
    trusted_proxy_cidrs: list[str] = field(default_factory=lambda: _list("TRUSTED_PROXY_CIDRS"))
    # Keys the stored session-token digest (HMAC-SHA256) so that a database
    # dump alone cannot be used to forge/verify session ids. Required in production.
    session_secret: str | None = field(default_factory=lambda: os.getenv("SESSION_SECRET") or None)
    # Interactive API docs (/api/docs). Always off in production unless explicitly enabled.
    api_docs_enabled: bool = field(default_factory=lambda: _bool(
        "API_DOCS_ENABLED", (os.getenv("APP_ENV") or "").strip().lower() not in PRODUCTION_ENVS))
    # Strict-Transport-Security max-age sent in production (0 disables).
    hsts_max_age: int = field(default_factory=lambda: int(os.getenv("HSTS_MAX_AGE", "31536000")))

    # Serve /api/docs and /api/openapi.json without login (default: login required).
    api_docs_public: bool = field(default_factory=lambda: _bool("API_DOCS_PUBLIC", False))

    # --- Device management (endpoint agent) ---------------------------------
    # Body cap for /api/agent/* (check-ins with large software lists, log bundles).
    agent_max_request_bytes: int = field(
        default_factory=lambda: int(os.getenv("AGENT_MAX_REQUEST_BYTES", str(6 * 1024 * 1024))))
    # Largest accepted collect_logs bundle (gzip tar, stored in the database).
    device_log_bundle_max_bytes: int = field(
        default_factory=lambda: int(os.getenv("DEVICE_LOG_BUNDLE_MAX_BYTES", str(5 * 1024 * 1024))))
    # Per-device request budget on /api/agent/* (agents poll for commands every ~60s).
    device_rate_limit: int = field(default_factory=lambda: int(os.getenv("DEVICE_RATE_LIMIT", "120")))
    device_rate_window_seconds: float = field(
        default_factory=lambda: float(os.getenv("DEVICE_RATE_WINDOW_SECONDS", "600")))
    # Enrollment attempts per client IP. A whole office (or a mass Intune / GPO
    # rollout) behind one NAT address shares this budget, so it is generous;
    # failed attempts (wrong / used-up tokens) have their own, smaller budget.
    enroll_rate_limit: int = field(default_factory=lambda: int(os.getenv("ENROLL_RATE_LIMIT", "300")))
    enroll_failure_limit: int = field(default_factory=lambda: int(os.getenv("ENROLL_FAILURE_LIMIT", "20")))
    enroll_rate_window_seconds: float = field(
        default_factory=lambda: float(os.getenv("ENROLL_RATE_WINDOW_SECONDS", "600")))
    # Alert (audit log + notification source "agent_security") when rejected
    # agent requests (bad / revoked credentials, failed enrollments, rate limits)
    # reach this many within the window, per backend worker process. 0 disables.
    agent_auth_alert_threshold: int = field(
        default_factory=lambda: int(os.getenv("AGENT_AUTH_ALERT_THRESHOLD", "50")))
    agent_auth_alert_window_seconds: float = field(
        default_factory=lambda: float(os.getenv("AGENT_AUTH_ALERT_WINDOW_SECONDS", "300")))
    # Device health thresholds.
    device_stale_hours: float = field(default_factory=lambda: float(os.getenv("DEVICE_STALE_HOURS", "24")))
    device_inactive_days: float = field(default_factory=lambda: float(os.getenv("DEVICE_INACTIVE_DAYS", "7")))
    device_updates_grace_days: float = field(
        default_factory=lambda: float(os.getenv("DEVICE_UPDATES_GRACE_DAYS", "14")))
    device_av_signature_max_age_days: float = field(
        default_factory=lambda: float(os.getenv("DEVICE_AV_SIGNATURE_MAX_AGE_DAYS", "7")))
    # Posture snapshots kept per device (older ones are pruned on check-in).
    device_history_limit: int = field(default_factory=lambda: int(os.getenv("DEVICE_HISTORY_LIMIT", "200")))
    # Default lifetime of a queued remote command.
    device_command_ttl_hours: float = field(
        default_factory=lambda: float(os.getenv("DEVICE_COMMAND_TTL_HOURS", "24")))
    # Optional link shown on the enrollment page for downloading agent builds
    # (e.g. your GitHub release or an internal file share).
    agent_download_url: str | None = field(default_factory=lambda: os.getenv("AGENT_DOWNLOAD_URL") or None)
    # --- Pre-configured agent installers (Devices > Enroll > Download installer) ---
    # https:// URL agents use to reach this server; embedded in generated
    # installers (also used for notification deep links).
    public_base_url: str = field(default_factory=lambda: (os.getenv("PUBLIC_BASE_URL") or "").strip().rstrip("/"))
    # Optional https:// URL agents use instead of PUBLIC_BASE_URL, e.g. a
    # dedicated internet-facing name (https://agents.example.com) when only the
    # agent API is published (on-prem: cnapp-ctl public-agent enable). Used in
    # generated installers and enrollment instructions; staff links and SSO keep
    # using PUBLIC_BASE_URL.
    public_agent_url: str = field(default_factory=lambda: (os.getenv("PUBLIC_AGENT_URL") or "").strip().rstrip("/"))
    # Generic MSI / pkg (+ manifest.json with their SHA-256) bundled into the image
    # by CI; point it at another directory to serve your own (e.g. signed) builds.
    agent_installers_dir: str = field(default_factory=lambda: os.getenv("AGENT_INSTALLERS_DIR") or str(
        __import__("pathlib").Path(__file__).resolve().parents[1] / "installers"))
    # Private CA that issued the server certificate (base64 of the PEM bundle, or
    # a PEM file path). Embedded in installers so agents trust the server; leave
    # empty when the certificate is publicly trusted. cnapp-ctl sets
    # AGENT_CA_CERT_B64 on-prem when the built-in CA (or `tls import --ca`) is used.
    agent_ca_cert_b64: str = field(default_factory=lambda: (os.getenv("AGENT_CA_CERT_B64") or "").strip())
    agent_ca_cert_file: str | None = field(default_factory=lambda: os.getenv("AGENT_CA_CERT_FILE") or None)
    # Installer downloads per admin per window, and parallel builds per process.
    agent_installer_rate_limit: int = field(default_factory=lambda: int(os.getenv("AGENT_INSTALLER_RATE_LIMIT", "10")))
    agent_installer_rate_window_seconds: float = field(
        default_factory=lambda: float(os.getenv("AGENT_INSTALLER_RATE_WINDOW_SECONDS", "600")))
    agent_installer_max_parallel: int = field(default_factory=lambda: int(os.getenv("AGENT_INSTALLER_MAX_PARALLEL", "2")))
    # --- Agent auto-update (docs/AGENT_UPDATES.md) --------------------------------
    # Extra trusted release-signing PUBLIC keys ("<key id> <base64 key>", ";"-separated)
    # in addition to app/agent_update_keys.txt. The server only uses them to refuse
    # bundles agents would reject anyway; agents trust the keys compiled into them.
    agent_update_trusted_keys: str = field(default_factory=lambda: os.getenv("AGENT_UPDATE_TRUSTED_KEYS", ""))
    # Largest accepted release bundle (tar.gz of the signed manifest + binaries).
    agent_update_max_bundle_bytes: int = field(
        default_factory=lambda: int(os.getenv("AGENT_UPDATE_MAX_BUNDLE_BYTES", str(256 * 1024 * 1024))))
    # Agents start an offered update after a random delay of up to this many
    # seconds, so a fleet does not download at once. Bigger fleets get more
    # automatically: at least ceil(active devices / max parallel downloads) x 15 s
    # (app/services/agent_updates.py:effective_jitter_seconds).
    agent_update_jitter_seconds: int = field(default_factory=lambda: int(os.getenv("AGENT_UPDATE_JITTER_SECONDS", "120")))
    # Background job (leader-elected): automatic rollout (Pilot first, everyone
    # after the soak period) and the optional GitHub Releases auto-import.
    agent_update_worker_enabled: bool = field(default_factory=lambda: _bool("AGENT_UPDATE_WORKER_ENABLED", True))
    # Initial update mode for a new installation (changed in the console):
    # "automatic" (new releases go to Pilot, then everyone) or "manual" (rings only).
    agent_update_default_mode: str = field(
        default_factory=lambda: os.getenv("AGENT_UPDATE_DEFAULT_MODE", "automatic").strip().lower())
    agent_update_default_soak_hours: int = field(
        default_factory=lambda: int(os.getenv("AGENT_UPDATE_SOAK_HOURS", "24")))
    # Poll GitHub Releases for new signed agent bundles (tags agent-v*) and import
    # them through the normal verification. Default for a new installation; the
    # console setting overrides it. On by default on-prem (docker-compose.prod.yml).
    # Uses HTTPS_PROXY / HTTP_PROXY / NO_PROXY from the environment.
    agent_update_auto_import: bool = field(default_factory=lambda: _bool("AGENT_UPDATE_AUTO_IMPORT", False))
    agent_update_releases_repo: str = field(
        default_factory=lambda: os.getenv("AGENT_UPDATE_RELEASES_REPO", "Amechi-demigod/CloudSecurity").strip())
    agent_update_releases_api: str = field(
        default_factory=lambda: os.getenv("AGENT_UPDATE_RELEASES_API", "https://api.github.com").strip().rstrip("/"))
    agent_update_auto_import_interval_minutes: int = field(
        default_factory=lambda: int(os.getenv("AGENT_UPDATE_AUTO_IMPORT_INTERVAL_MINUTES", "60")))
    # A new agent version must check in successfully within this window after the
    # swap, otherwise the agent restores the previous binary (60-3600).
    agent_update_health_timeout_seconds: int = field(
        default_factory=lambda: int(os.getenv("AGENT_UPDATE_HEALTH_TIMEOUT_SECONDS", "600")))
    # Concurrent binary downloads per backend process (more get 503 + Retry-After).
    agent_update_max_parallel_downloads: int = field(
        default_factory=lambda: int(os.getenv("AGENT_UPDATE_MAX_PARALLEL_DOWNLOADS", "4")))
    # --- Two-person approval for high-risk device actions (docs/DEVICE_MANAGEMENT.md) ---
    # A requested remote wipe / medium- or high-risk script run waits this long for
    # a second admin, then expires.
    device_approval_ttl_hours: float = field(
        default_factory=lambda: float(os.getenv("DEVICE_APPROVAL_TTL_HOURS", "24")))
    # Single-admin installs only: let the requester approve their own request.
    # Off by default. When on, self-approval needs the device name typed again and
    # the action only runs after a cancellable cooling-off delay.
    device_approval_allow_self: bool = field(default_factory=lambda: _bool("DEVICE_APPROVAL_ALLOW_SELF", False))
    device_approval_self_cooldown_minutes: float = field(
        default_factory=lambda: float(os.getenv("DEVICE_APPROVAL_SELF_COOLDOWN_MINUTES", "15")))
    # Validity window of an approved remote-wipe command: the device must pick it
    # up (be online) within this time, or the wipe has to be requested again.
    device_wipe_command_ttl_minutes: float = field(
        default_factory=lambda: float(os.getenv("DEVICE_WIPE_COMMAND_TTL_MINUTES", "60")))
    # --- Approved (signed) device scripts (docs/DEVICE_SCRIPTS.md) ----------------
    # Extra trusted script-signing PUBLIC keys ("<key id> <base64 key>", ";"-separated)
    # in addition to app/script_signing_keys.txt (server-side import check only).
    device_script_trusted_keys: str = field(default_factory=lambda: os.getenv("DEVICE_SCRIPT_TRUSTED_KEYS", ""))
    device_script_max_bundle_bytes: int = field(
        default_factory=lambda: int(os.getenv("DEVICE_SCRIPT_MAX_BUNDLE_BYTES", str(512 * 1024))))
    # --- Multi-factor authentication (TOTP) -------------------------------------
    # Key(s) encrypting TOTP secrets at rest. Any string of 32+ characters (e.g.
    # `openssl rand -hex 32`); comma-separate several to rotate: the first one
    # encrypts, all of them decrypt. Required in production.
    mfa_encryption_keys: list[str] = field(default_factory=lambda: _list("MFA_ENCRYPTION_KEY"))
    # Roles that must use MFA, e.g. "admin,analyst": users with these roles who
    # have not enrolled are taken through enrolment at their next password login.
    mfa_required_roles: list[str] = field(
        default_factory=lambda: [r.lower() for r in _list("MFA_REQUIRED_ROLES")])
    # Name shown in authenticator apps; defaults to the brand ("CloudSecurity CNAPP" unless BRAND_NAME is set).
    mfa_issuer: str = field(default_factory=lambda: os.getenv("MFA_ISSUER")
                            or f"{(os.getenv('BRAND_NAME') or '').strip()[:64] or 'CloudSecurity'} CNAPP")
    # Lifetime of the token between the password step and the code step.
    mfa_challenge_ttl_seconds: int = field(default_factory=lambda: int(os.getenv("MFA_CHALLENGE_TTL_SECONDS", "300")))
    # Wrong codes allowed per challenge (the account lockout counter also applies).
    mfa_challenge_max_attempts: int = field(default_factory=lambda: int(os.getenv("MFA_CHALLENGE_MAX_ATTEMPTS", "5")))

    # --- Password login policy ---------------------------------------------------
    # false: only Microsoft sign-in, except for the break-glass accounts below.
    auth_password_login_enabled: bool = field(default_factory=lambda: _bool("AUTH_PASSWORD_LOGIN_ENABLED", True))
    # Whether users linked to an Entra identity may still sign in with a local password.
    auth_password_login_for_sso_users: bool = field(
        default_factory=lambda: _bool("AUTH_PASSWORD_LOGIN_FOR_SSO_USERS", False))
    # Local accounts that may always use password (+ MFA) login, whatever the two
    # settings above say (emergency access when Entra ID is unavailable).
    # Defaults to ADMIN_EMAIL.
    auth_break_glass_emails: list[str] = field(default_factory=lambda: [
        e.lower() for e in (_list("AUTH_BREAK_GLASS_EMAILS") or _list("ADMIN_EMAIL"))])

    # --- Microsoft Entra ID single sign-on (OIDC, authorization code + PKCE) ----
    entra_tenant_id: str | None = field(default_factory=lambda: (os.getenv("ENTRA_TENANT_ID") or "").strip() or None)
    entra_client_id: str | None = field(default_factory=lambda: (os.getenv("ENTRA_CLIENT_ID") or "").strip() or None)
    # How the app authenticates to the token endpoint:
    #   auto (default)     certificate if ENTRA_CLIENT_CERTIFICATE is set, else client
    #                      secret if ENTRA_CLIENT_SECRET is set, else managed_identity
    #                      if a managed identity client id is configured
    #   certificate        private_key_jwt signed with ENTRA_CLIENT_CERTIFICATE (PEM: key + cert)
    #   secret             ENTRA_CLIENT_SECRET
    #   managed_identity   federated credential: a managed identity token is the client assertion
    entra_client_auth: str = field(default_factory=lambda: (os.getenv("ENTRA_CLIENT_AUTH") or "auto").strip().lower())
    entra_client_secret: str | None = field(default_factory=lambda: os.getenv("ENTRA_CLIENT_SECRET") or None)
    entra_client_certificate: str | None = field(default_factory=lambda: os.getenv("ENTRA_CLIENT_CERTIFICATE") or None)
    entra_managed_identity_client_id: str | None = field(default_factory=lambda: (
        os.getenv("ENTRA_MANAGED_IDENTITY_CLIENT_ID") or os.getenv("AZURE_MANAGED_IDENTITY_CLIENT_ID") or None))
    entra_authority_host: str = field(default_factory=lambda: (
        os.getenv("ENTRA_AUTHORITY_HOST") or "https://login.microsoftonline.com").rstrip("/"))
    # Must exactly match a redirect URI of the app registration, e.g.
    # https://cnapp-web.<env>.azurecontainerapps.io/api/auth/sso/entra/callback
    entra_redirect_uri: str | None = field(default_factory=lambda: os.getenv("ENTRA_REDIRECT_URI") or None)
    # Create unknown users on their first Microsoft sign-in (off: an admin must add them first).
    entra_jit_provisioning: bool = field(default_factory=lambda: _bool("ENTRA_JIT_PROVISIONING", False))
    entra_default_role: str = field(default_factory=lambda: (os.getenv("ENTRA_DEFAULT_ROLE") or "viewer").strip().lower())
    # App role values or group object ids -> local role, e.g.
    # "CNAPP.Admin=admin,CNAPP.Analyst=analyst,0f6c...=viewer". The highest match
    # wins and is applied at every sign-in.
    entra_role_map: dict[str, str] = field(default_factory=lambda: _mapping("ENTRA_ROLE_MAP"))
    # Refuse Microsoft sign-in when no ENTRA_ROLE_MAP entry matches.
    entra_require_role: bool = field(default_factory=lambda: _bool("ENTRA_REQUIRE_ROLE", False))
    # Also require the local TOTP after Microsoft sign-in (default off: enforce MFA
    # in Entra ID with Conditional Access instead).
    entra_enforce_local_mfa: bool = field(default_factory=lambda: _bool("ENTRA_ENFORCE_LOCAL_MFA", False))

    # --- IT asset lifecycle (docs/ASSET_MANAGEMENT.md) ---------------------------
    # Defaults for settings an admin can override in the UI (IT assets > Settings).
    asset_default_currency: str = field(
        default_factory=lambda: (os.getenv("ASSET_DEFAULT_CURRENCY") or "NGN").strip().upper())
    # Agent devices not seen for this many days are flagged as idle candidates.
    asset_idle_days: int = field(default_factory=lambda: int(os.getenv("ASSET_IDLE_DAYS", "30")))
    # "Warranty expiring" window (dashboard + notifications).
    asset_warranty_warning_days: int = field(
        default_factory=lambda: int(os.getenv("ASSET_WARRANTY_WARNING_DAYS", "30")))
    # Default retrieval due date = leave date + this many days.
    asset_retrieval_due_days: int = field(default_factory=lambda: int(os.getenv("ASSET_RETRIEVAL_DUE_DAYS", "7")))
    # Wipe / destruction certificates (PDF, PNG, JPEG; stored in the database).
    asset_certificate_max_bytes: int = field(
        default_factory=lambda: int(os.getenv("ASSET_CERTIFICATE_MAX_BYTES", str(5 * 1024 * 1024))))
    # CSV import limits.
    asset_import_max_bytes: int = field(
        default_factory=lambda: int(os.getenv("ASSET_IMPORT_MAX_BYTES", str(2 * 1024 * 1024))))
    asset_import_max_rows: int = field(default_factory=lambda: int(os.getenv("ASSET_IMPORT_MAX_ROWS", "5000")))
    # How often the notification dispatcher checks for overdue retrievals,
    # expiring warranties and unseen devices.
    asset_notification_poll_seconds: float = field(
        default_factory=lambda: float(os.getenv("ASSET_NOTIFICATION_POLL_SECONDS", "3600")))

    # --- Vulnerability (CVE) matching (docs/VULNERABILITIES.md) -----------------
    # Match endpoint software (NVD by CPE) and sensor-reported Linux packages
    # (OSV.dev) against public vulnerability data, flag CISA KEV and add EPSS.
    # Needs egress to services.nvd.nist.gov, api.osv.dev, www.cisa.gov and
    # api.first.org (HTTPS_PROXY / NO_PROXY are honoured).
    vuln_matching_enabled: bool = field(default_factory=lambda: _bool("VULN_MATCHING_ENABLED", True))
    # Optional NVD API key (https://nvd.nist.gov/developers/request-an-api-key):
    # 50 instead of 5 requests per 30 s. Never logged.
    nvd_api_key: str | None = field(default_factory=lambda: (os.getenv("NVD_API_KEY") or "").strip() or None)
    nvd_api_url: str = field(default_factory=lambda: (
        os.getenv("NVD_API_URL") or "https://services.nvd.nist.gov/rest/json/cves/2.0").strip())
    osv_api_url: str = field(default_factory=lambda: (os.getenv("OSV_API_URL") or "https://api.osv.dev").strip()
                             .rstrip("/"))
    kev_url: str = field(default_factory=lambda: (os.getenv("KEV_URL") or (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")).strip())
    epss_enabled: bool = field(default_factory=lambda: _bool("EPSS_ENABLED", True))
    epss_api_url: str = field(default_factory=lambda: (
        os.getenv("EPSS_API_URL") or "https://api.first.org/data/v1/epss").strip())
    # Re-match every device / asset this often even without inventory changes
    # (new CVEs are published every day).
    vuln_rematch_interval_hours: float = field(
        default_factory=lambda: _checked_float("VULN_REMATCH_INTERVAL_HOURS", 12.0))
    # KEV catalog (and EPSS scores) refresh interval.
    vuln_kev_refresh_hours: float = field(default_factory=lambda: _checked_float("VULN_KEV_REFRESH_HOURS", 24.0))
    # How long NVD product data / OSV results are reused before an (incremental) refresh.
    vuln_nvd_cache_hours: float = field(default_factory=lambda: _checked_float("VULN_NVD_CACHE_HOURS", 12.0))
    vuln_osv_cache_hours: float = field(default_factory=lambda: _checked_float("VULN_OSV_CACHE_HOURS", 12.0))
    # A changed inventory (agent check-in / sensor report) is matched after this
    # quiet period, so bursts of check-ins are handled together.
    vuln_debounce_seconds: float = field(default_factory=lambda: _checked_float("VULN_DEBOUNCE_SECONDS", 120.0))
    # Notify about new vulnerabilities at or above this severity (KEV-listed
    # ones always), aggregated per CVE: critical | high | medium | low.
    vuln_notify_min_severity: str = field(
        default_factory=lambda: (os.getenv("VULN_NOTIFY_MIN_SEVERITY") or "critical").strip().lower())
    # Internal: run the (leader-elected) matching worker thread in this process.
    vuln_worker_enabled: bool = field(default_factory=lambda: _bool("VULN_WORKER_ENABLED", True))

    @property
    def entra_enabled(self) -> bool:
        return bool(self.entra_tenant_id and self.entra_client_id)

    @property
    def is_production(self) -> bool:
        return self.environment in PRODUCTION_ENVS

    @property
    def effective_log_format(self) -> str:
        if self.log_format in {"json", "text"}:
            return self.log_format
        return "json" if self.is_production else "text"

    def production_problems(self) -> list[str]:
        """Misconfigurations that are fatal when APP_ENV=production."""
        if not self.is_production:
            return []
        problems = []
        if self.debug:
            problems.append("DEBUG must be off in production")
        if not self.cookie_secure:
            problems.append("COOKIE_SECURE must be true in production")
        if "*" in self.cors_origins:
            problems.append("CORS_ORIGINS must list explicit origins in production, not '*'")
        if any(not o.startswith("https://") for o in self.cors_origins):
            problems.append("CORS_ORIGINS must only contain https:// origins in production")
        if not self.session_secret or len(self.session_secret) < 32:
            problems.append("SESSION_SECRET must be set (32+ characters) in production")
        if self.ingest_allow_unauthenticated:
            problems.append("INGEST_ALLOW_UNAUTHENTICATED must be false in production")
        if self.api_docs_public:
            problems.append("API_DOCS_PUBLIC must be false in production")
        if self.database_url.startswith("sqlite") and not _bool("ALLOW_SQLITE_IN_PRODUCTION", False):
            problems.append("DATABASE_URL must point to PostgreSQL in production "
                            "(set ALLOW_SQLITE_IN_PRODUCTION=true to override for a single-instance demo)")
        if not self.mfa_encryption_keys or any(len(k) < 32 for k in self.mfa_encryption_keys):
            problems.append("MFA_ENCRYPTION_KEY must be set (32+ characters) in production")
        problems.extend(self.auth_config_problems())
        return problems

    def auth_config_problems(self) -> list[str]:
        """MFA / SSO misconfigurations (fatal in every environment)."""
        from .models import ROLES

        problems = []
        for r in self.mfa_required_roles:
            if r not in ROLES:
                problems.append(f"MFA_REQUIRED_ROLES: unknown role {r!r}")
        if self.entra_default_role not in ROLES:
            problems.append(f"ENTRA_DEFAULT_ROLE: unknown role {self.entra_default_role!r}")
        for k, r in self.entra_role_map.items():
            if r not in ROLES:
                problems.append(f"ENTRA_ROLE_MAP: unknown role {r!r} for {k!r}")
        if not 0 < self.device_approval_ttl_hours <= 168:
            problems.append("DEVICE_APPROVAL_TTL_HOURS must be between 0 and 168")
        if not 1 <= self.device_approval_self_cooldown_minutes <= 1440:
            problems.append("DEVICE_APPROVAL_SELF_COOLDOWN_MINUTES must be between 1 and 1440")
        if not 5 <= self.device_wipe_command_ttl_minutes <= 1440:
            problems.append("DEVICE_WIPE_COMMAND_TTL_MINUTES must be between 5 and 1440")
        problems.extend(self.scan_schedule_problems())
        if not 1 <= self.invite_ttl_hours <= 24 * 30:
            problems.append("INVITE_TTL_HOURS must be between 1 and 720")
        if self.platform_smtp_security not in ("starttls", "tls"):
            problems.append("PLATFORM_SMTP_SECURITY must be starttls or tls")
        if self.platform_smtp_host and not self.platform_smtp_from:
            problems.append("PLATFORM_SMTP_FROM is required with PLATFORM_SMTP_HOST")
        problems.extend(self.vuln_matching_problems())
        if self.entra_client_auth not in {"auto", "certificate", "secret", "managed_identity"}:
            problems.append("ENTRA_CLIENT_AUTH must be auto, certificate, secret or managed_identity")
        if self.entra_enabled:
            if (self.entra_tenant_id or "").lower() in {"common", "organizations", "consumers"}:
                problems.append("ENTRA_TENANT_ID must be your tenant id, not a multi-tenant alias")
            if self.is_production and not (self.entra_redirect_uri or "").startswith("https://"):
                problems.append("ENTRA_REDIRECT_URI must be set to an https:// URL in production")
        problems.extend(self.cloud_config_problems())
        return problems

    def cloud_config_problems(self) -> list[str]:
        """AWS / GCP connector misconfigurations (fatal in every environment).

        Only the syntax is checked here: a missing credentials file just leaves
        the connector "not configured". Messages never include secret values.
        """
        problems = []
        if self.aws_auth_mode not in {"auto", "access_key", "default"}:
            problems.append("AWS_AUTH_MODE must be auto, access_key or default")
        if bool(self.aws_access_key_id) != bool(self.aws_secret_access_key):
            problems.append("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set together")
        if self.aws_access_key_id and not AWS_ACCESS_KEY_RE.match(self.aws_access_key_id):
            problems.append("AWS_ACCESS_KEY_ID does not look like an access key id (AKIA... / ASIA...)")
        for arn in self.aws_role_arns:
            if not AWS_ROLE_ARN_RE.match(arn):
                problems.append(f"AWS_ROLE_ARNS: {arn!r} is not an IAM role ARN (arn:aws:iam::<12-digit account>:role/<name>)")
        if self.aws_external_id is not None and not AWS_EXTERNAL_ID_RE.match(self.aws_external_id):
            problems.append("AWS_EXTERNAL_ID must be 2-1224 characters of letters, digits and +=,.@:/-")
        for r in self.aws_regions:
            if not AWS_REGION_RE.match(r):
                problems.append(f"AWS_REGIONS: {r!r} is not a region name (e.g. eu-west-1)")
        if not AWS_REGION_RE.match(self.aws_home_region):
            problems.append(f"AWS_HOME_REGION: {self.aws_home_region!r} is not a region name (e.g. us-east-1)")
        for p in self.gcp_project_ids:
            if not GCP_PROJECT_RE.match(p):
                problems.append(f"GCP_PROJECT_IDS: {p!r} is not a project ID (6-30 chars: lowercase letters, digits, -)")
        if self.gcp_organization_id and not self.gcp_organization_id.isdigit():
            problems.append("GCP_ORGANIZATION_ID must be the numeric organization ID (gcloud organizations list)")
        if self.gcp_credentials_file and not os.path.isabs(self.gcp_credentials_file):
            problems.append("GCP_CREDENTIALS_FILE must be an absolute path (on-prem: /run/secrets/gcp/credentials.json)")
        return problems

    def vuln_matching_problems(self) -> list[str]:
        problems = []
        for name, value, lo, hi in (("VULN_REMATCH_INTERVAL_HOURS", self.vuln_rematch_interval_hours, 1, 720),
                                    ("VULN_KEV_REFRESH_HOURS", self.vuln_kev_refresh_hours, 1, 720),
                                    ("VULN_NVD_CACHE_HOURS", self.vuln_nvd_cache_hours, 1, 720),
                                    ("VULN_OSV_CACHE_HOURS", self.vuln_osv_cache_hours, 1, 720),
                                    ("VULN_DEBOUNCE_SECONDS", self.vuln_debounce_seconds, 0, 86400)):
            if not lo <= value <= hi:
                problems.append(f"{name} must be between {lo} and {hi}")
        if self.vuln_notify_min_severity not in {"critical", "high", "medium", "low"}:
            problems.append("VULN_NOTIFY_MIN_SEVERITY must be critical, high, medium or low")
        return problems

    def scan_schedule_problems(self) -> list[str]:
        problems = []
        if not MIN_INTERVAL_HOURS <= self.scan_interval_hours <= MAX_INTERVAL_HOURS:
            problems.append(f"SCAN_INTERVAL_HOURS must be between {MIN_INTERVAL_HOURS:g} and {MAX_INTERVAL_HOURS:g}")
        if not 0 <= self.scan_startup_delay_seconds <= MAX_STARTUP_DELAY_SECONDS:
            problems.append(f"SCAN_STARTUP_DELAY_SECONDS must be between 0 and {MAX_STARTUP_DELAY_SECONDS}")
        for name, value in (("DASHBOARD_SLA_CRITICAL_DAYS", self.dashboard_sla_critical_days),
                            ("DASHBOARD_SLA_HIGH_DAYS", self.dashboard_sla_high_days)):
            if not 0 < value <= 3650:
                problems.append(f"{name} must be more than 0 and at most 3650 days")
        return problems


settings = Settings()


def reload_settings() -> Settings:
    """Re-read env vars (used by tests)."""
    global settings
    settings = Settings()
    return settings
