"""Application settings, loaded from environment variables.

Everything is configured through env vars so that no secrets ever need to live
in the repository. See `.env.example` at the repo root for the full reference.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


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
    # --- Multi-factor authentication (TOTP) -------------------------------------
    # Key(s) encrypting TOTP secrets at rest. Any string of 32+ characters (e.g.
    # `openssl rand -hex 32`); comma-separate several to rotate: the first one
    # encrypts, all of them decrypt. Required in production.
    mfa_encryption_keys: list[str] = field(default_factory=lambda: _list("MFA_ENCRYPTION_KEY"))
    # Roles that must use MFA, e.g. "admin,analyst": users with these roles who
    # have not enrolled are taken through enrolment at their next password login.
    mfa_required_roles: list[str] = field(
        default_factory=lambda: [r.lower() for r in _list("MFA_REQUIRED_ROLES")])
    mfa_issuer: str = field(default_factory=lambda: os.getenv("MFA_ISSUER") or "CloudSecurity CNAPP")
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
        if self.entra_client_auth not in {"auto", "certificate", "secret", "managed_identity"}:
            problems.append("ENTRA_CLIENT_AUTH must be auto, certificate, secret or managed_identity")
        if self.entra_enabled:
            if (self.entra_tenant_id or "").lower() in {"common", "organizations", "consumers"}:
                problems.append("ENTRA_TENANT_ID must be your tenant id, not a multi-tenant alias")
            if self.is_production and not (self.entra_redirect_uri or "").startswith("https://"):
                problems.append("ENTRA_REDIRECT_URI must be set to an https:// URL in production")
        return problems


settings = Settings()


def reload_settings() -> Settings:
    """Re-read env vars (used by tests)."""
    global settings
    settings = Settings()
    return settings
