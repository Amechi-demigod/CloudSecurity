"""Notification settings (env vars).

Kept separate from `app.config.Settings` so this feature stays self-contained.
`get()` re-reads the environment on every call; it is only called a few times
per worker tick / API request, and tests can simply set env vars.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from .. import config as app_config

# Default hostname allowlists per channel type ("*." = any subdomain). An empty
# list means "any public host". Override with NOTIFICATIONS_ALLOWED_HOSTS_<TYPE>
# (comma-separated; "*" disables the allowlist for that type).
DEFAULT_ALLOWED_HOSTS: dict[str, list[str]] = {
    # Classic Office 365 connector webhooks and Teams "Workflows" (Power Automate) webhooks.
    "teams": ["*.webhook.office.com", "*.logic.azure.com", "*.api.powerplatform.com"],
    "slack": ["hooks.slack.com"],
    "webhook": [],
    # Azure Communication Services Email endpoint (from its connection string).
    "acs": ["*.communication.azure.com"],
    "smtp": [],
}


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name) or default)
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name) or default)
    except ValueError:
        return default


def _hosts(kind: str) -> list[str]:
    raw = os.getenv(f"NOTIFICATIONS_ALLOWED_HOSTS_{kind.upper()}")
    if raw is None:
        return list(DEFAULT_ALLOWED_HOSTS.get(kind, []))
    items = [h.strip().lower() for h in raw.replace(";", ",").split(",") if h.strip()]
    return [] if "*" in items else items


@dataclass
class NotificationSettings:
    # Background dispatcher (leader-elected; safe to enable on every replica).
    worker_enabled: bool = field(default_factory=lambda: _bool("NOTIFICATIONS_WORKER_ENABLED", True))
    poll_seconds: float = field(default_factory=lambda: _float("NOTIFICATIONS_POLL_SECONDS", 5.0))
    # Fernet key(s), comma-separated: the first encrypts, all decrypt (rotation).
    encryption_keys: list[str] = field(default_factory=lambda: [
        k.strip() for k in (os.getenv("NOTIFICATIONS_ENCRYPTION_KEY") or "").split(",") if k.strip()])
    # Base URL of the web UI for deep links in messages, e.g. https://cnapp.example.com
    public_base_url: str = field(default_factory=lambda: (os.getenv("PUBLIC_BASE_URL") or "").strip().rstrip("/"))
    # Delivery engine
    max_attempts: int = field(default_factory=lambda: max(1, _int("NOTIFICATIONS_MAX_ATTEMPTS", 6)))
    backoff_base_seconds: float = field(default_factory=lambda: _float("NOTIFICATIONS_BACKOFF_BASE_SECONDS", 30.0))
    backoff_max_seconds: float = field(default_factory=lambda: _float("NOTIFICATIONS_BACKOFF_MAX_SECONDS", 3600.0))
    send_batch_size: int = field(default_factory=lambda: max(1, _int("NOTIFICATIONS_SEND_BATCH", 50)))
    event_batch_size: int = field(default_factory=lambda: max(1, _int("NOTIFICATIONS_EVENT_BATCH", 500)))
    retention_days: int = field(default_factory=lambda: max(1, _int("NOTIFICATIONS_RETENTION_DAYS", 30)))
    attack_path_poll_minutes: float = field(
        default_factory=lambda: _float("NOTIFICATIONS_ATTACK_PATH_POLL_MINUTES", 10.0))
    # Outbound HTTP
    connect_timeout: float = field(default_factory=lambda: _float("NOTIFICATIONS_CONNECT_TIMEOUT", 5.0))
    read_timeout: float = field(default_factory=lambda: _float("NOTIFICATIONS_READ_TIMEOUT", 10.0))
    max_response_bytes: int = field(default_factory=lambda: _int("NOTIFICATIONS_MAX_RESPONSE_BYTES", 65536))
    # DEV ONLY: allow http:// webhook URLs and private/loopback targets (e.g. a
    # local test receiver). Ignored in production.
    allow_insecure_dev: bool = field(default_factory=lambda: _bool("NOTIFICATIONS_ALLOW_INSECURE_DEV", False))
    # Allow SMTP relays on private (RFC 1918 / ULA) addresses, e.g. an internal
    # mail relay. Loopback, link-local and cloud metadata stay blocked.
    smtp_allow_private: bool = field(default_factory=lambda: _bool("NOTIFICATIONS_SMTP_ALLOW_PRIVATE", False))

    @property
    def insecure_dev(self) -> bool:
        return self.allow_insecure_dev and not app_config.settings.is_production

    def allowed_hosts(self, kind: str) -> list[str]:
        return _hosts(kind)

    def problems(self) -> list[str]:
        """Warnings logged at startup (not fatal: notifications are optional)."""
        out = []
        if app_config.settings.is_production and not self.encryption_keys:
            out.append("NOTIFICATIONS_ENCRYPTION_KEY is not set: notification channels cannot be saved")
        if app_config.settings.is_production and not self.public_base_url.startswith("https://"):
            out.append("PUBLIC_BASE_URL is not an https:// URL: notifications will not contain deep links")
        if self.allow_insecure_dev and app_config.settings.is_production:
            out.append("NOTIFICATIONS_ALLOW_INSECURE_DEV is ignored in production")
        return out


def get() -> NotificationSettings:
    return NotificationSettings()
