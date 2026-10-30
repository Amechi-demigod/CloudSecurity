"""Platform transactional email (invitations), through the same senders as the
email notification channel (app/notifications/channels.py: SMTP with
STARTTLS / TLS and the SSRF guard, or Azure Communication Services).

Configured with PLATFORM_SMTP_* (or PLATFORM_ACS_*). When nothing is
configured, `send()` returns False and callers show the link to the inviter
instead (docs/MULTI_TENANCY.md#email-for-invitations)."""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from . import config

log = logging.getLogger(__name__)


@dataclass
class MailResult:
    sent: bool
    error: str | None = None


def configured() -> bool:
    s = config.settings
    return bool((s.platform_smtp_host and s.platform_smtp_from)
                or (s.platform_acs_connection_string and s.platform_acs_sender))


def _channel() -> tuple[dict, dict]:
    s = config.settings
    if s.platform_smtp_host and s.platform_smtp_from:
        cfg = {"provider": "smtp", "host": s.platform_smtp_host, "port": s.platform_smtp_port,
               "security": s.platform_smtp_security, "from_address": s.platform_smtp_from,
               "username": s.platform_smtp_username or ""}
        return cfg, {"password": s.platform_smtp_password or ""}
    return ({"provider": "acs", "sender_address": s.platform_acs_sender},
            {"connection_string": s.platform_acs_connection_string or ""})


def send(to: str, subject: str, text: str, html: str) -> MailResult:
    """Send one transactional email (plain text + HTML alternative), not the
    alert layout of the notification channel. Never raises."""
    from .notifications import channels as ch

    if not configured():
        return MailResult(False, "no platform mail server configured (PLATFORM_SMTP_HOST)")
    cfg, secrets = _channel()
    cfg["to_addresses"] = [to]
    try:
        ch.send("email", cfg, secrets, {}, uuid.uuid4().hex, rendered=(subject, text, html))
        return MailResult(True)
    except (ch.PermanentError, ch.TransientError) as e:
        log.warning("platform mail to %s failed: %s", to.split("@")[-1], e)
        return MailResult(False, str(e)[:300])
    except Exception as e:  # mail must never break the request
        log.exception("platform mail failed")
        return MailResult(False, f"{type(e).__name__}")
