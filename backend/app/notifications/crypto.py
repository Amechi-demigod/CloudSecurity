"""Encryption of channel secrets at rest, and masking for display.

Secrets (webhook URLs, SMTP passwords, signing secrets, ACS connection strings)
are stored as one Fernet token (AES-128-CBC + HMAC-SHA256) per channel.
The key comes from NOTIFICATIONS_ENCRYPTION_KEY (Key Vault in Azure); several
comma-separated keys enable rotation: the first encrypts, all decrypt.

Without a key, development falls back to a key derived from SESSION_SECRET
(or a fixed, clearly insecure development key); production refuses to store
secrets instead.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from .. import config as app_config
from . import settings as nsettings

log = logging.getLogger(__name__)

_DEV_FALLBACK = b"cnapp-insecure-development-notifications-key"
_warned = False


class EncryptionUnavailable(RuntimeError):
    """No encryption key configured (production)."""


class DecryptionFailed(RuntimeError):
    """Stored secrets cannot be decrypted (key rotated away / corrupted)."""


def generate_key() -> str:
    return Fernet.generate_key().decode()


def _derive(material: bytes) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(b"cnapp-notifications:" + material).digest())


def _fernet() -> MultiFernet:
    global _warned
    keys = nsettings.get().encryption_keys
    if keys:
        try:
            return MultiFernet([Fernet(k.encode()) for k in keys])
        except (ValueError, TypeError) as exc:
            raise EncryptionUnavailable(
                "NOTIFICATIONS_ENCRYPTION_KEY is not a valid Fernet key (32 url-safe base64-encoded bytes)") from exc
    s = app_config.settings
    if s.is_production:
        raise EncryptionUnavailable("NOTIFICATIONS_ENCRYPTION_KEY is not configured")
    if not _warned:
        log.warning("NOTIFICATIONS_ENCRYPTION_KEY not set: using a development key derived from %s",
                    "SESSION_SECRET" if s.session_secret else "a built-in constant (INSECURE)")
        _warned = True
    return MultiFernet([Fernet(_derive(s.session_secret.encode() if s.session_secret else _DEV_FALLBACK))])


def encrypt_secrets(secrets: dict[str, str]) -> str:
    return _fernet().encrypt(json.dumps(secrets, separators=(",", ":")).encode()).decode()


def decrypt_secrets(token: str | None) -> dict[str, str]:
    if not token:
        return {}
    try:
        return json.loads(_fernet().decrypt(token.encode()))
    except InvalidToken as exc:
        raise DecryptionFailed("channel secrets cannot be decrypted with the configured key(s)") from exc


def rotate(token: str) -> str:
    """Re-encrypt with the primary key (after adding a new key in front)."""
    return _fernet().rotate(token.encode()).decode()


def mask(value: str, *, kind: str = "secret") -> str:
    """Display form of a secret. URLs show scheme + host only; others the last 4 chars."""
    if not value:
        return ""
    if kind == "url":
        try:
            parts = urlsplit(value)
            if parts.hostname:
                return f"{parts.scheme}://{parts.hostname}/••••••"
        except ValueError:
            pass
        return "••••••"
    if kind == "connection_string":
        endpoint = next((p.split("=", 1)[1] for p in value.split(";") if p.lower().startswith("endpoint=")), "")
        return mask(endpoint, kind="url") if endpoint else "••••••"
    return "••••" + value[-4:] if len(value) >= 12 else "••••••"


def redact(text: str, secrets: dict[str, str] | None) -> str:
    """Remove every secret value (and URL path/query parts) from an error message."""
    if not text:
        return text
    for v in (secrets or {}).values():
        if not v:
            continue
        candidates = {v}
        if "://" in v:
            try:
                parts = urlsplit(v)
                if parts.path and len(parts.path) > 1:
                    candidates.add(parts.path)
                if parts.query:
                    candidates.add(parts.query)
            except ValueError:
                pass
        if ";" in v:  # connection strings: redact each key=value
            candidates.update(p.split("=", 1)[1] for p in v.split(";") if "=" in p and len(p.split("=", 1)[1]) >= 8)
        for c in sorted(candidates, key=len, reverse=True):
            if len(c) >= 4:
                text = text.replace(c, "[REDACTED]")
    return text
