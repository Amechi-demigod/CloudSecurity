"""Multi-factor authentication: TOTP (RFC 6238), recovery codes and login challenges.

Design
------
* TOTP: SHA-1, 6 digits, 30 s steps (what every authenticator app supports),
  accepting one step of clock drift either way. The matched time step is stored
  in `user_mfa.last_used_step` with a conditional UPDATE, so a code (or an
  older one) can never be used twice, even by two concurrent requests.
* Secrets are encrypted at rest with Fernet (AES-128-CBC + HMAC-SHA256). Keys
  come from MFA_ENCRYPTION_KEY (env / Key Vault); each configured string is
  stretched with HKDF, the first one encrypts and all of them decrypt, so keys
  can be rotated. Without a key (local development only) a fixed development
  key is used and a warning is logged; production refuses to start.
* The enrolment QR code is rendered server-side as an SVG data URI (segno), so
  the secret never leaves this server except to the user's own browser.
* Recovery codes: 10 per user, 80 bits of randomness each, shown once. Only
  SHA-256 of the normalized code is stored (no key needed, so key rotation
  never invalidates them); using one is a conditional UPDATE (single use).
* Login challenge: after the first factor the client gets a random token
  (only its HMAC is stored, like session tokens) that expires after
  MFA_CHALLENGE_TTL_SECONDS and allows MFA_CHALLENGE_MAX_ATTEMPTS wrong codes.
  Wrong codes also count towards the account lockout (LOGIN_MAX_FAILURES).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import time
from datetime import timedelta
from functools import lru_cache

import pyotp
import segno
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import delete, or_, select, update
from sqlalchemy.orm import Session

from . import config
from .models import MfaChallenge, MfaRecoveryCode, User, UserMfa, utcnow

log = logging.getLogger(__name__)

TOTP_DIGITS = 6
TOTP_INTERVAL = 30
TOTP_DRIFT_STEPS = 1
RECOVERY_CODE_COUNT = 10
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o, 1/l/i
_RECOVERY_LEN = 16  # 31^16 ~ 2^79
_DEV_KEY = "cnapp-insecure-development-mfa-key-do-not-use"
PENDING_TTL = timedelta(minutes=15)


class MfaError(Exception):
    pass


# --- encryption of TOTP secrets ------------------------------------------------------

@lru_cache(maxsize=8)
def _fernet(keys: tuple[str, ...]) -> MultiFernet:
    fernets = []
    for k in keys:
        derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"cnapp-mfa", info=b"totp-secret-v1").derive(
            k.encode())
        fernets.append(Fernet(base64.urlsafe_b64encode(derived)))
    return MultiFernet(fernets)


_warned_dev_key = False


def _cipher() -> MultiFernet:
    global _warned_dev_key
    keys = tuple(config.settings.mfa_encryption_keys)
    if not keys:
        if not _warned_dev_key:
            log.warning("MFA_ENCRYPTION_KEY is not set: TOTP secrets are encrypted with a fixed development key")
            _warned_dev_key = True
        keys = (_DEV_KEY,)
    return _fernet(keys)


def encrypt_secret(secret: str) -> str:
    return _cipher().encrypt(secret.encode()).decode()


def decrypt_secret(token: str) -> str:
    try:
        return _cipher().decrypt(token.encode()).decode()
    except InvalidToken as e:
        raise MfaError("cannot decrypt the TOTP secret (MFA_ENCRYPTION_KEY changed?)") from e


# --- TOTP --------------------------------------------------------------------------

def new_secret() -> str:
    return pyotp.random_base32(32)  # 160 bits, as RFC 4226 recommends


def provisioning_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL).provisioning_uri(
        name=email, issuer_name=config.settings.mfa_issuer)


def qr_svg_data_uri(uri: str) -> str:
    return segno.make(uri, error="m").svg_data_uri(scale=5, border=2, dark="#000", light="#fff")


def setup_payload(secret: str, email: str) -> dict:
    uri = provisioning_uri(secret, email)
    return {"secret": secret, "otpauth_uri": uri, "qr_svg": qr_svg_data_uri(uri),
            "digits": TOTP_DIGITS, "period": TOTP_INTERVAL}


def normalize_code(code: str) -> str:
    return "".join(ch for ch in code if not ch.isspace() and ch != "-").lower()


def match_totp_step(secret: str, code: str, now: float | None = None) -> int | None:
    """Return the time step `code` is valid for (within the drift window), else None."""
    code = normalize_code(code)
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL)
    current = int((time.time() if now is None else now) // TOTP_INTERVAL)
    found = None
    for step in range(current - TOTP_DRIFT_STEPS, current + TOTP_DRIFT_STEPS + 1):
        if hmac.compare_digest(totp.generate_otp(step), code):
            found = step  # no early return: constant work per attempt
    return found


def consume_totp(db: Session, mfa: UserMfa, code: str, *, secret_enc: str | None = None) -> bool:
    """Verify a TOTP code against the active (or given) secret and burn its time
    step. False for wrong, expired or already-used codes."""
    enc = secret_enc or mfa.totp_secret_enc
    if not enc:
        return False
    step = match_totp_step(decrypt_secret(enc), code)
    if step is None:
        return False
    # Atomic replay guard: only one request can move last_used_step past `step`.
    res = db.execute(update(UserMfa)
                     .where(UserMfa.user_id == mfa.user_id,
                            or_(UserMfa.last_used_step.is_(None), UserMfa.last_used_step < step))
                     .values(last_used_step=step)
                     .execution_options(synchronize_session=False))
    if res.rowcount != 1:
        return False
    mfa.last_used_step = step
    return True


def looks_like_totp(code: str) -> bool:
    c = normalize_code(code)
    return len(c) == TOTP_DIGITS and c.isdigit()


# --- recovery codes ----------------------------------------------------------------

def _hash_recovery(code: str) -> str:
    return hashlib.sha256(("cnapp-recovery:" + normalize_code(code)).encode()).hexdigest()


def _format_recovery(raw: str) -> str:
    return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))


def generate_recovery_codes(db: Session, user: User) -> list[str]:
    """Replace the user's recovery codes; returns the plaintext codes (show once)."""
    db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_LEN))
        codes.append(_format_recovery(raw))
        db.add(MfaRecoveryCode(user_id=user.id, code_hash=_hash_recovery(raw)))
    return codes


def consume_recovery_code(db: Session, user: User, code: str) -> bool:
    if len(normalize_code(code)) != _RECOVERY_LEN:
        return False
    res = db.execute(update(MfaRecoveryCode)
                     .where(MfaRecoveryCode.user_id == user.id, MfaRecoveryCode.code_hash == _hash_recovery(code),
                            MfaRecoveryCode.used_at.is_(None))
                     .values(used_at=utcnow())
                     .execution_options(synchronize_session=False))
    return res.rowcount == 1


def recovery_codes_remaining(db: Session, user: User) -> int:
    return len(db.scalars(select(MfaRecoveryCode.id).where(MfaRecoveryCode.user_id == user.id,
                                                           MfaRecoveryCode.used_at.is_(None))).all())


def verify_second_factor(db: Session, user: User, code: str) -> str | None:
    """Check a TOTP or recovery code for a user with MFA enabled.
    Returns "totp" / "recovery_code" on success, None otherwise."""
    if not user.mfa_enabled:
        return None
    if looks_like_totp(code):
        return "totp" if consume_totp(db, user.mfa, code) else None
    return "recovery_code" if consume_recovery_code(db, user, code) else None


# --- enrolment / reset ---------------------------------------------------------------

def mfa_row(db: Session, user: User) -> UserMfa:
    if user.mfa is None:
        user.mfa = UserMfa(user_id=user.id)
        db.flush()
    return user.mfa


def enable(db: Session, user: User, secret_enc: str, step_used: int | None = None) -> list[str]:
    """Activate `secret_enc` as the user's authenticator; returns new recovery codes."""
    mfa = mfa_row(db, user)
    mfa.totp_secret_enc = secret_enc
    mfa.pending_secret_enc = None
    mfa.pending_created_at = None
    mfa.enabled_at = utcnow()
    if step_used is not None:
        mfa.last_used_step = step_used
    return generate_recovery_codes(db, user)


def disable(db: Session, user: User) -> None:
    db.execute(delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == user.id))
    if user.mfa is not None:
        db.delete(user.mfa)
        user.mfa = None
    db.execute(delete(MfaChallenge).where(MfaChallenge.user_id == user.id))


def is_required(user: User) -> bool:
    return user.role in config.settings.mfa_required_roles


# --- login challenges ------------------------------------------------------------------

def _challenge_id(token: str) -> str:
    from .auth import _token_id

    return _token_id("mfa:" + token)


def create_challenge(db: Session, user: User, *, purpose: str, method: str, ip: str | None) -> str:
    s = config.settings
    now = utcnow()
    db.execute(delete(MfaChallenge).where(or_(MfaChallenge.expires_at < now, MfaChallenge.consumed_at.is_not(None))))
    token = secrets.token_urlsafe(32)
    db.add(MfaChallenge(id=_challenge_id(token), user_id=user.id, purpose=purpose, method=method, created_at=now,
                        expires_at=now + timedelta(seconds=s.mfa_challenge_ttl_seconds), ip=ip))
    return token


def get_challenge(db: Session, token: str, purpose: str) -> MfaChallenge | None:
    """A live, unconsumed challenge for `purpose` whose user is still active."""
    if not token or len(token) > 128:
        return None
    ch = db.get(MfaChallenge, _challenge_id(token))
    s = config.settings
    if (ch is None or ch.purpose != purpose or ch.consumed_at is not None or ch.expires_at <= utcnow()
            or ch.attempts >= s.mfa_challenge_max_attempts or not ch.user.is_active):
        return None
    return ch
