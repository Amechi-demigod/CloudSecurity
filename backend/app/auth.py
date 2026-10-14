"""User authentication: password hashing, server-side sessions, CSRF, RBAC, audit.

Design
------
* Passwords are hashed with Argon2id (argon2-cffi). Minimum length 12.
* Login creates a row in `user_sessions`; the browser gets a random 256-bit
  token in an httpOnly, SameSite=Lax cookie (Secure unless COOKIE_SECURE=false).
  Only sha256(token) is stored, so a DB leak does not leak live sessions.
* Sessions expire after SESSION_MAX_AGE_HOURS (absolute) or SESSION_IDLE_MINUTES
  without activity. Logout revokes the row server-side.
* CSRF: synchronizer token. Each session has a random `csrf_token`, returned by
  /api/auth/login and /api/auth/me. Every state-changing request (POST, PUT,
  PATCH, DELETE) authenticated by the session cookie must echo it in the
  `X-CSRF-Token` header. A cross-site page can neither read the token nor set
  custom headers without a CORS preflight, and SameSite=Lax already keeps the
  cookie off cross-site subrequests. The login endpoint (no session yet) only
  accepts `application/json` bodies, which HTML forms cannot send cross-site.
* Roles are ordered viewer < analyst < admin.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from . import config
from .db import get_db
from .models import ROLES, AuditLog, User, UserSession, utcnow

log = logging.getLogger(__name__)

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
ROLE_RANK = {r: i for i, r in enumerate(ROLES)}
GENERIC_LOGIN_ERROR = "Invalid email or password"
# Avoid a DB write on every request: only bump last_seen_at this often.
_TOUCH_INTERVAL = timedelta(seconds=30)

_hasher = PasswordHasher()
_dummy_hash: str | None = None


# --- passwords -----------------------------------------------------------------

def normalize_email(email: str) -> str:
    return email.strip().lower()


def password_problem(password: str) -> str | None:
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"password must be at least {MIN_PASSWORD_LENGTH} characters"
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"password must be at most {MAX_PASSWORD_LENGTH} characters"
    if not password.strip():
        return "password must not be blank"
    return None


def hash_password(password: str) -> str:
    problem = password_problem(password)
    if problem:
        raise ValueError(problem)
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def burn_verify_time(password: str) -> None:
    """Spend about as long as a real verification (unknown / inactive users)."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = _hasher.hash(secrets.token_urlsafe(16))
    verify_password(_dummy_hash, password)


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return False


# --- request helpers -------------------------------------------------------------

def client_ip(request: Request) -> str:
    if config.settings.trust_proxy_headers:
        xff = request.headers.get("x-forwarded-for", "")
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[-1][:64]
    return (request.client.host if request.client else "unknown")[:64]


class RateLimiter:
    """In-memory sliding-window limiter (single process, like the rest of the MVP)."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window: float) -> bool:
        """Record an attempt; return False if `key` is over `limit` within `window` seconds."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self._hits) > 10_000:  # bound memory: drop idle keys
                for k in [k for k, v in self._hits.items() if not v]:
                    del self._hits[k]
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


login_limiter = RateLimiter()


# --- audit -----------------------------------------------------------------------

def audit(db: Session, action: str, *, actor: User | None = None, actor_email: str | None = None,
          target: str | None = None, ip: str | None = None, **detail) -> None:
    """Add an audit record to the current transaction (caller commits)."""
    db.add(AuditLog(action=action, actor_id=actor.id if actor else None,
                    actor_email=actor.email if actor else actor_email, target=target, ip=ip, detail=detail))


# --- sessions ------------------------------------------------------------------

def _token_id(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: Session, user: User, request: Request) -> tuple[str, UserSession]:
    s = config.settings
    now = utcnow()
    # Opportunistic cleanup of dead sessions.
    db.execute(delete(UserSession).where(or_(UserSession.expires_at < now, UserSession.revoked_at.is_not(None))))
    token = secrets.token_urlsafe(32)
    sess = UserSession(id=_token_id(token), user_id=user.id, csrf_token=secrets.token_urlsafe(32),
                       created_at=now, last_seen_at=now,
                       expires_at=now + timedelta(hours=s.session_max_age_hours),
                       ip=client_ip(request), user_agent=(request.headers.get("user-agent") or "")[:255])
    db.add(sess)
    return token, sess


def revoke_user_sessions(db: Session, user_id: str, *, keep: str | None = None) -> None:
    stmt = select(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    for sess in db.scalars(stmt):
        if sess.id != keep:
            sess.revoked_at = utcnow()


def set_session_cookie(response: Response, token: str) -> None:
    s = config.settings
    response.set_cookie(s.session_cookie_name, token, max_age=int(s.session_max_age_hours * 3600), path="/",
                        httponly=True, secure=s.cookie_secure, samesite="lax")


def clear_session_cookie(response: Response) -> None:
    s = config.settings
    response.delete_cookie(s.session_cookie_name, path="/", httponly=True, secure=s.cookie_secure, samesite="lax")


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(401, detail, headers={"WWW-Authenticate": "Session"})


def current_session(request: Request, db: Session = Depends(get_db)) -> UserSession:
    """Resolve the session cookie; enforce expiry, idle timeout and CSRF."""
    s = config.settings
    token = request.cookies.get(s.session_cookie_name)
    if not token:
        raise _unauthorized("Not authenticated")
    sess = db.get(UserSession, _token_id(token))
    now = utcnow()
    if sess is None or sess.revoked_at is not None or not sess.user.is_active:
        raise _unauthorized("Session expired")
    idle_deadline = sess.last_seen_at + timedelta(minutes=s.session_idle_minutes)
    if now >= sess.expires_at or now >= idle_deadline:
        sess.revoked_at = now
        db.commit()
        raise _unauthorized("Session expired")
    if request.method not in SAFE_METHODS:
        supplied = request.headers.get(CSRF_HEADER, "")
        if not supplied or not hmac.compare_digest(supplied.encode(), sess.csrf_token.encode()):
            raise HTTPException(403, "CSRF token missing or invalid")
    if now - sess.last_seen_at >= _TOUCH_INTERVAL:
        sess.last_seen_at = now
        db.commit()
    request.state.session = sess
    return sess


def current_user(sess: UserSession = Depends(current_session)) -> User:
    return sess.user


def require_role(minimum: str):
    rank = ROLE_RANK[minimum]

    def dep(user: User = Depends(current_user)) -> User:
        if ROLE_RANK.get(user.role, -1) < rank:
            raise HTTPException(403, f"requires the {minimum} role")
        return user

    dep.__name__ = f"require_{minimum}"
    return dep


require_viewer = require_role("viewer")
require_analyst = require_role("analyst")
require_admin = require_role("admin")


# --- bootstrap -------------------------------------------------------------------

def bootstrap_admin(db: Session) -> User | None:
    """Create the first admin from ADMIN_EMAIL / ADMIN_PASSWORD when no users exist."""
    s = config.settings
    if db.scalar(select(func.count()).select_from(User)):
        return None
    if not (s.admin_email and s.admin_password):
        log.warning("No users exist. Set ADMIN_EMAIL and ADMIN_PASSWORD, or run "
                    "`python -m app.cli create-user --email you@example.com --role admin`.")
        return None
    problem = password_problem(s.admin_password)
    if problem:
        log.error("ADMIN_PASSWORD rejected (%s); no admin user was created", problem)
        return None
    user = User(email=normalize_email(s.admin_email), name=s.admin_name, role="admin",
                password_hash=hash_password(s.admin_password), password_changed_at=utcnow())
    db.add(user)
    db.flush()
    audit(db, "user_bootstrapped", actor_email="system", target=user.email, role="admin")
    db.commit()
    log.info("Created initial admin user %s from ADMIN_EMAIL", user.email)
    return user
