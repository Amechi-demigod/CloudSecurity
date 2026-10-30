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
* Roles are ordered viewer < analyst < admin. A role belongs to an
  organisation membership; every session acts in one organisation (the user's
  membership at sign-in) and scopes the request's database session to it
  (app/tenancy.py). Platform owners (`is_platform_admin`) additionally manage
  organisations; that is not an organisation role.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
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
from starlette.requests import HTTPConnection

from . import config, tenancy
from .db import get_db
from .models import ROLES, AuditLog, Organization, OrganizationMembership, User, UserSession, utcnow

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

def _parse_networks(cidrs: tuple[str, ...]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            log.warning("ignoring invalid TRUSTED_PROXY_CIDRS entry %r", c)
    return nets


_networks_cache: dict[tuple[str, ...], list] = {}


def _is_trusted_proxy(ip: str, cidrs: list[str]) -> bool:
    key = tuple(cidrs)
    nets = _networks_cache.get(key)
    if nets is None:
        nets = _networks_cache[key] = _parse_networks(key)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def client_ip(request: HTTPConnection) -> str:
    """Best-effort client IP, used for rate limiting and the audit log (requests
    and WebSocket handshakes alike).

    * TRUST_PROXY_HEADERS=false (default): the TCP peer.
    * TRUST_PROXY_HEADERS=true without TRUSTED_PROXY_CIDRS: the right-most
      X-Forwarded-For entry (the address your single proxy saw).
    * With TRUSTED_PROXY_CIDRS (e.g. Azure Container Apps, where the request
      passes the ingress and the frontend nginx): X-Forwarded-For is only
      honoured if the peer is a trusted proxy, and the client is the right-most
      entry that is not one, so values a client injects are ignored.
    """
    s = config.settings
    peer = request.client.host if request.client else "unknown"
    if s.trust_proxy_headers:
        xff = request.headers.get("x-forwarded-for", "")
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if s.trusted_proxy_cidrs:
            if parts and _is_trusted_proxy(peer, s.trusted_proxy_cidrs):
                for hop in reversed(parts):
                    if not _is_trusted_proxy(hop, s.trusted_proxy_cidrs):
                        return hop[:64]
                return parts[0][:64]  # every hop is internal (e.g. a client on the VNet)
        elif parts:
            return parts[-1][:64]
    return peer[:64]


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

    def blocked(self, key: str, limit: int, window: float) -> bool:
        """True if `key` is already at `limit` within `window` (does not record an attempt)."""
        now = time.monotonic()
        with self._lock:
            q = self._hits.get(key)
            return bool(q) and sum(1 for t in q if t > now - window) >= limit

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


login_limiter = RateLimiter()


# --- audit -----------------------------------------------------------------------

def audit(db: Session, action: str, *, actor: User | None = None, actor_email: str | None = None,
          target: str | None = None, ip: str | None = None, organization_id: str | None = None, **detail) -> None:
    """Add an audit record to the current transaction (caller commits). It goes
    to the session's organisation, else the given one, else the actor's
    (sign-in events), else the default organisation (the platform operator:
    events that belong to no organisation, e.g. attempts on unknown accounts)."""
    org = tenancy.org_id(db) or organization_id or (actor.organization_id if actor else None)
    if org is None and actor is not None:
        rows = memberships(db, actor.id)
        org = rows[0][1].id if rows else None
    org = org or tenancy.DEFAULT_ORG_ID
    db.add(AuditLog(action=action, actor_id=actor.id if actor else None, organization_id=org,
                    actor_email=actor.email if actor else actor_email, target=target, ip=ip, detail=detail))


# --- organisations ----------------------------------------------------------------

class OrgAccessError(Exception):
    """The user has no usable organisation membership (none, or suspended)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def is_platform_admin(user: User | None) -> bool:
    """Platform owner: flagged in the database (`python -m app.cli platform-admin`)
    or listed in PLATFORM_ADMIN_EMAILS."""
    if user is None or not user.is_active:
        return False
    return bool(user.is_platform_admin) or user.email in config.settings.platform_admin_emails


def memberships(db: Session, user_id: str) -> list[tuple[OrganizationMembership, Organization]]:
    """All memberships of a user with their organisations (any session mode)."""
    rows = db.execute(select(OrganizationMembership, Organization)
                      .join(Organization, Organization.id == OrganizationMembership.organization_id)
                      .where(OrganizationMembership.user_id == user_id)
                      .order_by(OrganizationMembership.created_at, OrganizationMembership.id)
                      .execution_options(tenant_unscoped=True))
    return [(m, o) for m, o in rows]


def attach_membership(db: Session, user: User, org_id: str | None = None) -> Organization:
    """Resolve the organisation a sign-in acts in (version 1: the user's only
    membership, or `org_id`) and set `user.role` / `user.organization_id`.
    Raises OrgAccessError when there is none or the organisation is suspended."""
    rows = memberships(db, user.id)
    if org_id is not None:
        rows = [(m, o) for m, o in rows if o.id == org_id]
    if not rows:
        raise OrgAccessError("no_membership")
    m, org = rows[0]
    if org.status != "active":
        raise OrgAccessError("organization_suspended")
    user.role, user.organization_id = m.role, org.id
    return org


def set_membership(db: Session, user: User, org_id: str, role: str) -> OrganizationMembership:
    """Create or update the user's membership of `org_id` (caller commits)."""
    m = db.scalar(select(OrganizationMembership).where(OrganizationMembership.user_id == user.id,
                                                       OrganizationMembership.organization_id == org_id)
                  .execution_options(tenant_unscoped=True))
    if m is None:
        m = OrganizationMembership(organization_id=org_id, user_id=user.id, role=role)
        db.add(m)
    else:
        m.role = role
    if user.organization_id in (None, org_id):
        user.role, user.organization_id = role, org_id
    db.flush()
    return m


def org_user(db: Session, user_id: str) -> User | None:
    """A user of the request's organisation (with `role` set from the membership).
    User accounts are platform-wide, so this goes through the (scoped) membership."""
    row = db.execute(select(User, OrganizationMembership.role)
                     .join(OrganizationMembership, OrganizationMembership.user_id == User.id)
                     .where(User.id == user_id)).first()
    if row is None:
        return None
    user, role = row
    user.role, user.organization_id = role, tenancy.require_org(db)
    return user


def org_users(db: Session) -> list[User]:
    oid = tenancy.require_org(db)
    out = []
    for user, role in db.execute(select(User, OrganizationMembership.role)
                                 .join(OrganizationMembership, OrganizationMembership.user_id == User.id)
                                 .order_by(User.email)):
        user.role, user.organization_id = role, oid
        out.append(user)
    return out


def active_admins(db: Session) -> int:
    """Active admins of the request's organisation."""
    return db.scalar(select(func.count()).select_from(OrganizationMembership)
                     .join(User, User.id == OrganizationMembership.user_id)
                     .where(OrganizationMembership.role == "admin", User.is_active.is_(True))) or 0


# --- sessions ------------------------------------------------------------------

def _token_id(token: str) -> str:
    """Database key for a session token: HMAC-SHA256 keyed with SESSION_SECRET
    (plain SHA-256 when no secret is configured, e.g. local development).
    Rotating SESSION_SECRET signs everybody out."""
    secret = config.settings.session_secret
    if secret:
        return hmac.new(secret.encode(), token.encode(), hashlib.sha256).hexdigest()
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: Session, user: User, request: Request) -> tuple[str, UserSession]:
    s = config.settings
    if user.organization_id is None:
        attach_membership(db, user)
    now = utcnow()
    # Opportunistic cleanup of dead sessions.
    db.execute(delete(UserSession).where(or_(UserSession.expires_at < now, UserSession.revoked_at.is_not(None))))
    token = secrets.token_urlsafe(32)
    sess = UserSession(id=_token_id(token), user_id=user.id, organization_id=user.organization_id,
                       csrf_token=secrets.token_urlsafe(32),
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


def session_from_connection(conn: HTTPConnection, db: Session, *, check_csrf: bool = False) -> UserSession:
    """Resolve the session cookie of a request or WebSocket handshake: enforce
    expiry, idle timeout and the membership (and CSRF for state-changing
    requests with `check_csrf`), and scope `db` to the session's organisation.
    WebSockets have no CSRF header: the relay checks their Origin instead."""
    s = config.settings
    token = conn.cookies.get(s.session_cookie_name)
    if not token:
        raise _unauthorized("Not authenticated")
    sess = db.get(UserSession, _token_id(token))
    now = utcnow()
    if sess is None or sess.revoked_at is not None or not sess.user.is_active:
        raise _unauthorized("Session expired")
    try:
        attach_membership(db, sess.user, sess.organization_id)
    except OrgAccessError as e:
        # Membership removed or organisation suspended: the session ends now.
        sess.revoked_at = now
        db.commit()
        raise _unauthorized("Organisation access suspended" if e.reason == "organization_suspended"
                            else "Session expired") from None
    idle_deadline = sess.last_seen_at + timedelta(minutes=s.session_idle_minutes)
    if now >= sess.expires_at or now >= idle_deadline:
        sess.revoked_at = now
        db.commit()
        raise _unauthorized("Session expired")
    if check_csrf and getattr(conn, "method", "GET") not in SAFE_METHODS:
        supplied = conn.headers.get(CSRF_HEADER, "")
        if not supplied or not hmac.compare_digest(supplied.encode(), sess.csrf_token.encode()):
            raise HTTPException(403, "CSRF token missing or invalid")
    if now - sess.last_seen_at >= _TOUCH_INTERVAL:
        sess.last_seen_at = now
        db.commit()
    conn.state.session = sess
    tenancy.set_org(db, sess.organization_id)
    return sess


def current_session(request: Request, db: Session = Depends(get_db)) -> UserSession:
    """Resolve the session cookie; enforce expiry, idle timeout and CSRF; scope
    the request's database session to the session's organisation."""
    return session_from_connection(request, db, check_csrf=True)


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


def require_platform_admin(user: User = Depends(current_user), db: Session = Depends(get_db)) -> User:
    """Platform owner only. The request's database session becomes unscoped
    (the platform console works across organisations on purpose)."""
    if not is_platform_admin(user):
        raise HTTPException(403, "requires a platform administrator")
    tenancy.set_unscoped(db)
    return user


def require_installation_admin(user: User = Depends(require_admin)) -> User:
    """Writes to platform-wide data shared by every organisation (signed agent
    releases, signed device-script bundles, the GitHub auto-import): a platform
    owner, or an admin of the default (installation operator's) organisation."""
    if not (is_platform_admin(user) or tenancy.is_default(user.organization_id)):
        raise HTTPException(403, "requires a platform administrator: this setting is shared by every organisation")
    return user


# --- bootstrap -------------------------------------------------------------------

def bootstrap_admin(db: Session) -> User | None:
    """Create the first admin (of the default organisation) from ADMIN_EMAIL /
    ADMIN_PASSWORD when no users exist."""
    s = config.settings
    tenancy.set_org(db, tenancy.DEFAULT_ORG_ID)
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
    user = User(email=normalize_email(s.admin_email), name=s.admin_name,
                password_hash=hash_password(s.admin_password), password_changed_at=utcnow())
    db.add(user)
    db.flush()
    set_membership(db, user, tenancy.DEFAULT_ORG_ID, "admin")
    audit(db, "user_bootstrapped", actor_email="system", target=user.email, role="admin")
    db.commit()
    log.info("Created initial admin user %s from ADMIN_EMAIL", user.email)
    return user
