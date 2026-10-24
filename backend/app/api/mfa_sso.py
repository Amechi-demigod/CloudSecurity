"""Second factor (TOTP / recovery codes), MFA self-service, admin MFA reset and
Microsoft Entra ID single sign-on.

Login flow
----------
1. First factor: POST /api/auth/login (password) or the Entra callback.
2. `finish_first_factor()` then either issues the session (same cookie + CSRF
   token as before) or, when a second step is needed, a short-lived MFA
   challenge token instead:
     * purpose "verify": the user has TOTP enabled -> POST /api/auth/login/mfa
     * purpose "enroll": MFA_REQUIRED_ROLES covers the user's role but they have
       not enrolled -> /api/auth/login/mfa/enroll/start + /confirm
   Microsoft sign-ins skip the local second factor (MFA is Entra's job, via
   Conditional Access) unless ENTRA_ENFORCE_LOCAL_MFA=true.
"""
from __future__ import annotations

import hmac
import re
from datetime import timedelta
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .. import config, entra, mfa, tenancy
from ..auth import (
    ROLE_RANK,
    OrgAccessError,
    _token_id,
    active_admins,
    attach_membership,
    audit,
    client_ip,
    create_session,
    current_session,
    current_user,
    is_platform_admin,
    login_limiter,
    normalize_email,
    org_user,
    require_admin,
    revoke_user_sessions,
    set_membership,
    set_session_cookie,
    verify_password,
)
from ..db import get_db
from ..models import UNUSABLE_PASSWORD_PREFIX, OidcAuthRequest, Organization, User, UserIdentity, UserSession, utcnow
from ..schemas import (
    AuthProviders,
    LoginComplete,
    MfaChallengeOut,
    MfaCodeRequest,
    MfaEnableRequest,
    MfaManageRequest,
    MfaSetupOut,
    MfaStatus,
    MfaTokenRequest,
    OrganizationBrief,
    RecoveryCodesOut,
    SessionInfo,
    UserOut,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])
admin_router = APIRouter(prefix="/api", tags=["admin"], dependencies=[Depends(require_admin)])

INVALID_CODE = "Invalid verification code"
CHALLENGE_EXPIRED = "Your sign-in has expired. Please sign in again."
OIDC_COOKIE = "cnapp_oidc"
OIDC_COOKIE_PATH = "/api/auth/sso"
OIDC_REQUEST_TTL = timedelta(minutes=10)
CALLBACK_PATH = "/api/auth/sso/entra/callback"


def session_info(db: Session, sess: UserSession, recovery_codes: list[str] | None = None) -> LoginComplete:
    org = db.get(Organization, sess.organization_id)
    return LoginComplete(user=UserOut.model_validate(sess.user), csrf_token=sess.csrf_token,
                         expires_at=sess.expires_at, idle_timeout_minutes=config.settings.session_idle_minutes,
                         recovery_codes=recovery_codes, organization=OrganizationBrief.model_validate(org),
                         platform_admin=is_platform_admin(sess.user))


def safe_return_path(path: str | None) -> str:
    """Only same-app paths (never protocol-relative / absolute URLs, never back to /login)."""
    if (not path or not path.startswith("/") or path.startswith("//") or "\\" in path
            or path.startswith("/login") or path.startswith("/api/") or len(path) > 512):
        return "/"
    return path


# --- shared: first factor done --------------------------------------------------------

def register_failure(db: Session, user: User, ip: str, action: str, **detail) -> None:
    """Count a failed credential (password or second factor) towards the account lockout."""
    s = config.settings
    user.failed_login_count += 1
    detail["failed_count"] = user.failed_login_count
    if user.failed_login_count >= s.login_max_failures:
        user.locked_until = utcnow() + timedelta(minutes=s.login_lockout_minutes)
        user.failed_login_count = 0
        detail["locked_until"] = user.locked_until.isoformat() + "Z"
    audit(db, action, actor=user, ip=ip, **detail)


def _start_session(db: Session, user: User, request: Request, *, method: str, mfa_method: str | None = None
                   ) -> tuple[str, UserSession]:
    try:
        attach_membership(db, user)
    except OrgAccessError as e:
        audit(db, "login_denied", actor=user, ip=client_ip(request), reason=e.reason)
        db.commit()
        raise HTTPException(403, "Your organisation's access is suspended. Contact the platform administrator."
                            if e.reason == "organization_suspended" else
                            "This account is not a member of any organisation.") from None
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    token, sess = create_session(db, user, request)
    detail = {"method": method}
    if mfa_method:
        detail["mfa"] = mfa_method
    audit(db, "login_success", actor=user, ip=client_ip(request), **detail)
    return token, sess


def finish_first_factor(db: Session, user: User, request: Request, *, method: str
                        ) -> tuple[str, UserSession] | MfaChallengeOut:
    """Issue a session, or an MFA challenge when a second step is required. Commits.
    Raises OrgAccessError when the user has no active organisation."""
    s = config.settings
    ip = client_ip(request)
    if user.organization_id is None:
        attach_membership(db, user)
    local_mfa = method == "password" or s.entra_enforce_local_mfa
    purpose = None
    if local_mfa and user.mfa_enabled:
        purpose = "verify"
    elif local_mfa and mfa.is_required(user):
        purpose = "enroll"
    if purpose:
        token = mfa.create_challenge(db, user, purpose=purpose, method=method, ip=ip)
        audit(db, "mfa_challenge_issued" if purpose == "verify" else "mfa_enrollment_required", actor=user, ip=ip,
              method=method)
        db.commit()
        return MfaChallengeOut(purpose=purpose, mfa_token=token, expires_in=s.mfa_challenge_ttl_seconds)
    result = _start_session(db, user, request, method=method)
    db.commit()
    return result


def _mfa_rate_limit(request: Request) -> str:
    s = config.settings
    ip = client_ip(request)
    if not login_limiter.hit(f"mfa:{ip}", s.login_rate_limit, s.login_rate_window_seconds):
        raise HTTPException(429, "Too many attempts. Try again later.",
                            headers={"Retry-After": str(int(s.login_rate_window_seconds))})
    return ip


def _require_json(request: Request) -> None:
    if not (request.headers.get("content-type") or "").lower().startswith("application/json"):
        raise HTTPException(415, "requires an application/json body")


def _challenge_or_401(db: Session, token: str, purpose: str):
    ch = mfa.get_challenge(db, token, purpose)
    if ch is None:
        raise HTTPException(401, CHALLENGE_EXPIRED)
    return ch


def _locked(user: User) -> bool:
    return bool(user.locked_until and user.locked_until > utcnow())


# --- login step 2: verify ------------------------------------------------------------------

@router.post("/login/mfa", response_model=LoginComplete)
def login_mfa(body: MfaCodeRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    """Second step of a login: a TOTP code or a recovery code for the challenge token."""
    _require_json(request)
    ip = _mfa_rate_limit(request)
    ch = _challenge_or_401(db, body.mfa_token, "verify")
    user = ch.user
    if _locked(user):
        ch.consumed_at = utcnow()
        audit(db, "mfa_locked", actor=user, ip=ip)
        db.commit()
        raise HTTPException(401, CHALLENGE_EXPIRED)
    used = mfa.verify_second_factor(db, user, body.code)
    if not used:
        ch.attempts += 1
        register_failure(db, user, ip, "mfa_failure", attempts=ch.attempts)
        if _locked(user):
            ch.consumed_at = utcnow()
        db.commit()
        raise HTTPException(401, INVALID_CODE)
    ch.consumed_at = utcnow()
    if used == "recovery_code":
        audit(db, "mfa_recovery_code_used", actor=user, ip=ip, remaining=mfa.recovery_codes_remaining(db, user))
    token, sess = _start_session(db, user, request, method=ch.method, mfa_method=used)
    db.commit()
    set_session_cookie(response, token)
    return session_info(db, sess)


# --- login step 2: forced enrolment ---------------------------------------------------------

@router.post("/login/mfa/enroll/start", response_model=MfaSetupOut)
def login_enroll_start(body: MfaTokenRequest, request: Request, db: Session = Depends(get_db)):
    _require_json(request)
    ip = _mfa_rate_limit(request)
    ch = _challenge_or_401(db, body.mfa_token, "enroll")
    secret = mfa.new_secret()
    ch.pending_secret_enc = mfa.encrypt_secret(secret)
    audit(db, "mfa_setup_started", actor=ch.user, ip=ip, forced=True)
    db.commit()
    return mfa.setup_payload(secret, ch.user.email)


@router.post("/login/mfa/enroll/confirm", response_model=LoginComplete)
def login_enroll_confirm(body: MfaCodeRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    _require_json(request)
    ip = _mfa_rate_limit(request)
    ch = _challenge_or_401(db, body.mfa_token, "enroll")
    user = ch.user
    step = mfa.match_totp_step(mfa.decrypt_secret(ch.pending_secret_enc), body.code) if ch.pending_secret_enc else None
    if step is None:
        ch.attempts += 1
        audit(db, "mfa_enable_failure", actor=user, ip=ip, forced=True, attempts=ch.attempts)
        db.commit()
        raise HTTPException(400 if ch.pending_secret_enc else 409,
                            INVALID_CODE if ch.pending_secret_enc else "start the enrolment first")
    ch.consumed_at = utcnow()
    codes = mfa.enable(db, user, ch.pending_secret_enc, step_used=step)
    audit(db, "mfa_enabled", actor=user, target=user.email, ip=ip, forced=True)
    token, sess = _start_session(db, user, request, method=ch.method, mfa_method="totp")
    db.commit()
    set_session_cookie(response, token)
    return session_info(db, sess, recovery_codes=codes)


# --- self-service (signed in) -------------------------------------------------------------

def _status(db: Session, user: User) -> MfaStatus:
    return MfaStatus(enabled=user.mfa_enabled, enabled_at=user.mfa.enabled_at if user.mfa else None,
                     required=mfa.is_required(user), recovery_codes_remaining=mfa.recovery_codes_remaining(db, user),
                     has_password=user.has_password, sso_user=bool(user.identities))


@router.get("/mfa", response_model=MfaStatus)
def mfa_status(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return _status(db, user)


@router.post("/mfa/totp/setup", response_model=MfaSetupOut)
def mfa_setup(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Start enrolment: a new pending secret (the active one, if any, keeps working)."""
    if user.mfa_enabled:
        raise HTTPException(409, "MFA is already enabled; disable it first to enrol a new authenticator")
    secret = mfa.new_secret()
    row = mfa.mfa_row(db, user)
    row.pending_secret_enc = mfa.encrypt_secret(secret)
    row.pending_created_at = utcnow()
    audit(db, "mfa_setup_started", actor=user, ip=client_ip(request))
    db.commit()
    return mfa.setup_payload(secret, user.email)


@router.post("/mfa/totp/enable", response_model=RecoveryCodesOut)
def mfa_enable(body: MfaEnableRequest, request: Request, user: User = Depends(current_user),
               db: Session = Depends(get_db)):
    """Verify-before-enable: the first code from the authenticator activates MFA."""
    ip = _mfa_rate_limit(request)
    row = user.mfa
    if user.mfa_enabled:
        raise HTTPException(409, "MFA is already enabled")
    if row is None or not row.pending_secret_enc or not row.pending_created_at \
            or row.pending_created_at + mfa.PENDING_TTL < utcnow():
        raise HTTPException(409, "start the setup again (it expires after 15 minutes)")
    step = mfa.match_totp_step(mfa.decrypt_secret(row.pending_secret_enc), body.code)
    if step is None:
        audit(db, "mfa_enable_failure", actor=user, ip=ip)
        db.commit()
        raise HTTPException(400, INVALID_CODE)
    codes = mfa.enable(db, user, row.pending_secret_enc, step_used=step)
    audit(db, "mfa_enabled", actor=user, target=user.email, ip=ip)
    db.commit()
    return RecoveryCodesOut(recovery_codes=codes)


def _check_manage(db: Session, user: User, body: MfaManageRequest, request: Request, action: str) -> str:
    """Password (when the account has one) + current TOTP / recovery code."""
    ip = _mfa_rate_limit(request)
    if not user.mfa_enabled:
        raise HTTPException(409, "MFA is not enabled")
    if user.has_password and not (body.password and verify_password(user.password_hash, body.password)):
        audit(db, f"{action}_failure", actor=user, ip=ip, reason="bad_password")
        db.commit()
        raise HTTPException(400, "current password is incorrect")
    used = mfa.verify_second_factor(db, user, body.code)
    if not used:
        audit(db, f"{action}_failure", actor=user, ip=ip, reason="bad_code")
        db.commit()
        raise HTTPException(400, INVALID_CODE)
    return used


@router.post("/mfa/totp/disable", status_code=204)
def mfa_disable(body: MfaManageRequest, request: Request, sess: UserSession = Depends(current_session),
                db: Session = Depends(get_db)):
    user = sess.user
    if mfa.is_required(user):
        raise HTTPException(409, "MFA is required for your role and cannot be turned off")
    used = _check_manage(db, user, body, request, "mfa_disable")
    mfa.disable(db, user)
    revoke_user_sessions(db, user.id, keep=sess.id)
    audit(db, "mfa_disabled", actor=user, target=user.email, ip=client_ip(request), verified_with=used)
    db.commit()


@router.post("/mfa/recovery-codes", response_model=RecoveryCodesOut)
def mfa_regenerate(body: MfaManageRequest, request: Request, user: User = Depends(current_user),
                   db: Session = Depends(get_db)):
    used = _check_manage(db, user, body, request, "mfa_recovery_codes_regenerate")
    codes = mfa.generate_recovery_codes(db, user)
    audit(db, "mfa_recovery_codes_regenerated", actor=user, target=user.email, ip=client_ip(request),
          verified_with=used)
    db.commit()
    return RecoveryCodesOut(recovery_codes=codes)


# --- admin -------------------------------------------------------------------------------

@admin_router.post("/users/{user_id}/reset-mfa", response_model=UserOut)
def admin_reset_mfa(user_id: str, request: Request, admin: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    """Remove a user's authenticator and recovery codes (lost device). They are
    signed out; if their role requires MFA they enrol again at the next login."""
    user = org_user(db, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    had = user.mfa_enabled
    mfa.disable(db, user)
    keep = request.state.session.id if user.id == admin.id else None
    revoke_user_sessions(db, user.id, keep=keep)
    audit(db, "mfa_reset", actor=admin, target=user.email, ip=client_ip(request), had_mfa=had)
    db.commit()
    db.refresh(user)
    return org_user(db, user_id)


# --- providers ---------------------------------------------------------------------------

@router.get("/providers", response_model=AuthProviders)
def providers():
    """Public: which sign-in methods the login page should offer."""
    s = config.settings
    return AuthProviders(password=s.auth_password_login_enabled,
                         entra=s.entra_enabled and entra.client_auth_mode() != "none")


# --- Microsoft Entra ID ----------------------------------------------------------------

def _entra_ready() -> None:
    s = config.settings
    if not (s.entra_enabled and entra.client_auth_mode() != "none"):
        raise HTTPException(404, "Microsoft sign-in is not configured")


def _callback_fallback(request: Request) -> str:
    """Redirect URI when ENTRA_REDIRECT_URI is unset: this request's origin,
    honouring X-Forwarded-Proto/Host only behind a trusted proxy."""
    s = config.settings
    scheme, host = request.url.scheme, request.headers.get("host") or request.url.netloc
    if s.trust_proxy_headers:
        scheme = (request.headers.get("x-forwarded-proto") or scheme).split(",")[0].strip()
        host = (request.headers.get("x-forwarded-host") or host).split(",")[0].strip()
    return f"{scheme}://{host}{CALLBACK_PATH}"


def _login_redirect(error: str | None = None, fragment: str | None = None, clear: bool = True) -> RedirectResponse:
    url = "/login"
    if error:
        url += f"?sso_error={quote(error)}"
    if fragment:
        url += f"#{fragment}"
    resp = RedirectResponse(url, status_code=302)
    if clear:
        _clear_oidc_cookie(resp)
    return resp


def _clear_oidc_cookie(resp: Response) -> None:
    s = config.settings
    resp.delete_cookie(OIDC_COOKIE, path=OIDC_COOKIE_PATH, httponly=True, secure=s.cookie_secure, samesite="lax")


@router.get("/sso/entra/login", include_in_schema=True)
def entra_login(request: Request, next: str | None = None, db: Session = Depends(get_db)):  # noqa: A002
    """Start Microsoft sign-in: redirect the browser to Entra ID."""
    _entra_ready()
    s = config.settings
    ip = client_ip(request)
    if not login_limiter.hit(f"sso:{ip}", s.login_rate_limit * 2, s.login_rate_window_seconds):
        return _login_redirect("rate_limited")
    try:
        req = entra.build_authorization_request(_callback_fallback(request))
    except entra.SsoError as e:
        audit(db, "sso_login_failure", actor_email="", ip=ip, provider="entra", reason=e.code)
        db.commit()
        return _login_redirect(e.code)
    now = utcnow()
    db.execute(delete(OidcAuthRequest).where(OidcAuthRequest.expires_at < now))
    binding = entra.new_binding()
    db.add(OidcAuthRequest(id=_token_id("oidc-state:" + req.state), browser_binding=_token_id("oidc-bind:" + binding),
                           nonce=req.nonce, code_verifier=req.code_verifier, return_to=safe_return_path(next),
                           created_at=now, expires_at=now + OIDC_REQUEST_TTL))
    db.commit()
    resp = RedirectResponse(req.url, status_code=302)
    resp.set_cookie(OIDC_COOKIE, binding, max_age=int(OIDC_REQUEST_TTL.total_seconds()), path=OIDC_COOKIE_PATH,
                    httponly=True, secure=s.cookie_secure, samesite="lax")
    return resp


_SAFE_ERR = re.compile(r"[^a-z0-9_.-]")


class _Deny(Exception):
    def __init__(self, reason: str, email: str | None = None, **detail):
        super().__init__(reason)
        self.reason, self.email, self.detail = reason, email, detail


def _resolve_user(db: Session, claims: dict, ip: str) -> User:
    """Find (or provision) the local user for validated Entra claims and apply role mapping.

    The environment-configured Entra ID app (ENTRA_*) belongs to the default
    organisation: only its members can sign in with it and JIT provisioning
    creates members of it. A user of another organisation is refused even if
    the Entra tenant asserts their email address (an Entra tenant controls the
    email claims of its own accounts)."""
    s = config.settings
    org = tenancy.DEFAULT_ORG_ID
    tid, oid = str(claims["tid"]), str(claims["oid"])
    email = entra.claimed_email(claims)
    role = entra.mapped_role(claims)
    if s.entra_role_map and s.entra_require_role and role is None:
        raise _Deny("no_role_assigned", email)

    identity = db.scalar(select(UserIdentity).where(UserIdentity.provider == "entra", UserIdentity.tenant_id == tid,
                                                    UserIdentity.subject == oid))
    user = identity.user if identity else None
    if user is None:
        if not email:
            raise _Deny("no_email_claim")
        user = db.scalar(select(User).where(User.email == normalize_email(email)))
        if user is None:
            if not s.entra_jit_provisioning:
                raise _Deny("not_provisioned", email)
            name = str(claims.get("name") or "")[:128]
            user = User(email=normalize_email(email)[:320], name=name,
                        password_hash=UNUSABLE_PASSWORD_PREFIX + "sso", password_changed_at=None)
            db.add(user)
            db.flush()
            set_membership(db, user, org, role or s.entra_default_role)
            audit(db, "user_provisioned", actor_email="system", target=user.email, ip=ip, provider="entra",
                  role=user.role, oid=oid)
        try:
            attach_membership(db, user, org)
        except OrgAccessError:
            raise _Deny("not_provisioned", email) from None
        identity = UserIdentity(user_id=user.id, provider="entra", tenant_id=tid, subject=oid, email=email)
        db.add(identity)
        user.identities.append(identity)
        db.flush()
        audit(db, "sso_identity_linked", actor=user, target=user.email, ip=ip, provider="entra", oid=oid)

    if not user.is_active:
        raise _Deny("inactive", user.email)
    try:
        attach_membership(db, user, org)
    except OrgAccessError as e:
        raise _Deny("not_provisioned" if e.reason == "no_membership" else e.reason, user.email) from None
    if role and role != user.role:
        demotes_last_admin = (user.role == "admin" and ROLE_RANK[role] < ROLE_RANK["admin"]
                              and active_admins(db) <= 1)
        if demotes_last_admin:
            audit(db, "user_role_sync_skipped", actor_email="system", target=user.email, ip=ip,
                  reason="last_active_admin", mapped_role=role)
        else:
            audit(db, "user_updated", actor_email="system", target=user.email, ip=ip, source="entra_role_map",
                  changes={"role": [user.role, role]})
            set_membership(db, user, org, role)
    identity.last_login_at = utcnow()
    if email:
        identity.email = email[:320]
    return user


@router.get("/sso/entra/callback", name="entra_callback")
def entra_callback(request: Request, code: str | None = None, state: str | None = None,
                   error: str | None = None, db: Session = Depends(get_db)):
    """Redirect target registered in Entra ID. Validates the response, then signs
    the user in exactly like a password login (same cookie and CSRF token)."""
    _entra_ready()
    ip = client_ip(request)
    tenancy.set_org(db, tenancy.DEFAULT_ORG_ID)  # the ENTRA_* app is the default organisation's

    def fail(reason: str, email: str | None = None, clear: bool = True, **detail) -> RedirectResponse:
        db.rollback()
        audit(db, "sso_login_failure", actor_email=(email or "")[:320], ip=ip, provider="entra", reason=reason,
              **detail)
        db.commit()
        return _login_redirect(reason, clear=clear)

    # An unknown state must not disturb a sign-in in progress in this browser
    # (a third party could otherwise abort it with a forged callback link).
    if not state or len(state) > 256:
        return fail("invalid_state", clear=False)
    pending = db.get(OidcAuthRequest, _token_id("oidc-state:" + state))
    if pending is None:
        return fail("invalid_state", clear=False)
    db.delete(pending)  # single use, whatever happens next
    db.commit()
    binding = request.cookies.get(OIDC_COOKIE) or ""
    if not binding or not hmac.compare_digest(_token_id("oidc-bind:" + binding), pending.browser_binding):
        return fail("invalid_state", detail="browser_mismatch")
    if pending.expires_at <= utcnow():
        return fail("expired")
    if error:
        return fail("idp_error", idp_error=_SAFE_ERR.sub("", error.lower())[:64])
    if not code or len(code) > 4096:
        return fail("invalid_request")

    try:
        token = entra.exchange_code(code, pending.code_verifier, _callback_fallback(request))
        claims = entra.validate_id_token(token["id_token"], pending.nonce)
        user = _resolve_user(db, claims, ip)
    except entra.SsoError as e:
        return fail(e.code, detail=str(e)[:200])
    except _Deny as d:
        return fail(d.reason, d.email, **d.detail)

    try:
        result = finish_first_factor(db, user, request, method="entra")
    except OrgAccessError as e:
        return fail(e.reason, user.email)
    if isinstance(result, MfaChallengeOut):
        frag = f"mfa_token={quote(result.mfa_token)}&purpose={result.purpose}&next={quote(pending.return_to)}"
        return _login_redirect(fragment=frag)
    session_token, _ = result
    resp = RedirectResponse(pending.return_to, status_code=302)
    _clear_oidc_cookie(resp)
    set_session_cookie(resp, session_token)
    return resp


def is_password_login_allowed(user: User) -> bool:
    """Password-login policy (checked only after the password was verified)."""
    s = config.settings
    if user.email in s.auth_break_glass_emails:
        return True
    if not s.auth_password_login_enabled:
        return False
    return s.auth_password_login_for_sso_users or not user.identities


__all__ = ["router", "admin_router", "finish_first_factor", "register_failure", "is_password_login_allowed",
           "session_info", "SessionInfo"]
