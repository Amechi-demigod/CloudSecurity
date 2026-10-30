"""Login / logout / session info, admin user management and the audit log."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config, tenancy
from ..auth import (
    GENERIC_LOGIN_ERROR,
    OrgAccessError,
    active_admins,
    attach_membership,
    audit,
    burn_verify_time,
    clear_session_cookie,
    client_ip,
    current_session,
    current_user,
    hash_password,
    is_platform_admin,
    login_limiter,
    needs_rehash,
    normalize_email,
    org_user,
    org_users,
    password_problem,
    require_admin,
    revoke_user_sessions,
    set_membership,
    set_session_cookie,
    verify_password,
)
from ..db import get_db
from ..models import AuditLog, Organization, User, UserSession, utcnow
from ..schemas import (
    AuditLogOut,
    ChangePasswordRequest,
    LoginRequest,
    MfaChallengeOut,
    OrganizationBrief,
    PasswordReset,
    SessionInfo,
    UserCreate,
    UserOut,
    UserUpdate,
)
from .mfa_sso import finish_first_factor, is_password_login_allowed, register_failure

router = APIRouter(prefix="/api/auth", tags=["auth"])
admin_router = APIRouter(prefix="/api", tags=["admin"], dependencies=[Depends(require_admin)])


def org_brief(db: Session, org_id: str) -> OrganizationBrief:
    org = db.get(Organization, org_id)
    return OrganizationBrief.model_validate(org)


def _session_info(db: Session, sess: UserSession) -> SessionInfo:
    return SessionInfo(user=UserOut.model_validate(sess.user), csrf_token=sess.csrf_token,
                       expires_at=sess.expires_at, idle_timeout_minutes=config.settings.session_idle_minutes,
                       organization=org_brief(db, sess.organization_id), platform_admin=is_platform_admin(sess.user))


def _check_password(password: str) -> None:
    problem = password_problem(password)
    if problem:
        raise HTTPException(422, problem)


@router.post("/login", response_model=SessionInfo | MfaChallengeOut)
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    """Exchange email + password for a session cookie (returns the CSRF token), or
    for an MFA challenge token when a second factor / enrolment is required."""
    s = config.settings
    # Login CSRF: only accept JSON (a cross-site HTML form cannot send it without a CORS preflight).
    if not (request.headers.get("content-type") or "").lower().startswith("application/json"):
        raise HTTPException(415, "login requires an application/json body")
    ip = client_ip(request)
    if not login_limiter.hit(f"ip:{ip}", s.login_rate_limit, s.login_rate_window_seconds):
        audit(db, "login_rate_limited", actor_email=normalize_email(body.email)[:320], ip=ip)
        db.commit()
        raise HTTPException(429, "Too many login attempts. Try again later.",
                            headers={"Retry-After": str(int(s.login_rate_window_seconds))})

    email = normalize_email(body.email)
    user = db.scalar(select(User).where(User.email == email))
    now = utcnow()
    if user is None or not user.is_active:
        burn_verify_time(body.password)
        audit(db, "login_failure", actor_email=email[:320], ip=ip,
              reason="unknown_user" if user is None else "inactive")
        db.commit()
        raise HTTPException(401, GENERIC_LOGIN_ERROR)
    if user.locked_until and user.locked_until > now:
        burn_verify_time(body.password)
        audit(db, "login_locked", actor=user, ip=ip, locked_until=user.locked_until.isoformat() + "Z")
        db.commit()
        raise HTTPException(401, GENERIC_LOGIN_ERROR)
    if not verify_password(user.password_hash, body.password):
        register_failure(db, user, ip, "login_failure", reason="bad_password")
        db.commit()
        raise HTTPException(401, GENERIC_LOGIN_ERROR)
    # Policy is checked only after the password, so it reveals nothing to someone without it.
    if not is_password_login_allowed(user):
        audit(db, "login_password_disabled", actor=user, ip=ip)
        db.commit()
        raise HTTPException(403, "Password sign-in is disabled for this account. Use Sign in with Microsoft.")
    try:
        attach_membership(db, user)
    except OrgAccessError as e:
        audit(db, "login_denied", actor=user, ip=ip, reason=e.reason)
        db.commit()
        raise HTTPException(403, "Your organisation's access is suspended. Contact the platform administrator."
                            if e.reason == "organization_suspended" else
                            "This account is not a member of any organisation.") from None

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    # Second factor / forced enrolment if needed (the failure counter is only
    # reset once the whole login succeeds, so MFA guesses keep counting).
    result = finish_first_factor(db, user, request, method="password")
    if isinstance(result, MfaChallengeOut):
        return result
    token, sess = result
    set_session_cookie(response, token)
    return _session_info(db, sess)


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, sess: UserSession = Depends(current_session),
           db: Session = Depends(get_db)):
    sess.revoked_at = utcnow()
    audit(db, "logout", actor=sess.user, ip=client_ip(request))
    db.commit()
    clear_session_cookie(response)


@router.get("/me", response_model=SessionInfo)
def me(sess: UserSession = Depends(current_session), db: Session = Depends(get_db)):
    return _session_info(db, sess)


@router.post("/change-password", status_code=204)
def change_password(body: ChangePasswordRequest, request: Request,
                    sess: UserSession = Depends(current_session), db: Session = Depends(get_db)):
    user = sess.user
    if not verify_password(user.password_hash, body.current_password):
        raise HTTPException(400, "current password is incorrect")
    _check_password(body.new_password)
    if body.new_password == body.current_password:
        raise HTTPException(422, "new password must differ from the current one")
    user.password_hash = hash_password(body.new_password)
    user.password_changed_at = utcnow()
    revoke_user_sessions(db, user.id, keep=sess.id)  # sign out everywhere else
    audit(db, "password_changed", actor=user, target=user.email, ip=client_ip(request))
    db.commit()


# --- admin: users & audit log ---------------------------------------------------

def _get_user(db: Session, user_id: str) -> User:
    user = org_user(db, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    return user


@admin_router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db)):
    return org_users(db)


@admin_router.post("/users", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, request: Request, admin: User = Depends(current_user),
                db: Session = Depends(get_db)):
    email = normalize_email(body.email)
    # Email addresses are unique on the whole platform (one organisation per user for now).
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "a user with this email already exists")
    _check_password(body.password)
    user = User(email=email, name=body.name.strip(), password_hash=hash_password(body.password),
                password_changed_at=utcnow())
    db.add(user)
    db.flush()
    set_membership(db, user, tenancy.require_org(db), body.role)
    audit(db, "user_created", actor=admin, target=email, ip=client_ip(request), role=body.role)
    db.commit()
    return user


@admin_router.patch("/users/{user_id}", response_model=UserOut)
def update_user(user_id: str, body: UserUpdate, request: Request, admin: User = Depends(current_user),
                db: Session = Depends(get_db)):
    user = _get_user(db, user_id)
    changes: dict = {}
    loses_admin = (body.role is not None and body.role != "admin") or body.is_active is False
    if loses_admin and user.role == "admin" and user.is_active and active_admins(db) <= 1:
        raise HTTPException(409, "cannot demote or deactivate the last active admin")
    if body.name is not None and body.name.strip() != user.name:
        changes["name"] = [user.name, body.name.strip()]
        user.name = body.name.strip()
    if body.role is not None and body.role != user.role:
        changes["role"] = [user.role, body.role]
        set_membership(db, user, tenancy.require_org(db), body.role)
    if body.is_active is not None and body.is_active != user.is_active:
        changes["is_active"] = [user.is_active, body.is_active]
        user.is_active = body.is_active
        if body.is_active:
            user.failed_login_count, user.locked_until = 0, None
        else:
            revoke_user_sessions(db, user.id)
    if changes:
        audit(db, "user_updated", actor=admin, target=user.email, ip=client_ip(request), changes=changes)
    db.commit()
    return user


@admin_router.post("/users/{user_id}/reset-password", response_model=UserOut)
def reset_password(user_id: str, body: PasswordReset, request: Request, admin: User = Depends(current_user),
                   db: Session = Depends(get_db)):
    user = _get_user(db, user_id)
    _check_password(body.password)
    user.password_hash = hash_password(body.password)
    user.password_changed_at = utcnow()
    user.failed_login_count, user.locked_until = 0, None
    keep = request.state.session.id if user.id == admin.id else None
    revoke_user_sessions(db, user.id, keep=keep)
    audit(db, "password_reset", actor=admin, target=user.email, ip=client_ip(request))
    db.commit()
    return user


@admin_router.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: str, request: Request, admin: User = Depends(current_user), db: Session = Depends(get_db)):
    """Permanently delete a deactivated account of this organisation (and its
    membership, sessions, MFA and SSO links). Audit history is kept."""
    from ..services import user_deletion

    user = _get_user(db, user_id)
    org_id = tenancy.require_org(db)
    email, role = user.email, user.role
    try:
        user_deletion.check(db, user, org_id, actor_id=admin.id)
    except user_deletion.UserDeleteError as e:
        raise HTTPException(e.status, e.message) from None
    removed = user_deletion.delete_account(db, user, org_id)
    audit(db, "user_deleted", actor=admin, target=email, ip=client_ip(request), role=role, removed=removed)
    db.commit()


@admin_router.get("/audit-log", response_model=list[AuditLogOut])
def audit_log(db: Session = Depends(get_db), action: str | None = None, actor: str | None = None,
              limit: int = Query(200, ge=1, le=2000)):
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if actor:
        stmt = stmt.where(AuditLog.actor_email == normalize_email(actor))
    return list(db.scalars(stmt.order_by(AuditLog.id.desc()).limit(limit)))
