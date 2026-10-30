"""Permanent deletion of a (deactivated) user account by an organisation admin
or the CLI (docs/MULTI_TENANCY.md, "Users").

Accounts are platform-wide with one organisation membership. Deleting one
removes the account and everything that belongs only to it:

* organization_memberships   (FK users.id ON DELETE CASCADE) deleted
* user_sessions              (FK users.id ON DELETE CASCADE) deleted
* user_mfa                   (FK users.id ON DELETE CASCADE) deleted
* mfa_recovery_codes         (FK users.id ON DELETE CASCADE) deleted
* mfa_challenges             (FK users.id ON DELETE CASCADE) deleted
* user_identities (SSO)      (FK users.id ON DELETE CASCADE) deleted
* organization_invitations   pending ones of that organisation for the email deleted
                             (no FK; accepted / revoked ones are history and stay)

The rows are deleted explicitly, children first, so neither PostgreSQL nor
SQLite (with or without `PRAGMA foreign_keys`) depends on the cascade. History
that names the user in plain text (audit_log actor / target / actor_id,
approvals, commands, remote sessions, asset custody, invitations'
accepted_user_id, `*_by` columns) has no foreign key and is left unchanged.

Callers commit and write the `user_deleted` audit record.
"""
from __future__ import annotations

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .. import config
from ..auth import memberships, normalize_email
from ..models import (
    MfaChallenge,
    MfaRecoveryCode,
    OrganizationInvitation,
    OrganizationMembership,
    User,
    UserIdentity,
    UserMfa,
    UserSession,
)


class UserDeleteError(Exception):
    """The account may not be deleted (`status` is the HTTP status to answer with)."""

    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.message = message
        self.status = status


def is_protected_owner(user: User) -> bool:
    """Platform owner (flag or PLATFORM_ADMIN_EMAILS), whatever `is_active` says
    (auth.is_platform_admin is False for deactivated accounts)."""
    return bool(user.is_platform_admin) or user.email in config.settings.platform_admin_emails


def is_break_glass(user: User) -> bool:
    s = config.settings
    protected = set(s.auth_break_glass_emails)
    if s.admin_email:
        protected.add(normalize_email(s.admin_email))
    return user.email in protected


def check(db: Session, user: User, org_id: str, *, actor_id: str | None = None) -> None:
    """Raise UserDeleteError unless `user` (a member of `org_id`) may be deleted."""
    if actor_id is not None and user.id == actor_id:
        raise UserDeleteError("you cannot delete your own account")
    if user.is_active:
        raise UserDeleteError("deactivate the user before deleting the account")
    if is_protected_owner(user):
        raise UserDeleteError("this account is a platform owner: revoke platform-admin first "
                              "(python -m app.cli platform-admin EMAIL --revoke, and PLATFORM_ADMIN_EMAILS)")
    if is_break_glass(user):
        raise UserDeleteError("this account is a break-glass / bootstrap admin (AUTH_BREAK_GLASS_EMAILS or "
                              "ADMIN_EMAIL) and cannot be deleted")
    rows = memberships(db, user.id)
    if any(o.id != org_id for _, o in rows):
        raise UserDeleteError("this account is also a member of another organisation")
    mine = [m for m, o in rows if o.id == org_id]
    if not mine:
        raise UserDeleteError("user not found", 404)
    if mine[0].role == "admin":
        others = db.scalar(select(func.count()).select_from(OrganizationMembership)
                           .join(User, User.id == OrganizationMembership.user_id)
                           .where(OrganizationMembership.organization_id == org_id,
                                  OrganizationMembership.role == "admin",
                                  OrganizationMembership.user_id != user.id,
                                  User.is_active.is_(True))
                           .execution_options(tenant_unscoped=True)) or 0
        if not others:
            raise UserDeleteError("this is the organisation's last admin: make someone else an admin first")


def delete_account(db: Session, user: User, org_id: str) -> dict[str, int]:
    """Delete `user` and the rows that belong only to it (after `check`). Returns
    the number of rows removed per table (for the audit record)."""
    uid, email = user.id, user.email
    counts: dict[str, int] = {}

    def _run(name: str, stmt) -> None:
        counts[name] = db.execute(stmt.execution_options(tenant_unscoped=True)).rowcount or 0

    _run("organization_invitations", delete(OrganizationInvitation).where(
        OrganizationInvitation.organization_id == org_id, OrganizationInvitation.email == email,
        OrganizationInvitation.accepted_at.is_(None), OrganizationInvitation.revoked_at.is_(None)))
    _run("organization_memberships", delete(OrganizationMembership).where(OrganizationMembership.user_id == uid))
    _run("user_sessions", delete(UserSession).where(UserSession.user_id == uid))
    _run("mfa_challenges", delete(MfaChallenge).where(MfaChallenge.user_id == uid))
    _run("mfa_recovery_codes", delete(MfaRecoveryCode).where(MfaRecoveryCode.user_id == uid))
    _run("user_mfa", delete(UserMfa).where(UserMfa.user_id == uid))
    _run("user_identities", delete(UserIdentity).where(UserIdentity.user_id == uid))
    _run("users", delete(User).where(User.id == uid))
    return {k: v for k, v in counts.items() if v}
