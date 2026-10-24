"""Invite-only sign-up (docs/MULTI_TENANCY.md#onboarding-a-new-organisation).

A platform owner creates an organisation and invites its first admin; org
admins invite their teammates. An invitation is a random single-use token
(only its SHA-256 is stored) with an expiry, sent by email as a link to
/invite#token=... (a URL fragment never reaches server logs or Referer
headers). Accepting it creates the account (email + password; MFA and SSO work
as for every account) and its membership, and signs the person in.

Version 1: an email address belongs to at most one account and one
organisation, so inviting an address that already has an account is refused.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config, mailer, tenancy
from ..models import ROLES, Organization, OrganizationInvitation, User, utcnow

TOKEN_PREFIX = "cnv_"  # noqa: S105 (token prefix, not a secret)
STATES = ("pending", "accepted", "expired", "revoked")


class InvitationError(ValueError):
    def __init__(self, message: str, status: int = 422):
        super().__init__(message)
        self.status = status


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def state(inv: OrganizationInvitation, now: datetime | None = None) -> str:
    now = now or utcnow()
    if inv.accepted_at:
        return "accepted"
    if inv.revoked_at:
        return "revoked"
    if inv.expires_at <= now:
        return "expired"
    return "pending"


def invite_url(token: str, base_url: str | None = None) -> str:
    base = (config.settings.public_base_url or base_url or "").rstrip("/")
    return f"{base}/invite#token={token}"


@dataclass
class Issued:
    invitation: OrganizationInvitation
    url: str
    emailed: bool
    email_error: str | None


def _issue_token(inv: OrganizationInvitation, now: datetime) -> str:
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    inv.token_hash = hash_token(raw)
    inv.expires_at = now + timedelta(hours=config.settings.invite_ttl_hours)
    return raw


def _send(org: Organization, inv: OrganizationInvitation, url: str, inviter: str | None, now: datetime) -> Issued:
    hours = config.settings.invite_ttl_hours
    msg = {"severity": "info", "source_label": "Invitation",
           "title": f"You are invited to {org.name} on CloudSecurity",
           "summary": (f"{inviter or 'An administrator'} invited you to join {org.name} on the CloudSecurity "
                       f"platform as {inv.role}. Open the link to choose your password. It can be used once and "
                       f"expires in {hours:g} hours. If you did not expect this invitation, ignore this email."),
           "facts": [("Organisation", org.name), ("Role", inv.role), ("Email", inv.email)],
           "link": url}
    res = mailer.send(inv.email, msg)
    inv.last_sent_at = now
    inv.sent_count = (inv.sent_count or 0) + 1
    return Issued(inv, url, res.sent, res.error)


def create(db: Session, org: Organization, *, email: str, role: str, invited_by: str | None,
           base_url: str | None = None) -> Issued:
    """Invite `email` to `org` (any session mode; the caller audits and commits).
    A pending invitation of the same address is replaced (its link stops working)."""
    from ..auth import normalize_email

    email = normalize_email(email)
    if "@" not in email or len(email) > 320:
        raise InvitationError("invalid email address")
    if role not in ROLES:
        raise InvitationError(f"role must be one of {', '.join(ROLES)}")
    if org.status != "active":
        raise InvitationError("the organisation is suspended", 409)
    if db.scalar(select(User.id).where(User.email == email)):
        raise InvitationError("an account with this email address already exists (one organisation per "
                              "account for now)", 409)
    now = utcnow()
    for old in db.scalars(select(OrganizationInvitation).where(
            OrganizationInvitation.organization_id == org.id, OrganizationInvitation.email == email,
            OrganizationInvitation.accepted_at.is_(None), OrganizationInvitation.revoked_at.is_(None))
            .execution_options(tenant_unscoped=True)):
        old.revoked_at = now
    inv = OrganizationInvitation(organization_id=org.id, email=email, role=role, invited_by=invited_by,
                                 created_at=now, sent_count=0)
    raw = _issue_token(inv, now)
    db.add(inv)
    db.flush()
    return _send(org, inv, invite_url(raw, base_url), invited_by, now)


def resend(db: Session, org: Organization, inv: OrganizationInvitation, *, invited_by: str | None,
           base_url: str | None = None) -> Issued:
    """New link and expiry for a pending or expired invitation (the old link stops working)."""
    if inv.accepted_at or inv.revoked_at:
        raise InvitationError(f"the invitation is {state(inv)}", 409)
    if org.status != "active":
        raise InvitationError("the organisation is suspended", 409)
    now = utcnow()
    raw = _issue_token(inv, now)
    return _send(org, inv, invite_url(raw, base_url), invited_by, now)


def find(db: Session, token: str) -> tuple[OrganizationInvitation, Organization] | None:
    """Usable invitation for `token` with its organisation (any session mode)."""
    if not token or not token.startswith(TOKEN_PREFIX) or len(token) > 128:
        return None
    row = db.execute(select(OrganizationInvitation, Organization)
                     .join(Organization, Organization.id == OrganizationInvitation.organization_id)
                     .where(OrganizationInvitation.token_hash == hash_token(token))
                     .execution_options(tenant_unscoped=True)).first()
    if row is None:
        return None
    inv, org = row
    if state(inv) != "pending" or org.status != "active":
        return None
    return inv, org


def accept(db: Session, token: str, *, name: str, password: str) -> tuple[User, Organization]:
    """Create the account and membership for a pending invitation. Scopes `db`
    to the organisation; the caller creates the session, audits and commits."""
    from ..auth import hash_password, password_problem, set_membership

    found = find(db, token)
    if found is None:
        raise InvitationError("this invitation link is invalid, expired or already used", 410)
    inv, org = found
    problem = password_problem(password)
    if problem:
        raise InvitationError(problem)
    if db.scalar(select(User.id).where(User.email == inv.email)):
        raise InvitationError("an account with this email address already exists: sign in instead", 409)
    tenancy.set_org(db, org.id)
    inv = db.get(OrganizationInvitation, inv.id)
    now = utcnow()
    user = User(email=inv.email, name=(name or "").strip()[:128], password_hash=hash_password(password),
                password_changed_at=now)
    db.add(user)
    db.flush()
    set_membership(db, user, org.id, inv.role)
    inv.accepted_at, inv.accepted_user_id = now, user.id
    return user, org
