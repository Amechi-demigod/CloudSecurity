"""The console's "Getting started" checklist for a new organisation
(GET /api/organization/onboarding, docs/MULTI_TENANCY.md).

Every step is detected from the organisation's own data: the queries run on the
request's session, which app/tenancy.py scopes to the session's organisation,
so another organisation's rows can never mark a step done. Only "Secure your
account" is personal (the signed-in user's MFA). An organisation admin can
dismiss the checklist for the whole organisation.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import ConnectorConfig, Device, OrganizationInvitation, OrganizationMembership, ScanRun, User, utcnow
from ..notifications.models import NotificationChannel

#: Step keys in display order (the console maps each to the page where it is done).
STEPS = ("mfa", "team", "cloud", "agent", "scan", "alerts")


def _any(db: Session, model, *where) -> bool:
    # Selecting the entity's own column keeps the statement ORM-scoped (tenant filter applied).
    return db.scalar(select(model.organization_id).where(*where).limit(1)) is not None


def steps(db: Session, user: User) -> dict[str, bool]:
    """Done flag per step for `user` in the session's organisation."""
    now = utcnow()
    return {
        "mfa": user.mfa_enabled,
        # Someone besides the user: another member, or an invitation still open.
        "team": _any(db, OrganizationMembership, OrganizationMembership.user_id != user.id) or _any(
            db, OrganizationInvitation, OrganizationInvitation.accepted_at.is_(None),
            OrganizationInvitation.revoked_at.is_(None), OrganizationInvitation.expires_at > now),
        # Stored credentials for a provider (the environment fallback is the default organisation's only).
        "cloud": _any(db, ConnectorConfig, ConnectorConfig.enabled.is_(True)),
        # An enrolled device; an enrollment token on its own does not count.
        "agent": _any(db, Device, Device.status == "active"),
        "scan": _any(db, ScanRun, ScanRun.status == "succeeded"),
        "alerts": _any(db, NotificationChannel, NotificationChannel.enabled.is_(True)),
    }
