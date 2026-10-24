"""Organisations (tenants): creation, status and usage counts for the platform
console and the CLI. All functions expect an unscoped session (platform
access) unless stated otherwise; callers commit."""
from __future__ import annotations

import re

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Asset, Device, Organization, OrganizationMembership, ScanRun, User, utcnow

SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
RESERVED_SLUGS = frozenset({"api", "admin", "platform", "login", "invite", "system", "www", "static"})


class OrgError(ValueError):
    pass


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return slug[:64].strip("-") or "org"


def validate_slug(slug: str) -> str:
    slug = slug.strip().lower()
    if not SLUG_RE.match(slug):
        raise OrgError("slug must be 1-64 lowercase letters, digits or '-' (not starting or ending with '-')")
    if slug in RESERVED_SLUGS:
        raise OrgError(f"slug {slug!r} is reserved")
    return slug


def create_organization(db: Session, *, name: str, slug: str | None = None, contact_email: str | None = None,
                        logo_url: str | None = None, plan: str | None = None, created_by: str | None = None
                        ) -> Organization:
    name = name.strip()
    if not name:
        raise OrgError("name is required")
    slug = validate_slug(slug or slugify(name))
    if db.scalar(select(Organization.id).where(Organization.slug == slug)):
        raise OrgError(f"an organisation with slug {slug!r} already exists")
    org = Organization(name=name[:128], slug=slug, contact_email=(contact_email or "").strip().lower() or None,
                       logo_url=logo_url or None, plan=plan or None, status="active", is_default=False,
                       created_by=created_by)
    db.add(org)
    db.flush()
    return org


def set_status(db: Session, org: Organization, status: str, reason: str | None = None) -> None:
    if status not in ("active", "suspended"):
        raise OrgError("status must be active or suspended")
    if status == "suspended" and org.is_default:
        raise OrgError("the default organisation cannot be suspended")
    org.status = status
    org.suspended_at = utcnow() if status == "suspended" else None
    org.suspended_reason = (reason or "")[:500] or None if status == "suspended" else None
    org.updated_at = utcnow()


def usage(db: Session) -> dict[str, dict[str, int]]:
    """Per organisation: users, active devices, cloud assets, scans (one query each)."""
    out: dict[str, dict[str, int]] = {}

    def add(key: str, rows) -> None:
        for oid, n in rows:
            out.setdefault(oid, {"users": 0, "devices": 0, "assets": 0, "scans": 0})[key] = n

    add("users", db.execute(select(OrganizationMembership.organization_id, func.count())
                            .join(User, User.id == OrganizationMembership.user_id)
                            .where(User.is_active.is_(True)).group_by(OrganizationMembership.organization_id)))
    add("devices", db.execute(select(Device.organization_id, func.count()).where(Device.status == "active")
                              .group_by(Device.organization_id)))
    add("assets", db.execute(select(Asset.organization_id, func.count()).group_by(Asset.organization_id)))
    add("scans", db.execute(select(ScanRun.organization_id, func.count()).group_by(ScanRun.organization_id)))
    return out


def list_with_usage(db: Session) -> list[tuple[Organization, dict[str, int]]]:
    counts = usage(db)
    orgs = db.scalars(select(Organization).order_by(Organization.is_default.desc(), Organization.name))
    empty = {"users": 0, "devices": 0, "assets": 0, "scans": 0}
    return [(o, counts.get(o.id, dict(empty))) for o in orgs]
