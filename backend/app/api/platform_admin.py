"""Platform console (/api/platform/*): platform owners list, create, suspend
and reactivate organisations, see their usage and (re)send invitations.
Separate from organisation roles; the request's session is unscoped
(app/auth.py:require_platform_admin). Every action is audited in the
affected organisation's log. There is no impersonation."""
from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import mailer
from ..auth import audit, client_ip, require_platform_admin
from ..db import get_db
from ..models import Organization, OrganizationInvitation, OrganizationMembership, User, utcnow
from ..schemas import UTCDateTime
from ..services import invitations as inv_svc
from ..services import organizations as orgs
from .invitations import InvitationOut, IssuedOut, inv_out, issued_out, request_base
from .organization import OrganizationOut

router = APIRouter(prefix="/api/platform", tags=["platform-admin"], dependencies=[Depends(require_platform_admin)])
OrgId = Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{1,32}$")]
Role = Literal["viewer", "analyst", "admin"]
Email = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=320,
                                         pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")]


class Usage(BaseModel):
    users: int = 0
    devices: int = 0
    assets: int = 0
    scans: int = 0


class PlatformOrg(OrganizationOut):
    updated_at: UTCDateTime | None = None
    suspended_at: UTCDateTime | None = None
    suspended_reason: str | None = None
    created_by: str | None = None
    usage: Usage = Field(default_factory=Usage)
    pending_invitations: int = 0


class Member(BaseModel):
    id: str
    email: str
    name: str
    role: str
    is_active: bool
    last_login_at: UTCDateTime | None = None


class PlatformOrgDetail(PlatformOrg):
    members: list[Member] = []
    invitations: list[InvitationOut] = []


class OrgCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    slug: Annotated[str, StringConstraints(max_length=64)] | None = None
    contact_email: Email | None = None
    plan: Annotated[str, StringConstraints(max_length=32)] | None = None
    # The first admin, invited by email.
    admin_email: Email


class OrgUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: Annotated[str, StringConstraints(min_length=1, max_length=128)] | None = None
    contact_email: Annotated[str, StringConstraints(max_length=320)] | None = None
    logo_url: Annotated[str, StringConstraints(max_length=1024, pattern=r"^$|^https://\S+$")] | None = None
    plan: Annotated[str, StringConstraints(max_length=32)] | None = None
    max_users: int | None = Field(None, ge=0, le=1_000_000)
    max_devices: int | None = Field(None, ge=0, le=10_000_000)


class StatusIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    reason: Annotated[str, StringConstraints(max_length=500)] = ""


class PlatformInviteIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    email: Email
    role: Role = "admin"


class CreatedOut(BaseModel):
    organization: PlatformOrg
    invitation: IssuedOut


def _pending_counts(db: Session) -> dict[str, int]:
    now = utcnow()
    out: dict[str, int] = {}
    for inv in db.scalars(select(OrganizationInvitation).where(OrganizationInvitation.accepted_at.is_(None),
                                                               OrganizationInvitation.revoked_at.is_(None),
                                                               OrganizationInvitation.expires_at > now)):
        out[inv.organization_id] = out.get(inv.organization_id, 0) + 1
    return out


def _org_out(org: Organization, usage: dict | None, pending: int = 0) -> PlatformOrg:
    out = PlatformOrg.model_validate(org, from_attributes=True)
    out.usage = Usage(**(usage or {}))
    out.pending_invitations = pending
    return out


def _get(db: Session, org_id: str) -> Organization:
    org = db.get(Organization, org_id)
    if org is None:
        raise HTTPException(404, "organisation not found")
    return org


@router.get("/organizations", response_model=list[PlatformOrg])
def list_organizations(db: Session = Depends(get_db)):
    pending = _pending_counts(db)
    return [_org_out(o, u, pending.get(o.id, 0)) for o, u in orgs.list_with_usage(db)]


@router.get("/mail")
def mail_status():
    return {"configured": mailer.configured()}


@router.post("/organizations", response_model=CreatedOut, status_code=201)
def create_organization(body: OrgCreate, request: Request, admin: User = Depends(require_platform_admin),
                        db: Session = Depends(get_db)):
    """Create an organisation and invite its first admin by email (the link is
    returned instead when no platform mail server is configured)."""
    try:
        org = orgs.create_organization(db, name=body.name, slug=body.slug or None, contact_email=body.contact_email,
                                       plan=body.plan, created_by=admin.email)
        issued = inv_svc.create(db, org, email=body.admin_email, role="admin", invited_by=admin.email,
                                base_url=request_base(request))
    except inv_svc.InvitationError as e:
        db.rollback()
        raise HTTPException(e.status, str(e)) from None
    except orgs.OrgError as e:
        db.rollback()
        raise HTTPException(409 if "already exists" in str(e) else 422, str(e)) from None
    audit(db, "organization_created", actor=admin, target=f"organization:{org.slug}", ip=client_ip(request),
          organization_id=org.id, name=org.name, admin_email=issued.invitation.email, emailed=issued.emailed)
    db.commit()
    return CreatedOut(organization=_org_out(org, None, 1), invitation=issued_out(issued))


@router.get("/organizations/{org_id}", response_model=PlatformOrgDetail)
def get_organization(org_id: OrgId, db: Session = Depends(get_db)):
    org = _get(db, org_id)
    out = PlatformOrgDetail(**_org_out(org, orgs.usage(db).get(org.id), _pending_counts(db).get(org.id, 0))
                            .model_dump())
    rows = db.execute(select(User, OrganizationMembership.role)
                      .join(OrganizationMembership, OrganizationMembership.user_id == User.id)
                      .where(OrganizationMembership.organization_id == org.id).order_by(User.email))
    out.members = [Member(id=u.id, email=u.email, name=u.name, role=role, is_active=u.is_active,
                          last_login_at=u.last_login_at) for u, role in rows]
    out.invitations = [inv_out(i) for i in db.scalars(
        select(OrganizationInvitation).where(OrganizationInvitation.organization_id == org.id)
        .order_by(OrganizationInvitation.created_at.desc()).limit(200))]
    return out


@router.patch("/organizations/{org_id}", response_model=PlatformOrg)
def update_organization(org_id: OrgId, body: OrgUpdate, request: Request,
                        admin: User = Depends(require_platform_admin), db: Session = Depends(get_db)):
    org = _get(db, org_id)
    changes: dict[str, list] = {}
    for f in body.model_fields_set:
        v = getattr(body, f)
        if isinstance(v, str):
            v = v or None
        if f == "name" and not v:
            continue
        if v != getattr(org, f):
            changes[f] = [getattr(org, f), v]
            setattr(org, f, v)
    if changes:
        org.updated_at = utcnow()
        audit(db, "organization_updated", actor=admin, target=f"organization:{org.slug}", ip=client_ip(request),
              organization_id=org.id, changes=changes, by="platform")
        db.commit()
    return _org_out(org, orgs.usage(db).get(org.id), _pending_counts(db).get(org.id, 0))


def _set_status(db: Session, org_id: str, status: str, reason: str, admin: User, request: Request) -> PlatformOrg:
    org = _get(db, org_id)
    if org.status != status:
        try:
            orgs.set_status(db, org, status, reason)
        except orgs.OrgError as e:
            raise HTTPException(409, str(e)) from None
        audit(db, "organization_suspended" if status == "suspended" else "organization_reactivated", actor=admin,
              target=f"organization:{org.slug}", ip=client_ip(request), organization_id=org.id, reason=reason)
        db.commit()
    return _org_out(org, orgs.usage(db).get(org.id), _pending_counts(db).get(org.id, 0))


@router.post("/organizations/{org_id}/suspend", response_model=PlatformOrg)
def suspend(org_id: OrgId, body: StatusIn, request: Request, admin: User = Depends(require_platform_admin),
            db: Session = Depends(get_db)):
    """Suspend: its users are signed out and cannot sign in, its agents and
    sensors are refused, background jobs skip it. Data is kept."""
    return _set_status(db, org_id, "suspended", body.reason, admin, request)


@router.post("/organizations/{org_id}/activate", response_model=PlatformOrg)
def activate(org_id: OrgId, body: StatusIn, request: Request, admin: User = Depends(require_platform_admin),
             db: Session = Depends(get_db)):
    return _set_status(db, org_id, "active", body.reason, admin, request)


@router.post("/organizations/{org_id}/invitations", response_model=IssuedOut, status_code=201)
def invite(org_id: OrgId, body: PlatformInviteIn, request: Request, admin: User = Depends(require_platform_admin),
           db: Session = Depends(get_db)):
    org = _get(db, org_id)
    try:
        issued = inv_svc.create(db, org, email=body.email, role=body.role, invited_by=admin.email,
                                base_url=request_base(request))
    except inv_svc.InvitationError as e:
        raise HTTPException(e.status, str(e)) from None
    audit(db, "user_invited", actor=admin, target=issued.invitation.email, ip=client_ip(request),
          organization_id=org.id, role=body.role, emailed=issued.emailed, by="platform")
    db.commit()
    return issued_out(issued)


@router.post("/organizations/{org_id}/invitations/{inv_id}/resend", response_model=IssuedOut)
def resend(org_id: OrgId, request: Request, inv_id: str = Path(pattern=r"^[0-9a-f]{32}$"),
           admin: User = Depends(require_platform_admin), db: Session = Depends(get_db)):
    org = _get(db, org_id)
    inv = db.get(OrganizationInvitation, inv_id)
    if inv is None or inv.organization_id != org.id:
        raise HTTPException(404, "invitation not found")
    try:
        issued = inv_svc.resend(db, org, inv, invited_by=admin.email, base_url=request_base(request))
    except inv_svc.InvitationError as e:
        raise HTTPException(e.status, str(e)) from None
    audit(db, "user_invitation_resent", actor=admin, target=inv.email, ip=client_ip(request),
          organization_id=org.id, emailed=issued.emailed, by="platform")
    db.commit()
    return issued_out(issued)
