"""Platform console (/api/platform/*): platform owners list, create, suspend
and reactivate organisations, see their usage and (re)send invitations.
Separate from organisation roles; the request's session is unscoped
(app/auth.py:require_platform_admin). Every action is audited in the
affected organisation's log. There is no impersonation."""
from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import mailer
from ..auth import audit, client_ip, require_platform_admin
from ..db import get_db
from ..models import AuditLog, Organization, OrganizationInvitation, OrganizationMembership, User, utcnow
from ..modules import enabled_modules
from ..schemas import AuditLogOut, UTCDateTime
from ..services import invitations as inv_svc
from ..services import organizations as orgs
from .invitations import InvitationOut, IssuedOut, inv_out, issued_out, request_base
from .organization import OrganizationOut

router = APIRouter(prefix="/api/platform", tags=["platform-admin"], dependencies=[Depends(require_platform_admin)])
OrgId = Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{1,32}$")]
Role = Literal["viewer", "analyst", "admin"]
ModuleKey = Literal["cloud", "endpoints", "vulnerabilities", "assets", "external"]  # app/modules.py
Email = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=320,
                                         pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")]


class Usage(BaseModel):
    users: int = 0
    devices: int = 0
    assets: int = 0
    scans: int = 0


class PlatformOrg(OrganizationOut):
    kind: str = "customer"
    partner_org_id: str | None = None
    max_clients: int | None = None
    clients: int = 0  # MSP organisations: client organisations managed
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
    # Product modules switched on from the start (none by default).
    modules: list[ModuleKey] = []
    # "msp": a partner that manages client organisations (docs/MSP.md). Only the platform owner can create one.
    kind: Literal["customer", "msp"] = "customer"
    max_clients: int | None = Field(None, ge=0, le=100_000)  # MSP only; null = unlimited
    # Create the organisation as a client of this MSP.
    partner_org_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,32}$")] | None = None


class OrgUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: Annotated[str, StringConstraints(min_length=1, max_length=128)] | None = None
    contact_email: Annotated[str, StringConstraints(max_length=320)] | None = None
    logo_url: Annotated[str, StringConstraints(max_length=1024, pattern=r"^$|^https://\S+$")] | None = None
    plan: Annotated[str, StringConstraints(max_length=32)] | None = None
    max_users: int | None = Field(None, ge=0, le=1_000_000)
    max_devices: int | None = Field(None, ge=0, le=10_000_000)
    max_clients: int | None = Field(None, ge=0, le=100_000)  # MSP only
    kind: Literal["customer", "msp"] | None = None  # mark / unmark an organisation as an MSP


class PartnerIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # The MSP that manages the organisation; null ends the partnership (the MSP's staff lose access at once).
    partner_org_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,32}$")] | None = None


class ModuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


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


def _client_counts(db: Session) -> dict[str, int]:
    return {pid: n for pid, n in db.execute(select(Organization.partner_org_id, func.count())
                                            .where(Organization.partner_org_id.is_not(None))
                                            .group_by(Organization.partner_org_id))}


def _org_out(org: Organization, usage: dict | None, pending: int = 0, db: Session | None = None) -> PlatformOrg:
    out = PlatformOrg.model_validate(org, from_attributes=True)
    if db is not None and org.kind == "msp":
        out.clients = _client_counts(db).get(org.id, 0)
    out.usage = Usage(**(usage or {}))
    out.pending_invitations = pending
    return out


def _require_msp(db: Session, org_id: str) -> Organization:
    msp = db.get(Organization, org_id)
    if msp is None or msp.kind != "msp":
        raise HTTPException(422, "partner_org_id must be an MSP organisation")
    return msp


def _get(db: Session, org_id: str) -> Organization:
    org = db.get(Organization, org_id)
    if org is None:
        raise HTTPException(404, "organisation not found")
    return org


@router.get("/organizations", response_model=list[PlatformOrg])
def list_organizations(db: Session = Depends(get_db)):
    pending = _pending_counts(db)
    counts = _client_counts(db)
    rows = [_org_out(o, u, pending.get(o.id, 0)) for o, u in orgs.list_with_usage(db)]
    for r in rows:
        r.clients = counts.get(r.id, 0)
    return rows


@router.get("/mail")
def mail_status():
    return {"configured": mailer.configured()}


@router.post("/organizations", response_model=CreatedOut, status_code=201)
def create_organization(body: OrgCreate, request: Request, admin: User = Depends(require_platform_admin),
                        db: Session = Depends(get_db)):
    """Create an organisation and invite its first admin by email (the link is
    returned instead when no platform mail server is configured)."""
    try:
        if body.kind == "msp" and body.partner_org_id:
            raise HTTPException(422, "an MSP cannot be a client of another MSP")
        if body.partner_org_id:
            _require_msp(db, body.partner_org_id)
        org = orgs.create_organization(db, name=body.name, slug=body.slug or None, contact_email=body.contact_email,
                                       plan=body.plan, created_by=admin.email, modules=body.modules, kind=body.kind,
                                       partner_org_id=body.partner_org_id,
                                       max_clients=body.max_clients if body.kind == "msp" else None)
        issued = inv_svc.create(db, org, email=body.admin_email, role="admin", invited_by=admin.email,
                                base_url=request_base(request))
    except inv_svc.InvitationError as e:
        db.rollback()
        raise HTTPException(e.status, str(e)) from None
    except orgs.OrgError as e:
        db.rollback()
        raise HTTPException(409 if "already exists" in str(e) else 422, str(e)) from None
    audit(db, "organization_created", actor=admin, target=f"organization:{org.slug}", ip=client_ip(request),
          organization_id=org.id, name=org.name, admin_email=issued.invitation.email, emailed=issued.emailed,
          modules=org.modules, kind=org.kind, max_clients=org.max_clients,
          # A client's partner is never shown to the client: flag the row (hidden from its audit-log API).
          via_partner_org_id=org.partner_org_id, partner_org_id=org.partner_org_id)
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
        if f == "kind":
            if v is None or v == org.kind:
                continue
            if org.is_default:
                raise HTTPException(409, "the default organisation cannot be an MSP")
            if v == "msp" and org.partner_org_id:
                raise HTTPException(409, "an organisation that is a client of an MSP cannot become an MSP")
            if v == "customer" and db.scalar(select(func.count()).select_from(Organization)
                                            .where(Organization.partner_org_id == org.id)):
                raise HTTPException(409, "this MSP still has clients: move them away first")
        if f == "max_clients" and org.kind != "msp" and "kind" not in body.model_fields_set:
            raise HTTPException(409, "max_clients applies to MSP organisations only")
        if v != getattr(org, f):
            changes[f] = [getattr(org, f), v]
            setattr(org, f, v)
    if changes:
        org.updated_at = utcnow()
        audit(db, "organization_updated", actor=admin, target=f"organization:{org.slug}", ip=client_ip(request),
              organization_id=org.id, changes=changes, by="platform")
        db.commit()
    return _org_out(org, orgs.usage(db).get(org.id), _pending_counts(db).get(org.id, 0), db)


@router.put("/organizations/{org_id}/partner", response_model=PlatformOrg)
def set_partner(org_id: OrgId, body: PartnerIn, request: Request, admin: User = Depends(require_platform_admin),
                db: Session = Depends(get_db)):
    """Make an organisation a client of an MSP, move it to another one, or end the partnership (null).
    Only the platform owner can do this; the MSP's staff lose access to the client immediately."""
    org = _get(db, org_id)
    if org.is_default or org.kind != "customer":
        raise HTTPException(409, "only customer organisations (not the default one) can be clients of an MSP")
    old = org.partner_org_id
    if body.partner_org_id:
        msp = _require_msp(db, body.partner_org_id)
        if msp.max_clients is not None and old != msp.id and db.scalar(
                select(func.count()).select_from(Organization).where(Organization.partner_org_id == msp.id)) >= msp.max_clients:
            raise HTTPException(409, "this MSP has reached its client limit")
    if body.partner_org_id != old:
        org.partner_org_id = body.partner_org_id
        org.updated_at = utcnow()
        # Hidden from the client's audit-log API; the platform owner sees it.
        audit(db, "organization_partner_changed", actor=admin, target=f"organization:{org.slug}",
              ip=client_ip(request), organization_id=org.id, via_partner_org_id=body.partner_org_id or old,
              before=old, after=body.partner_org_id)
        for msp_id in {i for i in (old, body.partner_org_id) if i}:
            audit(db, "msp_client_partnership_changed", actor=admin, target=f"organization:{org.slug}",
                  ip=client_ip(request), organization_id=msp_id, before=old, after=body.partner_org_id)
        db.commit()
    return _org_out(org, orgs.usage(db).get(org.id), _pending_counts(db).get(org.id, 0), db)


class PlatformAuditOut(AuditLogOut):
    via_partner_org_id: str | None = None


@router.get("/organizations/{org_id}/audit-log", response_model=list[PlatformAuditOut])
def organization_audit_log(org_id: OrgId, db: Session = Depends(get_db), limit: int = Query(200, ge=1, le=2000),
                           via_partner: bool | None = Query(None, description="only (true) / without (false) "
                                                                              "actions by MSP staff")):
    """The organisation's complete audit log, including what MSP staff did inside it (platform owner only;
    the organisation's own audit-log API hides those rows)."""
    org = _get(db, org_id)
    stmt = select(AuditLog).where(AuditLog.organization_id == org.id)
    if via_partner is True:
        stmt = stmt.where(AuditLog.via_partner_org_id.is_not(None))
    elif via_partner is False:
        stmt = stmt.where(AuditLog.via_partner_org_id.is_(None))
    return list(db.scalars(stmt.order_by(AuditLog.id.desc()).limit(limit)))


@router.put("/organizations/{org_id}/modules/{module}", response_model=PlatformOrg)
def set_module(body: ModuleIn, request: Request, org_id: OrgId, module: ModuleKey,
               admin: User = Depends(require_platform_admin), db: Session = Depends(get_db)):
    """Switch one product module on or off for an organisation. Off hides it and
    refuses its APIs; the data is kept and shows again when it is switched back on."""
    org = _get(db, org_id)
    on = set(enabled_modules(org))
    if body.enabled:
        on.add(module)
    else:
        on.discard(module)
    turned_on, turned_off = orgs.set_modules(org, on)
    for m in turned_on + turned_off:
        audit(db, "org_module_enabled" if m in turned_on else "org_module_disabled", actor=admin,
              target=f"organization:{org.slug}", ip=client_ip(request), organization_id=org.id, module=m,
              by="platform")
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
