"""MSP accounts (/api/msp/*, docs/MSP.md): a managed service provider's staff list and manage their client
organisations and switch into one to work in it.

Access is derived from the partner relationship (`Organization.partner_org_id`), never from a membership in
the client. Every client is looked up through `auth.partner_client`, so an id that is not one of the caller's
clients (another MSP's client, a plain customer, the default organisation, a made-up id) is "not found".
Platform-level actions (creating an MSP, marking an organisation as one, moving a client between MSPs) are
platform-owner only (app/api/platform_admin.py)."""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import db as dbmod
from .. import tenancy
from ..auth import ROLE_RANK, audit, client_ip, current_session, leave_acting, partner_client
from ..db import get_db
from ..models import Finding, Organization, OrganizationInvitation, ScanRun, User, UserSession, utcnow
from ..modules import enabled_modules
from ..schemas import UTCDateTime
from ..services import invitations as inv_svc
from ..services import organizations as orgs
from .invitations import InvitationOut, IssuedOut, inv_out, issued_out, request_base
from .organization import OrganizationOut

router = APIRouter(prefix="/api/msp", tags=["msp"])
ClientId = Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{1,32}$")]
Role = Literal["viewer", "analyst", "admin"]
ModuleKey = Literal["cloud", "endpoints", "vulnerabilities", "assets", "external"]  # app/modules.py
Email = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=320,
                                         pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")]
OVERVIEW_CAP = 100  # the overview computes its numbers client by client: at most this many per request


@dataclass
class Msp:
    """The calling MSP staff member, with their MSP organisation and role in it."""
    user: User
    org: Organization
    sess: UserSession


def msp_staff(minimum: str = "viewer"):
    """Dependency: the caller is staff of an active MSP organisation with at least `minimum` role there.
    The request is scoped to the MSP's own organisation (even while the session works in a client)."""
    rank = ROLE_RANK[minimum]

    def dep(sess: UserSession = Depends(current_session), db: Session = Depends(get_db)) -> Msp:
        home = db.get(Organization, sess.organization_id)
        role = sess.user.role  # the role in the MSP (the real user, not the client stand-in)
        if home is None or home.kind != "msp" or home.status != "active":
            raise HTTPException(403, "requires an MSP account")
        if ROLE_RANK.get(role, -1) < rank:
            raise HTTPException(403, f"requires the {minimum} role")
        sess = leave_acting(db, sess)
        return Msp(sess.user, db.get(Organization, home.id), sess)

    dep.__name__ = f"msp_staff_{minimum}"
    return dep


staff = msp_staff("viewer")
staff_admin = msp_staff("admin")


# ----------------------------------------------------------------------------- schemas
class ClientOut(OrganizationOut):
    updated_at: UTCDateTime | None = None
    # Whether the MSP may reactivate it (not when the platform owner suspended it).
    suspended_at: UTCDateTime | None = None
    suspended_reason: str | None = None
    can_reactivate: bool = False
    pending_invitations: int = 0


class ClientCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    contact_email: Email
    # The MSP may switch on any module for any client.
    modules: list[ModuleKey] = []
    # Optional: invite the client's first admin right away (or use POST .../invitations later).
    admin_email: Email | None = None


class ClientUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: Annotated[str, StringConstraints(min_length=1, max_length=128)] | None = None
    contact_email: Email | None = None


class ModulesIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    modules: list[ModuleKey]


class ReasonIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    reason: Annotated[str, StringConstraints(max_length=500)] = ""


class InviteIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    email: Email
    role: Role = "admin"


class SwitchIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # A client's id, or null to go back to the MSP's own organisation.
    organization_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,32}$")] | None = None


class MspOut(BaseModel):
    organization: OrganizationOut
    role: str
    max_clients: int | None = None
    clients: int
    acting_as_client: bool


class CreatedClientOut(BaseModel):
    client: ClientOut
    invitation: IssuedOut | None = None


# ----------------------------------------------------------------------------- helpers
def _client(db: Session, msp: Msp, client_id: str) -> Organization:
    with tenancy.unscoped(db):
        client = partner_client(db, msp.org.id, client_id)
    if client is None:
        raise HTTPException(404, "client not found")
    return client


def _pending(db: Session, client_ids: list[str]) -> dict[str, int]:
    if not client_ids:
        return {}
    now = utcnow()
    with tenancy.unscoped(db):
        rows = db.execute(select(OrganizationInvitation.organization_id, func.count())
                          .where(OrganizationInvitation.organization_id.in_(client_ids),
                                 OrganizationInvitation.accepted_at.is_(None),
                                 OrganizationInvitation.revoked_at.is_(None),
                                 OrganizationInvitation.expires_at > now)
                          .group_by(OrganizationInvitation.organization_id))
        return {oid: n for oid, n in rows}


def _out(org: Organization, pending: int = 0) -> ClientOut:
    out = ClientOut.model_validate(org, from_attributes=True)
    out.pending_invitations = pending
    out.can_reactivate = org.status == "suspended" and org.status_set_by == "partner"
    return out


def _count_clients(db: Session, msp_id: str) -> int:
    return db.scalar(select(func.count()).select_from(Organization).where(Organization.partner_org_id == msp_id)) or 0


def _unique_slug(db: Session, name: str) -> str:
    base = orgs.slugify(name)[:50].strip("-") or "client"
    slug = base
    while db.scalar(select(Organization.id).where(Organization.slug == slug)) or slug in orgs.RESERVED_SLUGS:
        slug = f"{base}-{secrets.token_hex(2)}"  # never reveals that a slug is taken elsewhere
    return orgs.validate_slug(slug)


def _audit(db: Session, msp: Msp, request: Request, action: str, client: Organization | None = None, **detail) -> None:
    """MSP-level action: recorded in the MSP's own audit log."""
    audit(db, action, actor=msp.user, target=f"client:{client.slug}" if client else None, ip=client_ip(request),
          organization_id=msp.org.id, client_id=client.id if client else None, **detail)


# ----------------------------------------------------------------------------- the MSP itself
@router.get("", response_model=MspOut)
def get_msp(m: Msp = Depends(staff), db: Session = Depends(get_db)):
    return MspOut(organization=OrganizationOut.model_validate(m.org), role=m.user.role,
                  max_clients=m.org.max_clients, clients=_count_clients(db, m.org.id),
                  acting_as_client=bool(m.sess.acting_org_id))


@router.post("/switch", response_model=MspOut)
def switch(body: SwitchIn, request: Request, m: Msp = Depends(staff), db: Session = Depends(get_db)):
    """Work inside one of the MSP's clients (every other console API then acts in that client, with the
    caller's MSP role), or go back to the MSP's own organisation (`organization_id` null). An id that is
    not one of this MSP's clients is "not found"."""
    previous = m.sess.acting_org_id
    if body.organization_id is None:
        m.sess.acting_org_id = None
        if previous:
            _audit(db, m, request, "msp_client_left", _client_or_none(db, m, previous))
    else:
        client = _client(db, m, body.organization_id)
        if client.status != "active":
            raise HTTPException(409, "this client is suspended")
        m.sess.acting_org_id = client.id
        _audit(db, m, request, "msp_client_entered", client)
    db.commit()
    return MspOut(organization=OrganizationOut.model_validate(m.org), role=m.user.role,
                  max_clients=m.org.max_clients, clients=_count_clients(db, m.org.id),
                  acting_as_client=bool(m.sess.acting_org_id))


def _client_or_none(db: Session, m: Msp, client_id: str) -> Organization | None:
    with tenancy.unscoped(db):
        return partner_client(db, m.org.id, client_id)


# ----------------------------------------------------------------------------- clients
@router.get("/clients", response_model=list[ClientOut])
def list_clients(m: Msp = Depends(staff), db: Session = Depends(get_db)):
    rows = list(db.scalars(select(Organization).where(Organization.partner_org_id == m.org.id,
                                                      Organization.kind == "customer")
                           .order_by(Organization.name, Organization.id)))
    pending = _pending(db, [r.id for r in rows])
    return [_out(r, pending.get(r.id, 0)) for r in rows]


@router.post("/clients", response_model=CreatedClientOut, status_code=201)
def create_client(body: ClientCreate, request: Request, m: Msp = Depends(staff_admin),
                  db: Session = Depends(get_db)):
    """Create a client organisation (MSP admin). Any module can be switched on."""
    if m.org.max_clients is not None and _count_clients(db, m.org.id) >= m.org.max_clients:
        raise HTTPException(409, "client limit reached: ask the platform owner to raise it")
    issued = None
    with tenancy.unscoped(db):
        try:
            client = orgs.create_organization(db, name=body.name, slug=_unique_slug(db, body.name),
                                              contact_email=body.contact_email, created_by=None,
                                              modules=body.modules, partner_org_id=m.org.id)
            client.status_set_by = "partner"
            if body.admin_email:
                issued = inv_svc.create(db, client, email=body.admin_email, role="admin", invited_by=None,
                                        base_url=request_base(request))
            db.flush()  # rows of the client are written while the session is unscoped
        except inv_svc.InvitationError as e:
            db.rollback()
            raise HTTPException(e.status, str(e)) from None
        except orgs.OrgError as e:
            db.rollback()
            raise HTTPException(422, str(e)) from None
    _audit(db, m, request, "msp_client_created", client, name=client.name, modules=client.modules,
           admin_email=issued.invitation.email if issued else None)
    db.commit()
    return CreatedClientOut(client=_out(client, 1 if issued else 0), invitation=issued_out(issued) if issued else None)


@router.get("/clients/{client_id}", response_model=ClientOut)
def get_client(client_id: ClientId, m: Msp = Depends(staff), db: Session = Depends(get_db)):
    client = _client(db, m, client_id)
    return _out(client, _pending(db, [client.id]).get(client.id, 0))


@router.patch("/clients/{client_id}", response_model=ClientOut)
def update_client(client_id: ClientId, body: ClientUpdate, request: Request, m: Msp = Depends(staff_admin),
                  db: Session = Depends(get_db)):
    client = _client(db, m, client_id)
    changes: dict[str, list] = {}
    for f in ("name", "contact_email"):
        v = getattr(body, f)
        if v is None:
            continue
        v = v.lower() if f == "contact_email" else v
        if v != getattr(client, f):
            changes[f] = [getattr(client, f), v]
            setattr(client, f, v)
    if changes:
        client.updated_at = utcnow()
        _audit(db, m, request, "msp_client_updated", client, changes=changes)
        db.commit()
    return _out(client, _pending(db, [client.id]).get(client.id, 0))


@router.put("/clients/{client_id}/modules", response_model=ClientOut)
def set_client_modules(client_id: ClientId, body: ModulesIn, request: Request, m: Msp = Depends(staff_admin),
                       db: Session = Depends(get_db)):
    """Set the client's enabled modules (MSP admin; any module). Off hides a module, its data is kept."""
    client = _client(db, m, client_id)
    turned_on, turned_off = orgs.set_modules(client, body.modules)
    for mod in turned_on + turned_off:
        _audit(db, m, request, "msp_client_module_enabled" if mod in turned_on else "msp_client_module_disabled",
               client, module=mod)
    db.commit()
    return _out(client, _pending(db, [client.id]).get(client.id, 0))


@router.post("/clients/{client_id}/suspend", response_model=ClientOut)
def suspend_client(client_id: ClientId, body: ReasonIn, request: Request, m: Msp = Depends(staff_admin),
                   db: Session = Depends(get_db)):
    """Suspend a client: its users are signed out, its agents refused. MSP staff in it are moved out too."""
    client = _client(db, m, client_id)
    if client.status != "suspended":
        with tenancy.unscoped(db):
            orgs.set_status(db, client, "suspended", body.reason, by="partner")
        _audit(db, m, request, "msp_client_suspended", client, reason=body.reason)
        db.commit()
    return _out(client, _pending(db, [client.id]).get(client.id, 0))


@router.post("/clients/{client_id}/activate", response_model=ClientOut)
def activate_client(client_id: ClientId, body: ReasonIn, request: Request, m: Msp = Depends(staff_admin),
                    db: Session = Depends(get_db)):
    client = _client(db, m, client_id)
    if client.status == "suspended":
        if client.status_set_by != "partner":
            raise HTTPException(409, "this client was suspended by the platform owner")
        with tenancy.unscoped(db):
            orgs.set_status(db, client, "active", body.reason, by="partner")
        _audit(db, m, request, "msp_client_reactivated", client, reason=body.reason)
        db.commit()
    return _out(client, _pending(db, [client.id]).get(client.id, 0))


# ----------------------------------------------------------------------------- invitations of a client's admins
@router.get("/clients/{client_id}/invitations", response_model=list[InvitationOut])
def list_client_invitations(client_id: ClientId, m: Msp = Depends(staff_admin), db: Session = Depends(get_db)):
    client = _client(db, m, client_id)
    with tenancy.unscoped(db):
        rows = db.scalars(select(OrganizationInvitation).where(OrganizationInvitation.organization_id == client.id)
                          .order_by(OrganizationInvitation.created_at.desc()).limit(200))
        return [inv_out(i) for i in rows]


@router.post("/clients/{client_id}/invitations", response_model=IssuedOut, status_code=201)
def invite_client_user(client_id: ClientId, body: InviteIn, request: Request, m: Msp = Depends(staff_admin),
                       db: Session = Depends(get_db)):
    """Invite a person into the client (normally its first admin). Same flow as any invitation: single-use
    link by email (or returned when no mail server is configured); the email names the brand only."""
    client = _client(db, m, client_id)
    try:
        with tenancy.unscoped(db):
            issued = inv_svc.create(db, client, email=body.email, role=body.role, invited_by=None,
                                    base_url=request_base(request))
            db.flush()
    except inv_svc.InvitationError as e:
        raise HTTPException(e.status, str(e)) from None
    _audit(db, m, request, "msp_client_user_invited", client, email=issued.invitation.email, role=body.role,
           emailed=issued.emailed)
    db.commit()
    return issued_out(issued)


@router.post("/clients/{client_id}/invitations/{inv_id}/resend", response_model=IssuedOut)
def resend_client_invitation(client_id: ClientId, request: Request, inv_id: str = Path(pattern=r"^[0-9a-f]{32}$"),
                             m: Msp = Depends(staff_admin), db: Session = Depends(get_db)):
    client = _client(db, m, client_id)
    with tenancy.unscoped(db):
        inv = db.get(OrganizationInvitation, inv_id)
        if inv is None or inv.organization_id != client.id:
            raise HTTPException(404, "invitation not found")
        try:
            issued = inv_svc.resend(db, client, inv, invited_by=None, base_url=request_base(request))
        except inv_svc.InvitationError as e:
            raise HTTPException(e.status, str(e)) from None
        db.flush()
    _audit(db, m, request, "msp_client_invitation_resent", client, email=inv.email, emailed=issued.emailed)
    db.commit()
    return issued_out(issued)


# ----------------------------------------------------------------------------- all-clients overview
class ClientOverview(BaseModel):
    id: str
    name: str
    status: str
    modules: list[str]
    users: int | None = None
    devices: int | None = None
    assets: int | None = None
    open_critical_findings: int | None = None
    risk_score: float | int | None = None
    last_scan_at: UTCDateTime | None = None
    last_scan_status: str | None = None
    error: str | None = None


class OverviewOut(BaseModel):
    clients: list[ClientOverview]
    total_clients: int
    # True when more clients exist than `limit` (use offset): the numbers are computed per client.
    truncated: bool


@router.get("/overview", response_model=OverviewOut)
def overview(m: Msp = Depends(staff), db: Session = Depends(get_db),
             limit: int = Query(OVERVIEW_CAP, ge=1, le=OVERVIEW_CAP), offset: int = Query(0, ge=0)):
    """Per client: status, modules and headline numbers (risk score, open critical findings, devices, assets,
    last scan). Cheap counts come from one grouped query each; the risk score is computed per client by the
    dashboards service, which is why a request covers at most OVERVIEW_CAP clients (page with offset).
    Suspended clients are listed without numbers."""
    total = _count_clients(db, m.org.id)
    clients = list(db.scalars(select(Organization).where(Organization.partner_org_id == m.org.id,
                                                         Organization.kind == "customer")
                              .order_by(Organization.name, Organization.id).offset(offset).limit(limit)))
    ids = [c.id for c in clients]
    with tenancy.unscoped(db):
        counts = orgs.usage(db) if ids else {}
        crit = {oid: n for oid, n in db.execute(
            select(Finding.organization_id, func.count())
            .where(Finding.organization_id.in_(ids), Finding.status == "open", Finding.severity == "critical")
            .group_by(Finding.organization_id))} if ids else {}
        last = {}
        if ids:
            for oid, started in db.execute(select(ScanRun.organization_id, func.max(ScanRun.started_at))
                                           .where(ScanRun.organization_id.in_(ids)).group_by(ScanRun.organization_id)):
                last[oid] = started
        last_status = {}
        for oid, started in last.items():
            last_status[oid] = db.scalar(select(ScanRun.status).where(ScanRun.organization_id == oid,
                                                                      ScanRun.started_at == started).limit(1))
    out = []
    for c in clients:
        mods = enabled_modules(c)
        row = ClientOverview(id=c.id, name=c.name, status=c.status, modules=mods)
        if c.status == "active":
            u = counts.get(c.id, {})
            row.users, row.devices, row.assets = u.get("users", 0), u.get("devices", 0), u.get("assets", 0)
            row.open_critical_findings = crit.get(c.id, 0)
            row.last_scan_at, row.last_scan_status = last.get(c.id), last_status.get(c.id)
            row.risk_score = _risk_score(c.id)
            if row.risk_score is None and any(x in mods for x in ("cloud", "vulnerabilities", "endpoints")):
                row.error = "risk score unavailable"
        out.append(row)
    return OverviewOut(clients=out, total_clients=total, truncated=total > offset + len(clients))


def _risk_score(client_id: str):
    """The client's risk score from the dashboards service (its own, client-scoped session)."""
    from ..services import dashboards

    try:
        with dbmod.get_session(client_id) as s:
            return dashboards.current_metrics(s).get("risk_score")
    except Exception:  # noqa: BLE001 - one broken client must not break the whole overview
        return None

