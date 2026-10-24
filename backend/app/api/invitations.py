"""Invitations: accepting one (public, the token is the credential) and the
organisation admin's invitation management (/api/organization/invitations)."""
from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config, mailer, mfa, tenancy
from ..auth import audit, client_ip, create_session, login_limiter, require_admin, set_session_cookie
from ..db import get_db
from ..models import Organization, OrganizationInvitation, User, utcnow
from ..schemas import ORM, SessionInfo, UTCDateTime
from ..services import invitations as svc
from .auth import _session_info

public_router = APIRouter(prefix="/api/invitations", tags=["invitations"])
router = APIRouter(prefix="/api/organization/invitations", tags=["organization"],
                   dependencies=[Depends(require_admin)])

Role = Literal["viewer", "analyst", "admin"]
Token = Annotated[str, StringConstraints(min_length=10, max_length=128)]


class InvitationOut(ORM):
    id: str
    email: str
    role: str
    invited_by: str | None = None
    created_at: UTCDateTime
    expires_at: UTCDateTime
    last_sent_at: UTCDateTime | None = None
    sent_count: int = 0
    accepted_at: UTCDateTime | None = None
    revoked_at: UTCDateTime | None = None
    state: str = "pending"


class IssuedOut(BaseModel):
    invitation: InvitationOut
    emailed: bool
    email_error: str | None = None
    # Only when the email was not sent: the inviter passes the link on (single use, expires).
    invite_url: str | None = None


class InviteIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    email: Annotated[str, StringConstraints(min_length=3, max_length=320)]
    role: Role = "viewer"


def inv_out(inv: OrganizationInvitation) -> InvitationOut:
    out = InvitationOut.model_validate(inv)
    out.state = svc.state(inv)
    return out


def issued_out(issued: svc.Issued) -> IssuedOut:
    return IssuedOut(invitation=inv_out(issued.invitation), emailed=issued.emailed, email_error=issued.email_error,
                     invite_url=None if issued.emailed else issued.url)


def request_base(request: Request) -> str:
    return str(request.base_url).rstrip("/")


# ----------------------------------------------------------------------------- organisation admin
@router.get("", response_model=list[InvitationOut])
def list_invitations(db: Session = Depends(get_db)):
    rows = db.scalars(select(OrganizationInvitation).order_by(OrganizationInvitation.created_at.desc()).limit(500))
    return [inv_out(i) for i in rows]


@router.get("/mail")
def mail_status():
    """Whether invitations are emailed (else the console shows the link to copy)."""
    return {"configured": mailer.configured()}


@router.post("", response_model=IssuedOut, status_code=201)
def invite(body: InviteIn, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    org = db.get(Organization, tenancy.require_org(db))
    try:
        issued = svc.create(db, org, email=body.email, role=body.role, invited_by=admin.email,
                            base_url=request_base(request))
    except svc.InvitationError as e:
        raise HTTPException(e.status, str(e)) from None
    audit(db, "user_invited", actor=admin, target=issued.invitation.email, ip=client_ip(request), role=body.role,
          emailed=issued.emailed)
    db.commit()
    return issued_out(issued)


def _get(db: Session, inv_id: str) -> OrganizationInvitation:
    inv = db.get(OrganizationInvitation, inv_id)
    if inv is None:
        raise HTTPException(404, "invitation not found")
    return inv


@router.post("/{inv_id}/resend", response_model=IssuedOut)
def resend(request: Request, inv_id: str = Path(pattern=r"^[0-9a-f]{32}$"), admin: User = Depends(require_admin),
           db: Session = Depends(get_db)):
    inv = _get(db, inv_id)
    org = db.get(Organization, tenancy.require_org(db))
    try:
        issued = svc.resend(db, org, inv, invited_by=admin.email, base_url=request_base(request))
    except svc.InvitationError as e:
        raise HTTPException(e.status, str(e)) from None
    audit(db, "user_invitation_resent", actor=admin, target=inv.email, ip=client_ip(request), emailed=issued.emailed)
    db.commit()
    return issued_out(issued)


@router.delete("/{inv_id}", response_model=InvitationOut)
def revoke(request: Request, inv_id: str = Path(pattern=r"^[0-9a-f]{32}$"), admin: User = Depends(require_admin),
           db: Session = Depends(get_db)):
    inv = _get(db, inv_id)
    if svc.state(inv) in ("pending", "expired"):
        inv.revoked_at = utcnow()
        audit(db, "user_invitation_revoked", actor=admin, target=inv.email, ip=client_ip(request))
        db.commit()
    return inv_out(inv)


# ----------------------------------------------------------------------------- public: accept
class LookupIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: Token


class InvitationInfo(BaseModel):
    organization: str
    email: str
    role: str
    expires_at: UTCDateTime
    # Microsoft sign-in is available to members of the default organisation.
    sso_available: bool = False


class AcceptIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: Token
    name: Annotated[str, StringConstraints(strip_whitespace=True, max_length=128)] = ""
    password: Annotated[str, StringConstraints(max_length=1024)]


def _rate_limit(request: Request) -> str:
    s = config.settings
    ip = client_ip(request)
    if not login_limiter.hit(f"invite:{ip}", s.login_rate_limit, s.login_rate_window_seconds):
        raise HTTPException(429, "Too many attempts. Try again later.",
                            headers={"Retry-After": str(int(s.login_rate_window_seconds))})
    return ip


def _require_json(request: Request) -> None:
    if not (request.headers.get("content-type") or "").lower().startswith("application/json"):
        raise HTTPException(415, "requires an application/json body")


@public_router.post("/lookup", response_model=InvitationInfo)
def lookup(body: LookupIn, request: Request, db: Session = Depends(get_db)):
    """What an invitation link is for (shown before choosing a password)."""
    _require_json(request)
    _rate_limit(request)
    found = svc.find(db, body.token)
    if found is None:
        raise HTTPException(410, "this invitation link is invalid, expired or already used")
    inv, org = found
    return InvitationInfo(organization=org.name, email=inv.email, role=inv.role, expires_at=inv.expires_at,
                          sso_available=bool(org.is_default and config.settings.entra_enabled))


class SignInRequired(BaseModel):
    sign_in_required: bool = True
    email: str
    reason: str


@public_router.post("/accept", response_model=SessionInfo | SignInRequired)
def accept(body: AcceptIn, request: Request, response: Response, db: Session = Depends(get_db)):
    """Create the invited account with a password and sign it in. When the role
    must use MFA (MFA_REQUIRED_ROLES), no session is issued: the person signs in
    normally and is taken through authenticator enrolment."""
    _require_json(request)
    ip = _rate_limit(request)
    try:
        user, _org = svc.accept(db, body.token, name=body.name, password=body.password)
    except svc.InvitationError as e:
        raise HTTPException(e.status, str(e)) from None
    audit(db, "invitation_accepted", actor=user, target=user.email, ip=ip, role=user.role)
    if mfa.is_required(user):
        db.commit()
        return SignInRequired(email=user.email, reason="mfa_enrollment_required")
    token, sess = create_session(db, user, request)
    audit(db, "login_success", actor=user, ip=ip, method="invitation")
    db.commit()
    set_session_cookie(response, token)
    return _session_info(db, sess)
