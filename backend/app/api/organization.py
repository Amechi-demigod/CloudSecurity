"""The signed-in user's organisation: profile, sensor ingest tokens and cloud
connector settings (/api/organization/*). Everything here is scoped to the
session's organisation by app/tenancy.py; reads need any role, writes admin."""
from __future__ import annotations

import secrets
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import tenancy
from ..auth import audit, client_ip, require_admin, require_viewer
from ..connectors import access_check, build_registry, org_config
from ..db import get_db
from ..models import IngestToken, Organization, ScanRun, User, utcnow
from ..schemas import ORM, UTCDateTime
from ..security import INGEST_TOKEN_PREFIX, hash_ingest_token
from ..services import onboarding
from ..services import organizations as orgs
from ..services.scans import FIRST_SCAN, start_scan

router = APIRouter(prefix="/api/organization", tags=["organization"], dependencies=[Depends(require_viewer)])
Provider = Literal["azure", "aws", "gcp"]


class OrganizationOut(ORM):
    id: str
    name: str
    slug: str
    status: str
    is_default: bool
    contact_email: str | None = None
    logo_url: str | None = None
    plan: str | None = None
    max_users: int | None = None
    max_devices: int | None = None
    created_at: UTCDateTime


class OrganizationUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: Annotated[str, StringConstraints(min_length=1, max_length=128)] | None = None
    contact_email: Annotated[str, StringConstraints(max_length=320, pattern=r"^$|^[^@\s]+@[^@\s]+\.[^@\s]+$")] | None = None
    logo_url: Annotated[str, StringConstraints(max_length=1024, pattern=r"^$|^https://\S+$")] | None = None


def _org(db: Session) -> Organization:
    return db.get(Organization, tenancy.require_org(db))


@router.get("", response_model=OrganizationOut)
def get_organization(db: Session = Depends(get_db)):
    return _org(db)


@router.patch("", response_model=OrganizationOut)
def update_organization(body: OrganizationUpdate, request: Request, admin: User = Depends(require_admin),
                        db: Session = Depends(get_db)):
    org = _org(db)
    changes: dict[str, list] = {}
    for f in ("name", "contact_email", "logo_url"):
        v = getattr(body, f)
        if v is None:
            continue
        v = v or None if f != "name" else v
        if f == "contact_email" and v:
            v = v.lower()
        if v != getattr(org, f):
            changes[f] = [getattr(org, f), v]
            setattr(org, f, v)
    if changes:
        org.updated_at = utcnow()
        audit(db, "organization_updated", actor=admin, target=f"organization:{org.slug}", ip=client_ip(request),
              changes=changes)
        db.commit()
    return org


@router.get("/usage")
def get_usage(db: Session = Depends(get_db)):
    oid = tenancy.require_org(db)
    with tenancy.unscoped(db):
        counts = orgs.usage(db).get(oid)
    return counts or {"users": 0, "devices": 0, "assets": 0, "scans": 0}


# ----------------------------------------------------------------------------- getting started
class OnboardingStep(BaseModel):
    key: str
    done: bool


class OnboardingOut(BaseModel):
    steps: list[OnboardingStep]
    completed: int
    total: int
    # The default organisation is the platform operator's own: the console shows no checklist for it.
    is_default: bool
    dismissed: bool
    dismissed_at: UTCDateTime | None = None
    dismissed_by: str | None = None


def _onboarding(db: Session, org: Organization, user: User) -> OnboardingOut:
    done = onboarding.steps(db, user)
    return OnboardingOut(steps=[OnboardingStep(key=k, done=done[k]) for k in onboarding.STEPS],
                         completed=sum(done.values()), total=len(done), is_default=org.is_default,
                         dismissed=org.onboarding_dismissed_at is not None, dismissed_at=org.onboarding_dismissed_at,
                         dismissed_by=org.onboarding_dismissed_by)


@router.get("/onboarding", response_model=OnboardingOut)
def get_onboarding(user: User = Depends(require_viewer), db: Session = Depends(get_db)):
    """The "Getting started" checklist: each step's done flag from this organisation's data."""
    return _onboarding(db, _org(db), user)


@router.post("/onboarding/dismiss", response_model=OnboardingOut)
def dismiss_onboarding(request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Hide the checklist for everyone in this organisation."""
    org = _org(db)
    if org.onboarding_dismissed_at is None:
        org.onboarding_dismissed_at, org.onboarding_dismissed_by = utcnow(), admin.email
        audit(db, "onboarding_dismissed", actor=admin, target=f"organization:{org.slug}", ip=client_ip(request),
              completed=sum(onboarding.steps(db, admin).values()))
        db.commit()
    return _onboarding(db, org, admin)


# ----------------------------------------------------------------------------- ingest tokens
class IngestTokenOut(ORM):
    id: str
    name: str
    token_prefix: str
    created_by: str | None = None
    created_at: UTCDateTime
    last_used_at: UTCDateTime | None = None
    revoked_at: UTCDateTime | None = None


class IngestTokenCreated(IngestTokenOut):
    token: str  # shown once


class IngestTokenIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: Annotated[str, StringConstraints(min_length=1, max_length=128)]


@router.get("/ingest-tokens", response_model=list[IngestTokenOut], dependencies=[Depends(require_admin)])
def list_ingest_tokens(db: Session = Depends(get_db)):
    return list(db.scalars(select(IngestToken).order_by(IngestToken.created_at.desc())))


@router.post("/ingest-tokens", response_model=IngestTokenCreated, status_code=201)
def create_ingest_token(body: IngestTokenIn, request: Request, admin: User = Depends(require_admin),
                        db: Session = Depends(get_db)):
    """A bearer token for this organisation's runtime sensors (SENSOR_API_TOKEN).
    Shown once; only its SHA-256 is stored."""
    raw = INGEST_TOKEN_PREFIX + secrets.token_urlsafe(32)
    tok = IngestToken(name=body.name, token_hash=hash_ingest_token(raw), token_prefix=raw[:12],
                      created_by=admin.email)
    db.add(tok)
    db.flush()
    audit(db, "ingest_token_created", actor=admin, target=f"ingest-token:{tok.id}", ip=client_ip(request),
          name=tok.name)
    db.commit()
    return IngestTokenCreated(**IngestTokenOut.model_validate(tok).model_dump(), token=raw)


@router.delete("/ingest-tokens/{token_id}", response_model=IngestTokenOut)
def revoke_ingest_token(request: Request, token_id: str = Path(pattern=r"^[0-9a-f]{32}$"),
                        admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    tok = db.get(IngestToken, token_id)
    if tok is None:
        raise HTTPException(404, "ingest token not found")
    if tok.revoked_at is None:
        tok.revoked_at = utcnow()
        audit(db, "ingest_token_revoked", actor=admin, target=f"ingest-token:{tok.id}", ip=client_ip(request),
              name=tok.name)
        db.commit()
    return tok


# ----------------------------------------------------------------------------- cloud connectors
class ConnectorConfigOut(BaseModel):
    provider: str
    stored: bool
    enabled: bool
    config: dict[str, Any]
    # Masked hints only ("key for scanner@project.iam..."), never the secrets.
    secrets: dict[str, str | None]
    updated_at: datetime | None = None
    updated_by: str | None = None
    # Default organisation only: true while the environment (AZURE_* / AWS_* /
    # GCP_*) configures this provider and no console setting overrides it.
    from_environment: bool = False
    # PUT with "test": true: what the connection test reached ("Connected to Azure: ...").
    test_message: str | None = None
    # PUT with "start_first_scan": true: the scan started because this provider had none yet.
    first_scan_id: str | None = None


class ConnectorConfigIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    # Secret fields to set; omitted ones are kept, "" removes one.
    secrets: dict[str, str] = Field(default_factory=dict)
    reason: Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)] = ""
    # Connection test before saving ("Test & save"): one read-only call per scope
    # (app/connectors/access_check.py); nothing is stored when it fails (422).
    test: bool = False
    # Start a scan of this provider right away when it has never been scanned.
    start_first_scan: bool = False


def _env_configured(provider: str) -> bool:
    from .. import config

    return build_registry(config.settings)[provider].is_configured()


def _out(db: Session, provider: str) -> ConnectorConfigOut:
    row = org_config.rows(db).get(provider)
    view = org_config.public_view(row, provider)
    env = row is None and tenancy.is_default(tenancy.org_id(db)) and _env_configured(provider)
    return ConnectorConfigOut(**view, from_environment=env)


@router.get("/connectors", response_model=list[ConnectorConfigOut], dependencies=[Depends(require_admin)])
def list_connector_configs(db: Session = Depends(get_db)):
    return [_out(db, p) for p in org_config.PROVIDERS]


@router.put("/connectors/{provider}", response_model=ConnectorConfigOut)
def put_connector_config(provider: Provider, body: ConnectorConfigIn, request: Request,
                         admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Set this organisation's read-only credentials for a cloud provider
    (docs/CONNECT_AWS.md, CONNECT_GCP.md, README "Connecting a real Azure
    environment" for the permissions). With "test": true the credentials are
    tried first (read-only calls, short timeout) and only stored if they work."""
    check = None
    try:
        if body.test and body.enabled:
            cfg, secrets_now = org_config.prepare(db, provider, config_in=body.config, secrets_in=body.secrets)
            check = access_check.run(provider, org_config.probe_settings(provider, cfg, secrets_now), secrets_now)
            audit(db, "connector_config_tested", actor=admin, target=f"connector:{provider}", ip=client_ip(request),
                  ok=check.ok, scopes=[s["id"] for s in check.scopes])
            if not check.ok:
                db.commit()
                raise HTTPException(422, check.message)
        row = org_config.upsert(db, provider, config_in=body.config, secrets_in=body.secrets, enabled=body.enabled,
                                actor=admin.email)
    except org_config.ConnectorConfigError as e:
        raise HTTPException(422, str(e)) from None
    audit(db, "connector_config_updated", actor=admin, target=f"connector:{provider}", ip=client_ip(request),
          enabled=row.enabled, config=row.config, secrets_set=sorted(row.secret_hints), reason=body.reason,
          tested=check is not None)
    db.commit()
    first_scan = _start_first_scan(db, provider, admin, request) if body.start_first_scan and row.enabled else None
    out = _out(db, provider)
    out.test_message = check.message if check else None
    out.first_scan_id = first_scan
    return out


def _start_first_scan(db: Session, provider: str, admin: User, request: Request) -> str | None:
    """Scan a newly connected provider once, right away (the schedule takes over
    from there). Only when this organisation has never scanned it, so a re-save
    or an edit never piles up scans; one scan per connector at a time still
    holds (app/services/scans.py)."""
    if db.scalar(select(ScanRun.id).where(ScanRun.connector == provider).limit(1)) is not None:
        return None
    conn = build_registry(org_config.org_settings(db))[provider]
    if not conn.is_configured():
        return None
    run = start_scan(conn, tenancy.require_org(db), background=True, trigger=FIRST_SCAN)
    audit(db, "scan_started", actor=admin, target=provider, ip=client_ip(request), scan_id=run.id,
          trigger=FIRST_SCAN)
    db.commit()
    return run.id


@router.delete("/connectors/{provider}", response_model=ConnectorConfigOut)
def delete_connector_config(provider: Provider, request: Request, admin: User = Depends(require_admin),
                            db: Session = Depends(get_db)):
    """Remove the stored settings (the default organisation falls back to the environment)."""
    row = org_config.rows(db).get(provider)
    if row is not None:
        db.delete(row)
        audit(db, "connector_config_deleted", actor=admin, target=f"connector:{provider}", ip=client_ip(request))
        db.commit()
    return _out(db, provider)
