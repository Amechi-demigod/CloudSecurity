"""Dedicated directory collector API (docs/DIRECTORY_DISCOVERY.md#dedicated-collectors).

* ``/api/collector/*``: called by the collector program itself, authenticated
  by its own credential (``Authorization: Bearer cnc_...``; never a device
  credential, never a user session). Enrollment takes a collector enrollment
  token. Commands are limited to collectors.COMMAND_TYPES.
* ``/api/collectors/*``: the console (viewer reads, admin writes, all audited):
  list, rename, revoke, delete, on-collector Test, enrollment tokens and the
  pre-configured installer.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import zlib

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Request, Response
from pydantic import ValidationError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, load_only
from starlette.concurrency import run_in_threadpool

from .. import config, tenancy
from ..api.agent import _deny, _require_active_org, device_limiter, enroll_failure_limiter, enroll_limiter
from ..api.devices import installer_limiter
from ..auth import audit, client_ip, require_admin, require_viewer
from ..db import get_db
from ..models import EnrollmentToken, User, utcnow
from ..notifications import agent_security
from ..services import devices as devsvc
from . import collector_installer, reconcile
from . import collectors as coll
from . import service as svc
from .models import CollectorCommand, CollectorRelease, CollectorReleaseArtifact, DirectoryCollector, DirectorySource
from .schemas import (
    BatchIn,
    CollectorEnrollIn,
    CollectorHeartbeatIn,
    CollectorInstallerIn,
    CollectorRename,
    CollectorResultIn,
    CollectorTestIn,
    CollectorTokenIn,
    CollectorUpdateStatusIn,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/collector", tags=["collector"])
admin_router = APIRouter(prefix="/api/collectors", tags=["directory"], dependencies=[Depends(require_viewer)])
def Id32():  # noqa: N802 - a fresh Path() per parameter
    return Path(pattern=r"^[0-9a-f]{32}$")
_UA_RE = re.compile(r"^cnapp-collector/(\S{1,64}) \((windows); (amd64|arm64)\)")
MAX_COMPRESSED = 16 * 1024 * 1024
MAX_JSON = 64 * 1024 * 1024


# ----------------------------------------------------------------------------- collector side
def current_collector(request: Request, authorization: str | None = Header(None),
                      db: Session = Depends(get_db)) -> DirectoryCollector:
    s = config.settings
    scheme, _, token = (authorization or "").strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token.startswith(coll.SECRET_PREFIX) or len(token) > 128:
        raise _deny(401, "missing or invalid collector credential", request)
    with tenancy.unscoped(db):
        row = db.scalar(select(DirectoryCollector.organization_id).where(
            DirectoryCollector.secret_hash == coll.hash_secret(token)))
    if row is None:
        raise _deny(401, "missing or invalid collector credential", request)
    _require_active_org(db, row, request)
    tenancy.set_org(db, row)
    c = coll.authenticate(db, token)
    if c is None:
        raise _deny(401, "missing or invalid collector credential", request)
    if c.status != "active":
        raise _deny(403, "collector revoked: re-install it with a new enrollment token", request, "revoked_device")
    if not device_limiter.hit(f"collector:{c.id}", s.device_rate_limit, s.device_rate_window_seconds):
        agent_security.rejected("device_rate_limited", client_ip(request))
        raise HTTPException(429, "rate limit exceeded for this collector",
                            headers={"Retry-After": str(int(s.device_rate_window_seconds / 4))})
    c.last_seen_at, c.last_ip = utcnow(), client_ip(request)
    return c


@router.post("/enroll")
def enroll(body: CollectorEnrollIn, request: Request, db: Session = Depends(get_db)):
    """Exchange a collector enrollment token for the collector's credential (shown once)."""
    s = config.settings
    ip = client_ip(request)
    if (enroll_failure_limiter.blocked(f"ip:{ip}", s.enroll_failure_limit, s.enroll_rate_window_seconds)
            or not enroll_limiter.hit(f"ip:{ip}", s.enroll_rate_limit, s.enroll_rate_window_seconds)):
        agent_security.rejected("enroll_rate_limited", ip)
        raise HTTPException(429, "too many enrollment attempts", headers={"Retry-After": "60"})
    with tenancy.unscoped(db):
        org_id = db.scalar(select(EnrollmentToken.organization_id).where(
            EnrollmentToken.token_hash == devsvc.hash_secret(body.token), EnrollmentToken.kind == "collector"))
    if org_id is not None:
        _require_active_org(db, org_id, request)
        tenancy.set_org(db, org_id)
    token = devsvc.consume_enrollment_token(db, body.token, kind="collector") if org_id is not None else None
    if token is None:
        enroll_failure_limiter.hit(f"ip:{ip}", s.enroll_failure_limit, s.enroll_rate_window_seconds)
        agent_security.rejected("enroll_failed", ip)
        raise _deny(401, "invalid, expired, revoked or used-up collector enrollment token")
    c, secret, again = coll.enroll(db, token, {**body.facts.model_dump(), "machine_id": body.machine_id}, ip)
    audit(db, "directory_collector_reenrolled" if again else "directory_collector_enrolled",
          actor_email=f"enrollment-token:{token.name}"[:320], target=f"directory-collector:{c.id}", ip=ip,
          hostname=c.hostname, domain=c.domain, run_as=c.run_as, is_domain_controller=c.is_domain_controller,
          token_id=token.id)
    db.commit()
    return {"collector_id": c.id, "collector_secret": secret, "name": c.name, "server_time": utcnow(),
            "command_poll_seconds": 60, "heartbeat_seconds": 300, "reenrolled": again}


@router.post("/heartbeat")
def heartbeat(body: CollectorHeartbeatIn, request: Request, user_agent: str | None = Header(None),
              c: DirectoryCollector = Depends(current_collector), db: Session = Depends(get_db)):
    """Host facts (domain, run-as identity, DC, version); returns a self-update offer, if any."""
    was_dc = c.is_domain_controller
    coll.apply_facts(c, body.facts.model_dump())
    c.last_heartbeat_at = utcnow()
    if c.is_domain_controller and not was_dc:
        audit(db, "directory_collector_on_domain_controller", actor_email=f"collector:{c.name}"[:320],
              target=f"directory-collector:{c.id}", hostname=c.hostname)
    offer = None
    m = _UA_RE.match(user_agent or "")
    if m:
        try:
            offer = coll.offer_for(db, c, m[1], m[2], m[3])
        except Exception:  # an offer must never fail the heartbeat
            log.exception("collector update offer failed")
    db.commit()
    return {"server_time": utcnow(), "update": offer}


@router.get("/commands")
def fetch_commands(c: DirectoryCollector = Depends(current_collector), db: Session = Depends(get_db)):
    out = []
    for cmd in coll.deliver_pending(db, c):
        params = dict(cmd.params or {})
        if cmd.type == coll.DIRECTORY_SYNC:
            delivered = svc.delivery_params(db, cmd)
            if delivered is None:
                cmd.status, cmd.completed_at, cmd.output = "cancelled", utcnow(), "directory sync no longer queued"
                continue
            params = delivered
        elif cmd.type == coll.DIAGNOSTICS and params.get("auth") == "simple" and params.get("source_id"):
            src = db.get(DirectorySource, params["source_id"])
            cred = svc._credential(src) if src is not None else None
            if cred is None:
                cmd.status, cmd.completed_at = "failed", utcnow()
                cmd.output = "the source's service-account credential is missing or cannot be decrypted"
                continue
            params["credential"] = cred  # only in this response, never stored
        out.append({"id": cmd.id, "device_id": c.id, "type": cmd.type, "params": params, "nonce": cmd.nonce,
                    "issued_at": cmd.created_at.isoformat() + "Z", "expires_at": cmd.expires_at.isoformat() + "Z"})
    db.commit()
    return {"server_time": utcnow().isoformat() + "Z", "commands": out}


@router.post("/commands/{command_id}/result", status_code=204)
def command_result(body: CollectorResultIn, command_id: str = Id32(), c: DirectoryCollector = Depends(current_collector),
                   db: Session = Depends(get_db)):
    try:
        cmd = coll.delivered_command(db, c, command_id, body.nonce)
    except coll.CollectorError as e:
        raise HTTPException(e.status, e.detail) from None
    if body.result_data is not None and len(json.dumps(body.result_data)) > 32768:
        raise HTTPException(422, "result_data too large")
    cmd.status, cmd.output, cmd.completed_at = body.status, body.output, utcnow()
    cmd.result_data = body.result_data or None
    if cmd.type == coll.DIRECTORY_SYNC and body.status != "succeeded":
        svc.command_failed(db, cmd, body.output)
    elif cmd.type == coll.DIAGNOSTICS:
        coll.record_diagnostics(c, cmd, body.status, body.output, body.result_data)
    audit(db, "directory_collector_command_completed", actor_email=f"collector:{c.name}"[:320],
          target=f"directory-collector:{c.id}", command_id=cmd.id, type=cmd.type, status=body.status)
    db.commit()


def _decompress(data: bytes) -> bytes:
    if not data.startswith(b"\x1f\x8b"):
        raise HTTPException(415, "batches must be gzip-compressed JSON (Content-Encoding: gzip)")
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(data, MAX_JSON + 1)
    except zlib.error:
        raise HTTPException(400, "invalid gzip data") from None
    if len(out) > MAX_JSON or d.unconsumed_tail:
        raise HTTPException(413, f"decompressed batch exceeds {MAX_JSON} bytes")
    return out


@router.post("/directory/runs/{run_id}/batches")
async def upload_batch(request: Request, run_id: str = Id32(),
                       x_directory_sync_token: str | None = Header(None, max_length=128),
                       c: DirectoryCollector = Depends(current_collector), db: Session = Depends(get_db)):
    """One batch of directory objects (same contract as /api/agent/directory)."""
    body = await request.body()
    if len(body) > MAX_COMPRESSED:
        raise HTTPException(413, f"batch exceeds {MAX_COMPRESSED} bytes")
    return await run_in_threadpool(_process, db, c, run_id, x_directory_sync_token, body)


def _process(db: Session, c: DirectoryCollector, run_id: str, token: str | None, body: bytes) -> dict:
    raw = _decompress(body)
    try:
        batch = BatchIn.model_validate(json.loads(raw))
    except (ValueError, ValidationError) as e:
        raise HTTPException(422, f"invalid batch: {str(e)[:1000]}") from None
    finally:
        del raw
    try:
        result = svc.ingest_batch(db, None, run_id, token, batch, collector=c)
    except svc.DirectoryError as e:
        db.commit()
        raise HTTPException(e.status, e.detail) from None
    db.commit()
    if batch.final:
        try:
            reconcile.reconcile(db, notify=True)
        except Exception:
            db.rollback()
            log.exception("re-evaluating directory matches after run %s failed", run_id)
    return result


@router.get("/updates/releases/{release_id}/manifest")
def update_manifest(release_id: str = Id32(), c: DirectoryCollector = Depends(current_collector),
                    db: Session = Depends(get_db)):
    rel = db.get(CollectorRelease, release_id)
    if rel is None:
        raise HTTPException(404, "release not found")
    return Response(content=rel.manifest_envelope, media_type="application/json")


@router.get("/updates/releases/{release_id}/artifacts/{goos}/{goarch}")
def update_artifact(release_id: str = Id32(), goos: str = Path(pattern="^windows$"),
                    goarch: str = Path(pattern="^(amd64|arm64)$"), c: DirectoryCollector = Depends(current_collector),
                    db: Session = Depends(get_db)):
    a = db.scalar(select(CollectorReleaseArtifact).where(
        CollectorReleaseArtifact.release_id == release_id, CollectorReleaseArtifact.os == goos,
        CollectorReleaseArtifact.arch == goarch).options(load_only(
            CollectorReleaseArtifact.name, CollectorReleaseArtifact.sha256, CollectorReleaseArtifact.data)))
    if a is None:
        raise HTTPException(404, "artifact not found")
    return Response(content=a.data, media_type="application/octet-stream",
                    headers={"X-Content-SHA256": a.sha256, "Content-Disposition": f'attachment; filename="{a.name}"'})


@router.post("/updates/status", status_code=204)
def update_status(body: CollectorUpdateStatusIn, c: DirectoryCollector = Depends(current_collector),
                  db: Session = Depends(get_db)):
    c.update_status, c.update_status_detail, c.update_status_at = body.status, body.detail, utcnow()
    audit(db, f"directory_collector_update_{body.status}", actor_email=f"collector:{c.name}"[:320],
          target=f"directory-collector:{c.id}", from_version=body.from_version, to_version=body.to_version,
          detail=body.detail)
    db.commit()


# ----------------------------------------------------------------------------- console
def _get(db: Session, collector_id: str) -> DirectoryCollector:
    c = db.get(DirectoryCollector, collector_id)
    if c is None:
        raise HTTPException(404, "collector not found")
    return c


@admin_router.get("")
def list_collectors(db: Session = Depends(get_db)):
    """Dedicated directory collectors (never endpoint devices)."""
    now = utcnow()
    used = coll.sources_by_collector(db)
    rows = db.scalars(select(DirectoryCollector).order_by(DirectoryCollector.status, DirectoryCollector.name))
    return [coll.collector_out(c, now, used.get(c.id, [])) for c in rows]


@admin_router.get("/{collector_id}")
def get_collector(collector_id: str = Id32(), db: Session = Depends(get_db)):
    c = _get(db, collector_id)
    return coll.collector_out(c, utcnow(), coll.sources_by_collector(db).get(c.id, []))


@admin_router.patch("/{collector_id}")
def rename(body: CollectorRename, request: Request, collector_id: str = Id32(), admin: User = Depends(require_admin),
           db: Session = Depends(get_db)):
    c = _get(db, collector_id)
    if body.name != c.name:
        audit(db, "directory_collector_renamed", actor=admin, target=f"directory-collector:{c.id}",
              ip=client_ip(request), changes={"name": [c.name, body.name]})
        c.name = body.name
        db.commit()
    return coll.collector_out(c, utcnow(), coll.sources_by_collector(db).get(c.id, []))


@admin_router.post("/{collector_id}/revoke")
def revoke(request: Request, collector_id: str = Id32(), admin: User = Depends(require_admin),
           db: Session = Depends(get_db)):
    """Revoke the collector's credential (it can no longer call the API); pending commands are cancelled."""
    c = _get(db, collector_id)
    if c.status != "revoked":
        now = utcnow()
        c.status, c.revoked_at = "revoked", now
        for cmd in db.scalars(select(CollectorCommand).where(CollectorCommand.collector_id == c.id,
                                                             CollectorCommand.status.in_(("pending", "delivered")))):
            cmd.status, cmd.completed_at, cmd.output = "cancelled", now, "collector revoked"
        audit(db, "directory_collector_revoked", actor=admin, target=f"directory-collector:{c.id}",
              ip=client_ip(request), name=c.name, hostname=c.hostname)
        db.commit()
    return coll.collector_out(c, utcnow(), coll.sources_by_collector(db).get(c.id, []))


@admin_router.delete("/{collector_id}", status_code=204)
def delete_collector(request: Request, collector_id: str = Id32(), admin: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    c = _get(db, collector_id)
    if c.status != "revoked":
        raise HTTPException(409, "revoke the collector before deleting it")
    for s in db.scalars(select(DirectorySource).where(DirectorySource.type == "ad")):
        if c.id in (s.collector_ids or []):
            s.collector_ids = [i for i in s.collector_ids if i != c.id]
    db.execute(delete(CollectorCommand).where(CollectorCommand.collector_id == c.id))
    audit(db, "directory_collector_deleted", actor=admin, target=f"directory-collector:{c.id}",
          ip=client_ip(request), name=c.name, hostname=c.hostname)
    db.delete(c)
    db.commit()


@admin_router.post("/{collector_id}/test", status_code=202)
def test_collector(body: CollectorTestIn, request: Request, collector_id: str = Id32(),
                   admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Run diagnostics ON the collector: DC locator, port, certificate, bind as its
    identity, read 5 objects. Results arrive with the command result."""
    c = _get(db, collector_id)
    src = None
    if body.source_id:
        src = db.get(DirectorySource, body.source_id)
        if src is None or src.type != "ad":
            raise HTTPException(404, "Active Directory source not found")
    config = body.config.model_dump() if body.config is not None else None
    try:
        params = coll.diagnostics_params(src, c, config)
        cmd = coll.new_command(db, c, coll.DIAGNOSTICS, params, "collector test", actor=admin.email,
                               ttl=coll.DIAGNOSTICS_TTL)
    except coll.CollectorError as e:
        raise HTTPException(e.status, e.detail) from None
    c.diagnostics = {"command_id": cmd.id, "at": utcnow().isoformat() + "Z", "status": "queued", "steps": []}
    audit(db, "directory_collector_test_requested", actor=admin, target=f"directory-collector:{c.id}",
          ip=client_ip(request), command_id=cmd.id, source_id=body.source_id,
          domain=params["domain"] if config is not None else None)
    db.commit()
    return {"command_id": cmd.id, "status": "queued"}


@admin_router.get("/enrollment-tokens/list")
def list_tokens(db: Session = Depends(get_db)):
    now = utcnow()
    rows = db.scalars(select(EnrollmentToken).where(EnrollmentToken.kind == "collector")
                      .order_by(EnrollmentToken.created_at.desc()).limit(100))
    return [{"id": t.id, "name": t.name, "token_prefix": t.token_prefix, "state": devsvc.token_state(t, now),
             "max_uses": t.max_uses, "use_count": t.use_count, "created_at": t.created_at.isoformat() + "Z",
             "expires_at": t.expires_at.isoformat() + "Z", "created_by": t.created_by,
             "package": t.package_platform} for t in rows]


@admin_router.post("/enrollment-tokens", status_code=201)
def create_token(body: CollectorTokenIn, request: Request, admin: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    """A collector enrollment token (shown once), for a manual install."""
    t, raw = coll.new_token(db, name=body.name, max_uses=body.max_uses, expires_in_hours=body.expires_in_hours,
                            actor=admin.email)
    audit(db, "directory_collector_token_created", actor=admin, target=f"enrollment-token:{t.id}",
          ip=client_ip(request), name=t.name, max_uses=t.max_uses, expires_at=t.expires_at.isoformat() + "Z")
    db.commit()
    return {"id": t.id, "token": raw, "expires_at": t.expires_at.isoformat() + "Z",
            "server_url": collector_installer.server_url()}


@admin_router.post("/enrollment-tokens/{token_id}/revoke")
def revoke_token(request: Request, token_id: str = Id32(), admin: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    t = db.get(EnrollmentToken, token_id)
    if t is None or t.kind != "collector":
        raise HTTPException(404, "token not found")
    if t.revoked_at is None:
        t.revoked_at = utcnow()
        audit(db, "directory_collector_token_revoked", actor=admin, target=f"enrollment-token:{t.id}",
              ip=client_ip(request), name=t.name)
        db.commit()
    return {"id": t.id, "state": devsvc.token_state(t)}


@admin_router.get("/installer/info")
def installer_info():
    return collector_installer.availability()


@admin_router.post("/installer")
def download_installer(body: CollectorInstallerIn, request: Request, admin: User = Depends(require_admin),
                       db: Session = Depends(get_db)):
    """A pre-configured collector installer with a fresh single-use enrollment token:
    the MSI (x64, recommended) or the zip (signed binary, install scripts and the
    enrollment preset; advanced / scripted and Arm64). Rate limited like the
    agent installers; the plaintext token only exists in the returned file."""
    s = config.settings
    if body.format == "msi" and body.arch != "amd64":
        raise HTTPException(422, "the collector MSI is x64 only; use the zip for Windows on Arm64")
    if not installer_limiter.hit(f"user:{admin.id}", s.agent_installer_rate_limit,
                                 s.agent_installer_rate_window_seconds):
        raise HTTPException(429, "too many installer downloads; try again later", headers={"Retry-After": "60"})
    t, raw = coll.new_token(db, name=body.name, max_uses=1, expires_in_hours=body.expires_in_hours,
                            actor=admin.email,  # package_platform is at most 16 characters
                            package="collector-msi" if body.format == "msi" else f"collector-{body.arch}")
    ca_included = None
    try:
        if body.format == "msi":
            data, version, ca_included = collector_installer.build_msi(raw, include_ca=body.include_ca,
                                                                       gmsa=body.gmsa, name=body.name)
            media_type = "application/x-msi"
        else:
            data, version = collector_installer.build(body.arch, raw, include_ca=body.include_ca, gmsa=body.gmsa,
                                                      name=body.name)
            media_type = "application/zip"
    except collector_installer.InstallerUnavailable as e:
        db.rollback()
        raise HTTPException(503, str(e)) from None
    except collector_installer.InstallerConfigError as e:
        db.rollback()
        raise HTTPException(409, str(e)) from None
    except Exception:
        db.rollback()
        log.exception("building the collector %s installer failed", body.format)
        raise HTTPException(500, "building the installer failed; see the server log") from None
    del raw  # the plaintext token now only exists inside `data`
    digest = hashlib.sha256(data).hexdigest()
    t.package_sha256 = digest
    audit(db, "directory_collector_installer_downloaded", actor=admin, target=f"enrollment-token:{t.id}",
          ip=client_ip(request), format=body.format, arch=body.arch, gmsa=body.gmsa or None, version=version,
          sha256=digest, size_bytes=len(data), ca_included=ca_included, expires_at=t.expires_at.isoformat() + "Z",
          server_url=collector_installer.server_url())
    db.commit()
    filename = collector_installer.download_name(body.arch, body.format)
    return Response(content=data, media_type=media_type, headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store", "X-Collector-Version": version, "X-Enrollment-Token-Id": t.id,
        "X-Content-SHA256": digest})


@admin_router.get("/setup/scripts")
def setup_scripts(domain: str = "", gmsa: str = "", hosts: str = ""):
    """Copyable PowerShell for gMSA setup and the manual pre-check (nothing secret)."""
    return collector_installer.setup_scripts(domain=domain, gmsa=gmsa, hosts=hosts)
