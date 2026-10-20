"""Approved (signed) device scripts (docs/DEVICE_SCRIPTS.md).

User side (/api/scripts/*, session):
  viewer: script library, bundles, trusted key ids, run history and output
  admin : import a signed bundle (raw application/gzip body), run a script.
          A script whose *signed* manifest says `risk: low` runs right away;
          medium / high need a second admin (two-person approval).

Device side (/api/agent/scripts/*, per-device credential): the signed manifest
envelope and the script bytes, which the agent verifies before running.
"""
from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import select
from sqlalchemy.orm import Session, undefer

from ..auth import audit, client_ip, require_admin, require_viewer
from ..db import get_db
from ..models import Device, DeviceApproval, DeviceCommand, DeviceScript, DeviceScriptBundle, User, utcnow
from ..services import approvals
from ..services import device_scripts as svc
from ..services import devices as dsvc
from .agent import current_device

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/scripts", tags=["device-scripts"], dependencies=[Depends(require_viewer)])
device_router = APIRouter(prefix="/api/agent/scripts", tags=["agent"])
Id32 = Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")]


def _z(d):
    return d.isoformat() + "Z" if d else None


def _script_out(s: DeviceScript) -> dict[str, Any]:
    return {"name": s.name, "description": s.description, "platform": s.platform, "interpreter": s.interpreter,
            "risk": s.risk, "timeout_seconds": s.timeout_seconds, "parameters": s.parameters, "sha256": s.sha256,
            "size_bytes": s.size_bytes, "requires_approval": s.risk != "low"}


def _bundle_out(b: DeviceScriptBundle) -> dict[str, Any]:
    return {"id": b.id, "version": b.version, "key_id": b.key_id, "released_at": _z(b.released_at),
            "expires_at": _z(b.expires_at), "notes": b.notes, "bundle_sha256": b.bundle_sha256,
            "imported_by": b.imported_by, "imported_at": _z(b.imported_at), "expired": b.expires_at <= utcnow(),
            "scripts": [s.name for s in b.scripts]}


@router.get("")
def library(db: Session = Depends(get_db)):
    """The script library: scripts of the newest imported, non-expired bundle."""
    b = svc.latest_bundle(db)
    return {"bundle": _bundle_out(b) if b else None, "scripts": [_script_out(s) for s in (b.scripts if b else [])],
            "trusted_keys": [k.key_id for k in svc.trusted_keys()]}


@router.get("/bundles")
def list_bundles(db: Session = Depends(get_db)):
    return [_bundle_out(b) for b in svc.bundles(db)]


@router.post("/bundles", status_code=201)
def import_bundle(request: Request, data: bytes = Body(..., media_type="application/gzip"),
                  admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    try:
        b = svc.import_bundle(db, data, admin.email)
    except svc.ScriptBundleError as e:
        db.rollback()
        audit(db, "device_script_bundle_rejected", actor=admin, ip=client_ip(request), reason=str(e)[:500],
              size_bytes=len(data))
        db.commit()
        raise HTTPException(422, str(e)) from None
    audit(db, "device_script_bundle_imported", actor=admin, target=f"script-bundle:{b.id}", ip=client_ip(request),
          version=b.version, key_id=b.key_id, bundle_sha256=b.bundle_sha256,
          scripts=[f"{s.name} {s.risk} {s.sha256}" for s in b.scripts])
    db.commit()
    return _bundle_out(b)


class RunIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
    script: Annotated[str, StringConstraints(max_length=64)]
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=500)]


@router.post("/run", status_code=201)
def run_script(body: RunIn, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    device = db.get(Device, body.device_id)
    if device is None:
        raise HTTPException(404, "device not found")
    if device.status != "active":
        raise HTTPException(409, "device is revoked")
    script = svc.find_script(db, body.script)
    if script is None:
        raise HTTPException(404, f"script {body.script!r} is not in the current signed script library")
    if script.platform != device.os_family:
        raise HTTPException(409, f"script {script.name} is for {script.platform}, the device runs {device.os_family}")
    try:
        params = svc.validate_run(script, body.parameters)
    except svc.ScriptBundleError as e:
        raise HTTPException(422, str(e)) from None
    b = script.bundle
    cmd_params = {"bundle_id": b.id, "bundle_version": b.version, "script": script.name,
                  "script_sha256": script.sha256, "parameters": params}
    summary = svc.summary(script, params)
    if script.risk == "low":
        cmd = dsvc.new_command(db, device, "run_script", cmd_params, body.reason, requested_by_id=admin.id,
                               requested_by_email=admin.email)
        audit(db, "device_command_created", actor=admin, target=f"device:{device.id}", ip=client_ip(request),
              hostname=device.hostname, command_id=cmd.id, type=cmd.type, params=cmd_params, reason=body.reason,
              risk=script.risk)
        db.commit()
        return {"mode": "command", "command_id": cmd.id, "approval": None}
    try:
        a = approvals.request(db, admin, device, "run_script", cmd_params, reason=body.reason, summary=summary,
                              risk=script.risk, ip=client_ip(request))
    except approvals.ApprovalError as e:
        raise HTTPException(e.status, e.detail) from None
    db.commit()
    return {"mode": "approval", "command_id": None, "approval": approvals.out(a, device, admin)}


@router.get("/runs")
def runs(device_id: str | None = Query(None, pattern=r"^[0-9a-f]{32}$"),
         script: str | None = Query(None, max_length=64), limit: int = Query(100, ge=1, le=1000),
         db: Session = Depends(get_db)):
    """Run history (commands of type run_script), newest first, with output."""
    dsvc.expire_commands(db, device_id)
    db.commit()
    stmt = select(DeviceCommand).where(DeviceCommand.type == "run_script")
    if device_id:
        stmt = stmt.where(DeviceCommand.device_id == device_id)
    out = []
    hosts: dict[str, str] = {}
    for c in db.scalars(stmt.order_by(DeviceCommand.created_at.desc()).limit(limit * 3 if script else limit)):
        p = c.params or {}
        if script and p.get("script") != script:
            continue
        if c.device_id not in hosts:
            d = db.get(Device, c.device_id)
            hosts[c.device_id] = d.hostname if d else "?"
        out.append({"id": c.id, "device_id": c.device_id, "hostname": hosts[c.device_id], "script": p.get("script"),
                    "bundle_version": p.get("bundle_version"), "parameters": p.get("parameters") or {},
                    "status": c.status, "exit_code": c.exit_code, "output": c.output, "reason": c.reason,
                    "requested_by_email": c.requested_by_email, "approved_by_email": c.approved_by_email,
                    "approval_id": c.approval_id, "created_at": _z(c.created_at), "completed_at": _z(c.completed_at),
                    "expires_at": _z(c.expires_at)})
        if len(out) >= limit:
            break
    return out


@router.get("/pending-approvals")
def pending_script_approvals(db: Session = Depends(get_db)):
    """Script runs waiting for a second admin (visible to everyone; decided under /approvals)."""
    rows = db.scalars(select(DeviceApproval).where(DeviceApproval.action == "run_script",
                                                   DeviceApproval.status.in_(approvals.OPEN_STATES))
                      .order_by(DeviceApproval.requested_at.desc()).limit(200))
    return [approvals.out(a, db.get(Device, a.device_id)) for a in rows]


# ----------------------------------------------------------------------------- device API
def _device_bundle(db: Session, bundle_id: str) -> DeviceScriptBundle:
    b = db.get(DeviceScriptBundle, bundle_id)
    if b is None:
        raise HTTPException(404, "script bundle not found")
    return b


@device_router.get("/bundles/{bundle_id}/manifest")
def bundle_manifest(bundle_id: Id32, device: Device = Depends(current_device), db: Session = Depends(get_db)):
    db.commit()  # persist last_seen_at
    b = _device_bundle(db, bundle_id)
    return Response(content=b.manifest_envelope, media_type="application/json", headers={"Cache-Control": "no-store"})


@device_router.get("/bundles/{bundle_id}/scripts/{name}")
def bundle_script(bundle_id: Id32, name: Annotated[str, Path(pattern=r"^[a-z0-9][a-z0-9-]{1,63}$")],
                  device: Device = Depends(current_device), db: Session = Depends(get_db)):
    db.commit()
    s = db.scalar(select(DeviceScript).options(undefer(DeviceScript.content))
                  .where(DeviceScript.bundle_id == bundle_id, DeviceScript.name == name))
    if s is None:
        raise HTTPException(404, "script not found")
    # Only a device with a delivered run of this script may download it.
    pending = db.scalar(select(DeviceCommand.id).where(
        DeviceCommand.device_id == device.id, DeviceCommand.type == "run_script",
        DeviceCommand.status == "delivered").limit(1))
    if pending is None:
        raise HTTPException(403, "no delivered run_script command for this device")
    return Response(content=s.content, media_type="application/octet-stream",
                    headers={"X-Content-SHA256": s.sha256, "Cache-Control": "no-store"})
