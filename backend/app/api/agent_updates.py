"""Agent auto-update API.

Device side (/api/agent/updates/*, per-device credential, reachable from the
internet like the rest of /api/agent/):
  GET  /api/agent/updates/releases/{id}/manifest                 signed manifest envelope
  GET  /api/agent/updates/releases/{id}/artifacts/{os}/{arch}    binary (size-capped, parallelism-limited)
  POST /api/agent/updates/status                                  progress / outcome report

User side (/api/updates/*, session + RBAC; deliberately NOT under /api/agent/):
  viewer: read releases, rings, keys, fleet summary, per-device update state
  admin : import / withdraw releases, manage rings, assign / pin devices.
          The signed-in admin session is enough (MFA is enforced at sign-in,
          not per action). Everything is audited.
"""
from __future__ import annotations

import logging
import threading
from typing import Annotated, Literal

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..auth import audit, client_ip, require_admin, require_viewer
from ..db import get_db
from ..models import AgentRelease, AgentUpdateEvent, AgentUpdateRing, Device, User, utcnow
from ..notifications import agent_update_source
from ..services import agent_update_auto as auto
from ..services import agent_updates as svc
from .agent import current_device

log = logging.getLogger(__name__)

def Id32():  # noqa: N802  (a fresh Path() per parameter: FastAPI must not share FieldInfo objects)
    return Path(pattern=r"^[0-9a-f]{32}$")
device_router = APIRouter(prefix="/api/agent/updates", tags=["agent"])
router = APIRouter(prefix="/api/updates", tags=["agent-updates"], dependencies=[Depends(require_viewer)])


class _Downloads:
    """Bounded number of concurrent artifact downloads per process (fleet-wide
    rate limiting on top of the agents' random start delay)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.active = 0

    def acquire(self) -> bool:
        with self._lock:
            if self.active >= max(1, config.settings.agent_update_max_parallel_downloads):
                return False
            self.active += 1
            return True

    def release(self) -> None:
        with self._lock:
            self.active -= 1


downloads = _Downloads()


# ----------------------------------------------------------------------------- device API
@device_router.get("/releases/{release_id}/manifest")
def release_manifest(release_id: str = Id32(), device: Device = Depends(current_device), db: Session = Depends(get_db)):
    rel = db.get(AgentRelease, release_id)
    db.commit()  # persist last_seen_at
    if rel is None or rel.withdrawn_at is not None:
        raise HTTPException(404, "release not found")
    return Response(content=rel.manifest_envelope, media_type="application/json", headers={"Cache-Control": "no-store"})


@device_router.get("/releases/{release_id}/artifacts/{goos}/{goarch}")
def release_artifact(release_id: str = Id32(), goos: str = Path(pattern="^(windows|darwin)$"),
                     goarch: str = Path(pattern="^(amd64|arm64)$"), device: Device = Depends(current_device),
                     db: Session = Depends(get_db)):
    db.commit()
    rel = db.get(AgentRelease, release_id)
    if rel is None or rel.withdrawn_at is not None:
        raise HTTPException(404, "release not found")
    if not downloads.acquire():
        raise HTTPException(503, "too many concurrent agent downloads; retry later", headers={"Retry-After": "120"})
    try:
        art = svc.artifact_with_data(db, release_id, goos, goarch)
        if art is None:
            raise HTTPException(404, f"release {rel.version} has no {goos}/{goarch} binary")
        data = art.data
    finally:
        downloads.release()
    return Response(content=data, media_type="application/octet-stream", headers={
        "Content-Disposition": f'attachment; filename="{art.name}"', "X-Content-SHA256": art.sha256,
        "Cache-Control": "no-store"})


class StatusIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    release_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")] | None = None
    from_version: Annotated[str, StringConstraints(max_length=64)] = ""
    to_version: Annotated[str, StringConstraints(max_length=64)] = ""
    status: Literal["downloading", "verified", "installing", "installed", "rolled_back", "failed", "rejected"]
    detail: Annotated[str, StringConstraints(max_length=2000)] = ""


@device_router.post("/status", status_code=204)
def report_status(body: StatusIn, device: Device = Depends(current_device), db: Session = Depends(get_db)):
    svc.record_status(db, device, release_id=body.release_id, from_version=body.from_version,
                      to_version=body.to_version, status=body.status, detail=body.detail)
    if body.status in ("installed", "rolled_back", "rejected"):
        audit(db, f"agent_update_{body.status}", actor_email=f"device:{device.hostname}"[:320],
              target=f"device:{device.id}", release_id=body.release_id, from_version=body.from_version,
              to_version=body.to_version, detail=body.detail[:500])
    if body.status in svc.FAILURE_STATUSES:
        agent_update_source.update_failed(db, device, body.status, body.from_version, body.to_version, body.detail)
    db.commit()
    log.info("device %s update %s -> %s: %s", device.id, body.from_version, body.to_version, body.status)


# ----------------------------------------------------------------------------- helpers
def _release_out(r: AgentRelease, adoption: dict[str, int] | None = None) -> dict:
    return {"id": r.id, "version": r.version, "key_id": r.key_id, "released_at": _z(r.released_at),
            "expires_at": _z(r.expires_at), "min_supported_version": r.min_supported_version, "notes": r.notes,
            "rollback_allowed_from": r.manifest.get("rollback_allowed_from") or [],
            "bundle_sha256": r.bundle_sha256, "imported_by": r.imported_by, "imported_at": _z(r.imported_at),
            "withdrawn_at": _z(r.withdrawn_at), "withdrawn_reason": r.withdrawn_reason,
            "expired": r.expires_at <= utcnow(),
            "artifacts": [{"os": a.os, "arch": a.arch, "name": a.name, "sha256": a.sha256, "size_bytes": a.size_bytes}
                          for a in r.artifacts],
            "devices_running": (adoption or {}).get(r.version, 0)}


def _z(d):
    return d.isoformat() + "Z" if d else None


def _ring_out(r: AgentUpdateRing, db: Session) -> dict:
    rel = db.get(AgentRelease, r.target_release_id) if r.target_release_id else None
    return {"id": r.id, "name": r.name, "description": r.description, "position": r.position,
            "device_groups": r.device_groups or [], "is_default": r.is_default,
            "target_release_id": r.target_release_id, "target_version": rel.version if rel else None,
            "rollout_percent": r.rollout_percent, "paused": r.paused, "updated_at": _z(r.updated_at),
            "updated_by": r.updated_by,
            "explicit_devices": len(db.scalars(select(Device.id).where(Device.update_ring_id == r.id)).all())}


# ----------------------------------------------------------------------------- user API: read
@router.get("/keys")
def keys():
    try:
        ks = svc.trusted_keys()
    except ValueError as e:
        return {"keys": [], "error": str(e)}
    return {"keys": [{"key_id": k.key_id, "source": k.source} for k in ks], "error": None}


@router.get("/summary")
def summary(db: Session = Depends(get_db)):
    svc.ensure_default_rings(db)
    db.commit()
    return svc.fleet_summary(db)


@router.get("/releases")
def list_releases(db: Session = Depends(get_db)):
    adoption = {v["version"]: v["devices"] for v in svc.fleet_summary(db)["versions"]}
    rels = sorted(db.scalars(select(AgentRelease)), key=lambda r: svc.version_sort_key(r.version), reverse=True)
    return [_release_out(r, adoption) for r in rels]


@router.get("/rings")
def list_rings(db: Session = Depends(get_db)):
    svc.ensure_default_rings(db)
    db.commit()
    return [_ring_out(r, db) for r in svc.rings(db)]


@router.get("/devices/{device_id}")
def device_update_state(device_id: str = Id32(), limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db)):
    d = db.get(Device, device_id)
    if d is None:
        raise HTTPException(404, "device not found")
    t = svc.target_for(db, d)
    pin = db.get(AgentRelease, d.update_pinned_release_id) if d.update_pinned_release_id else None
    events = db.scalars(select(AgentUpdateEvent).where(AgentUpdateEvent.device_id == d.id)
                        .order_by(AgentUpdateEvent.id.desc()).limit(limit))
    return {"device_id": d.id, "agent_version": d.agent_version,
            "pending": auto.pending_state(db, d, t),
            "ring": {"id": t.ring.id, "name": t.ring.name} if t.ring else None,
            "ring_assignment": "explicit" if d.update_ring_id else ("group" if t.ring and not t.ring.is_default
                                                                     else "default"),
            "pinned_release": {"id": pin.id, "version": pin.version} if pin else None,
            "target_version": t.release.version if t.release else None, "target_reason": t.reason,
            "status": d.update_status, "status_version": d.update_status_version,
            "status_detail": d.update_status_detail, "status_at": _z(d.update_status_at),
            "history": [{"id": e.id, "release_id": e.release_id, "from_version": e.from_version,
                         "to_version": e.to_version, "status": e.status, "detail": e.detail,
                         "created_at": _z(e.created_at)} for e in events]}


# ----------------------------------------------------------------------------- user API: admin
@router.post("/releases", status_code=201)
def import_release(request: Request, data: bytes = Body(..., media_type="application/gzip"),
                   admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Import a signed release bundle (.tar.gz: manifest.json + binaries)."""
    try:
        rel = svc.import_bundle(db, data, admin.email)
    except svc.ReleaseError as e:
        db.rollback()
        audit(db, "agent_release_rejected", actor=admin, ip=client_ip(request), reason=str(e)[:500],
              size_bytes=len(data))
        db.commit()
        raise HTTPException(422, str(e)) from None
    audit(db, "agent_release_imported", actor=admin, target=f"agent-release:{rel.id}", ip=client_ip(request),
          version=rel.version, key_id=rel.key_id, bundle_sha256=rel.bundle_sha256,
          artifacts=[f"{a.os}/{a.arch} {a.sha256}" for a in rel.artifacts])
    db.commit()
    return _release_out(rel)


class Reason(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    reason: Annotated[str, StringConstraints(min_length=3, max_length=500)]


@router.post("/releases/{release_id}/withdraw")
def withdraw_release(body: Reason, request: Request, release_id: str = Id32(), admin: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    """Stop offering a release (devices already running it keep it; point rings elsewhere to move them)."""
    rel = db.get(AgentRelease, release_id)
    if rel is None:
        raise HTTPException(404, "release not found")
    if rel.withdrawn_at is None:
        rel.withdrawn_at, rel.withdrawn_reason = utcnow(), body.reason
        audit(db, "agent_release_withdrawn", actor=admin, target=f"agent-release:{rel.id}", ip=client_ip(request),
              version=rel.version, reason=body.reason)
        db.commit()
    return _release_out(rel)


GroupName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")]


class RingIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: Annotated[str, StringConstraints(min_length=1, max_length=64)] | None = None
    description: Annotated[str, StringConstraints(max_length=500)] | None = None
    position: int | None = Field(None, ge=0, le=100000)
    device_groups: list[GroupName] | None = Field(None, max_length=50)
    target_release_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")] | None = None
    clear_target: bool = False
    rollout_percent: int | None = Field(None, ge=0, le=100)
    paused: bool | None = None
    reason: Annotated[str, StringConstraints(min_length=3, max_length=500)]

    @field_validator("device_groups")
    @classmethod
    def _dedupe(cls, v):
        return sorted(set(v)) if v is not None else v


def _apply_ring(db: Session, ring: AgentUpdateRing, body: RingIn, admin: User) -> dict:
    changes: dict = {}
    for f in ("name", "description", "position", "device_groups", "rollout_percent", "paused"):
        v = getattr(body, f)
        if v is not None and v != getattr(ring, f):
            changes[f] = {"from": getattr(ring, f), "to": v}
            setattr(ring, f, v)
    if body.clear_target and ring.target_release_id is not None:
        changes["target_release_id"] = {"from": ring.target_release_id, "to": None}
        ring.target_release_id = None
    elif body.target_release_id and body.target_release_id != ring.target_release_id:
        rel = db.get(AgentRelease, body.target_release_id)
        if rel is None:
            raise HTTPException(404, "release not found")
        if rel.withdrawn_at is not None:
            raise HTTPException(409, f"release {rel.version} is withdrawn")
        changes["target_release_id"] = {"from": ring.target_release_id, "to": rel.id, "version": rel.version}
        ring.target_release_id = rel.id
    if "name" in changes and db.scalar(select(AgentUpdateRing).where(AgentUpdateRing.name == ring.name,
                                                                     AgentUpdateRing.id != ring.id)):
        raise HTTPException(409, "a ring with this name already exists")
    ring.updated_at, ring.updated_by = utcnow(), admin.email
    return changes


@router.post("/rings", status_code=201)
def create_ring(body: RingIn, request: Request,
                admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    if not body.name:
        raise HTTPException(422, "name is required")
    svc.ensure_default_rings(db)
    ring = AgentUpdateRing(name=body.name, position=body.position if body.position is not None else 100,
                           device_groups=[], rollout_percent=100, paused=False)
    if db.scalar(select(AgentUpdateRing).where(AgentUpdateRing.name == body.name)):
        raise HTTPException(409, "a ring with this name already exists")
    db.add(ring)
    changes = _apply_ring(db, ring, body.model_copy(update={"name": None}), admin)
    db.flush()
    audit(db, "agent_update_ring_created", actor=admin, target=f"agent-ring:{ring.id}", ip=client_ip(request),
          name=ring.name, changes=changes, reason=body.reason)
    db.commit()
    return _ring_out(ring, db)


@router.patch("/rings/{ring_id}")
def update_ring(body: RingIn, request: Request, ring_id: str = Id32(),
                admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    ring = db.get(AgentUpdateRing, ring_id)
    if ring is None:
        raise HTTPException(404, "ring not found")
    changes = _apply_ring(db, ring, body, admin)
    audit(db, "agent_update_ring_changed", actor=admin, target=f"agent-ring:{ring.id}", ip=client_ip(request),
          name=ring.name, changes=changes, reason=body.reason)
    db.commit()
    return _ring_out(ring, db)


@router.delete("/rings/{ring_id}", status_code=204)
def delete_ring(request: Request, ring_id: str = Id32(), reason: str = Query(..., min_length=3, max_length=500),
                admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    ring = db.get(AgentUpdateRing, ring_id)
    if ring is None:
        raise HTTPException(404, "ring not found")
    if ring.is_default:
        raise HTTPException(409, "the default ring cannot be deleted")
    for d in db.scalars(select(Device).where(Device.update_ring_id == ring.id)):
        d.update_ring_id = None
    audit(db, "agent_update_ring_deleted", actor=admin, target=f"agent-ring:{ring.id}", ip=client_ip(request),
          name=ring.name, reason=reason)
    db.delete(ring)
    db.commit()


class DeviceUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    ring_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")] | None = None
    clear_ring: bool = False
    pinned_release_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")] | None = None
    clear_pin: bool = False
    reason: Annotated[str, StringConstraints(min_length=3, max_length=500)]


@router.put("/devices/{device_id}")
def set_device_update(body: DeviceUpdateIn, request: Request, device_id: str = Id32(),
                      admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Assign a device to a ring explicitly and/or pin it to a release (pin overrides the ring)."""
    d = db.get(Device, device_id)
    if d is None:
        raise HTTPException(404, "device not found")
    changes: dict = {}
    if body.clear_ring:
        changes["ring"] = {"from": d.update_ring_id, "to": None}
        d.update_ring_id = None
    elif body.ring_id:
        if db.get(AgentUpdateRing, body.ring_id) is None:
            raise HTTPException(404, "ring not found")
        changes["ring"] = {"from": d.update_ring_id, "to": body.ring_id}
        d.update_ring_id = body.ring_id
    if body.clear_pin:
        changes["pin"] = {"from": d.update_pinned_release_id, "to": None}
        d.update_pinned_release_id = None
    elif body.pinned_release_id:
        rel = db.get(AgentRelease, body.pinned_release_id)
        if rel is None:
            raise HTTPException(404, "release not found")
        if rel.withdrawn_at is not None:
            raise HTTPException(409, f"release {rel.version} is withdrawn")
        changes["pin"] = {"from": d.update_pinned_release_id, "to": rel.id, "version": rel.version}
        d.update_pinned_release_id = rel.id
    if not changes:
        raise HTTPException(422, "nothing to change")
    audit(db, "agent_update_device_changed", actor=admin, target=f"device:{d.id}", ip=client_ip(request),
          hostname=d.hostname, changes=changes, reason=body.reason)
    db.commit()
    return device_update_state(device_id, 50, db)
