"""Device management for users (/api/devices/*), session-authenticated with RBAC.

viewer  : read everything except log bundles
analyst : + recheck_posture, collect_logs, download log bundles
admin   : + lock_device, restart_agent, update_check_in_interval, enrollment
          tokens, revoke / delete devices

Every remote action needs a reason and is written to the audit log.
"""
from __future__ import annotations

import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .. import config
from ..auth import ROLE_RANK, audit, client_ip, current_user, require_admin, require_analyst
from ..db import get_db
from ..models import (
    Device,
    DeviceCommand,
    DeviceLogBundle,
    DevicePostureSnapshot,
    DeviceSoftware,
    EnrollmentToken,
    User,
    utcnow,
)
from ..schemas_devices import (
    COMMAND_ROLES,
    CommandCreate,
    CommandOut,
    DeviceAction,
    DeviceDetailOut,
    DeviceSummaryOut,
    EnrollmentTokenCreate,
    EnrollmentTokenCreated,
    EnrollmentTokenOut,
    SnapshotOut,
    SoftwareOut,
)
from ..services import devices as svc

router = APIRouter(prefix="/api/devices", tags=["devices"])
DeviceId = Path(pattern=r"^[0-9a-f]{32}$")


def _get_device(db: Session, device_id: str) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(404, "device not found")
    return device


def _token_out(t: EnrollmentToken, cls=EnrollmentTokenOut, **extra):
    return cls(id=t.id, name=t.name, token_prefix=t.token_prefix, max_uses=t.max_uses, use_count=t.use_count,
               created_by=t.created_by, created_at=t.created_at, expires_at=t.expires_at,
               last_used_at=t.last_used_at, revoked_at=t.revoked_at, state=svc.token_state(t), **extra)


# ----------------------------------------------------------------------------- fleet
@router.get("", response_model=list[DeviceSummaryOut])
def list_devices(db: Session = Depends(get_db),
                 q: str | None = Query(None, max_length=255),
                 os: str | None = Query(None, pattern="^(windows|macos|linux)$"),
                 health: str | None = Query(None, pattern="^(healthy|warning|critical|unknown)$"),
                 issue: str | None = Query(None, max_length=64),
                 connectivity: str | None = Query(None, pattern="^(active|stale|inactive|never)$"),
                 status: str = Query("active", pattern="^(active|revoked|all)$"),
                 limit: int = Query(500, ge=1, le=5000)):
    stmt = select(Device)
    if status != "all":
        stmt = stmt.where(Device.status == status)
    if os:
        stmt = stmt.where(Device.os_family == os)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(Device.hostname.ilike(like), Device.serial_number.ilike(like),
                              Device.model.ilike(like), Device.id == q.lower()))
    now = utcnow()
    out = []
    for d in db.scalars(stmt.order_by(Device.hostname)):
        sm = svc.summarize(d, now)
        if health and sm["health"] != health:
            continue
        if connectivity and sm["connectivity"] != connectivity:
            continue
        if issue and issue not in {i["code"] for i in sm["issues"]}:
            continue
        out.append(sm)
        if len(out) >= limit:
            break
    return out


@router.get("/summary")
def devices_summary(db: Session = Depends(get_db)):
    """Fleet counts for the dashboard tile."""
    return svc.fleet_summary(db)


@router.get("/issue-types")
def issue_types():
    return [{"code": c, "severity": sev, "title": t} for c, (sev, t) in svc.ISSUE_DEFS.items()]


# ----------------------------------------------------------------------------- enrollment (admin)
@router.get("/enrollment/info", dependencies=[Depends(require_admin)])
def enrollment_info():
    s = config.settings
    return {"agent_download_url": s.agent_download_url, "default_check_in_interval_seconds":
            svc.DEFAULT_INTERVAL_SECONDS, "command_poll_seconds": svc.COMMAND_POLL_SECONDS}


@router.get("/enrollment-tokens", response_model=list[EnrollmentTokenOut], dependencies=[Depends(require_admin)])
def list_tokens(db: Session = Depends(get_db)):
    return [_token_out(t) for t in db.scalars(select(EnrollmentToken).order_by(EnrollmentToken.created_at.desc()))]


@router.post("/enrollment-tokens", response_model=EnrollmentTokenCreated, status_code=201)
def create_token(body: EnrollmentTokenCreate, request: Request, admin: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    raw = svc.new_enrollment_token()
    now = utcnow()
    t = EnrollmentToken(name=body.name, token_hash=svc.hash_secret(raw), token_prefix=raw[:10],
                        max_uses=body.max_uses, created_by=admin.email, created_at=now,
                        expires_at=now + timedelta(hours=body.expires_in_hours))
    db.add(t)
    db.flush()
    audit(db, "enrollment_token_created", actor=admin, target=f"enrollment-token:{t.id}", ip=client_ip(request),
          name=t.name, max_uses=t.max_uses, expires_at=t.expires_at.isoformat() + "Z")
    db.commit()
    return _token_out(t, EnrollmentTokenCreated, token=raw)


@router.post("/enrollment-tokens/{token_id}/revoke", response_model=EnrollmentTokenOut)
def revoke_token(request: Request, token_id: str = Path(pattern=r"^[0-9a-f]{32}$"),
                 admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    t = db.get(EnrollmentToken, token_id)
    if t is None:
        raise HTTPException(404, "enrollment token not found")
    if t.revoked_at is None:
        t.revoked_at = utcnow()
        audit(db, "enrollment_token_revoked", actor=admin, target=f"enrollment-token:{t.id}",
              ip=client_ip(request), name=t.name)
        db.commit()
    return _token_out(t)


# ----------------------------------------------------------------------------- one device
@router.get("/{device_id}", response_model=DeviceDetailOut)
def device_detail(device_id: str = DeviceId, db: Session = Depends(get_db)):
    d = _get_device(db, device_id)
    return {**svc.summarize(d), "os_build": d.os_build, "last_ip": d.last_ip,
            "check_in_interval_seconds": d.check_in_interval_seconds, "software_count": d.software_count,
            "updates_pending_since": d.updates_pending_since, "revoked_at": d.revoked_at,
            "inventory": d.inventory or {}, "posture": d.posture or {}, "collection_errors": d.collection_errors or {}}


@router.get("/{device_id}/software", response_model=list[SoftwareOut])
def device_software(device_id: str = DeviceId, q: str | None = Query(None, max_length=255),
                    db: Session = Depends(get_db)):
    _get_device(db, device_id)
    stmt = select(DeviceSoftware).where(DeviceSoftware.device_id == device_id)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(DeviceSoftware.name.ilike(like), DeviceSoftware.publisher.ilike(like)))
    return list(db.scalars(stmt.order_by(DeviceSoftware.name, DeviceSoftware.version)))


@router.get("/{device_id}/history", response_model=list[SnapshotOut])
def device_history(device_id: str = DeviceId, limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db)):
    _get_device(db, device_id)
    return list(db.scalars(select(DevicePostureSnapshot).where(DevicePostureSnapshot.device_id == device_id)
                           .order_by(DevicePostureSnapshot.id.desc()).limit(limit)))


@router.get("/{device_id}/commands", response_model=list[CommandOut])
def device_commands(device_id: str = DeviceId, limit: int = Query(100, ge=1, le=1000),
                    db: Session = Depends(get_db)):
    _get_device(db, device_id)
    svc.expire_commands(db, device_id)
    db.commit()
    return list(db.scalars(select(DeviceCommand).where(DeviceCommand.device_id == device_id)
                           .order_by(DeviceCommand.created_at.desc()).limit(limit)))


@router.post("/{device_id}/commands", response_model=CommandOut, status_code=201)
def create_command(body: CommandCreate, request: Request, device_id: str = DeviceId,
                   user: User = Depends(current_user), db: Session = Depends(get_db)):
    needed = COMMAND_ROLES[body.type]
    if ROLE_RANK.get(user.role, -1) < ROLE_RANK[needed]:
        raise HTTPException(403, f"{body.type} requires the {needed} role")
    device = _get_device(db, device_id)
    if device.status != "active":
        raise HTTPException(409, "device is revoked")
    try:
        params = svc.validate_params(body.type, body.params)
    except ValueError as e:
        raise HTTPException(422, str(e)) from None
    now = utcnow()
    ttl = body.expires_in_hours or config.settings.device_command_ttl_hours
    cmd = DeviceCommand(device_id=device.id, type=body.type, params=params, nonce=secrets.token_hex(16),
                        reason=body.reason, requested_by_id=user.id, requested_by_email=user.email, created_at=now,
                        expires_at=now + timedelta(hours=ttl))
    db.add(cmd)
    db.flush()
    audit(db, "device_command_created", actor=user, target=f"device:{device.id}", ip=client_ip(request),
          hostname=device.hostname, command_id=cmd.id, type=cmd.type, params=params, reason=body.reason)
    db.commit()
    return cmd


@router.post("/{device_id}/commands/{command_id}/cancel", response_model=CommandOut)
def cancel_command(body: DeviceAction, request: Request, device_id: str = DeviceId,
                   command_id: str = Path(pattern=r"^[0-9a-f]{32}$"), user: User = Depends(require_analyst),
                   db: Session = Depends(get_db)):
    cmd = db.get(DeviceCommand, command_id)
    if cmd is None or cmd.device_id != device_id:
        raise HTTPException(404, "command not found")
    if ROLE_RANK[user.role] < ROLE_RANK[COMMAND_ROLES.get(cmd.type, "admin")]:
        raise HTTPException(403, f"cancelling {cmd.type} requires the {COMMAND_ROLES.get(cmd.type, 'admin')} role")
    if cmd.status != "pending":
        raise HTTPException(409, f"only pending commands can be cancelled (this one is {cmd.status})")
    cmd.status, cmd.completed_at, cmd.output = "cancelled", utcnow(), f"cancelled by {user.email}"
    audit(db, "device_command_cancelled", actor=user, target=f"device:{device_id}", ip=client_ip(request),
          command_id=cmd.id, type=cmd.type, reason=body.reason)
    db.commit()
    return cmd


@router.get("/{device_id}/log-bundles/{bundle_id}")
def download_log_bundle(request: Request, device_id: str = DeviceId, bundle_id: str = Path(pattern=r"^[0-9a-f]{32}$"),
                        user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    b = db.get(DeviceLogBundle, bundle_id)
    if b is None or b.device_id != device_id:
        raise HTTPException(404, "log bundle not found")
    audit(db, "device_log_bundle_downloaded", actor=user, target=f"device:{device_id}", ip=client_ip(request),
          bundle_id=b.id, size_bytes=b.size_bytes)
    db.commit()
    return Response(content=b.data, media_type="application/gzip", headers={
        "Content-Disposition": f'attachment; filename="device-{device_id[:8]}-logs-{b.id[:8]}.tar.gz"',
        "X-Content-SHA256": b.sha256})


@router.post("/{device_id}/revoke", response_model=DeviceDetailOut)
def revoke(body: DeviceAction, request: Request, device_id: str = DeviceId, admin: User = Depends(require_admin),
           db: Session = Depends(get_db)):
    """Invalidate the device credential: the agent is rejected until re-enrolled."""
    d = _get_device(db, device_id)
    if d.status != "revoked":
        svc.revoke_device(db, d)
        audit(db, "device_revoked", actor=admin, target=f"device:{d.id}", ip=client_ip(request),
              hostname=d.hostname, reason=body.reason)
        db.commit()
    return device_detail(device_id, db)


@router.delete("/{device_id}", status_code=204)
def delete_device(request: Request, device_id: str = DeviceId,
                  reason: str = Query(..., min_length=3, max_length=500),
                  admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Remove the device and all its data (history, software, commands, log bundles)."""
    d = _get_device(db, device_id)
    audit(db, "device_deleted", actor=admin, target=f"device:{d.id}", ip=client_ip(request),
          hostname=d.hostname, serial_number=d.serial_number, reason=reason.strip())
    db.delete(d)
    db.commit()
