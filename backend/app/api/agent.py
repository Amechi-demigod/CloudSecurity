"""Endpoint-agent API (/api/agent/*).

Authenticated by the per-device credential (`Authorization: Bearer cnd_...`),
never by user sessions: no cookies are read here, so there is no CSRF surface,
and a device credential is not accepted by any user endpoint. Enrollment is
authenticated by an admin-issued enrollment token in the request body.
"""
from __future__ import annotations

import hashlib
import hmac
import logging

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Path, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..auth import RateLimiter, audit, client_ip
from ..db import get_db
from ..models import Device, DeviceCommand, DeviceCredential, DeviceLogBundle, utcnow
from ..schemas_devices import (
    AgentCommand,
    AgentCommandList,
    CheckinRequest,
    CheckinResponse,
    CommandResultIn,
    EnrollRequest,
    EnrollResponse,
)
from ..services import devices as svc

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/agent", tags=["agent"])
device_limiter = RateLimiter()
enroll_limiter = RateLimiter()
CommandId = Path(pattern=r"^[0-9a-f]{32}$")


def _deny(status: int, detail: str) -> HTTPException:
    return HTTPException(status, detail, headers={"WWW-Authenticate": "Bearer"} if status == 401 else None)


def current_device(request: Request, authorization: str | None = Header(None),
                   db: Session = Depends(get_db)) -> Device:
    """Resolve the device credential; reject revoked devices and rate-limit per device."""
    s = config.settings
    scheme, _, token = (authorization or "").strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token.startswith(svc.DEVICE_SECRET_PREFIX) or len(token) > 128:
        raise _deny(401, "missing or invalid device credential")
    cred = db.scalar(select(DeviceCredential).where(DeviceCredential.secret_hash == svc.hash_secret(token)))
    if cred is None:
        raise _deny(401, "missing or invalid device credential")
    device = cred.device
    if device.status != "active":
        raise _deny(403, "device revoked: re-enroll with a new enrollment token")
    if cred.revoked_at is not None:
        raise _deny(401, "device credential superseded (the device was re-enrolled)")
    if not device_limiter.hit(f"device:{device.id}", s.device_rate_limit, s.device_rate_window_seconds):
        raise HTTPException(429, "rate limit exceeded for this device",
                            headers={"Retry-After": str(int(s.device_rate_window_seconds / 4))})
    now = utcnow()
    cred.last_used_at = now
    device.last_seen_at = now
    device.last_ip = client_ip(request)
    return device


@router.post("/enroll", response_model=EnrollResponse)
def enroll(body: EnrollRequest, request: Request, db: Session = Depends(get_db)):
    """Exchange an enrollment token for a per-device credential (shown once)."""
    s = config.settings
    ip = client_ip(request)
    if not enroll_limiter.hit(f"ip:{ip}", s.enroll_rate_limit, s.enroll_rate_window_seconds):
        raise HTTPException(429, "too many enrollment attempts", headers={"Retry-After": "60"})
    token = svc.consume_enrollment_token(db, body.token)
    info = body.device
    if token is None:
        audit(db, "device_enroll_failed", actor_email=f"device:{info.hostname}"[:320], ip=ip,
              reason="invalid, expired, revoked or used-up enrollment token")
        db.commit()
        raise _deny(401, "invalid, expired, revoked or used-up enrollment token")
    existing = None
    if info.machine_id:
        existing = db.scalar(select(Device).where(Device.os_family == info.os_family,
                                                  Device.machine_id == info.machine_id)
                             .order_by(Device.enrolled_at.desc()).limit(1))
    now = utcnow()
    device = existing or Device(os_family=info.os_family, machine_id=info.machine_id,
                                check_in_interval_seconds=svc.DEFAULT_INTERVAL_SECONDS)
    was_revoked = existing is not None and existing.status == "revoked"
    device.hostname = info.hostname
    device.os_name, device.os_version = info.os_name, info.os_version
    device.serial_number = info.serial_number or device.serial_number or ""
    device.agent_version = info.agent_version
    device.status, device.revoked_at = "active", None
    device.enrolled_at, device.enrollment_token_id = now, token.id
    device.last_seen_at, device.last_ip = now, ip
    if existing is None:
        db.add(device)
    db.flush()
    secret = svc.issue_credential(db, device)
    audit(db, "device_reenrolled" if existing else "device_enrolled", actor_email=f"enrollment-token:{token.name}"[:320],
          target=f"device:{device.id}", ip=ip, hostname=device.hostname, os_family=device.os_family,
          token_id=token.id, previously_revoked=was_revoked)
    db.commit()
    log.info("device %s (%s) %s", device.id, device.hostname, "re-enrolled" if existing else "enrolled")
    return EnrollResponse(device_id=device.id, device_secret=secret,
                          check_in_interval_seconds=device.check_in_interval_seconds,
                          command_poll_seconds=svc.COMMAND_POLL_SECONDS, server_time=now,
                          reenrolled=existing is not None)


@router.post("/checkin", response_model=CheckinResponse)
def checkin(body: CheckinRequest, request: Request, device: Device = Depends(current_device),
            db: Session = Depends(get_db)):
    """Full inventory + posture report (every check-in interval, or on recheck_posture)."""
    if body.device.os_family != device.os_family:
        raise HTTPException(409, f"device is enrolled as {device.os_family}, not {body.device.os_family}")
    issues = svc.apply_checkin(db, device, body, client_ip(request))
    pending = svc.pending_count(db, device.id)
    db.commit()
    return CheckinResponse(device_id=device.id, server_time=utcnow(), pending_commands=pending, issues=issues)


@router.get("/commands", response_model=AgentCommandList)
def fetch_commands(device: Device = Depends(current_device), db: Session = Depends(get_db)):
    """Pending commands for this device. Each is handed out once (then 'delivered')."""
    cmds = svc.deliver_pending(db, device)
    db.commit()
    return AgentCommandList(server_time=utcnow(), commands=[
        AgentCommand(id=c.id, device_id=c.device_id, type=c.type, params=c.params or {}, nonce=c.nonce,
                     issued_at=c.created_at, expires_at=c.expires_at) for c in cmds])


def _delivered_command(db: Session, device: Device, command_id: str, nonce: str) -> DeviceCommand:
    cmd = db.get(DeviceCommand, command_id)
    if cmd is None or cmd.device_id != device.id:
        raise HTTPException(404, "command not found")
    if not hmac.compare_digest(nonce.encode(), cmd.nonce.encode()):
        raise HTTPException(403, "nonce mismatch")
    if cmd.status != "delivered":
        raise HTTPException(409, f"command is {cmd.status}, not awaiting a result")
    return cmd


@router.post("/commands/{command_id}/result", status_code=204)
def command_result(body: CommandResultIn, command_id: str = CommandId, device: Device = Depends(current_device),
                   db: Session = Depends(get_db)):
    cmd = _delivered_command(db, device, command_id, body.nonce)
    cmd.status = body.status
    cmd.output = body.output
    cmd.completed_at = utcnow()
    if cmd.type == "update_check_in_interval" and body.status == "succeeded":
        device.check_in_interval_seconds = svc.clamp_interval(int(cmd.params.get("interval_seconds", 900)))
    audit(db, "device_command_completed", actor_email=f"device:{device.hostname}"[:320],
          target=f"device:{device.id}", command_id=cmd.id, type=cmd.type, status=body.status)
    db.commit()


@router.post("/commands/{command_id}/logs", status_code=201)
def upload_logs(command_id: str = CommandId, data: bytes = Body(..., media_type="application/gzip"),
                x_command_nonce: str = Header(..., max_length=64), device: Device = Depends(current_device),
                db: Session = Depends(get_db)):
    """Log bundle (gzip tar) for a delivered collect_logs command."""
    s = config.settings
    cmd = _delivered_command(db, device, command_id, x_command_nonce)
    if cmd.type != "collect_logs":
        raise HTTPException(409, "command is not collect_logs")
    if cmd.log_bundle_id:
        raise HTTPException(409, "a log bundle was already uploaded for this command")
    if len(data) > s.device_log_bundle_max_bytes:
        raise HTTPException(413, f"log bundle exceeds {s.device_log_bundle_max_bytes} bytes")
    if not data.startswith(b"\x1f\x8b"):
        raise HTTPException(415, "log bundle must be gzip-compressed")
    bundle = DeviceLogBundle(device_id=device.id, command_id=cmd.id, size_bytes=len(data),
                             sha256=hashlib.sha256(data).hexdigest(), data=data)
    db.add(bundle)
    db.flush()
    cmd.log_bundle_id = bundle.id
    db.commit()
    return {"id": bundle.id, "size_bytes": bundle.size_bytes, "sha256": bundle.sha256}
