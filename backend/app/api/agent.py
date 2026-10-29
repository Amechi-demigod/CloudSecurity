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
import re

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Path, Request
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config, tenancy
from ..auth import RateLimiter, audit, client_ip
from ..db import get_db
from ..models import Device, DeviceCommand, DeviceCredential, DeviceLogBundle, EnrollmentToken, utcnow
from ..notifications import agent_security, approval_source, device_source, host_isolation_source
from ..schemas_devices import (
    AgentCommand,
    AgentCommandList,
    CheckinRequest,
    CheckinResponse,
    CommandAckIn,
    CommandResultIn,
    EnrollRequest,
    EnrollResponse,
    validate_result_data,
)
from ..services import agent_updates, approvals
from ..services import devices as svc

log = logging.getLogger(__name__)
_FEATURE_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

router = APIRouter(prefix="/api/agent", tags=["agent"])
device_limiter = RateLimiter()
enroll_limiter = RateLimiter()
enroll_failure_limiter = RateLimiter()
CommandId = Path(pattern=r"^[0-9a-f]{32}$")


def _deny(status: int, detail: str, request: Request | None = None, kind: str = "invalid_credential") -> HTTPException:
    if request is not None:
        agent_security.rejected(kind, client_ip(request))
    return HTTPException(status, detail, headers={"WWW-Authenticate": "Bearer"} if status == 401 else None)


def current_device(request: Request, authorization: str | None = Header(None),
                   db: Session = Depends(get_db)) -> Device:
    """Resolve the device credential; reject revoked devices and rate-limit per device."""
    s = config.settings
    scheme, _, token = (authorization or "").strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token.startswith(svc.DEVICE_SECRET_PREFIX) or len(token) > 128:
        raise _deny(401, "missing or invalid device credential", request)
    # The credential determines the organisation: everything this request reads
    # or writes is scoped to it (app/tenancy.py).
    with tenancy.unscoped(db):
        cred = db.scalar(select(DeviceCredential).where(DeviceCredential.secret_hash == svc.hash_secret(token)))
    if cred is None:
        raise _deny(401, "missing or invalid device credential", request)
    _require_active_org(db, cred.organization_id, request)
    tenancy.set_org(db, cred.organization_id)
    device = cred.device
    if device.status != "active":
        raise _deny(403, "device revoked: re-enroll with a new enrollment token", request, "revoked_device")
    if cred.revoked_at is not None:
        raise _deny(401, "device credential superseded (the device was re-enrolled)", request, "superseded_credential")
    if not device_limiter.hit(f"device:{device.id}", s.device_rate_limit, s.device_rate_window_seconds):
        agent_security.rejected("device_rate_limited", client_ip(request))
        raise HTTPException(429, "rate limit exceeded for this device",
                            headers={"Retry-After": str(int(s.device_rate_window_seconds / 4))})
    now = utcnow()
    cred.last_used_at = now
    device.last_seen_at = now
    device.last_ip = client_ip(request)
    return device


def _require_active_org(db: Session, org_id: str, request: Request) -> None:
    org = tenancy.get_org(db, org_id)
    if org is None or org.status != "active":
        raise _deny(403, "organisation suspended", request, "suspended_organization")


@router.post("/enroll", response_model=EnrollResponse)
def enroll(body: EnrollRequest, request: Request, db: Session = Depends(get_db)):
    """Exchange an enrollment token for a per-device credential (shown once)."""
    s = config.settings
    ip = client_ip(request)
    # Per source IP: all attempts (generous: offices enroll many devices behind one
    # NAT address) and failed attempts (small: tokens are not guessable, but a
    # client that keeps failing is a scanner or a broken script).
    if (enroll_failure_limiter.blocked(f"ip:{ip}", s.enroll_failure_limit, s.enroll_rate_window_seconds)
            or not enroll_limiter.hit(f"ip:{ip}", s.enroll_rate_limit, s.enroll_rate_window_seconds)):
        agent_security.rejected("enroll_rate_limited", ip)
        raise HTTPException(429, "too many enrollment attempts", headers={"Retry-After": "60"})
    # The enrollment token determines the organisation the device joins.
    with tenancy.unscoped(db):
        org_id = db.scalar(select(EnrollmentToken.organization_id)
                           .where(EnrollmentToken.token_hash == svc.hash_secret(body.token)))
    if org_id is not None:
        _require_active_org(db, org_id, request)
        tenancy.set_org(db, org_id)
    token = svc.consume_enrollment_token(db, body.token) if org_id is not None else None
    info = body.device
    if token is None:
        enroll_failure_limiter.hit(f"ip:{ip}", s.enroll_failure_limit, s.enroll_rate_window_seconds)
        agent_security.rejected("enroll_failed", ip)
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
    if token.device_group:
        device.device_group = token.device_group
    device.last_seen_at, device.last_ip = now, ip
    if existing is None:
        db.add(device)
    db.flush()
    secret = svc.issue_credential(db, device)
    audit(db, "device_reenrolled" if existing else "device_enrolled", actor_email=f"enrollment-token:{token.name}"[:320],
          target=f"device:{device.id}", ip=ip, hostname=device.hostname, os_family=device.os_family,
          token_id=token.id, previously_revoked=was_revoked, installer=token.package_platform)
    db.commit()
    log.info("device %s (%s) %s", device.id, device.hostname, "re-enrolled" if existing else "enrolled")
    return EnrollResponse(device_id=device.id, device_secret=secret,
                          check_in_interval_seconds=device.check_in_interval_seconds,
                          command_poll_seconds=svc.COMMAND_POLL_SECONDS, server_time=now,
                          reenrolled=existing is not None)


def _detect_isolation_crash_recovery(db: Session, device: Device) -> None:
    """The agent's Suspend-sign-in Manager.OnStart reports a crash-recovery
    outcome on exactly one check-in after it resolves an incomplete suspend or
    restore (see endpoint-agent/internal/signin). A malformed or missing field
    is ignored defensively - this must never break a check-in, and re-seeing
    the same outcome on a later check-in (a retried request) just re-notifies
    rather than failing."""
    data = ((device.posture or {}).get("isolation") or {}).get("data") or {}
    if data.get("recovered_at_boot") is not True:
        return
    outcome = data.get("recovery_outcome")
    if outcome not in ("rolled_back", "completed"):
        return
    try:
        audit(db, f"host_isolation_{outcome}_after_crash", actor_email=f"device:{device.hostname}"[:320],
              target=f"device:{device.id}", recovery_outcome=outcome)
        host_isolation_source.notify(db, device, f"{outcome}_after_crash", data=data)
    except Exception:  # must never break a check-in
        log.exception("failed to record isolation crash-recovery for device %s", device.id)


@router.post("/checkin", response_model=CheckinResponse)
def checkin(body: CheckinRequest, request: Request, device: Device = Depends(current_device),
            db: Session = Depends(get_db)):
    """Full inventory + posture report (every check-in interval, or on recheck_posture)."""
    if body.device.os_family != device.os_family:
        raise HTTPException(409, f"device is enrolled as {device.os_family}, not {body.device.os_family}")
    issues = svc.apply_checkin(db, device, body, client_ip(request))
    _detect_isolation_crash_recovery(db, device)
    features = request.headers.get("x-cnapp-agent-features", "")
    device.agent_features = ",".join(f for f in features.split(",") if _FEATURE_RE.match(f.strip()))[:128] or None
    pending = svc.pending_count(db, device.id)
    db.commit()
    try:
        offer = agent_updates.offer_for(db, device, request.headers.get("user-agent"))
        db.commit()  # the offer is recorded on the device (console: "offered at ...")
    except Exception:  # an update problem must never break check-ins
        db.rollback()
        log.exception("computing the update offer for device %s failed", device.id)
        offer = None
    return CheckinResponse(device_id=device.id, server_time=utcnow(), pending_commands=pending, issues=issues,
                           update=offer)


@router.get("/commands", response_model=AgentCommandList)
def fetch_commands(device: Device = Depends(current_device), db: Session = Depends(get_db)):
    """Pending commands for this device. Each is handed out once (then 'delivered')."""
    approvals.release_due(db, device.id)  # self-approved actions whose cooling-off delay is over
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
    try:
        result_data = validate_result_data(cmd.type, body.result_data)
    except (ValueError, PydanticValidationError) as e:
        raise HTTPException(422, str(e)) from None
    cmd.status = body.status
    cmd.output = body.output
    cmd.result_data = result_data or None
    cmd.completed_at = utcnow()
    if cmd.type == "run_script":
        cmd.exit_code = body.exit_code
    if cmd.type == "update_check_in_interval" and body.status == "succeeded":
        device.check_in_interval_seconds = svc.clamp_interval(int(cmd.params.get("interval_seconds", 900)))
    svc.command_finished(device, cmd)
    audit(db, "device_command_completed", actor_email=f"device:{device.hostname}"[:320],
          target=f"device:{device.id}", command_id=cmd.id, type=cmd.type, status=body.status,
          exit_code=cmd.exit_code)
    incident_id = (cmd.params or {}).get("incident_id")
    if cmd.type == "isolate_host":
        blocked = body.status != "succeeded" and result_data.get("error_code") == "ERR_NO_LOCAL_ADMIN_PRESENT"
        if blocked:
            audit(db, "host_isolation_preflight_blocked", actor_email=f"device:{device.hostname}"[:320],
                  target=f"device:{device.id}", command_id=cmd.id, status=body.status)
            host_isolation_source.notify(
                db, device, "preflight_blocked_no_local_admin",
                actor=cmd.requested_by_email, detail=body.output, data=result_data, incident_id=incident_id,
            )
        else:
            audit(db, "host_isolated" if body.status == "succeeded" else "host_isolation_failed",
                  actor_email=f"device:{device.hostname}"[:320], target=f"device:{device.id}",
                  command_id=cmd.id, status=body.status)
            host_isolation_source.notify(
                db, device, "host_isolated" if body.status == "succeeded" else "isolation_failed",
                actor=cmd.requested_by_email, detail=body.output, data=result_data, incident_id=incident_id,
            )
    elif cmd.type == "restore_host":
        audit(db, "host_restored" if body.status == "succeeded" else "host_restore_failed",
              actor_email=f"device:{device.hostname}"[:320], target=f"device:{device.id}",
              command_id=cmd.id, status=body.status)
        host_isolation_source.notify(
            db, device, "host_restored" if body.status == "succeeded" else "restore_failed",
            actor=cmd.requested_by_email, detail=body.output, data=result_data,
        )
    device_source.command_completed(db, device, cmd)
    db.commit()


@router.post("/commands/{command_id}/ack")
def command_ack(body: CommandAckIn, command_id: str = CommandId, device: Device = Depends(current_device),
                db: Session = Depends(get_db)):
    """wipe_device: the agent's final acknowledgement, sent right before it
    starts the wipe. The agent only wipes after this returns {"proceed": true},
    so the console always learns that a wipe began (the device may never report
    again). Acknowledging twice is refused (single use)."""
    cmd = _delivered_command(db, device, command_id, body.nonce)
    if cmd.type != "wipe_device":
        raise HTTPException(409, "only wipe_device is acknowledged")
    if cmd.acknowledged_at is not None:
        raise HTTPException(409, "this wipe was already acknowledged")
    now = utcnow()
    if cmd.expires_at <= now:
        raise HTTPException(409, "the wipe command expired")
    cmd.acknowledged_at = now
    if device.wipe_command_id == cmd.id:
        device.wipe_status, device.wipe_status_at = "acknowledged", now
    audit(db, "device_wipe_acknowledged", actor_email=f"device:{device.hostname}"[:320],
          target=f"device:{device.id}", command_id=cmd.id, approval_id=cmd.approval_id,
          mode=(cmd.params or {}).get("mode"))
    if cmd.approval_id:
        from ..models import DeviceApproval

        a = db.get(DeviceApproval, cmd.approval_id)
        if a is not None:
            approval_source.notify(db, a, device, "wipe_acknowledged")
    db.commit()
    return {"proceed": True, "server_time": now.isoformat() + "Z"}


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
