"""Device management for users (/api/devices/*), session-authenticated with RBAC.

viewer  : read everything except log bundles
analyst : + recheck_posture, collect_logs, download log bundles
admin   : + lock_device, restart_agent, update_check_in_interval, lost mode
          (enable_lost_mode / disable_lost_mode), enrollment tokens, revoke /
          delete devices, and *request* a remote wipe (Windows only; executed
          only after a second admin approves, see app/services/approvals.py)

Every remote action needs a reason and is written to the audit log.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .. import config
from ..auth import ROLE_RANK, RateLimiter, audit, client_ip, current_user, require_admin, require_analyst
from ..db import get_db
from ..models import (
    Device,
    DeviceCommand,
    DeviceLogBundle,
    DevicePostureSnapshot,
    DeviceSoftware,
    EnrollmentToken,
    User,
    Vulnerability,
    utcnow,
)
from ..notifications import host_isolation_source
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
    InstallerCreate,
    SnapshotOut,
    SoftwareOut,
)
from ..services import approvals, installers
from ..services import devices as svc

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/devices", tags=["devices"])
installer_limiter = RateLimiter()
DeviceId = Path(pattern=r"^[0-9a-f]{32}$")


def _get_device(db: Session, device_id: str) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(404, "device not found")
    return device


def _token_out(t: EnrollmentToken, cls=EnrollmentTokenOut, **extra):
    return cls(id=t.id, name=t.name, token_prefix=t.token_prefix, package_platform=t.package_platform,
               device_group=t.device_group, max_uses=t.max_uses, use_count=t.use_count,
               created_by=t.created_by, created_at=t.created_at, expires_at=t.expires_at,
               last_used_at=t.last_used_at, revoked_at=t.revoked_at, state=svc.token_state(t), **extra)


# ----------------------------------------------------------------------------- fleet
@router.get("", response_model=list[DeviceSummaryOut])
def list_devices(db: Session = Depends(get_db),
                 q: str | None = Query(None, max_length=255),
                 os: str | None = Query(None, pattern="^(windows|macos|linux)$"),
                 health: str | None = Query(None, pattern="^(healthy|warning|critical|unknown)$"),
                 issue: str | None = Query(None, max_length=64),
                 connectivity: str | None = Query(None, pattern="^(active|stale|inactive|never|offline)$",
                                                   description="offline = stale or inactive (no check-in for 24 h+)"),
                 status: str = Query("active", pattern="^(active|revoked|all)$"),
                 group: str | None = Query(None, max_length=64),
                 limit: int = Query(500, ge=1, le=5000)):
    stmt = select(Device)
    if status != "all":
        stmt = stmt.where(Device.status == status)
    if os:
        stmt = stmt.where(Device.os_family == os)
    if group:
        stmt = stmt.where(Device.device_group == group)
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
        if connectivity and sm["connectivity"] not in (("stale", "inactive") if connectivity == "offline" else (connectivity,)):
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
    return {"agent_download_url": s.agent_download_url, "server_url": installers.server_url_or_none(),
            "default_check_in_interval_seconds":
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


@router.get("/installers", dependencies=[Depends(require_admin)])
def installer_info():
    """What a pre-configured installer would contain (never the token) and which platforms are available."""
    try:
        server, server_error = installers.server_url(), None
    except installers.InstallerConfigError as e:
        server, server_error = None, str(e)
    try:
        ca, ca_error = installers.server_ca_pem(), None
    except installers.InstallerConfigError as e:
        ca, ca_error = None, str(e)
    return {"server_url": server, "server_error": server_error, "ca_configured": ca is not None,
            "ca_error": ca_error, "include_ca_default": ca is not None, "platforms": installers.availability(),
            "defaults": {"expires_in_days": 30, "max_devices": 500}}


@router.post("/installers")
def create_installer(body: InstallerCreate, request: Request, admin: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    """Mint a package-bound enrollment token and return the installer with it embedded.

    The token's plaintext exists only in the response body (the file); the
    database keeps its hash like any other enrollment token, so it is listed,
    limited and revocable under Enrollment tokens."""
    s = config.settings
    if not installer_limiter.hit(f"user:{admin.id}", s.agent_installer_rate_limit,
                                 s.agent_installer_rate_window_seconds):
        raise HTTPException(429, "too many installer downloads; try again later", headers={"Retry-After": "60"})
    include_ca = body.include_ca
    if body.allow_wipe and body.platform != "windows-msi":
        raise HTTPException(422, "remote wipe is only available for Windows devices (MSI)")
    try:
        if include_ca is None:
            include_ca = installers.server_ca_pem() is not None
        installers.server_url()
        installers.artifact(body.platform, verify=False)
    except installers.InstallerConfigError as e:
        raise HTTPException(409, str(e)) from None
    except installers.InstallerUnavailable as e:
        raise HTTPException(503, str(e)) from None
    spec = installers.PLATFORMS[body.platform]
    raw = svc.new_enrollment_token()
    now = utcnow()
    name = body.name or f"Installer {spec['label']} {now:%Y-%m-%d}"
    t = EnrollmentToken(name=name[:128], token_hash=svc.hash_secret(raw), token_prefix=raw[:10],
                        max_uses=body.max_devices, created_by=admin.email, created_at=now,
                        expires_at=now + timedelta(days=body.expires_in_days), package_platform=body.platform,
                        device_group=body.device_group or None)
    try:
        data, art, ca_included = installers.build(body.platform, raw, include_ca, body.allow_wipe)
    except installers.InstallerConfigError as e:
        raise HTTPException(409, str(e)) from None
    except installers.InstallerUnavailable as e:
        raise HTTPException(503, str(e)) from None
    except Exception:
        log.exception("building the %s installer failed", body.platform)
        raise HTTPException(500, "building the installer failed; see the server log") from None
    del raw  # the plaintext token now only exists inside `data`
    digest = hashlib.sha256(data).hexdigest()
    t.package_sha256 = digest
    db.add(t)
    db.flush()
    audit(db, "agent_installer_created", actor=admin, target=f"enrollment-token:{t.id}", ip=client_ip(request),
          name=t.name, platform=body.platform, agent_version=art.version, base_sha256=art.sha256,
          sha256=digest, size_bytes=len(data), max_uses=t.max_uses, expires_at=t.expires_at.isoformat() + "Z",
          device_group=t.device_group, ca_included=ca_included, server_url=installers.server_url(),
          allow_wipe=body.allow_wipe)
    db.commit()
    return Response(content=data, media_type=spec["media_type"], headers={
        "Content-Disposition": f'attachment; filename="{spec["download"]}"',
        "Cache-Control": "no-store", "X-Content-SHA256": digest, "X-Enrollment-Token-Id": t.id,
        "X-Agent-Version": art.version, "X-CA-Included": "true" if ca_included else "false",
        "X-Allow-Wipe": "true" if body.allow_wipe else "false"})


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
            "inventory": d.inventory or {}, "posture": d.posture or {}, "collection_errors": d.collection_errors or {},
            "lost_mode": svc.lost_mode_info(d), "wipe": svc.wipe_info(d), "isolation": svc.isolation_info(db, d)}


@router.get("/{device_id}/software", response_model=list[SoftwareOut])
def device_software(device_id: str = DeviceId, q: str | None = Query(None, max_length=255),
                    db: Session = Depends(get_db)):
    _get_device(db, device_id)
    stmt = select(DeviceSoftware).where(DeviceSoftware.device_id == device_id)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(DeviceSoftware.name.ilike(like), DeviceSoftware.publisher.ilike(like)))
    return list(db.scalars(stmt.order_by(DeviceSoftware.name, DeviceSoftware.version)))


@router.get("/{device_id}/vulnerabilities")
def device_vulnerabilities(device_id: str = DeviceId, status: str = Query("open", pattern="^(open|resolved|all)$"),
                           db: Session = Depends(get_db)):
    """CVEs matched on this device's OS and installed software (docs/VULNERABILITIES.md),
    plus which software was checked and which could not be ("not checked")."""
    from ..api.vulns import vuln_out, z
    from ..vulnmatch.state import DEVICE, get_state

    d = _get_device(db, device_id)
    stmt = select(Vulnerability).where(Vulnerability.device_id == device_id)
    if status != "all":
        stmt = stmt.where(Vulnerability.status == status)
    vulns = list(db.scalars(stmt.order_by(Vulnerability.risk_score.desc(), Vulnerability.cvss.desc())))
    st = get_state(db, DEVICE, device_id)
    names = {device_id: d.hostname}
    return {
        "vulnerabilities": [vuln_out(v, names) for v in vulns],
        "matched_at": z(st.matched_at) if st else None,
        "pending": bool(st and st.requested_at),
        "error": st.error if st else None,
        "os": st.os_info if st else {},
        "checked": st.checked if st else [],
        "not_checked": st.not_checked if st else [],
    }


@router.get("/{device_id}/history", response_model=list[SnapshotOut])
def device_history(device_id: str = DeviceId, limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db)):
    _get_device(db, device_id)
    return list(db.scalars(select(DevicePostureSnapshot).where(DevicePostureSnapshot.device_id == device_id)
                           .order_by(DevicePostureSnapshot.id.desc()).limit(limit)))


@router.get("/{device_id}/commands", response_model=list[CommandOut])
def device_commands(device_id: str = DeviceId, limit: int = Query(100, ge=1, le=1000),
                    db: Session = Depends(get_db)):
    _get_device(db, device_id)
    approvals.release_due(db, device_id)
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
    if body.type == "enable_lost_mode":
        if (body.confirm_hostname or "").strip().lower() != device.hostname.lower():
            raise HTTPException(422, f"type the device name ({device.hostname}) to confirm")
        if device.wipe_status in svc.WIPE_PENDING_STATES:
            raise HTTPException(409, "a remote wipe of this device is in progress")
    if body.type in ("enable_lost_mode", "disable_lost_mode") and device.lost_mode_status in ("enabling", "disabling"):
        raise HTTPException(409, f"lost mode is already {device.lost_mode_status}; wait for the device or cancel "
                                 "the pending command")
    if body.type == "disable_lost_mode" and device.lost_mode_status is None:
        raise HTTPException(409, "the device is not in lost mode")
    if body.type in ("isolate_host", "restore_host") and device.isolation_status in ("isolating", "restoring"):
        raise HTTPException(409, f"host isolation is already {device.isolation_status}; wait for the device or cancel "
                                 "the pending command")
    if body.type == "isolate_host" and device.isolation_status == "isolated":
        raise HTTPException(409, "the device is already isolated")
    if body.type == "restore_host" and device.isolation_status is None:
        raise HTTPException(409, "the device is not isolated")
    ttl = body.expires_in_hours or config.settings.device_command_ttl_hours
    cmd = svc.new_command(db, device, body.type, params, body.reason, requested_by_id=user.id,
                          requested_by_email=user.email, ttl=timedelta(hours=ttl))
    audit(db, "device_command_created", actor=user, target=f"device:{device.id}", ip=client_ip(request),
          hostname=device.hostname, command_id=cmd.id, type=cmd.type, params=params, reason=body.reason)
    if body.type == "isolate_host":
        audit(db, "host_isolation_requested", actor=user, target=f"device:{device.id}", ip=client_ip(request),
              hostname=device.hostname, command_id=cmd.id, reason=body.reason)
        host_isolation_source.notify(db, device, "isolation_requested", actor=user.email, reason=body.reason)
    elif body.type == "restore_host":
        audit(db, "host_restore_requested", actor=user, target=f"device:{device.id}", ip=client_ip(request),
              hostname=device.hostname, command_id=cmd.id, reason=body.reason)
        host_isolation_source.notify(db, device, "restore_requested", actor=user.email, reason=body.reason)
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
    svc.command_finished(_get_device(db, device_id), cmd)
    audit(db, "device_command_cancelled", actor=user, target=f"device:{device_id}", ip=client_ip(request),
          command_id=cmd.id, type=cmd.type, reason=body.reason)
    db.commit()
    return cmd


class WipeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=500)]
    confirm_hostname: Annotated[str, StringConstraints(max_length=255)]
    # protected: MDM_RemoteWipe.doWipeProtectedMethod (default; keeps trying after a
    # power cycle). standard: doWipeMethod (a power cycle during reset can stop it).
    mode: Literal["protected", "standard"] = "protected"


@router.post("/{device_id}/wipe", status_code=201)
def request_wipe(body: WipeRequest, request: Request, device_id: str = DeviceId,
                 admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Request a remote wipe (Windows only). Creates a two-person approval
    request; nothing is sent to the device until a different admin approves."""
    device = _get_device(db, device_id)
    if device.os_family != "windows":
        raise HTTPException(409, "remote wipe is only supported on Windows: erasing a Mac needs a real Apple MDM "
                                 "(EraseDevice), which this product does not have")
    if body.confirm_hostname.strip().lower() != device.hostname.lower():
        raise HTTPException(422, f"type the device name ({device.hostname}) to confirm")
    info = svc.wipe_info(device)
    if not info["opted_in"]:
        raise HTTPException(409, "this device did not opt in to remote wipe at install time (MSI property "
                                 "CNAPP_ALLOW_WIPE=1 or the 'Allow remote wipe' installer option); the agent "
                                 "would refuse the command")
    if device.wipe_status in svc.WIPE_PENDING_STATES:
        raise HTTPException(409, f"a wipe of this device is already {device.wipe_status}")
    try:
        a = approvals.request(db, admin, device, "wipe_device", {"mode": body.mode}, reason=body.reason,
                              summary=f"Remote wipe ({body.mode})", risk="high", ip=client_ip(request))
    except approvals.ApprovalError as e:
        raise HTTPException(e.status, e.detail) from None
    db.commit()
    return approvals.out(a, device, admin)


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
