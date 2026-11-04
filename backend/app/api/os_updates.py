"""Missing OS updates (docs/PATCHING.md), read-only.

agent_router  POST /api/agent/os-updates                    the agent's Windows Update report (device credential)
router        GET  /api/devices/{id}/os-updates             the device's report (viewer)
              POST /api/devices/{id}/os-updates/scan        "Check for updates now" (analyst, audited)
              GET  /api/os-updates/export.csv               missing updates, one row per device and update
                                                            (viewer, audited)
"""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy.orm import Session

from ..asset_lifecycle import csvio
from ..auth import audit, client_ip, require_analyst, require_viewer
from ..db import get_db
from ..models import Device, User, utcnow
from ..schemas_os_updates import OsUpdateReportIn
from ..services import devices as device_svc
from ..services import os_updates as svc
from .agent import current_device

log = logging.getLogger(__name__)
agent_router = APIRouter(prefix="/api/agent", tags=["agent"])
router = APIRouter(tags=["devices"])
DeviceId = Path(pattern=r"^[0-9a-f]{32}$")
# A scan request that the device does not pick up within a day is dropped.
SCAN_TTL = timedelta(hours=24)


@agent_router.post("/os-updates", status_code=204)
def report(body: OsUpdateReportIn, device: Device = Depends(current_device), db: Session = Depends(get_db)):
    """Store the device's latest Windows Update search (replaces the previous report)."""
    if device.os_family != "windows":
        raise HTTPException(409, "OS update reports are Windows only in this version")
    st = svc.store_report(db, device, body)
    log.info("device %s reported %d missing OS update(s) (%s, %s)", device.id, st.missing_count, body.status,
             body.trigger)
    db.commit()


def _device(db: Session, device_id: str) -> Device:
    d = db.get(Device, device_id)
    if d is None:
        raise HTTPException(404, "device not found")
    return d


@router.get("/api/devices/{device_id}/os-updates")
def device_os_updates(device_id: str = DeviceId, db: Session = Depends(get_db)):
    return svc.device_view(db, _device(db, device_id))


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=500)] = \
        "Check for updates now"


@router.post("/api/devices/{device_id}/os-updates/scan", status_code=201)
def scan_now(request: Request, body: ScanRequest | None = None, device_id: str = DeviceId,
             user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    """Queue a read-only Windows Update search on the device (it reports when done)."""
    body = body or ScanRequest()
    device = _device(db, device_id)
    if device.status != "active":
        raise HTTPException(409, "device is revoked")
    supported, reason, _ = svc.support(device)
    if not supported:
        raise HTTPException(409, reason)
    if svc.pending_scan(db, device.id) is not None:
        raise HTTPException(409, "a check for updates is already queued for this device")
    cmd = device_svc.new_command(db, device, svc.COMMAND_TYPE, {}, body.reason, requested_by_id=user.id,
                                 requested_by_email=user.email, ttl=SCAN_TTL)
    audit(db, "device_command_created", actor=user, target=f"device:{device.id}", ip=client_ip(request),
          hostname=device.hostname, command_id=cmd.id, type=cmd.type, params={}, reason=body.reason)
    db.commit()
    return {"command_id": cmd.id, "status": cmd.status, "requested_at": svc.z(cmd.created_at)}


@router.get("/api/os-updates/export.csv")
def export(request: Request, scope: str = Query("security", pattern="^(security|all)$"),
           device_id: str | None = Query(None, pattern=r"^[0-9a-f]{32}$"),
           user: User = Depends(require_viewer), db: Session = Depends(get_db)):
    body, n = svc.export_csv(db, security_only=scope == "security", device_id=device_id, safe_cell=csvio.safe_cell)
    audit(db, "os_updates_exported", actor=user, ip=client_ip(request), rows=n, scope=scope, device_id=device_id)
    db.commit()
    return Response(content=body.encode("utf-8"), media_type="text/csv; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="missing-os-updates-{utcnow():%Y%m%d}.csv"'})
