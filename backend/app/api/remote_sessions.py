"""Attended remote sessions for users (session-authenticated, organisation-scoped).

viewer  : read the history
analyst : + start View only sessions, end their own
admin   : + start View and control sessions, end anyone's

Another organisation's device or session is 404 (app/tenancy.py). Starting a
session needs a reason and is audited; the screen itself goes through the relay
(app/api/remote_relay.py), never through these endpoints.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import tenancy
from ..auth import client_ip, current_user
from ..db import get_db
from ..models import Device, RemoteSession, User
from ..schemas_remote import RemoteAvailabilityOut, RemoteSessionCreate, RemoteSessionOut
from ..services import remote_sessions as rsvc

router = APIRouter(tags=["remote-sessions"])
DeviceId = Path(pattern=r"^[0-9a-f]{32}$")
SessionId = Path(pattern=r"^[0-9a-f]{32}$")


def _device(db: Session, device_id: str) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(404, "device not found")
    return device


def _session(db: Session, session_id: str) -> RemoteSession:
    rs = db.get(RemoteSession, session_id)
    if rs is None:
        raise HTTPException(404, "remote session not found")
    return rs


def out(rs: RemoteSession) -> RemoteSessionOut:
    o = RemoteSessionOut.model_validate(rs)
    o.duration_seconds = rsvc.duration_seconds(rs)
    return o


@router.get("/api/devices/{device_id}/remote-sessions/availability", response_model=RemoteAvailabilityOut)
def availability(device_id: str = DeviceId, user: User = Depends(current_user), db: Session = Depends(get_db)):
    device = _device(db, device_id)
    rsvc.sweep(db)
    db.commit()
    open_id = db.scalar(select(RemoteSession.id).where(RemoteSession.open_device_id == device.id))
    why = rsvc.availability(device)
    modes = [m for m in ("view", "control") if rsvc.can_start(user, m)]
    if why is None and not modes:
        why = "starting a remote session requires the analyst role"
    return RemoteAvailabilityOut(available=why is None and open_id is None, reason=why, modes=modes,
                                 open_session_id=open_id)


@router.post("/api/devices/{device_id}/remote-sessions", response_model=RemoteSessionOut, status_code=201)
def start(body: RemoteSessionCreate, request: Request, device_id: str = DeviceId, user: User = Depends(current_user),
          db: Session = Depends(get_db)):
    device = _device(db, device_id)
    org = tenancy.get_org(db, user.organization_id)
    try:
        rs = rsvc.create(db, device, user, body.mode, body.reason, client_ip(request), org.name if org else "")
    except rsvc.RemoteSessionError as e:
        db.rollback()
        raise HTTPException(e.status, e.detail) from None
    db.commit()
    return out(rs)


@router.get("/api/devices/{device_id}/remote-sessions", response_model=list[RemoteSessionOut])
def history(device_id: str = DeviceId, limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db)):
    _device(db, device_id)
    rsvc.sweep(db)
    db.commit()
    rows = db.scalars(select(RemoteSession).where(RemoteSession.device_id == device_id)
                      .order_by(RemoteSession.created_at.desc()).limit(limit))
    return [out(r) for r in rows]


@router.get("/api/remote-sessions/{session_id}", response_model=RemoteSessionOut)
def get(session_id: str = SessionId, db: Session = Depends(get_db)):
    rs = _session(db, session_id)
    if rsvc.is_open(rs):
        rsvc.sweep(db)
        db.commit()
    return out(rs)


@router.post("/api/remote-sessions/{session_id}/end", response_model=RemoteSessionOut)
def end(request: Request, session_id: str = SessionId, user: User = Depends(current_user),
        db: Session = Depends(get_db)):
    rs = _session(db, session_id)
    if not rsvc.can_end(user, rs):
        raise HTTPException(403, "only the requester or an admin can end this session")
    reason = "ended_by_viewer" if user.id == rs.requested_by_id else "ended_by_admin"
    rsvc.end(db, rs, reason, actor=user, ip=client_ip(request))
    db.commit()
    return out(rs)
