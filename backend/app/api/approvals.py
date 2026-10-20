"""Two-person approvals of high-risk device actions (/api/approvals/*, admin only).

See app/services/approvals.py for the rules. Requests are created by the action
endpoints (POST /api/devices/{id}/wipe, POST /api/scripts/run).
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth import client_ip, require_admin
from ..db import get_db
from ..models import Device, DeviceApproval, User
from ..services import approvals as svc

router = APIRouter(prefix="/api/approvals", tags=["approvals"], dependencies=[Depends(require_admin)])
Reason = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=500)]


class ApproveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)] | None = None
    confirm_hostname: Annotated[str, StringConstraints(max_length=255)] | None = None


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Reason


def _get(db: Session, approval_id: str) -> DeviceApproval:
    a = db.get(DeviceApproval, approval_id)
    if a is None:
        raise HTTPException(404, "approval request not found")
    return a


def _out(db: Session, a: DeviceApproval, user: User) -> dict:
    return svc.out(a, db.get(Device, a.device_id), user)


def _run(fn):
    try:
        return fn()
    except svc.ApprovalError as e:
        raise HTTPException(e.status, e.detail) from None


@router.get("")
def list_approvals(status: str = Query("open", pattern="^(open|pending|approved|final|all)$"),
                   device_id: str | None = Query(None, pattern=r"^[0-9a-f]{32}$"),
                   limit: int = Query(200, ge=1, le=1000), user: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    svc.expire(db)
    svc.release_due(db)
    db.commit()
    stmt = select(DeviceApproval)
    if status == "open":
        stmt = stmt.where(DeviceApproval.status.in_(svc.OPEN_STATES))
    elif status == "final":
        stmt = stmt.where(DeviceApproval.status.in_(svc.FINAL_STATES))
    elif status != "all":
        stmt = stmt.where(DeviceApproval.status == status)
    if device_id:
        stmt = stmt.where(DeviceApproval.device_id == device_id)
    rows = db.scalars(stmt.order_by(DeviceApproval.requested_at.desc()).limit(limit))
    return [_out(db, a, user) for a in rows]


@router.get("/summary")
def summary(user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Counts for the navigation badge: requests this admin can decide, and cooling-off ones."""
    svc.expire(db)
    svc.release_due(db)
    db.commit()
    pending = db.scalars(select(DeviceApproval).where(DeviceApproval.status == "pending"))
    actionable = sum(1 for a in pending if svc.out(a, None, user)["can_decide"])
    total = db.scalar(select(func.count()).select_from(DeviceApproval).where(DeviceApproval.status == "pending")) or 0
    cooling = db.scalar(select(func.count()).select_from(DeviceApproval)
                        .where(DeviceApproval.status == "approved")) or 0
    return {"pending": total, "actionable": actionable, "cooling_off": cooling, "settings": svc.settings_out()}


@router.get("/{approval_id}")
def get_approval(approval_id: str = Path(pattern=r"^[0-9a-f]{32}$"), user: User = Depends(require_admin),
                 db: Session = Depends(get_db)):
    svc.expire(db)
    db.commit()
    return _out(db, _get(db, approval_id), user)


@router.post("/{approval_id}/approve")
def approve(body: ApproveIn, request: Request, approval_id: str = Path(pattern=r"^[0-9a-f]{32}$"),
            user: User = Depends(require_admin), db: Session = Depends(get_db)):
    a = _get(db, approval_id)
    _run(lambda: svc.approve(db, a, user, reason=body.reason, confirm_hostname=body.confirm_hostname,
                             ip=client_ip(request)))
    db.commit()
    return _out(db, a, user)


@router.post("/{approval_id}/reject")
def reject(body: DecisionIn, request: Request, approval_id: str = Path(pattern=r"^[0-9a-f]{32}$"),
           user: User = Depends(require_admin), db: Session = Depends(get_db)):
    a = _get(db, approval_id)
    _run(lambda: svc.reject(db, a, user, reason=body.reason, ip=client_ip(request)))
    db.commit()
    return _out(db, a, user)


@router.post("/{approval_id}/cancel")
def cancel(body: DecisionIn, request: Request, approval_id: str = Path(pattern=r"^[0-9a-f]{32}$"),
           user: User = Depends(require_admin), db: Session = Depends(get_db)):
    a = _get(db, approval_id)
    _run(lambda: svc.cancel(db, a, user, reason=body.reason, ip=client_ip(request)))
    db.commit()
    return _out(db, a, user)
