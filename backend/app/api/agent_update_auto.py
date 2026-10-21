"""Agent update automation API (/api/updates/automation, /api/updates/update-now).

  viewer : GET  /api/updates/automation                 mode, rollout state, auto-import status
  admin  : PUT  /api/updates/automation                 mode, soak period, auto-import settings
           POST /api/updates/automation/promote          automatic mode: give the current release to everyone now
           POST /api/updates/automation/check-github     run the GitHub Releases auto-import check now
  analyst: POST /api/updates/update-now  {device_id}     one device: check in and start its target now
  admin  : POST /api/updates/update-now  {ring_id | all} a ring / every device with a pending update

Everything is audited. "Update now" never chooses what is installed: it only
makes devices check in immediately and skip the random start delay for the
release their ring / pin already targets; agents verify it as always.
"""
from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import ROLE_RANK, audit, client_ip, current_user, require_admin, require_viewer
from ..db import get_db
from ..models import AgentRelease, AgentUpdateRing, Device, User, utcnow
from ..services import agent_update_auto as auto
from ..services import agent_updates as svc

router = APIRouter(prefix="/api/updates", tags=["agent-updates"], dependencies=[Depends(require_viewer)])

Reason = Annotated[str, StringConstraints(min_length=3, max_length=500)]
Id32 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]


class AutomationIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    mode: Literal["automatic", "manual"] | None = None
    soak_hours: int | None = Field(None, ge=0, le=720)
    auto_import_enabled: bool | None = None
    auto_import_repo: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")] | None = None
    auto_import_interval_minutes: int | None = Field(None, ge=15, le=7 * 24 * 60)
    reason: Reason = "changed from the console"


class ReasonIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    reason: Reason = "requested from the console"


class UpdateNowIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    device_id: Id32 | None = None
    ring_id: Id32 | None = None
    all: bool = False
    reason: Reason = "update now from the console"


@router.get("/automation")
def get_automation(db: Session = Depends(get_db)):
    state = auto.automation_state(db)
    db.commit()  # creates the settings row on first use
    return state


@router.put("/automation")
def set_automation(body: AutomationIn, request: Request, admin: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    st = auto.get_settings(db)
    changes = {}
    for f in ("mode", "soak_hours", "auto_import_enabled", "auto_import_repo", "auto_import_interval_minutes"):
        v = getattr(body, f)
        if v is not None and v != getattr(st, f):
            changes[f] = {"from": getattr(st, f), "to": v}
            setattr(st, f, v)
    if not changes:
        return auto.automation_state(db)
    if "auto_import_repo" in changes or changes.get("auto_import_enabled", {}).get("to"):
        st.import_checked_at, st.import_failed_version = None, None  # check soon with the new settings
    if changes.get("mode", {}).get("to") == "automatic":
        st.auto_release_id = None  # re-evaluate: newest release to Pilot, then everyone
    st.updated_at, st.updated_by = utcnow(), admin.email
    audit(db, "agent_update_settings_changed", actor=admin, ip=client_ip(request), changes=changes, reason=body.reason)
    tick = auto.auto_tick(db)
    db.commit()
    out = auto.automation_state(db)
    out["tick"] = {"action": tick.action, "detail": tick.detail}
    return out


@router.post("/automation/promote")
def promote_now(body: ReasonIn, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Automatic mode: target the current release to every ring now (skips the
    rest of the soak period, or overrides a pause after Pilot failures)."""
    st = auto.get_settings(db)
    rel = db.get(AgentRelease, st.auto_release_id) if st.auto_release_id else None
    if st.mode != "automatic" or rel is None:
        raise HTTPException(409, "no automatic rollout in progress (automatic mode and an imported release needed)")
    if rel.withdrawn_at is not None or rel.expires_at <= utcnow():
        raise HTTPException(409, f"release {rel.version} is withdrawn or expired")
    auto.promote_all(db, st, rel, admin.email, utcnow(), f"promoted by {admin.email}: {body.reason}")
    audit(db, "agent_update_auto_promote_requested", actor=admin, ip=client_ip(request), version=rel.version,
          reason=body.reason)
    db.commit()
    return auto.automation_state(db)


@router.post("/automation/check-github")
def check_github_now(request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Run the auto-import check now (also when the periodic check is disabled)."""
    res = auto.check_github(db, actor=f"auto-import (requested by {admin.email})")
    audit(db, "agent_release_check_requested", actor=admin, ip=client_ip(request), status=res["status"],
          message=res["message"][:500])
    db.commit()
    return {**res, "automation": auto.automation_state(db)}


@router.post("/update-now")
def update_now(body: UpdateNowIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    selectors = sum(x is not None and x is not False for x in (body.device_id, body.ring_id, body.all or None))
    if selectors != 1:
        raise HTTPException(422, "give exactly one of device_id, ring_id or all")
    needed = "analyst" if body.device_id else "admin"
    if ROLE_RANK.get(user.role, -1) < ROLE_RANK[needed]:
        raise HTTPException(403, f"update now for {'a device' if body.device_id else 'a ring or the fleet'} "
                                 f"requires the {needed} role")
    all_rings = svc.rings(db)
    if body.device_id:
        d = db.get(Device, body.device_id)
        if d is None:
            raise HTTPException(404, "device not found")
        if d.status != "active":
            raise HTTPException(409, "device is revoked")
        devices, scope = [d], f"device:{d.id}"
    elif body.ring_id:
        ring = db.get(AgentUpdateRing, body.ring_id)
        if ring is None:
            raise HTTPException(404, "ring not found")
        devices = [d for d in db.scalars(select(Device).where(Device.status == "active"))
                   if (r := svc.ring_for(d, all_rings)) is not None and r.id == ring.id]
        scope = f"agent-ring:{ring.id}"
    else:
        devices, scope = list(db.scalars(select(Device).where(Device.status == "active"))), "fleet"
    res = auto.request_update_now(db, devices, actor_id=user.id, actor_email=user.email, reason=body.reason)
    if body.device_id and not res["queued"]:
        raise HTTPException(409, f"nothing to update now: {res['skipped'][0]['reason']}")
    audit(db, "agent_update_now_requested", actor=user, target=scope, ip=client_ip(request), reason=body.reason,
          devices=[q["hostname"] for q in res["queued"]][:200], skipped=len(res["skipped"]))
    db.commit()
    return res
