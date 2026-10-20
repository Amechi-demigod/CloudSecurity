"""Two-person ("maker-checker") approval of high-risk device actions.

Rules (docs/DEVICE_MANAGEMENT.md#two-person-approval):

* Actions: `wipe_device` (always) and `run_script` when the script's *signed*
  manifest says risk medium or high. Lost mode is reversible and needs no
  approval (it is audited like every remote action).
* An admin requests the action with a reason; a **different** active admin
  approves or rejects it in the console. Nothing reaches the device before that.
* Requests expire after DEVICE_APPROVAL_TTL_HOURS (default 24 h).
* Self-approval is off by default. With DEVICE_APPROVAL_ALLOW_SELF=true (on-prem:
  `cnapp-ctl approvals self-approval enable`, for single-admin installs) the
  requester may approve their own request, but must type the device name again
  and the action only runs after DEVICE_APPROVAL_SELF_COOLDOWN_MINUTES (default
  15), during which any admin can cancel it.
* Wipe: the device name must be typed both when requesting and when approving.
* Every step is audited and raises a `device_approvals` notification event.
* Decisions are race-safe: a request changes state with a conditional UPDATE,
  so two admins clicking at once cannot both approve (or approve + reject).
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .. import config
from ..auth import audit
from ..models import Device, DeviceApproval, DeviceScript, User, utcnow
from ..notifications import approval_source
from . import devices as dsvc

APPROVAL_ACTIONS = ("wipe_device", "run_script")
OPEN_STATES = ("pending", "approved")
FINAL_STATES = ("executed", "rejected", "cancelled", "expired", "failed")


class ApprovalError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def settings_out() -> dict[str, Any]:
    s = config.settings
    return {"ttl_hours": s.device_approval_ttl_hours, "allow_self_approval": s.device_approval_allow_self,
            "self_approval_cooldown_minutes": s.device_approval_self_cooldown_minutes,
            "wipe_command_ttl_minutes": s.device_wipe_command_ttl_minutes}


def _hostname_matches(device: Device, typed: str | None) -> bool:
    return (typed or "").strip().lower() == device.hostname.strip().lower() and bool(device.hostname)


def request(db: Session, user: User, device: Device, action: str, params: dict[str, Any], *, reason: str,
            summary: str, risk: str, ip: str | None) -> DeviceApproval:
    assert action in APPROVAL_ACTIONS
    if device.status != "active":
        raise ApprovalError(409, "device is revoked")
    now = utcnow()
    open_same = db.scalar(select(DeviceApproval).where(
        DeviceApproval.device_id == device.id, DeviceApproval.action == action,
        DeviceApproval.status.in_(OPEN_STATES), DeviceApproval.expires_at > now).limit(1))
    if action == "wipe_device" and open_same is not None:
        raise ApprovalError(409, "a wipe of this device is already waiting for approval")
    a = DeviceApproval(device_id=device.id, action=action, params=params, summary=summary[:500], risk=risk,
                       reason=reason, status="pending", requested_by_id=user.id, requested_by_email=user.email,
                       requested_at=now, expires_at=now + timedelta(hours=config.settings.device_approval_ttl_hours))
    db.add(a)
    db.flush()
    audit(db, "device_approval_requested", actor=user, target=f"device:{device.id}", ip=ip, approval_id=a.id,
          action=action, params=params, risk=risk, reason=reason, hostname=device.hostname,
          expires_at=a.expires_at.isoformat() + "Z")
    approval_source.notify(db, a, device, "approval_requested")
    return a


def expire(db: Session) -> None:
    """Expire pending requests past their deadline (lazily, on every read)."""
    now = utcnow()
    for a in db.scalars(select(DeviceApproval).where(DeviceApproval.status == "pending",
                                                     DeviceApproval.expires_at <= now)):
        a.status = "expired"
        audit(db, "device_approval_expired", actor_email="system", target=f"device:{a.device_id}",
              approval_id=a.id, action=a.action)
        dev = db.get(Device, a.device_id)
        if dev is not None:
            approval_source.notify(db, a, dev, "approval_expired")
    db.flush()


def _transition(db: Session, a: DeviceApproval, from_states: tuple[str, ...], **values) -> bool:
    res = db.execute(update(DeviceApproval).where(DeviceApproval.id == a.id, DeviceApproval.status.in_(from_states))
                     .values(**values).execution_options(synchronize_session=False))
    if res.rowcount != 1:
        return False
    for k, v in values.items():
        setattr(a, k, v)
    return True


def approve(db: Session, a: DeviceApproval, user: User, *, reason: str | None, confirm_hostname: str | None,
            ip: str | None) -> DeviceApproval:
    expire(db)
    device = db.get(Device, a.device_id)
    if a.status != "pending":
        raise ApprovalError(409, f"this request is {a.status}, not pending")
    if device is None or device.status != "active":
        raise ApprovalError(409, "device is revoked or deleted")
    s = config.settings
    self_approval = a.requested_by_id == user.id
    if self_approval and not s.device_approval_allow_self:
        raise ApprovalError(403, "two-person rule: a different admin must approve this request "
                                 "(self-approval is disabled on this server)")
    if (self_approval or a.action == "wipe_device") and not _hostname_matches(device, confirm_hostname):
        raise ApprovalError(422, f"type the device name ({device.hostname}) to confirm")
    now = utcnow()
    values: dict[str, Any] = {"decided_by_id": user.id, "decided_by_email": user.email, "decided_at": now,
                              "decision_reason": (reason or "").strip() or None, "self_approved": self_approval}
    if self_approval:
        values.update(status="approved", execute_after=now + timedelta(minutes=s.device_approval_self_cooldown_minutes))
    else:
        values.update(status="approved", execute_after=now)
    if not _transition(db, a, ("pending",), **values):
        raise ApprovalError(409, "this request was decided by someone else in the meantime")
    audit(db, "device_approval_approved", actor=user, target=f"device:{device.id}", ip=ip, approval_id=a.id,
          action=a.action, self_approved=self_approval, reason=values["decision_reason"],
          requested_by=a.requested_by_email,
          execute_after=a.execute_after.isoformat() + "Z" if a.execute_after else None)
    approval_source.notify(db, a, device, "approval_approved")
    if not self_approval:
        execute(db, a)
    return a


def reject(db: Session, a: DeviceApproval, user: User, *, reason: str, ip: str | None) -> DeviceApproval:
    expire(db)
    if a.status != "pending":
        raise ApprovalError(409, f"this request is {a.status}, not pending")
    if not _transition(db, a, ("pending",), status="rejected", decided_by_id=user.id, decided_by_email=user.email,
                       decided_at=utcnow(), decision_reason=reason):
        raise ApprovalError(409, "this request was decided by someone else in the meantime")
    audit(db, "device_approval_rejected", actor=user, target=f"device:{a.device_id}", ip=ip, approval_id=a.id,
          action=a.action, reason=reason, requested_by=a.requested_by_email)
    dev = db.get(Device, a.device_id)
    if dev is not None:
        approval_source.notify(db, a, dev, "approval_rejected")
    return a


def cancel(db: Session, a: DeviceApproval, user: User, *, reason: str, ip: str | None) -> DeviceApproval:
    """The requester or any admin withdraws a pending request, or stops a
    self-approved one during its cooling-off delay."""
    expire(db)
    if a.status not in OPEN_STATES:
        raise ApprovalError(409, f"this request is {a.status}; only pending or cooling-off requests can be cancelled")
    if not _transition(db, a, OPEN_STATES, status="cancelled", decision_reason=reason,
                       decided_at=a.decided_at or utcnow()):
        raise ApprovalError(409, "this request changed in the meantime")
    audit(db, "device_approval_cancelled", actor=user, target=f"device:{a.device_id}", ip=ip, approval_id=a.id,
          action=a.action, reason=reason)
    dev = db.get(Device, a.device_id)
    if dev is not None:
        approval_source.notify(db, a, dev, "approval_cancelled", actor=user.email)
    return a


def release_due(db: Session, device_id: str | None = None) -> None:
    """Execute self-approved requests whose cooling-off delay has passed
    (called on reads and on every agent command poll, so no timer is needed)."""
    now = utcnow()
    stmt = select(DeviceApproval).where(DeviceApproval.status == "approved", DeviceApproval.execute_after <= now)
    if device_id:
        stmt = stmt.where(DeviceApproval.device_id == device_id)
    for a in list(db.scalars(stmt)):
        execute(db, a)


def execute(db: Session, a: DeviceApproval) -> None:
    """Turn an approved request into a device command (exactly once)."""
    device = db.get(Device, a.device_id)
    now = utcnow()
    if not _transition(db, a, ("approved",), status="executed", executed_at=now):
        return
    problem = None
    if device is None or device.status != "active":
        problem = "device is revoked or deleted"
    params = dict(a.params or {})
    ttl = None
    if problem is None and a.action == "wipe_device":
        ttl = timedelta(minutes=config.settings.device_wipe_command_ttl_minutes)
        params = {"mode": params.get("mode", "protected"), "hostname": device.hostname}
    elif problem is None and a.action == "run_script":
        script = db.scalar(select(DeviceScript).where(DeviceScript.bundle_id == params.get("bundle_id"),
                                                      DeviceScript.name == params.get("script")))
        if script is None:
            problem = "the script (or its bundle) no longer exists"
    if problem is not None:
        a.status = "failed"
        a.decision_reason = ((a.decision_reason or "") + f" [not executed: {problem}]").strip()
        audit(db, "device_approval_failed", actor_email="system", target=f"device:{a.device_id}",
              approval_id=a.id, action=a.action, problem=problem)
        return
    cmd = dsvc.new_command(db, device, a.action, params, a.reason, requested_by_id=a.requested_by_id,
                           requested_by_email=a.requested_by_email, ttl=ttl, approval_id=a.id,
                           approved_by_email=a.decided_by_email)
    a.command_id = cmd.id
    audit(db, "device_command_created", actor_email=a.requested_by_email, target=f"device:{device.id}",
          hostname=device.hostname, command_id=cmd.id, type=cmd.type, params=params, reason=a.reason,
          approval_id=a.id, approved_by=a.decided_by_email, self_approved=a.self_approved)
    approval_source.notify(db, a, device, "action_executed")


def out(a: DeviceApproval, device: Device | None, user: User | None = None) -> dict[str, Any]:
    s = config.settings
    can_decide = (user is not None and a.status == "pending" and user.role == "admin"
                  and (a.requested_by_id != user.id or s.device_approval_allow_self))
    return {"id": a.id, "device_id": a.device_id, "hostname": device.hostname if device else None,
            "os_family": device.os_family if device else None, "action": a.action, "params": a.params,
            "summary": a.summary, "risk": a.risk, "reason": a.reason, "status": a.status,
            "requested_by_email": a.requested_by_email, "requested_at": a.requested_at, "expires_at": a.expires_at,
            "decided_by_email": a.decided_by_email, "decided_at": a.decided_at, "decision_reason": a.decision_reason,
            "self_approved": a.self_approved, "execute_after": a.execute_after, "executed_at": a.executed_at,
            "command_id": a.command_id,
            "is_own_request": user is not None and a.requested_by_id == user.id, "can_decide": can_decide}
