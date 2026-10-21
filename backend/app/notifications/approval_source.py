"""Two-person approvals of high-risk device actions as a notification source.

Events: approval_requested (a second admin is needed), approval_approved,
approval_rejected, approval_cancelled, approval_expired, action_executed (the
command was queued for the device) and wipe_acknowledged (the agent confirmed
it is about to wipe). Route them to Teams / Slack / email with a rule on the
source "device_approvals" (docs/NOTIFICATIONS.md).

Imports of the device modules are deferred (loaded while app.models imports).
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from .events import Event, EventSource, emit, register_source

log = logging.getLogger(__name__)

SOURCE = "device_approvals"
EVENT_TYPES = ("approval_requested", "approval_approved", "approval_rejected", "approval_cancelled",
               "approval_expired", "action_executed", "wipe_acknowledged")
VERBS = {"approval_requested": "needs a second admin's approval", "approval_approved": "approved",
         "approval_rejected": "rejected", "approval_cancelled": "cancelled", "approval_expired": "expired",
         "action_executed": "executed (queued for the device)", "wipe_acknowledged": "acknowledged by the device"}


def _severity(approval, event_type: str) -> str:
    if approval.action == "wipe_device":
        return "critical" if event_type in ("approval_requested", "action_executed", "wipe_acknowledged") else "high"
    return {"high": "high", "medium": "medium"}.get(approval.risk, "low")


def notify(db: Session, approval, device, event_type: str, actor: str | None = None) -> None:
    if event_type not in EVENT_TYPES:
        return
    try:
        what = approval.summary or approval.action.replace("_", " ")
        lines = [f"Requested by {approval.requested_by_email}: {approval.reason}"]
        if approval.decided_by_email and event_type != "approval_requested":
            lines.append(f"Decided by {approval.decided_by_email}"
                         + (f": {approval.decision_reason}" if approval.decision_reason else ""))
        if approval.self_approved and approval.execute_after and event_type == "approval_approved":
            lines.append(f"Self-approved: runs after {approval.execute_after:%Y-%m-%d %H:%M} UTC unless cancelled")
        if actor and event_type in ("approval_cancelled",):
            lines.append(f"Cancelled by {actor}")
        emit(db, Event(
            source=SOURCE, event_type=event_type, severity=_severity(approval, event_type),
            title=f"{what} on {device.hostname} {VERBS[event_type]}", summary="\n".join(lines)[:1000],
            entity_id=approval.id, group_key=f"{SOURCE}:{approval.id}:{event_type}", rule_id=approval.action,
            link_path="/approvals",
            attributes={"asset_type": "device", "asset_name": device.hostname, "hostname": device.hostname,
                        "os_family": device.os_family, "action": approval.action, "risk": approval.risk,
                        "requested_by": approval.requested_by_email, "decided_by": approval.decided_by_email,
                        "status": approval.status},
        ))
    except Exception:  # notifications must never break the approval flow
        log.exception("failed to queue approval notification")


register_source(EventSource(
    SOURCE, "Device approvals", EVENT_TYPES,
    "Two-person approvals of high-risk device actions (remote wipe, medium/high-risk scripts): pending "
    "requests that need a second admin, decisions, expiry, execution and the device's wipe acknowledgement."))
