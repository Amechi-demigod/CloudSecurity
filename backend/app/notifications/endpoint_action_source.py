"""Built-in endpoint actions (services, uninstall, USB storage) as a
notification source (docs/DEVICE_MANAGEMENT.md#endpoint-actions).

Events (same transaction as the agent's result):
  * action_failed: the agent tried and failed (service did not stop, the
    uninstaller returned an error, a registry value could not be written, ...)
  * action_rejected: the agent refused it (protected service, no silent
    uninstaller, unsupported OS, the program changed since the inventory)
  * restart_required: an uninstall succeeded but needs a restart (3010 / 1641)

Successful actions are audited and shown in the command history; they are
not notified (the generic `device` source still sends command_succeeded to
rules that ask for it).
"""
from __future__ import annotations

import logging
from urllib.parse import quote

from sqlalchemy.orm import Session

from .events import Event, EventSource, emit, register_source

log = logging.getLogger(__name__)

SOURCE = "endpoint_action"
EVENT_TYPES = ("action_failed", "action_rejected", "restart_required")
SEVERITY = {"action_failed": "medium", "action_rejected": "low", "restart_required": "low"}
TITLES = {"action_failed": "failed", "action_rejected": "refused by the agent", "restart_required": "needs a restart"}


def notify(db: Session, device, cmd, event_type: str, label: str) -> None:
    if event_type not in EVENT_TYPES:
        return
    try:
        lines = [f"Requested by {cmd.requested_by_email}" if cmd.requested_by_email else "",
                 f"Reason: {cmd.reason}" if cmd.reason else "", (cmd.output or "")[:800]]
        emit(db, Event(
            source=SOURCE, event_type=event_type, severity=SEVERITY[event_type],
            title=f"{label} {TITLES[event_type]} on {device.hostname}",
            summary="\n".join(x for x in lines if x)[:1000], entity_id=cmd.id,
            group_key=f"{SOURCE}:{device.id}:{cmd.id}", rule_id=cmd.type,
            link_path=f"/devices/{quote(str(device.id), safe='')}",
            attributes={"asset_type": "device", "asset_name": device.hostname, "hostname": device.hostname,
                        "os_family": device.os_family, "command_id": cmd.id, "command_type": cmd.type,
                        "action": label, "status": cmd.status, "exit_code": cmd.exit_code,
                        "requested_by": cmd.requested_by_email},
        ))
    except Exception:  # notifications must never break the agent API
        log.exception("failed to queue endpoint action notification")


register_source(EventSource(
    SOURCE, "Endpoint actions", EVENT_TYPES,
    "Built-in endpoint actions (stop / start / disable services, uninstall software, block USB storage) "
    "that failed or were refused by the agent, and uninstalls that need a restart.",
))
