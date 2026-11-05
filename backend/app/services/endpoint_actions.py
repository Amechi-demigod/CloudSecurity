"""Built-in endpoint actions (docs/DEVICE_MANAGEMENT.md#endpoint-actions).

manage_service       stop / start a service, set its startup type to Disabled,
                     restore the startup type it had before
uninstall_software   remove a program with its own silent uninstaller (MSI
                     product code or QuietUninstallString; never the agent)
block_usb_storage    USBSTOR driver off + "Removable Disks: Deny read / write /
unblock_usb_storage  execute"; unblock restores the previous values exactly

Queued through POST /api/devices/{id}/commands like the other remote actions:
admin role, a reason, no second-admin approval, every request and result is
audited and listed in the device's command history. Windows only in this
version (agent 1.4.0+, feature `endpoint_actions`); the command types and
parameters are OS-neutral so other OSes can be added. The agent enforces its
own copy of every check here (endpoint-agent/internal/actions).
"""
from __future__ import annotations

import re
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..auth import audit
from ..models import REMOTE_SESSION_OPEN_STATES, Device, DeviceCommand, DeviceService, DeviceSoftware, RemoteSession
from ..notifications import endpoint_action_source
from .devices import usb_storage_state

FEATURE = "endpoint_actions"
MIN_AGENT_VERSION = "1.4.0"
TYPES = ("manage_service", "uninstall_software", "block_usb_storage", "unblock_usb_storage")
SERVICE_ACTIONS = ("stop", "start", "disable", "restore")

AGENT_SERVICE = "CNAPPAgent"
# Never stopped or disabled from the console (mirrors ProtectedServices in
# endpoint-agent/internal/actions/services.go): this agent, and what Windows
# needs to boot, sign users in, stay manageable and stay protected.
PROTECTED_SERVICES = (
    AGENT_SERVICE,
    "RpcSs", "RpcEptMapper", "DcomLaunch", "LSM", "SamSs", "PlugPlay", "Power", "BrokerInfrastructure",
    "SystemEventsBroker", "CoreMessagingRegistrar", "ProfSvc", "UserManager", "gpsvc", "Netlogon",
    "EventLog", "Winmgmt", "Schedule",
    "Dhcp", "Dnscache", "nsi",
    "WinDefend", "WdNisSvc", "Sense", "SecurityHealthService", "wscsvc", "mpssvc", "BFE", "CryptSvc", "KeyIso",
)
_PROTECTED = {s.lower() for s in PROTECTED_SERVICES}
# Protected while an attended remote session is open on the device.
REMOTE_SESSION_SERVICE = "TermService"
AGENT_PRODUCT = "CNAPP Endpoint Agent"
UNINSTALL_SOURCES = ("registry_hklm64", "registry_hklm32")
RESTORABLE_START_TYPES = ("auto", "auto_delayed", "manual")

SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.$@{}~+ -]{0,255}$")
KEY_NAME_RE = re.compile(r"^[^\\\x00-\x1f\x7f]{1,255}$")


class ActionError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


def support(device: Device) -> tuple[bool, str | None, bool]:
    """(supported, reason when not, agent update required)."""
    if device.os_family != "windows":
        return False, "Endpoint actions are Windows only in this version.", False
    if FEATURE not in (device.agent_features or "").split(","):
        return False, (f"Agent update required: endpoint actions need agent {MIN_AGENT_VERSION} or later "
                       f"(this device runs {device.agent_version or 'an older agent'})."), True
    return True, None, False


def is_agent_name(name: str) -> bool:
    n = name.strip().lower()
    return n == AGENT_PRODUCT.lower() or n.startswith(("cnapp endpoint agent", "cnapp agent"))


def remote_session_open(db: Session, device: Device) -> bool:
    return bool(db.scalar(select(func.count()).select_from(RemoteSession)
                          .where(RemoteSession.device_id == device.id,
                                 RemoteSession.state.in_(REMOTE_SESSION_OPEN_STATES))))


def protected_reason(db: Session, device: Device, name: str) -> str | None:
    n = name.lower()
    if n == AGENT_SERVICE.lower():
        return "it is the CNAPP agent's own service"
    if n in _PROTECTED:
        return "it is a protected system or security service"
    if n == REMOTE_SESSION_SERVICE.lower() and remote_session_open(db, device):
        return "a remote session is open on this device"
    return None


def _str(params: dict[str, Any], key: str) -> str:
    v = params.get(key)
    if not isinstance(v, str):
        raise ActionError(422, f"{key} must be a string")
    return v.strip()


def _in_flight(db: Session, device: Device, cmd_type: str, match: dict[str, Any]) -> bool:
    for c in db.scalars(select(DeviceCommand).where(DeviceCommand.device_id == device.id,
                                                    DeviceCommand.type == cmd_type,
                                                    DeviceCommand.status.in_(("pending", "delivered")))):
        p = c.params or {}
        if all(str(p.get(k, "")).lower() == str(v).lower() for k, v in match.items()):
            return True
    return False


def last_disabled_start_type(db: Session, device: Device, service: str) -> str | None:
    """The startup type a service had before the most recent successful
    disable (sent as restore_to; the agent prefers its own saved value)."""
    for c in db.scalars(select(DeviceCommand).where(DeviceCommand.device_id == device.id,
                                                    DeviceCommand.type == "manage_service",
                                                    DeviceCommand.status == "succeeded")
                        .order_by(DeviceCommand.created_at.desc()).limit(200)):
        p, r = c.params or {}, c.result_data or {}
        if str(p.get("service", "")).lower() != service.lower():
            continue
        if p.get("action") == "restore":
            return None  # restored since: nothing pending to restore
        if p.get("action") == "disable":
            prev = r.get("previous_start_type")
            return prev if prev in RESTORABLE_START_TYPES else None
    return None


def prepare(db: Session, device: Device, cmd_type: str, params: dict[str, Any]) -> dict[str, Any]:
    """Validate an endpoint action for this device and return the params to queue."""
    ok, reason, _ = support(device)
    if not ok:
        raise ActionError(409, reason or "not supported")
    if cmd_type == "manage_service":
        if not set(params) <= {"service", "action"} or "service" not in params or "action" not in params:
            raise ActionError(422, "params must be {'service': name, 'action': stop|start|disable|restore}")
        name, action = _str(params, "service"), _str(params, "action")
        if not SERVICE_NAME_RE.match(name):
            raise ActionError(422, "service must be a Windows service name")
        if action not in SERVICE_ACTIONS:
            raise ActionError(422, "action must be stop, start, disable or restore")
        row = db.scalar(select(DeviceService).where(DeviceService.device_id == device.id,
                                                    func.lower(DeviceService.name) == name.lower()))
        if row is None:
            raise ActionError(404, f"the device has not reported a service named {name}")
        name = row.name
        if action in ("stop", "disable"):
            why = protected_reason(db, device, name)
            if why:
                raise ActionError(409, f"{name} cannot be {'stopped' if action == 'stop' else 'disabled'}: {why}")
        if _in_flight(db, device, cmd_type, {"service": name}):
            raise ActionError(409, f"an action on {name} is already queued; wait for it or cancel it")
        out: dict[str, Any] = {"service": name, "action": action}
        if action == "restore":
            prev = last_disabled_start_type(db, device, name)
            if prev:
                out["restore_to"] = prev
        return out
    if cmd_type == "uninstall_software":
        if set(params) != {"identifier", "source"}:
            raise ActionError(422, "params must be {'identifier': registry key, 'source': registry view}")
        ident, source = _str(params, "identifier"), _str(params, "source")
        if source == "registry_user":
            raise ActionError(409, "per-user installs cannot be uninstalled by the agent (it runs as LocalSystem, "
                                   "not as the user): use a script")
        if source not in UNINSTALL_SOURCES or not KEY_NAME_RE.match(ident):
            raise ActionError(422, "identifier / source must name a machine-wide program from the software inventory")
        sw = db.scalar(select(DeviceSoftware).where(DeviceSoftware.device_id == device.id,
                                                    DeviceSoftware.identifier == ident,
                                                    DeviceSoftware.source == source).limit(1))
        if sw is None:
            raise ActionError(404, "this program is not in the device's software inventory")
        if is_agent_name(sw.name):
            raise ActionError(409, "the CNAPP agent cannot uninstall itself: use the MSI or the uninstall script")
        if _in_flight(db, device, cmd_type, {"identifier": ident, "source": source}):
            raise ActionError(409, f"an uninstall of {sw.name} is already queued")
        return {"identifier": ident, "source": source, "name": sw.name, "version": sw.version}
    # block / unblock_usb_storage
    if params:
        raise ActionError(422, f"{cmd_type} takes no parameters")
    if _in_flight(db, device, "block_usb_storage", {}) or _in_flight(db, device, "unblock_usb_storage", {}):
        raise ActionError(409, "a USB storage action is already queued for this device")
    return {}


def info(db: Session, device: Device) -> dict[str, Any]:
    ok, reason, update_required = support(device)
    check = (device.posture or {}).get("usb_storage") or {}
    data = check.get("data") or {}
    return {
        "supported": ok, "unsupported_reason": reason, "agent_update_required": update_required,
        "min_agent_version": MIN_AGENT_VERSION,
        "usb_storage": {"state": usb_storage_state(device), "detail": check.get("detail") or "",
                        "blocked_by_agent": data.get("blocked_by_agent") is True,
                        "blocked_since": data.get("blocked_since"),
                        "usbstor_start": data.get("usbstor_start"),
                        "deny_read": data.get("removable_disks_deny_read"),
                        "deny_all": data.get("deny_all_removable")},
        "protected_services": list(PROTECTED_SERVICES)
        + ([REMOTE_SESSION_SERVICE] if device.os_family == "windows" and remote_session_open(db, device) else []),
        "services_reported": db.scalar(select(func.count()).select_from(DeviceService)
                                       .where(DeviceService.device_id == device.id)) or 0,
    }


def apply_services(db: Session, device: Device, services: list[Any] | None) -> None:
    """Replace the services inventory (None: not sent, keep the previous list)."""
    if services is None:
        return
    db.execute(delete(DeviceService).where(DeviceService.device_id == device.id))
    seen: set[str] = set()
    rows = []
    for s in services:
        if s.name.lower() in seen:
            continue
        seen.add(s.name.lower())
        rows.append(DeviceService(device_id=device.id, name=s.name, display_name=s.display_name, status=s.status,
                                  start_type=s.start_type))
    db.add_all(rows)


def _label(cmd: DeviceCommand) -> str:
    p = cmd.params or {}
    if cmd.type == "manage_service":
        verb = {"stop": "Stop", "start": "Start", "disable": "Disable", "restore": "Restore startup type of"}
        return f"{verb.get(p.get('action'), 'Change')} service {p.get('service', '')}"
    if cmd.type == "uninstall_software":
        return f"Uninstall {p.get('name', '')} {p.get('version', '')}".strip()
    return "Block USB storage" if cmd.type == "block_usb_storage" else "Unblock USB storage"


def command_result(db: Session, device: Device, cmd: DeviceCommand, result: dict[str, Any]) -> None:
    """Apply an endpoint action's result: refresh the stored service row,
    drop an uninstalled program from the inventory (the agent's follow-up
    check-in sends the full list anyway), audit and notify."""
    if cmd.type not in TYPES:
        return
    ok = cmd.status == "succeeded"
    p = cmd.params or {}
    if cmd.type == "manage_service" and result.get("service"):
        row = db.scalar(select(DeviceService).where(DeviceService.device_id == device.id,
                                                    func.lower(DeviceService.name) == str(result["service"]).lower()))
        if row is not None:
            row.status = result.get("status") or row.status
            row.start_type = result.get("start_type") or row.start_type
    if cmd.type == "uninstall_software" and ok and (result.get("verified") or result.get("already_removed")):
        db.execute(delete(DeviceSoftware).where(DeviceSoftware.device_id == device.id,
                                                DeviceSoftware.identifier == p.get("identifier"),
                                                DeviceSoftware.source == p.get("source")))
    if cmd.type in ("block_usb_storage", "unblock_usb_storage") and isinstance(result.get("blocked"), bool):
        posture = dict(device.posture or {})
        prev = posture.get("usb_storage") or {}
        data = {**(prev.get("data") or {}), **{k: v for k, v in result.items() if k != "error_code"}}
        if ok:  # until the next check-in reports it
            data["blocked_by_agent"] = cmd.type == "block_usb_storage"
        posture["usb_storage"] = {**prev, "status": "info", "data": data,
                                  "detail": "USB storage blocked" if result["blocked"] else "USB storage allowed"}
        device.posture = posture
    audit(db, "endpoint_action_succeeded" if ok else f"endpoint_action_{cmd.status}",
          actor_email=f"device:{device.hostname}"[:320], target=f"device:{device.id}", command_id=cmd.id,
          type=cmd.type, label=_label(cmd), status=cmd.status, exit_code=cmd.exit_code,
          reboot_required=result.get("reboot_required"))
    if not ok:
        endpoint_action_source.notify(db, device, cmd, "action_" + cmd.status, _label(cmd))
    elif result.get("reboot_required"):
        endpoint_action_source.notify(db, device, cmd, "restart_required", _label(cmd))
