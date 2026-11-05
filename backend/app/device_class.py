"""Device classification (docs/DEVICE_MANAGEMENT.md#device-class): workstation,
server or domain controller, plus form factor, virtualisation and cloud.

Agents 1.4.0+ report it (check-in `device.classification`, read locally from
the OS product type, SMBIOS / DMI and CPUID). For older agents it is inferred
from the OS name and the make / model strings and marked "inferred". Directory
computers without an agent are classified from their directory attributes
(AD operatingSystem and userAccountControl, Entra / Intune / Google OS fields).
"""
from __future__ import annotations

import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

DEVICE_CLASSES = ("workstation", "server", "domain_controller")
CLASS_LABEL = {"workstation": "Workstation", "server": "Server", "domain_controller": "Domain controller"}

# userAccountControl SERVER_TRUST_ACCOUNT: the computer account of a domain controller.
UAC_SERVER_TRUST_ACCOUNT = 0x2000

# Make / model strings of virtual machines (older agents, Intune devices).
_VIRTUAL = (
    (re.compile(r"vmware", re.I), "vmware"),
    (re.compile(r"virtualbox|innotek", re.I), "virtualbox"),
    (re.compile(r"parallels", re.I), "parallels"),
    (re.compile(r"microsoft corporation.*virtual machine|^virtual machine$|hyper-v", re.I), "hyper-v"),
    (re.compile(r"\bxen\b|hvm domu", re.I), "xen"),
    (re.compile(r"qemu|\bkvm\b|bochs|openstack|google compute engine", re.I), "kvm"),
    (re.compile(r"amazon ec2", re.I), "nitro"),
    (re.compile(r"virtualmac", re.I), "apple"),
)
_LAPTOP_MODEL = re.compile(r"^macbook", re.I)


def virtual_from_model(manufacturer: str, model: str) -> str:
    """Hypervisor recognised from make / model strings ("" = looks physical)."""
    text = f"{manufacturer or ''} {model or ''}".strip()
    if re.search(r"amazon ec2", text, re.I) and (model or "").lower().endswith(".metal"):
        return ""
    for rx, name in _VIRTUAL:
        if rx.search(text):
            return name
    return ""


def is_server_os(os_name: str) -> bool:
    return "server" in (os_name or "").lower()


def infer(os_family: str, os_name: str, manufacturer: str, model: str) -> dict[str, Any]:
    """Classification of a device whose agent does not report one (< 1.4.0).
    Windows: "Server" in the OS name (a domain controller cannot be told apart
    from a member server this way); macOS: workstation; Linux: server (the
    agent-side heuristic needs the chassis / boot target, unknown here)."""
    fam = (os_family or "").lower()
    if fam == "windows":
        role = "server" if is_server_os(os_name) else "workstation"
    elif fam == "macos":
        role = "workstation"
    else:
        role = "server"
    hv = virtual_from_model(manufacturer, model)
    form = ""
    if hv:
        form = "other"
    elif fam == "macos" and _LAPTOP_MODEL.search(model or ""):
        form = "laptop"
    return {"role": role, "form_factor": form, "is_virtual": True if hv else None, "hypervisor": hv,
            "cloud_provider": "", "cloud_instance_id": ""}


def apply(device: Any, reported: Any) -> None:
    """Store the classification of a check-in on the device: the agent's own
    (source "agent") or, for older agents, the inferred one."""
    data = reported.model_dump(mode="json") if reported is not None else None
    if data and data.get("role"):
        device.class_source = "agent"
    else:
        inferred = infer(device.os_family, device.os_name, device.manufacturer, device.model)
        # An agent that reports form factor / virtualisation but no role (unknown
        # product type) keeps those facts.
        data = {**inferred, **{k: v for k, v in (data or {}).items() if v not in (None, "")}}
        device.class_source = "inferred"
    device.device_class = data.get("role") if data.get("role") in DEVICE_CLASSES else None
    device.form_factor = (data.get("form_factor") or "")[:16] or None
    device.is_virtual = data.get("is_virtual")
    device.hypervisor = (data.get("hypervisor") or "")[:32] or None
    device.cloud_provider = (data.get("cloud_provider") or "")[:16] or None
    device.cloud_instance_id = (data.get("cloud_instance_id") or "").lower()[:128] or None


def summary(device: Any) -> dict[str, Any]:
    """The classification fields of the device API."""
    return {"device_class": device.device_class, "class_source": device.class_source,
            "form_factor": device.form_factor, "is_virtual": device.is_virtual, "hypervisor": device.hypervisor,
            "cloud_provider": device.cloud_provider, "cloud_instance_id": device.cloud_instance_id}


def is_server_class(device_class: str | None) -> bool:
    return device_class in ("server", "domain_controller")


def asset_type(device: Any, fallback: str) -> str:
    """IT asset type of an agent device: "server" for servers and domain
    controllers (physical or virtual), else laptop / desktop / tablet from the
    form factor, else `fallback` (the make / model guess)."""
    if is_server_class(device.device_class):
        return "server"
    if device.form_factor in ("laptop", "desktop", "tablet"):
        return device.form_factor
    return fallback


def directory_class(device_kind: str, os_name: str, uac: int | None, platform: str) -> str | None:
    """Class of a directory computer (no agent needed): AD computer accounts
    with SERVER_TRUST_ACCOUNT are domain controllers; "Server" in the OS name
    (AD operatingSystem, Entra / Intune operatingSystem) is a server; Linux
    computers are servers (as for agents without a graphical session); other
    desktop operating systems are workstations. Phones, tablets and unknown
    operating systems have no class."""
    if device_kind == "ad" and (uac or 0) & UAC_SERVER_TRUST_ACCOUNT:
        return "domain_controller"
    if is_server_os(os_name):
        return "server"
    if platform == "linux":
        return "server"
    if platform in ("windows", "macos", "chromeos"):
        return "workstation"
    return None


# ----------------------------------------------------------------------------- cloud link
def _swapped_uuid(u: str) -> str:
    """The same SMBIOS UUID with the first three fields byte-swapped (Azure VM
    ids read on older firmware / tools use the other byte order)."""
    p = u.split("-")
    if len(p) != 5:
        return u
    sw = lambda s: "".join(reversed([s[i:i + 2] for i in range(0, len(s), 2)]))  # noqa: E731
    return "-".join([sw(p[0]), sw(p[1]), sw(p[2]), p[3], p[4]])


def cloud_resource(db: Session, device: Any) -> dict[str, Any] | None:
    """The cloud inventory resource this VM is (AWS instance id, Azure VM id,
    GCE instance name), from the organisation's scanned cloud inventory."""
    from .models import Asset

    provider, iid = device.cloud_provider, (device.cloud_instance_id or "").lower()
    found = None
    if provider == "aws" and iid:
        found = db.scalars(select(Asset).where(Asset.type == "ec2_instance", Asset.id.like(f"%:instance/{iid}"))
                           ).first()
    elif provider == "azure" and iid:
        want = {iid, _swapped_uuid(iid)}
        found = next((a for a in db.scalars(select(Asset).where(Asset.type == "vm"))
                      if str((a.properties or {}).get("vm_id") or "").lower() in want), None)
    elif provider == "gcp":
        # GCE puts no instance id into SMBIOS: link by instance name when unique.
        host = (device.hostname or "").split(".")[0].lower()
        rows = list(db.scalars(select(Asset).where(Asset.type == "gce_instance", Asset.name == host).limit(2)))
        found = rows[0] if len(rows) == 1 else None
    if found is None:
        return None
    return {"id": found.id, "name": found.name, "type": found.type, "provider": found.provider,
            "region": found.region}
