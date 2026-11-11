"""Linux server agent (agent 1.7.0+): one record per server when both the endpoint agent and the runtime sensor
run on it (docs/DEVICE_MANAGEMENT.md#linux-servers).

The agent answers "is this server configured and patched?", the sensor "is something bad happening on it right
now?". Both can be installed. To keep the vulnerability counts honest the **agent's package list is used and the
sensor's is ignored** while the agent is checking in; the server is then one record: the Device carries the
packages and their vulnerabilities, the sensor's asset keeps runtime events and gets `agent_device_id`.

The sensor and the agent are matched, in this order:

1. **cloud resource id**: the sensor's `cloud.resource_id` against the agent's DMI instance id (AWS: the
   ``instance/i-...`` suffix of the resource id; Azure: the VM id of the scanned VM asset);
2. **machine id**: the sensor's optional ``machine_id`` (SHA-256 of /etc/machine-id with the agent's
   ``cnapp-agent:`` prefix, never the raw id) against the device's ``machine_id``;
3. **host name**: case-insensitive, short or fully qualified, only when exactly one agent device has it.

An agent that has not checked in for AGENT_FRESH_DAYS no longer wins: the sensor's list is used again until
the agent returns.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..models import Asset, AssetPackage, Device, Vulnerability, VulnMatchState
from ..vulnmatch.state import ASSET

log = logging.getLogger(__name__)

AGENT_FRESH_DAYS = 7


def _short(host: str | None) -> str:
    return (host or "").strip().lower().split(".")[0]


def _active_linux_devices(db: Session, now: datetime) -> list[Device]:
    cutoff = now - timedelta(days=AGENT_FRESH_DAYS)
    return list(db.scalars(select(Device).where(
        Device.os_family == "linux", Device.status == "active", Device.last_checkin_at.is_not(None),
        Device.last_checkin_at >= cutoff, Device.software_count > 0)))


def _cloud_id_matches(db: Session, d: Device, rid: str) -> bool:
    iid = (d.cloud_instance_id or "").strip().lower()
    if not iid or not rid:
        return False
    rid = rid.strip().lower().rstrip("/")
    if rid == iid or rid.endswith("/" + iid) or rid.endswith(":" + iid):
        return True  # AWS: arn:aws:ec2:region:account:instance/i-...
    if d.cloud_provider == "azure":
        from ..models import get_asset

        a = get_asset(db, rid)
        vm_id = str(((a.properties or {}) if a is not None else {}).get("vm_id") or "").lower()
        return bool(vm_id) and vm_id == iid
    return False


def agent_for_sensor(db: Session, now: datetime, *, resource_id: str | None, machine_id: str | None,
                     host: str | None) -> Device | None:
    """The Linux agent device that is the same server as a sensor host (see the module docstring), or None."""
    devices = _active_linux_devices(db, now)
    if not devices:
        return None
    if resource_id:
        for d in devices:
            if _cloud_id_matches(db, d, resource_id):
                return d
    if machine_id:
        for d in devices:
            if d.machine_id and d.machine_id == machine_id.strip().lower():
                return d
    if host:
        same = [d for d in devices if d.hostname.lower() == host.strip().lower() or _short(d.hostname) == _short(host)]
        if len(same) == 1:
            return same[0]
    return None


def asset_for_device(db: Session, d: Device) -> Asset | None:
    """The inventory / sensor asset of the same server as an agent device (cloud resource, machine id, host name)."""
    from ..device_class import cloud_resource
    from ..models import get_asset

    if d.cloud_provider:
        try:
            res = cloud_resource(db, d)
        except Exception:  # noqa: BLE001 - linking is best effort
            log.exception("cloud resource lookup failed")
            res = None
        if res is not None and (a := get_asset(db, res["id"])) is not None:
            return a
    if d.machine_id:
        for a in db.scalars(select(Asset).where(Asset.source == "sensor")):
            if str((a.properties or {}).get("machine_id") or "").lower() == d.machine_id:
                return a
    short = _short(d.hostname)
    rows = [a for a in db.scalars(select(Asset).where(Asset.type == "vm", func.lower(Asset.name).like(short + "%")))
            if _short(a.name) == short]
    return rows[0] if len(rows) == 1 else None


def supersede_sensor_packages(db: Session, asset: Asset, device: Device, now: datetime) -> int:
    """The agent's package list replaces the sensor's on this asset: drop the sensor rows and resolve the
    vulnerabilities they produced (the device carries them now). Returns the number of removed packages."""
    from ..vulnmatch import matcher

    props = dict(asset.properties or {})
    if props.get("package_source") != "agent" or props.get("agent_device_id") != device.id:
        props["package_source"], props["agent_device_id"] = "agent", device.id
        asset.properties = props
    n = db.execute(delete(AssetPackage).where(AssetPackage.asset_id == asset.id)).rowcount or 0
    if n:
        matcher.resolve_all(db, Vulnerability.asset_id == asset.id, now,
                            "package inventory now comes from the endpoint agent on this server")
        db.execute(delete(VulnMatchState).where(VulnMatchState.target_type == ASSET,
                                                VulnMatchState.target_id == asset.id))
    return n


def reconcile_sensor(db: Session, device: Device, now: datetime) -> None:
    """Called on every Linux agent check-in: if a sensor asset is the same server, the agent's packages win."""
    if device.status != "active" or (device.software_count or 0) == 0:
        return
    try:
        asset = asset_for_device(db, device)
        if asset is not None:
            supersede_sensor_packages(db, asset, device, now)
    except Exception:  # noqa: BLE001 - bookkeeping must never fail a check-in
        log.exception("could not reconcile the sensor asset of device %s", device.id)
