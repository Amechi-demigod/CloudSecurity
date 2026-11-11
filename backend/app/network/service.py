"""Network discovery: scan configuration, queueing on a dedicated collector, batch ingest, device merge,
linking to endpoints / directory computers / IT assets, findings and vulnerability matching requests.

Secrets: SNMP credentials are stored Fernet-encrypted (notifications/crypto.py, the mechanism directory
sources use). The params of a queued `network_scan` command (stored in `collector_commands.params` and in
`network_scan_runs.params`) never contain them; `delivery_params` adds them to the copy handed to the
collector and nowhere else.
"""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, load_only

from ..directory import collectors as coll
from ..directory.models import CollectorCommand, DirectoryCollector, DirectoryComputer
from ..models import Asset, Device, Finding, get_asset, utcnow
from ..vulnmatch import state as vstate
from . import normalize, rules, validate
from .models import (
    DEFAULT_PORTS,
    RUN_ACTIVE,
    NetworkDevice,
    NetworkDeviceEvent,
    NetworkDeviceInterface,
    NetworkDevicePort,
    NetworkFdb,
    NetworkScan,
    NetworkScanRun,
    NetworkSnmpCredential,
)
from .schemas import DeviceIn, NetBatchIn, clean

log = logging.getLogger(__name__)

SYSTEM = "system"
UPLOAD_URL = "/api/collector/network/batches"
NETWORK_SCAN = coll.NETWORK_SCAN
NETWORK_SUBNETS = coll.NETWORK_SUBNETS
PICKUP_TIMEOUT = timedelta(minutes=15)
STALL_TIMEOUT = timedelta(minutes=30)
COMMAND_TTL = timedelta(minutes=30)  # network_subnets
SCAN_TTL = timedelta(hours=6)  # the collector stops a scan at the command's expires_at: the latest acceptable end
TIMEOUT_MS = 1500
SCHEDULE_GRACE = timedelta(hours=4)
UPLINK_PORT_MACS = 24  # a switch port that learned more MACs than this is treated as an uplink / trunk
NEW_WINDOW = timedelta(days=14)
NETWORK_TARGET = "network"  # VulnMatchState.target_type


class NetworkError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


# ----------------------------------------------------------------------------- credentials
def hint_for(version: str, username: str) -> str:
    if version == "v3":
        u = (username or "").strip()
        return f"{u[:2]}••••"[:64]
    return "community string"


def store_secret(cred: NetworkSnmpCredential, data: dict[str, str]) -> None:
    from ..notifications import crypto

    try:
        cred.secret_ciphertext = crypto.encrypt_secrets(data)
    except crypto.EncryptionUnavailable as e:
        raise NetworkError(503, f"cannot store the credential: {e}") from None


def load_secret(cred: NetworkSnmpCredential) -> dict[str, str] | None:
    from ..notifications import crypto

    if not cred.secret_ciphertext:
        return None
    try:
        return crypto.decrypt_secrets(cred.secret_ciphertext)
    except (crypto.DecryptionFailed, crypto.EncryptionUnavailable):
        return None


def rotate_secrets(db: Session) -> int:
    from ..notifications import crypto

    n = 0
    for c in db.scalars(select(NetworkSnmpCredential).where(NetworkSnmpCredential.secret_ciphertext.is_not(None))
                        .execution_options(tenant_unscoped=True)):
        c.secret_ciphertext = crypto.rotate(c.secret_ciphertext)
        n += 1
    return n


def apply_credential(cred: NetworkSnmpCredential, *, version: str, username: str, level: str, auth_proto: str,
                     priv_proto: str, auth_password: str, priv_password: str, community: str) -> None:
    """Validate and store one credential (secrets encrypted; non-secret settings in columns)."""
    if version == "v3":
        if not username.strip():
            raise NetworkError(422, "SNMPv3 needs a username")
        if level not in ("authPriv", "authNoPriv"):
            raise NetworkError(422, "choose a security level (authPriv recommended)")
        if not auth_proto or not auth_password:
            raise NetworkError(422, "SNMPv3 needs an authentication protocol and password")
        if len(auth_password) < 8 or (level == "authPriv" and len(priv_password) < 8):
            raise NetworkError(422, "SNMPv3 passwords must be at least 8 characters")
        if level == "authPriv" and (priv_proto not in ("AES128", "AES256") or not priv_password):
            raise NetworkError(422, "authPriv needs a privacy protocol (AES128 / AES256) and password")
        cred.username, cred.level, cred.auth_proto = username.strip(), level, auth_proto
        cred.priv_proto = priv_proto if level == "authPriv" else "none"
        store_secret(cred, {"auth_password": auth_password,
                            "priv_password": priv_password if level == "authPriv" else ""})
    else:
        if not community.strip():
            raise NetworkError(422, "SNMPv2c needs a community string")
        cred.username = cred.level = cred.auth_proto = cred.priv_proto = ""
        store_secret(cred, {"community": community.strip()})
    cred.version = version
    cred.hint = hint_for(version, username)
    cred.updated_at = utcnow()


def cred_out(c: NetworkSnmpCredential) -> dict[str, Any]:
    """Never contains a secret."""
    return {"id": c.id, "name": c.name, "version": c.version, "username_hint": c.hint if c.version == "v3" else "",
            "level": c.level, "auth_proto": c.auth_proto, "priv_proto": c.priv_proto,
            "label": "SNMPv3 (preferred)" if c.version == "v3" else "SNMPv2c", "created_at": c.created_at.isoformat() + "Z",
            "created_by": c.created_by, "secret_stored": bool(c.secret_ciphertext)}


def snmp_stored(c: NetworkSnmpCredential) -> dict[str, Any]:
    """The credential as it appears in stored params: no secret fields."""
    if c.version == "v3":
        return {"id": c.id, "version": "v3", "username": c.username, "auth_proto": c.auth_proto,
                "priv_proto": c.priv_proto, "level": c.level}
    return {"id": c.id, "version": "v2c"}


# ----------------------------------------------------------------------------- params
def default_ports() -> list[dict[str, Any]]:
    return [dict(p) for p in DEFAULT_PORTS]


def stored_params(run_id: str, *, targets: list[str], exclude: list[str], port_check: bool, concurrency: int,
                  creds: list[NetworkSnmpCredential]) -> dict[str, Any]:
    """The network_scan params as STORED (no secrets). Exactly the contract in docs/NETWORK_DISCOVERY.md."""
    return {"scan_id": run_id, "targets": list(targets), "exclude": list(exclude), "port_check": bool(port_check),
            "ports": default_ports() if port_check else [], "concurrency": int(concurrency), "timeout_ms": TIMEOUT_MS,
            "snmp": [snmp_stored(c) for c in creds], "upload_url": UPLOAD_URL}


def delivery_params(db: Session, cmd: CollectorCommand) -> dict[str, Any] | None:
    """Params handed to the collector for a network_scan: the stored ones plus each credential's secrets.
    None (the caller cancels the command) when the run is no longer waiting or a secret cannot be decrypted.
    The result is only ever put in the HTTP response: never stored, logged or returned by another API."""
    run = db.get(NetworkScanRun, (cmd.params or {}).get("scan_id") or "")
    if run is None or run.status != "queued" or run.command_id != cmd.id:
        return None
    params = dict(cmd.params or {})
    out = []
    for s in params.get("snmp") or []:
        cred = db.get(NetworkSnmpCredential, s.get("id") or "")
        sec = load_secret(cred) if cred is not None else None
        if sec is None:
            fail_run(db, run, "an SNMP credential is missing or cannot be decrypted "
                              "(NOTIFICATIONS_ENCRYPTION_KEY changed?): enter it again")
            return None
        item = dict(s)
        if s.get("version") == "v3":
            item["auth_password"] = sec.get("auth_password", "")
            item["priv_password"] = sec.get("priv_password", "")
        else:
            item["community"] = sec.get("community", "")
        out.append(item)
    params["snmp"] = out
    now = utcnow()
    run.status, run.started_at = "running", now
    return params


# ----------------------------------------------------------------------------- collectors / queueing
def collector_for(db: Session, collector_id: str | None) -> DirectoryCollector:
    c = db.get(DirectoryCollector, collector_id) if collector_id else None
    if c is None:
        raise NetworkError(404, "collector not found")
    return c


def require_online(c: DirectoryCollector, now: datetime | None = None) -> None:
    if "network_discovery" not in (c.features or "").split(","):
        raise NetworkError(409, f"collector {c.name} does not support network discovery: update it to 1.6.0 or later")
    if not coll.is_healthy(c, now):
        raise NetworkError(409, f"collector {c.name} is not online (seen in the last 10 minutes)")


def active_run(db: Session, scan_id: str) -> NetworkScanRun | None:
    return db.scalar(select(NetworkScanRun).where(NetworkScanRun.scan_id == scan_id,
                                                  NetworkScanRun.status.in_(RUN_ACTIVE)).limit(1))


def _queue(db: Session, c: DirectoryCollector, run: NetworkScanRun, creds: list[NetworkSnmpCredential], *,
           targets: list[str], exclude: list[str], port_check: bool, concurrency: int, reason: str,
           actor: str | None) -> NetworkScanRun:
    db.add(run)
    db.flush()
    run.params = stored_params(run.id, targets=targets, exclude=exclude, port_check=port_check,
                               concurrency=concurrency, creds=creds)
    cmd = coll.new_command(db, c, NETWORK_SCAN, run.params, reason, actor=actor or SYSTEM, ttl=SCAN_TTL)
    run.command_id = cmd.id
    return run


def credentials_by_id(db: Session, ids: list[str]) -> list[NetworkSnmpCredential]:
    rows = {c.id: c for c in db.scalars(select(NetworkSnmpCredential).where(NetworkSnmpCredential.id.in_(ids)))} if ids else {}
    missing = [i for i in ids if i not in rows]
    if missing:
        raise NetworkError(422, "unknown SNMP credential")
    # v3 first: the collector tries the credentials in order and v3 is preferred.
    return sorted((rows[i] for i in ids), key=lambda c: (c.version != "v3", ids.index(c.id)))


def queue_scan(db: Session, scan: NetworkScan, *, trigger: str, actor: str | None, now: datetime | None = None
               ) -> NetworkScanRun:
    """Queue a saved scan on its collector (caller commits)."""
    now = now or utcnow()
    c = collector_for(db, scan.collector_id)
    require_online(c, now)
    if active_run(db, scan.id) is not None:
        raise NetworkError(409, "this scan is already queued or running")
    creds = credentials_by_id(db, list(scan.credential_ids or []))
    run = NetworkScanRun(scan_id=scan.id, name=scan.name, trigger=trigger, status="queued", collector_id=c.id,
                         requested_by=actor, queued_at=now)
    _queue(db, c, run, creds, targets=scan.targets, exclude=scan.exclude, port_check=scan.port_check,
           concurrency=scan.concurrency, reason=f"network scan {scan.name} ({trigger})", actor=actor)
    scan.last_run_id, scan.last_status = run.id, "queued"
    return run


def queue_address(db: Session, c: DirectoryCollector, address: str, creds: list[NetworkSnmpCredential], *,
                  trigger: str, actor: str | None, port_check: bool = True, name: str = "") -> NetworkScanRun:
    """One-address scan (the wizard's test, "Re-scan device"): a network_scan with a single /32 target."""
    try:
        ip = str(ipaddress.IPv4Address(address.strip()))
        targets, _, _ = validate.validate([f"{ip}/32"])
    except (ipaddress.AddressValueError, ValueError) as e:
        raise NetworkError(422, str(e)) from None
    require_online(c)
    run = NetworkScanRun(scan_id=None, name=name or f"Test {ip}", trigger=trigger, status="queued", collector_id=c.id,
                         requested_by=actor, queued_at=utcnow())
    return _queue(db, c, run, creds, targets=targets, exclude=[], port_check=port_check, concurrency=20,
                  reason=f"network {trigger} of {ip}", actor=actor)


def queue_subnets(db: Session, c: DirectoryCollector, actor: str | None) -> CollectorCommand:
    require_online(c)
    return coll.new_command(db, c, NETWORK_SUBNETS, {}, "suggest subnets from AD Sites and DHCP", actor=actor or SYSTEM,
                            ttl=COMMAND_TTL)


def suggestions(db: Session, collector_id: str | None = None) -> list[dict[str, Any]]:
    """The newest successful `network_subnets` result of each collector (or of one)."""
    out = []
    cols = [collector_for(db, collector_id)] if collector_id else list(db.scalars(select(DirectoryCollector)))
    for c in cols:
        cmd = db.scalar(select(CollectorCommand).where(
            CollectorCommand.collector_id == c.id, CollectorCommand.type == NETWORK_SUBNETS,
            CollectorCommand.status == "succeeded").order_by(CollectorCommand.completed_at.desc()).limit(1))
        pending = db.scalar(select(CollectorCommand).where(
            CollectorCommand.collector_id == c.id, CollectorCommand.type == NETWORK_SUBNETS,
            CollectorCommand.status.in_(("pending", "delivered"))).limit(1))
        data = clean_suggestions((cmd.result_data if cmd is not None else None) or {})
        out.append({"collector_id": c.id, "collector_name": c.name, "at": cmd.completed_at.isoformat() + "Z" if cmd else None,
                    "pending": pending is not None, **data})
    return out


def clean_suggestions(data: dict[str, Any]) -> dict[str, Any]:
    """Sanitise a network_subnets result (strings capped, only valid subnets) and add a flat `items` list."""
    sites, scopes, items = [], [], []
    for s in (data.get("ad_sites") or [])[:2000]:
        if not isinstance(s, dict):
            continue
        item = {"site": clean(str(s.get("site") or ""), 128), "subnet": clean(str(s.get("subnet") or ""), 64),
                "description": clean(str(s.get("description") or ""), 255)}
        try:
            lo, hi = validate.parse(item["subnet"], forbid=False)
        except validate.TargetError:
            continue
        sites.append(item)
        items.append({"subnet": item["subnet"], "name": item["description"] or item["site"], "source": "ad_site",
                      "suggested_by": f"AD Site: {item['site']}", "addresses": hi - lo + 1})
    for s in (data.get("dhcp_scopes") or [])[:2000]:
        if not isinstance(s, dict):
            continue
        item = {k: clean(str(s.get(k) or ""), 128) for k in ("server", "scope", "mask", "name", "start", "end")}
        try:
            net = ipaddress.IPv4Network(f"{item['scope']}/{item['mask']}", strict=False)
        except ValueError:
            continue
        scopes.append(item)
        items.append({"subnet": str(net), "name": item["name"] or str(net), "source": "dhcp",
                      "suggested_by": f"DHCP: {item['server']}", "addresses": net.num_addresses})
    seen: dict[str, dict[str, Any]] = {}
    for it in items:  # one row per subnet: AD Site and DHCP can suggest the same one
        row = seen.setdefault(it["subnet"], {**it, "suggested_by_all": []})
        row["suggested_by_all"].append(it["suggested_by"])
    errors = [clean(str(e), 300) for e in (data.get("errors") or [])[:20]]
    return {"ad_sites": sites, "dhcp_scopes": scopes, "errors": errors, "items": list(seen.values())}


# ----------------------------------------------------------------------------- runs
def fail_run(db: Session, run: NetworkScanRun, error: str, *, now: datetime | None = None) -> None:
    if run.status in ("succeeded", "failed", "cancelled"):
        return
    now = now or utcnow()
    run.status, run.error, run.finished_at = "failed", error[:2000], now
    _scan_finished(db, run, now)


def _scan_finished(db: Session, run: NetworkScanRun, now: datetime) -> None:
    scan = db.get(NetworkScan, run.scan_id) if run.scan_id else None
    if scan is not None and scan.last_run_id == run.id:
        scan.last_run_at, scan.last_status = now, run.status
        s = dict(run.summary or {})
        s["devices"] = run.devices_seen
        if run.error:
            s["error"] = run.error
        scan.last_summary = s


def command_failed(db: Session, cmd: CollectorCommand, output: str) -> None:
    run = db.get(NetworkScanRun, (cmd.params or {}).get("scan_id") or "")
    if run is not None:
        fail_run(db, run, output or f"the collector reported the scan as {cmd.status}")


def supervise(db: Session, now: datetime) -> list[str]:
    """Fail runs the collector never picked up or stopped reporting on. Returns failed run ids."""
    failed = []
    for run in db.scalars(select(NetworkScanRun).where(NetworkScanRun.status.in_(RUN_ACTIVE))):
        reason = None
        if run.status == "queued":
            cmd = db.get(CollectorCommand, run.command_id) if run.command_id else None
            if cmd is None or cmd.status in ("expired", "cancelled"):
                reason = "the collector did not pick up the scan (command expired or cancelled)"
            elif now - run.queued_at >= PICKUP_TIMEOUT:
                reason = "the collector did not pick up the scan within 15 minutes (offline?)"
                if cmd.status == "pending":
                    cmd.status, cmd.completed_at, cmd.output = "cancelled", now, "scan not picked up"
        elif now - (run.last_batch_at or run.started_at or run.queued_at) >= STALL_TIMEOUT:
            reason = "no data from the collector for 30 minutes"
        if reason:
            fail_run(db, run, reason, now=now)
            failed.append(run.id)
    return failed


def schedule_slot(scan: NetworkScan, now: datetime) -> datetime | None:
    """The most recent scheduled start (UTC) at or before `now`; None for manual scans."""
    if scan.schedule == "manual":
        return None
    hh, mm = (int(x) for x in (scan.schedule_time or "02:00").split(":"))
    slot = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if scan.schedule == "daily":
        return slot if slot <= now else slot - timedelta(days=1)
    back = (now.weekday() - (scan.schedule_weekday or 0)) % 7
    slot -= timedelta(days=back)
    return slot if slot <= now else slot - timedelta(days=7)


def next_run_at(scan: NetworkScan, now: datetime | None = None) -> datetime | None:
    now = now or utcnow()
    if not scan.enabled or scan.schedule == "manual":
        return None
    slot = schedule_slot(scan, now)
    nxt = slot + (timedelta(days=1) if scan.schedule == "daily" else timedelta(days=7))
    return nxt if nxt > now else now


def tick_org(db: Session, now: datetime) -> dict[str, list[str]]:
    """One scheduler pass for the session's organisation (caller commits per scan)."""
    out: dict[str, list[str]] = {"queued": [], "failed": [], "skipped": []}
    out["failed"] += supervise(db, now)
    db.commit()
    for scan in list(db.scalars(select(NetworkScan).where(NetworkScan.enabled.is_(True)))):
        try:
            slot = schedule_slot(scan, now)
            if slot is None or slot <= scan.created_at:
                continue
            done = db.scalar(select(func.count()).select_from(NetworkScanRun).where(
                NetworkScanRun.scan_id == scan.id, NetworkScanRun.trigger == "scheduled",
                NetworkScanRun.queued_at >= slot))
            if done or active_run(db, scan.id) is not None:
                continue
            c = db.get(DirectoryCollector, scan.collector_id) if scan.collector_id else None
            if c is None or not coll.is_healthy(c, now):
                if now - slot >= SCHEDULE_GRACE:  # give up on this slot (recorded, so the schedule moves on)
                    run = NetworkScanRun(scan_id=scan.id, name=scan.name, trigger="scheduled", status="queued",
                                         queued_at=now, requested_by=SYSTEM)
                    db.add(run)
                    db.flush()
                    scan.last_run_id = run.id
                    fail_run(db, run, "the collector was offline at the scheduled time", now=now)
                    out["skipped"].append(scan.id)
                db.commit()
                continue
            run = queue_scan(db, scan, trigger="scheduled", actor=SYSTEM, now=now)
            from ..auth import audit

            audit(db, "network_scan_started", actor_email=SYSTEM, target=f"network-scan:{scan.id}", run_id=run.id,
                  trigger="scheduled", collector_id=c.id)
            out["queued"].append(run.id)
            db.commit()
        except Exception:
            db.rollback()
            log.exception("network scan %s: scheduling failed", scan.id)
    return out


# ----------------------------------------------------------------------------- device merge
def _event(db: Session, nd: NetworkDevice, kind: str, detail: str, run_id: str | None, now: datetime) -> None:
    db.add(NetworkDeviceEvent(device_id=nd.id, at=now, kind=kind, detail=detail[:512], run_id=run_id))


def find_device(db: Session, ip: str, mac: str) -> NetworkDevice | None:
    """Identity: the MAC when known, else the IP (a MAC-less record is upgraded when its MAC shows up)."""
    nd = None
    if mac:
        nd = db.scalar(select(NetworkDevice).where(NetworkDevice.mac == mac).order_by(NetworkDevice.last_seen.desc()).limit(1))
        if nd is None:
            nd = db.scalar(select(NetworkDevice).where(NetworkDevice.ip == ip, NetworkDevice.mac == "").limit(1))
    else:
        nd = db.scalar(select(NetworkDevice).where(NetworkDevice.ip == ip).order_by(NetworkDevice.last_seen.desc()).limit(1))
    return nd


def short_name(*names: str) -> str:
    for n in names:
        if n:
            return n.split(".")[0].lower()
    return ""


def apply_device(db: Session, run: NetworkScanRun, d: DeviceIn, now: datetime, *, port_check: bool,
                 targets: list[str]) -> NetworkDevice | None:
    try:
        ip = str(ipaddress.IPv4Address((d.ip or "").strip()))
    except ValueError:
        return None
    mac = normalize.mac_clean(d.mac)
    snmp = d.snmp
    nd = find_device(db, ip, mac)
    new = nd is None
    if nd is None:
        nd = NetworkDevice(ip=ip, mac=mac, first_seen=now, last_seen=now)
        db.add(nd)
        db.flush()
        _event(db, nd, "first_seen", f"First seen at {ip}", run.id, now)
    if not new and nd.ip != ip:
        _event(db, nd, "ip_changed", f"IP address changed from {nd.ip} to {ip}", run.id, now)
        nd.ip = ip
    if mac and not nd.mac:
        nd.mac = mac
    nd.mac_vendor = clean(d.mac_vendor, 128) or normalize.mac_vendor(nd.mac) or nd.mac_vendor
    nd.hostname = clean(d.hostname, 255) or nd.hostname
    nd.alive_via = list(d.alive_via)
    nd.subnet = validate.subnet_of(ip, targets or run.params.get("targets") or []) or nd.subnet
    nd.last_seen, nd.last_run_id = now, run.id
    ports = [{"port": p.port, "proto": p.proto, "service": clean(p.service, 64), "banner": clean(p.banner, 200)}
             for p in d.open_ports][:64]
    hints = {"vendor": clean(d.vendor, 64), "model": clean(d.model, 128), "firmware": clean(d.firmware, 64),
             "serial": clean(d.serial, 128), "device_type": clean(d.device_type, 16)}
    if snmp is not None:
        nd.snmp_version = snmp.version
        nd.snmp_credential_id = clean(snmp.credential_id, 32)
        nd.sys_name = clean(snmp.sys_name, 255)
        nd.sys_descr = clean(snmp.sys_descr, 1024)
        nd.sys_object_id = clean(snmp.sys_object_id, 128)
        nd.sys_location = clean(snmp.sys_location, 255)
        nd.sys_contact = clean(snmp.sys_contact, 255)
        nd.uptime_s = snmp.uptime_s if snmp.uptime_s is None or snmp.uptime_s >= 0 else None
    else:
        nd.snmp_version = ""
        nd.snmp_credential_id = ""
    nd.default_community = d.default_community or ""
    ssh = next((p["banner"] for p in sorted(ports, key=lambda p: p["port"] != 22)
                if p["proto"] == "tcp" and p["banner"].startswith("SSH-")), "")
    n = normalize.normalize(nd.sys_descr, nd.sys_object_id, nd.mac, [p["port"] for p in ports], hints, ssh)
    if n.vendor:
        nd.vendor = n.vendor
    elif not nd.vendor:
        nd.vendor = nd.mac_vendor
    old_fw, old_type = nd.firmware, nd.device_type
    nd.model = n.model or nd.model
    nd.firmware = n.firmware or nd.firmware
    nd.serial = n.serial or hints["serial"] or nd.serial
    nd.device_type = n.device_type
    nd.family, nd.cpe_product, nd.cpe_version, nd.cpe_update = n.family, n.cpe_product, n.cpe_version, n.cpe_update
    if not new and old_fw and nd.firmware and old_fw != nd.firmware:
        _event(db, nd, "firmware_changed", f"Firmware changed from {old_fw} to {nd.firmware}", run.id, now)
    if not new and old_type != nd.device_type and old_type != "unknown":
        _event(db, nd, "type_changed", f"Identified as {nd.device_type} (was {old_type})", run.id, now)
    ensure_asset(db, nd, now)
    if port_check:
        _apply_ports(db, nd, ports, run, now, first=new)
    if d.interfaces is not None:
        _apply_interfaces(db, nd, d.interfaces)
    if d.fdb is not None:
        _apply_fdb(db, nd, d.fdb, now)
    db.flush()
    link_directory(db, nd)
    request_vuln_match(db, nd, now)
    db.flush()
    return nd


def _apply_ports(db: Session, nd: NetworkDevice, ports: list[dict], run: NetworkScanRun, now: datetime, *, first: bool) -> None:
    have = {(p.port, p.proto): p for p in db.scalars(select(NetworkDevicePort).where(NetworkDevicePort.device_id == nd.id))}
    seen = set()
    for p in ports:
        k = (p["port"], p["proto"])
        seen.add(k)
        row = have.get(k)
        if row is None:
            db.add(NetworkDevicePort(device_id=nd.id, first_seen=now, last_seen=now, **p))
            if not first:
                _event(db, nd, "port_opened", f"Port {p['port']}/{p['proto']} opened", run.id, now)
        else:
            row.service, row.banner, row.last_seen = p["service"] or row.service, p["banner"], now
    for k, row in have.items():
        if k not in seen:
            _event(db, nd, "port_closed", f"Port {k[0]}/{k[1]} no longer open", run.id, now)
            db.delete(row)


def _apply_interfaces(db: Session, nd: NetworkDevice, items) -> None:
    db.execute(delete(NetworkDeviceInterface).where(NetworkDeviceInterface.device_id == nd.id))
    seen = set()
    for i in items:
        if i.index in seen:
            continue
        seen.add(i.index)
        db.add(NetworkDeviceInterface(device_id=nd.id, if_index=i.index, name=clean(i.name, 64), descr=clean(i.descr, 255),
                                      mac=normalize.mac_clean(i.mac), oper_up=bool(i.oper_up), speed_mbps=i.speed_mbps))


def _apply_fdb(db: Session, nd: NetworkDevice, items, now: datetime) -> None:
    have = {(f.mac, f.port_name): f for f in db.scalars(select(NetworkFdb).where(NetworkFdb.device_id == nd.id))}
    seen = set()
    for f in items:
        mac = normalize.mac_clean(f.mac)
        port = clean(f.port_name, 64)
        if not mac or (mac, port) in seen:
            continue
        seen.add((mac, port))
        row = have.get((mac, port))
        if row is None:
            db.add(NetworkFdb(device_id=nd.id, mac=mac, port_name=port, vlan=f.vlan, first_seen=now, last_seen=now))
        else:
            row.vlan, row.last_seen = f.vlan, now
    for k, row in have.items():
        if k not in seen:
            db.delete(row)


def ensure_asset(db: Session, nd: NetworkDevice, now: datetime) -> Asset:
    """The shadow cloud-inventory row findings are keyed to."""
    nd.asset_id = nd.asset_id or f"netdev-{nd.id}"
    a = get_asset(db, nd.asset_id)
    name = nd.sys_name or nd.hostname or nd.ip
    props = {"ip": nd.ip, "mac": nd.mac, "vendor": nd.vendor, "model": nd.model, "firmware": nd.firmware,
             "device_type": nd.device_type, "network_device_id": nd.id}
    if a is None:
        a = Asset(id=nd.asset_id, name=name[:255], type="network_device", provider="onprem", tags={},
                  internet_exposed=False, sensitive_data=False, properties=props, source="network", first_seen=now,
                  last_seen=now)
        db.add(a)
        db.flush()
    else:
        a.name, a.properties, a.last_seen = name[:255], props, now
    return a


def display_name(nd: NetworkDevice) -> str:
    return nd.sys_name or nd.hostname or nd.ip


# ----------------------------------------------------------------------------- linking
def link_directory(db: Session, nd: NetworkDevice) -> None:
    """Match an AD computer by (short) host name; takes its IT asset / agent device when it has one."""
    if nd.directory_computer_id and db.get(DirectoryComputer, nd.directory_computer_id) is not None:
        return
    names = {n for n in (short_name(nd.hostname), short_name(nd.sys_name)) if n}
    if not names:
        return
    rows = list(db.scalars(select(DirectoryComputer).where(DirectoryComputer.short_name.in_(names),
                                                           DirectoryComputer.missing_since.is_(None)).limit(3)))
    if len(rows) != 1:  # none, or ambiguous: never guess
        return
    c = rows[0]
    nd.directory_computer_id = c.id
    if c.device_id and not nd.device_id:
        nd.device_id = c.device_id
    if c.it_asset_id and not nd.it_asset_id:
        nd.it_asset_id = c.it_asset_id


def link_sensor(db: Session, nd: NetworkDevice, by_name: dict[str, list[str]] | None = None) -> bool:
    """Match a host that runs the Linux runtime sensor. The sensor reports no MAC or IP, only its host name, and
    creates an `assets` row (source "sensor", type vm) named after it, so the link is by short host name and, like
    the AD link, only when exactly one sensor asset has that name (never guessed)."""
    if by_name is None:
        by_name = sensor_names(db)
    ids = {i for s in {short_name(nd.hostname), short_name(nd.sys_name)} if s for i in by_name.get(s, [])}
    if len(ids) == 1:
        nd.sensor_asset_id = ids.pop()
        return True
    if nd.sensor_asset_id and nd.sensor_asset_id not in {i for v in by_name.values() for i in v}:
        nd.sensor_asset_id = None  # the sensor asset was deleted
    return False


def sensor_names(db: Session) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for aid, name in db.execute(select(Asset.id, Asset.name).where(Asset.source == "sensor", Asset.type == "vm")):
        out.setdefault(short_name(name), []).append(aid)
    return out


def endpoint_maps(db: Session) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """(mac -> device id, ip -> device id, short hostname -> device id) of the enrolled endpoints. Reads each
    device's inventory once (chunked): only used at the end of a scan, never per batch."""
    macs: dict[str, str] = {}
    ips: dict[str, str] = {}
    names: dict[str, list[str]] = {}
    q = select(Device).options(load_only(Device.id, Device.hostname, Device.inventory)).where(Device.status == "active")
    for d in db.scalars(q.execution_options(yield_per=200)):
        for itf in (d.inventory or {}).get("network") or []:
            if not isinstance(itf, dict):
                continue
            m = normalize.mac_clean(str(itf.get("mac") or ""))
            if m:
                macs[m] = d.id
            for ip in itf.get("ips") or []:
                ips[str(ip)] = d.id
        names.setdefault(short_name(d.hostname), []).append(d.id)
    unique = {n: ids[0] for n, ids in names.items() if n and len(ids) == 1}
    return macs, ips, unique


def link_endpoints(db: Session, devices: list[NetworkDevice], maps: tuple[dict, dict, dict]) -> int:
    from ..asset_lifecycle.models import ItAsset

    todo = [d for d in devices if not d.device_id]
    if not todo:
        return 0
    macs, ips, names = maps
    n = 0
    for nd in todo:
        did = (macs.get(nd.mac) if nd.mac else None) or ips.get(nd.ip) or next(
            (names[s] for s in (short_name(nd.hostname), short_name(nd.sys_name)) if s in names), None)
        if did:
            nd.device_id = did
            n += 1
            if not nd.it_asset_id:
                nd.it_asset_id = db.scalar(select(ItAsset.id).where(ItAsset.device_id == did))
    return n


# ----------------------------------------------------------------------------- vulnerabilities
def request_vuln_match(db: Session, nd: NetworkDevice, now: datetime) -> None:
    if not nd.cpe_product or not nd.cpe_version:
        return
    digest = vstate.inventory_hash([("net", nd.cpe_product, nd.cpe_version, nd.cpe_update)])
    vstate.inventory_changed(db, NETWORK_TARGET, nd.id, digest, now)


# ----------------------------------------------------------------------------- findings
def known_macs(db: Session, devices_macs: dict[str, str]) -> set[str]:
    """MACs of everything we manage: scanned devices, their interfaces and the enrolled endpoints."""
    macs = set(devices_macs)
    macs |= {m for (m,) in db.execute(select(NetworkDeviceInterface.mac).where(NetworkDeviceInterface.mac != "").distinct())}
    macs |= {m for (m,) in db.execute(select(NetworkDevice.mac).where(NetworkDevice.mac != "").distinct())}
    return macs


def fdb_view(db: Session, sw: NetworkDevice, known: set[str]) -> list[dict[str, Any]]:
    """The MACs on a switch's access ports that are not managed (not a scanned device, interface or endpoint)."""
    rows = list(db.scalars(select(NetworkFdb).where(NetworkFdb.device_id == sw.id)))
    per_port: dict[str, int] = {}
    for r in rows:
        per_port[r.port_name] = per_port.get(r.port_name, 0) + 1
    out = []
    baseline = min((r.first_seen for r in rows), default=sw.first_seen)  # the first table we saw is not "new"
    for r in rows:
        if r.mac in known or per_port.get(r.port_name, 0) > UPLINK_PORT_MACS:
            continue
        out.append({"mac": r.mac, "vendor": normalize.mac_vendor(r.mac), "port": r.port_name, "vlan": r.vlan,
                    "first_seen": r.first_seen.isoformat() + "Z", "new": r.first_seen > baseline and utcnow() - r.first_seen <= NEW_WINDOW})
    return out


def evaluate_device(db: Session, nd: NetworkDevice, now: datetime, known: set[str] | None = None) -> None:
    """Open / refresh / resolve the NET-* findings of one device."""
    ports = [{"port": p.port, "proto": p.proto, "service": p.service, "banner": p.banner}
             for p in db.scalars(select(NetworkDevicePort).where(NetworkDevicePort.device_id == nd.id))]
    new_fdb: list[dict] = []
    if nd.device_type == "switch" and known is not None:
        new_fdb = [x for x in fdb_view(db, nd, known) if x["new"]]
    result = rules.evaluate(rules.facts(nd, ports, new_fdb, now.date()))
    ensure_asset(db, nd, now)
    existing = {f.rule_id: f for f in db.scalars(select(Finding).where(
        Finding.asset_id == nd.asset_id, Finding.source == "network"))}
    for rid, ev in result.items():
        r = rules.RULES[rid]
        f = existing.get(rid)
        if f is None:
            db.add(Finding(rule_id=rid, asset_id=nd.asset_id, title=r.title, description=r.description,
                           severity=r.severity, status="open", remediation=r.remediation, compliance=list(r.compliance),
                           evidence=ev, source="network", first_seen=now, last_seen=now))
        else:
            f.title, f.description, f.severity, f.remediation = r.title, r.description, r.severity, r.remediation
            f.evidence, f.last_seen = ev, now
            if f.status == "resolved":
                f.status, f.resolved_at, f.first_seen = "open", None, now
    for rid, f in existing.items():
        if rid not in result and f.status == "open":
            f.status, f.resolved_at = "resolved", now


def finish_run(db: Session, run: NetworkScanRun, batch: NetBatchIn, now: datetime) -> None:
    """The collector's final batch: link endpoints, evaluate findings, mark the run done."""
    devices = list(db.scalars(select(NetworkDevice).where(NetworkDevice.last_run_id == run.id)))
    maps = endpoint_maps(db)
    link_endpoints(db, devices, maps)
    names = sensor_names(db)
    for nd in devices:
        link_sensor(db, nd, names)
    known = known_macs(db, maps[0])
    for nd in devices:
        evaluate_device(db, nd, now, known)
    s = batch.summary
    run.summary = {"addresses": s.addresses, "alive": s.alive, "snmp": s.snmp, "duration_s": s.duration_s,
                   "errors": [clean(e, 300) for e in s.errors[:50]]} if s else {}
    run.status, run.finished_at = "succeeded", now
    _scan_finished(db, run, now)


def ingest_batch(db: Session, c: DirectoryCollector, batch: NetBatchIn) -> dict[str, Any]:
    """One uploaded batch. Idempotent per (scan_id, seq): a repeated seq is acknowledged and ignored."""
    run = db.get(NetworkScanRun, batch.scan_id)
    if run is None or run.collector_id != c.id:
        raise NetworkError(404, "scan not found")
    if run.status in ("succeeded", "failed", "cancelled"):
        if batch.seq in (run.seqs or []):
            return {"accepted": 0, "duplicate": True, "status": run.status}
        raise NetworkError(409, f"the scan is {run.status}")
    if run.status == "queued":
        raise NetworkError(409, "the scan command has not been delivered")
    if batch.seq in (run.seqs or []):
        return {"accepted": 0, "duplicate": True, "status": run.status}
    now = utcnow()
    port_check = bool((run.params or {}).get("port_check"))
    targets = list((run.params or {}).get("targets") or [])
    n = 0
    for d in batch.devices:
        if apply_device(db, run, d, now, port_check=port_check, targets=targets) is not None:
            n += 1
    run.seqs = [*(run.seqs or []), batch.seq]
    run.devices_seen += n
    run.last_batch_at = now
    if batch.final:
        finish_run(db, run, batch, now)
    return {"accepted": n, "duplicate": False, "status": run.status}


# ----------------------------------------------------------------------------- output
def z(dt: datetime | None) -> str | None:
    return dt.isoformat() + "Z" if dt is not None else None


def tracked_of(nd: NetworkDevice) -> str:
    if nd.device_id:
        return "agent"
    if nd.directory_computer_id:
        return "ad"
    if nd.it_asset_id:
        return "it_asset"
    if nd.sensor_asset_id:
        return "sensor"
    return "none"


def run_out(r: NetworkScanRun) -> dict[str, Any]:
    p = r.params or {}
    return {"id": r.id, "scan_id": r.scan_id, "name": r.name, "trigger": r.trigger, "status": r.status,
            "collector_id": r.collector_id, "queued_at": z(r.queued_at), "started_at": z(r.started_at),
            "finished_at": z(r.finished_at), "devices_seen": r.devices_seen, "summary": r.summary or {},
            "error": r.error, "requested_by": r.requested_by, "targets": p.get("targets") or [],
            "port_check": p.get("port_check")}


def scan_out(db: Session, s: NetworkScan, now: datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    c = db.get(DirectoryCollector, s.collector_id) if s.collector_id else None
    return {"id": s.id, "name": s.name, "enabled": s.enabled, "collector_id": s.collector_id,
            "collector": {"id": c.id, "name": c.name, "state": coll.state(c, now), "ip": c.last_ip, "version": c.version} if c else None,
            "targets": s.targets, "exclude": s.exclude, "target_notes": s.target_notes, "port_check": s.port_check,
            "ports": s.ports, "concurrency": s.concurrency, "pace": "gentle" if s.concurrency == 20 else "normal",
            "credential_ids": s.credential_ids, "schedule": s.schedule, "schedule_time": s.schedule_time,
            "schedule_weekday": s.schedule_weekday, "address_count": s.address_count,
            "next_run_at": z(next_run_at(s, now)), "last_run_id": s.last_run_id, "last_run_at": z(s.last_run_at),
            "last_status": s.last_status, "last_summary": s.last_summary or {}, "created_at": z(s.created_at),
            "created_by": s.created_by, "updated_at": z(s.updated_at), "updated_by": s.updated_by}


def apply_scan(s: NetworkScan, *, targets: list[str], exclude: list[str], concurrency: int) -> None:
    t, e, total = validate.validate(targets, exclude, concurrency)
    s.targets, s.exclude, s.address_count, s.concurrency = t, e, total, concurrency
    s.ports = default_ports() if s.port_check else []


def purge_old(db: Session, now: datetime, keep_days: int = 180) -> int:
    """Forget scan runs older than `keep_days`."""
    res = db.execute(delete(NetworkScanRun).where(NetworkScanRun.queued_at < now - timedelta(days=keep_days),
                                                  NetworkScanRun.status.not_in(RUN_ACTIVE)))
    return res.rowcount or 0

