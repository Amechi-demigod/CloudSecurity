"""What the network device pages show: list rows, stats, the device detail and "Fix first".

Read-only composition of the stored scan data, the shared findings / vulnerabilities and the IT asset record.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..models import Device, Finding, Vulnerability, utcnow
from ..services.vuln_fixes import sev_rank, worst
from ..vulnmatch.versions import compare_versions
from . import normalize, service
from .models import (
    INFRASTRUCTURE,
    NetworkDevice,
    NetworkDeviceEvent,
    NetworkDeviceInterface,
    NetworkDevicePort,
    NetworkFdb,
    NetworkScanRun,
)

TRACKED_LABEL = {"agent": "Agent", "ad": "AD", "it_asset": "IT asset", "sensor": "Runtime sensor", "none": "Not registered"}
TYPE_LABEL = {"switch": "Switch", "router": "Router", "firewall": "Firewall", "access_point": "Access point",
              "printer": "Printer", "ups": "UPS", "phone": "Phone", "camera": "Camera", "server": "Server",
              "workstation": "Workstation", "unknown": "Unknown"}
NEW_DAYS = 7

# Vendor security advisory pages (where a firmware fix is announced).
ADVISORY = {
    "Cisco": ("Cisco Security Advisories", "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"),
    "Fortinet": ("Fortinet PSIRT advisories", "https://www.fortiguard.com/psirt"),
    "Palo Alto Networks": ("Palo Alto Networks security advisories", "https://security.paloaltonetworks.com/"),
    "Juniper": ("Juniper security advisories", "https://supportportal.juniper.net/s/global-search/%40uri#t=Security%20Advisories"),
    "Aruba": ("Aruba security bulletins", "https://www.arubanetworks.com/support-services/security-bulletins/"),
    "HPE": ("HPE security bulletins", "https://support.hpe.com/connect/s/securitybulletinlibrary"),
    "MikroTik": ("MikroTik RouterOS changelogs", "https://mikrotik.com/download/changelogs"),
    "Ubiquiti": ("Ubiquiti security advisories", "https://community.ui.com/releases"),
}

# Interim workarounds that the vendor itself published for a CVE. Deliberately tiny: a CVE without an entry shows
# no workaround rather than an invented one.
WORKAROUNDS: dict[str, dict[str, str]] = {
    "CVE-2023-20198": {"text": "Disable the HTTP and HTTPS server features on internet-facing devices: no ip http server and no ip http secure-server (then copy running-config to startup-config).",
                       "source": "Cisco Security Advisory cisco-sa-iosxe-webui-privesc-j22SaA4z",
                       "url": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z"},
    "CVE-2022-42475": {"text": "Disable SSL-VPN (config vpn ssl settings / unset the listening interface) until the firmware is upgraded.",
                       "source": "Fortinet PSIRT FG-IR-22-398", "url": "https://www.fortiguard.com/psirt/FG-IR-22-398"},
    "CVE-2024-21762": {"text": "Disable SSL-VPN until the firmware is upgraded (disabling the webmode is not a valid workaround).",
                       "source": "Fortinet PSIRT FG-IR-24-015", "url": "https://www.fortiguard.com/psirt/FG-IR-24-015"},
}


def _vulns(db: Session, ids: list[str], status: str = "open") -> dict[str, list[Vulnerability]]:
    out: dict[str, list[Vulnerability]] = defaultdict(list)
    if not ids:
        return out
    for v in db.scalars(select(Vulnerability).where(Vulnerability.network_device_id.in_(ids), Vulnerability.status == status)):
        out[v.network_device_id].append(v)
    return out


def _findings(db: Session, asset_ids: list[str], status: str = "open") -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = defaultdict(list)
    if not asset_ids:
        return out
    for f in db.scalars(select(Finding).where(Finding.asset_id.in_(asset_ids), Finding.source == "network",
                                              Finding.status == status)):
        out[f.asset_id].append(f)
    return out


def rows(db: Session, devices: list[NetworkDevice]) -> list[dict[str, Any]]:
    """List rows with open ports, issue chips and tracking."""
    ids = [d.id for d in devices]
    ports: dict[str, list[NetworkDevicePort]] = defaultdict(list)
    if ids:
        for p in db.scalars(select(NetworkDevicePort).where(NetworkDevicePort.device_id.in_(ids)).order_by(NetworkDevicePort.port)):
            ports[p.device_id].append(p)
    vulns = _vulns(db, ids)
    finds = _findings(db, [d.asset_id for d in devices if d.asset_id])
    now = utcnow()
    out = []
    for d in devices:
        vs, fs = vulns.get(d.id, []), finds.get(d.asset_id or "", [])
        t = service.tracked_of(d)
        out.append({
            "id": d.id, "name": service.display_name(d), "ip": d.ip, "mac": d.mac, "mac_vendor": d.mac_vendor,
            "hostname": d.hostname, "device_type": d.device_type, "type_label": TYPE_LABEL.get(d.device_type, d.device_type),
            "vendor": d.vendor, "model": d.model, "firmware": d.firmware, "snmp_version": d.snmp_version,
            "identified_by": ("SNMP" + d.snmp_version) if d.snmp_version else "/".join(a.upper() for a in d.alive_via) or "scan",
            "subnet": d.subnet, "open_ports": [{"port": p.port, "proto": p.proto, "service": p.service} for p in ports.get(d.id, [])],
            "vulns": {"open": len(vs), "kev": sum(1 for v in vs if v.kev), "max_severity": worst(v.severity for v in vs) if vs else None},
            "findings": [{"id": f.id, "rule_id": f.rule_id, "severity": f.severity, "title": f.title} for f in sorted(fs, key=lambda f: sev_rank(f.severity))],
            "tracked": t, "tracked_label": TRACKED_LABEL[t], "it_asset_id": d.it_asset_id, "device_id": d.device_id,
            "first_seen": service.z(d.first_seen), "last_seen": service.z(d.last_seen),
            "new_this_week": now - d.first_seen <= timedelta(days=NEW_DAYS),
        })
    return out


def filtered(db: Session, *, q: str | None = None, type_: str | None = None, status: str | None = None,
             subnet: str | None = None):
    stmt = select(NetworkDevice)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(NetworkDevice.ip).like(like), func.lower(NetworkDevice.sys_name).like(like),
                              func.lower(NetworkDevice.hostname).like(like), func.lower(NetworkDevice.mac).like(like),
                              func.lower(NetworkDevice.vendor).like(like), func.lower(NetworkDevice.model).like(like),
                              func.lower(NetworkDevice.firmware).like(like)))
    if type_ == "infrastructure":
        stmt = stmt.where(NetworkDevice.device_type.in_(INFRASTRUCTURE))
    elif type_:
        stmt = stmt.where(NetworkDevice.device_type == type_)
    if subnet:
        stmt = stmt.where(NetworkDevice.subnet == subnet)
    if status == "not_in_it_assets":
        stmt = stmt.where(NetworkDevice.it_asset_id.is_(None))
    elif status == "has_vulns":
        stmt = stmt.where(NetworkDevice.id.in_(select(Vulnerability.network_device_id).where(
            Vulnerability.network_device_id.is_not(None), Vulnerability.status == "open")))
    elif status == "has_findings":
        stmt = stmt.where(NetworkDevice.asset_id.in_(select(Finding.asset_id).where(
            Finding.source == "network", Finding.status == "open")))
    elif status == "new_this_week":
        stmt = stmt.where(NetworkDevice.first_seen >= utcnow() - timedelta(days=NEW_DAYS))
    return stmt


def stats(db: Session) -> dict[str, Any]:
    devs = list(db.scalars(select(NetworkDevice)))
    vs = [v for v in db.scalars(select(Vulnerability).where(Vulnerability.network_device_id.is_not(None),
                                                            Vulnerability.status == "open"))]
    last = db.scalar(select(NetworkScanRun).where(NetworkScanRun.status.in_(("succeeded", "failed")), NetworkScanRun.trigger != "test")
                     .order_by(NetworkScanRun.queued_at.desc()).limit(1))
    snmp = sum(1 for d in devs if d.snmp_version)
    return {
        "devices": len(devs), "with_snmp": snmp, "ping_arp_only": len(devs) - snmp,
        "infrastructure": sum(1 for d in devs if d.device_type in INFRASTRUCTURE),
        "not_in_it_assets": sum(1 for d in devs if d.it_asset_id is None),
        "with_vulns": len({v.network_device_id for v in vs}), "kev": len({v.cve_id for v in vs if v.kev}),
        "vulns": len(vs),
        "last_scan": service.run_out(last) if last is not None else None,
        "subnets": sorted({d.subnet for d in devs if d.subnet}),
    }


# ----------------------------------------------------------------------------- fixes
def fixes(db: Session, nd: NetworkDevice) -> list[dict[str, Any]]:
    """"Fix first": the open CVEs of a device grouped by the firmware upgrade that closes them. One entry per target
    firmware (the highest fixed version among the group), KEV first; CVEs without a named fixed version are grouped
    separately as "no fixed firmware named yet"."""
    vs = _vulns(db, [nd.id]).get(nd.id, [])
    groups: dict[str | None, list[Vulnerability]] = defaultdict(list)
    for v in vs:
        groups[v.fixed_version or None].append(v)
    # A CVE fixed in 17.3.8 is also closed by 17.9.4: merge groups into the highest fixed version they share.
    targets = [k for k in groups if k]
    top = max(targets, key=_VKey) if targets else None
    merged: dict[str | None, list[Vulnerability]] = defaultdict(list)
    for k, group in groups.items():
        merged[top if k else None].extend(group)
    adv = ADVISORY.get(nd.vendor)
    out = []
    for target, group in merged.items():
        group = sorted(group, key=lambda v: (not v.kev, sev_rank(v.severity), -v.cvss))
        wk = next((WORKAROUNDS[v.cve_id] for v in group if v.cve_id in WORKAROUNDS and v.status == "open"), None)
        out.append({
            "title": f"Upgrade {nd.vendor} {nd.family or 'firmware'} {nd.firmware} to {target} or later" if target
            else "No fixed firmware is named in the vulnerability data yet",
            "current": nd.firmware, "target": target, "cve_count": len(group), "kev_count": sum(1 for v in group if v.kev),
            "max_severity": worst(v.severity for v in group),
            "cves": [{"cve_id": v.cve_id, "severity": v.severity, "cvss": v.cvss, "kev": bool(v.kev), "fixed_version": v.fixed_version,
                      "title": v.title[:160]} for v in group],
            "advisory": {"label": adv[0], "url": adv[1]} if adv else None,
            "workaround": ({"text": wk["text"], "source": wk["source"], "url": wk["url"]} if wk else None),
            "steps": (["Back up the device configuration.", f"Download {nd.vendor} firmware {target} (or the vendor's recommended release) from the vendor support site.",
                       "Schedule a maintenance window and upgrade, then re-scan the device to confirm the CVEs close."] if target else
                      ["Follow the vendor advisory for each CVE; no fixed firmware version is listed yet."]),
        })
    out.sort(key=lambda f: (-f["kev_count"], sev_rank(f["max_severity"]), -f["cve_count"]))
    return out


class _VKey:
    """Orders version strings with the vulnerability engine's comparison."""

    def __init__(self, v: str):
        self.v = v

    def __lt__(self, other: _VKey) -> bool:
        return compare_versions(self.v, other.v) < 0


# ----------------------------------------------------------------------------- detail
def connected(db: Session, nd: NetworkDevice) -> dict[str, Any]:
    """Devices behind a switch: its forwarding table, split into known and unmanaged."""
    fdb = list(db.scalars(select(NetworkFdb).where(NetworkFdb.device_id == nd.id).order_by(NetworkFdb.port_name)))
    if not fdb:
        return {"total": 0, "unmanaged": 0, "rows": []}
    macs = {f.mac for f in fdb}
    known_nd = {d.mac: d for d in db.scalars(select(NetworkDevice).where(NetworkDevice.mac.in_(macs)))}
    maps = service.endpoint_maps(db)
    known = service.known_macs(db, maps[0])
    per_port: dict[str, int] = defaultdict(int)
    for f in fdb:
        per_port[f.port_name] += 1
    out = []
    for f in fdb:
        uplink = per_port[f.port_name] > service.UPLINK_PORT_MACS
        d = known_nd.get(f.mac)
        out.append({"mac": f.mac, "vendor": normalize.mac_vendor(f.mac), "port": f.port_name, "vlan": f.vlan,
                    "first_seen": service.z(f.first_seen), "uplink": uplink,
                    "device": ({"id": d.id, "name": service.display_name(d), "ip": d.ip} if d else None),
                    "endpoint": f.mac in maps[0], "unmanaged": (f.mac not in known) and not uplink})
    out.sort(key=lambda r: (not r["unmanaged"], r["port"], r["mac"]))
    access = [r for r in out if not r["uplink"]]
    return {"total": len(access), "unmanaged": sum(1 for r in out if r["unmanaged"]), "rows": out[:1000]}


def detail(db: Session, nd: NetworkDevice) -> dict[str, Any]:
    from ..asset_lifecycle.models import ItAsset

    row = rows(db, [nd])[0]
    ifs = list(db.scalars(select(NetworkDeviceInterface).where(NetworkDeviceInterface.device_id == nd.id).order_by(NetworkDeviceInterface.if_index)))
    vs = sorted(_vulns(db, [nd.id]).get(nd.id, []), key=lambda v: (not v.kev, sev_rank(v.severity), -v.cvss))
    finds = _findings(db, [nd.asset_id] if nd.asset_id else []).get(nd.asset_id or "", [])
    events = list(db.scalars(select(NetworkDeviceEvent).where(NetworkDeviceEvent.device_id == nd.id).order_by(NetworkDeviceEvent.at.desc()).limit(100)))
    asset = db.get(ItAsset, nd.it_asset_id) if nd.it_asset_id else None
    last_run = db.get(NetworkScanRun, nd.last_run_id) if nd.last_run_id else None
    eos = normalize.end_of_support(nd.family, nd.firmware) if nd.family and nd.firmware else None
    conn = connected(db, nd) if nd.device_type == "switch" or db.scalar(select(NetworkFdb.id).where(NetworkFdb.device_id == nd.id).limit(1)) else {"total": 0, "unmanaged": 0, "rows": []}
    endpoint = db.get(Device, nd.device_id) if nd.device_id else None
    return {
        **row, "sys_descr": nd.sys_descr, "sys_object_id": nd.sys_object_id, "sys_location": nd.sys_location,
        "sys_contact": nd.sys_contact, "uptime_s": nd.uptime_s, "serial": nd.serial, "family": nd.family,
        "default_community": nd.default_community or None, "alive_via": nd.alive_via,
        "cpe": {"product": nd.cpe_product, "version": nd.cpe_version, "update": nd.cpe_update} if nd.cpe_product else None,
        "interfaces": [{"index": i.if_index, "name": i.name, "descr": i.descr, "mac": i.mac, "oper_up": i.oper_up, "speed_mbps": i.speed_mbps} for i in ifs],
        "interfaces_up": sum(1 for i in ifs if i.oper_up), "interfaces_down": sum(1 for i in ifs if not i.oper_up),
        "vulnerabilities": [{"id": v.id, "cve_id": v.cve_id, "severity": v.severity, "cvss": v.cvss, "kev": bool(v.kev), "epss": v.epss,
                             "package": v.package, "version": v.version, "fixed_version": v.fixed_version, "title": v.title[:255],
                             "risk_score": v.risk_score, "first_seen": service.z(v.first_seen)} for v in vs],
        "fixes": fixes(db, nd),
        "vuln_status": _vuln_status(db, nd),
        "finding_list": [{"id": f.id, "rule_id": f.rule_id, "severity": f.severity, "title": f.title, "first_seen": service.z(f.first_seen),
                          "description": f.description[:300]} for f in sorted(finds, key=lambda f: sev_rank(f.severity))],
        "connected": conn,
        "events": [{"at": service.z(e.at), "kind": e.kind, "detail": e.detail} for e in events],
        "it_asset": ({"id": asset.id, "asset_tag": asset.asset_tag, "assignee_name": asset.assignee_name,
                      "assignee_email": asset.assignee_email, "location": asset.location, "status": asset.status,
                      "warranty_end": asset.warranty_end.isoformat() if asset.warranty_end else None,
                      "supplier": asset.supplier, "notes": asset.notes} if asset else None),
        "end_of_support": eos,
        "endpoint": {"id": endpoint.id, "hostname": endpoint.hostname} if endpoint is not None else None,
        "last_run": service.run_out(last_run) if last_run is not None else None,
        "collector_id": last_run.collector_id if last_run is not None else None,
    }


def _vuln_status(db: Session, nd: NetworkDevice) -> dict[str, Any]:
    from ..models import VulnMatchState

    st = db.scalar(select(VulnMatchState).where(VulnMatchState.target_type == service.NETWORK_TARGET, VulnMatchState.target_id == nd.id))
    if not nd.cpe_product:
        return {"checked": False, "reason": "This device's firmware could not be identified well enough to look up CVEs "
                                              "(needs SNMP and a supported vendor)."}
    return {"checked": bool(st and st.matched_at), "at": service.z(st.matched_at) if st else None, "pending": bool(st and st.requested_at),
            "error": st.error if st else None, "reason": None}


def now() -> datetime:
    return utcnow()
