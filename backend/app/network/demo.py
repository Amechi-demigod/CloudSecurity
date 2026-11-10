"""Simulated network discovery data, so the console pages demo without a collector.

`seed(db)` is called when the simulated environment is seeded (SIMULATION_MODE) and inserts a scan, a finished run,
about thirty devices (with ports, interfaces, a switch forwarding table, history, findings produced by the real
rules and a few CVE rows) for the session's organisation. `python -m app.network.demo` seeds the same data plus a
simulated, online collector into the database `DATABASE_URL` points at (development only). Nothing here talks to a
network.
"""
from __future__ import annotations

import secrets
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..directory import collectors as coll
from ..directory.models import CollectorCommand, DirectoryCollector
from ..models import Vulnerability, VulnMatchState, new_id, utcnow
from . import normalize, service
from .models import (
    NetworkDevice,
    NetworkDeviceEvent,
    NetworkDeviceInterface,
    NetworkDevicePort,
    NetworkFdb,
    NetworkScan,
    NetworkScanRun,
)

XE = ("Cisco IOS Software [Amsterdam], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.3.4, RELEASE SOFTWARE (fc3)")
IOS = "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc2)"
OIDS = {"cisco": "1.3.6.1.4.1.9.1.2504", "forti": "1.3.6.1.4.1.12356.101.1.1000", "pan": "1.3.6.1.4.1.25461.2.3.34",
        "aruba": "1.3.6.1.4.1.14823.1.1.30", "hp": "1.3.6.1.4.1.11.2.3.9.1", "apc": "1.3.6.1.4.1.318.1.3.2.5",
        "mikrotik": "1.3.6.1.4.1.14988.1", "ubnt": "1.3.6.1.4.1.41112.1.6", "brother": "1.3.6.1.4.1.2435.2.3.9.1"}

# (ip, mac, name, descr, oid, snmp version, alive_via, ports, default community)
ROWS = [
    ("10.10.1.1", "00:1e:13:aa:bb:01", "hq-core-sw01", XE, "cisco", "v3", ["icmp", "arp"], [22, 23, 80, 443], None),
    ("10.10.1.2", "00:1e:13:aa:bb:02", "hq-dist-sw02", IOS, "cisco", "v2c", ["icmp", "arp"], [22, 80], "public"),
    ("10.10.1.3", "00:1e:13:aa:bb:03", "hq-access-sw03", XE, "cisco", "v3", ["icmp", "arp"], [22, 443], None),
    ("10.10.1.4", "00:1e:13:aa:bb:04", "hq-access-sw04", XE, "cisco", "v3", ["icmp", "arp"], [22, 443], "public"),
    ("10.10.1.254", "70:4c:a5:00:10:01", "hq-fw01", "FortiGate-100F v7.2.4,build1396,230206 (GA)", "forti", "v3",
     ["icmp", "arp"], [22, 443, 8443], None),
    ("10.30.0.1", "08:5b:0e:00:30:01", "branch-fw02", "FortiGate-60F v6.2.9,build1195,220407 (GA)", "forti", "v2c",
     ["icmp", "arp"], [22, 80, 443], "private"),
    ("10.10.1.253", "b4:0c:25:00:10:02", "hq-pa01", "Palo Alto Networks PA-3220 series firewall", "pan", "v3",
     ["icmp", "arp"], [22, 443], None),
    ("10.10.2.11", "20:4c:03:00:02:11", "hq-ap-lobby", "ArubaOS (MODEL: Aruba7210), Version 8.10.0.2 (82431)", "aruba",
     "v3", ["icmp", "arp"], [22, 443], None),
    ("10.10.2.12", "20:4c:03:00:02:12", "hq-ap-floor2", "ArubaOS (MODEL: Aruba7210), Version 8.10.0.2 (82431)", "aruba",
     "v3", ["icmp", "arp"], [22, 443], None),
    ("10.30.0.10", "24:5a:4c:00:30:10", "br-ap-01", "UAP-AC-Pro 6.2.14.13310", "ubnt", "v2c", ["icmp", "arp"], [22],
     None),
    ("10.30.0.2", "4c:5e:0c:00:30:02", "br-rtr01", "RouterOS CCR1036-8G-2S+ 6.49.7", "mikrotik", "v2c", ["icmp", "arp"],
     [22, 80, 8080], "public"),
    ("10.10.3.21", "3c:d9:2b:00:03:21", "prn-hq-fl1", "HP LaserJet Pro M404dn", "hp", "v2c", ["icmp", "arp", "tcp"],
     [80, 443, 9100, 445], "public"),
    ("10.10.3.22", "3c:d9:2b:00:03:22", "prn-hq-fl2", "HP LaserJet Pro M404dn", "hp", "v2c", ["icmp", "arp", "tcp"],
     [80, 9100], "public"),
    ("10.10.3.23", "00:1b:a9:00:03:23", "prn-hq-fin", "Brother NC-8300h, Firmware Ver.1.17  (23.04.20),MID 84UB52",
     "brother", "v2c", ["icmp", "arp", "tcp"], [80, 9100], None),
    ("10.30.0.20", "00:1e:8f:00:30:20", "", "", "", "", ["icmp", "arp", "tcp"], [80, 9100], None),
    ("10.10.4.5", "00:c0:b7:00:04:05", "ups-server-room",
     "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.9.6 PN:apc_hw05_aos_696.bin AF1:v6.9.6 AN1:apc_hw05_sumx_696.bin "
     "MN:AP9630 HR:05 SN: 5A1234E12345 MD:01/01/2019)", "apc", "v2c", ["icmp", "arp"], [80, 443, 23], "public"),
    ("10.10.5.31", "ac:cc:8e:00:05:31", "", "", "", "", ["icmp", "arp"], [80, 554], None),
    ("10.10.5.32", "ac:cc:8e:00:05:32", "", "", "", "", ["icmp", "arp"], [80, 554], None),
    ("10.10.6.40", "00:50:56:00:06:40", "", "", "", "", ["icmp", "arp", "tcp"], [3389, 445], None),
    ("10.10.6.41", "00:50:56:00:06:41", "", "", "", "", ["icmp", "arp", "tcp"], [445, 3389, 80], None),
    ("10.10.7.50", "ac:de:48:00:07:50", "", "", "", "", ["icmp", "arp"], [], None),
    ("10.10.7.51", "00:03:93:00:07:51", "", "", "", "", ["arp"], [], None),
    ("10.10.7.52", "dc:a6:32:00:07:52", "", "", "", "", ["icmp", "arp"], [22], None),
    ("10.10.8.60", "f8:bc:12:00:08:60", "", "", "", "", ["icmp", "arp", "tcp"], [445, 3389], None),
    ("10.10.8.61", "00:14:22:00:08:61", "", "", "", "", ["icmp"], [], None),
    ("10.10.9.70", "9a:11:22:33:44:70", "", "", "", "", ["icmp", "arp"], [8080], None),
]
HOSTNAMES = {"10.10.6.40": "fileserver01", "10.10.6.41": "intranet-app", "10.10.8.60": "ws-finance-07", "10.10.8.61": "ws-hr-02",
             "10.30.0.20": "prn-branch", "10.10.5.31": "cam-entrance", "10.10.5.32": "cam-carpark"}
SERVICES = {22: "ssh", 23: "telnet", 80: "http", 443: "https", 445: "microsoft-ds", 3389: "ms-wbt-server", 8080: "http-alt",
            8443: "https-alt", 9100: "jetdirect", 554: "rtsp"}
# Open CVEs: (device ip, cve, severity, cvss, kev, fixed version, title)
CVES = [
    ("10.10.1.1", "CVE-2023-20198", "critical", 10.0, True, "17.3.8a", "Cisco IOS XE Software Web UI privilege escalation vulnerability."),
    ("10.10.1.1", "CVE-2023-20273", "high", 7.2, True, "17.3.8a", "Cisco IOS XE Software Web UI command injection vulnerability."),
    ("10.10.1.3", "CVE-2023-20198", "critical", 10.0, True, "17.3.8a", "Cisco IOS XE Software Web UI privilege escalation vulnerability."),
    ("10.10.1.4", "CVE-2023-20198", "critical", 10.0, True, "17.3.8a", "Cisco IOS XE Software Web UI privilege escalation vulnerability."),
    ("10.10.1.254", "CVE-2024-21762", "critical", 9.6, True, "7.2.7", "Fortinet FortiOS out-of-bound write in sslvpnd."),
    ("10.10.1.254", "CVE-2023-27997", "critical", 9.8, False, "7.2.5", "Fortinet FortiOS SSL-VPN heap-based buffer overflow."),
    ("10.30.0.1", "CVE-2022-42475", "critical", 9.3, True, "6.2.13", "Fortinet FortiOS sslvpnd heap-based buffer overflow."),
]


def _mac_int(mac: str) -> int:
    return int(mac.replace(":", ""), 16)


def seed(db: Session, collector: DirectoryCollector | None = None, now=None) -> bool:
    """Insert the simulated network estate unless the organisation already has network devices."""
    if db.scalar(select(func.count()).select_from(NetworkDevice)):
        return False
    now = now or utcnow()
    scan = NetworkScan(name="HQ and branch networks", enabled=True, collector_id=collector.id if collector else None,
                       targets=["10.10.1.0/24", "10.10.2.0/23", "10.10.4.0/22", "10.30.0.0/24"],
                       exclude=["10.10.1.40", "10.10.4.200-10.10.4.220"],
                       target_notes={"10.10.1.0/24": "AD Site: HQ", "10.30.0.0/24": "DHCP: BR-DC01"},
                       port_check=True, ports=service.default_ports(), concurrency=20, credential_ids=[], schedule="daily",
                       schedule_time="02:00", created_by="simulation", updated_by="simulation", created_at=now - timedelta(days=30),
                       updated_at=now - timedelta(days=30), address_count=1530)
    db.add(scan)
    db.flush()
    run = NetworkScanRun(scan_id=scan.id, name=scan.name, trigger="scheduled", status="succeeded", collector_id=scan.collector_id,
                         params=service.stored_params("sim", targets=scan.targets, exclude=scan.exclude, port_check=True,
                                                      concurrency=20, creds=[]),
                         requested_by="system", queued_at=now - timedelta(hours=9), started_at=now - timedelta(hours=9),
                         finished_at=now - timedelta(hours=9) + timedelta(minutes=14), devices_seen=len(ROWS),
                         summary={"addresses": 1530, "alive": len(ROWS), "snmp": 13, "duration_s": 842, "errors": []})
    db.add(run)
    db.flush()
    run.params["scan_id"] = run.id
    scan.last_run_id, scan.last_run_at, scan.last_status = run.id, run.finished_at, "succeeded"
    scan.last_summary = {**run.summary, "devices": len(ROWS)}
    devices: dict[str, NetworkDevice] = {}
    for i, (ip, mac, name, descr, oid, ver, alive, ports, community) in enumerate(ROWS):
        n = normalize.normalize(descr, OIDS.get(oid, ""), mac, ports)
        age = timedelta(days=60 - 2 * i) if i < 20 else timedelta(days=2)
        nd = NetworkDevice(ip=ip, mac=mac, mac_vendor=normalize.mac_vendor(mac), hostname=HOSTNAMES.get(ip, name), sys_name=name,
                           sys_descr=descr, sys_object_id=OIDS.get(oid, "") if descr else "", sys_location="HQ rack 3" if name.startswith("hq-") else
                           ("Server room" if "ups" in name else ""), sys_contact="netops@example.com" if descr else "",
                           uptime_s=86400 * (20 + i) if descr else None, snmp_version=ver, snmp_credential_id="",
                           default_community=community or "", alive_via=alive, device_type=n.device_type,
                           vendor=n.vendor or normalize.mac_vendor(mac), model=n.model, firmware=n.firmware, serial=n.serial,
                           family=n.family, cpe_product=n.cpe_product, cpe_version=n.cpe_version, cpe_update=n.cpe_update,
                           subnet=next((t for t in scan.targets if service.validate.subnet_of(ip, [t])), ""),
                           first_seen=now - age, last_seen=run.finished_at, last_run_id=run.id)
        db.add(nd)
        db.flush()
        devices[ip] = nd
        service.ensure_asset(db, nd, now)
        for p in ports:
            db.add(NetworkDevicePort(device_id=nd.id, port=p, proto="tcp", service=SERVICES.get(p, ""), banner="", first_seen=nd.first_seen,
                                     last_seen=now))
        db.add(NetworkDeviceEvent(device_id=nd.id, at=nd.first_seen, kind="first_seen", detail=f"First seen at {ip}", run_id=run.id))
        if nd.cpe_product:
            db.add(VulnMatchState(target_type=service.NETWORK_TARGET, target_id=nd.id, inventory_hash="sim", matched_at=now,
                                  checked=[], not_checked=[], os_info={}))
    core = devices["10.10.1.1"]
    db.add(NetworkDeviceEvent(device_id=core.id, at=now - timedelta(days=12), kind="firmware_changed",
                              detail="Firmware changed from 17.3.2 to 17.3.4", run_id=run.id))
    db.add(NetworkDeviceEvent(device_id=core.id, at=now - timedelta(days=5), kind="port_opened", detail="Port 23/tcp opened", run_id=run.id))
    for k, (name, up, speed) in enumerate([("Gi1/0/1", True, 1000), ("Gi1/0/2", True, 1000), ("Gi1/0/3", False, 1000), ("Gi1/0/4", True, 100),
                                           ("Te1/1/1", True, 10000), ("Te1/1/2", False, 10000)], start=1):
        db.add(NetworkDeviceInterface(device_id=core.id, if_index=k, name=name, descr="uplink to hq-fw01" if k == 5 else "",
                                      mac="00:1e:13:aa:bb:%02x" % (0x10 + k), oper_up=up, speed_mbps=speed))
    sw3 = devices["10.10.1.3"]
    known = [(d.mac, f"Gi1/0/{5 + j}") for j, d in enumerate(d for d in devices.values() if d.device_type in ("printer", "camera"))]
    fdb = [*known, ("de:ad:be:ef:12:34", "Gi1/0/19"), ("b8:27:eb:11:22:33", "Gi1/0/21"), ("f4:f2:6d:aa:00:01", "Gi1/0/22")]
    for k, (mac, port) in enumerate(fdb):
        db.add(NetworkFdb(device_id=sw3.id, mac=mac, port_name=port, vlan=10 + (k % 3) * 10,
                          first_seen=now - timedelta(days=60 if k < len(known) else 3), last_seen=now))
    sw3.first_seen = now - timedelta(days=60)
    db.flush()
    # Findings from the real rules; CVE rows as the matcher would write them.
    maps: tuple[dict, dict, dict] = ({}, {}, {})
    known_macs = service.known_macs(db, maps[0])
    for nd in devices.values():
        service.evaluate_device(db, nd, now, known_macs)
    for ip, cve, sev, cvss, kev, fixed, title in CVES:
        nd = devices[ip]
        db.add(Vulnerability(id=new_id(), network_device_id=nd.id, cve_id=cve, package=f"{nd.vendor} {nd.family}", version=nd.firmware,
                             fixed_version=fixed, title=title, cvss=cvss, severity=sev, exploit_available=kev, kev=kev, epss=0.5 if kev else 0.1,
                             risk_score=cvss * (1.0 if kev else 0.8), priority="critical" if kev else "high", status="open",
                             source="simulated", first_seen=now - timedelta(days=9), last_seen=now, match_key=nd.cpe_product,
                             evidence={"cpe": nd.cpe_product, "firmware": nd.firmware, "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                                       "published": "2023-10-16", "simulated": True}))
    # IT assets for part of the estate (infrastructure first); the rest stays "Not registered".
    from ..asset_lifecycle.models import ItAsset

    for ip in ("10.10.1.1", "10.10.1.2", "10.10.1.254", "10.10.1.253", "10.30.0.1", "10.10.2.11", "10.10.3.21", "10.10.4.5"):
        nd = devices[ip]
        a = ItAsset(asset_tag=f"NET-{nd.sys_name.upper()}", serial_number=nd.serial, asset_type="printer" if nd.device_type == "printer" else "network",
                    manufacturer=nd.vendor, model=nd.model, status="assigned", source="network", assignee_name="IT Operations",
                    location=nd.sys_location, created_by="simulation", notes="Simulated")
        db.add(a)
        db.flush()
        nd.it_asset_id = a.id
    db.commit()
    return True


def seed_collector(db: Session) -> DirectoryCollector:
    """An online, simulated dedicated collector (development only) with a subnet suggestion result."""
    now = utcnow()
    c = DirectoryCollector(name="HQ-COLLECTOR01", secret_hash=coll.hash_secret(secrets.token_hex(16)), machine_id="sim" * 21 + "x",
                           status="active", hostname="HQ-COLLECTOR01", dns_hostname="hq-collector01.corp.example.com", domain="corp.example.com",
                           os_name="Windows Server 2022 Standard", os_version="10.0.20348", architecture="amd64", version="1.5.0",
                           run_as="CORP\\HQ-COLLECTOR01$", run_as_kind="computer_account", enrolled_at=now - timedelta(days=30),
                           last_seen_at=now, last_ip="10.10.1.30", features="directory_sync,network_discovery")
    db.add(c)
    c2 = DirectoryCollector(name="BR-COLLECTOR02", secret_hash=coll.hash_secret(secrets.token_hex(16)), machine_id="sim" * 21 + "y",
                            status="active", hostname="BR-COLLECTOR02", dns_hostname="br-collector02.corp.example.com", domain="corp.example.com",
                            os_name="Windows Server 2019 Standard", os_version="10.0.17763", architecture="amd64", version="1.5.0",
                            run_as="CORP\\BR-COLLECTOR02$", run_as_kind="computer_account", enrolled_at=now - timedelta(days=20),
                            last_seen_at=now, last_ip="10.30.0.30", features="directory_sync,network_discovery")
    db.add(c2)
    db.flush()
    data = {"ad_sites": [{"site": "HQ", "subnet": "10.10.1.0/24", "description": "HQ users"},
                         {"site": "HQ", "subnet": "10.10.2.0/24", "description": "HQ Wi-Fi"},
                         {"site": "Branch-Lagos", "subnet": "10.30.0.0/24", "description": "Lagos branch"}],
            "dhcp_scopes": [{"server": "HQ-DC01", "scope": "10.10.10.0", "mask": "255.255.254.0", "name": "Staff Wi-Fi",
                             "start": "10.10.10.10", "end": "10.10.11.250"},
                            {"server": "HQ-DC01", "scope": "10.10.20.0", "mask": "255.255.255.0", "name": "Guest", "start": "10.10.20.10",
                             "end": "10.10.20.250"}],
            "errors": []}
    db.add(CollectorCommand(collector_id=c.id, type=coll.NETWORK_SUBNETS, params={}, nonce=secrets.token_hex(16), status="succeeded",
                            reason="simulated", requested_by_email="simulation", created_at=now, expires_at=now + timedelta(minutes=30),
                            completed_at=now, result_data=data))
    db.flush()
    return c


def main() -> None:  # pragma: no cover - development helper
    import sys

    from .. import config
    from .. import db as dbmod
    from ..tenancy import DEFAULT_ORG_ID

    if config.settings.is_production:
        sys.exit("refusing to seed simulated data in production")
    with dbmod.get_session(DEFAULT_ORG_ID) as db:
        c = seed_collector(db)
        scan_collector = c
        print("seeded" if seed(db, scan_collector) else "network devices already exist")
        db.commit()


if __name__ == "__main__":  # pragma: no cover
    main()
