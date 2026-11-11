"""Network discovery: target validation, vendor normalisation, SNMP secret handling, scan queueing on dedicated
collectors, batch ingest (idempotent, merged by MAC), findings rules, CVE matching through the existing engine,
the scheduler, RBAC, tenancy, CSV / PDF. The tests play the collector; nothing touches a network."""
from __future__ import annotations

import gzip
import json
import logging
from datetime import date, datetime, timedelta

import pytest
from sqlalchemy import select

from app import db
from app.directory import collectors as coll
from app.directory.models import CollectorCommand, DirectoryCollector
from app.models import AuditLog, Finding, Vulnerability, VulnMatchState, utcnow
from app.network import normalize, rules, validate
from app.network.models import NetworkScan, NetworkScanRun, NetworkSnmpCredential
from app.vulnmatch import feeds, worker
from tests.conftest import make_user
from tests.test_directory_collectors import admin, enroll_collector  # noqa: F401
from tests.test_tenancy import ACME_ADMIN, ACME_PASSWORD, create_org, org_client
from tests.vuln_fakes import FakeFeeds, cve, cvss31, m, node

SECRETS = ("S3cretAuthPass", "S3cretPrivPass", "c0mmunity-secret")
V3 = {"name": "Monitoring v3", "version": "v3", "username": "snmpmon", "level": "authPriv", "auth_proto": "SHA256",
      "auth_password": SECRETS[0], "priv_proto": "AES128", "priv_password": SECRETS[1]}
V2C = {"name": "Legacy v2c", "version": "v2c", "community": SECRETS[2]}
XE_DESCR = ("Cisco IOS Software [Amsterdam], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.3.4, RELEASE "
            "SOFTWARE (fc3) Technical Support: http://www.cisco.com/techsupport Copyright (c) 1986-2021 by Cisco "
            "Systems, Inc.")


# ----------------------------------------------------------------------------- validation
@pytest.mark.parametrize("targets,exclude,total", [
    (["10.10.1.0/24"], [], 256),
    (["10.30.0.10-10.30.0.50"], [], 41),
    (["10.10.1.0/24", "10.10.1.128/25"], [], 256),  # overlaps count once
    (["10.10.1.0/24"], ["10.10.1.40", "10.10.1.100-10.10.1.109"], 245),
    (["10.0.0.0/16"], [], 65536),
])
def test_valid_targets(targets, exclude, total):
    assert validate.validate(targets, exclude, 20)[2] == total


@pytest.mark.parametrize("bad,why", [
    ("10.0.0.0/15", "/16"), ("10.0.0.1-10.2.0.1", "/16"), ("0.0.0.0/8", "never scanned"), ("0.0.0.0/0", "never scanned"),
    ("127.0.0.1", "never scanned"), ("127.0.0.0/8", "never scanned"), ("169.254.1.0/24", "never scanned"),
    ("224.0.0.1", "never scanned"), ("240.0.0.0/4", "never scanned"), ("255.255.255.255", "never scanned"),
    ("10.0.0.9-10.0.0.1", "ends before"), ("fe80::1", "IPv6"), ("2001:db8::/32", "IPv6"), ("10.0.0.0/33", "valid CIDR"),
    ("not-an-ip", "valid IPv4"), ("10.0.0.256", "valid IPv4"), ("", "at least one"),
])
def test_forbidden_or_malformed_targets(bad, why):
    with pytest.raises(validate.TargetError, match=why):
        validate.validate([bad])


def test_total_cap_and_concurrency_and_empty():
    four = [f"10.{i}.0.0/16" for i in range(4)]
    assert validate.validate(four)[2] == 262_144
    with pytest.raises(validate.TargetError, match="262,144"):
        validate.validate([*four, "10.9.0.0/24"])
    # Exclusions are removed from the total.
    assert validate.validate([*four, "10.9.0.0/24"], ["10.9.0.0/24"])[2] == 262_144
    for c in (1, 10, 32, 100):
        with pytest.raises(validate.TargetError, match="concurrency"):
            validate.validate(["10.0.0.1"], None, c)
    assert validate.validate(["10.0.0.1"], None, 64)[2] == 1
    with pytest.raises(validate.TargetError, match="at least one"):
        validate.validate([])
    with pytest.raises(validate.TargetError, match="excluded"):
        validate.validate(["10.0.0.0/30"], ["10.0.0.0/24"])


# ----------------------------------------------------------------------------- normalisation fixtures
CASES = [
    # (sysDescr, sysObjectID, vendor, type, firmware, cpe product, cpe version, family)
    (XE_DESCR, "1.3.6.1.4.1.9.1.2504", "Cisco", "switch", "17.3.4", "o:cisco:ios_xe", "17.3.4", "IOS XE"),
    ("Cisco IOS XE Software, Version 17.03.04, RELEASE SOFTWARE", "1.3.6.1.4.1.9.1.1", "Cisco", "router", "17.3.4",
     "o:cisco:ios_xe", "17.3.4", "IOS XE"),
    ("Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc2)",
     "1.3.6.1.4.1.9.1.2134", "Cisco", "switch", "15.2(7)E3", "o:cisco:ios", "15.2(7)e3", "IOS"),
    ("Cisco NX-OS(tm) n9k, Software (n9k-dk9), Version 9.3(5), RELEASE SOFTWARE Copyright (c) 2002-2020",
     "1.3.6.1.4.1.9.12.3.1.3.1", "Cisco", "switch", "9.3(5)", "o:cisco:nx-os", "9.3(5)", "NX-OS"),
    ("Cisco Adaptive Security Appliance Version 9.16(2)", "1.3.6.1.4.1.9.1.1", "Cisco", "firewall", "9.16.2",
     "o:cisco:adaptive_security_appliance_software", "9.16.2", "ASA"),
    ("FortiGate-100F v7.2.4,build1396,230206 (GA)", "1.3.6.1.4.1.12356.101.1.1000", "Fortinet", "firewall", "7.2.4",
     "o:fortinet:fortios", "7.2.4", "FortiOS"),
    ("Palo Alto Networks PA-3220 series firewall", "1.3.6.1.4.1.25461.2.3.34", "Palo Alto Networks", "firewall", "", "", "",
     "PAN-OS"),
    ("Juniper Networks, Inc. ex4300-48t Ethernet Switch, kernel JUNOS 20.4R3-S3.4, Build date: 2022-02-02 11:08:34 UTC "
     "Copyright (c) 1996-2022 Juniper Networks, Inc.", "1.3.6.1.4.1.2636.1.1.1.2.114", "Juniper", "switch",
     "20.4R3-S3.4", "o:juniper:junos", "20.4", "Junos"),
    ("ArubaOS (MODEL: Aruba7210), Version 8.10.0.2 (82431)", "1.3.6.1.4.1.14823.1.1.30", "Aruba", "router", "8.10.0.2",
     "o:arubanetworks:arubaos", "8.10.0.2", "ArubaOS"),
    ("Aruba JL256A 2930F-48G-4SFP+ Switch, revision WC.16.10.0003, ROM WC.16.01.0006", "1.3.6.1.4.1.11.2.3.7.11.176",
     "Aruba", "switch", "WC.16.10.0003", "", "", "ArubaOS-Switch"),
    ("ProCurve J9145A Switch 2910al-24G, revision W.15.16.0006, ROM W.14.04 (/sw/code/build/sbm(sw))",
     "1.3.6.1.4.1.11.2.3.7.11.52", "HPE", "switch", "W.15.16.0006", "", "", "ArubaOS-Switch"),
    ("UAP-AC-Pro 6.2.14.13310", "1.3.6.1.4.1.41112.1.6", "Ubiquiti", "access_point", "6.2.14.13310", "", "", "UniFi"),
    ("EdgeOS v2.0.9 EdgeRouter X ER-X", "1.3.6.1.4.1.41112.1.5", "Ubiquiti", "router", "2.0.9", "o:ubnt:edgeos", "2.0.9",
     "EdgeOS"),
    ("RouterOS CCR1036-8G-2S+ 6.49.7", "1.3.6.1.4.1.14988.1", "MikroTik", "router", "6.49.7", "o:mikrotik:routeros",
     "6.49.7", "RouterOS"),
    ("RouterOS RB750Gr3", "1.3.6.1.4.1.14988.1", "MikroTik", "router", "", "", "", "RouterOS"),
    ("HP ETHERNET MULTI-ENVIRONMENT,ROM none,JETDIRECT,JD149,EEPROM JSI23200031,CIDATE 05/31/2022",
     "1.3.6.1.4.1.11.2.3.9.1", "HP", "printer", "JSI23200031", "", "", "HP"),
    ("HP LaserJet Pro M404dn", "1.3.6.1.4.1.11.2.3.9.1", "HP", "printer", "", "", "", "HP"),
    ("Brother NC-8300h, Firmware Ver.1.17  (23.04.20),MID 84UB52", "1.3.6.1.4.1.2435.2.3.9.1", "Brother", "printer", "1.17",
     "", "", "Brother"),
    ("Canon iR-ADV C5535i /P", "1.3.6.1.4.1.1602.4.1", "Canon", "printer", "", "", "", "Canon"),
    ("RICOH IM C3000 1.12 / RICOH Network Printer D model", "1.3.6.1.4.1.367.1.1", "Ricoh", "printer", "1.12", "", "", "Ricoh"),
    ("Xerox WorkCentre 6515DN; SW#201.230.14.2", "1.3.6.1.4.1.253.8.62.1.19.1", "Xerox", "printer", "", "", "", "Xerox"),
    ("APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.9.6 PN:apc_hw05_aos_696.bin AF1:v6.9.6 AN1:apc_hw05_sumx_696.bin "
     "MN:AP9630 HR:05 SN: 5A1234E12345 MD:01/01/2019) (Embedded PowerNet SNMP Agent SW v2.2 compatible)",
     "1.3.6.1.4.1.318.1.3.2.5", "APC", "ups", "6.9.6", "", "", "APC"),
]


@pytest.mark.parametrize("descr,oid,vendor,typ,fw,cpe,cpe_ver,family", CASES)
def test_normalise_vendors(descr, oid, vendor, typ, fw, cpe, cpe_ver, family):
    n = normalize.normalize(descr, oid)
    assert (n.vendor, n.device_type, n.firmware, n.cpe_product, n.cpe_version, n.family) == (
        vendor, typ, fw, cpe, cpe_ver, family), n


def test_normalise_details_and_fallbacks():
    assert normalize.normalize(XE_DESCR, "").model == "CAT9K"
    assert normalize.normalize("FortiGate-100F v7.2.4,build1396", "").model == "FortiGate-100F"
    assert normalize.normalize("Palo Alto Networks PA-3220 series firewall", "").model == "PA-3220"
    n = normalize.normalize("Juniper Networks, Inc. ex4300-48t Ethernet Switch, kernel JUNOS 20.4R3-S3.4, x", "")
    assert (n.model, n.cpe_update) == ("ex4300-48t", "r3-s3")
    assert normalize.normalize("Brother NC-8300h, Firmware Ver.1.17", "").model == "NC-8300h"
    ups = normalize.normalize("APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.9.6 MN:AP9630 SN: 5A1234)", "")
    assert (ups.model, ups.serial) == ("AP9630", "5A1234")
    # sysObjectID alone identifies the enterprise; unknown descriptions stay unknown (never guessed).
    assert normalize.normalize("", "1.3.6.1.4.1.12356.101.1").vendor == "Fortinet"
    unk = normalize.normalize("Some Appliance 1.0", "1.3.6.1.4.1.99999.1")
    assert (unk.vendor, unk.device_type, unk.cpe_product) == ("", "unknown", "")
    # Without SNMP: the MAC OUI names the vendor, ports hint at the type.
    assert normalize.mac_vendor("00:0c:42:aa:bb:cc") == "MikroTik"
    assert normalize.normalize("", "", "", [9100]).device_type == "printer"
    assert normalize.normalize("", "", "", [3389, 445]).device_type == "server"
    assert normalize.normalize("", "", "70:4c:a5:00:00:01", []).device_type == "firewall"
    assert normalize.normalize("", "", "", [], {"device_type": "camera", "vendor": "Axis"}).device_type == "camera"
    assert normalize.mac_clean("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff" and normalize.mac_clean("0000.0000.0000") == ""
    assert normalize.mac_clean("garbage") == ""


# Real values from Sophos firewalls (LibreNMS test captures): sysDescr is plain Linux, the rest comes from
# SFOS-FIREWALL-MIB through the collector's hints.
SFOS_DESCR = "Linux localhost 6.6.116 #1 SMP Wed Jun  3 08:00:50 CDT 2026 x86_64"


@pytest.mark.parametrize("model,fw,want_model,want_ver", [
    ("XGS2100_RL01_SFOS", "22.0.2 MR-2-Build546", "XGS2100", "22.0.2"),
    ("SG230_WP01_SFOS", "20.0.3 MR-3-Build427", "SG230", "20.0.3"),
    ("SFVH_SO01_SFOS", "18.0.1 MR-1-Build396", "SFVH", "18.0.1"),
    ("XGS2100_RL01_SFOS", "SFOS 19.5.3 MR-3-Build652", "XGS2100", "19.5.3"),
])
def test_normalise_sophos_firewall(model, fw, want_model, want_ver):
    n = normalize.normalize(SFOS_DESCR, "1.3.6.1.4.1.2604.5",
                            hints={"model": model, "firmware": fw, "serial": "X21987654321012", "device_type": "server"})
    assert (n.vendor, n.device_type, n.model, n.firmware, n.serial, n.family, n.cpe_product, n.cpe_version) == (
        "Sophos", "firewall", want_model, fw, "X21987654321012", "SFOS", "o:sophos:sfos", want_ver), n


def test_normalise_sophos_without_firmware_is_identified_but_not_matched():
    # A 1.6.0 collector does not read SFOS-FIREWALL-MIB: still a Sophos firewall, but no CPE (never guessed).
    n = normalize.normalize(SFOS_DESCR, ".1.3.6.1.4.1.2604.5", hints={"vendor": "", "device_type": "server"})
    assert (n.vendor, n.device_type, n.family, n.cpe_product) == ("Sophos", "firewall", "SFOS", "")
    # Other Sophos subtrees (not SFOS) are only named, not called firewalls.
    assert normalize.normalize("", "1.3.6.1.4.1.2604.3").vendor == "Sophos"
    assert normalize.normalize("", "1.3.6.1.4.1.2604.3").device_type == "unknown"


def test_end_of_support():
    assert normalize.end_of_support("FortiOS", "6.2.9")["date"] == "2024-03-28"
    assert normalize.end_of_support("SFOS", "19.5.3 MR-3-Build652")["date"] == "2025-04-30"
    assert normalize.end_of_support("SFOS", "17.5.9 MR-9")["source"].startswith("No later than")
    assert normalize.end_of_support("SFOS", "20.0.3 MR-3-Build427") is None
    assert normalize.end_of_support("FortiOS", "7.4.1") is None
    assert normalize.end_of_support("IOS XE", "17.3.4") is None


# ----------------------------------------------------------------------------- findings rules (pure)
class FakeDevice:
    def __init__(self, **kw):
        self.device_type, self.vendor, self.firmware, self.snmp_version = "switch", "Cisco", "17.3.4", ""
        self.default_community, self.family, self.ip, self.cpe_product = "", "IOS XE", "10.0.0.1", ""
        self.__dict__.update(kw)


def ports(*ps):
    return [{"port": p, "proto": pr, "service": "", "banner": ""} for p, pr in ps]


def test_rules_fire_and_stay_quiet():
    ev = rules.evaluate(rules.facts(FakeDevice(default_community="public", snmp_version="v3"),
                                    ports((23, "tcp"), (80, "tcp"), (443, "tcp"), (445, "tcp"))))
    assert set(ev) == {"NET-SNMP-001", "NET-SNMP-002", "NET-TELNET-001", "NET-HTTP-001", "NET-SMB-001"}
    assert ev["NET-HTTP-001"]["https_also_open"] is True
    assert rules.evaluate(rules.facts(FakeDevice(snmp_version="v3"), ports((22, "tcp"), (443, "tcp"), (161, "udp")))) == {}
    # v2c-only default community: SNMP-001 only (nothing to compare v3 against).
    assert set(rules.evaluate(rules.facts(FakeDevice(default_community="private", snmp_version="v2c"), []))) == {"NET-SNMP-001"}
    # SMB on a Windows server / workstation is expected; HTTP on a workstation is not a management page.
    assert rules.evaluate(rules.facts(FakeDevice(device_type="server"), ports((445, "tcp"), (80, "tcp")))) == {}
    assert "NET-SMB-001" in rules.evaluate(rules.facts(FakeDevice(device_type="printer"), ports((445, "tcp"))))
    eos = rules.evaluate(rules.facts(FakeDevice(vendor="Fortinet", family="FortiOS", firmware="6.2.9"), [],
                                     today=date(2026, 11, 10)))
    assert eos["NET-FW-001"]["end_of_support"] == "2024-03-28"
    assert "NET-FW-001" not in rules.evaluate(rules.facts(FakeDevice(vendor="Fortinet", family="FortiOS", firmware="6.2.9"),
                                                          [], today=date(2024, 1, 1)))
    assert "NET-FDB-001" in rules.evaluate(rules.facts(FakeDevice(), [], [{"mac": "aa:bb:cc:00:00:01", "port": "Gi1/0/3"}]))


def test_every_rule_has_complete_guidance():
    from app.engine import guidance

    assert set(rules.GUIDANCE) == set(rules.RULES)
    for rid, g in rules.GUIDANCE.items():
        for key in guidance.REQUIRED_KEYS:
            assert g[key], f"{rid}.{key}"
        lo, hi = guidance.SCORE_BANDS[rules.RULES[rid].severity]
        assert lo <= g["risk_score"] <= hi, rid
        assert all(r["url"].startswith("https://") for r in g["references"])
        assert guidance.render(rid, name="sw1", resource_group=None, region=None, account=None)["fix_cli"]
    assert not set(rules.GUIDANCE) & set(guidance.GUIDANCE)  # kept out of the posture rule check


# ----------------------------------------------------------------------------- API helpers
def make_collector(admin, host="COLL01"):
    c, cid = enroll_collector(admin, host, machine=host[-1] * 64, features="directory_sync,network_discovery")
    return c, cid


def create_cred(admin, body=V3):
    r = admin.post("/api/network/credentials", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def scan_body(cid, creds=(), **over):
    return {"name": "HQ", "collector_id": cid, "targets": ["10.10.1.0/24", "10.30.0.10-10.30.0.50"],
            "exclude": ["10.10.1.40"], "credential_ids": list(creds), "schedule": "manual", **over}


def fetch_scan(c):
    r = c.get("/api/collector/commands")
    assert r.status_code == 200, r.text
    cmds = [x for x in r.json()["commands"] if x["type"] == "network_scan"]
    assert len(cmds) == 1, r.json()
    return cmds[0]


def post_batch(c, run_id, seq, devices=(), final=False, summary=None, gz=False):
    body = {"scan_id": run_id, "seq": seq, "final": final, "devices": list(devices)}
    if summary or final:
        body["summary"] = summary or {"addresses": 256, "alive": len(devices), "snmp": 1, "duration_s": 12, "errors": []}
    raw = json.dumps(body).encode()
    if gz:
        return c.post("/api/collector/network/batches", content=gzip.compress(raw),
                      headers={"Content-Type": "application/json", "Content-Encoding": "gzip"})
    return c.post("/api/collector/network/batches", content=raw, headers={"Content-Type": "application/json"})


def switch_device(ip="10.10.1.1", mac="00:1e:13:aa:bb:01", **over):
    d = {"ip": ip, "mac": mac, "hostname": "sw-core.corp.example.com", "alive_via": ["icmp", "arp"],
         "snmp": {"version": "v3", "credential_id": "c1", "sys_name": "sw-core", "sys_descr": XE_DESCR,
                  "sys_object_id": "1.3.6.1.4.1.9.1.2504", "sys_location": "HQ rack 3", "sys_contact": "net@corp", "uptime_s": 86400 * 30},
         "default_community": None,
         "interfaces": [{"index": 1, "name": "Gi1/0/1", "descr": "uplink", "mac": mac, "oper_up": True, "speed_mbps": 1000},
                        {"index": 2, "name": "Gi1/0/2", "descr": "", "mac": "", "oper_up": False, "speed_mbps": 1000}],
         "fdb": [{"mac": "00:50:56:00:00:01", "port_name": "Gi1/0/5", "vlan": 10}],
         "open_ports": [{"port": 22, "proto": "tcp", "service": "ssh", "banner": "SSH-2.0-Cisco-1.25"},
                        {"port": 23, "proto": "tcp", "service": "telnet"}, {"port": 80, "proto": "tcp"},
                        {"port": 443, "proto": "tcp"}]}
    d.update(over)
    return d


def scan_run(admin, c, cid, creds=()):
    r = admin.post("/api/network/scans", json=scan_body(cid, creds, run_now=True))
    assert r.status_code == 201, r.text
    cmd = fetch_scan(c)
    return r.json(), cmd


# ----------------------------------------------------------------------------- secrets
def test_secrets_never_stored_returned_or_logged(admin, caplog):
    caplog.set_level(logging.DEBUG)
    c, cid = make_collector(admin)
    v3, v2c = create_cred(admin, V3), create_cred(admin, V2C)
    for out in (v3, v2c):
        assert not any(s in json.dumps(out) for s in SECRETS)
    assert v3["label"].startswith("SNMPv3") and v3["secret_stored"] and v3["username_hint"] == "sn••••"
    scan, cmd = scan_run(admin, c, cid, [v2c["id"], v3["id"]])
    # v3 is tried first (preferred), then v2c; the delivered copy carries the secrets...
    snmp = cmd["params"]["snmp"]
    assert [s["version"] for s in snmp] == ["v3", "v2c"]
    assert snmp[0]["auth_password"] == SECRETS[0] and snmp[0]["priv_password"] == SECRETS[1] and snmp[1]["community"] == SECRETS[2]
    assert snmp[0]["auth_proto"] == "SHA256" and snmp[0]["level"] == "authPriv" and snmp[0]["username"] == "snmpmon"
    # ... the contract's shape ...
    p = cmd["params"]
    assert p["scan_id"] == scan["run"]["id"] and p["targets"] == ["10.10.1.0/24", "10.30.0.10-10.30.0.50"]
    assert p["exclude"] == ["10.10.1.40"] and p["port_check"] is True and p["concurrency"] == 20 and p["timeout_ms"] == 1500
    assert p["ports"] == [{"port": q, "proto": pr} for q, pr in
                          [(22, "tcp"), (23, "tcp"), (80, "tcp"), (443, "tcp"), (445, "tcp"), (3389, "tcp"), (161, "udp"),
                           (8080, "tcp"), (8443, "tcp"), (9100, "tcp")]]
    assert p["upload_url"] == "/api/collector/network/batches"
    # ... but nothing stored has them: not the command, not the run, not the credential columns.
    with db.get_session("default") as s:
        stored = [json.dumps(x.params) for x in s.scalars(select(CollectorCommand))]
        stored += [json.dumps(x.params) for x in s.scalars(select(NetworkScanRun))]
        stored += [json.dumps(x.__dict__, default=str) for x in s.scalars(select(NetworkSnmpCredential))]
        stored += [json.dumps(a.detail, default=str) for a in s.scalars(select(AuditLog))]
        for blob in stored:
            assert not any(sec in blob for sec in SECRETS), blob
        ct = s.scalar(select(NetworkSnmpCredential.secret_ciphertext))
        assert ct and not any(sec in ct for sec in SECRETS)
    # API responses and logs never contain them either.
    for path in ("/api/network/credentials", "/api/network/scans", f"/api/network/scans/{scan['id']}",
                 f"/api/network/scans/{scan['id']}/runs", "/api/network/runs/" + scan["run"]["id"], "/api/collectors"):
        assert not any(sec in admin.get(path).text for sec in SECRETS), path
    assert not any(sec in caplog.text for sec in SECRETS)
    # A command is delivered once: a second poll does not return it (nor the secrets).
    assert c.get("/api/collector/commands").json()["commands"] == []


def test_credential_validation_and_lifecycle(admin):
    for bad in ({**V3, "auth_password": "short"}, {**V3, "username": ""}, {**V3, "priv_password": ""},
                {**V3, "priv_proto": "none"}, {**V3, "auth_proto": ""}, {"name": "x", "version": "v2c", "community": ""},
                {**V3, "level": ""}):
        assert admin.post("/api/network/credentials", json=bad).status_code == 422, bad
    nopriv = create_cred(admin, {**V3, "name": "np", "level": "authNoPriv", "priv_proto": "", "priv_password": ""})
    assert nopriv["priv_proto"] == "none"
    cred = create_cred(admin)
    r = admin.put(f"/api/network/credentials/{cred['id']}", json={**V3, "auth_password": "AnotherPass1", "priv_password": "AnotherPass2"})
    assert r.status_code == 200 and "AnotherPass" not in r.text
    c, cid = make_collector(admin)
    scan = admin.post("/api/network/scans", json=scan_body(cid, [cred["id"]])).json()
    assert admin.delete(f"/api/network/credentials/{cred['id']}").status_code == 204
    assert admin.get(f"/api/network/scans/{scan['id']}").json()["credential_ids"] == []
    assert admin.post("/api/network/scans", json=scan_body(cid, ["f" * 32])).status_code == 422
    actions = {a.action for a in _audit()}
    assert {"network_credential_created", "network_credential_replaced", "network_credential_deleted"} <= actions


def _audit():
    with db.get_session("default") as s:
        return list(s.scalars(select(AuditLog)))


def test_undecryptable_credential_cancels_the_scan(admin, monkeypatch):
    c, cid = make_collector(admin)
    cred = create_cred(admin)
    with db.get_session("default") as s:
        s.get(NetworkSnmpCredential, cred["id"]).secret_ciphertext = "not-a-token"
        s.commit()
    assert admin.post("/api/network/scans", json=scan_body(cid, [cred["id"]], run_now=True)).status_code == 201
    assert c.get("/api/collector/commands").json()["commands"] == []
    with db.get_session("default") as s:
        run = s.scalar(select(NetworkScanRun))
        assert run.status == "failed" and "cannot be decrypted" in run.error


# ----------------------------------------------------------------------------- scans / queueing
def test_scan_crud_validation_audit_and_rbac(admin):
    c, cid = make_collector(admin)
    for bad in ({"targets": ["10.0.0.0/15"]}, {"targets": ["127.0.0.1"]}, {"targets": []}, {"concurrency": 30},
                {"exclude": ["nope"]}, {"collector_id": "0" * 32}, {"schedule_time": "25:00"}):
        assert admin.post("/api/network/scans", json=scan_body(cid, **bad)).status_code == 422, bad
    r = admin.post("/api/network/scans", json=scan_body(cid, concurrency=64, target_notes={"10.10.1.0/24": "AD Site: HQ"}))
    assert r.status_code == 201, r.text
    s = r.json()
    assert s["address_count"] == 256 + 41 - 1 and s["pace"] == "normal" and s["collector"]["state"] == "online"
    assert s["ports"][0] == {"port": 22, "proto": "tcp"} and s["target_notes"] == {"10.10.1.0/24": "AD Site: HQ"}
    p = admin.patch(f"/api/network/scans/{s['id']}", json={"concurrency": 20, "port_check": False, "schedule": "weekly",
                                                           "schedule_weekday": 2, "exclude": []})
    assert p.status_code == 200 and p.json()["ports"] == [] and p.json()["address_count"] == 297
    assert admin.patch(f"/api/network/scans/{s['id']}", json={"targets": ["0.0.0.0/8"]}).status_code == 422
    assert admin.post(f"/api/network/scans/{s['id']}/run").status_code == 202
    assert admin.post(f"/api/network/scans/{s['id']}/run").status_code == 409  # already queued
    assert admin.delete(f"/api/network/scans/{s['id']}").status_code == 409  # running
    # RBAC: viewers read; analysts cannot configure or run; admins can.
    make_user(admin, "viewer")
    make_user(admin, "analyst")
    from tests.conftest import login

    for role, code in (("viewer", 403), ("analyst", 403)):
        u = type(admin)(admin.app, base_url=str(admin.base_url))
        login(u, f"{role}@example.com", "a-long-test-password")
        assert u.get("/api/network/scans").status_code == 200
        assert u.get("/api/network/devices").status_code == 200
        assert u.get("/api/network/credentials").status_code == 200
        assert u.post("/api/network/scans", json=scan_body(cid)).status_code == code
        assert u.post(f"/api/network/scans/{s['id']}/run").status_code == code
        assert u.post("/api/network/credentials", json=V2C).status_code == code
        assert u.post("/api/network/test", json={"collector_id": cid, "address": "10.0.0.5"}).status_code == code
        assert u.patch(f"/api/network/scans/{s['id']}", json={"name": "x"}).status_code == code
        assert u.delete(f"/api/network/scans/{s['id']}").status_code == code
    actions = [a.action for a in _audit()]
    for a in ("network_scan_created", "network_scan_edited", "network_scan_started"):
        assert a in actions


def test_scan_only_on_online_dedicated_collectors(admin):
    c, cid = make_collector(admin)
    assert admin.post("/api/network/scans", json=scan_body("f" * 32)).status_code == 422
    # The command allow-list: endpoint agents are never sent network commands.
    from tests.test_directory import add_device

    agent, dev = add_device(admin, "PC1", "1" * 64)
    r = admin.post(f"/api/devices/{dev}/commands", json={"type": "network_scan", "reason": "x"})
    assert r.status_code in (404, 422)
    assert admin.post("/api/network/scans", json=scan_body(dev)).status_code == 422  # an endpoint is not a collector
    assert agent.get("/api/agent/commands").json()["commands"] == []
    # Offline collector: refused, nothing queued.
    with db.get_session("default") as s:
        s.get(DirectoryCollector, cid).last_seen_at = utcnow() - timedelta(hours=1)
        s.commit()
    sc = admin.post("/api/network/scans", json=scan_body(cid)).json()
    assert admin.post(f"/api/network/scans/{sc['id']}/run").status_code == 409
    assert admin.post("/api/network/test", json={"collector_id": cid, "address": "10.0.0.5"}).status_code == 409
    with db.get_session("default") as s:
        assert s.scalar(select(CollectorCommand.id).where(CollectorCommand.type == "network_scan")) is None
        c0 = s.get(DirectoryCollector, cid)
        for t in ("network_scan", "network_subnets"):
            assert t in coll.COMMAND_TYPES
        with pytest.raises(coll.CollectorError):
            coll.new_command(s, c0, "run_script", {}, "x", actor="a")


def test_test_one_address_and_rescan(admin):
    c, cid = make_collector(admin)
    cred = create_cred(admin, V2C)
    r = admin.post("/api/network/test", json={"collector_id": cid, "address": "10.10.1.1", "credential_ids": [cred["id"]]})
    assert r.status_code == 202, r.text
    run = r.json()
    assert run["trigger"] == "test" and run["targets"] == ["10.10.1.1/32"]
    cmd = fetch_scan(c)
    assert cmd["params"]["targets"] == ["10.10.1.1/32"] and cmd["params"]["exclude"] == []
    assert cmd["params"]["snmp"][0]["community"] == SECRETS[2]
    for bad in ("10.10.1.0/24", "127.0.0.1", "nope", "224.0.0.5"):
        assert admin.post("/api/network/test", json={"collector_id": cid, "address": bad}).status_code == 422, bad
    # Results of a test come back like any scan and create the device; "Re-scan device" queues a /32 as well.
    assert post_batch(c, run["id"], 0, [switch_device()], final=True).status_code == 200
    dev = admin.get("/api/network/devices").json()[0]
    rr = admin.post(f"/api/network/devices/{dev['id']}/rescan")
    assert rr.status_code == 202, rr.text
    assert fetch_scan(c)["params"]["targets"] == ["10.10.1.1/32"]


def test_suggestions_from_ad_sites_and_dhcp(admin):
    c, cid = make_collector(admin)
    assert admin.get(f"/api/network/suggestions?collector_id={cid}").json()[0]["items"] == []
    r = admin.post("/api/network/suggestions/refresh", json={"collector_id": cid})
    assert r.status_code == 202
    cmds = c.get("/api/collector/commands").json()["commands"]
    assert [x["type"] for x in cmds] == ["network_subnets"] and cmds[0]["params"] == {}
    assert admin.get(f"/api/network/suggestions?collector_id={cid}").json()[0]["pending"] is True
    data = {"ad_sites": [{"site": "HQ", "subnet": "10.10.1.0/24", "description": "HQ users"},
                         {"site": "X", "subnet": "garbage", "description": ""}],
            "dhcp_scopes": [{"server": "HQ-DC01", "scope": "10.10.10.0", "mask": "255.255.254.0", "name": "Staff Wi-Fi",
                             "start": "10.10.10.10", "end": "10.10.11.250"},
                            {"server": "HQ-DC01", "scope": "10.10.1.0", "mask": "255.255.255.0", "name": "Users"}],
            "errors": ["DHCP: access denied on DC02"]}
    ok = c.post(f"/api/collector/commands/{cmds[0]['id']}/result", json={"nonce": cmds[0]["nonce"], "status": "succeeded",
                                                                       "output": "", "result_data": data})
    assert ok.status_code == 204, ok.text
    s = admin.get(f"/api/network/suggestions?collector_id={cid}").json()[0]
    items = {i["subnet"]: i for i in s["items"]}
    assert set(items) == {"10.10.1.0/24", "10.10.10.0/23"}  # the garbage subnet is dropped, duplicates merged
    assert items["10.10.1.0/24"]["suggested_by"] == "AD Site: HQ" and items["10.10.1.0/24"]["addresses"] == 256
    assert items["10.10.1.0/24"]["suggested_by_all"] == ["AD Site: HQ", "DHCP: HQ-DC01"]
    assert items["10.10.10.0/23"]["suggested_by"] == "DHCP: HQ-DC01" and items["10.10.10.0/23"]["addresses"] == 512
    assert s["errors"] == ["DHCP: access denied on DC02"] and s["pending"] is False
    assert len(s["ad_sites"]) == 1 and len(s["dhcp_scopes"]) == 2


# ----------------------------------------------------------------------------- ingest
def test_batch_ingest_idempotent_merge_and_findings(admin):
    c, cid = make_collector(admin)
    cred = create_cred(admin)
    scan, cmd = scan_run(admin, c, cid, [cred["id"]])
    rid = cmd["params"]["scan_id"]
    # Auth and ownership: no credential, a wrong run, an unknown run.
    anon = type(c)(c.app, base_url=str(c.base_url))
    assert post_batch(anon, rid, 0).status_code == 401
    assert post_batch(c, "f" * 32, 0).status_code == 404
    sw = switch_device()
    printer = {"ip": "10.10.1.50", "mac": "00:80:77:11:22:33", "hostname": "prn-1", "alive_via": ["icmp", "tcp"],
               "open_ports": [{"port": 9100, "proto": "tcp"}, {"port": 80, "proto": "tcp", "banner": "Server: HP-ChaiSOE"}]}
    r1 = post_batch(c, rid, 0, [sw, printer], gz=True)
    assert r1.status_code == 200 and r1.json()["accepted"] == 2, r1.text
    again = post_batch(c, rid, 0, [sw, printer])
    assert again.json() == {"accepted": 0, "duplicate": True, "status": "running"}
    assert len(admin.get("/api/network/devices").json()) == 2
    # Same MAC at a new IP (DHCP) is the same device; a MAC-less record is upgraded when its MAC shows up.
    moved = {**printer, "ip": "10.10.1.51", "open_ports": [{"port": 9100, "proto": "tcp"}]}
    macless = {"ip": "10.10.1.60", "alive_via": ["icmp"], "open_ports": [{"port": 80, "proto": "tcp"}]}
    assert post_batch(c, rid, 1, [moved, macless]).status_code == 200
    assert post_batch(c, rid, 2, [{**macless, "mac": "ac:de:48:00:00:09"}], final=True).status_code == 200
    devs = admin.get("/api/network/devices").json()
    assert len(devs) == 3
    prn = next(d for d in devs if d["mac"] == "00:80:77:11:22:33")
    assert prn["ip"] == "10.10.1.51" and prn["device_type"] == "printer" and prn["vendor"] == "Brother"
    assert [p["port"] for p in prn["open_ports"]] == [9100]  # port 80 closed since the first sighting
    hist = admin.get(f"/api/network/devices/{prn['id']}").json()["events"]
    assert {"ip_changed", "port_closed", "first_seen"} <= {e["kind"] for e in hist}
    upgraded = next(d for d in devs if d["mac"] == "ac:de:48:00:00:09")
    assert upgraded["ip"] == "10.10.1.60" and upgraded["mac_vendor"] == "Apple"
    # Finished run, replay after the end is still idempotent; new data after the end is refused.
    assert post_batch(c, rid, 2, [], final=True).json()["duplicate"] is True
    assert post_batch(c, rid, 9, [sw]).status_code == 409
    run = admin.get(f"/api/network/runs/{rid}").json()
    assert run["status"] == "succeeded" and run["devices_seen"] == 5 and run["summary"]["snmp"] == 1
    assert admin.get(f"/api/network/scans/{scan['id']}").json()["last_status"] == "succeeded"
    # The switch: SNMP identified, normalised, findings opened.
    d = next(x for x in devs if x["ip"] == "10.10.1.1")
    assert (d["device_type"], d["vendor"], d["firmware"], d["identified_by"]) == ("switch", "Cisco", "17.3.4", "SNMPv3")
    assert d["subnet"] == "10.10.1.0/24"
    assert {f["rule_id"] for f in d["findings"]} == {"NET-TELNET-001", "NET-HTTP-001"}
    detail = admin.get(f"/api/network/devices/{d['id']}").json()
    assert detail["interfaces_up"] == 1 and detail["interfaces_down"] == 1 and detail["sys_location"] == "HQ rack 3"
    assert detail["connected"]["total"] == 1 and detail["connected"]["unmanaged"] == 1  # a VMware MAC nobody manages
    assert detail["tracked"] == "none" and detail["cpe"]["product"] == "o:cisco:ios_xe"
    # Findings live in the existing findings flow and open in the finding detail page, PDF included.
    fid = detail["finding_list"][0]["id"]
    f = admin.get(f"/api/findings/{fid}")
    assert f.status_code == 200, f.text
    fj = f.json()
    assert fj["source"] == "network" and fj["asset_type"] == "network_device" and fj["guidance"]["fix_cli"]
    assert fj["guidance"]["labels"]["console"] == "Device console" and fj["asset"]["source"] == "network"
    assert any(x["id"] == fid for x in admin.get("/api/findings?source=network").json())
    assert admin.get(f"/api/findings/{fid}/report.pdf").content.startswith(b"%PDF")
    # Findings resolve when the cause is fixed (telnet closed on the next scan).
    scan2 = admin.post(f"/api/network/scans/{scan['id']}/run")
    assert scan2.status_code == 202
    cmd2 = fetch_scan(c)
    fixed = switch_device(open_ports=[{"port": 22, "proto": "tcp"}, {"port": 443, "proto": "tcp"}])
    assert post_batch(c, cmd2["params"]["scan_id"], 0, [fixed], final=True).status_code == 200
    d2 = next(x for x in admin.get("/api/network/devices").json() if x["ip"] == "10.10.1.1")
    assert d2["findings"] == []
    assert admin.get(f"/api/findings/{fid}").json()["status"] == "resolved"


def test_ingest_sanitises_and_caps(admin):
    c, cid = make_collector(admin)
    scan, cmd = scan_run(admin, c, cid)
    rid = cmd["params"]["scan_id"]
    evil = {"ip": "10.10.1.7", "mac": "AA:BB:CC:DD:EE:07", "hostname": "h\x00ost\x07" + "x" * 400, "alive_via": ["icmp", "bogus"],
            "snmp": {"version": "v2c", "sys_name": "n\x1b[31mame", "sys_descr": "d" * 5000, "uptime_s": -5},
            "open_ports": [{"port": 80, "proto": "tcp", "banner": "B" * 900, "service": "http\x00"}]}
    assert post_batch(c, rid, 0, [evil, {"ip": "not-an-ip"}, {"ip": "10.10.1.8", "open_ports": [{"port": 70000}]}]).status_code in (200, 422)
    ok = post_batch(c, rid, 1, [evil, {"ip": "not-an-ip"}], final=True)
    assert ok.status_code == 200 and ok.json()["accepted"] == 1
    d = admin.get("/api/network/devices").json()[0]
    assert "\x00" not in d["hostname"] and len(d["hostname"]) == 255
    det = admin.get(f"/api/network/devices/{d['id']}").json()
    assert len(det["sys_descr"]) == 1024 and "\x1b" not in d["name"] and det["uptime_s"] is None
    assert len(det["open_ports"][0]["service"]) < 10 and det["alive_via"] == ["icmp"]
    with db.get_session("default") as s:
        from app.network.models import NetworkDevicePort

        assert len(s.scalar(select(NetworkDevicePort.banner))) == 200
    big = post_batch(c, rid, 5, [{"ip": f"10.10.{i // 250}.{i % 250 + 1}"} for i in range(501)])
    assert big.status_code == 422


def test_fdb_unmanaged_detection_and_new_device_finding(admin):
    c, cid = make_collector(admin)
    scan, cmd = scan_run(admin, c, cid)
    rid = cmd["params"]["scan_id"]
    known = {"ip": "10.10.1.80", "mac": "3c:d9:2b:00:00:80", "hostname": "pc80", "open_ports": [{"port": 445, "proto": "tcp"}]}
    base = [{"mac": "3c:d9:2b:00:00:80", "port_name": "Gi1/0/7", "vlan": 10}]
    sw = switch_device(fdb=base, open_ports=[], interfaces=[])
    assert post_batch(c, rid, 0, [sw, known], final=True).status_code == 200
    sid = next(d["id"] for d in admin.get("/api/network/devices").json() if d["ip"] == "10.10.1.1")
    first = admin.get(f"/api/network/devices/{sid}").json()
    assert first["connected"]["unmanaged"] == 0  # known by MAC (a scanned device)
    assert first["findings"] == [] or all(f["rule_id"] != "NET-FDB-001" for f in first["findings"])
    # Second scan: a new MAC appears on an access port: the switch gets a finding; a trunk port's MACs do not count.
    admin.post(f"/api/network/scans/{scan['id']}/run")
    cmd2 = fetch_scan(c)
    trunk = [{"mac": f"aa:bb:cc:00:{i // 256:02x}:{i % 256:02x}", "port_name": "Te1/1/1", "vlan": 1} for i in range(40)]
    fdb2 = [*base, {"mac": "de:ad:be:ef:00:01", "port_name": "Gi1/0/9", "vlan": 20}, *trunk]
    assert post_batch(c, cmd2["params"]["scan_id"], 0, [switch_device(fdb=fdb2, open_ports=[], interfaces=[]), known],
                      final=True).status_code == 200
    det = admin.get(f"/api/network/devices/{sid}").json()
    rows = {r["mac"]: r for r in det["connected"]["rows"]}
    assert rows["de:ad:be:ef:00:01"]["unmanaged"] is True and rows["3c:d9:2b:00:00:80"]["unmanaged"] is False
    assert all(r["uplink"] and not r["unmanaged"] for r in det["connected"]["rows"] if r["port"] == "Te1/1/1")
    assert det["connected"]["unmanaged"] == 1
    fdb_finding = next(f for f in det["finding_list"] if f["rule_id"] == "NET-FDB-001")
    ev = admin.get(f"/api/findings/{fdb_finding['id']}").json()["evidence"]
    assert ev["count"] == 1 and ev["new_devices"][0]["port"] == "Gi1/0/9" and ev["new_devices"][0]["mac"] == "de:ad:be:ef:00:01"


# ----------------------------------------------------------------------------- linking and IT assets
def test_links_to_endpoints_directory_and_it_assets(admin):
    from tests.test_directory import add_device

    agent, dev_id = add_device(admin, "PC81", "1" * 64)
    with db.get_session("default") as s:
        from app.models import Device

        d = s.get(Device, dev_id)
        d.inventory = {"network": [{"name": "Ethernet", "mac": "3C-D9-2B-00-00-81", "ips": ["10.10.1.81"]}]}
        s.commit()
    c, cid = make_collector(admin)
    scan, cmd = scan_run(admin, c, cid)
    rid = cmd["params"]["scan_id"]
    mac_match = {"ip": "10.10.1.99", "mac": "3c:d9:2b:00:00:81", "alive_via": ["arp"]}
    name_match = {"ip": "10.10.1.82", "mac": "3c:d9:2b:00:00:82", "hostname": "pc81.corp.example.com", "alive_via": ["icmp"]}
    stranger = {"ip": "10.10.1.83", "mac": "3c:d9:2b:00:00:83", "alive_via": ["icmp"], "open_ports": [{"port": 9100, "proto": "tcp"}]}
    assert post_batch(c, rid, 0, [mac_match, name_match, stranger], final=True).status_code == 200
    devs = {d["ip"]: d for d in admin.get("/api/network/devices").json()}
    assert devs["10.10.1.99"]["tracked"] == "agent" and devs["10.10.1.82"]["tracked"] == "agent"
    assert devs["10.10.1.83"]["tracked"] == "none" and devs["10.10.1.83"]["tracked_label"] == "Not registered"
    # Filters and stats.
    assert [d["ip"] for d in admin.get("/api/network/devices?status=not_in_it_assets").json()] == ["10.10.1.83"]
    stats = admin.get("/api/network/summary").json()
    assert stats["devices"] == 3 and stats["with_snmp"] == 0 and stats["ping_arp_only"] == 3
    assert [d["ip"] for d in admin.get("/api/network/devices?type=printer").json()] == ["10.10.1.83"]
    assert [d["ip"] for d in admin.get("/api/network/devices?q=pc81").json()] == ["10.10.1.82"]
    assert len(admin.get("/api/network/devices?status=new_this_week").json()) == 3
    assert admin.get("/api/network/devices?subnet=10.10.1.0/24").json() and not admin.get("/api/network/devices?subnet=1.2.3.0/24").json()
    assert admin.get("/api/network/devices?status=bogus").status_code == 422
    # Add to IT assets (analyst; bulk; idempotent).
    r = admin.post("/api/network/devices/add-to-it-assets", json={"device_ids": [devs["10.10.1.83"]["id"], "0" * 32]})
    assert r.status_code == 200 and len(r.json()["created"]) == 1 and r.json()["skipped"][0]["reason"] == "not found"
    assert admin.post("/api/network/devices/add-to-it-assets", json={"device_ids": [devs["10.10.1.83"]["id"]]}).json()["created"] == []
    d = admin.get(f"/api/network/devices/{devs['10.10.1.83']['id']}").json()
    assert d["tracked"] == "it_asset" and d["it_asset"]["asset_tag"].startswith("NET-")
    asset = admin.get(f"/api/it-assets/{d['it_asset']['id']}").json()
    assert asset["asset_type"] == "printer" and asset["source"] == "network"
    assert admin.get("/api/network/summary").json()["not_in_it_assets"] == 0  # the agent devices already have IT assets
    assert devs["10.10.1.99"]["it_asset_id"] and devs["10.10.1.82"]["it_asset_id"]
    assert "network_devices_added_to_it_assets" in [a.action for a in _audit()]


def test_exports_csv_and_pdf_and_rbac(admin):
    c, cid = make_collector(admin)
    scan, cmd = scan_run(admin, c, cid)
    risky = switch_device(hostname="=cmd|' /C calc'!A0", snmp={"version": "v3", "sys_name": "=HYPERLINK(1)", "sys_descr": XE_DESCR,
                                                              "sys_object_id": "1.3.6.1.4.1.9.1.2504"})
    assert post_batch(c, cmd["params"]["scan_id"], 0, [risky], final=True).status_code == 200
    r = admin.get("/api/network/devices/export.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    lines = r.text.strip().splitlines()
    assert lines[0].startswith("name,ip,mac,type,vendor") and "'=HYPERLINK(1)" in lines[1] and "10.10.1.1" in lines[1]
    did = admin.get("/api/network/devices").json()[0]["id"]
    pdf = admin.get(f"/api/network/devices/{did}/report.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF") and pdf.headers["content-type"] == "application/pdf"
    make_user(admin, "viewer")
    from tests.conftest import login

    v = type(admin)(admin.app, base_url=str(admin.base_url))
    login(v, "viewer@example.com", "a-long-test-password")
    assert v.get("/api/network/devices/export.csv").status_code == 200
    assert v.get(f"/api/network/devices/{did}/report.pdf").status_code == 403
    assert v.post("/api/network/devices/add-to-it-assets", json={"device_ids": [did]}).status_code == 403
    assert v.post(f"/api/network/devices/{did}/rescan").status_code == 403
    assert v.delete(f"/api/network/devices/{did}").status_code == 403
    actions = [a.action for a in _audit()]
    assert "network_devices_exported" in actions and "network_device_report_exported" in actions


# ----------------------------------------------------------------------------- CVE matching (existing engine)
@pytest.fixture()
def fake_feeds():
    f = FakeFeeds()
    f.nvd["cpe:2.3:o:cisco:ios_xe"] = [
        cve("CVE-2023-20198", "Cisco IOS XE Software Web UI privilege escalation vulnerability.",
            cvss31(10.0, "critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
            [{"operator": "AND", "nodes": [
                node(m("cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*", versionStartIncluding="17.3", versionEndExcluding="17.3.8a")),
                node(m("cpe:2.3:h:cisco:catalyst_9300:-:*:*:*:*:*:*:*", vulnerable=False))]}]),
        cve("CVE-2021-1435", "Cisco IOS XE web UI command injection.", cvss31(7.2, "high"),
            [{"nodes": [node(m("cpe:2.3:o:cisco:ios_xe:17.3.4:*:*:*:*:*:*:*"))]}]),
        cve("CVE-2024-99100", "Fixed long ago.", cvss31(9.0, "critical"),
            [{"nodes": [node(m("cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*", versionEndExcluding="17.3.1"))]}]),
        cve("CVE-2024-99101", "Newer train only.", cvss31(9.0, "critical"),
            [{"nodes": [node(m("cpe:2.3:o:cisco:ios_xe:*:*:*:*:*:*:*:*", versionStartIncluding="17.9", versionEndExcluding="17.9.5"))]}]),
    ]
    f.kev["vulnerabilities"].append({"cveID": "CVE-2023-20198", "vendorProject": "Cisco", "product": "IOS XE",
                                     "vulnerabilityName": "Cisco IOS XE Web UI Privilege Escalation Vulnerability",
                                     "dateAdded": "2023-10-16", "requiredAction": "Apply mitigations per vendor instructions.",
                                     "dueDate": "2023-10-20", "knownRansomwareCampaignUse": "Unknown"})
    feeds.set_transport(f.transport(), f.sleep)
    yield f
    feeds.set_transport(None)


def test_cves_land_on_network_devices_and_the_cve_page(admin, fake_feeds):
    c, cid = make_collector(admin)
    scan, cmd = scan_run(admin, c, cid)
    assert post_batch(c, cmd["params"]["scan_id"], 0, [switch_device()], final=True).status_code == 200
    with db.get_session("default") as s:
        st = s.scalar(select(VulnMatchState).where(VulnMatchState.target_type == "network"))
        assert st is not None and st.requested_at is not None
    res = worker.run_once(force=True)
    assert any(x.startswith("network:") for x in res.matched), res
    d = admin.get("/api/network/devices").json()[0]
    assert d["vulns"] == {"open": 2, "kev": 1, "max_severity": "critical"}
    detail = admin.get(f"/api/network/devices/{d['id']}").json()
    assert [v["cve_id"] for v in detail["vulnerabilities"]] == ["CVE-2023-20198", "CVE-2021-1435"]  # KEV first
    xe = detail["vulnerabilities"][0]
    assert xe["kev"] and xe["fixed_version"] == "17.3.8a" and xe["package"] == "Cisco IOS XE" and xe["version"] == "17.3.4"
    # "Fix first": one firmware upgrade closes both, KEV first, vendor advisory, the vendor-published workaround only
    # for the CVE that has one.
    fix = detail["fixes"][0]
    assert fix["target"] == "17.3.8a" and fix["cve_count"] == 1
    assert fix["kev_count"] == 1 and fix["cves"][0]["cve_id"] == "CVE-2023-20198"
    assert fix["advisory"]["url"].startswith("https://") and "no ip http server" in fix["workaround"]["text"]
    nofix = [f for f in detail["fixes"] if f["target"] is None]
    assert all(f["workaround"] is None for f in nofix)
    # The existing vulnerability list and CVE page include the network device with its firmware and fixed firmware.
    lst = admin.get("/api/vulnerabilities?scope=network").json()
    assert {v["cve_id"] for v in lst} == {"CVE-2023-20198", "CVE-2021-1435"} and lst[0]["network_device_name"] == "sw-core"
    assert admin.get("/api/vulnerabilities?scope=device").json() == []
    by_cve = {g["cve_id"]: g for g in admin.get("/api/vulnerabilities/by-cve").json()}
    assert by_cve["CVE-2023-20198"]["network_devices"] == ["sw-core"]
    page = admin.get("/api/vulnerabilities/CVE-2023-20198")
    assert page.status_code == 200, page.text
    pj = page.json()
    assert pj["affected"]["network_devices"] == 1 and pj["kev"] is True
    nd = pj["network_devices"][0]
    assert (nd["name"], nd["ip"], nd["firmware"], nd["fixed_version"]) == ("sw-core", "10.10.1.1", "17.3.4", "17.3.8a")
    assert nd["needs"] == "Upgrade firmware to 17.3.8a or later"
    assert pj["guidance"]["network"]["fixed_version"] == "17.3.8a" and pj["guidance"]["patch_available"] is True
    assert pj["fixed_in"] and admin.get("/api/vulnerabilities/CVE-2023-20198/report.pdf").content.startswith(b"%PDF")
    assert admin.get("/api/vulnerabilities/stats").json()["network_devices"] == {"open": 2, "affected": 1}
    # Upgrading the firmware resolves them on the next match.
    scan2 = admin.post(f"/api/network/scans/{scan['id']}/run")
    cmd2 = fetch_scan(c)
    up = switch_device(snmp={"version": "v3", "credential_id": "c1", "sys_name": "sw-core",
                             "sys_descr": XE_DESCR.replace("Version 17.3.4", "Version 17.3.9"), "sys_object_id": "1.3.6.1.4.1.9.1.2504"})
    assert scan2.status_code == 202 and post_batch(c, cmd2["params"]["scan_id"], 0, [up], final=True).status_code == 200
    worker.run_once(force=True)
    assert admin.get("/api/vulnerabilities?scope=network").json() == []
    assert any(e["kind"] == "firmware_changed" for e in admin.get(f"/api/network/devices/{d['id']}").json()["events"])


def test_unidentified_device_is_not_checked_and_says_why(admin, fake_feeds):
    c, cid = make_collector(admin)
    scan, cmd = scan_run(admin, c, cid)
    mystery = {"ip": "10.10.1.9", "snmp": {"version": "v2c", "sys_descr": "Some Appliance 1.0", "sys_name": "x"}}
    assert post_batch(c, cmd["params"]["scan_id"], 0, [mystery], final=True).status_code == 200
    worker.run_once(force=True)
    d = admin.get("/api/network/devices").json()[0]
    det = admin.get(f"/api/network/devices/{d['id']}").json()
    assert d["vulns"]["open"] == 0 and det["vuln_status"]["checked"] is False and "could not be identified" in det["vuln_status"]["reason"]


# ----------------------------------------------------------------------------- scheduler
def _tick(now):
    from app.directory.scheduler import DirectoryScheduler

    s = DirectoryScheduler()
    try:
        s.tick(now)
    finally:
        s.stop()


def test_scheduler_queues_scheduled_scans_on_online_collectors_only(admin):
    c, cid = make_collector(admin)
    admin.post("/api/network/scans", json=scan_body(cid, schedule="daily", schedule_time="02:00", name="nightly"))
    admin.post("/api/network/scans", json=scan_body(cid, schedule="manual", name="manual"))
    admin.post("/api/network/scans", json=scan_body(cid, schedule="weekly", schedule_time="03:00", schedule_weekday=0, name="weekly"))
    with db.get_session("default") as s:
        for sc in s.scalars(select(NetworkScan)):
            sc.created_at = datetime(2026, 11, 1)
        s.commit()
        col = s.get(DirectoryCollector, cid)
        col.last_seen_at = utcnow()
        s.commit()
    from app import tenancy

    now = datetime(2026, 11, 10, 2, 5)  # a Tuesday, 02:05 UTC
    # a heartbeat "now" for the fake clock
    with db.get_session("default") as s:
        s.get(DirectoryCollector, cid).last_seen_at = now
        s.commit()
    _tick(now)
    with db.get_session("default") as s:
        runs = list(s.scalars(select(NetworkScanRun)))
        names = sorted(r.name for r in runs)
        assert names == ["nightly", "weekly"]  # the manual one never runs on its own; weekly's Monday slot 03:00 was missed
        assert all(r.trigger == "scheduled" and r.status == "queued" and r.collector_id == cid for r in runs)
    cmds = [x for x in c.get("/api/collector/commands").json()["commands"] if x["type"] == "network_scan"]
    assert len(cmds) >= 1
    # No duplicate for the same slot.
    _tick(now + timedelta(minutes=1))
    with db.get_session("default") as s:
        assert len(list(s.scalars(select(NetworkScanRun)))) == len(runs)
    assert tenancy  # imported for clarity of intent: runs are tenant scoped
    # An unreachable collector at the slot: the scan is skipped after the grace period and recorded as failed.
    # The commands poll above was a heartbeat and a pickup on the real clock; put both back on the fake one.
    with db.get_session("default") as s:
        s.get(DirectoryCollector, cid).last_seen_at = now
        for r in s.scalars(select(NetworkScanRun)):
            r.started_at = r.last_batch_at = now if r.started_at else None
        s.commit()
    _tick(datetime(2026, 11, 11, 6, 30))
    with db.get_session("default") as s:
        failed = [r for r in s.scalars(select(NetworkScanRun)) if r.status == "failed" and r.queued_at >= datetime(2026, 11, 11)]
        assert any("offline at the scheduled time" in (r.error or "") for r in failed)


def test_scheduler_fails_runs_nobody_picked_up(admin):
    c, cid = make_collector(admin)
    sc = admin.post("/api/network/scans", json=scan_body(cid)).json()
    assert admin.post(f"/api/network/scans/{sc['id']}/run").status_code == 202
    with db.get_session("default") as s:
        run = s.scalar(select(NetworkScanRun))
        run.queued_at = utcnow() - timedelta(minutes=20)
        s.commit()
    _tick(utcnow())
    got = admin.get(f"/api/network/scans/{sc['id']}").json()
    assert got["last_status"] == "failed" and "did not pick up" in got["last_summary"]["error"]
    # A running scan that goes silent fails too.
    r2 = admin.post(f"/api/network/scans/{sc['id']}/run").json()
    fetch_scan(c)
    with db.get_session("default") as s:
        s.get(NetworkScanRun, r2["id"]).started_at = utcnow() - timedelta(minutes=45)
        s.commit()
    _tick(utcnow())
    assert admin.get(f"/api/network/runs/{r2['id']}").json()["status"] == "failed"


def test_failed_command_result_fails_the_run(admin):
    c, cid = make_collector(admin)
    scan, cmd = scan_run(admin, c, cid)
    r = c.post(f"/api/collector/commands/{cmd['id']}/result", json={"nonce": cmd["nonce"], "status": "failed",
                                                                  "output": "no route to 10.10.1.0/24"})
    assert r.status_code == 204
    run = admin.get(f"/api/network/runs/{cmd['params']['scan_id']}").json()
    assert run["status"] == "failed" and run["error"] == "no route to 10.10.1.0/24"


# ----------------------------------------------------------------------------- tenancy
def test_other_organisation_gets_404(admin):
    c, cid = make_collector(admin)
    cred = create_cred(admin)
    scan, cmd = scan_run(admin, c, cid, [cred["id"]])
    assert post_batch(c, cmd["params"]["scan_id"], 0, [switch_device()], final=True).status_code == 200
    did = admin.get("/api/network/devices").json()[0]["id"]
    create_org("acme", ACME_ADMIN, ACME_PASSWORD)
    acme = org_client(admin.app, ACME_ADMIN, ACME_PASSWORD)
    for path in (f"/api/network/scans/{scan['id']}", f"/api/network/scans/{scan['id']}/runs", f"/api/network/devices/{did}",
                 f"/api/network/devices/{did}/report.pdf", f"/api/network/runs/{cmd['params']['scan_id']}"):
        assert acme.get(path).status_code == 404, path
    for method, path in (("post", f"/api/network/scans/{scan['id']}/run"), ("post", f"/api/network/devices/{did}/rescan"),
                         ("delete", f"/api/network/scans/{scan['id']}"), ("delete", f"/api/network/credentials/{cred['id']}"),
                         ("delete", f"/api/network/devices/{did}")):
        assert getattr(acme, method)(path).status_code == 404, path
    assert acme.patch(f"/api/network/scans/{scan['id']}", json={"name": "x"}).status_code == 404
    assert acme.get("/api/network/devices").json() == [] and acme.get("/api/network/scans").json() == []
    assert acme.get("/api/network/credentials").json() == [] and acme.get("/api/network/summary").json()["devices"] == 0
    assert acme.post("/api/network/scans", json=scan_body(cid)).status_code == 422  # not its collector
    assert acme.post("/api/network/test", json={"collector_id": cid, "address": "10.0.0.5"}).status_code == 404
    assert acme.post("/api/network/devices/add-to-it-assets", json={"device_ids": [did]}).json()["created"] == []
    # Another organisation's collector cannot upload into the run, and its findings / CVEs stay private.
    assert acme.get("/api/findings?source=network").json() == []
    # The finding is invisible to acme (asset and finding ids are per organisation).
    with db.get_session("default") as s:
        fid = s.scalar(select(Finding.id).where(Finding.source == "network"))
        vid = s.scalar(select(Vulnerability.id).where(Vulnerability.network_device_id == did))
    assert acme.get(f"/api/findings/{fid}").status_code == 404 and vid is None


# ----------------------------------------------------------------------------- simulated data
def test_simulated_data_seeds_a_usable_estate(admin):
    from app.network import demo

    with db.get_session("default") as s:
        c = demo.seed_collector(s)
        assert demo.seed(s, c) is True
        assert demo.seed(s, c) is False  # idempotent
        s.commit()
    stats = admin.get("/api/network/summary").json()
    assert stats["devices"] == len(demo.ROWS) and stats["infrastructure"] >= 8 and stats["with_vulns"] == 5 and stats["kev"] >= 3
    assert stats["last_scan"]["status"] == "succeeded" and stats["not_in_it_assets"] > 0
    assert len(admin.get("/api/network/suggestions").json()[0]["items"]) == 5
    types = {d["device_type"] for d in admin.get("/api/network/devices").json()}
    assert {"switch", "firewall", "access_point", "printer", "ups", "camera"} <= types
    findings = admin.get("/api/findings?source=network").json()
    assert {f["rule_id"] for f in findings} >= {"NET-SNMP-001", "NET-TELNET-001", "NET-HTTP-001", "NET-FW-001", "NET-FDB-001", "NET-SMB-001"}
    core = next(d for d in admin.get("/api/network/devices").json() if d["name"] == "hq-core-sw01")
    detail = admin.get(f"/api/network/devices/{core['id']}").json()
    assert detail["fixes"][0]["target"] == "17.3.8a" and detail["connected"]["rows"] == [] and detail["it_asset"]["asset_tag"]


def test_old_collectors_are_refused_and_scans_get_a_long_expiry(admin):
    old, old_id = enroll_collector(admin, "OLD01", machine="d" * 64)  # no network_discovery feature
    assert admin.post("/api/network/test", json={"collector_id": old_id, "address": "10.0.0.5"}).status_code == 409
    assert "1.6.0" in admin.post("/api/network/suggestions/refresh", json={"collector_id": old_id}).text
    c, cid = make_collector(admin)
    assert "network_discovery" in next(x for x in admin.get("/api/collectors").json() if x["id"] == cid)["features"]
    scan, cmd = scan_run(admin, c, cid)
    exp = datetime.fromisoformat(cmd["expires_at"].rstrip("Z"))
    assert timedelta(hours=5, minutes=50) < exp - utcnow() <= timedelta(hours=6)
    dev = {"ip": "10.10.1.5", "alive_via": ["snmp", "icmp"], "default_community": "public",
           "fdb": [{"mac": "aa:bb:cc:dd:ee:01", "port_name": "x", "vlan": 0}]}
    assert post_batch(c, cmd["params"]["scan_id"], 0, [dev]).status_code == 200


def test_batch_schema_accepts_collector_output():
    """A batch marshalled by the Go collector (internal/netscan Batch, every field set) validates.
    Regression: a host alive via icmp, arp, tcp and snmp (4 entries) was refused, which stopped the scan."""
    import json
    from pathlib import Path

    from app.network.schemas import NetBatchIn

    raw = json.loads((Path(__file__).parent / "fixtures" / "network_batch_from_collector.json").read_text())
    b = NetBatchIn.model_validate(raw)
    assert b.devices[0].alive_via == ["icmp", "arp", "tcp", "snmp"]
    assert b.devices[0].default_community == "public" and b.devices[0].snmp.version == "v3"
    assert b.devices[1].snmp is None and b.devices[1].default_community is None
    assert b.final and b.summary.alive == 2


def test_sophos_cves_are_matched_under_every_nvd_product_name(admin, fake_feeds):
    # NVD files Sophos Firewall CVEs under several names; one SFOS 19.0.1 firewall is checked against all of them.
    sfos = "cpe:2.3:o:sophos:sfos"
    fake_feeds.nvd[sfos] = [
        cve("CVE-2022-1040", "Sophos Firewall authentication bypass.", cvss31(9.8, "critical"),
            [{"nodes": [node(m(f"{sfos}:*:*:*:*:*:*:*:*", versionEndIncluding="18.5.3"))]}])]
    fake_feeds.nvd["cpe:2.3:a:sophos:firewall"] = [
        cve("CVE-2022-3236", "Sophos Firewall code injection.", cvss31(9.8, "critical"),
            [{"nodes": [node(m("cpe:2.3:a:sophos:firewall:*:*:*:*:*:*:*:*", versionEndIncluding="19.0.1"))]}])]
    fake_feeds.nvd["cpe:2.3:o:sophos:firewall_firmware"] = [
        cve("CVE-2024-12727", "Sophos Firewall SQL injection.", cvss31(9.8, "critical"),
            [{"nodes": [node(m("cpe:2.3:o:sophos:firewall_firmware:*:*:*:*:*:*:*:*", versionEndExcluding="21.0.1"))]}])]
    c, cid = make_collector(admin)
    scan, cmd = scan_run(admin, c, cid)
    fw = switch_device(ip="10.10.1.254", mac="00:1a:8c:00:00:01", fdb=[], interfaces=[],
                       snmp={"version": "v3", "credential_id": "c1", "sys_name": "hq-fw", "sys_descr": SFOS_DESCR,
                             "sys_object_id": "1.3.6.1.4.1.2604.5"},
                       vendor="Sophos", model="XGS2100_RL01_SFOS", firmware="19.0.1 MR-1-Build365",
                       serial="X21987654321012", device_type="firewall")
    assert post_batch(c, cmd["params"]["scan_id"], 0, [fw], final=True).status_code == 200
    worker.run_once(force=True)
    d = admin.get("/api/network/devices").json()[0]
    assert (d["vendor"], d["device_type"]) == ("Sophos", "firewall")
    detail = admin.get(f"/api/network/devices/{d['id']}").json()
    assert sorted(v["cve_id"] for v in detail["vulnerabilities"]) == ["CVE-2022-3236", "CVE-2024-12727"]
    assert {v["package"] for v in detail["vulnerabilities"]} == {"Sophos SFOS"}
