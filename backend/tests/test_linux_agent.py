"""Linux server agent (agent 1.7.0): check-in schema, posture issues, OSV matching of the agent's packages
(Amazon Linux reported as not matched), command refusal, one record per server with the runtime sensor, signed
.deb / .rpm packages in the release bundle and the Linux enrolment file."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from app import config, db
from app.models import Asset, AssetPackage, Device, DeviceSoftware, Vulnerability, VulnMatchState
from app.services import agent_updates as updates
from app.vulnmatch import feeds, worker
from tests.conftest import AUTH
from tests.test_devices import agent_client, enroll, new_token
from tests.vuln_fakes import FakeFeeds

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
import agent_release as rel_tool  # noqa: E402

DEB_SW = [
    {"name": "libssl3", "version": "3.0.11-1~deb12u2", "source": "dpkg", "ecosystem": "Debian:12", "source_name": "openssl"},
    {"name": "openssl", "version": "3.0.11-1~deb12u2", "source": "dpkg", "ecosystem": "Debian:12"},
    {"name": "bash", "version": "5.2.15-2+b2", "source": "dpkg", "ecosystem": "Debian:12", "source_name": "bash",
     "source_version": "5.2.15-2"},
]
MACHINE_HASH = "c" * 64


@pytest.fixture()
def fake():
    f = FakeFeeds()
    feeds.set_transport(f.transport(), f.sleep)
    yield f
    feeds.set_transport(None)


@pytest.fixture()
def admin(empty_client):
    return empty_client


def linux_checkin(hostname="web-1", software=None, posture=None, os_name="Debian GNU/Linux 12 (bookworm)",
                  os_version="12", classification=None, **device):
    body = {
        "schema_version": 1, "collected_at": "2026-11-11T10:00:00Z",
        "device": {"hostname": hostname, "os_family": "linux", "os_name": os_name, "os_version": os_version,
                   "os_build": "6.1.0-25-amd64", "architecture": "amd64", "serial_number": "", "manufacturer": "Xen",
                   "model": "HVM domU", "cpu": "Intel Xeon", "cpu_cores": 2, "memory_bytes": 8 << 30,
                   "disks": [{"mount": "/", "filesystem": "ext4", "size_bytes": 100 << 30, "free_bytes": 60 << 30}],
                   "uptime_seconds": 3600, "logged_in_users": ["deploy"],
                   "network": [{"name": "eth0", "mac": "00:11:22:33:44:55", "ips": ["10.0.0.7"]}],
                   "agent_version": "1.7.0",
                   "classification": classification or {"role": "server", "role_source": "linux_agent",
                                                        "form_factor": "other", "is_virtual": True, "hypervisor": "xen",
                                                        "cloud_provider": "aws", "cloud_instance_id": "i-0abc123def4567890"},
                   **device},
        "posture": posture if posture is not None else {
            "security_updates": {"status": "pass", "detail": "No security updates are pending.",
                                 "data": {"security_updates": 0, "pending_updates": 3, "package_manager": "apt"}},
            "ssh_root_login": {"status": "info", "detail": "Root can log in with a key only."},
        },
        "software": [dict(s) for s in (DEB_SW if software is None else software)],
        "services": [{"name": "ssh.service", "display_name": "OpenBSD Secure Shell server", "status": "running",
                      "start_type": "auto"}],
        "errors": {},
    }
    return body


def new_linux(admin, hostname="web-1", machine="d" * 64, **kw):
    token = new_token(admin)
    agent = agent_client(admin.app)
    r = enroll(agent, token, machine_id=machine, os_family="linux", hostname=hostname)
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    agent.headers["User-Agent"] = "cnapp-agent/1.7.0 (linux; amd64)"
    r = agent.post("/api/agent/checkin", json=linux_checkin(hostname=hostname, **kw))
    assert r.status_code == 200, r.text
    return agent, r.json()["device_id"]


def run():
    return worker.run_once(force=True)


def device_vulns(device_id, status="open"):
    with db.get_session("default") as s:
        return {v.cve_id: v for v in s.scalars(select(Vulnerability).where(
            Vulnerability.device_id == device_id, Vulnerability.status == status))}


# --------------------------------------------------------------------------- check-in, issues, packages
def test_linux_checkin_is_accepted_and_stored(admin):
    _, dev = new_linux(admin)
    d = admin.get(f"/api/devices/{dev}").json()
    assert d["os_family"] == "linux" and d["device_class"] == "server" and d["cloud_provider"] == "aws"
    assert d["posture"]["security_updates"]["data"]["package_manager"] == "apt"
    sw = {s["name"]: s for s in admin.get(f"/api/devices/{dev}/software").json()}
    assert sw["libssl3"]["ecosystem"] == "Debian:12" and sw["libssl3"]["source_name"] == "openssl"
    assert sw["bash"]["source_version"] == "5.2.15-2" and sw["bash"]["source"] == "dpkg"
    assert [s["name"] for s in admin.get(f"/api/devices/{dev}/services").json()] == ["ssh.service"]
    # the updates column of the Devices list comes from the posture checks
    row = admin.get("/api/devices", params={"os": "linux"}).json()[0]
    assert row["os_updates"]["security"] == 0 and row["os_updates"]["source"] == "apt"
    assert row["os_updates"]["reboot_pending"] is False


def test_failing_linux_checks_raise_issues(admin):
    post = {
        "security_updates": {"status": "fail", "detail": "14 security updates waiting.",
                             "data": {"security_updates": 14, "pending_updates": 20, "package_manager": "apt",
                                      "cache_age_hours": 6}},
        "reboot_required": {"status": "fail", "detail": "A newer kernel is installed but not running."},
        "ssh_root_login": {"status": "fail", "detail": "Root can log in over SSH with a password."},
        "ssh_password_login": {"status": "fail", "detail": "Password login is allowed."},
        "admin_accounts": {"status": "fail", "detail": "1 extra UID 0 account (toor)."},
        "firewall": {"status": "fail", "detail": "No active host firewall."},
        "disk_encryption": {"status": "info", "detail": "No LUKS volumes (cloud)."},
        "endpoint_protection": {"status": "fail", "detail": "None found."},
        "mandatory_access_control": {"status": "fail", "detail": "Neither is enforcing."},
        "audit_logging": {"status": "fail", "detail": "auditd is not installed."},
        "time_sync": {"status": "fail", "detail": "Not synchronised."},
        "auto_updates": {"status": "fail", "detail": "Not enabled."},
    }
    _, dev = new_linux(admin, posture=post)
    codes = {i["code"] for i in admin.get(f"/api/devices/{dev}").json()["issues"]}
    assert codes == {"os_security_updates_missing", "os_reboot_pending", "ssh_root_login_allowed",
                     "ssh_password_login_allowed", "admin_accounts_risky", "firewall_off", "endpoint_protection_off",
                     "mac_not_enforcing", "audit_logging_off", "time_not_synced", "auto_updates_off"}
    types = {i["code"] for i in admin.get("/api/devices/issue-types").json()}
    assert codes <= types
    row = admin.get("/api/devices", params={"os": "linux"}).json()[0]
    assert row["os_updates"]["security"] == 14 and row["os_updates"]["reboot_pending"] is True
    assert row["os_updates"]["cache_age_hours"] == 6
    # info and unknown never raise issues
    _, dev2 = new_linux(admin, hostname="web-2", machine="e" * 64, posture={
        "ssh_root_login": {"status": "info", "detail": "key only"},
        "security_updates": {"status": "unknown", "detail": "cache is 9 days old"}})
    assert admin.get(f"/api/devices/{dev2}").json()["issues"] == []


def test_unknown_posture_field_is_still_rejected(admin):
    token = new_token(admin)
    agent = agent_client(admin.app)
    r = enroll(agent, token, machine_id="f" * 64, os_family="linux", hostname="x")
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    body = linux_checkin(hostname="x")
    body["software"][0]["surprise"] = "1"
    assert agent.post("/api/agent/checkin", json=body).status_code == 422


# --------------------------------------------------------------------------- vulnerability matching (OSV)
def test_agent_packages_are_matched_through_osv(admin, fake):
    _, dev = new_linux(admin)
    assert fake.requests == []  # the check-in never talks to a feed
    res = run()
    assert f"device:{dev}" in res.matched
    found = device_vulns(dev)
    assert set(found) == {"CVE-2023-5678", "CVE-2023-5363"}
    v = found["CVE-2023-5678"]
    assert v.source == "osv" and v.package == "openssl" and v.version == "3.0.11-1~deb12u2"
    assert v.fixed_version == "3.0.13-1~deb12u1" and v.device_id == dev and v.asset_id is None
    assert v.evidence["binaries"] == ["libssl3", "openssl"]
    detail = admin.get(f"/api/devices/{dev}/vulnerabilities").json()
    assert {x["cve_id"] for x in detail["vulnerabilities"]} == set(found)
    assert detail["os"]["matching"] == "osv"
    # upgrade: resolved
    agent, _ = new_linux(admin, hostname="web-1", machine="d" * 64, software=[
        {**p, "version": "3.0.15-1~deb12u1", "source_version": "3.0.15-1~deb12u1"} if p["name"] != "bash" else p
        for p in DEB_SW])
    run()
    assert device_vulns(dev) == {}
    assert "CVE-2023-5678" in device_vulns(dev, "resolved")


def test_amazon_linux_is_reported_but_not_matched(admin, fake):
    sw = [{"name": "openssl-libs", "version": "1:3.0.8-1.amzn2023.0.14", "source": "rpm", "ecosystem": "",
           "source_name": "openssl"}]
    _, dev = new_linux(admin, hostname="build-1", machine="a1" * 32, software=sw, os_name="Amazon Linux 2023",
                       os_version="2023")
    run()
    assert device_vulns(dev) == {} and fake.count("osv.invalid") == 0  # nothing was sent to OSV
    detail = admin.get(f"/api/devices/{dev}/vulnerabilities").json()
    assert detail["os"]["matching"] == "not_matched" and detail["checked"] == []
    assert any("Not matched" in n["reason"] and "Amazon Linux 2023" in n["reason"] for n in detail["not_checked"])


def test_rpm_packages_use_the_rpm_version_and_binary_name(admin, fake):
    sw = [{"name": "openssl-libs", "version": "1:3.0.7-27.el9", "source": "rpm", "ecosystem": "Rocky Linux:9",
           "source_name": "openssl"}]
    _, dev = new_linux(admin, hostname="db-1", machine="b2" * 32, software=sw, os_name="Rocky Linux 9.4",
                       os_version="9.4")
    fake.osv_queries[("Rocky Linux:9", "openssl-libs", "1:3.0.7-27.el9")] = []
    run()
    detail = admin.get(f"/api/devices/{dev}/vulnerabilities").json()
    assert [c["name"] for c in detail["checked"]] == ["openssl-libs"]  # not the source package, unlike Debian


# --------------------------------------------------------------------------- commands
def test_linux_servers_refuse_desktop_commands(admin):
    _, dev = new_linux(admin)
    for t in ("lock_device", "enable_lost_mode", "isolate_host", "restore_host", "block_usb_storage", "manage_service"):
        r = admin.post(f"/api/devices/{dev}/commands", json={"type": t, "reason": "test reason", "params": {}})
        assert r.status_code in (409, 422), (t, r.text)
        if r.status_code == 409:
            assert "not available on Linux servers" in r.json()["detail"] or "Linux" in r.json()["detail"], r.text
    for t in ("recheck_posture", "collect_logs", "restart_agent", "check_for_update"):
        r = admin.post(f"/api/devices/{dev}/commands", json={"type": t, "reason": "test reason", "params": {}})
        assert r.status_code == 201, (t, r.text)
    assert admin.post(f"/api/devices/{dev}/commands", json={
        "type": "update_check_in_interval", "reason": "test reason", "params": {"interval_seconds": 900}}).status_code == 201
    # wipe goes through approvals, scripts through /api/scripts/run, remote sessions through their own API
    r = admin.post(f"/api/devices/{dev}/remote-sessions", json={"mode": "view", "reason": "test reason"})
    assert r.status_code in (409, 422) and "Linux" in r.text
    r = admin.post("/api/scripts/run", json={"device_id": dev, "script": "macos-list-local-admins", "parameters": {},
                                             "reason": "test reason"})
    assert r.status_code == 409 and "Linux" in r.json()["detail"]
    r = admin.post(f"/api/devices/{dev}/os-updates/scan", json={})
    assert r.status_code == 409


# --------------------------------------------------------------------------- agent + sensor on the same server
SENSOR_INV = {
    "schema_version": "1.1", "sensor_id": "web-1", "host": "web-1", "collected_at": "2026-11-11T10:00:00Z",
    "os": {"id": "debian", "version_id": "12", "pretty_name": "Debian GNU/Linux 12 (bookworm)"}, "cloud": None,
    "packages": [
        {"name": "libssl3", "version": "3.0.11-1~deb12u2", "kind": "deb", "source_name": "openssl",
         "source_version": "3.0.11-1~deb12u2", "ecosystem": "Debian:12"},
        {"name": "openssl", "version": "3.0.11-1~deb12u2", "kind": "deb", "source_name": "openssl",
         "ecosystem": "Debian:12"},
    ],
}


def sensor_vulns(asset_id="sensor:web-1", status="open"):
    with db.get_session("default") as s:
        return {v.cve_id for v in s.scalars(select(Vulnerability).where(
            Vulnerability.asset_id == asset_id, Vulnerability.status == status))}


def asset_packages(asset_id="sensor:web-1"):
    with db.get_session("default") as s:
        return s.scalars(select(AssetPackage).where(AssetPackage.asset_id == asset_id)).all()


def test_agent_wins_over_a_sensor_that_was_there_first_by_hostname(admin, client, fake):
    assert client.post("/api/runtime/packages", json=SENSOR_INV, headers=AUTH).status_code == 202
    run()
    assert sensor_vulns() == {"CVE-2023-5678", "CVE-2023-5363"} and len(asset_packages()) == 2
    # the agent appears on the same server: its package list replaces the sensor's, no double counting
    _, dev = new_linux(client)
    assert asset_packages() == []
    assert sensor_vulns() == set() and sensor_vulns(status="resolved") == {"CVE-2023-5678", "CVE-2023-5363"}
    with db.get_session("default") as s:
        a = s.get(Asset, ("default", "sensor:web-1"))
        assert a.properties["package_source"] == "agent" and a.properties["agent_device_id"] == dev
        assert s.scalar(select(VulnMatchState).where(VulnMatchState.target_id == "sensor:web-1")) is None
    run()
    assert set(device_vulns(dev)) == {"CVE-2023-5678", "CVE-2023-5363"}
    # the sensor keeps reporting: its list is ignored while the agent checks in
    r = client.post("/api/runtime/packages", json=SENSOR_INV, headers=AUTH)
    assert r.status_code == 202 and r.json()["superseded_by_agent"] is True and r.json()["packages"] == 0
    assert r.json()["agent_device_id"] == dev and asset_packages() == []
    run()
    assert sensor_vulns() == set()
    total = len(device_vulns(dev)) + len(sensor_vulns())
    assert total == 2  # one record per server: each CVE counted once


def test_agent_first_then_sensor_matches_by_machine_id_and_cloud_id(admin, client, fake):
    _, dev = new_linux(client, hostname="ip-10-0-0-7", machine=MACHINE_HASH)
    # different host name, same machine id
    r = client.post("/api/runtime/packages", json={**SENSOR_INV, "host": "something-else", "machine_id": MACHINE_HASH},
                    headers=AUTH)
    assert r.json()["superseded_by_agent"] is True and r.json()["agent_device_id"] == dev
    # different host name, the agent's AWS instance id is in the sensor's cloud resource id
    inv = {**SENSOR_INV, "host": "other-name",
           "cloud": {"provider": "aws", "resource_id": "arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc123def4567890"}}
    r = client.post("/api/runtime/packages", json=inv, headers=AUTH)
    assert r.json()["superseded_by_agent"] is True
    # an unrelated host is untouched
    r = client.post("/api/runtime/packages", json={**SENSOR_INV, "host": "batch-9", "sensor_id": "batch-9"}, headers=AUTH)
    assert r.json()["superseded_by_agent"] is False and r.json()["packages"] == 2


def test_ambiguous_hostname_is_not_linked(admin, client):
    new_linux(client, hostname="dup", machine="1" * 64)
    new_linux(client, hostname="DUP.example.com", machine="2" * 64)
    r = client.post("/api/runtime/packages", json={**SENSOR_INV, "host": "dup", "sensor_id": "dup"}, headers=AUTH)
    assert r.json()["superseded_by_agent"] is False  # two agents claim the name: never guess


def test_a_silent_agent_no_longer_wins(admin, client):
    _, dev = new_linux(client)
    from datetime import timedelta

    from app.models import utcnow

    with db.get_session("default") as s:
        d = s.get(Device, dev)
        d.last_checkin_at = utcnow() - timedelta(days=updates_days() + 1)
        s.commit()
    r = client.post("/api/runtime/packages", json=SENSOR_INV, headers=AUTH)
    assert r.json()["superseded_by_agent"] is False and r.json()["packages"] == 2


def updates_days() -> int:
    from app.services import linux_agent

    return linux_agent.AGENT_FRESH_DAYS


# --------------------------------------------------------------------------- signed .deb / .rpm in the release bundle
@pytest.fixture()
def key(monkeypatch):
    k = Ed25519PrivateKey.generate()
    monkeypatch.setenv("AGENT_UPDATE_TRUSTED_KEYS", rel_tool.trusted_line(k))
    config.reload_settings()
    yield k
    monkeypatch.delenv("AGENT_UPDATE_TRUSTED_KEYS")
    config.reload_settings()


def linux_bundle(tmp_path: Path, version: str, key, *, tamper=False, rpm_missing=False) -> bytes:
    bins, pkgs = [], []
    for goos, arch in (("windows", "amd64"), ("linux", "amd64"), ("linux", "arm64")):
        p = tmp_path / f"cnapp-agent-{goos}-{arch}{'.exe' if goos == 'windows' else ''}"
        p.write_bytes(f"binary {version} {goos}/{arch}".encode() * 50)
        bins.append(p)
    for name in (f"cnapp-agent_{version}_amd64.deb", f"cnapp-agent_{version}_arm64.deb",
                 f"cnapp-agent-{version}-1.x86_64.rpm", f"cnapp-agent-{version}-1.aarch64.rpm"):
        p = tmp_path / name
        p.write_bytes(f"package {name}".encode() * 80)
        pkgs.append(p)
    m = rel_tool.build_manifest(version, bins, days=30, min_supported="0.0.0", notes="linux test", rollback_from=[],
                                packages=pkgs)
    env = rel_tool.sign_manifest(m, [key])
    if tamper:
        pkgs[0].write_bytes(b"evil" + pkgs[0].read_bytes()[4:])
    out = tmp_path / f"bundle-{version}.tar.gz"
    rel_tool.write_bundle(out, env, bins, packages=pkgs[:3] if rpm_missing else pkgs)
    return out.read_bytes()


def upload(c, data: bytes):
    return c.post("/api/updates/releases", content=data, headers={"Content-Type": "application/gzip"})


def test_release_bundle_carries_signed_linux_packages(admin, key, tmp_path, monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://cnapp.example.com")
    config.reload_settings()
    info = admin.get("/api/devices/installers").json()
    assert not any(p["available"] for p in info["linux_packages"])
    assert admin.get("/api/devices/installers/linux/deb/amd64").status_code == 404

    r = upload(admin, linux_bundle(tmp_path, "1.7.0", key))
    assert r.status_code == 201, r.text
    info = admin.get("/api/devices/installers").json()
    pk = {(p["format"], p["arch"]): p for p in info["linux_packages"]}
    assert len(pk) == 4 and all(p["available"] and p["version"] == "1.7.0" for p in pk.values())
    r = admin.get("/api/devices/installers/linux/rpm/arm64")
    assert r.status_code == 200 and r.headers["content-disposition"].endswith('cnapp-agent-1.7.0-1.aarch64.rpm"')
    assert r.headers["x-content-sha256"] == hashlib.sha256(r.content).hexdigest() == pk[("rpm", "arm64")]["sha256"]
    # Linux binaries are real update artifacts
    with db.get_session("default") as s:
        rel = s.scalar(select(updates.AgentRelease))
        assert {(a.os, a.arch) for a in rel.artifacts} == {("windows", "amd64"), ("linux", "amd64"), ("linux", "arm64")}
    # the newest release with packages wins
    assert upload(admin, linux_bundle(tmp_path, "1.7.1", key)).status_code == 201
    assert admin.get("/api/devices/installers/linux/deb/amd64").headers["x-agent-version"] == "1.7.1"
    # RBAC: only admins download installers
    assert admin.get("/api/devices/installers/linux/deb/bogus").status_code == 422


def test_tampered_or_incomplete_package_set_is_refused(admin, key, tmp_path):
    r = upload(admin, linux_bundle(tmp_path, "1.7.0", key, tamper=True))
    assert r.status_code == 422 and "SHA-256 does not match" in json.dumps(r.json())
    r = upload(admin, linux_bundle(tmp_path / "x" if (tmp_path / "x").mkdir() is None else tmp_path, "1.7.2", key,
                                   rpm_missing=True))
    assert r.status_code == 422 and "missing" in json.dumps(r.json())


def test_package_entries_are_validated_in_the_manifest(key):
    base = {"schema": 1, "product": "cnapp-agent", "version": "1.7.0", "min_supported_version": "0.0.0",
            "released_at": "2026-11-11T00:00:00Z", "expires_at": "2027-05-11T00:00:00Z",
            "artifacts": [{"os": "linux", "arch": "amd64", "name": "cnapp-agent-linux-amd64", "sha256": "a" * 64,
                           "size": 10}]}
    good = {"format": "deb", "arch": "amd64", "name": "cnapp-agent_1.7.0_amd64.deb", "sha256": "b" * 64, "size": 10}
    updates._check_packages({**base, "packages": [good]})
    for bad in ({**good, "format": "msi"}, {**good, "arch": "386"}, {**good, "name": "../x.deb"},
                {**good, "name": "x.rpm"}, {**good, "sha256": "zz"}, {**good, "size": 0}):
        with pytest.raises(updates.ReleaseError):
            updates._check_packages({**base, "packages": [bad]})
    with pytest.raises(updates.ReleaseError):
        updates._check_packages({**base, "packages": [good, good]})


# --------------------------------------------------------------------------- Linux enrolment file
def test_linux_enrolment_file_carries_server_and_token_never_a_url(admin, monkeypatch):
    from app.api import devices as devices_api

    monkeypatch.setenv("PUBLIC_BASE_URL", "https://cnapp.example.com")
    config.reload_settings()
    devices_api.installer_limiter.reset()
    r = admin.post("/api/devices/installers", json={"platform": "linux-enroll", "max_devices": 5, "expires_in_days": 3,
                                                    "device_group": "Linux servers", "include_ca": False})
    assert r.status_code == 200, r.text
    assert r.headers["content-disposition"] == 'attachment; filename="cnapp-agent-enroll.json"'
    assert r.headers["cache-control"] == "no-store"
    cfg = json.loads(r.content)
    assert cfg["version"] == 1 and cfg["server_url"] == "https://cnapp.example.com" and cfg["token"].startswith("cne_")
    assert "ca_pem" not in cfg and "allow_wipe" not in cfg
    tok = admin.get("/api/devices/enrollment-tokens").json()[0]
    assert tok["package_platform"] == "linux-enroll" and tok["device_group"] == "Linux servers" and "token" not in tok
    assert cfg["token"] not in json.dumps(admin.get("/api/audit-log").json())
    # it enrolls a Linux server into the group
    agent = agent_client(admin.app)
    assert enroll(agent, cfg["token"], machine_id="9" * 64, os_family="linux", hostname="srv-1").status_code == 200
    assert admin.get("/api/devices").json()[0]["device_group"] == "Linux servers"
    # wipe is Windows only
    r = admin.post("/api/devices/installers", json={"platform": "linux-enroll", "allow_wipe": True})
    assert r.status_code == 422


def test_device_software_has_the_linux_columns():
    """0030_linux_agent adds them (tests/test_database.py compares the migrated schema with the ORM)."""
    cols = {c.name for c in DeviceSoftware.__table__.columns}
    assert {"ecosystem", "source_name", "source_version"} <= cols
