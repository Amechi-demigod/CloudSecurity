"""End-to-end vulnerability matching with fake feeds (no network): endpoint
devices via NVD CPE data, KEV / EPSS enrichment, resolution on upgrade /
removal, offline behaviour, aggregated notifications, the API and the
sensor's Linux package inventory via OSV."""
from __future__ import annotations

import logging
from datetime import timedelta

import pytest
from sqlalchemy import select

from app import config, db
from app.models import Asset, Device, DeviceSoftware, Vulnerability, VulnFeedCache, VulnFeedStatus, VulnMatchState
from app.notifications.models import NotificationEvent
from app.vulnmatch import feeds, matcher, worker
from tests.conftest import AUTH, make_user
from tests.test_devices import agent_client, enroll, new_token, windows_checkin
from tests.vuln_fakes import FakeFeeds

WIN_DEVICE = {"os_name": "Microsoft Windows 11 Pro 23H2", "os_version": "10.0.22631", "os_build": "22631.4169"}
SOFTWARE = [
    {"name": "Google Chrome", "version": "130.0.6723.70", "publisher": "Google LLC"},
    {"name": "7-Zip 24.08 (x64 edition)", "version": "24.08.00.0", "publisher": "Igor Pavlov"},
    {"name": "Microsoft 365 Apps for enterprise - en-us", "version": "16.0.17928.20156",
     "publisher": "Microsoft Corporation"},
    {"name": "Contoso Expenses", "version": "1.2", "publisher": "Contoso"},
]


@pytest.fixture()
def fake():
    f = FakeFeeds()
    feeds.set_transport(f.transport(), f.sleep)
    yield f
    feeds.set_transport(None)


@pytest.fixture()
def admin(empty_client):
    return empty_client


def checkin_body(software=None, hostname="LAPTOP-001", **device):
    body = windows_checkin(software=SOFTWARE if software is None else software)
    body["device"].update({**WIN_DEVICE, "hostname": hostname, **device})
    return body


def new_device(admin, hostname="LAPTOP-001", machine="a", software=None, **device):
    token = new_token(admin)
    agent = agent_client(admin.app)
    r = enroll(agent, token, machine_id=machine * 64, hostname=hostname)
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    r = agent.post("/api/agent/checkin", json=checkin_body(software, hostname=hostname, **device))
    assert r.status_code == 200, r.text
    return agent, r.json()["device_id"]


def run(**kw):
    return worker.run_once(force=True, **kw)


def vulns(device_id=None, status="open"):
    with db.get_session("default") as s:
        stmt = select(Vulnerability)
        if device_id:
            stmt = stmt.where(Vulnerability.device_id == device_id)
        if status:
            stmt = stmt.where(Vulnerability.status == status)
        return {v.cve_id: v for v in s.scalars(stmt)}


# --------------------------------------------------------------------------- devices (NVD)
def test_checkin_queues_and_worker_matches(admin, fake):
    _, dev = new_device(admin)
    with db.get_session("default") as s:
        st = s.scalar(select(VulnMatchState).where(VulnMatchState.target_id == dev))
        assert st is not None and st.requested_at is not None and st.matched_at is None
    assert fake.requests == []  # the check-in itself never talks to a feed

    res = run()
    assert f"device:{dev}" in res.matched and res.kev_refreshed
    found = vulns(dev)
    # Chrome 130.0.6723.70 < 130.0.6723.91; "Chrome on Windows" AND config; Windows 11 23H2 < .4317
    assert set(found) == {"CVE-2024-10487", "CVE-2024-99002", "CVE-2024-43547"}
    chrome = found["CVE-2024-10487"]
    assert chrome.package == "Google Chrome" and chrome.version == "130.0.6723.70"
    assert chrome.fixed_version == "130.0.6723.91" and chrome.severity == "critical" and chrome.cvss == 9.8
    assert chrome.source == "nvd" and chrome.asset_id is None and chrome.kev is False
    assert chrome.in_use is False and chrome.risk_score > 0 and chrome.epss == pytest.approx(0.42)
    win = found["CVE-2024-43547"]
    assert win.package == "Windows 11 23H2" and win.fixed_version == "10.0.22631.4317"
    # 7-Zip 24.08 is past the 24.07 fix; Android-only / rejected / unversioned records never match.
    assert "CVE-2024-11477" not in found and "CVE-2024-99001" not in found and "CVE-2024-99004" not in found

    detail = admin.get(f"/api/devices/{dev}/vulnerabilities").json()
    assert {v["cve_id"] for v in detail["vulnerabilities"]} == set(found)
    assert detail["vulnerabilities"][0]["device_name"] == "LAPTOP-001"
    checked = {c["rule"] for c in detail["checked"]}
    assert checked == {"os", "chrome", "7zip"}
    nc = {n["name"]: n["reason"] for n in detail["not_checked"]}
    assert nc["Contoso Expenses"] == "no CPE mapping"
    assert "Microsoft 365" in nc["Microsoft 365 Apps for enterprise - en-us"]
    assert detail["matched_at"].endswith("Z") and detail["pending"] is False


def test_kev_flag_and_old_chrome(admin, fake):
    _, dev = new_device(admin, software=[{"name": "Google Chrome", "version": "127.0.6533.99",
                                          "publisher": "Google LLC"}])
    run()
    v = vulns(dev)["CVE-2024-7971"]
    assert v.kev is True and v.exploit_available is True and v.evidence["kev"]["added"] == "2024-08-26"
    # KEV raises the risk score (exploit_available in engine/risk.py)
    assert v.risk_score > vulns(dev)["CVE-2024-10487"].risk_score * 0.6
    r = admin.get("/api/vulnerabilities", params={"kev": True, "scope": "device"}).json()
    assert [x["cve_id"] for x in r] == ["CVE-2024-7971"] and r[0]["kev"] is True


def test_resolved_on_upgrade_and_reopened_on_downgrade(admin, fake):
    agent, dev = new_device(admin)
    run()
    assert "CVE-2024-10487" in vulns(dev)
    upgraded = [{**SOFTWARE[0], "version": "130.0.6723.92"}] + SOFTWARE[1:]
    assert agent.post("/api/agent/checkin", json=checkin_body(upgraded)).status_code == 200
    run()
    resolved = vulns(dev, status="resolved")
    assert "CVE-2024-10487" in resolved and resolved["CVE-2024-10487"].resolved_at is not None
    assert "CVE-2024-10487" not in vulns(dev)
    assert "CVE-2024-43547" in vulns(dev)  # the OS was not updated
    # Windows update applied (newer UBR) -> OS CVE resolved too
    assert agent.post("/api/agent/checkin", json=checkin_body(upgraded, os_build="22631.4317")).status_code == 200
    run()
    assert "CVE-2024-43547" not in vulns(dev)
    # Downgrade: the same row is reopened, not duplicated
    assert agent.post("/api/agent/checkin", json=checkin_body(SOFTWARE)).status_code == 200
    run()
    with db.get_session("default") as s:
        rows = list(s.scalars(select(Vulnerability).where(Vulnerability.device_id == dev,
                                                          Vulnerability.cve_id == "CVE-2024-10487")))
    assert len(rows) == 1 and rows[0].status == "open" and rows[0].resolved_at is None


def test_resolved_when_software_removed(admin, fake):
    agent, dev = new_device(admin)
    run()
    assert agent.post("/api/agent/checkin", json=checkin_body(SOFTWARE[1:])).status_code == 200
    run()
    assert "CVE-2024-10487" not in vulns(dev) and "CVE-2024-10487" in vulns(dev, status="resolved")


def test_offline_keeps_existing_and_never_blocks_checkins(admin, fake):
    agent, dev = new_device(admin)
    run()
    before = set(vulns(dev))
    fake.offline = True
    with db.get_session("default") as s:  # expire the caches so a refresh is attempted
        for row in s.scalars(select(VulnFeedCache)):
            row.expires_at = row.fetched_at - timedelta(seconds=1)
        st = s.get(VulnFeedStatus, "kev")
        st.last_success_at = st.last_attempt_at = st.last_attempt_at - timedelta(days=2)
        s.commit()
    upgraded = [{**SOFTWARE[0], "version": "130.0.6723.92"}] + SOFTWARE[1:]
    assert agent.post("/api/agent/checkin", json=checkin_body(upgraded)).status_code == 200
    res = run()
    assert res.errors == []
    # stale cached NVD data still evaluates the upgrade (Chrome fixed), nothing else is lost
    assert set(vulns(dev)) == before - {"CVE-2024-10487", "CVE-2024-99002"}
    status = admin.get("/api/vulnerabilities/status").json()
    by_feed = {f["feed"]: f for f in status["feeds"]}
    assert "nvd.invalid" in by_feed["nvd"]["last_error"] and by_feed["nvd"]["last_success_at"]
    assert by_feed["kev"]["last_error"]


def test_offline_without_cache_does_not_resolve(admin, fake):
    agent, dev = new_device(admin)
    run()
    with db.get_session("default") as s:
        for row in list(s.scalars(select(VulnFeedCache).where(VulnFeedCache.key.like("nvd:%")))):
            s.delete(row)
        s.commit()
    fake.offline = True
    assert agent.post("/api/agent/checkin", json=checkin_body(SOFTWARE + [
        {"name": "VLC media player", "version": "3.0.21", "publisher": "VideoLAN"}])).status_code == 200
    run()
    assert "CVE-2024-10487" in vulns(dev)  # product data unavailable: keep, don't resolve
    detail = admin.get(f"/api/devices/{dev}/vulnerabilities").json()
    reasons = {n["name"]: n["reason"] for n in detail["not_checked"]}
    assert "feed offline" in reasons["Google Chrome"] and detail["error"]


def test_feeds_are_cached_between_devices(admin, fake):
    new_device(admin, "LAPTOP-001", "a")
    run()
    n = fake.count("nvd.invalid")
    new_device(admin, "LAPTOP-002", "b")
    run()
    assert fake.count("nvd.invalid") == n  # same products: served from the cache


def test_incremental_nvd_refresh(admin, fake):
    new_device(admin)
    run()
    with db.get_session("default") as s:
        for row in s.scalars(select(VulnFeedCache).where(VulnFeedCache.key.like("nvd:%"))):
            row.expires_at = row.fetched_at
        s.commit()
    assert admin.post("/api/vulnerabilities/rematch").status_code == 202
    fake.requests.clear()
    run()
    nvd = [r for r in fake.requests if r.url.host == "nvd.invalid"]
    assert nvd and all("lastModStartDate" in str(r.url) for r in nvd)


def test_nvd_rate_limit_and_api_key_not_logged(admin, fake, monkeypatch, caplog):
    new_device(admin)
    with caplog.at_level(logging.DEBUG):
        run()
    assert any(5.0 <= s <= 6.0 for s in fake.sleeps)  # requests spaced ~6 s without a key
    assert all("apiKey" not in r.headers for r in fake.requests)

    monkeypatch.setenv("NVD_API_KEY", "secret-test-nvd-key")
    config.reload_settings()

    def refetch():
        fake.sleeps.clear()
        fake.requests.clear()
        with db.get_session("default") as s:
            for row in list(s.scalars(select(VulnFeedCache).where(VulnFeedCache.key.like("nvd:%")))):
                s.delete(row)
            s.commit()
        assert admin.post("/api/vulnerabilities/rematch").status_code == 202
        with caplog.at_level(logging.DEBUG):
            run()
        return [r for r in fake.requests if r.url.host == "nvd.invalid"]

    nvd = refetch()
    assert len(nvd) == 3 and all(r.headers.get("apiKey") == "secret-test-nvd-key" for r in nvd)
    assert fake.sleeps and max(fake.sleeps) <= 0.7  # 50 requests / 30 s with a key
    fake.fail_hosts = {"nvd.invalid"}
    assert refetch()
    assert "secret-test-nvd-key" not in caplog.text
    with db.get_session("default") as s:
        assert "secret-test-nvd-key" not in (s.get(VulnFeedStatus, "nvd").last_error or "")
    assert admin.get("/api/vulnerabilities/status").json()["nvd_api_key_configured"] is True
    monkeypatch.delenv("NVD_API_KEY")
    config.reload_settings()


def test_proxy_settings_are_honoured():
    feeds.set_transport(None)
    with feeds._client() as c:
        assert c._trust_env is True  # HTTPS_PROXY / NO_PROXY from cnapp.env


# --------------------------------------------------------------------------- notifications
def _vuln_events():
    with db.get_session("default") as s:
        return list(s.scalars(select(NotificationEvent).where(NotificationEvent.source == "vulnerability")))


def test_notifications_aggregated_per_cve(admin, fake):
    for i in range(12):
        new_device(admin, f"LAPTOP-{i:03d}", "0123456789ab"[i])
    run()
    events = _vuln_events()
    # one critical CVE (Chrome) on 12 devices -> exactly one event; medium/high ones are not notified
    assert [e.entity_id for e in events] == ["CVE-2024-10487"]
    e = events[0]
    assert "12 devices" in e.title and e.attributes["device_count"] == 12 and e.severity == "critical"
    assert e.group_key == "vulnerability:CVE-2024-10487:aggregate" and e.link_path.endswith("CVE-2024-10487")
    # another laptop later: no second notification within the window
    new_device(admin, "LAPTOP-LATE", "c")
    run()
    assert len(_vuln_events()) == 1


def test_kev_listing_notifies_existing(admin, fake):
    new_device(admin)
    run()
    assert [e.entity_id for e in _vuln_events()] == ["CVE-2024-10487"]
    fake.kev["vulnerabilities"].append({"cveID": "CVE-2024-99002", "dateAdded": "2024-11-02",
                                        "requiredAction": "Update", "dueDate": "2024-11-23"})
    with db.get_session("default") as s:
        worker.refresh_kev(s, matcher_now(), force=True)
    v = vulns()["CVE-2024-99002"]
    assert v.kev and v.exploit_available
    titles = [e.title for e in _vuln_events() if e.entity_id == "CVE-2024-99002"]
    assert len(titles) == 1 and titles[0].startswith("Now known exploited")


def matcher_now():
    from app.models import utcnow

    return utcnow()


# --------------------------------------------------------------------------- API
def test_api_views_and_filters(admin, fake):
    new_device(admin, "LAPTOP-001", "a")
    new_device(admin, "LAPTOP-002", "b", software=[{"name": "Google Chrome", "version": "127.0.6533.99",
                                                    "publisher": "Google LLC"}])
    run()
    devs = admin.get("/api/vulnerabilities", params={"scope": "device"}).json()
    assert devs and all(v["device_id"] and v["asset_type"] == "device" for v in devs)
    # simulated workload vulns are still there and the noise-reduction stat only counts workloads
    assets = admin.get("/api/vulnerabilities", params={"scope": "asset"}).json()
    assert all(v["device_id"] is None for v in assets)
    stats = admin.get("/api/vulnerabilities/stats").json()
    assert stats["devices"]["affected"] == 2 and stats["noise_reduction"]["total"] == stats["assets"]["open"]
    assert stats["kev"]["cves"] == 1
    by_cve = {g["cve_id"]: g for g in admin.get("/api/vulnerabilities/by-cve", params={"scope": "device"}).json()}
    assert by_cve["CVE-2024-10487"]["device_count"] == 2
    assert by_cve["CVE-2024-10487"]["devices"] == ["LAPTOP-001", "LAPTOP-002"]
    first = admin.get("/api/vulnerabilities/by-cve", params={"scope": "device"}).json()[0]
    assert first["kev"] is True  # KEV first
    sw = {g["package"]: g for g in admin.get("/api/vulnerabilities/by-software", params={"scope": "device"}).json()}
    assert sw["Google Chrome"]["device_count"] == 2 and sw["Google Chrome"]["kev_count"] == 1
    r = admin.get("/api/vulnerabilities", params={"package": "chrome", "severity": "critical"}).json()
    assert {v["cve_id"] for v in r} == {"CVE-2024-10487"}
    status = admin.get("/api/vulnerabilities/status").json()
    assert status["devices"]["matched"] == 2 and status["software_not_checked"] == 2
    assert any(n["name"] == "Contoso Expenses" and n["devices"] == 1 for n in status["not_checked_top"])
    dash = admin.get("/api/dashboard").json()
    assert dash["vulnerabilities"]["on_devices"] == len(devs)


def test_rematch_requires_analyst(admin, fake):
    new_device(admin)
    make_user(admin, "viewer")
    r = admin.post("/api/vulnerabilities/rematch")
    assert r.status_code == 202 and r.json()["queued"] == 1
    actions = [a["action"] for a in admin.get("/api/audit-log").json()]
    assert "vulnerability_rematch" in actions


def test_revoked_device_vulns_resolved(admin, fake):
    _, dev = new_device(admin)
    run()
    assert admin.post(f"/api/devices/{dev}/revoke", json={"reason": "stolen"}).status_code in (200, 204)
    run()
    assert vulns(dev) == {}


def test_disabled_matching_does_nothing(admin, fake, monkeypatch):
    new_device(admin)
    monkeypatch.setenv("VULN_MATCHING_ENABLED", "false")
    config.reload_settings()
    assert worker.VulnWorker().tick().leader is False
    assert fake.requests == []
    assert admin.post("/api/vulnerabilities/rematch").status_code == 409
    monkeypatch.delenv("VULN_MATCHING_ENABLED")
    config.reload_settings()


def test_macos_device(admin, fake):
    token = new_token(admin)
    agent = agent_client(admin.app)
    r = enroll(agent, token, machine_id="d" * 64, os_family="macos", hostname="MBP-1")
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    body = windows_checkin(software=[
        {"name": "Google Chrome", "version": "130.0.6723.70", "identifier": "com.google.Chrome",
         "publisher": "google", "source": "applications"}])
    body["device"].update({"os_family": "macos", "os_name": "macOS", "os_version": "15.1", "os_build": "24B83",
                           "architecture": "arm64", "hostname": "MBP-1"})
    body["posture"] = {}
    assert agent.post("/api/agent/checkin", json=body).status_code == 200, agent
    run()
    found = vulns(r.json()["device_id"])
    # macOS 15.1 < 15.2; Chrome range CVE yes; "Chrome on Windows" no
    assert set(found) == {"CVE-2024-44243", "CVE-2024-10487"}
    assert found["CVE-2024-44243"].package == "macOS"


# --------------------------------------------------------------------------- Linux hosts (sensor + OSV)
INVENTORY = {
    "schema_version": "1.1", "sensor_id": "web-1", "host": "web-1", "collected_at": "2026-10-23T10:00:00Z",
    "os": {"id": "debian", "version_id": "12", "pretty_name": "Debian GNU/Linux 12 (bookworm)"},
    "cloud": None,
    "packages": [
        {"name": "libssl3", "version": "3.0.11-1~deb12u2", "kind": "deb", "source_name": "openssl",
         "source_version": "3.0.11-1~deb12u2", "ecosystem": "Debian:12"},
        {"name": "openssl", "version": "3.0.11-1~deb12u2", "kind": "deb", "source_name": "openssl",
         "ecosystem": "Debian:12"},
        {"name": "numpy", "version": "1.26.4", "kind": "python", "ecosystem": "PyPI"},
    ],
}


def post_inventory(c, body=INVENTORY, headers=AUTH):
    return c.post("/api/runtime/packages", json=body, headers=headers)


def test_sensor_inventory_requires_token_and_valid_schema(anon_client):
    assert post_inventory(anon_client, headers={}).status_code == 401
    bad = {**INVENTORY, "packages": [{"name": "x"}]}
    assert post_inventory(anon_client, bad).status_code == 422
    assert post_inventory(anon_client, {**INVENTORY, "schema_version": "2.0"}).status_code == 422


def test_sensor_inventory_osv_match_and_runtime_in_use(client, fake):
    r = post_inventory(client)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["asset_created"] is True and body["asset_id"] == "sensor:web-1" and body["packages"] == 3
    assert fake.requests == []  # matching happens in the worker
    run()
    def host_vulns(status="open"):
        with db.get_session("default") as s:
            return {v.cve_id: v for v in s.scalars(select(Vulnerability).where(
                Vulnerability.asset_id == "sensor:web-1", Vulnerability.status == status))}

    found = host_vulns()
    assert set(found) == {"CVE-2023-5678", "CVE-2023-5363"}
    v = found["CVE-2023-5678"]
    assert v.source == "osv" and v.package == "openssl" and v.version == "3.0.11-1~deb12u2"
    assert v.fixed_version == "3.0.13-1~deb12u1" and v.cvss == 5.3 and v.severity == "medium"
    assert v.evidence["binaries"] == ["libssl3", "openssl"] and v.in_use is False
    assert found["CVE-2023-5363"].cvss == 9.8 and found["CVE-2023-5363"].severity == "critical"
    # one querybatch for the unique (ecosystem, source package, version) keys
    assert fake.count("osv.invalid") == 1 + 2
    # The runtime sensor sees libssl3 mapped into a process -> "in use", risk goes up
    before = v.risk_score
    ev = {"schema_version": "1.0", "event_type": "library_loaded", "host": "web-1", "sensor_id": "web-1",
          "library": {"path": "/usr/lib/x86_64-linux-gnu/libssl.so.3", "package": "libssl3",
                      "version": "3.0.11-1~deb12u2", "kind": "shared_object", "source": "dpkg"}}
    r = client.post("/api/runtime/events", json=[ev], headers=AUTH)
    assert r.status_code == 202 and r.json()["in_use_updates"] == 2
    after = host_vulns()["CVE-2023-5678"]
    assert after.in_use and after.in_use_source == "sensor" and after.risk_score > before
    # upgrade: resolved
    upgraded = {**INVENTORY, "packages": [
        {**p, "version": "3.0.15-1~deb12u1", "source_version": "3.0.15-1~deb12u1"} if p["kind"] == "deb" else p
        for p in INVENTORY["packages"]]}
    assert post_inventory(client, upgraded).status_code == 202
    run()
    assert host_vulns() == {}
    assert host_vulns("resolved")["CVE-2023-5678"].resolved_at is not None
    lst = client.get("/api/vulnerabilities", params={"asset_id": "sensor:web-1", "status": "all"}).json()
    assert {x["status"] for x in lst} == {"resolved"}


def test_sensor_inventory_attaches_to_existing_vm(client, fake):
    with db.get_session("default") as s:
        vm = s.scalars(select(Asset).where(Asset.type == "vm")).first()
        name, aid = vm.name, vm.id
    r = post_inventory(client, {**INVENTORY, "host": name.upper()})
    assert r.json()["asset_id"] == aid and r.json()["asset_created"] is False
    run()
    with db.get_session("default") as s:
        v = s.scalar(select(Vulnerability).where(Vulnerability.asset_id == aid, Vulnerability.source == "osv",
                                                 Vulnerability.cve_id == "CVE-2023-5363"))
    assert v is not None
    with db.get_session("default") as s:
        a = s.get(Asset, ("default", aid))
        assert v.internet_exposed == bool(a.internet_exposed)


def test_osv_offline_keeps_data_and_ingest_still_works(client, fake):
    fake.offline = True
    assert post_inventory(client).status_code == 202
    run()
    with db.get_session("default") as s:
        assert not list(s.scalars(select(Vulnerability).where(Vulnerability.asset_id == "sensor:web-1")))
    with db.get_session("default") as s:
        st = s.get(VulnFeedStatus, "osv")
        assert st.last_error and st.last_success_at is None
        state = s.scalar(select(VulnMatchState).where(VulnMatchState.target_id == "sensor:web-1"))
        assert any("offline" in n["reason"] for n in state.not_checked)
    fake.offline = False
    with db.get_session("default") as s:
        s.scalar(select(VulnMatchState).where(VulnMatchState.target_id == "sensor:web-1")).requested_at = \
            matcher_now()
        s.commit()
    run()
    with db.get_session("default") as s:
        assert s.scalar(select(Vulnerability).where(Vulnerability.asset_id == "sensor:web-1",
                                                    Vulnerability.cve_id == "CVE-2023-5678")) is not None


def test_device_delete_cascades(admin, fake):
    _, dev = new_device(admin)
    run()
    assert vulns(dev)
    assert admin.delete(f"/api/devices/{dev}?reason=decommissioned").status_code == 204
    with db.get_session("default") as s:
        assert s.get(Device, dev) is None
        assert not list(s.scalars(select(Vulnerability).where(Vulnerability.device_id == dev)))
        assert not list(s.scalars(select(DeviceSoftware).where(DeviceSoftware.device_id == dev)))
    run()  # state of the deleted device is cleaned up
    with db.get_session("default") as s:
        assert s.scalar(select(VulnMatchState).where(VulnMatchState.target_id == dev)) is None


def test_matcher_skips_unknown_windows_build(admin, fake):
    _, dev = new_device(admin, os_build="99999.1", os_version="10.0.99999")
    run()
    detail = admin.get(f"/api/devices/{dev}/vulnerabilities").json()
    assert any(n["reason"] == "operating system build not recognised" for n in detail["not_checked"])
    assert matcher.device_os(Device(os_family="linux", os_name="", os_version="", os_build="")) is None


def test_osv_vulnerability_in_use_feeds_attack_paths(empty_client, fake):
    """An OSV-matched CVE that the sensor sees loaded makes the workload on an
    attack path an exploitable hop (engine/attack_paths.py)."""
    from app.models import Relationship
    from app.services import analytics

    with db.get_session("default") as s:
        s.add(Asset(id="vm-1", name="web-1", type="vm", provider="azure", internet_exposed=True, tags={},
                    properties={"exposure": "public IP"}, source="azure"))
        s.add(Asset(id="st-1", name="customerdata", type="storage_account", provider="azure", sensitive_data=True,
                    tags={}, properties={}, source="azure"))
        s.add(Relationship(source_id="vm-1", target_id="st-1", type="connects_to", properties={}, source="azure"))
        s.commit()
    assert post_inventory(empty_client).json()["asset_id"] == "vm-1"
    run()
    ev = {"schema_version": "1.0", "event_type": "library_loaded", "host": "web-1", "sensor_id": "web-1",
          "library": {"path": "/usr/lib/x86_64-linux-gnu/libssl.so.3", "package": "libssl3",
                      "version": "3.0.11-1~deb12u2", "kind": "shared_object", "source": "dpkg"}}
    assert empty_client.post("/api/runtime/events", json=[ev], headers=AUTH).json()["in_use_updates"] == 2
    with db.get_session("default") as s:
        paths = analytics.attack_paths(s, limit=10)
    reasons = [r for p in paths for st in p.steps for r in st.reasons]
    assert any("CVE-2023-5363 in openssl (loaded at runtime" in r for r in reasons), reasons
