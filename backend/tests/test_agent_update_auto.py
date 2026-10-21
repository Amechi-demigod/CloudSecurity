"""Agent update automation: the production diagnosis (CI-built agent version in
an explicitly assigned Pilot ring gets the offer), pending state shown per
device, "update now" (check_for_update / recheck_posture fallback, no jitter),
fleet-size-aware jitter, automatic mode (Pilot -> everyone after the soak,
pause on Pilot failures) and the GitHub Releases auto-import."""
from __future__ import annotations

from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import config, db
from app.models import AgentUpdateSettings, Device, DeviceCommand, utcnow
from app.notifications.models import NotificationEvent
from app.services import agent_update_auto as auto
from app.services import agent_updates as svc
from tests.conftest import BASE_URL, login, make_user
from tests.test_agent_updates import audits, make_bundle, rel_tool, ring, set_ring, upload
from tests.test_devices import agent_client, enroll, new_token, windows_checkin


@pytest.fixture()
def key(monkeypatch):
    k = Ed25519PrivateKey.generate()
    monkeypatch.setenv("AGENT_UPDATE_TRUSTED_KEYS", rel_tool.trusted_line(k))
    config.reload_settings()
    yield k
    monkeypatch.delenv("AGENT_UPDATE_TRUSTED_KEYS")
    config.reload_settings()


@pytest.fixture()
def admin(empty_client, key):
    return empty_client

CI_VERSION = "0.1.132+1c918b1"  # what ci.yml builds into the MSI / PKG


def device(c, hostname: str, *, version: str = CI_VERSION, os_family: str = "windows", arch: str = "amd64",
           features: str | None = None):
    token = new_token(c)
    agent = agent_client(c.app)
    r = enroll(agent, token, machine_id=hostname.encode().hex().ljust(64, "0")[:64], hostname=hostname,
               os_family=os_family)
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    goos = "darwin" if os_family == "macos" else "windows"
    agent.headers["User-Agent"] = f"cnapp-agent/{version} ({goos}; {arch})"
    if features:
        agent.headers["X-CNAPP-Agent-Features"] = features
    agent.meta = {"hostname": hostname, "version": version, "os_family": os_family, "arch": arch}
    return agent, r.json()["device_id"]


def checkin(agent):
    body = windows_checkin()
    body["device"].update(hostname=agent.meta["hostname"], agent_version=agent.meta["version"],
                          os_family=agent.meta["os_family"], architecture=agent.meta["arch"])
    r = agent.post("/api/agent/checkin", json=body)
    assert r.status_code == 200, r.text
    return r.json()["update"]


def state(c, device_id):
    r = c.get(f"/api/updates/devices/{device_id}")
    assert r.status_code == 200, r.text
    return r.json()


def assign(c, device_id, ring_id):
    r = c.put(f"/api/updates/devices/{device_id}", json={"ring_id": ring_id, "reason": "pilot device"})
    assert r.status_code == 200, r.text


def settings_row():
    with db.get_session() as s:
        st = s.get(AgentUpdateSettings, 1)
        s.expunge(st)
        return st


def events(event_type: str):
    with db.get_session() as s:
        return list(s.scalars(select(NotificationEvent).where(NotificationEvent.event_type == event_type)))


# ----------------------------------------------------------------------------- diagnosis
@pytest.mark.parametrize("os_family,arch", [("windows", "amd64"), ("macos", "arm64"), ("macos", "amd64")])
def test_ci_built_agent_in_explicit_pilot_ring_gets_the_offer(admin, key, tmp_path, os_family, arch):
    """Production report: device in ring Pilot, Running 0.1.132+1c918b1, Target 1.0.0,
    last status "—". The server side does offer 1.0.0 to such an agent (build
    metadata, explicit ring, 100% default, platform): it is only waiting for the
    next check-in plus the start jitter, which the console now shows."""
    plats = (("windows", "amd64"), ("windows", "arm64"), ("darwin", "amd64"), ("darwin", "arm64"))
    rel = upload(admin, make_bundle(tmp_path, "1.0.0", [key], platforms=plats)).json()
    agent, did = device(admin, f"host-{os_family}-{arch}", os_family=os_family, arch=arch)
    checkin(agent)  # first check-in (no target yet)
    pilot = ring(admin, "Pilot")
    assert pilot["rollout_percent"] == 100
    assign(admin, did, pilot["id"])
    set_ring(admin, pilot["id"], target_release_id=rel["id"])
    st = state(admin, did)
    assert st["target_version"] == "1.0.0" and st["ring"]["name"] == "Pilot" and st["status"] is None
    assert st["pending"]["state"] == "waiting_checkin", st["pending"]
    assert st["pending"]["next_checkin_by"] and st["pending"]["can_update_now"]
    offer = checkin(agent)
    goos = "darwin" if os_family == "macos" else "windows"
    assert offer and offer["version"] == "1.0.0" and offer["artifact_path"].endswith(f"/{goos}/{arch}")
    assert offer["jitter_seconds"] == 120 and "immediate" not in offer  # new default (was 900)
    p = state(admin, did)["pending"]
    assert p["state"] == "offered" and p["offered_at"] and p["starts_by"]
    # Repeated check-ins keep the original offer time (the agent keeps its schedule).
    checkin(agent)
    assert state(admin, did)["pending"]["offered_at"] == p["offered_at"]


def test_pending_state_explains_blocked_and_done(admin, key, tmp_path):
    rel = upload(admin, make_bundle(tmp_path, "1.0.0", [key], platforms=(("windows", "amd64"),))).json()
    allr = ring(admin)
    set_ring(admin, allr["id"], target_release_id=rel["id"])
    arm, arm_id = device(admin, "arm-laptop", arch="arm64")
    checkin(arm)
    assert checkin(arm) is None
    p = state(admin, arm_id)["pending"]
    assert p["state"] == "blocked" and "no windows/arm64 binary" in p["message"] and not p["can_update_now"]
    done, done_id = device(admin, "done-laptop", version="1.0.0")
    checkin(done)
    assert state(admin, done_id)["pending"]["state"] == "up_to_date"
    rb, rb_id = device(admin, "rb-laptop")
    checkin(rb)
    r = rb.post("/api/agent/updates/status", json={"release_id": rel["id"], "from_version": CI_VERSION,
                                                    "to_version": "1.0.0", "status": "rolled_back", "detail": "x"})
    assert r.status_code == 204
    p = state(admin, rb_id)["pending"]
    assert p["state"] == "blocked" and "rolled back on this device" in p["message"]


# ----------------------------------------------------------------------------- jitter
def test_fleet_size_aware_jitter(admin, monkeypatch):
    with db.get_session() as s:
        assert svc.effective_jitter_seconds(s) == 120
        monkeypatch.setattr(config.settings, "agent_update_jitter_seconds", 0)
        assert svc.effective_jitter_seconds(s) == 0  # no devices
        for i in range(10):
            s.add(Device(hostname=f"d{i}", os_family="windows", status="active"))
        s.flush()
        assert svc.effective_jitter_seconds(s) == 3 * 15  # ceil(10 / 4 parallel) waves of 15 s
        monkeypatch.setattr(config.settings, "agent_update_jitter_seconds", 120)
        assert svc.effective_jitter_seconds(s) == 120
        monkeypatch.setattr(config.settings, "agent_update_max_parallel_downloads", 1)
        for i in range(10, 20):
            s.add(Device(hostname=f"d{i}", os_family="windows", status="active"))
        s.flush()
        assert svc.effective_jitter_seconds(s) == 300
        s.rollback()


# ----------------------------------------------------------------------------- update now
def test_update_now_device(admin, key, tmp_path):
    rel = upload(admin, make_bundle(tmp_path, "1.0.0", [key])).json()
    set_ring(admin, ring(admin)["id"], target_release_id=rel["id"])
    old, old_id = device(admin, "old-agent")  # an agent from before check_for_update existed
    new, new_id = device(admin, "new-agent", features="check_for_update")
    for a in (old, new):
        checkin(a)
    for did, expected in ((old_id, "recheck_posture"), (new_id, "check_for_update")):
        r = admin.post("/api/updates/update-now", json={"device_id": did})
        assert r.status_code == 200, r.text
        q = r.json()["queued"]
        assert len(q) == 1 and q[0]["command"] == expected and q[0]["delay_seconds"] == 0
        assert state(admin, did)["pending"]["state"] == "update_now_requested"
    # The agent polls its commands, checks in, and gets an immediate offer.
    cmds = new.get("/api/agent/commands").json()["commands"]
    assert [c["type"] for c in cmds] == ["check_for_update"] and cmds[0]["params"] == {}
    offer = checkin(new)
    assert offer["immediate"] is True and offer["jitter_seconds"] == 0
    assert state(admin, new_id)["pending"]["state"] == "offered"
    # Older agents: same zero delay through recheck_posture + the offer.
    assert [c["type"] for c in old.get("/api/agent/commands").json()["commands"]] == ["recheck_posture"]
    assert checkin(old)["jitter_seconds"] == 0
    # Asking twice does not pile up commands.
    admin.post("/api/updates/update-now", json={"device_id": new_id})
    admin.post("/api/updates/update-now", json={"device_id": new_id})
    with db.get_session() as s:
        pending = s.scalars(select(DeviceCommand).where(DeviceCommand.device_id == new_id,
                                                        DeviceCommand.status == "pending")).all()
        assert len(pending) == 1
    # Installed: the request is cleared, the device is up to date, nothing left to do.
    r = new.post("/api/agent/updates/status", json={"release_id": rel["id"], "from_version": CI_VERSION,
                                                     "to_version": "1.0.0", "status": "installed"})
    assert r.status_code == 204
    new.meta["version"] = "1.0.0"
    new.headers["User-Agent"] = "cnapp-agent/1.0.0 (windows; amd64)"
    assert checkin(new) is None
    r = admin.post("/api/updates/update-now", json={"device_id": new_id})
    assert r.status_code == 409 and "target version" in r.json()["detail"]
    assert audits("agent_update_now_requested")


def test_update_now_ring_and_fleet_rbac_and_stagger(admin, key, tmp_path, monkeypatch):
    rel = upload(admin, make_bundle(tmp_path, "1.0.0", [key])).json()
    allr = ring(admin)
    set_ring(admin, allr["id"], target_release_id=rel["id"])
    monkeypatch.setattr(config.settings, "agent_update_max_parallel_downloads", 2)
    ids = []
    for i in range(5):
        a, did = device(admin, f"fleet-{i}", features="check_for_update")
        checkin(a)
        ids.append(did)
    up, up_id = device(admin, "fleet-current", version="1.0.0")
    checkin(up)
    make_user(admin, "analyst")
    make_user(admin, "viewer")
    analyst = TestClient(admin.app, base_url=BASE_URL)
    login(analyst, "analyst@example.com", "a-long-test-password")
    viewer = TestClient(admin.app, base_url=BASE_URL)
    login(viewer, "viewer@example.com", "a-long-test-password")
    assert viewer.post("/api/updates/update-now", json={"device_id": ids[0]}).status_code == 403
    assert analyst.post("/api/updates/update-now", json={"device_id": ids[0]}).status_code == 200
    assert analyst.post("/api/updates/update-now", json={"all": True}).status_code == 403
    assert analyst.post("/api/updates/update-now", json={"ring_id": allr["id"]}).status_code == 403
    assert admin.post("/api/updates/update-now", json={}).status_code == 422
    assert admin.post("/api/updates/update-now", json={"all": True, "ring_id": allr["id"]}).status_code == 422
    r = admin.post("/api/updates/update-now", json={"ring_id": allr["id"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert sorted(q["device_id"] for q in body["queued"]) == sorted(ids)
    assert [q["delay_seconds"] for q in body["queued"]] == [0, 0, 20, 20, 40]  # 2 parallel downloads per wave
    assert [s["hostname"] for s in body["skipped"]] == ["fleet-current"]
    assert admin.post("/api/updates/update-now", json={"all": True}).json()["queued"]


def test_check_for_update_is_a_queueable_command(admin, key, tmp_path):
    a, did = device(admin, "cmd-host")
    r = admin.post(f"/api/devices/{did}/commands", json={"type": "check_for_update", "reason": "test it", "params": {}})
    assert r.status_code == 201, r.text
    bad = admin.post(f"/api/devices/{did}/commands",
                     json={"type": "check_for_update", "reason": "test it", "params": {"release_id": "x"}})
    assert bad.status_code == 422


# ----------------------------------------------------------------------------- automatic mode
def set_mode(c, **body):
    r = c.put("/api/updates/automation", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_default_mode_is_automatic(admin, monkeypatch):
    monkeypatch.setattr(config.settings, "agent_update_default_mode", "automatic")
    st = admin.get("/api/updates/automation").json()
    assert st["mode"] == "automatic" and st["soak_hours"] == 24 and st["jitter_seconds"] == 120
    assert st["auto_import"]["enabled"] is False  # AGENT_UPDATE_AUTO_IMPORT=false in tests; on-prem default true


def test_automatic_mode_pilot_then_everyone(admin, key, tmp_path):
    set_mode(admin, mode="automatic", soak_hours=24)
    pilot = ring(admin, "Pilot")
    p_agent, p_id = device(admin, "pilot-1")
    assign(admin, p_id, pilot["id"])
    other, other_id = device(admin, "unassigned-1")  # in no ring: "All devices"
    upload(admin, make_bundle(tmp_path, "1.0.0", [key])).json()
    # Imported -> Pilot targeted at once; everyone else not yet.
    assert ring(admin, "Pilot")["target_version"] == "1.0.0"
    assert ring(admin, "All devices")["target_version"] is None
    assert checkin(p_agent)["version"] == "1.0.0"
    assert checkin(other) is None
    st = admin.get("/api/updates/automation").json()
    assert st["rollout"]["stage"] == "pilot" and st["rollout"]["version"] == "1.0.0" and st["rollout"]["promote_at"]
    assert st["rollout"]["pilot_devices"] == 1
    assert events("rollout_started")
    # Before the soak: nothing changes.
    with db.get_session() as s:
        assert auto.auto_tick(s, utcnow() + timedelta(hours=23)).action == "none"
        s.commit()
    # After the soak without failures: every ring (incl. All devices) targets it.
    with db.get_session() as s:
        assert auto.auto_tick(s, utcnow() + timedelta(hours=25)).action == "promoted"
        s.commit()
    assert {r["target_version"] for r in admin.get("/api/updates/rings").json()} == {"1.0.0"}
    assert checkin(other)["version"] == "1.0.0"
    assert events("rollout_promoted") and audits("agent_update_auto_promoted")
    # A newer release starts over at Pilot (everyone else keeps 1.0.0 meanwhile).
    upload(admin, make_bundle(tmp_path, "1.1.0", [key]))
    assert ring(admin, "Pilot")["target_version"] == "1.1.0"
    assert ring(admin, "All devices")["target_version"] == "1.0.0"
    assert settings_row().auto_stage == "pilot"


def test_automatic_mode_pauses_on_pilot_failure_and_promote_override(admin, key, tmp_path):
    set_mode(admin, mode="automatic")
    pilot = ring(admin, "Pilot")
    p_agent, p_id = device(admin, "pilot-2")
    assign(admin, p_id, pilot["id"])
    other, _ = device(admin, "unassigned-2")
    rel = upload(admin, make_bundle(tmp_path, "1.0.0", [key])).json()
    checkin(p_agent)
    r = p_agent.post("/api/agent/updates/status", json={"release_id": rel["id"], "from_version": CI_VERSION,
                                                         "to_version": "1.0.0", "status": "rolled_back",
                                                         "detail": "health check failed"})
    assert r.status_code == 204
    with db.get_session() as s:
        res = auto.auto_tick(s, utcnow() + timedelta(hours=1))
        s.commit()
    assert res.action == "paused" and "pilot-2" in res.detail
    st = admin.get("/api/updates/automation").json()
    assert st["rollout"]["stage"] == "paused" and "pilot-2" in st["rollout"]["paused_reason"]
    ev = events("rollout_paused")
    assert ev and ev[0].severity == "high"
    # Still paused after the soak: the rest of the fleet does not get it.
    with db.get_session() as s:
        assert auto.auto_tick(s, utcnow() + timedelta(days=3)).action == "none"
        s.commit()
    assert ring(admin, "All devices")["target_version"] is None and checkin(other) is None
    # An admin can promote anyway (audited); viewers cannot.
    make_user(admin, "viewer")
    v = TestClient(admin.app, base_url=BASE_URL)
    login(v, "viewer@example.com", "a-long-test-password")
    assert v.post("/api/updates/automation/promote", json={"reason": "go"}).status_code == 403
    assert v.put("/api/updates/automation", json={"mode": "manual"}).status_code == 403
    assert v.get("/api/updates/automation").status_code == 200
    r = admin.post("/api/updates/automation/promote", json={"reason": "known issue on that laptop only"})
    assert r.status_code == 200 and r.json()["rollout"]["stage"] == "all"
    assert checkin(other)["version"] == "1.0.0"


def test_failed_status_holds_promotion_at_end_of_soak(admin, key, tmp_path):
    set_mode(admin, mode="automatic", soak_hours=1)
    p_agent, p_id = device(admin, "pilot-3")
    assign(admin, p_id, ring(admin, "Pilot")["id"])
    rel = upload(admin, make_bundle(tmp_path, "1.0.0", [key])).json()
    checkin(p_agent)
    p_agent.post("/api/agent/updates/status", json={"release_id": rel["id"], "from_version": CI_VERSION,
                                                     "to_version": "1.0.0", "status": "failed",
                                                     "detail": "download failed (will retry)"})
    with db.get_session() as s:
        assert auto.auto_tick(s, utcnow() + timedelta(minutes=30)).action == "none"  # transient, during soak
        assert auto.auto_tick(s, utcnow() + timedelta(hours=2)).action == "paused"  # still failed at the end
        s.commit()


def test_manual_mode_leaves_rings_alone(admin, key, tmp_path):
    assert admin.get("/api/updates/automation").json()["mode"] == "manual"
    upload(admin, make_bundle(tmp_path, "1.0.0", [key]))
    assert all(r["target_version"] is None for r in admin.get("/api/updates/rings").json())
    # Switching to automatic picks up the newest release right away.
    out = set_mode(admin, mode="automatic", reason="set and forget")
    assert out["tick"]["action"] == "started" and ring(admin, "Pilot")["target_version"] == "1.0.0"
    assert audits("agent_update_settings_changed")


def test_worker_tick_runs_the_rollout(admin, key, tmp_path):
    with db.get_session() as s:
        auto.get_settings(s).mode = "automatic"
        s.commit()
    with db.get_session() as s:  # import without the hook having run in automatic mode
        auto.get_settings(s).mode = "manual"
        s.commit()
    upload(admin, make_bundle(tmp_path, "1.0.0", [key]))
    with db.get_session() as s:
        auto.get_settings(s).mode = "automatic"
        s.commit()
    w = auto.AgentUpdateWorker()
    try:
        assert w.tick() is True
    finally:
        w.stop()
    assert ring(admin, "Pilot")["target_version"] == "1.0.0"


# ----------------------------------------------------------------------------- auto-import
def gh_release(tag, *, draft=False, prerelease=False, asset=True, size=1000):
    return {"tag_name": tag, "draft": draft, "prerelease": prerelease, "assets": [
        {"name": auto.BUNDLE_ASSET if asset else "other.zip", "size": size,
         "browser_download_url": f"https://github.com/o/r/releases/download/{tag}/{auto.BUNDLE_ASSET}"}]}


def test_find_new_release_filters():
    rels = [gh_release("agent-v1.2.0", draft=True), gh_release("agent-v1.3.0-rc1", prerelease=True),
            gh_release("v9.9.9"), gh_release("agent-v1.1.0"), gh_release("agent-v1.0.5"),
            gh_release("agent-v2.0.0", asset=False), gh_release("agent-v1.1.1", size=10**10), "junk"]
    best = auto.find_new_release(rels, {"1.0.0"}, 10**8)
    assert best["version"] == "1.1.0" and best["tag"] == "agent-v1.1.0"
    assert auto.find_new_release(rels, {"1.1.0"}, 10**8) is None  # nothing newer than what is imported
    assert auto.find_new_release({"message": "rate limited"}, set(), 10**8) is None


def test_auto_import_from_github(admin, key, tmp_path, monkeypatch):
    bundles = {"agent-v1.0.0": make_bundle(tmp_path, "1.0.0", [key]),
               "agent-v1.1.0": make_bundle(tmp_path, "1.1.0", [Ed25519PrivateKey.generate()])}  # untrusted key
    listing = [gh_release("agent-v1.0.0", size=len(bundles["agent-v1.0.0"]))]
    calls = []

    def fake_json(url):
        calls.append(url)
        return listing

    def fake_download(url, max_bytes):
        tag = url.split("/download/")[1].split("/")[0]
        return bundles[tag]

    monkeypatch.setattr(auto, "http_get_json", fake_json)
    monkeypatch.setattr(auto, "http_download", fake_download)
    set_mode(admin, mode="automatic", auto_import_enabled=True, auto_import_repo="Amechi-demigod/CloudSecurity")
    with db.get_session() as s:
        assert auto.import_due(auto.get_settings(s), utcnow())
        res = auto.check_github(s)
        s.commit()
    assert res["status"] == "ok" and res["imported"] == "1.0.0", res
    assert calls == ["https://api.github.com/repos/Amechi-demigod/CloudSecurity/releases?per_page=30"]
    assert [r["version"] for r in admin.get("/api/updates/releases").json()] == ["1.0.0"]
    assert ring(admin, "Pilot")["target_version"] == "1.0.0"  # automatic mode: straight to Pilot
    a = [x for x in audits("agent_release_imported") if x.detail.get("source") == "auto-import"]
    assert a and a[0].actor_email == "auto-import:github.com/Amechi-demigod/CloudSecurity"
    assert events("release_imported")
    with db.get_session() as s:
        assert not auto.import_due(auto.get_settings(s), utcnow())  # next check after the interval
        assert auto.check_github(s)["message"].startswith("no new release")
        s.commit()
    # A release signed with an untrusted key is refused, surfaced and not retried.
    listing.append(gh_release("agent-v1.1.0", size=len(bundles["agent-v1.1.0"])))
    with db.get_session() as s:
        res = auto.check_github(s)
        s.commit()
    assert res["status"] == "error" and "not signed by a trusted release key" in res["message"]
    assert events("release_import_failed")[0].severity == "high"
    assert [r["version"] for r in admin.get("/api/updates/releases").json()] == ["1.0.0"]
    with db.get_session() as s:
        again = auto.check_github(s)
        s.commit()
    assert again["status"] == "error" and "not retried" in again["message"] and len(events("release_import_failed")) == 1
    st = admin.get("/api/updates/automation").json()["auto_import"]
    assert st["status"] == "error" and st["failed_version"] == "1.1.0"


def test_auto_import_offline_only_logs(admin, monkeypatch):
    def offline(url):
        raise auto.ImportCheckError("cannot reach https://api.github.com: ConnectError: no route to host")

    monkeypatch.setattr(auto, "http_get_json", offline)
    r = admin.post("/api/updates/automation/check-github")
    assert r.status_code == 200 and r.json()["status"] == "offline"
    assert admin.get("/api/updates/automation").json()["auto_import"]["status"] == "offline"
    assert not events("release_import_failed")


def test_auto_import_real_network_errors_are_offline(admin, monkeypatch):
    # Unroutable address: the real httpx path turns a connection failure into "offline".
    monkeypatch.setattr(config.settings, "agent_update_releases_api", "https://127.0.0.1:9")
    with db.get_session() as s:
        res = auto.check_github(s)
        s.commit()
    assert res["status"] == "offline", res
    monkeypatch.setattr(config.settings, "agent_update_releases_api", "http://example.com")
    with db.get_session() as s:
        assert auto.check_github(s)["status"] == "error"


def test_automation_settings_validation(admin):
    assert admin.put("/api/updates/automation", json={"mode": "yolo"}).status_code == 422
    assert admin.put("/api/updates/automation", json={"auto_import_repo": "https://evil/x"}).status_code == 422
    assert admin.put("/api/updates/automation", json={"auto_import_interval_minutes": 1}).status_code == 422
    assert admin.put("/api/updates/automation", json={"soak_hours": -1}).status_code == 422
    out = set_mode(admin, soak_hours=0, auto_import_interval_minutes=30)
    assert out["soak_hours"] == 0 and out["auto_import"]["interval_minutes"] == 30
    assert admin.post("/api/updates/automation/promote", json={"reason": "nothing"}).status_code == 409
