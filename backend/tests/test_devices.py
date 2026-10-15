"""Device management: enrollment, agent auth isolation, check-in validation,
derived health, remote commands (RBAC, allowlist, expiry, at-most-once) and
log bundles. Runs on SQLite and PostgreSQL."""
from __future__ import annotations

import gzip
import io
import tarfile
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app import config, db
from app.models import Device, DeviceCommand, DevicePostureSnapshot, utcnow
from tests.conftest import BASE_URL, login, make_user

MACHINE = "a" * 64


def windows_checkin(**over):
    body = {
        "schema_version": 1,
        "collected_at": "2026-10-15T10:00:00Z",
        "device": {
            "hostname": "LAPTOP-001", "os_family": "windows", "os_name": "Microsoft Windows 11 Pro",
            "os_version": "10.0.22631", "os_build": "22631", "architecture": "amd64", "serial_number": "PF12345",
            "manufacturer": "LENOVO", "model": "20XW", "cpu": "Intel(R) Core(TM) i7", "cpu_cores": 8,
            "memory_bytes": 17179869184, "disks": [{"mount": "C:", "filesystem": "NTFS", "size_bytes": 512000000000,
                                                     "free_bytes": 100000000000}],
            "uptime_seconds": 3600, "last_boot": "2026-10-15T09:00:00Z", "logged_in_users": ["CORP\\alice"],
            "network": [{"name": "Ethernet", "mac": "00:11:22:33:44:55", "ips": ["10.0.0.5"]}],
            "agent_version": "0.1.0",
        },
        "posture": {
            "disk_encryption": {"status": "pass", "detail": "BitLocker on for C:"},
            "firewall": {"status": "pass", "detail": "all profiles enabled"},
            "antivirus": {"status": "pass", "detail": "Defender real-time on", "data": {"signature_age_days": 1}},
            "os_updates": {"status": "pass", "detail": "no pending updates", "data": {"pending_count": 0}},
            "local_admins": {"status": "info", "data": {"accounts": ["Administrator", "CORP\\alice"]}},
        },
        "software": [{"name": "Google Chrome", "version": "130.0.1", "publisher": "Google LLC"},
                     {"name": "7-Zip", "version": "24.08", "publisher": "Igor Pavlov"},
                     {"name": "7-Zip", "version": "24.08", "publisher": "Igor Pavlov"}],
        "errors": {},
    }
    for k, v in over.items():
        body[k] = v
    return body


@pytest.fixture()
def admin(empty_client):
    return empty_client


def new_token(c, **kw) -> str:
    body = {"name": "laptops", "max_uses": 5, "expires_in_hours": 24, **kw}
    r = c.post("/api/devices/enrollment-tokens", json=body)
    assert r.status_code == 201, r.text
    assert r.json()["token"].startswith("cne_") and r.json()["state"] == "active"
    return r.json()["token"]


def agent_client(app) -> TestClient:
    return TestClient(app, base_url=BASE_URL)


def enroll(c, token: str, machine_id: str = MACHINE, os_family: str = "windows", hostname: str = "LAPTOP-001"):
    return c.post("/api/agent/enroll", json={"token": token, "device": {
        "hostname": hostname, "os_family": os_family, "os_version": "10.0.22631", "serial_number": "PF12345",
        "machine_id": machine_id, "agent_version": "0.1.0"}})


@pytest.fixture()
def device(admin):
    """(agent TestClient with device credential, device_id)."""
    token = new_token(admin)
    agent = agent_client(admin.app)
    r = enroll(agent, token)
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    assert agent.post("/api/agent/checkin", json=windows_checkin()).status_code == 200
    return agent, r.json()["device_id"]


# --------------------------------------------------------------------------- enrollment
def test_enroll_and_checkin_flow(admin, device):
    agent, device_id = device
    d = admin.get(f"/api/devices/{device_id}").json()
    assert d["hostname"] == "LAPTOP-001" and d["os_family"] == "windows" and d["health"] == "healthy"
    assert d["connectivity"] == "active" and d["issues"] == [] and d["software_count"] == 2
    assert d["inventory"]["memory_bytes"] == 17179869184 and d["posture"]["firewall"]["status"] == "pass"
    sw = admin.get(f"/api/devices/{device_id}/software").json()
    assert [s["name"] for s in sw] == ["7-Zip", "Google Chrome"]
    assert len(admin.get(f"/api/devices/{device_id}/history").json()) == 1
    lst = admin.get("/api/devices").json()
    assert [x["id"] for x in lst] == [device_id]
    actions = [a["action"] for a in admin.get("/api/audit-log").json()]
    assert "device_enrolled" in actions and "enrollment_token_created" in actions


def test_secret_is_hashed_at_rest(admin, device):
    agent, device_id = device
    secret = agent.headers["Authorization"].split()[1]
    from app.models import DeviceCredential

    with db.get_session() as s:
        cred = s.query(DeviceCredential).filter_by(device_id=device_id).one()
        assert cred.secret_hash != secret and len(cred.secret_hash) == 64


def test_single_use_token(admin):
    token = new_token(admin, max_uses=1)
    agent = agent_client(admin.app)
    assert enroll(agent, token).status_code == 200
    r = enroll(agent, token, machine_id="b" * 64)
    assert r.status_code == 401
    t = admin.get("/api/devices/enrollment-tokens").json()[0]
    assert t["state"] == "exhausted" and t["use_count"] == 1 and "token" not in t


def test_expired_and_revoked_tokens_rejected(admin):
    token = new_token(admin)
    tid = admin.get("/api/devices/enrollment-tokens").json()[0]["id"]
    assert admin.post(f"/api/devices/enrollment-tokens/{tid}/revoke").json()["state"] == "revoked"
    assert enroll(agent_client(admin.app), token).status_code == 401
    token2 = new_token(admin, expires_in_hours=1)
    from app.models import EnrollmentToken

    with db.get_session() as s:
        for t in s.query(EnrollmentToken):
            t.expires_at = utcnow() - timedelta(seconds=1)
        s.commit()
    assert enroll(agent_client(admin.app), token2).status_code == 401
    assert enroll(agent_client(admin.app), "cne_not-a-real-token").status_code == 401


def test_reenrollment_rotates_credential(admin, device):
    agent, device_id = device
    old = agent.headers["Authorization"]
    r = enroll(agent_client(admin.app), new_token(admin))
    assert r.status_code == 200 and r.json()["reenrolled"] and r.json()["device_id"] == device_id
    assert agent.get("/api/agent/commands").status_code == 401  # old secret superseded
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    assert agent.get("/api/agent/commands").status_code == 200
    assert old != agent.headers["Authorization"]
    assert len(admin.get("/api/devices").json()) == 1


def test_enroll_validation(admin):
    token = new_token(admin)
    agent = agent_client(admin.app)
    bad = {"token": token, "device": {"hostname": "x", "os_family": "solaris"}}
    assert agent.post("/api/agent/enroll", json=bad).status_code == 422
    extra = {"token": token, "device": {"hostname": "x", "os_family": "macos", "evil": 1}}
    assert agent.post("/api/agent/enroll", json=extra).status_code == 422


def test_enroll_rate_limited(admin, monkeypatch):
    monkeypatch.setenv("ENROLL_RATE_LIMIT", "3")
    config.reload_settings()
    agent = agent_client(admin.app)
    codes = [enroll(agent, "cne_wrong-token-xxxx").status_code for _ in range(5)]
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]
    monkeypatch.delenv("ENROLL_RATE_LIMIT")
    config.reload_settings()


# --------------------------------------------------------------------------- auth isolation
def test_agent_endpoints_reject_user_sessions(admin):
    """A logged-in user session (cookie + CSRF) cannot act as a device."""
    assert admin.get("/api/agent/commands").status_code == 401
    assert admin.post("/api/agent/checkin", json=windows_checkin()).status_code == 401


def test_device_credentials_cannot_reach_user_api(admin, device):
    agent, device_id = device
    agent.cookies.clear()
    for path in ("/api/devices", f"/api/devices/{device_id}", "/api/dashboard", "/api/users", "/api/auth/me"):
        assert agent.get(path).status_code == 401, path
    r = agent.post(f"/api/devices/{device_id}/commands", json={"type": "lock_device", "reason": "nope"})
    assert r.status_code == 401


def test_ingest_token_is_not_a_device_credential(admin):
    agent = agent_client(admin.app)
    agent.headers["Authorization"] = "Bearer test-ingest-token"
    assert agent.get("/api/agent/commands").status_code == 401


def test_revoked_device_rejected(admin, device):
    agent, device_id = device
    r = admin.post(f"/api/devices/{device_id}/revoke", json={"reason": "laptop stolen"})
    assert r.status_code == 200 and r.json()["status"] == "revoked"
    assert agent.get("/api/agent/commands").status_code == 403
    assert agent.post("/api/agent/checkin", json=windows_checkin()).status_code == 403
    assert admin.get("/api/devices").json() == []
    assert len(admin.get("/api/devices?status=revoked").json()) == 1
    r = admin.post(f"/api/devices/{device_id}/commands", json={"type": "recheck_posture", "reason": "check"})
    assert r.status_code == 409
    # A new enrollment token re-activates the same machine with a fresh credential.
    r = enroll(agent_client(admin.app), new_token(admin))
    assert r.status_code == 200 and r.json()["device_id"] == device_id
    assert admin.get(f"/api/devices/{device_id}").json()["status"] == "active"


def test_device_rate_limited(admin, device, monkeypatch):
    agent, _ = device
    monkeypatch.setenv("DEVICE_RATE_LIMIT", "3")
    config.reload_settings()
    from app.api.agent import device_limiter

    device_limiter.reset()
    codes = [agent.get("/api/agent/commands").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    monkeypatch.delenv("DEVICE_RATE_LIMIT")
    config.reload_settings()


# --------------------------------------------------------------------------- check-in validation
@pytest.mark.parametrize("mutate", [
    lambda b: b["device"].update(os_family="plan9"),
    lambda b: b["device"].update(hostname=""),
    lambda b: b["device"].update(hostname="h" * 300),
    lambda b: b["device"].update(unexpected=True),
    lambda b: b["posture"].update(firewall={"status": "maybe"}),
    lambda b: b["posture"].update({"Bad Name": {"status": "pass"}}),
    lambda b: b["posture"].update(firewall={"status": "pass", "data": {"blob": "x" * 20000}}),
    lambda b: b.update(software=[{"name": "x", "version": "1"}] * 10001),
    lambda b: b.update(schema_version=2),
])
def test_checkin_strict_validation(device, mutate):
    agent, _ = device
    body = windows_checkin()
    mutate(body)
    assert agent.post("/api/agent/checkin", json=body).status_code == 422


def test_checkin_os_family_must_match(device):
    agent, _ = device
    body = windows_checkin()
    body["device"]["os_family"] = "macos"
    assert agent.post("/api/agent/checkin", json=body).status_code == 409


def test_checkin_body_limit(device, monkeypatch):
    agent, _ = device
    huge = windows_checkin(software=[{"name": f"pkg-{i}", "version": "1.0" * 30, "publisher": "p" * 200}
                                     for i in range(9000)])
    # > 1 MiB (the global cap) but within AGENT_MAX_REQUEST_BYTES
    assert agent.post("/api/agent/checkin", json=huge).status_code == 200


def test_software_kept_when_not_sent(admin, device):
    agent, device_id = device
    body = windows_checkin()
    body["software"] = None
    assert agent.post("/api/agent/checkin", json=body).status_code == 200
    assert len(admin.get(f"/api/devices/{device_id}/software").json()) == 2


def test_history_is_pruned(admin, device, monkeypatch):
    agent, device_id = device
    monkeypatch.setenv("DEVICE_HISTORY_LIMIT", "3")
    config.reload_settings()
    for _ in range(5):
        assert agent.post("/api/agent/checkin", json=windows_checkin()).status_code == 200
    with db.get_session() as s:
        assert s.query(DevicePostureSnapshot).filter_by(device_id=device_id).count() == 3
    monkeypatch.delenv("DEVICE_HISTORY_LIMIT")
    config.reload_settings()


# --------------------------------------------------------------------------- health / issues
def test_issues_and_health(admin, device):
    agent, device_id = device
    body = windows_checkin()
    body["posture"]["disk_encryption"] = {"status": "fail", "detail": "BitLocker off"}
    body["posture"]["antivirus"] = {"status": "pass", "data": {"signature_age_days": 30}}
    assert agent.post("/api/agent/checkin", json=body).json()["issues"] == ["disk_encryption_off",
                                                                          "av_signatures_outdated"]
    d = admin.get(f"/api/devices/{device_id}").json()
    assert d["health"] == "critical"
    assert {i["code"] for i in d["issues"]} == {"disk_encryption_off", "av_signatures_outdated"}
    assert [x["id"] for x in admin.get("/api/devices?issue=disk_encryption_off").json()] == [device_id]
    assert admin.get("/api/devices?health=healthy").json() == []
    s = admin.get("/api/devices/summary").json()
    assert s["total"] == 1 and s["encrypted_percent"] == 0.0 and s["firewall_percent"] == 100.0
    assert s["by_health"]["critical"] == 1 and s["issues"]["disk_encryption_off"] == 1


def test_updates_pending_grace_period(admin, device):
    agent, device_id = device
    body = windows_checkin()
    body["posture"]["os_updates"] = {"status": "fail", "data": {"pending_count": 3}}
    agent.post("/api/agent/checkin", json=body)
    assert admin.get(f"/api/devices/{device_id}").json()["issues"] == []  # within grace period
    with db.get_session() as s:
        s.get(Device, device_id).updates_pending_since = utcnow() - timedelta(days=20)
        s.commit()
    issues = admin.get(f"/api/devices/{device_id}").json()["issues"]
    assert [i["code"] for i in issues] == ["os_updates_pending"] and "3 update(s)" in issues[0]["detail"]
    agent.post("/api/agent/checkin", json=windows_checkin())  # 0 pending: cleared
    assert admin.get(f"/api/devices/{device_id}").json()["updates_pending_since"] is None


@pytest.mark.parametrize("age,expected", [(timedelta(hours=2), "active"), (timedelta(hours=30), "stale"),
                                          (timedelta(days=9), "inactive")])
def test_stale_and_inactive(admin, device, age, expected):
    _, device_id = device
    with db.get_session() as s:
        s.get(Device, device_id).last_seen_at = utcnow() - age
        s.commit()
    d = admin.get(f"/api/devices/{device_id}").json()
    assert d["connectivity"] == expected
    codes = {i["code"] for i in d["issues"]}
    assert (expected in codes) == (expected != "active")
    assert admin.get("/api/devices/summary").json()["connectivity"][expected] == 1


# --------------------------------------------------------------------------- commands
def queue(c, device_id, type_, reason="investigating", **extra):
    return c.post(f"/api/devices/{device_id}/commands", json={"type": type_, "reason": reason, **extra})


def test_command_lifecycle_once_only(admin, device):
    agent, device_id = device
    r = queue(admin, device_id, "recheck_posture")
    assert r.status_code == 201 and r.json()["status"] == "pending"
    cid = r.json()["id"]
    cmds = agent.get("/api/agent/commands").json()["commands"]
    assert [c["id"] for c in cmds] == [cid] and cmds[0]["device_id"] == device_id and cmds[0]["type"] == "recheck_posture"
    nonce = cmds[0]["nonce"]
    assert agent.get("/api/agent/commands").json()["commands"] == []  # delivered at most once
    assert agent.post(f"/api/agent/commands/{cid}/result",
                      json={"nonce": "0" * 32, "status": "succeeded"}).status_code == 403
    r = agent.post(f"/api/agent/commands/{cid}/result", json={"nonce": nonce, "status": "succeeded",
                                                             "output": "check-in completed"})
    assert r.status_code == 204
    again = agent.post(f"/api/agent/commands/{cid}/result", json={"nonce": nonce, "status": "failed"})
    assert again.status_code == 409
    c = admin.get(f"/api/devices/{device_id}/commands").json()[0]
    assert c["status"] == "succeeded" and c["output"] == "check-in completed" and c["completed_at"]
    audit = admin.get("/api/audit-log?action=device_command_created").json()[0]
    assert audit["detail"]["reason"] == "investigating" and audit["detail"]["type"] == "recheck_posture"


def test_command_expiry(admin, device):
    agent, device_id = device
    cid = queue(admin, device_id, "collect_logs").json()["id"]
    with db.get_session() as s:
        s.get(DeviceCommand, cid).expires_at = utcnow() - timedelta(seconds=1)
        s.commit()
    assert agent.get("/api/agent/commands").json()["commands"] == []
    assert admin.get(f"/api/devices/{device_id}/commands").json()[0]["status"] == "expired"


def test_commands_bound_to_device(admin, device):
    agent, device_id = device
    other = agent_client(admin.app)
    r = enroll(other, new_token(admin), machine_id="c" * 64, hostname="MAC-2", os_family="macos")
    other.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    cid = queue(admin, device_id, "recheck_posture").json()["id"]
    assert other.get("/api/agent/commands").json()["commands"] == []
    nonce = agent.get("/api/agent/commands").json()["commands"][0]["nonce"]
    assert other.post(f"/api/agent/commands/{cid}/result", json={"nonce": nonce, "status": "succeeded"}).status_code == 404


def test_server_side_allowlist(admin, device):
    _, device_id = device
    for bad in ("run_script", "shell", "wipe_device", ""):
        assert queue(admin, device_id, bad).status_code == 422
    assert queue(admin, device_id, "recheck_posture", params={"cmd": "whoami"}).status_code == 422
    assert queue(admin, device_id, "update_check_in_interval", params={"interval_seconds": 5}).status_code == 422
    assert queue(admin, device_id, "update_check_in_interval",
                 params={"interval_seconds": 600, "x": 1}).status_code == 422
    assert queue(admin, device_id, "lock_device", reason="").status_code == 422  # reason required
    assert queue(admin, device_id, "lock_device", reason="  ").status_code == 422


def test_interval_update_applied_on_success(admin, device):
    agent, device_id = device
    cid = queue(admin, device_id, "update_check_in_interval", params={"interval_seconds": 600}).json()["id"]
    nonce = agent.get("/api/agent/commands").json()["commands"][0]["nonce"]
    agent.post(f"/api/agent/commands/{cid}/result", json={"nonce": nonce, "status": "succeeded"})
    assert admin.get(f"/api/devices/{device_id}").json()["check_in_interval_seconds"] == 600


def test_command_rbac(admin, device):
    _, device_id = device
    make_user(admin, "viewer")
    make_user(admin, "analyst")
    app = admin.app
    # No `with`: entering a TestClient context would re-run the app lifespan (and re-init the DB).
    viewer, analyst = TestClient(app, base_url=BASE_URL), TestClient(app, base_url=BASE_URL)
    login(viewer, "viewer@example.com", "a-long-test-password")
    login(analyst, "analyst@example.com", "a-long-test-password")
    assert viewer.get("/api/devices").status_code == 200
    assert viewer.get(f"/api/devices/{device_id}/software").status_code == 200
    for t in ("recheck_posture", "collect_logs", "lock_device", "restart_agent"):
        assert queue(viewer, device_id, t).status_code == 403
    assert queue(analyst, device_id, "recheck_posture").status_code == 201
    assert queue(analyst, device_id, "collect_logs").status_code == 201
    for t in ("lock_device", "restart_agent"):
        assert queue(analyst, device_id, t).status_code == 403
    assert queue(analyst, device_id, "update_check_in_interval",
                 params={"interval_seconds": 600}).status_code == 403
    assert analyst.post("/api/devices/enrollment-tokens", json={"name": "x"}).status_code == 403
    assert analyst.get("/api/devices/enrollment-tokens").status_code == 403
    assert analyst.post(f"/api/devices/{device_id}/revoke", json={"reason": "abc"}).status_code == 403
    assert analyst.delete(f"/api/devices/{device_id}?reason=abc").status_code == 403
    lock = queue(admin, device_id, "lock_device", reason="user reported theft")
    assert lock.status_code == 201
    # analysts cannot cancel an admin-only action
    r = analyst.post(f"/api/devices/{device_id}/commands/{lock.json()['id']}/cancel", json={"reason": "oops"})
    assert r.status_code == 403
    r = admin.post(f"/api/devices/{device_id}/commands/{lock.json()['id']}/cancel", json={"reason": "oops"})
    assert r.status_code == 200 and r.json()["status"] == "cancelled"


def test_csrf_required_for_device_actions(admin, device):
    _, device_id = device
    token = admin.headers.pop("X-CSRF-Token")
    assert queue(admin, device_id, "recheck_posture").status_code == 403
    admin.headers["X-CSRF-Token"] = token


# --------------------------------------------------------------------------- log bundles
def _bundle() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b"agent log line\n"
        info = tarfile.TarInfo("agent.log")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_log_bundle_upload_and_download(admin, device):
    agent, device_id = device
    cid = queue(admin, device_id, "collect_logs").json()["id"]
    nonce = agent.get("/api/agent/commands").json()["commands"][0]["nonce"]
    hdr = {"Content-Type": "application/gzip"}
    assert agent.post(f"/api/agent/commands/{cid}/logs", content=_bundle(),
                      headers={**hdr, "X-Command-Nonce": "f" * 32}).status_code == 403
    assert agent.post(f"/api/agent/commands/{cid}/logs", content=b"not gzip",
                      headers={**hdr, "X-Command-Nonce": nonce}).status_code == 415
    r = agent.post(f"/api/agent/commands/{cid}/logs", content=_bundle(), headers={**hdr, "X-Command-Nonce": nonce})
    assert r.status_code == 201, r.text
    assert agent.post(f"/api/agent/commands/{cid}/logs", content=_bundle(),
                      headers={**hdr, "X-Command-Nonce": nonce}).status_code == 409
    agent.post(f"/api/agent/commands/{cid}/result", json={"nonce": nonce, "status": "succeeded"})
    c = admin.get(f"/api/devices/{device_id}/commands").json()[0]
    assert c["log_bundle_id"] == r.json()["id"]
    dl = admin.get(f"/api/devices/{device_id}/log-bundles/{c['log_bundle_id']}")
    assert dl.status_code == 200 and dl.headers["content-type"] == "application/gzip"
    assert gzip.decompress(dl.content)  # valid gzip
    make_user(admin, "viewer")
    viewer = TestClient(admin.app, base_url=BASE_URL)
    login(viewer, "viewer@example.com", "a-long-test-password")
    assert viewer.get(f"/api/devices/{device_id}/log-bundles/{c['log_bundle_id']}").status_code == 403


def test_log_bundle_size_cap(admin, device, monkeypatch):
    agent, device_id = device
    monkeypatch.setenv("DEVICE_LOG_BUNDLE_MAX_BYTES", "1000")
    config.reload_settings()
    cid = queue(admin, device_id, "collect_logs").json()["id"]
    nonce = agent.get("/api/agent/commands").json()["commands"][0]["nonce"]
    big = b"\x1f\x8b" + b"0" * 5000
    r = agent.post(f"/api/agent/commands/{cid}/logs", content=big,
                   headers={"Content-Type": "application/gzip", "X-Command-Nonce": nonce})
    assert r.status_code == 413
    monkeypatch.delenv("DEVICE_LOG_BUNDLE_MAX_BYTES")
    config.reload_settings()


def test_logs_only_for_collect_logs(admin, device):
    agent, device_id = device
    cid = queue(admin, device_id, "recheck_posture").json()["id"]
    nonce = agent.get("/api/agent/commands").json()["commands"][0]["nonce"]
    r = agent.post(f"/api/agent/commands/{cid}/logs", content=_bundle(),
                   headers={"Content-Type": "application/gzip", "X-Command-Nonce": nonce})
    assert r.status_code == 409


# --------------------------------------------------------------------------- delete
def test_delete_device_removes_everything(admin, device):
    agent, device_id = device
    queue(admin, device_id, "recheck_posture")
    assert admin.delete(f"/api/devices/{device_id}").status_code == 422  # reason required
    assert admin.delete(f"/api/devices/{device_id}?reason=decommissioned").status_code == 204
    assert admin.get(f"/api/devices/{device_id}").status_code == 404
    assert agent.get("/api/agent/commands").status_code == 401
    with db.get_session() as s:
        assert s.query(DeviceCommand).count() == 0 and s.query(DevicePostureSnapshot).count() == 0
    assert admin.get("/api/audit-log?action=device_deleted").json()[0]["detail"]["reason"] == "decommissioned"
