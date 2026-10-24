"""Agent auto-update: signed bundle import (signature, hashes, tampering), RBAC
(no per-action MFA step-up), device-credential-only update endpoints, ring / percentage /
pin targeting, status reporting, audit and notifications."""
from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pyotp
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import config, db, mfa
from app.api import agent_updates as api_mod
from app.models import AuditLog, Device
from app.notifications.models import NotificationEvent
from app.services import agent_updates as svc
from tests.conftest import BASE_URL, login, make_user
from tests.test_devices import agent_client, enroll, new_token, windows_checkin

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
import agent_release as rel_tool  # noqa: E402

UA_WIN = "cnapp-agent/{v} (windows; amd64)"


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


def make_bundle(tmp_path: Path, version: str, keys, *, platforms=(("windows", "amd64"), ("darwin", "arm64")),
                tamper: str | None = None, days: int = 30, rollback_from=(), now=None) -> bytes:
    bins = []
    for goos, arch in platforms:
        p = tmp_path / f"cnapp-agent-{goos}-{arch}{'.exe' if goos == 'windows' else ''}"
        p.write_bytes(f"binary {version} {goos}/{arch}".encode() * 100)
        bins.append(p)
    m = rel_tool.build_manifest(version, bins, days=days, min_supported="0.0.0", notes="test",
                                rollback_from=list(rollback_from), now=now)
    env = rel_tool.sign_manifest(m, keys)
    if tamper == "artifact":
        bins[0].write_bytes(b"evil" + bins[0].read_bytes()[4:])
    out = tmp_path / f"b-{version}.tar.gz"
    rel_tool.write_bundle(out, env, bins)
    return out.read_bytes()


def upload(c, data: bytes, **headers):
    return c.post("/api/updates/releases", content=data, headers={"Content-Type": "application/gzip", **headers})


def enrolled_device(admin, hostname="LAPTOP-001", machine="a" * 64, version="1.0.0"):
    token = new_token(admin)
    agent = agent_client(admin.app)
    r = enroll(agent, token, machine_id=machine, hostname=hostname)
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    agent.headers["User-Agent"] = UA_WIN.format(v=version)
    return agent, r.json()["device_id"]


def checkin(agent, version="1.0.0"):
    body = windows_checkin()
    body["device"]["hostname"] = "LAPTOP-001"
    body["device"]["agent_version"] = version
    agent.headers["User-Agent"] = UA_WIN.format(v=version)
    r = agent.post("/api/agent/checkin", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def ring(c, name="All devices"):
    return next(r for r in c.get("/api/updates/rings").json() if r["name"] == name)


def set_ring(c, ring_id, **body):
    r = c.patch(f"/api/updates/rings/{ring_id}", json={"reason": "test rollout", **body})
    assert r.status_code == 200, r.text
    return r.json()


def audits(action: str) -> list[AuditLog]:
    with db.get_session("default") as s:
        return list(s.scalars(select(AuditLog).where(AuditLog.action == action)))


# ----------------------------------------------------------------------------- import
def test_import_valid_bundle_and_list(admin, key, tmp_path):
    r = upload(admin, make_bundle(tmp_path, "1.1.0", [key]))
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["version"] == "1.1.0" and body["key_id"] == rel_tool.key_id(rel_tool.public_bytes(key))
    assert {(a["os"], a["arch"]) for a in body["artifacts"]} == {("windows", "amd64"), ("darwin", "arm64")}
    assert [x["version"] for x in admin.get("/api/updates/releases").json()] == ["1.1.0"]
    a = audits("agent_release_imported")
    assert len(a) == 1 and a[0].detail["version"] == "1.1.0" and "step_up" not in a[0].detail
    # Same version twice is refused.
    again = upload(admin, make_bundle(tmp_path, "1.1.0", [key]))
    assert again.status_code == 422 and "already imported" in again.json()["detail"]
    keys = admin.get("/api/updates/keys").json()["keys"]
    assert any(k["source"] == "AGENT_UPDATE_TRUSTED_KEYS" for k in keys)


def test_import_rejects_untrusted_tampered_and_malformed(admin, key, tmp_path):
    other = Ed25519PrivateKey.generate()
    cases = {
        "untrusted key": (make_bundle(tmp_path, "2.0.0", [other]), "not signed by a trusted"),
        "tampered artifact": (make_bundle(tmp_path, "2.0.1", [key], tamper="artifact"), "SHA-256 does not match"),
        "expired": (make_bundle(tmp_path, "2.0.2", [key], now=datetime.now(UTC) - timedelta(days=40)), "expired"),
        "not a tarball": (b"garbage", "not a valid .tar.gz"),
    }
    # Path traversal entry.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        ti = tarfile.TarInfo("../evil")
        ti.size = 1
        tf.addfile(ti, io.BytesIO(b"x"))
    cases["path traversal"] = (buf.getvalue(), "not a plain")
    # Manifest signature over a different payload.
    good = make_bundle(tmp_path, "2.0.3", [key])
    with tarfile.open(fileobj=io.BytesIO(good)) as tf:
        files = {m.name: tf.extractfile(m).read() for m in tf.getmembers()}
    env = json.loads(files["manifest.json"])
    import base64
    payload = json.loads(base64.b64decode(env["payload"]))
    payload["version"] = "9.9.9"
    env["payload"] = base64.b64encode(json.dumps(payload).encode()).decode()
    files["manifest.json"] = json.dumps(env).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for n, d in files.items():
            ti = tarfile.TarInfo(n)
            ti.size = len(d)
            tf.addfile(ti, io.BytesIO(d))
    cases["bad signature"] = (buf.getvalue(), "signature is invalid")
    for name, (data, msg) in cases.items():
        r = upload(admin, data)
        assert r.status_code == 422, (name, r.text)
        assert msg in r.json()["detail"], (name, r.json())
    assert admin.get("/api/updates/releases").json() == []
    assert len(audits("agent_release_rejected")) == len(cases)


def test_server_without_trusted_keys_refuses(empty_client, tmp_path, monkeypatch):
    monkeypatch.setattr(svc, "KEYS_FILE", tmp_path / "no_agent_update_keys.txt")  # ignore the committed keys
    k = Ed25519PrivateKey.generate()
    r = upload(empty_client, make_bundle(tmp_path, "1.0.0", [k]))
    assert r.status_code == 422 and "no trusted release-signing keys" in r.json()["detail"]


def test_committed_key_files_match():
    agent = svc.parse_keys((REPO / "endpoint-agent/internal/update/trusted_keys.txt").read_text(), "agent")
    server = svc.parse_keys(svc.KEYS_FILE.read_text(), "server")
    assert [k.key_id for k in agent] == [k.key_id for k in server]
    assert "PRIVATE KEY" not in svc.KEYS_FILE.read_text()


def test_python_and_go_compatible_signature_context():
    go = (REPO / "endpoint-agent/internal/update/manifest.go").read_text()
    assert 'SignatureContext = "cnapp-agent-update-manifest-v1\\x00"' in go
    assert svc.SIG_CONTEXT == rel_tool.SIG_CONTEXT == b"cnapp-agent-update-manifest-v1\x00"


# ----------------------------------------------------------------------------- RBAC / auth
def test_rbac_and_no_step_up(admin, key, tmp_path, monkeypatch):
    data = make_bundle(tmp_path, "1.1.0", [key])
    for role in ("viewer", "analyst"):
        make_user(admin, role)
        c = TestClient(admin.app, base_url=BASE_URL)
        login(c, f"{role}@example.com", "a-long-test-password")
        assert c.get("/api/updates/releases").status_code == 200
        assert c.get("/api/updates/rings").status_code == 200
        assert upload(c, data).status_code == 403
        assert c.patch(f"/api/updates/rings/{ring(admin)['id']}", json={"reason": "nope", "paused": True}).status_code == 403
    anon = TestClient(admin.app, base_url=BASE_URL)
    assert anon.get("/api/updates/releases").status_code == 401
    # An admin WITH MFA enabled needs no fresh code for previously step-up-gated
    # changes: MFA is enforced at sign-in only; the session (RBAC + CSRF) is enough.
    secret = admin.post("/api/auth/mfa/totp/setup").json()["secret"]
    now = [float(int(__import__("time").time() // 30) * 30 + 5)]
    monkeypatch.setattr(mfa.time, "time", lambda: now[0])
    assert admin.post("/api/auth/mfa/totp/enable", json={"code": pyotp.TOTP(secret).at(now[0])}).status_code == 200
    assert admin.get("/api/auth/me").json()["user"]["mfa_enabled"] is True
    r = upload(admin, data)
    assert r.status_code == 201, r.text
    assert "step_up" not in audits("agent_release_imported")[0].detail
    rid = ring(admin)["id"]
    ok = admin.patch(f"/api/updates/rings/{rid}", json={"reason": "go live", "target_release_id": r.json()["id"],
                                                       "rollout_percent": 100})
    assert ok.status_code == 200, ok.text
    assert admin.patch(f"/api/updates/rings/{rid}", json={"reason": "stop", "paused": True}).status_code == 200
    assert admin.patch(f"/api/updates/rings/{rid}", json={"reason": "resume", "paused": False}).status_code == 200
    _, device_id = enrolled_device(admin)
    pin = admin.put(f"/api/updates/devices/{device_id}", json={"reason": "pin it", "pinned_release_id": r.json()["id"]})
    assert pin.status_code == 200, pin.text
    # Everything stays audited.
    changed = audits("agent_update_ring_changed")
    assert len(changed) == 3 and all(a.actor_email == "admin@example.com" for a in changed)
    assert changed[0].detail["changes"]["target_release_id"]["version"] == "1.1.0"
    dev = audits("agent_update_device_changed")
    assert len(dev) == 1 and dev[0].detail["changes"]["pin"]["version"] == "1.1.0"


def test_update_endpoints_require_device_credential(admin, key, tmp_path):
    rel = upload(admin, make_bundle(tmp_path, "1.1.0", [key])).json()
    paths = [f"/api/agent/updates/releases/{rel['id']}/manifest",
             f"/api/agent/updates/releases/{rel['id']}/artifacts/windows/amd64"]
    for p in paths:  # the admin's session cookie is not a device credential
        assert admin.get(p).status_code == 401
        assert TestClient(admin.app, base_url=BASE_URL).get(p, headers={"Authorization": "Bearer cnd_wrong"}).status_code == 401
    assert admin.post("/api/agent/updates/status", json={"status": "installed"}).status_code == 401
    agent, _ = enrolled_device(admin)
    # ... and a device credential is not accepted by the admin API.
    bare = TestClient(admin.app, base_url=BASE_URL)
    assert bare.get("/api/updates/releases", headers={"Authorization": agent.headers["Authorization"]}).status_code == 401


# ----------------------------------------------------------------------------- targeting
def test_ring_targeting_percentage_pause_and_downloads(admin, key, tmp_path):
    rel = upload(admin, make_bundle(tmp_path, "1.1.0", [key])).json()
    agent, device_id = enrolled_device(admin)
    assert checkin(agent)["update"] is None  # rings have no target yet
    allr = ring(admin)
    set_ring(admin, allr["id"], target_release_id=rel["id"])
    offer = checkin(agent)["update"]
    assert offer["version"] == "1.1.0" and offer["release_id"] == rel["id"]
    assert offer["manifest_path"] == f"/api/agent/updates/releases/{rel['id']}/manifest"
    assert offer["artifact_path"].endswith("/artifacts/windows/amd64")
    assert 60 <= offer["health_timeout_seconds"] <= 3600
    # Manifest and artifact are served exactly as signed.
    m = agent.get(offer["manifest_path"])
    assert m.status_code == 200 and json.loads(m.content)["signatures"][0]["key_id"] == rel["key_id"]
    a = agent.get(offer["artifact_path"])
    win = next(x for x in rel["artifacts"] if x["os"] == "windows")
    assert a.status_code == 200 and hashlib.sha256(a.content).hexdigest() == win["sha256"] == a.headers["X-Content-SHA256"]
    assert agent.get(offer["artifact_path"].replace("windows/amd64", "windows/arm64")).status_code == 404
    # Percentage 0 and pause stop offers; resuming brings them back.
    set_ring(admin, allr["id"], rollout_percent=0)
    assert checkin(agent)["update"] is None
    set_ring(admin, allr["id"], rollout_percent=100, paused=True)
    assert checkin(agent)["update"] is None
    set_ring(admin, allr["id"], paused=False)
    assert checkin(agent)["update"] is not None
    # Already on the version, newer than the target, or another platform: nothing.
    assert checkin(agent, "1.1.0")["update"] is None
    assert checkin(agent, "1.2.0")["update"] is None
    agent.headers["User-Agent"] = "cnapp-agent/1.0.0 (windows; arm64)"
    assert agent.post("/api/agent/checkin", json=windows_checkin()).json()["update"] is None
    agent.headers["User-Agent"] = "curl/8"
    assert agent.post("/api/agent/checkin", json=windows_checkin()).json()["update"] is None
    # Withdrawn: no offer and no download.
    assert admin.post(f"/api/updates/releases/{rel['id']}/withdraw", json={"reason": "bad build"}).status_code == 200
    assert checkin(agent)["update"] is None
    assert agent.get(offer["manifest_path"]).status_code == 404
    summary = admin.get("/api/updates/summary").json()
    assert summary["devices"] == 1 and summary["versions"][0]["devices"] == 1


def test_percentage_buckets_are_stable_and_monotonic():
    devices = [f"{i:032x}" for i in range(400)]
    rid = "f" * 32
    at = {p: {d for d in devices if svc.in_rollout(d, rid, p)} for p in (0, 10, 50, 100)}
    assert not at[0] and at[100] == set(devices)
    assert at[10] <= at[50] <= at[100]
    assert 15 < len(at[10]) < 70 and 150 < len(at[50]) < 250


def test_explicit_ring_groups_and_pin(admin, key, tmp_path):
    r1 = upload(admin, make_bundle(tmp_path, "1.1.0", [key])).json()
    tmp2 = tmp_path / "2"
    tmp2.mkdir()
    r2 = upload(admin, make_bundle(tmp2, "1.2.0", [key])).json()
    agent, device_id = enrolled_device(admin)
    pilot, allr = ring(admin, "Pilot"), ring(admin, "All devices")
    set_ring(admin, allr["id"], target_release_id=r1["id"])
    set_ring(admin, pilot["id"], target_release_id=r2["id"])
    assert checkin(agent)["update"]["version"] == "1.1.0"
    # Device group "pilot" puts it in the Pilot ring.
    with db.get_session("default") as s:
        s.get(Device, device_id).device_group = "pilot"
        s.commit()
    assert checkin(agent)["update"]["version"] == "1.2.0"
    st = admin.get(f"/api/updates/devices/{device_id}").json()
    assert st["ring"]["name"] == "Pilot" and st["ring_assignment"] == "group" and st["target_version"] == "1.2.0"
    # Explicit assignment beats the group.
    r = admin.put(f"/api/updates/devices/{device_id}", json={"ring_id": allr["id"], "reason": "move back"})
    assert r.status_code == 200 and r.json()["ring"]["name"] == "All devices"
    assert checkin(agent)["update"]["version"] == "1.1.0"
    # A pin beats the ring, even a paused one.
    set_ring(admin, allr["id"], paused=True)
    r = admin.put(f"/api/updates/devices/{device_id}", json={"pinned_release_id": r2["id"], "reason": "canary"})
    assert r.status_code == 200 and r.json()["pinned_release"]["version"] == "1.2.0"
    assert checkin(agent)["update"]["version"] == "1.2.0"
    # Pinning to an older version is never offered without a signed rollback permission.
    r = admin.put(f"/api/updates/devices/{device_id}", json={"pinned_release_id": r1["id"], "reason": "rollback"})
    assert checkin(agent, "1.2.0")["update"] is None
    assert len(audits("agent_update_device_changed")) == 3
    # The default ring cannot be deleted; deleting another clears explicit members.
    assert admin.delete(f"/api/updates/rings/{allr['id']}", params={"reason": "x" * 5}).status_code == 409
    c = admin.post("/api/updates/rings", json={"name": "Canary", "reason": "new ring", "device_groups": ["canary"]})
    assert c.status_code == 201, c.text
    admin.put(f"/api/updates/devices/{device_id}", json={"ring_id": c.json()["id"], "reason": "x" * 5})
    assert admin.delete(f"/api/updates/rings/{c.json()['id']}", params={"reason": "cleanup"}).status_code == 204
    with db.get_session("default") as s:
        assert s.get(Device, device_id).update_ring_id is None


def test_signed_rollback_is_offered_to_named_version_only(admin, key, tmp_path):
    rel = upload(admin, make_bundle(tmp_path, "1.1.0", [key], rollback_from=["1.2.0"])).json()
    agent, device_id = enrolled_device(admin)
    admin.put(f"/api/updates/devices/{device_id}", json={"pinned_release_id": rel["id"], "reason": "roll back"})
    assert checkin(agent, "1.2.0")["update"]["version"] == "1.1.0"
    assert checkin(agent, "1.3.0")["update"] is None


# ----------------------------------------------------------------------------- status
def test_status_reporting_history_audit_and_notifications(admin, key, tmp_path):
    rel = upload(admin, make_bundle(tmp_path, "1.1.0", [key])).json()
    agent, device_id = enrolled_device(admin)
    set_ring(admin, ring(admin)["id"], target_release_id=rel["id"])
    for status in ("downloading", "verified", "installing"):
        r = agent.post("/api/agent/updates/status", json={"release_id": rel["id"], "from_version": "1.0.0",
                                                          "to_version": "1.1.0", "status": status})
        assert r.status_code == 204, r.text
    r = agent.post("/api/agent/updates/status", json={"release_id": rel["id"], "from_version": "1.0.0",
                                                      "to_version": "1.1.0", "status": "rolled_back",
                                                      "detail": "health check failed"})
    assert r.status_code == 204
    assert agent.post("/api/agent/updates/status", json={"status": "exploded"}).status_code == 422
    assert agent.post("/api/agent/updates/status", json={"status": "failed", "extra": 1}).status_code == 422
    st = admin.get(f"/api/updates/devices/{device_id}").json()
    assert [h["status"] for h in st["history"]] == ["rolled_back", "installing", "verified", "downloading"]
    assert st["status"] == "rolled_back" and st["status_detail"] == "health check failed"
    # A release that rolled back on this device is not offered to it again.
    assert checkin(agent)["update"] is None
    assert len(audits("agent_update_rolled_back")) == 1
    with db.get_session("default") as s:
        ev = s.scalars(select(NotificationEvent).where(NotificationEvent.source == "agent_update")).all()
        assert [e.event_type for e in ev] == ["update_rolled_back"]
    summary = admin.get("/api/updates/summary").json()
    assert summary["statuses"] == {"rolled_back": 1}
    assert any(rg["failed"] == 1 for rg in summary["rings"])


def test_parallel_download_limit(admin, key, tmp_path, monkeypatch):
    rel = upload(admin, make_bundle(tmp_path, "1.1.0", [key])).json()
    agent, _ = enrolled_device(admin)
    monkeypatch.setattr(api_mod.downloads, "active", config.settings.agent_update_max_parallel_downloads)
    r = agent.get(f"/api/agent/updates/releases/{rel['id']}/artifacts/windows/amd64")
    assert r.status_code == 503 and r.headers["Retry-After"]


def test_cli_import(admin, key, tmp_path, capsys):
    from app import cli

    p = tmp_path / "bundle.tar.gz"
    p.write_bytes(make_bundle(tmp_path, "3.0.0", [key]))
    assert cli.agent_release_import(type("A", (), {"bundle": str(p), "actor": "cnapp-ctl"})()) == 0
    assert "Imported agent release 3.0.0" in capsys.readouterr().out
    assert [r["version"] for r in admin.get("/api/updates/releases").json()] == ["3.0.0"]
    with pytest.raises(SystemExit):
        cli.agent_release_import(type("A", (), {"bundle": str(p), "actor": "cnapp-ctl"})())


def test_semver_matches_agent_rules():
    order = ["0.1.0-dev", "0.1.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0", "1.10.0"]
    for a, b in zip(order, order[1:], strict=False):
        assert svc.compare_versions(a, b) == -1, (a, b)
    assert svc.compare_versions("1.2.3+a", "1.2.3+b") == 0
    for bad in ("1.2", "01.2.3", "1.2.3-", "x"):
        with pytest.raises(ValueError):
            svc.parse_semver(bad)
    assert svc.parse_user_agent("cnapp-agent/1.2.3+abc (darwin; arm64)") == ("1.2.3+abc", "darwin", "arm64")
    assert svc.parse_user_agent("Mozilla/5.0") is None


def test_cli_notify_server_update(admin, capsys):
    """cnapp-ctl update raises failed/rolled-back server updates through the notification rules."""
    from app import cli

    args = type("A", (), {"status": "rolled_back", "from_tag": "a" * 40, "to_tag": "b" * 40,
                          "detail": "health check failed", "automatic": True, "actor": "cnapp-ctl"})()
    assert cli.notify_server_update(args) == 0
    assert "rolled_back" in capsys.readouterr().out
    with db.get_session("default") as s:
        ev = s.scalars(select(NotificationEvent).where(NotificationEvent.source == "server_update")).all()
        assert [(e.event_type, e.severity) for e in ev] == [("update_rolled_back", "high")]
        assert ev[0].attributes["automatic"] is True and ev[0].attributes["to_tag"] == "b" * 40
        assert "(automatic)" in ev[0].title
    assert any(s["name"] == "server_update" for s in admin.get("/api/notifications/meta").json()["sources"])
