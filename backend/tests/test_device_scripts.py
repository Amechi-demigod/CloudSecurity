"""Approved (signed) device scripts: manifest rules, bundle import (signature,
hashes, tampering, anti-rollback), RBAC, low-risk direct runs vs two-person
approval, typed parameter validation, device download endpoints, results."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import config, db
from app import script_manifest as sm
from app.models import AuditLog
from app.services import agent_updates, device_scripts
from tests.conftest import BASE_URL, login, make_user
from tests.test_approvals_lost_wipe import PW, enrolled, poll, result

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
import agent_release as rel_tool  # noqa: E402
import device_scripts as tool  # noqa: E402


@pytest.fixture()
def key(monkeypatch):
    k = Ed25519PrivateKey.generate()
    monkeypatch.setenv("DEVICE_SCRIPT_TRUSTED_KEYS", rel_tool.trusted_line(k))
    config.reload_settings()
    yield k
    monkeypatch.delenv("DEVICE_SCRIPT_TRUSTED_KEYS")
    config.reload_settings()


@pytest.fixture()
def admin(empty_client, key):
    return empty_client


@pytest.fixture()
def admin2(admin):
    make_user(admin, "admin", email="second-admin@example.com", password=PW)
    c = TestClient(admin.app, base_url=BASE_URL)
    login(c, "second-admin@example.com", PW)
    return c


def bundle(tmp_path: Path, version: str, keys, *, tamper: bool = False, days: int = 30, now=None) -> bytes:
    sources = tool.load_sources(REPO / "device-scripts")
    m = tool.build_manifest(version, sources, days=days, notes="test", now=now)
    env = tool.sign_manifest(m, keys)
    if tamper:
        e, data = sources[0]
        sources[0] = (e, data + b"\nWrite-Output 'evil'")
    out = tmp_path / f"s-{version}.tar.gz"
    tool.write_bundle(out, env, sources)
    return out.read_bytes()


def upload(c, data: bytes):
    return c.post("/api/scripts/bundles", content=data, headers={"Content-Type": "application/gzip"})


def run(c, device_id, script, parameters=None, reason="ticket INC-7"):
    return c.post("/api/scripts/run", json={"device_id": device_id, "script": script,
                                            "parameters": parameters or {}, "reason": reason})


# --------------------------------------------------------------------------- manifest rules (shared with the agent)
def test_repo_scripts_are_valid():
    sources = tool.load_sources(REPO / "device-scripts")
    names = {e["name"]: e for e, _ in sources}
    assert {"windows-list-local-admins", "windows-restart-print-spooler", "windows-clear-temp-files",
            "macos-list-local-admins"} <= set(names)
    assert names["windows-list-local-admins"]["risk"] == "low"
    assert names["macos-list-local-admins"]["risk"] == "low"
    assert names["windows-restart-print-spooler"]["risk"] == "medium"


def test_keys_files_match():
    """The server's script keys must be exactly the agent's compiled-in keys,
    and must not reuse the agent *release* key."""
    agent = agent_updates.parse_keys((REPO / "endpoint-agent/internal/scripts/trusted_keys.txt").read_text(), "agent")
    server = agent_updates.parse_keys(device_scripts.KEYS_FILE.read_text(), "server")
    assert [(k.key_id, k.public) for k in agent] == [(k.key_id, k.public) for k in server]
    release = agent_updates.parse_keys((REPO / "endpoint-agent/internal/update/trusted_keys.txt").read_text(), "rel")
    assert not {k.key_id for k in agent} & {k.key_id for k in release}


TEMP = {"name": "x-clean", "description": "d", "platform": "windows", "interpreter": "powershell",
        "file": "s.ps1", "timeout_seconds": 60, "risk": "medium",
        "parameters": [{"name": "days", "type": "int", "min": 1, "max": 30, "default": 7},
                       {"name": "scope", "type": "enum", "values": ["a", "b"]},
                       {"name": "svc", "type": "string", "pattern": "^[A-Za-z]{1,8}$", "required": False},
                       {"name": "dry", "type": "bool", "default": True}]}


def test_param_validation():
    e = sm.validate_script_entry(TEMP, signed=False)
    assert sm.validate_params(e, {"scope": "a"}) == {"days": 7, "scope": "a", "dry": True}
    assert sm.validate_params(e, {"scope": "b", "days": 30, "svc": "Spooler", "dry": False})["svc"] == "Spooler"
    for bad in ({}, {"scope": "c"}, {"scope": "a", "days": 0}, {"scope": "a", "days": "7; rm -rf /"},
                {"scope": "a", "days": True}, {"scope": "a", "svc": "Spooler; calc"}, {"scope": "a", "svc": "a\nb"},
                {"scope": "a", "dry": "yes"}, {"scope": "a", "other": 1}, {"scope": ["a"]}):
        with pytest.raises(sm.ManifestError):
            sm.validate_params(e, bad)


@pytest.mark.parametrize("patch", [
    {"name": "Bad Name"}, {"platform": "linux"}, {"interpreter": "bash"}, {"file": "../x.ps1"},
    {"file": "s.sh"}, {"timeout_seconds": 1}, {"timeout_seconds": 7200}, {"risk": "none"}, {"extra": 1},
    {"parameters": [{"name": "s", "type": "string", "pattern": "[a-z]+"}]},
    {"parameters": [{"name": "s", "type": "string", "pattern": "^(a)\\1$"}]},
    {"parameters": [{"name": "s", "type": "string", "pattern": "^(?i)a$"}]},
    {"parameters": [{"name": "n", "type": "int", "min": 5, "max": 1}]},
    {"parameters": [{"name": "n", "type": "int", "min": 1, "max": 5, "default": 9}]},
    {"parameters": [{"name": "e", "type": "enum", "values": ["a b"]}]},
    {"parameters": [{"name": "e", "type": "enum", "values": ["a"], "pattern": "^a$"}]},
    {"parameters": [{"name": "X", "type": "bool"}]},
    {"parameters": [{"name": "x", "type": "bool"}, {"name": "x", "type": "bool"}]},
])
def test_manifest_rules(patch):
    with pytest.raises(sm.ManifestError):
        sm.validate_script_entry({**TEMP, **patch}, signed=False)


# --------------------------------------------------------------------------- import
def test_import_and_library(admin, key, tmp_path):
    assert admin.get("/api/scripts").json()["bundle"] is None
    r = upload(admin, bundle(tmp_path, "1.0.0", [key]))
    assert r.status_code == 201, r.text
    lib = admin.get("/api/scripts").json()
    assert lib["bundle"]["version"] == "1.0.0" and lib["bundle"]["key_id"] == rel_tool.key_id(rel_tool.public_bytes(key))
    by = {s["name"]: s for s in lib["scripts"]}
    assert by["windows-list-local-admins"]["requires_approval"] is False
    assert by["windows-clear-temp-files"]["requires_approval"] is True
    assert [p["name"] for p in by["windows-clear-temp-files"]["parameters"]] == ["older_than_days", "scope", "dry_run"]
    # duplicate, older version
    assert "already imported" in upload(admin, bundle(tmp_path, "1.0.0", [key])).json()["detail"]
    upload(admin, bundle(tmp_path, "1.1.0", [key]))
    r = upload(admin, bundle(tmp_path, "1.0.5", [key]))
    assert r.status_code == 422 and "anti-rollback" in r.json()["detail"]
    assert admin.get("/api/scripts").json()["bundle"]["version"] == "1.1.0"
    with db.get_session() as s:
        acts = [a.action for a in s.scalars(select(AuditLog))]
    assert acts.count("device_script_bundle_imported") == 2 and "device_script_bundle_rejected" in acts


def test_import_refuses_bad_bundles(admin, key, tmp_path):
    other = Ed25519PrivateKey.generate()
    r = upload(admin, bundle(tmp_path, "1.0.0", [other]))
    assert r.status_code == 422 and "not signed by a trusted script-signing key" in r.json()["detail"]
    r = upload(admin, bundle(tmp_path, "1.0.0", [key], tamper=True))
    assert r.status_code == 422 and "SHA-256 does not match" in r.json()["detail"]
    old = datetime.now(UTC) - timedelta(days=40)
    r = upload(admin, bundle(tmp_path, "1.0.0", [key], days=30, now=old))
    assert r.status_code == 422 and "expired" in r.json()["detail"]
    assert upload(admin, b"not a tarball").status_code == 422
    # An agent *release* bundle signed with a trusted key is not a script bundle.
    payload = json.dumps({"schema": 1, "product": "cnapp-agent", "version": "1.0.0"}).encode()
    sig = base64.b64encode(key.sign(sm.SIG_CONTEXT + payload)).decode()
    env = json.dumps({"payload": base64.b64encode(payload).decode(),
                      "signatures": [{"key_id": rel_tool.key_id(rel_tool.public_bytes(key)), "sig": sig}]}).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        ti = tarfile.TarInfo("manifest.json")
        ti.size = len(env)
        tf.addfile(ti, io.BytesIO(env))
    r = upload(admin, buf.getvalue())
    assert r.status_code == 422 and "cnapp-device-scripts" in r.json()["detail"]
    # Signed with the agent-update context instead of the script context: refused.
    sources = tool.load_sources(REPO / "device-scripts")
    m = tool.build_manifest("1.0.0", sources, days=30, notes="")
    p2 = json.dumps(m, separators=(",", ":"), sort_keys=True).encode()
    bad = {"payload": base64.b64encode(p2).decode(), "signatures": [{
        "key_id": rel_tool.key_id(rel_tool.public_bytes(key)),
        "sig": base64.b64encode(key.sign(rel_tool.SIG_CONTEXT + p2)).decode()}]}
    out = tmp_path / "ctx.tar.gz"
    tool.write_bundle(out, json.dumps(bad).encode(), sources)
    r = upload(admin, out.read_bytes())
    assert r.status_code == 422 and "signature is invalid" in r.json()["detail"]
    assert admin.get("/api/scripts/bundles").json() == []


def test_no_keys_configured(empty_client, tmp_path, monkeypatch):
    monkeypatch.setattr(device_scripts, "KEYS_FILE", tmp_path / "no_script_signing_keys.txt")  # ignore the committed keys
    r = upload(empty_client, bundle(tmp_path, "1.0.0", [Ed25519PrivateKey.generate()]))
    assert r.status_code == 422 and "no trusted script-signing keys" in r.json()["detail"]


def test_rbac(admin, key, tmp_path):
    _, dev = enrolled(admin)
    make_user(admin, "analyst", password=PW)
    c = TestClient(admin.app, base_url=BASE_URL)
    login(c, "analyst@example.com", PW)
    assert upload(c, bundle(tmp_path, "1.0.0", [key])).status_code == 403
    upload(admin, bundle(tmp_path, "1.0.0", [key]))
    assert c.get("/api/scripts").status_code == 200 and c.get("/api/scripts/runs").status_code == 200
    assert run(c, dev, "windows-list-local-admins").status_code == 403


# --------------------------------------------------------------------------- running
def test_low_risk_runs_directly_and_agent_downloads(admin, key, tmp_path):
    agent, dev = enrolled(admin)
    upload(admin, bundle(tmp_path, "1.0.0", [key]))
    bid = admin.get("/api/scripts").json()["bundle"]["id"]
    # The script body is only served for a delivered run.
    assert agent.get(f"/api/agent/scripts/bundles/{bid}/scripts/windows-list-local-admins").status_code == 403
    r = run(admin, dev, "windows-list-local-admins")
    assert r.status_code == 201 and r.json()["mode"] == "command"
    (cmd,) = poll(agent)
    assert cmd["type"] == "run_script"
    p = cmd["params"]
    assert p["script"] == "windows-list-local-admins" and p["bundle_id"] == bid and p["parameters"] == {}
    env = agent.get(f"/api/agent/scripts/bundles/{bid}/manifest")
    assert env.status_code == 200
    m, _ = device_scripts.verify_envelope(env.content, device_scripts.trusted_keys())
    entry = next(e for e in m["scripts"] if e["name"] == p["script"])
    # Only the delivered script, not another one of the bundle.
    assert agent.get(f"/api/agent/scripts/bundles/{bid}/scripts/windows-clear-temp-files").status_code == 403
    body = agent.get(f"/api/agent/scripts/bundles/{bid}/scripts/{p['script']}")
    assert body.status_code == 200 and hashlib.sha256(body.content).hexdigest() == entry["sha256"] == p["script_sha256"]
    assert admin.get(f"/api/agent/scripts/bundles/{bid}/manifest").status_code == 401  # user session is not a device
    out = "exit code: 0\n--- stdout ---\nAdministrator\nCORP\\alice"
    assert result(agent, cmd, output=out, exit_code=0).status_code == 204
    (row,) = admin.get(f"/api/scripts/runs?device_id={dev}").json()
    assert row["status"] == "succeeded" and row["exit_code"] == 0 and "alice" in row["output"]
    assert row["hostname"] == "LAPTOP-001" and row["approved_by_email"] is None


def test_medium_risk_needs_second_admin(admin, admin2, key, tmp_path):
    agent, dev = enrolled(admin)
    upload(admin, bundle(tmp_path, "1.0.0", [key]))
    r = run(admin, dev, "windows-clear-temp-files", {"older_than_days": 30, "scope": "system"})
    assert r.status_code == 201 and r.json()["mode"] == "approval", r.text
    a = r.json()["approval"]
    assert a["risk"] == "medium" and "older_than_days=30" in a["summary"]
    assert a["params"]["parameters"] == {"older_than_days": 30, "scope": "system", "dry_run": False}
    assert poll(agent) == []
    assert admin.post(f"/api/approvals/{a['id']}/approve", json={}).status_code == 403
    assert len(admin.get("/api/scripts/pending-approvals").json()) == 1
    r = admin2.post(f"/api/approvals/{a['id']}/approve", json={"reason": "fine"})  # no typed name needed for scripts
    assert r.status_code == 200 and r.json()["status"] == "executed"
    (cmd,) = poll(agent)
    assert cmd["params"]["parameters"]["older_than_days"] == 30
    result(agent, cmd, status="failed", output="exit code: 1", exit_code=1)
    (row,) = admin.get("/api/scripts/runs?script=windows-clear-temp-files").json()
    assert row["exit_code"] == 1 and row["approved_by_email"] == "second-admin@example.com"


@pytest.mark.parametrize("script,params,status", [
    ("windows-clear-temp-files", {"older_than_days": 0}, 422),
    ("windows-clear-temp-files", {"scope": "C:\\"}, 422),
    ("windows-clear-temp-files", {"older_than_days": "7; Remove-Item C:\\ -Recurse"}, 422),
    ("windows-clear-temp-files", {"command": "whoami"}, 422),
    ("windows-list-local-admins", {"x": 1}, 422),
    ("macos-list-local-admins", {}, 409),  # platform mismatch
    ("no-such-script", {}, 404),
])
def test_run_validation(admin, key, tmp_path, script, params, status):
    _, dev = enrolled(admin)
    upload(admin, bundle(tmp_path, "1.0.0", [key]))
    assert run(admin, dev, script, params).status_code == status


def test_run_on_revoked_device_and_without_library(admin, key, tmp_path):
    _, dev = enrolled(admin)
    assert run(admin, dev, "windows-list-local-admins").status_code == 404
    upload(admin, bundle(tmp_path, "1.0.0", [key]))
    admin.post(f"/api/devices/{dev}/revoke", json={"reason": "gone"})
    assert run(admin, dev, "windows-list-local-admins").status_code == 409
