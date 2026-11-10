"""Dedicated directory collectors: their own enrollment and credential, the
command allow-list (the server can never queue anything but directory work to
a collector), sources that use them (sealed LDAP default, legacy endpoint-agent
sources and switching), uploads, failover, RBAC, tenancy, the domain-controller
flag, offline notifications, signed collector releases and the installer.
Runs on SQLite and PostgreSQL; the tests play the collector."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import sys
import zipfile
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import db
from app.directory import collectors as coll
from app.directory.models import CollectorCommand, DirectoryCollector, DirectoryComputer, DirectorySource
from app.models import AuditLog, utcnow
from app.notifications.models import NotificationEvent
from tests.conftest import BASE_URL, login, make_user
from tests.test_devices import agent_client, enroll, new_token
from tests.test_directory import DOMAIN, add_device, computer, join, legacy_source, scheduler, user  # noqa: F401
from tests.test_tenancy import ACME_ADMIN, ACME_PASSWORD, create_org, org_client

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import agent_release as rel_tool  # noqa: E402

UA = "cnapp-collector/1.4.0 (windows; amd64)"


@pytest.fixture()
def admin(empty_client):
    from app.api import devices as devices_api

    devices_api.installer_limiter.reset()
    return empty_client


def facts(host: str = "COLL01", **over) -> dict:
    return {"hostname": host, "dns_hostname": f"{host.lower()}.{DOMAIN}", "domain": DOMAIN,
            "os_name": "Windows Server 2022 Standard", "os_version": "10.0.20348", "architecture": "amd64",
            "version": "1.4.0", "run_as": "CORP\\COLL01$", "run_as_kind": "computer_account",
            "is_domain_controller": False, "features": "directory_sync,collector_diagnostics", **over}


def collector_token(admin, **body) -> str:
    r = admin.post("/api/collectors/enrollment-tokens", json={"name": "collectors", "max_uses": 5, **body})
    assert r.status_code == 201, r.text
    assert r.json()["token"].startswith("cnct_")
    return r.json()["token"]


def enroll_collector(admin, host: str = "COLL01", machine: str = "c" * 64, **f) -> tuple[TestClient, str]:
    c = TestClient(admin.app, base_url=BASE_URL)
    r = c.post("/api/collector/enroll", json={"token": collector_token(admin), "machine_id": machine,
                                              "facts": facts(host, **f)})
    assert r.status_code == 200, r.text
    assert r.json()["collector_secret"].startswith("cnc_")
    c.headers.update({"Authorization": f"Bearer {r.json()['collector_secret']}", "User-Agent": UA})
    return c, r.json()["collector_id"]


def dedicated_source(admin, ids: list[str], **config) -> dict:
    r = admin.post("/api/directory/sources", json={"type": "ad", "name": "Corp AD",
                                                   "config": {"domain": DOMAIN, **config}, "collector_ids": ids})
    assert r.status_code == 201, r.text
    return r.json()


def fetch(c, type_: str = "directory_sync") -> dict:
    r = c.get("/api/collector/commands")
    assert r.status_code == 200, r.text
    cmds = [x for x in r.json()["commands"] if x["type"] == type_]
    assert len(cmds) == 1, r.json()
    return cmds[0]


def batch(c, cmd: dict, seq: int, *, final=False, computers=(), users=(), **extra):
    body = {"seq": seq, "final": final, "computers": list(computers), "users": list(users), "truncated": False,
            **extra}
    if final:
        body.setdefault("status", "succeeded")
        body.setdefault("totals", None)
    return c.post(cmd["params"]["upload_path"], content=gzip.compress(json.dumps(body).encode()), headers={
        "X-Directory-Sync-Token": cmd["params"]["upload_token"], "Content-Type": "application/json",
        "Content-Encoding": "gzip"})


# ----------------------------------------------------------------------------- identity
def test_enrollment_is_a_separate_identity(admin):
    c, cid = enroll_collector(admin)
    # Agent tokens do not enroll collectors and collector tokens do not enroll agents.
    anon = TestClient(admin.app, base_url=BASE_URL)
    assert anon.post("/api/collector/enroll", json={"token": new_token(admin), "facts": facts()}).status_code == 401
    assert enroll(agent_client(admin.app), collector_token(admin)).status_code == 401
    # Collector tokens are not listed with agent tokens.
    assert all(not t["token_prefix"].startswith("cnct_") for t in admin.get("/api/devices/enrollment-tokens").json())
    assert len(admin.get("/api/collectors/enrollment-tokens/list").json()) >= 2
    # A collector credential is not a device credential and vice versa.
    assert c.get("/api/agent/commands").status_code == 401
    agent, dev = add_device(admin, "PC1", "1" * 64)
    assert agent.get("/api/collector/commands").status_code == 401
    assert anon.get("/api/collector/commands", headers={"Authorization": "Bearer cnc_" + "x" * 43}).status_code == 401
    # Not a device, not an IT asset, not an endpoint.
    assert [d["hostname"] for d in admin.get("/api/devices").json()] == ["PC1"]
    assert admin.get("/api/devices/summary").json()["total"] == 1
    assets = admin.get("/api/it-assets").json()
    assert all(a.get("device_hostname") != "COLL01" for a in (assets["items"] if isinstance(assets, dict) else assets))
    # Listed under Collectors with its facts; the secret is stored hashed only.
    lst = admin.get("/api/collectors").json()
    assert [x["name"] for x in lst] == ["COLL01"] and lst[0]["state"] == "online"
    assert lst[0]["run_as"] == "CORP\\COLL01$" and lst[0]["run_as_kind"] == "computer_account"
    with db.get_session("default") as s:
        row = s.get(DirectoryCollector, cid)
        assert len(row.secret_hash) == 64
        actions = {a.action for a in s.scalars(select(AuditLog))}
    assert {"directory_collector_token_created", "directory_collector_enrolled"} <= actions
    # Re-installing on the same machine keeps the record and rotates the credential.
    c2, cid2 = enroll_collector(admin)
    assert cid2 == cid
    assert c.get("/api/collector/commands").status_code == 401
    assert c2.get("/api/collector/commands").status_code == 200


def test_heartbeat_domain_controller_flag_and_rename_revoke(admin):
    c, cid = enroll_collector(admin)
    r = c.post("/api/collector/heartbeat", json={"facts": facts(is_domain_controller=True,
                                                                run_as="CORP\\svc-collector$",
                                                                run_as_kind="gmsa")})
    assert r.status_code == 200, r.text
    got = admin.get(f"/api/collectors/{cid}").json()
    assert got["is_domain_controller"] is True and got["run_as_kind"] == "gmsa"
    assert c.post("/api/collector/heartbeat", json={"facts": {**facts(), "evil": 1}}).status_code == 422
    r = admin.patch(f"/api/collectors/{cid}", json={"name": "Lagos collector"})
    assert r.status_code == 200 and r.json()["name"] == "Lagos collector"
    assert admin.delete(f"/api/collectors/{cid}").status_code == 409  # revoke first
    assert admin.post(f"/api/collectors/{cid}/revoke").json()["status"] == "revoked"
    assert c.get("/api/collector/commands").status_code == 403
    assert admin.delete(f"/api/collectors/{cid}").status_code == 204
    with db.get_session("default") as s:
        actions = [a.action for a in s.scalars(select(AuditLog))]
    for a in ("directory_collector_on_domain_controller", "directory_collector_renamed", "directory_collector_revoked",
              "directory_collector_deleted"):
        assert a in actions


# ----------------------------------------------------------------------------- allow-list
@pytest.mark.parametrize("bad", ["run_script", "start_remote_session", "isolate_host", "lock_device", "wipe_device",
                                 "collect_logs", "restart_agent", "enable_lost_mode", "anything"])
def test_server_refuses_other_command_types(admin, bad):
    _, cid = enroll_collector(admin)
    with db.get_session("default") as s:
        c = s.get(DirectoryCollector, cid)
        with pytest.raises(coll.CollectorError) as e:
            coll.new_command(s, c, bad, {}, "x", actor="admin@example.com")
        assert e.value.status == 422
        assert s.scalar(select(CollectorCommand.id)) is None
    assert set(coll.COMMAND_TYPES) == {"directory_sync", "collector_diagnostics", "collector_health",
                                       "check_for_update", "network_subnets", "network_scan"}
    # A collector id is not a device: the device command API does not know it.
    r = admin.post(f"/api/devices/{cid}/commands", json={"type": "lock_device", "reason": "nope"})
    assert r.status_code in (404, 422)


def test_on_collector_diagnostics(admin):
    c, cid = enroll_collector(admin)
    src = dedicated_source(admin, [cid])
    r = admin.post(f"/api/collectors/{cid}/test", json={"source_id": src["id"]})
    assert r.status_code == 202, r.text
    cmd = fetch(c, "collector_diagnostics")
    assert cmd["params"]["security"] == "sealed" and cmd["params"]["port"] == 389
    assert cmd["params"]["auth"] == "kerberos" and "credential" not in cmd["params"]
    steps = [{"id": "dc_locator", "label": "DC locator", "status": "pass", "detail": "dc01, dc02"},
             {"id": "port", "label": "Port 389", "status": "warn",
              "detail": "dc02.corp.example.com: listed in DNS as a DC but not responding"},
             {"id": "certificate", "label": "Certificate", "status": "skip", "detail": "not needed (sealed)"},
             {"id": "bind", "label": "Bind", "status": "pass", "detail": "CORP\\COLL01$, signed+sealed: yes"},
             {"id": "read", "label": "Read 5 objects", "status": "pass", "detail": "5 objects"}]
    r = c.post(f"/api/collector/commands/{cmd['id']}/result", json={
        "nonce": cmd["nonce"], "status": "succeeded", "output": "all checks passed",
        "result_data": {"steps": steps, "transport": "sealed", "signed_sealed": True,
                        "server": "dc01.corp.example.com", "identity": "CORP\\COLL01$"}})
    assert r.status_code == 204, r.text
    d = admin.get(f"/api/collectors/{cid}").json()["diagnostics"]
    assert d["status"] == "succeeded" and d["signed_sealed"] is True and d["transport"] == "sealed"
    assert [x["status"] for x in d["steps"]] == ["pass", "warn", "skip", "pass", "pass"]
    # Replays are refused.
    assert c.post(f"/api/collector/commands/{cmd['id']}/result", json={
        "nonce": cmd["nonce"], "status": "succeeded"}).status_code == 409


# ----------------------------------------------------------------------------- sources
def test_new_sources_use_dedicated_collectors_with_sealed_default(admin):
    _, cid = enroll_collector(admin)
    src = dedicated_source(admin, [cid])
    assert src["config"]["security"] == "sealed" and src["config"]["port"] == 389
    assert src["legacy_collectors"] is False and src["dedicated_collectors"][0]["id"] == cid
    base = {"type": "ad", "name": "x", "config": {"domain": DOMAIN}}
    # Endpoint agents are refused for new sources; unknown collectors too.
    _, dev = add_device(admin, "PC1", "1" * 64, join_facts=join("PC1", 1100))
    assert admin.post("/api/directory/sources", json={**base, "collector_device_ids": [dev]}).status_code == 422
    assert admin.post("/api/directory/sources", json={**base, "collector_ids": [dev]}).status_code == 404
    # Service accounts never send a password over sealed LDAP: TLS by default, sealed refused.
    sa = {**base, "config": {"domain": DOMAIN, "auth": "service_account"}, "collector_ids": [cid],
          "credential": {"username": "svc@corp.example.com", "password": "Sup3r-secret-LDAP-pass!"}}
    r = admin.post("/api/directory/sources", json=sa)
    assert r.status_code == 201 and r.json()["config"]["security"] == "ldaps" and r.json()["config"]["port"] == 636
    bad = {**sa, "config": {"domain": DOMAIN, "auth": "service_account", "security": "sealed"}}
    assert admin.post("/api/directory/sources", json=bad).status_code == 422
    assert admin.post("/api/directory/sources", json={**base, "collector_ids": [cid], "config": {
        "domain": DOMAIN, "security": "sealed", "port": 636}}).status_code == 422
    # LDAPS / StartTLS stay selectable.
    r = admin.post("/api/directory/sources", json={**base, "collector_ids": [cid],
                                                   "config": {"domain": DOMAIN, "security": "starttls"}})
    assert r.status_code == 201 and r.json()["config"]["port"] == 389


def test_sync_on_dedicated_collector(admin):
    c, cid = enroll_collector(admin)
    src = dedicated_source(admin, [cid])
    r = admin.post(f"/api/directory/sources/{src['id']}/sync")
    assert r.status_code == 202, r.text
    assert r.json()["collector_id"] == cid and r.json()["device_hostname"] == "COLL01"
    cmd = fetch(c)
    p = cmd["params"]
    assert p["upload_path"] == f"/api/collector/directory/runs/{p['run_id']}/batches"
    assert p["security"] == "sealed" and len(p["upload_token"]) >= 40
    with db.get_session("default") as s:
        stored = s.get(CollectorCommand, cmd["id"])
        assert "upload_token" not in stored.params
    # An endpoint agent cannot upload into a collector's run.
    agent, _ = add_device(admin, "PC1", "1" * 64)
    bad = agent.post(f"/api/agent/directory/runs/{p['run_id']}/batches", content=gzip.compress(b"{}"),
                     headers={"X-Directory-Sync-Token": p["upload_token"], "Content-Encoding": "gzip"})
    assert bad.status_code in (404, 422)
    assert batch(c, cmd, 0, computers=[computer(1, "PC1"), computer(2, "PC2")], users=[user(1, "alice")]
                 ).status_code == 200
    r = batch(c, cmd, 1, final=True, totals={"computers": 2, "users": 1}, server="dc01.corp.example.com")
    assert r.status_code == 200, r.text
    run = admin.get(f"/api/directory/runs/{p['run_id']}").json()
    assert run["status"] == "succeeded" and run["computers_seen"] == 2
    assert admin.get(f"/api/directory/sources/{src['id']}").json()["computers_count"] == 2


def test_failover_between_collectors(admin, scheduler):  # noqa: F811
    c1, id1 = enroll_collector(admin, "COLL01", "c" * 64)
    c2, id2 = enroll_collector(admin, "COLL02", "d" * 64)
    src = dedicated_source(admin, [id1, id2])
    run = admin.post(f"/api/directory/sources/{src['id']}/sync").json()
    assert run["collector_id"] == id1
    # COLL01 never picks it up: after the pickup timeout the run fails over to COLL02.
    sched = scheduler
    later = utcnow() + timedelta(minutes=16)
    with db.get_session("default") as s:
        s.get(DirectoryCollector, id2).last_seen_at = later
        s.commit()
    out = sched.tick(now=later)
    assert run["id"] in out["failed"] and len(out["failed_over"]) == 1
    nxt = admin.get(f"/api/directory/runs/{out['failed_over'][0]}").json()
    assert nxt["collector_id"] == id2 and nxt["attempt"] == 2
    assert fetch(c2)["params"]["run_id"] == nxt["id"]
    # Offline notification: COLL01 has been silent for 16 minutes (raised once).
    with db.get_session("default") as s:
        ev = [e for e in s.scalars(select(NotificationEvent)) if e.event_type == "collector_offline"]
        assert [e.title for e in ev] == ["Directory collector offline: COLL01"], [e.title for e in ev]
    sched.tick(now=later + timedelta(minutes=1))
    with db.get_session("default") as s:
        assert len([e for e in s.scalars(select(NotificationEvent))
                    if e.event_type == "collector_offline" and "COLL01" in e.title]) == 1


def test_legacy_source_keeps_working_and_switches_without_losing_data(admin):
    agent, dev = add_device(admin, "COLLECTOR1", "1" * 64, join_facts=join("COLLECTOR1", 1100))
    src = legacy_source(admin, [dev])
    assert src["legacy_collectors"] is True and src["config"]["security"] == "ldaps"
    # Legacy runs still go to the endpoint agent.
    from tests.test_directory import run_sync

    run = run_sync(admin, agent, src["id"], computers=[computer(1, "PC1")])
    assert run["status"] == "succeeded"
    # Switch to a dedicated collector: objects and history stay.
    c, cid = enroll_collector(admin)
    r = admin.patch(f"/api/directory/sources/{src['id']}", json={"collector_ids": [cid]})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["legacy_collectors"] is False and out["collector_device_ids"] == [] and out["collector_ids"] == [cid]
    assert out["computers_count"] == 1 and len(admin.get(f"/api/directory/sources/{src['id']}/runs").json()) == 1
    with db.get_session("default") as s:
        assert s.scalar(select(DirectoryComputer.name)) == "PC1"
        assert any(a.detail.get("changes", {}).get("switched_to_dedicated") for a in s.scalars(
            select(AuditLog).where(AuditLog.action == "directory_source_updated")))
    # Endpoint agents cannot be chosen again.
    assert admin.patch(f"/api/directory/sources/{src['id']}", json={"collector_device_ids": [dev]}).status_code == 422
    assert admin.post(f"/api/directory/sources/{src['id']}/sync").json()["collector_id"] == cid


# ----------------------------------------------------------------------------- RBAC / tenancy
def test_rbac_and_tenancy(admin):
    c, cid = enroll_collector(admin)
    make_user(admin, "viewer")
    make_user(admin, "analyst")
    for role in ("viewer", "analyst"):
        u = TestClient(admin.app, base_url=BASE_URL)
        login(u, f"{role}@example.com", "a-long-test-password")
        assert u.get("/api/collectors").status_code == 200
        assert u.patch(f"/api/collectors/{cid}", json={"name": "x"}).status_code == 403
        assert u.post(f"/api/collectors/{cid}/revoke").status_code == 403
        assert u.post(f"/api/collectors/{cid}/test", json={}).status_code == 403
        assert u.post("/api/collectors/enrollment-tokens", json={}).status_code == 403
        assert u.post("/api/collectors/installer", json={}).status_code == 403
    create_org("acme", ACME_ADMIN, ACME_PASSWORD)
    acme = org_client(admin.app, ACME_ADMIN, ACME_PASSWORD)
    assert acme.get("/api/collectors").json() == []
    assert acme.get(f"/api/collectors/{cid}").status_code == 404
    assert acme.post(f"/api/collectors/{cid}/revoke").status_code == 404
    assert acme.post("/api/directory/sources", json={"type": "ad", "name": "x", "config": {"domain": DOMAIN},
                                                     "collector_ids": [cid]}).status_code == 404


# ----------------------------------------------------------------------------- releases / installer
@pytest.fixture()
def release_key(monkeypatch):
    k = Ed25519PrivateKey.generate()
    monkeypatch.setenv("AGENT_UPDATE_TRUSTED_KEYS", rel_tool.trusted_line(k))
    from app import config

    config.reload_settings()
    yield k
    monkeypatch.delenv("AGENT_UPDATE_TRUSTED_KEYS")
    config.reload_settings()


def bundle(tmp_path: Path, version: str, key, *, collector=True, tamper=False) -> bytes:
    bins = []
    for goos, arch in (("windows", "amd64"), ("darwin", "arm64")):
        p = tmp_path / f"cnapp-agent-{goos}-{arch}{'.exe' if goos == 'windows' else ''}"
        p.write_bytes(f"agent {version} {goos}/{arch}".encode() * 50)
        bins.append(p)
    cbins = []
    if collector:
        for arch in ("amd64", "arm64"):
            p = tmp_path / f"cnapp-collector-windows-{arch}.exe"
            p.write_bytes(f"collector {version} {arch}".encode() * 50)
            cbins.append(p)
    m = rel_tool.build_manifest(version, bins, days=30, min_supported="0.0.0", notes="t", rollback_from=[])
    cenv = None
    if cbins:
        cm = rel_tool.build_manifest(version, cbins, days=30, min_supported="0.0.0", notes="t", rollback_from=[],
                                     product="cnapp-collector")
        cenv = rel_tool.sign_manifest(cm, [key])
        if tamper:
            cbins[0].write_bytes(b"evil" + cbins[0].read_bytes()[4:])
    out = tmp_path / f"b-{version}.tar.gz"
    rel_tool.write_bundle(out, rel_tool.sign_manifest(m, [key]), bins, cenv, cbins)
    return out.read_bytes()


def test_release_bundle_with_collector_and_self_update(admin, release_key, tmp_path):
    r = admin.post("/api/updates/releases", content=bundle(tmp_path, "1.5.0", release_key, tamper=True),
                   headers={"Content-Type": "application/gzip"})
    assert r.status_code == 422 and "collector" in r.text
    r = admin.post("/api/updates/releases", content=bundle(tmp_path, "1.5.0", release_key),
                   headers={"Content-Type": "application/gzip"})
    assert r.status_code == 201, r.text
    rel_id = r.json()["id"]
    # The agent manifest never lists collector artifacts (older agents reject duplicate platforms).
    from app.models import AgentRelease

    with db.get_session("default") as s:
        m = s.get(AgentRelease, rel_id).manifest
        assert all(a["name"].startswith("cnapp-agent-") for a in m["artifacts"])
    c, cid = enroll_collector(admin)
    hb = c.post("/api/collector/heartbeat", json={"facts": facts()}).json()
    assert hb["update"] is None  # the default ring targets nothing yet
    from app.models import AgentUpdateRing
    from app.services import agent_updates as upd

    with db.get_session("default") as s:  # the default ring targets the release (Devices > Agent updates)
        upd.ensure_default_rings(s)
        s.scalar(select(AgentUpdateRing).where(AgentUpdateRing.is_default.is_(True))).target_release_id = rel_id
        s.commit()
    offer = c.post("/api/collector/heartbeat", json={"facts": facts()}).json()["update"]
    assert offer["version"] == "1.5.0" and offer["artifact_path"].endswith("/artifacts/windows/amd64")
    man = c.get(offer["manifest_path"])
    assert man.status_code == 200 and json.loads(man.content)["signatures"]
    art = c.get(offer["artifact_path"])
    assert art.status_code == 200 and art.headers["X-Content-SHA256"] == hashlib.sha256(art.content).hexdigest()
    # Already on that version: no offer.
    c.headers["User-Agent"] = "cnapp-collector/1.5.0 (windows; amd64)"
    assert c.post("/api/collector/heartbeat", json={"facts": facts()}).json()["update"] is None


def test_installer_zip(admin, tmp_path, monkeypatch):
    d = tmp_path / "installers"
    d.mkdir()
    exe = b"MZ fake collector binary" * 100
    (d / "cnapp-collector-windows-amd64.exe").write_bytes(exe)
    (d / "manifest.json").write_text(json.dumps({"version": "1.4.0", "files": {
        "cnapp-collector-windows-amd64.exe": hashlib.sha256(exe).hexdigest()}}))
    monkeypatch.setenv("AGENT_INSTALLERS_DIR", str(d))
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://cnapp.example.com")
    from app import config

    config.reload_settings()
    info = admin.get("/api/collectors/installer/info").json()
    assert info["arches"]["amd64"]["available"] and not info["arches"]["arm64"]["available"]
    r = admin.post("/api/collectors/installer", json={"name": "Lagos", "format": "zip", "gmsa": "CORP\\svc-collector$"})
    assert r.status_code == 200, r.text
    z = zipfile.ZipFile(io.BytesIO(r.content))
    assert set(z.namelist()) == {"cnapp-collector.exe", "collector.json", "Install-Collector.ps1",
                                 "Uninstall-Collector.ps1", "README.txt"}
    assert z.read("cnapp-collector.exe") == exe
    preset = json.loads(z.read("collector.json"))
    assert preset["token"].startswith("cnct_") and preset["run_as"] == "CORP\\svc-collector$"
    assert preset["service_display_name"].endswith(" Collector")
    assert "LanmanNT" in z.read("Install-Collector.ps1").decode()  # the domain-controller warning
    # Single use, collector kind, plaintext only in the zip.
    t = next(x for x in admin.get("/api/collectors/enrollment-tokens/list").json() if x["package"])
    assert t["max_uses"] == 1
    assert preset["token"] not in admin.get("/api/collectors/enrollment-tokens/list").text
    assert admin.post("/api/collectors/installer", json={"format": "zip", "gmsa": "not-a-gmsa"}).status_code == 422
    assert admin.post("/api/collectors/installer", json={"format": "zip", "arch": "arm64"}).status_code == 503
    # No MSI in this bundle: the (default) MSI download says so instead of building something else.
    assert not info["msi"]["available"] and "zip" in info["msi"]["reason"]
    assert admin.post("/api/collectors/installer", json={}).status_code == 503
    scripts = admin.get("/api/collectors/setup/scripts", params={"domain": DOMAIN, "gmsa": "svc-collector",
                                                                 "hosts": "COLL01 COLL02"}).json()
    assert "Add-KdsRootKey" in scripts["kds_root_key"] and "10 hours" in scripts["kds_root_key"]
    assert "'COLL01$', 'COLL02$'" in scripts["create_gmsa"]
    assert "Test-ADServiceAccount" in scripts["install_gmsa"] and "sc.exe config" in scripts["service_logon"]
    with db.get_session("default") as s:
        assert s.scalar(select(DirectorySource.id)) is None
