"""Directory discovery (on-prem AD): domain-join facts, sources (RBAC, secrets),
sync runs (single-use tokens, paging, caps, missing objects), matching and
findings, scheduler failover, add-to-IT-assets, notifications and tenant
isolation. Runs on SQLite and PostgreSQL. No real directory is contacted: the
tests play the collector agent."""
from __future__ import annotations

import gzip
import json
import logging
from datetime import timedelta

import pytest
from sqlalchemy import select

from app import config, db
from app.directory import reconcile
from app.directory.models import DirectoryComputer, DirectoryFinding, DirectorySource, DirectorySyncRun
from app.directory.scheduler import DirectoryScheduler
from app.models import AuditLog, Device, DeviceCommand, utcnow
from app.notifications.models import NotificationEvent
from tests.conftest import login, make_user
from tests.test_devices import agent_client, enroll, new_token, windows_checkin
from tests.test_tenancy import ACME_ADMIN, ACME_PASSWORD, create_org, org_client

PASSWORD = "Sup3r-secret-LDAP-pass!"
FEATURES = {"X-CNAPP-Agent-Features": "check_for_update,host_isolation,directory_collector"}
DOMAIN = "corp.example.com"
SID = "S-1-5-21-1111-2222-3333"


def join(host: str, rid: int, domain: str = DOMAIN, netbios: str = "CORP") -> dict:
    return {"ad_domain": domain, "ad_netbios": netbios, "ad_forest": domain, "ad_domain_sid": SID,
            "ad_computer_sid": f"{SID}-{rid}", "ad_object_guid": "", "dns_hostname": f"{host.lower()}.{domain}",
            "entra_device_id": "", "entra_tenant_id": "", "entra_join_type": "", "intune_enrollment_id": "",
            "source": "lsa"}


def add_device(admin, hostname: str, machine: str, *, os_family: str = "windows", join_facts: dict | None = None,
               users: list[str] | None = None, collector: bool = True):
    agent = agent_client(admin.app)
    r = enroll(agent, new_token(admin), machine_id=machine, hostname=hostname, os_family=os_family)
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    if collector:
        agent.headers.update(FEATURES)
    checkin(agent, hostname, os_family=os_family, join_facts=join_facts, users=users or [])
    return agent, r.json()["device_id"]


def checkin(agent, hostname: str, *, os_family: str = "windows", join_facts: dict | None = None,
            users: list[str] | None = None):
    body = windows_checkin()
    body["device"].update({"hostname": hostname, "os_family": os_family, "serial_number": ""})
    if users is not None:
        body["device"]["logged_in_users"] = users
    if join_facts is not None:
        body["device"]["directory_join"] = join_facts
    r = agent.post("/api/agent/checkin", json=body)
    assert r.status_code == 200, r.text


def guid(n: int) -> str:
    return f"{n:08x}-0000-4000-8000-{n:012x}"


def computer(n: int, name: str, *, domain: str = DOMAIN, uac: int = 4096, logon_days: int | None = 1,
             ou: str = "OU=Laptops", rid: int | None = None) -> dict:
    dc = ",".join(f"DC={p}" for p in domain.split("."))
    logon = (utcnow() - timedelta(days=logon_days)).isoformat() + "Z" if logon_days is not None else None
    return {"object_guid": guid(n), "object_sid": f"{SID}-{rid or 1000 + n}", "cn": name.upper(),
            "dns_hostname": f"{name.lower()}.{domain}", "sam_account_name": f"{name.upper()}$",
            "operating_system": "Windows 11 Enterprise", "operating_system_version": "10.0 (22631)",
            "distinguished_name": f"CN={name.upper()},{ou},{dc}", "user_account_control": uac,
            "last_logon_timestamp": logon, "when_created": "2024-01-01T00:00:00Z", "when_changed": None}


def user(n: int, sam: str, *, uac: int = 512, logon_days: int | None = 1, domain: str = DOMAIN) -> dict:
    dc = ",".join(f"DC={p}" for p in domain.split("."))
    logon = (utcnow() - timedelta(days=logon_days)).isoformat() + "Z" if logon_days is not None else None
    return {"object_guid": guid(100000 + n), "object_sid": f"{SID}-{5000 + n}", "sam_account_name": sam,
            "user_principal_name": f"{sam}@{domain}", "mail": f"{sam}@example.com", "display_name": sam.title(),
            "given_name": sam.title(), "sn": "Test", "department": "Finance", "title": "Analyst",
            "manager_dn": "", "distinguished_name": f"CN={sam},OU=Staff,{dc}", "user_account_control": uac,
            "last_logon_timestamp": logon, "when_created": None, "pwd_last_set": None}


@pytest.fixture()
def admin(empty_client):
    return empty_client


@pytest.fixture()
def scheduler():
    sched = DirectoryScheduler()
    yield sched
    sched.stop()  # releases the leader lock


@pytest.fixture()
def collector(admin):
    return add_device(admin, "COLLECTOR1", "1" * 64, join_facts=join("COLLECTOR1", 1100))


def make_source(admin, collector_ids, **over) -> dict:
    body = {"type": "ad", "name": "Corp AD", "config": {"domain": DOMAIN}, "collector_device_ids": collector_ids}
    body.update(over)
    r = admin.post("/api/directory/sources", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def fetch_sync(agent) -> dict:
    r = agent.get("/api/agent/commands")
    assert r.status_code == 200, r.text
    cmds = [c for c in r.json()["commands"] if c["type"] == "directory_sync"]
    assert len(cmds) == 1, r.json()
    return cmds[0]


def post_batch(agent, cmd: dict, seq: int, *, computers=(), users=(), final=False, token=None, **extra):
    body = {"seq": seq, "final": final, "computers": list(computers), "users": list(users), "truncated": False,
            **extra}
    if final:
        body.setdefault("status", "succeeded")
        body.setdefault("totals", None)
    data = gzip.compress(json.dumps(body).encode())
    return agent.post(cmd["params"]["upload_path"], content=data, headers={
        "X-Directory-Sync-Token": token or cmd["params"]["upload_token"], "Content-Type": "application/json",
        "Content-Encoding": "gzip"})


def run_sync(admin, agent, source_id: str, computers=(), users=(), **final_extra) -> dict:
    r = admin.post(f"/api/directory/sources/{source_id}/sync")
    assert r.status_code == 202, r.text
    cmd = fetch_sync(agent)
    assert post_batch(agent, cmd, 0, computers=computers, users=users).status_code == 200
    r = post_batch(agent, cmd, 1, final=True, **final_extra)
    assert r.status_code == 200, r.text
    return admin.get(f"/api/directory/runs/{cmd['params']['run_id']}").json()


# ----------------------------------------------------------------------------- join facts
def test_checkin_stores_domain_join_facts(admin, collector):
    _, dev = collector
    d = admin.get(f"/api/devices/{dev}").json()
    assert d["directory_join"]["ad_domain"] == DOMAIN
    assert d["directory_join"]["ad_computer_sid"] == f"{SID}-1100"
    assert "directory_join" not in d["inventory"]
    with db.get_session("default") as s:
        row = s.get(Device, dev)
        assert (row.ad_domain, row.ad_computer_sid) == (DOMAIN, f"{SID}-1100")
        assert "directory_collector" in row.agent_features


@pytest.mark.parametrize("bad", [{"ad_domain": "corp example"}, {"ad_computer_sid": "not-a-sid"},
                                 {"entra_device_id": "xyz"}, {"unknown": "x"}, {"ad_domain": "a" * 300}])
def test_checkin_rejects_invalid_join_facts(admin, collector, bad):
    agent, _ = collector
    body = windows_checkin()
    body["device"]["hostname"] = "COLLECTOR1"
    body["device"]["directory_join"] = {**join("COLLECTOR1", 1100), **bad}
    assert agent.post("/api/agent/checkin", json=body).status_code == 422


# ----------------------------------------------------------------------------- sources
def test_source_validation_and_secret_handling(admin, collector, caplog):
    caplog.set_level(logging.DEBUG)
    _, dev = collector
    mac_agent, mac = add_device(admin, "MAC1", "2" * 64, os_family="macos")
    _, old = add_device(admin, "OLD1", "3" * 64, collector=False)
    base = {"type": "ad", "name": "Corp", "config": {"domain": DOMAIN}}
    # Unknown device / no collector feature / Kerberos needs Windows / service account needs a credential.
    assert admin.post("/api/directory/sources", json={**base, "collector_device_ids": ["f" * 32]}).status_code == 404
    assert admin.post("/api/directory/sources", json={**base, "collector_device_ids": [old]}).status_code == 422
    assert admin.post("/api/directory/sources", json={**base, "collector_device_ids": [mac]}).status_code == 422
    sa = {**base, "config": {"domain": DOMAIN, "auth": "service_account"}, "collector_device_ids": [mac]}
    assert admin.post("/api/directory/sources", json=sa).status_code == 422
    # Plain LDAP is refused; bad domains and DNs too.
    for cfg in ({"domain": DOMAIN, "port": 389}, {"domain": "not a domain"}, {"domain": DOMAIN, "base_dns": ["OU=x"]},
                {"domain": DOMAIN, "security": "none"}):
        assert admin.post("/api/directory/sources", json={**base, "config": cfg,
                                                          "collector_device_ids": [dev]}).status_code == 422
    r = admin.post("/api/directory/sources", json={**sa, "credential": {"username": "CORP\\svc-ldap",
                                                                        "password": PASSWORD}})
    assert r.status_code == 201, r.text
    src = r.json()
    assert src["has_credential"] and src["credential_username_hint"] == "CORP\\sv••••"
    assert PASSWORD not in r.text and "svc-ldap" not in r.text
    assert PASSWORD not in admin.get("/api/directory/sources").text
    # Stored encrypted; the queued command never contains it; the delivered one does (once, over TLS).
    with db.get_session("default") as s:
        row = s.get(DirectorySource, src["id"])
        assert row.secret_ciphertext and PASSWORD not in row.secret_ciphertext
    # mac is a fresh device: make it a healthy collector (it checked in) and sync.
    assert admin.post(f"/api/directory/sources/{src['id']}/sync").status_code == 202
    with db.get_session("default") as s:
        cmd = s.scalars(select(DeviceCommand).where(DeviceCommand.type == "directory_sync")).one()
        assert "credential" not in cmd.params and "upload_token" not in cmd.params
        assert PASSWORD not in json.dumps(cmd.params) and cmd.params["auth"] == "simple"
    delivered = fetch_sync(mac_agent)
    assert delivered["params"]["credential"] == {"username": "CORP\\svc-ldap", "password": PASSWORD}
    assert len(delivered["params"]["upload_token"]) >= 40
    # Commands list in the console never shows the credential.
    assert PASSWORD not in admin.get(f"/api/devices/{mac}/commands").text
    # Rotate: PATCH with a new credential, then clear (back to computer account on a Windows collector).
    r = admin.patch(f"/api/directory/sources/{src['id']}", json={"credential": {"username": "svc2@corp.example.com",
                                                                               "password": PASSWORD + "2"}})
    assert r.status_code == 200 and r.json()["credential_username_hint"] == "sv••••@corp.example.com"
    r = admin.patch(f"/api/directory/sources/{src['id']}", json={
        "clear_credential": True, "config": {"domain": DOMAIN, "auth": "computer_account"},
        "collector_device_ids": [dev]})
    assert r.status_code == 200, r.text
    assert not r.json()["has_credential"]
    # Never in the audit log or the application log.
    with db.get_session("default") as s:
        details = json.dumps([a.detail for a in s.scalars(select(AuditLog))])
        assert PASSWORD not in details
        actions = {a.action for a in s.scalars(select(AuditLog))}
    assert {"directory_source_created", "directory_source_updated", "directory_sync_requested"} <= actions
    assert PASSWORD not in caplog.text


def test_rbac(admin, collector):
    _, dev = collector
    src = make_source(admin, [dev])
    for role in ("viewer", "analyst"):
        make_user(admin, role)
    from fastapi.testclient import TestClient

    for role in ("viewer", "analyst"):
        c = TestClient(admin.app, base_url=str(admin.base_url))
        login(c, f"{role}@example.com", "a-long-test-password")
        assert c.get("/api/directory/sources").status_code == 200
        assert c.get("/api/directory/issues").status_code == 200
        assert c.get("/api/directory/summary").status_code == 200
        assert c.get("/api/directory/computers").status_code == 200
        assert c.get("/api/directory/issues/export.csv").status_code == 200
        assert c.post("/api/directory/sources", json={"type": "ad", "name": "x", "config": {"domain": DOMAIN},
                                                      "collector_device_ids": [dev]}).status_code == 403
        assert c.patch(f"/api/directory/sources/{src['id']}", json={"enabled": False}).status_code == 403
        assert c.delete(f"/api/directory/sources/{src['id']}").status_code == 403
        assert c.post(f"/api/directory/sources/{src['id']}/sync").status_code == 403
        assert c.post(f"/api/directory/sources/{src['id']}/test").status_code == 403
        assert c.post("/api/directory/computers/add-to-assets",
                      json={"computer_ids": ["a" * 32]}).status_code == 403
    # The generic command endpoint cannot queue directory_sync.
    r = admin.post(f"/api/devices/{dev}/commands", json={"type": "directory_sync", "reason": "nope"})
    assert r.status_code == 422


# ----------------------------------------------------------------------------- sync runs
def test_sync_ingests_batches_with_single_use_token(admin, collector):
    agent, dev = collector
    src = make_source(admin, [dev])
    r = admin.post(f"/api/directory/sources/{src['id']}/sync")
    assert r.status_code == 202 and r.json()["status"] == "queued" and r.json()["device_hostname"] == "COLLECTOR1"
    assert admin.post(f"/api/directory/sources/{src['id']}/sync").status_code == 409  # one at a time
    cmd = fetch_sync(agent)
    p = cmd["params"]
    assert p["auth"] == "kerberos" and "credential" not in p and p["security"] == "ldaps" and p["port"] == 636
    assert p["upload_path"] == f"/api/agent/directory/runs/{p['run_id']}/batches"
    assert p["scopes"] == ["computers", "users"] and p["max_objects"] == config.settings.directory_max_objects
    assert agent.get("/api/agent/commands").json()["commands"] == []  # handed out once
    # Wrong token, missing token, not gzip, gaps.
    assert post_batch(agent, cmd, 0, token="x" * 43).status_code == 403
    assert agent.post(p["upload_path"], content=b"{}", headers={"X-Directory-Sync-Token": p["upload_token"]}
                      ).status_code == 415
    assert post_batch(agent, cmd, 1).status_code == 409
    assert post_batch(agent, cmd, 0, computers=[computer(1, "PC1"), computer(2, "PC2")],
                      users=[user(1, "alice")]).status_code == 200
    # A retried batch is acknowledged as a duplicate, not stored twice.
    r = post_batch(agent, cmd, 0, computers=[computer(1, "PC1")])
    assert r.status_code == 200 and r.json()["duplicate"] is True
    assert post_batch(agent, cmd, 1, computers=[computer(3, "PC3")]).status_code == 200
    r = post_batch(agent, cmd, 2, final=True, totals={"computers": 3, "users": 1}, server="dc1.corp.example.com",
                   duration_ms=1234)
    assert r.status_code == 200, r.text
    run = admin.get(f"/api/directory/runs/{p['run_id']}").json()
    assert (run["status"], run["computers_seen"], run["users_seen"], run["batches"]) == ("succeeded", 3, 1, 3)
    assert run["server"] == "dc1.corp.example.com" and run["trigger"] == "manual"
    # The token is single use: the run is over.
    assert post_batch(agent, cmd, 3).status_code == 403
    s = admin.get(f"/api/directory/sources/{src['id']}").json()
    assert (s["last_sync_status"], s["computers_count"], s["users_count"]) == ("succeeded", 3, 1)
    comps = admin.get("/api/directory/computers").json()
    assert comps["total"] == 3
    pc1 = next(c for c in comps["items"] if c["name"] == "PC1")
    assert pc1["domain"] == DOMAIN and pc1["ou"] == "OU=Laptops,DC=corp,DC=example,DC=com" and pc1["enabled"]
    users = admin.get("/api/directory/users").json()["items"]
    assert users[0]["user_principal_name"] == "alice@corp.example.com"


def test_batch_caps_and_scope(admin, collector, monkeypatch):
    agent, dev = collector
    src = make_source(admin, [dev], config={"domain": DOMAIN, "scopes": ["computers"]})
    monkeypatch.setattr(config.settings, "directory_max_objects", 2)
    admin.post(f"/api/directory/sources/{src['id']}/sync")
    cmd = fetch_sync(agent)
    assert cmd["params"]["scopes"] == ["computers"] and cmd["params"]["max_objects"] == 2
    assert post_batch(agent, cmd, 0, users=[user(1, "alice")]).status_code == 422  # outside the scope
    too_many = [computer(i, f"PC{i}") for i in range(5001)]
    assert post_batch(agent, cmd, 0, computers=too_many).status_code == 422  # > 5000 per batch
    assert post_batch(agent, cmd, 0, computers=[computer(1, "PC1"), computer(2, "PC2"),
                                                computer(3, "PC3")]).status_code == 422  # > max_objects
    run = admin.get(f"/api/directory/runs/{cmd['params']['run_id']}").json()
    assert run["status"] == "failed" and "more than the 2 objects" in run["error"]
    assert post_batch(agent, cmd, 0, computers=[computer(1, "PC1")]).status_code in (403, 409)


def test_missing_objects_marked_only_after_a_complete_run(admin, collector):
    agent, dev = collector
    src = make_source(admin, [dev])
    sid = src["id"]
    run_sync(admin, agent, sid, computers=[computer(1, "PC1"), computer(2, "PC2")], users=[user(1, "alice"),
                                                                                         user(2, "bob")])

    def missing():
        with db.get_session("default") as s:
            return sorted(c.name for c in s.scalars(select(DirectoryComputer)) if c.missing_since)

    # Truncated (safety cap) and failed runs never mark missing objects.
    run_sync(admin, agent, sid, computers=[computer(1, "PC1")], truncated=True)
    assert missing() == []
    run = run_sync(admin, agent, sid, computers=[computer(1, "PC1")], status="failed", error="LDAP bind failed")
    assert run["status"] == "failed" and run["error"] == "LDAP bind failed"
    assert missing() == []
    # Totals that do not match what arrived: not complete either.
    run_sync(admin, agent, sid, computers=[computer(1, "PC1")], totals={"computers": 7, "users": 0})
    assert missing() == []
    run_sync(admin, agent, sid, computers=[computer(1, "PC1")], users=[user(1, "alice")])
    assert missing() == ["PC2"]
    s = admin.get(f"/api/directory/sources/{sid}").json()
    assert (s["computers_count"], s["users_count"]) == (1, 1)
    assert admin.get("/api/directory/computers?status=missing").json()["total"] == 1
    # It comes back: no longer missing.
    run_sync(admin, agent, sid, computers=[computer(1, "PC1"), computer(2, "PC2")], users=[user(1, "alice")])
    assert missing() == []


def test_test_run_stores_only_a_sample(admin, collector):
    agent, dev = collector
    src = make_source(admin, [dev])
    r = admin.post(f"/api/directory/sources/{src['id']}/test")
    assert r.status_code == 202 and r.json()["trigger"] == "test"
    cmd = fetch_sync(agent)
    assert cmd["params"]["test"] is True and cmd["params"]["max_objects"] == 10
    post_batch(agent, cmd, 0, computers=[computer(1, "PC1")], users=[user(1, "alice")])
    post_batch(agent, cmd, 1, final=True)
    run = admin.get(f"/api/directory/runs/{cmd['params']['run_id']}").json()
    assert run["status"] == "succeeded" and {s["name"] for s in run["sample"]} == {"PC1", "alice"}
    assert admin.get("/api/directory/computers").json()["total"] == 0
    assert admin.get(f"/api/directory/sources/{src['id']}").json()["last_sync_status"] is None


def test_agent_reported_failure_and_disable_cancel(admin, collector):
    agent, dev = collector
    src = make_source(admin, [dev])
    admin.post(f"/api/directory/sources/{src['id']}/sync")
    cmd = fetch_sync(agent)
    r = agent.post(f"/api/agent/commands/{cmd['id']}/result", json={
        "nonce": cmd["nonce"], "status": "rejected", "output": "kerberos auth needs Windows"})
    assert r.status_code == 204
    run = admin.get(f"/api/directory/runs/{cmd['params']['run_id']}").json()
    assert run["status"] == "failed" and "kerberos" in run["error"]
    with db.get_session("default") as s:
        ev = s.scalars(select(NotificationEvent).where(NotificationEvent.source == "directory_source")).all()
        assert [e.event_type for e in ev] == ["sync_failed"]
    # Disabling the source cancels its active run.
    admin.post(f"/api/directory/sources/{src['id']}/sync")
    r = admin.patch(f"/api/directory/sources/{src['id']}", json={"enabled": False})
    assert r.status_code == 200 and r.json()["active_run"] is None and r.json()["next_sync_at"] is None
    assert agent.get("/api/agent/commands").json()["commands"] == []  # cancelled at delivery
    assert admin.post(f"/api/directory/sources/{src['id']}/sync").status_code == 409


# ----------------------------------------------------------------------------- matching and findings
def test_matching_findings_and_notifications(admin, collector):
    agent, dev = collector
    # Agent devices: PC1 reports its SID, PC2 (older agent) only its hostname, DISABLED1 is still active,
    # ROGUE is joined to the synced domain but not in AD, MAC1 is not domain-joined. alice signs in on PC1
    # but is disabled in AD; bob signs in on PC2 and has not logged on to the domain for a year.
    _, pc1 = add_device(admin, "PC1", "4" * 64, join_facts=join("PC1", 2001), users=["CORP\\alice"])
    _, pc2 = add_device(admin, "PC2", "5" * 64, collector=False, users=["CORP\\bob"])
    _, dis = add_device(admin, "DISABLED1", "6" * 64, join_facts=join("DISABLED1", 2003))
    _, rogue = add_device(admin, "ROGUE", "7" * 64, join_facts=join("ROGUE", 2999))
    _, mac = add_device(admin, "MAC1", "8" * 64, os_family="macos")
    src = make_source(admin, [dev])
    comps = [computer(1, "COLLECTOR1", rid=1100), computer(2, "PC1", rid=2001), computer(3, "PC2"),
             computer(4, "DISABLED1", uac=4096 | 2, rid=2003), computer(5, "UNMANAGED1"),
             computer(6, "OLDBOX", logon_days=400), computer(7, "NEVER", logon_days=None)]
    users = [user(1, "alice", uac=512 | 2), user(2, "bob", logon_days=365)]
    run_sync(admin, agent, src["id"], computers=comps, users=users)
    items = {c["name"]: c for c in admin.get("/api/directory/computers").json()["items"]}
    assert (items["PC1"]["device_id"], items["PC1"]["match_method"]) == (pc1, "directory_sid")
    assert items["PC2"]["device_id"] == pc2 and items["PC2"]["match_method"] == "hostname"
    assert items["COLLECTOR1"]["match_method"] == "directory_sid"
    assert items["UNMANAGED1"]["match_status"] == "unmatched"
    # IT assets of matched agent devices are linked; unmatched computers are not IT assets.
    assert items["PC1"]["in_it_assets"] and not items["UNMANAGED1"]["in_it_assets"]
    page = admin.get("/api/directory/issues?limit=1000").json()
    by = {}
    for i in page["items"]:
        by.setdefault(i["type"], set()).add(i["name"])
    assert by["not_managed"] == {"UNMANAGED1"}
    assert by["stale_computer"] == {"OLDBOX", "NEVER"}
    assert by["disabled_but_active"] == {"DISABLED1"}
    assert by["unknown_to_directory"] == {"ROGUE"}
    assert by["not_domain_joined"] == {"MAC1"}
    assert by["disabled_user_signed_in"] == {"alice"}
    assert by["stale_user_signed_in"] == {"bob"}
    assert page["counts"]["not_managed"] == 1 and page["total"] == len(page["items"])
    dis_issue = next(i for i in page["items"] if i["type"] == "disabled_but_active")
    assert dis_issue["device_id"] == dis and dis_issue["device_hostname"] == "DISABLED1"
    assert next(i for i in page["items"] if i["type"] == "unknown_to_directory")["device_id"] == rogue
    assert next(i for i in page["items"] if i["type"] == "not_domain_joined")["device_id"] == mac
    # Filters, search, paging and CSV export.
    assert admin.get("/api/directory/issues?type=stale_computer").json()["total"] == 2
    assert admin.get("/api/directory/issues?kind=user").json()["total"] == 2
    assert admin.get("/api/directory/issues?q=oldbox").json()["total"] == 1
    p1 = admin.get("/api/directory/issues?limit=2&offset=0").json()
    p2 = admin.get("/api/directory/issues?limit=2&offset=2").json()
    assert len(p1["items"]) == 2 and {i["id"] for i in p1["items"]}.isdisjoint({i["id"] for i in p2["items"]})
    csv_text = admin.get("/api/directory/issues/export.csv?type=not_managed").text
    assert csv_text.splitlines()[0].startswith("type,kind,name") and "UNMANAGED1" in csv_text
    # Summary / coverage: 6 enabled computers (DISABLED1 excluded), 3 managed (COLLECTOR1, PC1, PC2).
    summary = admin.get("/api/directory/summary").json()
    assert summary["coverage"] == {"directory_computers": 6, "managed": 3, "pct": 50.0}
    assert summary["sources"] == 1 and summary["users"] == 2
    # Notifications: one "not managed" event; re-evaluating with the same count adds none.
    with db.get_session("default") as s:
        def events():
            return [e.event_type for e in s.scalars(select(NotificationEvent).where(
                NotificationEvent.source == "directory_source"))]
        assert events() == ["not_managed_changed"]
        reconcile.reconcile(s, notify=True)
        assert events() == ["not_managed_changed"]
    # first_seen_at survives re-evaluation.
    first = {i["id"]: i["first_seen_at"] for i in page["items"]}
    run_sync(admin, agent, src["id"], computers=comps, users=users)
    again = {i["id"]: i["first_seen_at"] for i in admin.get("/api/directory/issues?limit=1000").json()["items"]}
    assert again == first
    # IT asset owner enrichment (display only; the owner stays the username).
    assets = {a["device_id"]: a for a in admin.get("/api/it-assets").json()}
    a1 = assets[pc1]
    assert a1["assignee_name"] == "alice"
    assert a1["owner_directory"]["display_name"] == "Alice" and a1["owner_directory"]["enabled"] is False
    assert a1["owner_directory"]["department"] == "Finance"


def test_add_to_it_assets_and_later_enrollment_links(admin, collector):
    agent, dev = collector
    src = make_source(admin, [dev])
    run_sync(admin, agent, src["id"], computers=[computer(1, "COLLECTOR1", rid=1100), computer(2, "SRV1"),
                                                 computer(3, "SRV2")])
    items = {c["name"]: c for c in admin.get("/api/directory/computers?status=not_in_assets").json()["items"]}
    assert set(items) == {"SRV1", "SRV2"}  # never created automatically
    viewer_free = admin.post("/api/directory/computers/add-to-assets", json={"computer_ids": ["e" * 32]})
    assert viewer_free.status_code == 404
    r = admin.post("/api/directory/computers/add-to-assets",
                   json={"computer_ids": [items["SRV1"]["id"], items["SRV2"]["id"]]})
    assert r.status_code == 200 and r.json()["created"] == 2
    r = admin.post("/api/directory/computers/add-to-assets", json={"computer_ids": [items["SRV1"]["id"]]})
    assert r.json() == {"created": 0, "skipped": 1, "asset_ids": []}
    assets = [a for a in admin.get("/api/it-assets").json() if a["source"] == "directory"]
    assert {a["status"] for a in assets} == {"in_stock"} and len(assets) == 2
    assert all(a["asset_tag"].startswith("DIR-SRV") for a in assets)
    assert admin.get("/api/directory/computers?status=not_in_assets").json()["total"] == 0
    # SRV1 later gets an agent: its asset is linked instead of a duplicate being created.
    _, srv1 = add_device(admin, "SRV1", "9" * 64, join_facts=join("SRV1", 9001), collector=False)
    linked = [a for a in admin.get("/api/it-assets").json() if a["device_id"] == srv1]
    assert len(linked) == 1 and linked[0]["source"] == "directory"
    with db.get_session("default") as s:
        assert "directory_computers_added_to_assets" in {a.action for a in s.scalars(select(AuditLog))}


# ----------------------------------------------------------------------------- scheduler
def test_scheduler_queues_fails_over_and_records_missed_slots(admin, collector, scheduler):
    agent1, dev1 = collector
    agent2, dev2 = add_device(admin, "COLLECTOR2", "a" * 64, join_facts=join("COLLECTOR2", 1101))
    src = make_source(admin, [dev1, dev2])
    sched = scheduler
    now = utcnow()
    out = sched.tick(now)
    assert len(out["queued"]) == 1
    with db.get_session("default") as s:
        run = s.get(DirectorySyncRun, out["queued"][0])
        assert run.device_id == dev1 and run.trigger == "scheduled"
    assert sched.tick(now + timedelta(minutes=1))["queued"] == []  # not due / already running
    # Collector 1 never fetches the command: after the pickup timeout the run fails over to collector 2
    # (still polling, collector 1 too: it is online but stuck).
    with db.get_session("default") as s:
        for d in s.scalars(select(Device)):
            d.last_seen_at = now + timedelta(minutes=15)
        s.commit()
    out = sched.tick(now + timedelta(minutes=16))
    assert out["failed"] == [run.id] and len(out["failed_over"]) == 1
    cmd = fetch_sync(agent2)
    assert agent1.get("/api/agent/commands").json()["commands"] == []  # the first command was cancelled
    post_batch(agent2, cmd, 0, computers=[computer(1, "PC1")])
    post_batch(agent2, cmd, 1, final=True)
    s_out = admin.get(f"/api/directory/sources/{src['id']}").json()
    assert s_out["last_sync_status"] == "succeeded"
    runs = admin.get(f"/api/directory/sources/{src['id']}/runs").json()
    assert [r["status"] for r in runs] == ["succeeded", "failed"] and runs[0]["attempt"] == 2
    # Next slot: no healthy collector (both offline) -> a failed run is recorded and notified.
    with db.get_session("default") as s:
        for d in s.scalars(select(Device)):
            d.last_seen_at = now - timedelta(hours=1)
        s.commit()
    out = sched.tick(now + timedelta(hours=7))
    assert len(out["failed"]) == 1
    with db.get_session("default") as s:
        failed = s.get(DirectorySyncRun, out["failed"][0])
        assert failed.status == "failed" and "no healthy collector" in failed.error
        assert s.scalars(select(NotificationEvent).where(NotificationEvent.event_type == "sync_failed")).first()


def test_scheduler_fails_stalled_runs(admin, collector, scheduler):
    agent, dev = collector
    src = make_source(admin, [dev])
    sched = scheduler
    now = utcnow()
    sched.tick(now)
    cmd = fetch_sync(agent)
    post_batch(agent, cmd, 0, computers=[computer(1, "PC1")])
    out = sched.tick(utcnow() + timedelta(minutes=31))
    assert out["failed"] == [cmd["params"]["run_id"]]
    run = admin.get(f"/api/directory/runs/{cmd['params']['run_id']}").json()
    assert run["status"] == "failed" and "no data from the collector" in run["error"]
    assert post_batch(agent, cmd, 1, final=True).status_code == 403  # token cleared
    assert admin.get(f"/api/directory/sources/{src['id']}").json()["computers_count"] == 0


# ----------------------------------------------------------------------------- tenant isolation
def test_tenant_isolation(admin, collector, scheduler):
    agent, dev = collector
    src = make_source(admin, [dev])
    run_sync(admin, agent, src["id"], computers=[computer(1, "PC1"), computer(2, "PC2")], users=[user(1, "alice")])
    acme_id = create_org("acme", ACME_ADMIN, ACME_PASSWORD)
    acme = org_client(admin.app, ACME_ADMIN, ACME_PASSWORD)
    acme_agent, acme_dev = add_device(acme, "ACME-DC-COLLECTOR", "b" * 64, join_facts=join("X", 1))
    sid = src["id"]
    comp_id = admin.get("/api/directory/computers").json()["items"][0]["id"]
    run_id = admin.get(f"/api/directory/sources/{sid}/runs").json()[0]["id"]
    # Another organisation sees nothing and gets 404 for every id.
    assert acme.get("/api/directory/sources").json() == []
    assert acme.get("/api/directory/computers").json()["total"] == 0
    assert acme.get("/api/directory/users").json()["total"] == 0
    assert acme.get("/api/directory/issues").json()["total"] == 0
    assert acme.get("/api/directory/summary").json()["coverage"]["directory_computers"] == 0
    assert [c["id"] for c in acme.get("/api/directory/collectors").json()] == [acme_dev]
    for method, path, body in (("get", f"/api/directory/sources/{sid}", None),
                               ("patch", f"/api/directory/sources/{sid}", {"enabled": False}),
                               ("delete", f"/api/directory/sources/{sid}", None),
                               ("post", f"/api/directory/sources/{sid}/sync", None),
                               ("post", f"/api/directory/sources/{sid}/test", None),
                               ("get", f"/api/directory/sources/{sid}/runs", None),
                               ("get", f"/api/directory/runs/{run_id}", None),
                               ("post", "/api/directory/computers/add-to-assets", {"computer_ids": [comp_id]})):
        r = getattr(acme, method)(path, **({"json": body} if body is not None else {}))
        assert r.status_code == 404, (method, path, r.status_code)
    # A source in acme cannot use the default organisation's devices as collectors.
    r = acme.post("/api/directory/sources", json={"type": "ad", "name": "x", "config": {"domain": DOMAIN},
                                                  "collector_device_ids": [dev]})
    assert r.status_code == 404
    # The acme agent cannot upload into the default organisation's run (even with its token).
    admin.post(f"/api/directory/sources/{sid}/sync")
    cmd = fetch_sync(agent)
    assert post_batch(acme_agent, cmd, 0, computers=[computer(9, "EVIL")]).status_code == 404
    assert post_batch(agent, cmd, 0, computers=[computer(3, "PC3")]).status_code == 200
    # Scheduler / reconcile per organisation keep data apart.
    scheduler.tick()
    with db.get_session(acme_id) as s:
        assert s.scalars(select(DirectoryComputer)).all() == []
        assert s.scalars(select(DirectoryFinding)).all() == []
    assert acme.get("/api/directory/sources").json() == []


def test_delete_source_removes_its_data(admin, collector):
    agent, dev = collector
    src = make_source(admin, [dev])
    run_sync(admin, agent, src["id"], computers=[computer(1, "UNMANAGED"), computer(2, "COLLECTOR1", rid=1100)])
    assert admin.get("/api/directory/issues").json()["total"] == 1
    assert admin.delete(f"/api/directory/sources/{src['id']}").status_code == 204
    assert admin.get("/api/directory/computers").json()["total"] == 0
    assert admin.get("/api/directory/issues").json()["total"] == 0
    assert admin.get(f"/api/directory/sources/{src['id']}").status_code == 404
