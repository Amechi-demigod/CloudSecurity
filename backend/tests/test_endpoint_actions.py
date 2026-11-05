"""Built-in endpoint actions (app/services/endpoint_actions.py): services
inventory, manage_service / uninstall_software / block / unblock_usb_storage,
RBAC, version gating, protected services, audit, notifications, tenancy, bulk."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import db
from app.models import AuditLog, Device, RemoteSession, utcnow
from app.notifications.models import NotificationEvent
from tests.conftest import BASE_URL, login, make_user
from tests.test_approvals_lost_wipe import checkin_body, poll, result
from tests.test_devices import agent_client, enroll, new_token
from tests.test_tenancy import ACME_ADMIN, ACME_PASSWORD, Tenants, acme_device, create_org, org_client

PW = "TestPassword123!"
FEATURES = "check_for_update,host_isolation,directory_collector,remote_session,endpoint_actions"
MSI = "{23170F69-40C1-2702-2409-000001000000}"
SERVICES = [
    {"name": "Spooler", "display_name": "Print Spooler", "status": "running", "start_type": "auto"},
    {"name": "WSearch", "display_name": "Windows Search", "status": "running", "start_type": "auto_delayed"},
    {"name": "RpcSs", "display_name": "Remote Procedure Call (RPC)", "status": "running", "start_type": "auto"},
    {"name": "CNAPPAgent", "display_name": "CNAPP Endpoint Agent", "status": "running", "start_type": "auto"},
    {"name": "TermService", "display_name": "Remote Desktop Services", "status": "running", "start_type": "manual"},
]
SOFTWARE = [
    {"name": "7-Zip 24.09 (x64)", "version": "24.09", "publisher": "Igor Pavlov", "identifier": MSI,
     "source": "registry_hklm64"},
    {"name": "Zoom Workplace", "version": "6.2", "publisher": "Zoom", "identifier": "ZoomUMX", "source": "registry_user"},
    {"name": "CNAPP Endpoint Agent", "version": "1.4.0", "publisher": "CloudSecurity CNAPP",
     "identifier": "{11111111-1111-1111-1111-111111111111}", "source": "registry_hklm64"},
]
USB_ALLOWED = {"usb_storage": {"status": "info", "detail": "USB storage allowed",
                               "data": {"blocked": False, "usbstor_start": 3, "blocked_by_agent": False}}}


@pytest.fixture()
def admin(empty_client):
    return empty_client


def device(admin, *, features=FEATURES, os_family="windows", hostname="LAPTOP-001", machine="a" * 64, posture=None):
    agent = agent_client(admin.app)
    r = enroll(agent, new_token(admin), machine_id=machine, os_family=os_family, hostname=hostname)
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    checkin(agent, features=features, os_family=os_family, hostname=hostname, posture=posture)
    return agent, r.json()["device_id"]


def checkin(agent, *, features=FEATURES, os_family="windows", hostname="LAPTOP-001", posture=None,
            services=SERVICES, software=SOFTWARE):
    body = checkin_body(posture if posture is not None else USB_ALLOWED, os_family, hostname)
    body["software"] = software
    if services is not None:
        body["services"] = services
    r = agent.post("/api/agent/checkin", json=body, headers={"X-CNAPP-Agent-Features": features})
    assert r.status_code == 200, r.text


def queue(c, dev, type_, params=None, reason="ticket INC-1"):
    return c.post(f"/api/devices/{dev}/commands", json={"type": type_, "reason": reason, "params": params or {}})


def audit_actions():
    with db.get_session("default") as s:
        return [a.action for a in s.scalars(select(AuditLog).order_by(AuditLog.id))]


def audit_rows(action):
    with db.get_session("default") as s:
        return [a.detail for a in s.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id))]


def events(source="endpoint_action"):
    with db.get_session("default") as s:
        return [e.event_type for e in s.scalars(select(NotificationEvent).where(NotificationEvent.source == source)
                                                .order_by(NotificationEvent.id))]


# --------------------------------------------------------------------------- inventory and state
def test_services_inventory_and_detail(admin):
    agent, dev = device(admin)
    r = admin.get(f"/api/devices/{dev}/services")
    assert r.status_code == 200
    assert {s["name"] for s in r.json()} == {s["name"] for s in SERVICES}
    assert [s["name"] for s in admin.get(f"/api/devices/{dev}/services", params={"q": "spool"}).json()] == ["Spooler"]
    d = admin.get(f"/api/devices/{dev}").json()
    ea = d["endpoint_actions"]
    assert ea["supported"] is True and ea["services_reported"] == 5
    assert ea["usb_storage"]["state"] == "allowed" and d["usb_storage"] == "allowed"
    assert "RpcSs" in ea["protected_services"] and "TermService" not in ea["protected_services"]
    # A check-in without services (older agent / not collected) keeps the list.
    checkin(agent, services=None)
    assert len(admin.get(f"/api/devices/{dev}/services").json()) == 5
    # Strict validation of the agent's list.
    body = checkin_body(USB_ALLOWED)
    body["services"] = [{"name": "x", "status": "weird", "start_type": "auto"}]
    assert agent.post("/api/agent/checkin", json=body).status_code == 422


def test_usb_filter_and_column(admin):
    _, d1 = device(admin)
    _, d2 = device(admin, hostname="LAPTOP-002", machine="b" * 64, posture={"usb_storage": {
        "status": "info", "detail": "USB storage blocked by the CNAPP agent",
        "data": {"blocked": True, "usbstor_start": 4, "blocked_by_agent": True}}})
    _, d3 = device(admin, hostname="MAC-1", machine="c" * 64, os_family="macos", posture={})
    assert [d["id"] for d in admin.get("/api/devices", params={"usb": "blocked"}).json()] == [d2]
    assert [d["id"] for d in admin.get("/api/devices", params={"usb": "allowed"}).json()] == [d1]
    assert [d["id"] for d in admin.get("/api/devices", params={"usb": "unknown"}).json()] == [d3]
    assert admin.get("/api/devices", params={"usb": "nope"}).status_code == 422


# --------------------------------------------------------------------------- RBAC and gating
def test_roles_only_admin_can_queue(admin):
    _, dev = device(admin)
    for role in ("viewer", "analyst"):
        make_user(admin, role, email=f"{role}@example.com", password=PW)
        c = TestClient(admin.app, base_url=BASE_URL)
        login(c, f"{role}@example.com", PW)
        r = queue(c, dev, "manage_service", {"service": "Spooler", "action": "stop"})
        assert r.status_code == 403 and "admin" in r.json()["detail"]
        assert queue(c, dev, "block_usb_storage").status_code == 403
        assert c.post("/api/devices/bulk-commands", json={"device_ids": [dev], "type": "block_usb_storage",
                                                          "reason": "policy"}).status_code == 403
        # ...but they can see the inventory.
        assert c.get(f"/api/devices/{dev}/services").status_code == 200
    assert queue(admin, dev, "manage_service", {"service": "Spooler", "action": "stop"}).status_code == 201


def test_version_and_os_gating(admin):
    _, old = device(admin, features="check_for_update,host_isolation,remote_session")
    r = queue(admin, old, "block_usb_storage")
    assert r.status_code == 409 and "Agent update required" in r.json()["detail"] and "1.4.0" in r.json()["detail"]
    ea = admin.get(f"/api/devices/{old}").json()["endpoint_actions"]
    assert ea["supported"] is False and ea["agent_update_required"] is True
    _, mac = device(admin, os_family="macos", hostname="MAC-1", machine="d" * 64, posture={})
    r = queue(admin, mac, "block_usb_storage")
    assert r.status_code == 409 and "Windows only" in r.json()["detail"]
    ea = admin.get(f"/api/devices/{mac}").json()["endpoint_actions"]
    assert ea["supported"] is False and ea["agent_update_required"] is False
    assert "endpoint_action_refused" in audit_actions()


# --------------------------------------------------------------------------- services
def test_protected_services_refused_server_side(admin):
    _, dev = device(admin)
    for name, action in (("RpcSs", "stop"), ("rpcss", "disable"), ("CNAPPAgent", "stop")):
        r = queue(admin, dev, "manage_service", {"service": name, "action": action})
        assert r.status_code == 409, r.text
        assert "protected" in r.json()["detail"] or "agent" in r.json()["detail"]
    # Starting a protected service is fine.
    assert queue(admin, dev, "manage_service", {"service": "RpcSs", "action": "start"}).status_code == 201
    # TermService is protected only while a remote session is open.
    assert queue(admin, dev, "manage_service", {"service": "TermService", "action": "stop"}).status_code == 201
    with db.get_session("default") as s:
        d = s.get(Device, dev)
        s.add(RemoteSession(device_id=dev, organization_id=d.organization_id, mode="view", state="active",
                            requested_by_id="x" * 32, requested_by_email="admin@example.com", reason="support",
                            created_at=utcnow()))
        s.commit()
    r = queue(admin, dev, "manage_service", {"service": "TermService", "action": "disable"})
    assert r.status_code == 409 and "remote session" in r.json()["detail"]
    assert "TermService" in admin.get(f"/api/devices/{dev}").json()["endpoint_actions"]["protected_services"]
    # Unknown service / bad params / duplicates.
    assert queue(admin, dev, "manage_service", {"service": "NoSuch", "action": "stop"}).status_code == 404
    assert queue(admin, dev, "manage_service", {"service": "Spooler", "action": "delete"}).status_code == 422
    assert queue(admin, dev, "manage_service", {"service": "Spooler", "action": "stop", "x": 1}).status_code == 422
    assert queue(admin, dev, "manage_service", {"service": "Spooler", "action": "stop"}).status_code == 201
    assert queue(admin, dev, "manage_service", {"service": "spooler", "action": "disable"}).status_code == 409


def test_disable_then_restore_round_trip(admin):
    agent, dev = device(admin)
    r = queue(admin, dev, "manage_service", {"service": "wsearch", "action": "disable"})
    assert r.status_code == 201 and r.json()["params"] == {"service": "WSearch", "action": "disable"}
    (cmd,) = poll(agent)
    assert cmd["type"] == "manage_service"
    rd = {"service": "WSearch", "action": "disable", "status": "running", "start_type": "disabled",
          "previous_start_type": "auto_delayed"}
    assert result(agent, cmd, output="WSearch startup type set to Disabled", result_data=rd).status_code == 204
    svc = {s["name"]: s for s in admin.get(f"/api/devices/{dev}/services").json()}
    assert svc["WSearch"]["start_type"] == "disabled"
    # Restore carries the server's record of the previous startup type as a fallback.
    r = queue(admin, dev, "manage_service", {"service": "WSearch", "action": "restore"})
    assert r.json()["params"] == {"service": "WSearch", "action": "restore", "restore_to": "auto_delayed"}
    (cmd,) = poll(agent)
    rd = {"service": "WSearch", "action": "restore", "status": "running", "start_type": "auto_delayed",
          "previous_start_type": "disabled", "restored_start_type": "auto_delayed"}
    assert result(agent, cmd, result_data=rd).status_code == 204
    # Restored since: no fallback any more.
    r = queue(admin, dev, "manage_service", {"service": "WSearch", "action": "restore"})
    assert "restore_to" not in r.json()["params"]
    # Unknown result_data keys are rejected.
    (cmd,) = poll(agent)
    assert result(agent, cmd, result_data={"service": "WSearch", "evil": 1}).status_code == 422
    assert "device_command_created" in audit_actions() and "endpoint_action_succeeded" in audit_actions()


def test_failure_notifies_and_is_audited(admin):
    agent, dev = device(admin)
    queue(admin, dev, "manage_service", {"service": "Spooler", "action": "stop"})
    (cmd,) = poll(agent)
    assert result(agent, cmd, status="failed", output="Spooler did not stop within 1m0s",
                  result_data={"service": "Spooler", "action": "stop", "status": "running",
                               "start_type": "auto"}).status_code == 204
    assert events() == ["action_failed"]
    assert "endpoint_action_failed" in audit_actions()
    assert "command_failed" in events("device")
    (row,) = audit_rows("endpoint_action_failed")
    assert row["label"] == "Stop service Spooler" and row["status"] == "failed"
    # Refusals by the agent (e.g. protected list) are notified as rejected.
    queue(admin, dev, "manage_service", {"service": "WSearch", "action": "disable"})
    (cmd,) = poll(agent)
    result(agent, cmd, status="rejected", output="refused",
           result_data={"service": "WSearch", "action": "disable", "error_code": "ERR_PROTECTED_SERVICE"})
    assert sorted(events()) == ["action_failed", "action_rejected"]


# --------------------------------------------------------------------------- uninstall
def test_uninstall(admin):
    agent, dev = device(admin)
    r = queue(admin, dev, "uninstall_software", {"identifier": MSI, "source": "registry_hklm64"})
    assert r.status_code == 201, r.text
    assert r.json()["params"] == {"identifier": MSI, "source": "registry_hklm64", "name": "7-Zip 24.09 (x64)",
                                  "version": "24.09"}
    assert queue(admin, dev, "uninstall_software", {"identifier": MSI, "source": "registry_hklm64"}).status_code == 409
    (cmd,) = poll(agent)
    assert result(agent, cmd, output="uninstalled", exit_code=3010,
                  result_data={"name": "7-Zip 24.09 (x64)", "version": "24.09", "method": "msi",
                               "reboot_required": True, "verified": True}).status_code == 204
    cmds = admin.get(f"/api/devices/{dev}/commands").json()
    assert cmds[0]["exit_code"] == 3010 and cmds[0]["result_data"]["reboot_required"] is True
    assert MSI not in {s["identifier"] for s in admin.get(f"/api/devices/{dev}/software").json()}
    assert events() == ["restart_required"]


def test_uninstall_refusals(admin):
    _, dev = device(admin)
    r = queue(admin, dev, "uninstall_software", {"identifier": "ZoomUMX", "source": "registry_user"})
    assert r.status_code == 409 and "per-user" in r.json()["detail"]
    r = queue(admin, dev, "uninstall_software", {"identifier": "{11111111-1111-1111-1111-111111111111}",
                                                 "source": "registry_hklm64"})
    assert r.status_code == 409 and "itself" in r.json()["detail"]
    r = queue(admin, dev, "uninstall_software", {"identifier": "{00000000-0000-0000-0000-000000000000}",
                                                 "source": "registry_hklm64"})
    assert r.status_code == 404
    r = queue(admin, dev, "uninstall_software", {"identifier": MSI, "source": "registry_hklm64",
                                                 "uninstall_string": "cmd /c whoami"})
    assert r.status_code == 422


# --------------------------------------------------------------------------- USB storage
def test_usb_block_unblock(admin):
    agent, dev = device(admin)
    assert queue(admin, dev, "block_usb_storage", {"all": True}).status_code == 422
    assert queue(admin, dev, "block_usb_storage").status_code == 201
    assert queue(admin, dev, "unblock_usb_storage").status_code == 409  # one USB action at a time
    (cmd,) = poll(agent)
    rd = {"blocked": True, "usbstor_start": 4, "removable_disks_deny_read": True, "removable_disks_deny_write": True,
          "deny_all_removable": False}
    assert result(agent, cmd, result_data=rd).status_code == 204
    d = admin.get(f"/api/devices/{dev}").json()
    assert d["usb_storage"] == "blocked" and d["endpoint_actions"]["usb_storage"]["blocked_by_agent"] is True
    assert queue(admin, dev, "unblock_usb_storage").status_code == 201
    (cmd,) = poll(agent)
    result(agent, cmd, status="failed", output="restoring failed", result_data=rd)
    assert admin.get(f"/api/devices/{dev}").json()["usb_storage"] == "blocked"
    assert events() == ["action_failed"]


def test_bulk_usb(admin):
    agent1, d1 = device(admin)
    _, d2 = device(admin, hostname="LAPTOP-002", machine="b" * 64, features="check_for_update")
    _, d3 = device(admin, hostname="MAC-1", machine="c" * 64, os_family="macos", posture={})
    r = admin.post("/api/devices/bulk-commands", json={"device_ids": [d1, d2, d3, "f" * 32], "type": "block_usb_storage",
                                                       "reason": "USB policy rollout"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["queued"] == 1 and out["skipped"] == 3
    by = {x["device_id"]: x for x in out["results"]}
    assert by[d1]["status"] == "queued"
    assert "Agent update required" in by[d2]["detail"] and "Windows only" in by[d3]["detail"]
    assert [c["type"] for c in poll(agent1)] == ["block_usb_storage"]
    assert "device_bulk_command" in audit_actions()
    r = admin.post("/api/devices/bulk-commands", json={"device_ids": [d1], "type": "manage_service",
                                                       "params": {"service": "RpcSs", "action": "stop"},
                                                       "reason": "x" * 5})
    assert r.json()["queued"] == 0 and "protected" in r.json()["results"][0]["detail"]
    assert admin.post("/api/devices/bulk-commands", json={"device_ids": [d1], "type": "wipe_device",
                                                          "reason": "nope"}).status_code == 422


# --------------------------------------------------------------------------- tenancy
@pytest.fixture()
def tenants(client) -> Tenants:
    acme_id = create_org("acme", ACME_ADMIN, ACME_PASSWORD, name="Acme Ltd")
    return Tenants(client, org_client(client.app, ACME_ADMIN, ACME_PASSWORD), acme_id)


def test_tenancy(tenants):
    d, a = tenants.default, tenants.acme
    agent_a, dev_a = acme_device(tenants, hostname="ACME-WS")
    checkin(agent_a, hostname="ACME-WS")
    assert d.get(f"/api/devices/{dev_a}/services").status_code == 404
    assert queue(d, dev_a, "block_usb_storage").status_code == 404
    r = d.post("/api/devices/bulk-commands", json={"device_ids": [dev_a], "type": "block_usb_storage",
                                                   "reason": "cross-tenant"})
    assert r.json()["queued"] == 0 and r.json()["results"][0]["detail"] == "device not found"
    assert len(a.get(f"/api/devices/{dev_a}/services").json()) == 5
    assert queue(a, dev_a, "block_usb_storage").status_code == 201
