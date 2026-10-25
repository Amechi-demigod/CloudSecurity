"""Tests for host isolation & network restoration backend:
- Roles: analyst and admin can isolate; only admin can restore.
- Command validation & rejection of unexpected parameters.
- Device lifecycle & state transitions (isolating -> isolated -> restoring -> active).
- Failure and cancellation handling.
- Audit entries (command creation, completion, requests).
- Notification events on host_isolation source.
- Multi-tenant isolation.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import db
from app.models import AuditLog
from app.notifications.models import NotificationEvent
from tests.conftest import BASE_URL, login, make_user
from tests.test_approvals_lost_wipe import checkin_body, enrolled, poll, result
from tests.test_devices import agent_client, enroll, new_token
from tests.test_tenancy import ACME_ADMIN, ACME_PASSWORD, Tenants, acme_device, create_org, org_client

PW = "TestPassword123!"


@pytest.fixture()
def admin(empty_client):
    return empty_client


@pytest.fixture()
def tenants(client) -> Tenants:
    acme_id = create_org("acme", ACME_ADMIN, ACME_PASSWORD, name="Acme Ltd")
    return Tenants(client, org_client(client.app, ACME_ADMIN, ACME_PASSWORD), acme_id)


def actions():
    with db.get_session("default") as s:
        return [a.action for a in s.scalars(select(AuditLog).order_by(AuditLog.id))]


def events(source="host_isolation"):
    with db.get_session("default") as s:
        return [e.event_type for e in s.scalars(select(NotificationEvent).where(NotificationEvent.source == source)
                                                .order_by(NotificationEvent.id))]


# --------------------------------------------------------------------------- roles
def test_roles_analyst_and_admin_can_isolate_only_admin_can_restore(admin):
    agent, dev = enrolled(admin)

    # 1. Reader / viewer cannot isolate or restore
    make_user(admin, "viewer", email="viewer@example.com", password=PW)
    viewer_client = TestClient(admin.app, base_url=BASE_URL)
    login(viewer_client, "viewer@example.com", PW)

    r = viewer_client.post(f"/api/devices/{dev}/commands",
                           json={"type": "isolate_host", "reason": "suspected breach"})
    assert r.status_code == 403, r.text

    r = viewer_client.post(f"/api/devices/{dev}/commands",
                           json={"type": "restore_host", "reason": "remediation done"})
    assert r.status_code == 403, r.text

    # 2. Analyst can isolate
    make_user(admin, "analyst", email="analyst@example.com", password=PW)
    analyst_client = TestClient(admin.app, base_url=BASE_URL)
    login(analyst_client, "analyst@example.com", PW)

    r = analyst_client.post(f"/api/devices/{dev}/commands",
                            json={"type": "isolate_host", "reason": "compromised endpoint"})
    assert r.status_code == 201, r.text
    cmd = r.json()
    assert cmd["type"] == "isolate_host"
    assert cmd["status"] == "pending"

    # Agent reports success
    (agent_cmd,) = poll(agent)
    assert result(agent, agent_cmd, output="isolated").status_code == 204

    # 3. Analyst CANNOT restore (admin only)
    r = analyst_client.post(f"/api/devices/{dev}/commands",
                            json={"type": "restore_host", "reason": "remediation verified"})
    assert r.status_code == 403, r.text
    assert "admin" in r.json()["detail"]

    # 4. Admin CAN restore
    r = admin.post(f"/api/devices/{dev}/commands",
                   json={"type": "restore_host", "reason": "incident closed"})
    assert r.status_code == 201, r.text
    (agent_cmd,) = poll(agent)
    assert result(agent, agent_cmd, output="restored").status_code == 204

    # 5. Admin CAN isolate
    r = admin.post(f"/api/devices/{dev}/commands",
                   json={"type": "isolate_host", "reason": "second alert"})
    assert r.status_code == 201, r.text


# --------------------------------------------------------------------------- validation
def test_isolate_and_restore_no_params_allowed(admin):
    _, dev = enrolled(admin)
    r = admin.post(f"/api/devices/{dev}/commands",
                   json={"type": "isolate_host", "reason": "containment", "params": {"unexpected": 123}})
    assert r.status_code == 422, r.text
    assert "takes no parameters" in r.text

    r = admin.post(f"/api/devices/{dev}/commands",
                   json={"type": "restore_host", "reason": "containment", "params": {"unexpected": 123}})
    assert r.status_code == 422, r.text
    assert "takes no parameters" in r.text


# --------------------------------------------------------------------------- lifecycle & state
def test_host_isolation_lifecycle(admin):
    agent, dev = enrolled(admin)

    # Initially not isolated
    d = admin.get(f"/api/devices/{dev}").json()
    assert d["isolation"]["status"] is None
    assert d["device_state"] == "active"

    # Queue isolation
    r = admin.post(f"/api/devices/{dev}/commands",
                   json={"type": "isolate_host", "reason": "ransomware containment"})
    assert r.status_code == 201

    d = admin.get(f"/api/devices/{dev}").json()
    assert d["isolation"]["status"] == "isolating"
    assert d["device_state"] == "isolated"

    # Cannot queue duplicate isolate_host or restore_host while isolating
    assert admin.post(f"/api/devices/{dev}/commands",
                      json={"type": "isolate_host", "reason": "again"}).status_code == 409
    assert admin.post(f"/api/devices/{dev}/commands",
                      json={"type": "restore_host", "reason": "cancel"}).status_code == 409

    # Agent executes command
    (cmd,) = poll(agent)
    assert cmd["type"] == "isolate_host"
    assert result(agent, cmd, output="firewall rules added, interactive logins locked").status_code == 204

    d = admin.get(f"/api/devices/{dev}").json()
    assert d["isolation"]["status"] == "isolated"
    assert d["device_state"] == "isolated"

    # Cannot queue isolate_host when already isolated
    assert admin.post(f"/api/devices/{dev}/commands",
                      json={"type": "isolate_host", "reason": "again"}).status_code == 409

    # Agent reports isolation in check-in posture
    rep = {"isolation": {"status": "info", "detail": "host isolated", "data": {"isolated": True}}}
    agent.post("/api/agent/checkin", json=checkin_body(rep))
    d = admin.get(f"/api/devices/{dev}").json()
    assert d["isolation"]["status"] == "isolated"
    assert d["isolation"]["reported_isolated"] is True

    # Queue restoration
    r = admin.post(f"/api/devices/{dev}/commands",
                   json={"type": "restore_host", "reason": "forensics complete"})
    assert r.status_code == 201

    d = admin.get(f"/api/devices/{dev}").json()
    assert d["isolation"]["status"] == "restoring"

    # Agent executes restore
    (cmd,) = poll(agent)
    assert cmd["type"] == "restore_host"
    assert result(agent, cmd, output="firewall rules removed").status_code == 204

    d = admin.get(f"/api/devices/{dev}").json()
    assert d["isolation"]["status"] is None
    assert d["isolation"]["since"] is None
    assert d["device_state"] == "active"

    # Cannot queue restore_host when not isolated
    assert admin.post(f"/api/devices/{dev}/commands",
                      json={"type": "restore_host", "reason": "again"}).status_code == 409


# --------------------------------------------------------------------------- failure & cancellation
def test_host_isolation_failure_and_cancel(admin):
    agent, dev = enrolled(admin)

    # 1. Cancel pending isolate_host command reverts state to None
    cmd = admin.post(f"/api/devices/{dev}/commands",
                     json={"type": "isolate_host", "reason": "test"}).json()
    assert admin.get(f"/api/devices/{dev}").json()["isolation"]["status"] == "isolating"
    r = admin.post(f"/api/devices/{dev}/commands/{cmd['id']}/cancel", json={"reason": "false alarm"})
    assert r.status_code == 200
    assert admin.get(f"/api/devices/{dev}").json()["isolation"]["status"] is None

    # 2. Failed isolate_host command reverts state to None
    cmd = admin.post(f"/api/devices/{dev}/commands",
                     json={"type": "isolate_host", "reason": "test"}).json()
    (agent_cmd,) = poll(agent)
    result(agent, agent_cmd, status="failed", output="firewall policy error")
    assert admin.get(f"/api/devices/{dev}").json()["isolation"]["status"] is None

    # Now put device in isolated state
    admin.post(f"/api/devices/{dev}/commands", json={"type": "isolate_host", "reason": "test"})
    (agent_cmd,) = poll(agent)
    result(agent, agent_cmd, status="succeeded", output="isolated")
    assert admin.get(f"/api/devices/{dev}").json()["isolation"]["status"] == "isolated"

    # 3. Cancel pending restore_host command reverts state to isolated
    cmd = admin.post(f"/api/devices/{dev}/commands",
                     json={"type": "restore_host", "reason": "test"}).json()
    assert admin.get(f"/api/devices/{dev}").json()["isolation"]["status"] == "restoring"
    r = admin.post(f"/api/devices/{dev}/commands/{cmd['id']}/cancel", json={"reason": "not yet"})
    assert r.status_code == 200
    assert admin.get(f"/api/devices/{dev}").json()["isolation"]["status"] == "isolated"

    # 4. Failed restore_host command reverts state to isolated
    cmd = admin.post(f"/api/devices/{dev}/commands",
                     json={"type": "restore_host", "reason": "test"}).json()
    (agent_cmd,) = poll(agent)
    result(agent, agent_cmd, status="failed", output="error clearing rules")
    assert admin.get(f"/api/devices/{dev}").json()["isolation"]["status"] == "isolated"


# --------------------------------------------------------------------------- audit entries & notifications
def test_host_isolation_audit_entries_and_notifications(admin):
    agent, dev = enrolled(admin)

    # 1. Queue isolation
    admin.post(f"/api/devices/{dev}/commands",
               json={"type": "isolate_host", "reason": "incident response INC-101"})

    all_actions = actions()
    assert "device_command_created" in all_actions
    assert "host_isolation_requested" in all_actions

    all_events = events("host_isolation")
    assert "isolation_requested" in all_events

    # 2. Agent reports isolation succeeded
    (cmd,) = poll(agent)
    result(agent, cmd, status="succeeded", output="firewall applied")

    all_actions = actions()
    assert "device_command_completed" in all_actions
    assert "host_isolated" in all_actions

    all_events = events("host_isolation")
    assert "host_isolated" in all_events

    # 3. Queue restore
    admin.post(f"/api/devices/{dev}/commands",
               json={"type": "restore_host", "reason": "investigation done"})

    all_actions = actions()
    assert "host_restore_requested" in all_actions

    all_events = events("host_isolation")
    assert "restore_requested" in all_events

    # 4. Agent reports restore succeeded
    (cmd,) = poll(agent)
    result(agent, cmd, status="succeeded", output="firewall cleared")

    all_actions = actions()
    assert "host_restored" in all_actions

    all_events = events("host_isolation")
    assert "host_restored" in all_events


# --------------------------------------------------------------------------- cross-tenant isolation
def test_host_isolation_multi_tenancy(tenants):
    d, a = tenants.default, tenants.acme
    agent_a, dev_a = acme_device(tenants, hostname="ACME-WORKSTATION")

    # Default organisation admin cannot isolate acme's device
    r = d.post(f"/api/devices/{dev_a}/commands",
               json={"type": "isolate_host", "reason": "cross-tenant attempt"})
    assert r.status_code == 404

    # Acme admin can isolate their device
    r = a.post(f"/api/devices/{dev_a}/commands",
               json={"type": "isolate_host", "reason": "acme breach"})
    assert r.status_code == 201
    cmd = r.json()

    # Default organisation agent does not see acme's isolation command
    agent_d = agent_client(d.app)
    token_d = new_token(d)
    rd = enroll(agent_d, token_d, machine_id="d" * 64, hostname="DEFAULT-DEV")
    agent_d.headers["Authorization"] = f"Bearer {rd.json()['device_secret']}"
    assert agent_d.get("/api/agent/commands").json()["commands"] == []

    # Acme agent sees the command
    cmds = agent_a.get("/api/agent/commands").json()["commands"]
    assert [c["id"] for c in cmds] == [cmd["id"]]
