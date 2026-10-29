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

import json

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
def test_isolate_and_restore_params(admin):
    _, dev = enrolled(admin)
    r = admin.post(f"/api/devices/{dev}/commands",
                   json={"type": "isolate_host", "reason": "containment", "params": {"unexpected": 123}})
    assert r.status_code == 422, r.text
    assert "incident_id" in r.text

    r = admin.post(f"/api/devices/{dev}/commands",
                   json={"type": "restore_host", "reason": "containment", "params": {"unexpected": 123}})
    assert r.status_code == 422, r.text
    assert "takes no parameters" in r.text

    # isolate_host accepts an optional incident_id, shown on the agent's banner
    r = admin.post(f"/api/devices/{dev}/commands",
                   json={"type": "isolate_host", "reason": "containment", "params": {"incident_id": "INC-101"}})
    assert r.status_code == 201, r.text
    assert r.json()["params"] == {"incident_id": "INC-101"}

    r = admin.post(f"/api/devices/{dev}/commands/{r.json()['id']}/cancel", json={"reason": "cleanup"})
    assert r.status_code == 200, r.text

    r = admin.post(f"/api/devices/{dev}/commands",
                   json={"type": "isolate_host", "reason": "containment", "params": {"incident_id": "bad incident!"}})
    assert r.status_code == 422, r.text
    assert "incident_id" in r.text


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

    # Agent reports isolation in check-in posture (real agent payload shape:
    # signin.Manager.Status()/PostureData() - active/since/incident_id)
    rep = {"isolation": {"status": "info", "detail": "host isolated",
                        "data": {"active": True, "since": "2026-10-29T10:00:00Z", "incident_id": "INC-101"}}}
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


# --------------------------------------------------------------------------- result_data (pre-flight readiness)
def test_isolate_host_result_data_round_trip(admin):
    agent, dev = enrolled(admin)
    admin.post(f"/api/devices/{dev}/commands", json={"type": "isolate_host", "reason": "test"})
    (cmd,) = poll(agent)
    r = result(agent, cmd, status="succeeded", output="suspended",
              result_data={"local_admins": ["Administrator", "jdoe"], "laps_configured": True,
                           "laps_backs_up_to_entra": False})
    assert r.status_code == 204, r.text

    d = admin.get(f"/api/devices/{dev}").json()
    assert d["isolation"]["readiness"] == {"local_admins": ["Administrator", "jdoe"], "laps_configured": True,
                                           "laps_backs_up_to_entra": False}

    cmds = admin.get(f"/api/devices/{dev}/commands").json()
    assert cmds[0]["result_data"]["local_admins"] == ["Administrator", "jdoe"]


def test_restore_host_rejects_unexpected_result_data(admin):
    agent, dev = enrolled(admin)
    admin.post(f"/api/devices/{dev}/commands", json={"type": "isolate_host", "reason": "test"})
    (cmd,) = poll(agent)
    result(agent, cmd, status="succeeded", output="suspended")

    admin.post(f"/api/devices/{dev}/commands", json={"type": "restore_host", "reason": "test"})
    (cmd,) = poll(agent)
    r = result(agent, cmd, status="succeeded", output="restored", result_data={"unexpected": "nope"})
    assert r.status_code == 422, r.text


def test_other_command_types_reject_result_data(admin):
    agent, dev = enrolled(admin)
    admin.post(f"/api/devices/{dev}/commands", json={"type": "recheck_posture", "reason": "test"})
    (cmd,) = poll(agent)
    r = result(agent, cmd, status="succeeded", output="ok", result_data={"anything": 1})
    assert r.status_code == 422, r.text
    assert "does not accept result_data" in r.text


def test_isolate_host_result_data_size_cap():
    """Unit-level: the HTTP layer only re-exercises schema validation already
    covered by test_schemas_devices.py-style checks, so this hits
    validate_result_data directly for a precise, non-flaky size check."""
    from app.schemas_devices import MAX_DATA_JSON, validate_result_data

    huge = {"local_admins": ["x" * 255 for _ in range(64)]}
    assert len(json.dumps(huge)) > MAX_DATA_JSON
    with pytest.raises(ValueError, match="larger than"):
        validate_result_data("isolate_host", huge)


# --------------------------------------------------------------------------- pre-flight blocked (no local admin)
def test_isolate_host_preflight_blocked_no_local_admin(admin):
    agent, dev = enrolled(admin)
    admin.post(f"/api/devices/{dev}/commands", json={"type": "isolate_host", "reason": "containment INC-5"})
    (cmd,) = poll(agent)
    # The real agent reports this as "rejected" (local validation refused the
    # command before touching anything), not "failed" - see
    # endpoint-agent/internal/agent/protect.go's isolateHost.
    r = result(agent, cmd, status="rejected", output="aborted: no local admin would remain",
              result_data={"error_code": "ERR_NO_LOCAL_ADMIN_PRESENT"})
    assert r.status_code == 204, r.text

    # Same device-state side effect as any other failed isolate_host.
    assert admin.get(f"/api/devices/{dev}").json()["isolation"]["status"] is None

    all_actions = actions()
    assert "host_isolation_preflight_blocked" in all_actions
    assert "host_isolation_failed" not in all_actions

    all_events = events("host_isolation")
    assert "preflight_blocked_no_local_admin" in all_events
    assert "isolation_failed" not in all_events


def test_isolate_host_ordinary_failure_still_uses_generic_path(admin):
    """Regression: a failure with no error_code (or a different one) must not
    be mistaken for the no-local-admin pre-flight block."""
    agent, dev = enrolled(admin)
    admin.post(f"/api/devices/{dev}/commands", json={"type": "isolate_host", "reason": "test"})
    (cmd,) = poll(agent)
    result(agent, cmd, status="failed", output="LSA call failed")

    all_actions = actions()
    assert "host_isolation_failed" in all_actions
    assert "host_isolation_preflight_blocked" not in all_actions

    all_events = events("host_isolation")
    assert "isolation_failed" in all_events
    assert "preflight_blocked_no_local_admin" not in all_events


# --------------------------------------------------------------------------- crash-recovery reporting
def test_isolation_crash_recovery_reported_on_checkin(admin):
    agent, dev = enrolled(admin)
    admin.post(f"/api/devices/{dev}/commands", json={"type": "isolate_host", "reason": "test"})
    (cmd,) = poll(agent)
    result(agent, cmd, status="succeeded", output="suspended")

    rep = {"isolation": {"status": "info", "detail": "recovered after restart",
                         "data": {"active": True, "recovered_at_boot": True, "recovery_outcome": "rolled_back"}}}
    r = agent.post("/api/agent/checkin", json=checkin_body(rep))
    assert r.status_code == 200, r.text

    all_actions = actions()
    assert "host_isolation_rolled_back_after_crash" in all_actions
    all_events = events("host_isolation")
    assert "rolled_back_after_crash" in all_events

    d = admin.get(f"/api/devices/{dev}").json()
    assert d["isolation"]["recovered_at_boot"] is True
    assert d["isolation"]["recovery_outcome"] == "rolled_back"

    # A later, ordinary check-in (the agent clears the outcome after reporting
    # it once) must not raise another event.
    before = len(events("host_isolation"))
    rep2 = {"isolation": {"status": "info", "detail": "suspended", "data": {"active": True}}}
    agent.post("/api/agent/checkin", json=checkin_body(rep2))
    assert len(events("host_isolation")) == before


def test_isolation_crash_recovery_malformed_data_ignored(admin):
    agent, dev = enrolled(admin)
    # recovered_at_boot without a recognised recovery_outcome: ignored, never 500s.
    rep = {"isolation": {"status": "info", "detail": "", "data": {"recovered_at_boot": True, "recovery_outcome": "???"}}}
    r = agent.post("/api/agent/checkin", json=checkin_body(rep))
    assert r.status_code == 200, r.text
    assert "host_isolation_rolled_back_after_crash" not in actions()
    assert "host_isolation_completed_after_crash" not in actions()


def test_posture_isolated_key_still_accepted_as_fallback(admin):
    """Older agents (pre-rename) reported `isolated`, not `active`; accept both."""
    agent, dev = enrolled(admin)
    rep = {"isolation": {"status": "info", "detail": "", "data": {"isolated": True}}}
    agent.post("/api/agent/checkin", json=checkin_body(rep))
    d = admin.get(f"/api/devices/{dev}").json()
    assert d["isolation"]["status"] == "isolated"
    assert d["isolation"]["reported_isolated"] is True


# --------------------------------------------------------------------------- stuck isolate_host after a crash
def test_crash_rollback_while_isolating_unsticks_status_and_command(admin):
    """A crash during the FIRST isolate_host (PhaseApplying) can roll back
    entirely locally - the agent's Manager.OnStart never POSTs a result for
    the original command, since none was ever reported before the crash (see
    endpoint-agent/internal/signin). Without this fix, isolation_status and
    the command would stay stuck "isolating"/pending forever."""
    agent, dev = enrolled(admin)
    admin.post(f"/api/devices/{dev}/commands", json={"type": "isolate_host", "reason": "test"})
    poll(agent)  # delivered, but the agent "crashes" before ever posting a result

    assert admin.get(f"/api/devices/{dev}").json()["isolation"]["status"] == "isolating"

    rep = {"isolation": {"status": "info", "detail": "rolled back after restart",
                        "data": {"active": False, "recovered_at_boot": True, "recovery_outcome": "rolled_back"}}}
    r = agent.post("/api/agent/checkin", json=checkin_body(rep))
    assert r.status_code == 200, r.text

    d = admin.get(f"/api/devices/{dev}").json()
    assert d["isolation"]["status"] is None
    assert d["device_state"] == "active"

    cmds = admin.get(f"/api/devices/{dev}/commands").json()
    assert cmds[0]["status"] == "failed"

    assert "host_isolation_rolled_back_after_crash" in actions()

    # Nothing stuck: Suspend sign-in can be queued again.
    r = admin.post(f"/api/devices/{dev}/commands", json={"type": "isolate_host", "reason": "retry"})
    assert r.status_code == 201, r.text


def test_crash_completed_while_isolating_marks_command_succeeded(admin):
    """The other crash-recovery outcome: the agent finished applying the
    suspend forward after a restart. The stuck command must resolve to
    succeeded and isolation_status to isolated, never stay stuck "isolating"."""
    agent, dev = enrolled(admin)
    admin.post(f"/api/devices/{dev}/commands", json={"type": "isolate_host", "reason": "test"})
    poll(agent)

    rep = {"isolation": {"status": "info", "detail": "completed after restart",
                        "data": {"active": True, "recovered_at_boot": True, "recovery_outcome": "completed"}}}
    r = agent.post("/api/agent/checkin", json=checkin_body(rep))
    assert r.status_code == 200, r.text

    d = admin.get(f"/api/devices/{dev}").json()
    assert d["isolation"]["status"] == "isolated"
    assert d["device_state"] == "isolated"

    cmds = admin.get(f"/api/devices/{dev}/commands").json()
    assert cmds[0]["status"] == "succeeded"

    assert "host_isolation_completed_after_crash" in actions()
