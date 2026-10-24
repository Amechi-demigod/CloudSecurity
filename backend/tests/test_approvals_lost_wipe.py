"""Two-person approvals, lost mode and remote wipe: approval rules (different
admin, self-approval off by default, typed device name, cooling-off), expiry,
RBAC, single-use wipe commands (ack, replay), device state and notifications."""
from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import config, db
from app.models import AuditLog, Device, DeviceApproval, DeviceCommand, utcnow
from app.notifications.models import NotificationEvent
from tests.conftest import BASE_URL, login, make_user
from tests.test_devices import agent_client, enroll, new_token, windows_checkin

PW = "a-long-test-password"
WIPE_READY = {"status": "info", "detail": "remote wipe ready (doWipeProtectedMethod)",
              "data": {"opt_in": True, "supported": True, "winre_enabled": True, "mdm_bridge": True, "ready": True}}


@pytest.fixture()
def admin(empty_client):
    return empty_client


@pytest.fixture()
def admin2(admin):
    make_user(admin, "admin", email="second-admin@example.com", password=PW)
    c = TestClient(admin.app, base_url=BASE_URL)
    login(c, "second-admin@example.com", PW)
    return c


def checkin_body(posture_extra=None, os_family="windows", hostname="LAPTOP-001"):
    body = windows_checkin()
    body["device"]["os_family"] = os_family
    body["device"]["hostname"] = hostname
    body["posture"].update(posture_extra or {})
    return body


def enrolled(admin, *, os_family="windows", opt_in=True, hostname="LAPTOP-001", machine="a" * 64):
    agent = agent_client(admin.app)
    r = enroll(agent, new_token(admin), machine_id=machine, os_family=os_family, hostname=hostname)
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    extra = {"remote_wipe": WIPE_READY} if opt_in else {}
    assert agent.post("/api/agent/checkin", json=checkin_body(extra, os_family, hostname)).status_code == 200
    return agent, r.json()["device_id"]


def poll(agent):
    r = agent.get("/api/agent/commands")
    assert r.status_code == 200, r.text
    return r.json()["commands"]


def result(agent, cmd, status="succeeded", output="ok", **extra):
    return agent.post(f"/api/agent/commands/{cmd['id']}/result",
                      json={"nonce": cmd["nonce"], "status": status, "output": output, **extra})


def request_wipe(c, device_id, hostname="LAPTOP-001", **kw):
    return c.post(f"/api/devices/{device_id}/wipe",
                  json={"reason": "laptop stolen, INC-42", "confirm_hostname": hostname, **kw})


def actions():
    with db.get_session("default") as s:
        return [a.action for a in s.scalars(select(AuditLog).order_by(AuditLog.id))]


def events(source="device_approvals"):
    with db.get_session("default") as s:
        return [e.event_type for e in s.scalars(select(NotificationEvent).where(NotificationEvent.source == source)
                                                .order_by(NotificationEvent.id))]


# --------------------------------------------------------------------------- lost mode
def test_lost_mode_enable_report_disable(admin):
    agent, dev = enrolled(admin)
    body = {"type": "enable_lost_mode", "reason": "reported lost on the train",
            "params": {"message": "This laptop belongs to Wakanow.\nPlease call us.", "phone": "+234 1 234 5678"}}
    assert admin.post(f"/api/devices/{dev}/commands", json=body).status_code == 422  # no typed hostname
    assert admin.post(f"/api/devices/{dev}/commands", json={**body, "confirm_hostname": "other"}).status_code == 422
    r = admin.post(f"/api/devices/{dev}/commands", json={**body, "confirm_hostname": "laptop-001"})
    assert r.status_code == 201, r.text
    d = admin.get(f"/api/devices/{dev}").json()
    assert d["lost_mode"]["status"] == "enabling" and d["device_state"] == "lost"
    assert d["lost_mode"]["phone"] == "+234 1 234 5678" and d["lost_mode"]["requested_by"] == "admin@example.com"
    assert "lost_mode" in [i["code"] for i in d["issues"]] and d["health"] == "critical"
    # Only one lost-mode change in flight.
    assert admin.post(f"/api/devices/{dev}/commands", json={**body, "confirm_hostname": "LAPTOP-001"}).status_code == 409
    (cmd,) = poll(agent)
    assert cmd["type"] == "enable_lost_mode" and cmd["params"]["message"].startswith("This laptop")
    assert result(agent, cmd, output="legal notice set; 1 session locked").status_code == 204
    assert admin.get(f"/api/devices/{dev}").json()["lost_mode"]["status"] == "active"
    # The agent reports the state on check-in.
    rep = {"lost_mode": {"status": "info", "detail": "lost mode active", "data": {"active": True}}}
    agent.post("/api/agent/checkin", json=checkin_body(rep))
    d = admin.get(f"/api/devices/{dev}").json()
    assert d["lost_mode"]["status"] == "active" and d["lost_mode"]["reported_active"] is True
    # Fleet list shows it too.
    assert admin.get("/api/devices").json()[0]["device_state"] == "lost"
    r = admin.post(f"/api/devices/{dev}/commands", json={"type": "disable_lost_mode", "reason": "found by owner"})
    assert r.status_code == 201
    assert admin.get(f"/api/devices/{dev}").json()["lost_mode"]["status"] == "disabling"
    (cmd,) = poll(agent)
    assert result(agent, cmd, output="previous notice restored").status_code == 204
    d = admin.get(f"/api/devices/{dev}").json()
    assert d["lost_mode"]["status"] is None and d["lost_mode"]["message"] is None and d["device_state"] == "active"
    assert admin.post(f"/api/devices/{dev}/commands",
                      json={"type": "disable_lost_mode", "reason": "again"}).status_code == 409
    assert actions().count("device_command_created") == 2


def test_lost_mode_failure_and_cancel_restore_state(admin):
    agent, dev = enrolled(admin)
    body = {"type": "enable_lost_mode", "reason": "lost", "confirm_hostname": "LAPTOP-001",
            "params": {"message": "Lost device", "phone": "0800 123"}}
    cid = admin.post(f"/api/devices/{dev}/commands", json=body).json()["id"]
    assert admin.post(f"/api/devices/{dev}/commands/{cid}/cancel", json={"reason": "mistake"}).status_code == 200
    assert admin.get(f"/api/devices/{dev}").json()["lost_mode"]["status"] is None
    admin.post(f"/api/devices/{dev}/commands", json=body)
    (cmd,) = poll(agent)
    result(agent, cmd, status="failed", output="registry write failed")
    assert admin.get(f"/api/devices/{dev}").json()["lost_mode"]["status"] is None


@pytest.mark.parametrize("params", [
    {"message": "", "phone": "123456"},
    {"message": "hi", "phone": "call me maybe"},
    {"message": "x" * 301, "phone": "123456"},
    {"message": "bell\x07", "phone": "123456"},
    {"message": "hi", "phone": "123456", "extra": 1},
    {"message": "hi"},
])
def test_lost_mode_params_validated(admin, params):
    _, dev = enrolled(admin)
    r = admin.post(f"/api/devices/{dev}/commands", json={"type": "enable_lost_mode", "reason": "lost",
                                                         "confirm_hostname": "LAPTOP-001", "params": params})
    assert r.status_code == 422, r.text


def test_lost_mode_needs_admin_and_no_approval(admin):
    _, dev = enrolled(admin)
    make_user(admin, "analyst", password=PW)
    a = TestClient(admin.app, base_url=BASE_URL)
    login(a, "analyst@example.com", PW)
    r = a.post(f"/api/devices/{dev}/commands", json={"type": "enable_lost_mode", "reason": "lost",
                                                     "confirm_hostname": "LAPTOP-001",
                                                     "params": {"message": "Lost", "phone": "123456"}})
    assert r.status_code == 403
    # wipe / run_script can never be queued directly.
    for t in ("wipe_device", "run_script"):
        assert admin.post(f"/api/devices/{dev}/commands", json={"type": t, "reason": "nope"}).status_code == 422


# --------------------------------------------------------------------------- wipe: preconditions
def test_wipe_preconditions(admin):
    _, mac = enrolled(admin, os_family="macos", hostname="MBP-1", machine="b" * 64)
    r = request_wipe(admin, mac, "MBP-1")
    assert r.status_code == 409 and "Apple MDM" in r.json()["detail"]
    assert admin.get(f"/api/devices/{mac}").json()["wipe"]["supported"] is False
    _, win = enrolled(admin, opt_in=False, hostname="PC-2", machine="c" * 64)
    r = request_wipe(admin, win, "PC-2")
    assert r.status_code == 409 and "opt in" in r.json()["detail"]
    _, ok = enrolled(admin, hostname="PC-3", machine="d" * 64)
    assert request_wipe(admin, ok, "PC-4").status_code == 422  # wrong typed name
    assert request_wipe(admin, ok, "PC-3", mode="persist_user_data").status_code == 422
    r = request_wipe(admin, ok, "pc-3")
    assert r.status_code == 201 and r.json()["status"] == "pending"
    assert request_wipe(admin, ok, "PC-3").status_code == 409  # one open wipe request per device


def test_wipe_rbac(admin):
    _, dev = enrolled(admin)
    for role in ("analyst", "viewer"):
        make_user(admin, role, password=PW)
        c = TestClient(admin.app, base_url=BASE_URL)
        login(c, f"{role}@example.com", PW)
        assert request_wipe(c, dev).status_code == 403
        assert c.get("/api/approvals").status_code == 403
        assert c.get("/api/approvals/summary").status_code == 403


# --------------------------------------------------------------------------- wipe: two-person flow
def test_wipe_two_person_flow_ack_and_replay(admin, admin2):
    agent, dev = enrolled(admin)
    a = request_wipe(admin, dev).json()
    assert a["is_own_request"] and not a["can_decide"]
    assert poll(agent) == []  # nothing reaches the device before approval
    # Requester cannot approve (self-approval off by default).
    r = admin.post(f"/api/approvals/{a['id']}/approve", json={"confirm_hostname": "LAPTOP-001"})
    assert r.status_code == 403 and "different admin" in r.json()["detail"]
    s2 = admin2.get("/api/approvals/summary").json()
    assert s2["pending"] == 1 and s2["actionable"] == 1 and s2["settings"]["allow_self_approval"] is False
    assert admin.get("/api/approvals/summary").json()["actionable"] == 0
    # The approver must type the device name too.
    assert admin2.post(f"/api/approvals/{a['id']}/approve", json={}).status_code == 422
    r = admin2.post(f"/api/approvals/{a['id']}/approve", json={"confirm_hostname": "LAPTOP-001", "reason": "ok"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "executed" and r.json()["command_id"]
    # A second decision is refused.
    assert admin2.post(f"/api/approvals/{a['id']}/reject", json={"reason": "late"}).status_code == 409
    d = admin.get(f"/api/devices/{dev}").json()
    assert d["wipe"]["status"] == "queued" and d["device_state"] == "wipe_pending"
    with db.get_session("default") as s:
        c = s.get(DeviceCommand, r.json()["command_id"])
        assert c.type == "wipe_device" and c.approval_id == a["id"] and c.approved_by_email == "second-admin@example.com"
        ttl = c.expires_at - c.created_at
        assert timedelta(minutes=59) < ttl <= timedelta(minutes=60)  # short validity window
    (cmd,) = poll(agent)
    assert cmd["params"] == {"mode": "protected", "hostname": "LAPTOP-001"}
    assert poll(agent) == []  # delivered exactly once
    # Final acknowledgement before wiping: needs the nonce, single use.
    assert agent.post(f"/api/agent/commands/{cmd['id']}/ack", json={"nonce": "x" * 32}).status_code == 403
    r = agent.post(f"/api/agent/commands/{cmd['id']}/ack", json={"nonce": cmd["nonce"]})
    assert r.status_code == 200 and r.json()["proceed"] is True
    assert agent.post(f"/api/agent/commands/{cmd['id']}/ack", json={"nonce": cmd["nonce"]}).status_code == 409
    assert admin.get(f"/api/devices/{dev}").json()["wipe"]["status"] == "acknowledged"
    assert result(agent, cmd, output="doWipeProtectedMethod accepted; restarting into Windows RE").status_code == 204
    assert result(agent, cmd).status_code == 409  # replayed result
    d = admin.get(f"/api/devices/{dev}").json()
    assert d["wipe"]["status"] == "started" and d["device_state"] == "wipe_pending"
    acts = actions()
    for x in ("device_approval_requested", "device_approval_approved", "device_command_created",
              "device_wipe_acknowledged", "device_command_completed"):
        assert x in acts, x
    assert sorted(events()) == sorted(["approval_requested", "approval_approved", "action_executed", "wipe_acknowledged"])
    with db.get_session("default") as s:
        sev = s.scalars(select(NotificationEvent.severity).where(
            NotificationEvent.source == "device_approvals", NotificationEvent.event_type == "approval_requested")).one()
        assert sev == "critical"


def test_ack_only_for_wipe_and_not_after_expiry(admin, admin2):
    agent, dev = enrolled(admin)
    admin.post(f"/api/devices/{dev}/commands", json={"type": "recheck_posture", "reason": "check"})
    (cmd,) = poll(agent)
    assert agent.post(f"/api/agent/commands/{cmd['id']}/ack", json={"nonce": cmd["nonce"]}).status_code == 409
    a = request_wipe(admin, dev).json()
    admin2.post(f"/api/approvals/{a['id']}/approve", json={"confirm_hostname": "LAPTOP-001"})
    (cmd,) = poll(agent)
    with db.get_session("default") as s:
        s.get(DeviceCommand, cmd["id"]).expires_at = utcnow() - timedelta(seconds=1)
        s.commit()
    assert agent.post(f"/api/agent/commands/{cmd['id']}/ack", json={"nonce": cmd["nonce"]}).status_code == 409
    admin.get(f"/api/devices/{dev}/commands")  # expires it
    assert admin.get(f"/api/devices/{dev}").json()["wipe"]["status"] == "expired"


def test_reject_and_cancel(admin, admin2):
    agent, dev = enrolled(admin)
    a = request_wipe(admin, dev).json()
    assert admin2.post(f"/api/approvals/{a['id']}/reject", json={"reason": "x"}).status_code == 422  # reason too short
    r = admin2.post(f"/api/approvals/{a['id']}/reject", json={"reason": "not stolen, found in office"})
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    assert admin2.post(f"/api/approvals/{a['id']}/approve", json={"confirm_hostname": "LAPTOP-001"}).status_code == 409
    b = request_wipe(admin, dev).json()
    assert admin.post(f"/api/approvals/{b['id']}/cancel", json={"reason": "duplicate"}).json()["status"] == "cancelled"
    assert poll(agent) == []
    assert admin.get(f"/api/devices/{dev}").json()["wipe"]["status"] is None
    assert admin.get("/api/approvals?status=final").json()[0]["status"] in ("rejected", "cancelled")
    assert "approval_rejected" in events() and "approval_cancelled" in events()


def test_requests_expire(admin, admin2):
    agent, dev = enrolled(admin)
    a = request_wipe(admin, dev).json()
    with db.get_session("default") as s:
        s.get(DeviceApproval, a["id"]).expires_at = utcnow() - timedelta(minutes=1)
        s.commit()
    assert admin2.get("/api/approvals").json() == []  # open requests only
    assert admin2.get(f"/api/approvals/{a['id']}").json()["status"] == "expired"
    r = admin2.post(f"/api/approvals/{a['id']}/approve", json={"confirm_hostname": "LAPTOP-001"})
    assert r.status_code == 409 and "expired" in r.json()["detail"]
    assert poll(agent) == []
    assert "device_approval_expired" in actions() and "approval_expired" in events()


def test_default_ttl_is_24h(admin):
    _, dev = enrolled(admin)
    a = request_wipe(admin, dev).json()
    with db.get_session("default") as s:
        row = s.get(DeviceApproval, a["id"])
        assert row.expires_at - row.requested_at == timedelta(hours=24)


def test_revoked_device_cannot_be_wiped(admin, admin2):
    agent, dev = enrolled(admin)
    a = request_wipe(admin, dev).json()
    admin.post(f"/api/devices/{dev}/revoke", json={"reason": "gone"})
    r = admin2.post(f"/api/approvals/{a['id']}/approve", json={"confirm_hostname": "LAPTOP-001"})
    assert r.status_code == 409


# --------------------------------------------------------------------------- self-approval (single-admin installs)
@pytest.fixture()
def self_approval(monkeypatch):
    monkeypatch.setattr(config.settings, "device_approval_allow_self", True)
    monkeypatch.setattr(config.settings, "device_approval_self_cooldown_minutes", 15.0)


def test_self_approval_requires_name_and_cooling_off(admin, self_approval):
    agent, dev = enrolled(admin)
    a = request_wipe(admin, dev).json()
    assert a["can_decide"] is True
    assert admin.post(f"/api/approvals/{a['id']}/approve", json={}).status_code == 422
    r = admin.post(f"/api/approvals/{a['id']}/approve", json={"confirm_hostname": "LAPTOP-001"})
    assert r.status_code == 200, r.text
    a = r.json()
    assert a["status"] == "approved" and a["self_approved"] and a["command_id"] is None
    assert poll(agent) == []  # still cooling off
    assert admin.get("/api/approvals/summary").json()["cooling_off"] == 1
    # Fast-forward past the delay: the next agent poll releases it.
    with db.get_session("default") as s:
        s.get(DeviceApproval, a["id"]).execute_after = utcnow() - timedelta(seconds=1)
        s.commit()
    (cmd,) = poll(agent)
    assert cmd["type"] == "wipe_device"
    row = admin.get(f"/api/approvals/{a['id']}").json()
    assert row["status"] == "executed" and row["command_id"] == cmd["id"]
    with db.get_session("default") as s:
        detail = s.scalars(select(AuditLog.detail).where(AuditLog.action == "device_approval_approved")).one()
        assert detail["self_approved"] is True


def test_self_approval_can_be_cancelled_during_cooling_off(admin, self_approval):
    agent, dev = enrolled(admin)
    a = request_wipe(admin, dev).json()
    admin.post(f"/api/approvals/{a['id']}/approve", json={"confirm_hostname": "LAPTOP-001"})
    r = admin.post(f"/api/approvals/{a['id']}/cancel", json={"reason": "changed my mind"})
    assert r.status_code == 200 and r.json()["status"] == "cancelled"
    with db.get_session("default") as s:
        s.get(DeviceApproval, a["id"]).execute_after = utcnow() - timedelta(seconds=1)
        s.commit()
    assert poll(agent) == []
    assert admin.post(f"/api/approvals/{a['id']}/cancel", json={"reason": "again"}).status_code == 409


def test_other_admin_approval_skips_cooling_off_even_when_self_allowed(admin, admin2, self_approval):
    agent, dev = enrolled(admin)
    a = request_wipe(admin, dev).json()
    r = admin2.post(f"/api/approvals/{a['id']}/approve", json={"confirm_hostname": "LAPTOP-001"})
    assert r.json()["status"] == "executed" and not r.json()["self_approved"]
    assert len(poll(agent)) == 1


def test_settings_validation(monkeypatch):
    monkeypatch.setenv("DEVICE_APPROVAL_SELF_COOLDOWN_MINUTES", "0")
    monkeypatch.setenv("DEVICE_WIPE_COMMAND_TTL_MINUTES", "1")
    s = config.reload_settings()
    probs = s.auth_config_problems()
    assert any("COOLDOWN" in p for p in probs) and any("WIPE_COMMAND_TTL" in p for p in probs)
    monkeypatch.delenv("DEVICE_APPROVAL_SELF_COOLDOWN_MINUTES")
    monkeypatch.delenv("DEVICE_WIPE_COMMAND_TTL_MINUTES")
    config.reload_settings()


def test_installer_allow_wipe_is_windows_only(admin):
    r = admin.post("/api/devices/installers", json={"platform": "macos-pkg", "allow_wipe": True})
    assert r.status_code == 422 and "Windows" in r.json()["detail"]


def test_enroll_document_carries_wipe_opt_in_only_when_set():
    import json

    from app.services import installers

    plain = json.loads(installers.enroll_document("https://x.example", "cne_" + "a" * 43, None))
    assert "allow_wipe" not in plain
    opt = json.loads(installers.enroll_document("https://x.example", "cne_" + "a" * 43, None, True))
    assert opt["allow_wipe"] is True


def test_device_delete_cascades_approvals(admin):
    _, dev = enrolled(admin)
    request_wipe(admin, dev)
    admin.post(f"/api/devices/{dev}/revoke", json={"reason": "gone"})
    assert admin.delete(f"/api/devices/{dev}?reason=cleanup").status_code == 204
    with db.get_session("default") as s:
        assert s.scalars(select(DeviceApproval)).all() == []
        assert s.get(Device, dev) is None
