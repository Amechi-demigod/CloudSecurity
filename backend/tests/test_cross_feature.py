"""Cross-feature behaviour of the integrated branches: device events as a
notification source, device remote actions for SSO users (RBAC + audit), and
the agent / sensor-ingest credentials staying independent of session, CSRF,
MFA and SSO."""
from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import config, db
from app.models import AuditLog, Device, DeviceCommand, EnrollmentToken, utcnow
from app.notifications import device_source, dispatcher, rules
from app.notifications.models import NotificationEvent
from app.services import devices as svc
from tests.conftest import AUTH, BASE_URL, login
from tests.test_devices import enroll, new_token, queue, windows_checkin
from tests.test_notifications import add_channel, transport  # noqa: F401  (fixture)
from tests.test_sso import FakeEntra, app_client, browser, idp, me, sso_login  # noqa: F401  (fixtures)


def device_events(event_type: str | None = None) -> list[NotificationEvent]:
    with db.get_session("default") as s:
        q = select(NotificationEvent).where(NotificationEvent.source == "device").order_by(NotificationEvent.id)
        if event_type:
            q = q.where(NotificationEvent.event_type == event_type)
        return list(s.scalars(q))


def posture(**fails: str) -> dict:
    body = windows_checkin()
    for check in fails:
        body["posture"][check] = {"status": "fail", "detail": fails[check]}
    return body


@pytest.fixture()
def device(empty_client):
    token = new_token(empty_client)
    agent = TestClient(empty_client.app, base_url=BASE_URL)
    r = enroll(agent, token)
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    return agent, r.json()["device_id"]


# --------------------------------------------------------------------- device notification source
def test_device_source_is_registered_for_the_rule_builder(empty_client):
    meta = empty_client.get("/api/notifications/meta").json()
    src = next(s for s in meta["sources"] if s["name"] == "device")
    assert src["label"] == "Endpoint device"
    for t in ("disk_encryption_off", "firewall_off", "antivirus_off", "av_signatures_outdated",
              "os_updates_pending", "stale", "inactive", "command_succeeded", "command_failed"):
        assert t in src["event_types"]
    # every issue the device service can raise is a known event type (revoked, lost mode and wipe
    # are admin actions, notified through command results and the device_approvals source)
    assert set(svc.ISSUE_DEFS) - {"revoked", "lost_mode", "wipe_pending"} <= set(src["event_types"])


def test_new_checkin_issues_emit_events_once(device):
    agent, device_id = device
    assert agent.post("/api/agent/checkin", json=posture(disk_encryption="BitLocker off",
                                                         firewall="public profile off")).status_code == 200
    evs = device_events()
    assert sorted(e.event_type for e in evs) == ["disk_encryption_off", "firewall_off"]
    ev = next(e for e in evs if e.event_type == "firewall_off")
    assert ev.severity == "high" and ev.entity_id == device_id and ev.link_path == f"/devices/{device_id}"
    assert ev.title == "Firewall is off on LAPTOP-001" and ev.summary == "public profile off"
    assert ev.rule_id == "firewall_off" and ev.attributes["asset_type"] == "device"
    # same issues again: nothing new
    assert agent.post("/api/agent/checkin", json=posture(disk_encryption="BitLocker off",
                                                         firewall="public profile off")).status_code == 200
    assert len(device_events()) == 2
    # firewall fixed, then off again: notifies again; AV off + outdated signatures are new
    assert agent.post("/api/agent/checkin", json=posture(disk_encryption="BitLocker off")).status_code == 200
    body = posture(disk_encryption="BitLocker off", firewall="off again", antivirus="real-time off")
    body["posture"]["antivirus"]["data"] = {"signature_age_days": 30}
    assert agent.post("/api/agent/checkin", json=body).status_code == 200
    assert sorted(e.event_type for e in device_events()) == [
        "antivirus_off", "av_signatures_outdated", "disk_encryption_off", "firewall_off", "firewall_off"]


def test_overdue_updates_emit_event(device, monkeypatch):
    agent, device_id = device
    body = windows_checkin()
    body["posture"]["os_updates"] = {"status": "fail", "data": {"pending_count": 3}}
    assert agent.post("/api/agent/checkin", json=body).status_code == 200
    assert device_events("os_updates_pending") == []  # within the grace period
    with db.get_session("default") as s:
        s.get(Device, device_id).updates_pending_since = utcnow() - timedelta(days=30)
        s.commit()
    assert agent.post("/api/agent/checkin", json=body).status_code == 200
    [ev] = device_events("os_updates_pending")
    assert ev.severity == "medium" and "3 update(s) pending" in ev.summary


def test_remote_action_results_emit_events(empty_client, device):
    agent, device_id = device
    assert agent.post("/api/agent/checkin", json=windows_checkin()).status_code == 200
    results = {}
    for t, status in (("recheck_posture", "succeeded"), ("lock_device", "failed"), ("collect_logs", "rejected")):
        cid = queue(empty_client, device_id, t).json()["id"]
        cmd = next(c for c in agent.get("/api/agent/commands").json()["commands"] if c["id"] == cid)
        r = agent.post(f"/api/agent/commands/{cid}/result",
                       json={"nonce": cmd["nonce"], "status": status, "output": f"{t} {status}"})
        assert r.status_code == 204, r.text
        results[cid] = status
    evs = {e.entity_id: e for e in device_events() if e.event_type.startswith("command_")}
    assert {cid: evs[cid].event_type for cid in results} == {cid: f"command_{s}" for cid, s in results.items()}
    lock = next(e for e in evs.values() if e.event_type == "command_failed")
    assert lock.severity == "medium" and lock.rule_id == "lock_device" and lock.summary == "lock_device failed"
    assert lock.attributes["requested_by"] == "admin@example.com"
    assert lock.title == "Remote action lock device failed on LAPTOP-001"


def test_stale_and_inactive_devices_are_polled(device):
    agent, device_id = device
    assert agent.post("/api/agent/checkin", json=windows_checkin()).status_code == 200
    now = utcnow()

    def poll(at):
        with db.get_session("default") as s:
            dispatcher.poll_sources(s, now=at, force=True)

    def age(delta):
        with db.get_session("default") as s:
            s.get(Device, device_id).last_seen_at = now - delta
            s.commit()

    poll(now)  # baseline
    age(timedelta(hours=30))
    poll(now)
    poll(now)  # still stale: once only
    [stale] = device_events("stale")
    assert stale.severity == "medium" and "last check-in" in stale.summary
    age(timedelta(days=8))
    poll(now)
    assert len(device_events("inactive")) == 1
    # checks in again, later goes quiet again: notifies again
    assert agent.post("/api/agent/checkin", json=windows_checkin()).status_code == 200
    poll(utcnow())
    age(timedelta(hours=30))
    poll(now)
    assert len(device_events("stale")) == 2
    # revoked devices are not reported
    with db.get_session("default") as s:
        s.get(Device, device_id).status = "revoked"
        s.commit()
    age(timedelta(days=8))
    poll(now)
    assert len(device_events("inactive")) == 1


def test_first_poll_does_not_flood(device):
    agent, device_id = device
    assert agent.post("/api/agent/checkin", json=windows_checkin()).status_code == 200
    with db.get_session("default") as s:
        s.get(Device, device_id).last_seen_at = utcnow() - timedelta(days=30)
        s.commit()
        dispatcher.poll_sources(s, force=True)
    assert device_events("inactive") == []


def test_rules_can_select_device_events(device):
    agent, _ = device
    assert agent.post("/api/agent/checkin", json=posture(firewall="off")).status_code == 200
    [ev] = device_events()
    base = dict(enabled=True, sources=["device"], event_types=[], include_status_changes=False, min_severity="info",
                subscription_ids=[], asset_ids=[], asset_types=[], tags={}, rule_ids=[], mitre_techniques=[])
    ctx = rules.build_context(ev)
    assert rules.matches(SimpleNamespace(**base), ctx)
    assert rules.matches(SimpleNamespace(**{**base, "event_types": ["firewall_off"], "asset_types": ["device"]}), ctx)
    assert rules.matches(SimpleNamespace(**{**base, "rule_ids": ["firewall_*"], "min_severity": "high"}), ctx)
    assert not rules.matches(SimpleNamespace(**{**base, "event_types": ["stale"]}), ctx)
    assert not rules.matches(SimpleNamespace(**{**base, "sources": ["runtime_alert"]}), ctx)
    assert not rules.matches(SimpleNamespace(**{**base, "min_severity": "critical"}), ctx)


def test_device_rule_end_to_end_delivery(empty_client, device, transport):  # noqa: F811
    """A rule created in the rule builder (API) routes a device issue to a channel."""
    agent, device_id = device
    with db.get_session("default") as s:
        channel_id = add_channel(s).id
    r = empty_client.post("/api/notifications/rules", json={
        "name": "Laptop firewall", "sources": ["device"], "event_types": ["firewall_off"],
        "min_severity": "medium", "channel_ids": [channel_id], "throttle_minutes": 0})
    assert r.status_code == 201, r.text
    assert agent.post("/api/agent/checkin", json=posture(firewall="off", disk_encryption="off")).status_code == 200
    with db.get_session("default") as s:
        now = utcnow() + timedelta(seconds=5)
        dispatcher.process_events(s, now)
        # only firewall_off is selected (disk_encryption_off is not)
        assert dispatcher.send_due(s, now)["sent"] == 1
    [req] = transport.requests
    text = str(req["body"])
    assert "Firewall is off on LAPTOP-001" in text and f"https://cnapp.example.com/devices/{device_id}" in text


def test_notification_failure_never_breaks_checkin(device, monkeypatch):
    agent, _ = device

    def boom(*a, **kw):
        raise RuntimeError("bad event")

    monkeypatch.setattr(device_source, "_issue_event", boom)
    assert agent.post("/api/agent/checkin", json=posture(firewall="off")).status_code == 200
    assert device_events() == []


# ------------------------------------------------- agent / ingest auth vs MFA, SSO, sessions, CSRF
def _raw_enrollment_token() -> str:
    raw = svc.new_enrollment_token()
    now = utcnow()
    with db.get_session("default") as s:
        s.add(EnrollmentToken(name="direct", token_hash=svc.hash_secret(raw), token_prefix=raw[:10], max_uses=5,
                              created_by="test", created_at=now, expires_at=now + timedelta(hours=1)))
        s.commit()
    return raw


def test_agent_and_ingest_auth_independent_of_mfa_and_sso(app_client, idp, monkeypatch):  # noqa: F811
    # MFA required for every role, password login off, Microsoft sign-in on.
    monkeypatch.setattr(config.settings, "mfa_required_roles", ["admin", "analyst", "viewer"])
    monkeypatch.setattr(config.settings, "auth_password_login_enabled", False)
    monkeypatch.setattr(config.settings, "auth_break_glass_emails", [])
    monkeypatch.setattr(config.settings, "entra_jit_provisioning", True)
    monkeypatch.setattr(config.settings, "entra_role_map", {"CNAPP.Admin": "admin"})
    assert app_client.post("/api/auth/login", json={"email": "admin@example.com",
                                                    "password": "correct-horse-battery"}).status_code in (401, 403)

    # Agent: no session, no CSRF header, no MFA - only the enrollment token / device credential.
    agent = TestClient(app_client.app, base_url=BASE_URL)
    r = enroll(agent, _raw_enrollment_token())
    assert r.status_code == 200, r.text
    device_id = r.json()["device_id"]
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    assert "X-CSRF-Token" not in agent.headers and not agent.cookies
    assert agent.post("/api/agent/checkin", json=windows_checkin()).status_code == 200
    assert agent.get("/api/agent/commands").status_code == 200
    # Sensor ingest: bearer token only.
    ev = {"event_type": "file_access", "file": {"path": "/etc/shadow"}}
    assert TestClient(app_client.app, base_url=BASE_URL).post("/api/runtime/events", json=ev,
                                                                  headers=AUTH).status_code == 202

    # An SSO admin session is neither a device credential nor a sensor credential...
    idp.claims = {"roles": ["CNAPP.Admin"]}
    b = browser(app_client)
    sso_login(b, idp)
    assert me(b)["user"]["role"] == "admin"
    assert b.get("/api/agent/commands").status_code == 401
    assert b.post("/api/agent/checkin", json=windows_checkin()).status_code == 401
    assert b.post("/api/runtime/events", json=ev).status_code == 401
    # ...and device credentials / the ingest token do not reach the user API.
    assert agent.get("/api/devices").status_code == 401
    assert agent.get(f"/api/devices/{device_id}").status_code == 401
    assert TestClient(app_client.app, base_url=BASE_URL).get("/api/devices", headers=AUTH).status_code == 401
    # Wrong / missing device credential is still rejected.
    bad = TestClient(app_client.app, base_url=BASE_URL, headers={"Authorization": "Bearer cnd_wrong"})
    assert bad.get("/api/agent/commands").status_code == 401
    assert TestClient(app_client.app, base_url=BASE_URL).get("/api/agent/commands").status_code == 401


def test_sso_users_device_actions_rbac_and_audit(app_client, idp, monkeypatch):  # noqa: F811
    monkeypatch.setattr(config.settings, "entra_jit_provisioning", True)
    monkeypatch.setattr(config.settings, "entra_role_map", {"CNAPP.Admin": "admin", "CNAPP.Analyst": "analyst"})
    login(app_client)
    token = new_token(app_client)
    agent = TestClient(app_client.app, base_url=BASE_URL)
    r = enroll(agent, token)
    device_id = r.json()["device_id"]

    idp.claims = {"roles": ["CNAPP.Analyst"]}
    analyst = browser(app_client)
    sso_login(analyst, idp)
    info = me(analyst)
    assert info["user"]["role"] == "analyst"
    analyst.headers["X-CSRF-Token"] = info["csrf_token"]
    assert analyst.get(f"/api/devices/{device_id}").status_code == 200
    assert queue(analyst, device_id, "lock_device").status_code == 403  # admin only
    ok = queue(analyst, device_id, "recheck_posture", reason="SSO analyst check")
    assert ok.status_code == 201, ok.text
    # CSRF is still required for SSO sessions
    no_csrf = browser(app_client)
    no_csrf.cookies = analyst.cookies
    assert queue(no_csrf, device_id, "recheck_posture").status_code == 403

    with db.get_session("default") as s:
        cmd = s.get(DeviceCommand, ok.json()["id"])
        assert cmd.requested_by_email == "alice@example.com"
        row = s.scalars(select(AuditLog).where(AuditLog.action == "device_command_created")
                        .order_by(AuditLog.id.desc())).first()
        assert row.actor_email == "alice@example.com" and row.target == f"device:{device_id}"
