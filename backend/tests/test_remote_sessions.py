"""Attended remote sessions: RBAC per role and mode, organisation isolation of the
API and the relay, the single-use agent token (minted on delivery, hashed at
rest, expiry, replay), one session per device and the per-organisation cap,
termination (viewer, admin, revoke, lost mode, isolation, role loss, disabled
user, idle and hard limits), the audit trail and notifications, and the relay
itself (pairing, forwarding, View only input dropping, Origin, client IP, size
and rate limits) with fake agent and browser WebSocket clients.
Runs on SQLite and PostgreSQL."""
from __future__ import annotations

import json
import struct
import time
from datetime import timedelta
from types import SimpleNamespace

import anyio
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

from app import config, db
from app.models import AuditLog, DeviceCommand, RemoteSession, utcnow
from app.notifications.models import NotificationEvent
from app.services import remote_sessions as rsvc
from tests.conftest import BASE_URL, login, make_user
from tests.test_devices import agent_client, enroll, new_token, windows_checkin
from tests.test_tenancy import ACME_ADMIN, ACME_PASSWORD, create_org, org_client

PW = "a-long-test-password"
FEATURES = {"X-CNAPP-Agent-Features": "check_for_update,remote_session"}
ORIGIN = "https://testserver"
TILE = struct.pack(">BBHHHHIH", 1, 0, 0, 0, 64, 64, 1, 0) + b"\xff\xd8jpeg-bytes\xff\xd9"


@pytest.fixture()
def rs_env(monkeypatch):
    monkeypatch.setenv("REMOTE_SESSION_RECHECK_SECONDS", "1")


@pytest.fixture()
def admin(rs_env, empty_client):
    return empty_client


# --------------------------------------------------------------------------- helpers
def enroll_device(c, hostname="LAPTOP-001", machine="a" * 64, os_family="windows", features=True):
    token = new_token(c)
    agent = agent_client(c.app)
    r = enroll(agent, token, machine_id=machine, os_family=os_family, hostname=hostname)
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    body = windows_checkin()
    body["device"]["hostname"], body["device"]["os_family"] = hostname, os_family
    r = agent.post("/api/agent/checkin", json=body, headers=FEATURES if features else {})
    assert r.status_code == 200, r.text
    return agent, r.json()["device_id"]


def user_client(admin_c, role, email=None) -> TestClient:
    email = email or f"{role}@example.com"
    make_user(admin_c, role, email=email, password=PW)
    c = TestClient(admin_c.app, base_url=BASE_URL)
    login(c, email, PW)
    return c


def start(c, device_id, mode="view", reason="user reports a frozen Outlook"):
    return c.post(f"/api/devices/{device_id}/remote-sessions", json={"mode": mode, "reason": reason})


def poll_token(agent, sid) -> tuple[str, dict]:
    cmds = agent.get("/api/agent/commands").json()["commands"]
    cmd = next(c for c in cmds if c["type"] == "start_remote_session" and c["params"]["session_id"] == sid)
    return cmd["params"]["token"], cmd


def cookie(c) -> str:
    name = config.settings.session_cookie_name
    return f"{name}={c.cookies.get(name)}"


def viewer_ws(entered, c, sid, origin=ORIGIN):
    headers = {"cookie": cookie(c)}
    if origin:
        headers["origin"] = origin
    return entered.websocket_connect(f"/api/remote/{sid}", headers=headers)


def agent_ws(entered, agent, sid, token):
    return entered.websocket_connect(f"/api/agent/remote/{sid}", headers={
        "authorization": agent.headers["Authorization"], "x-remote-session-token": token})


def recv(ws, timeout=5.0) -> dict:
    """Next message from the server (an ASGI message dict), failing after `timeout`."""
    async def _r():
        with anyio.fail_after(timeout):
            return await ws._send_rx.receive()
    return ws.portal.call(_r)


def next_json(ws, timeout=5.0) -> dict:
    while True:
        m = recv(ws, timeout)
        if m["type"] == "websocket.close":
            raise WebSocketDisconnect(m.get("code", 1000), m.get("reason", ""))
        if m.get("text") is not None:
            d = json.loads(m["text"])
            if d.get("t") != "ping":
                return d


def until_state(ws, state, timeout=5.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        d = next_json(ws, timeout)
        if d.get("t") == "state" and d.get("state") == state:
            return d
    raise AssertionError(f"no state {state}")


def closed_code(ws, timeout=5.0) -> int:
    """Read until the server closes the socket; return the close code."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        m = recv(ws, timeout)
        if m["type"] == "websocket.close":
            return m.get("code", 1000)
    raise AssertionError("socket not closed")


def session_row(sid, org="default") -> RemoteSession:
    with db.get_session(org) as s:
        rs = s.get(RemoteSession, sid)
        s.expunge(rs)
        return rs


def audits(prefix="remote_session_", org="default") -> list[AuditLog]:
    with db.get_session(org) as s:
        rows = list(s.scalars(select(AuditLog).where(AuditLog.action.startswith(prefix)).order_by(AuditLog.id)))
        for r in rows:
            s.expunge(r)
        return rows


def events(org="default") -> list[str]:
    with db.get_session(org) as s:
        return [e.event_type for e in s.scalars(select(NotificationEvent)
                                                .where(NotificationEvent.source == "remote_session")
                                                .order_by(NotificationEvent.created_at))]


def connected(admin_c, agent, sid, viewer_c=None):
    """Viewer and agent connected and the user allowed: (viewer ws, agent ws) context managers entered."""
    token, _ = poll_token(agent, sid)
    v = viewer_ws(admin_c, viewer_c or admin_c, sid).__enter__()
    assert until_state(v, "requested")["mode"] in ("view", "control")
    a = agent_ws(admin_c, agent, sid, token).__enter__()
    until_state(v, "awaiting_consent")
    a.send_json({"t": "consent", "allow": True})
    until_state(v, "active")
    a.send_json({"t": "started"})
    until_state(v, "active")
    return v, a


# --------------------------------------------------------------------------- RBAC
def test_rbac_per_role_and_mode(admin):
    _, dev = enroll_device(admin)
    viewer, analyst = user_client(admin, "viewer"), user_client(admin, "analyst")
    assert start(viewer, dev).status_code == 403
    assert start(viewer, dev, "control").status_code == 403
    assert start(analyst, dev, "control").status_code == 403
    r = start(analyst, dev, "view")
    assert r.status_code == 201, r.text
    assert r.json()["state"] == "requested" and r.json()["mode"] == "view"
    # The analyst ends their own session; a View and control session needs an admin.
    assert analyst.post(f"/api/remote-sessions/{r.json()['id']}/end").json()["state"] == "ended"
    r = start(admin, dev, "control")
    assert r.status_code == 201 and r.json()["mode"] == "control"
    # Viewers read the history but cannot end the session; admins end anyone's.
    assert viewer.get(f"/api/devices/{dev}/remote-sessions").status_code == 200
    assert viewer.post(f"/api/remote-sessions/{r.json()['id']}/end").status_code == 403
    a = start(analyst, enroll_device(admin, "LAPTOP-002", "b" * 64)[1]).json()
    assert admin.post(f"/api/remote-sessions/{a['id']}/end").json()["end_reason"] == "ended_by_admin"
    # Reason: 3 to 500 characters, as for every remote action.
    assert start(admin, dev, reason="no").status_code == 422
    assert start(admin, dev, reason="x" * 501).status_code == 422


def test_csrf_required(admin):
    _, dev = enroll_device(admin)
    c = TestClient(admin.app, base_url=BASE_URL)
    login(c)
    del c.headers["X-CSRF-Token"]
    assert start(c, dev).status_code == 403


def test_availability_windows_only_and_feature_gated(admin):
    _, mac = enroll_device(admin, "MAC-001", "1" * 64, os_family="macos")
    _, old = enroll_device(admin, "OLD-001", "2" * 64, features=False)
    _, win = enroll_device(admin, "WIN-001", "3" * 64)
    a = admin.get(f"/api/devices/{mac}/remote-sessions/availability").json()
    assert not a["available"] and "Windows" in a["reason"]
    assert start(admin, mac).status_code == 409
    assert "update the agent" in admin.get(f"/api/devices/{old}/remote-sessions/availability").json()["reason"]
    assert start(admin, old).status_code == 409
    a = admin.get(f"/api/devices/{win}/remote-sessions/availability").json()
    assert a == {"available": True, "reason": None, "modes": ["view", "control"], "open_session_id": None}
    analyst = user_client(admin, "analyst")
    assert analyst.get(f"/api/devices/{win}/remote-sessions/availability").json()["modes"] == ["view"]


def test_no_button_when_mode_all_runs_several_workers(admin, monkeypatch):
    """REMOTE_RELAY_MODE=all with several workers (Azure: WEB_CONCURRENCY=2)
    would split a session's two sockets: remote sessions are not offered."""
    agent, dev = enroll_device(admin)
    monkeypatch.setenv("WEB_CONCURRENCY", "2")
    r = admin.get(f"/api/devices/{dev}/remote-sessions/availability")
    assert r.status_code == 200 and not r.json()["available"] and "not supported on this deployment" in r.json()["reason"]
    assert start(admin, dev).status_code == 409
    monkeypatch.setattr(config.settings, "remote_relay_mode", "api")  # on-prem: the relay service pairs them
    assert admin.get(f"/api/devices/{dev}/remote-sessions/availability").json()["available"]


def test_one_session_per_device_and_org_cap(admin, monkeypatch):
    _, d1 = enroll_device(admin)
    _, d2 = enroll_device(admin, "LAPTOP-002", "b" * 64)
    first = start(admin, d1)
    assert first.status_code == 201
    r = start(admin, d1)
    assert r.status_code == 409 and "already open" in r.json()["detail"]
    avail = admin.get(f"/api/devices/{d1}/remote-sessions/availability").json()
    assert not avail["available"] and avail["open_session_id"] == first.json()["id"]
    monkeypatch.setattr(config.settings, "remote_session_max_per_org", 1)
    r = start(admin, d2)
    assert r.status_code == 409 and "limit 1" in r.json()["detail"]
    admin.post(f"/api/remote-sessions/{first.json()['id']}/end")
    assert start(admin, d2).status_code == 201


# --------------------------------------------------------------------------- token
def test_token_minted_on_delivery_hashed_and_not_in_params(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    console = admin.get(f"/api/devices/{dev}/commands").json()
    cmd = next(c for c in console if c["type"] == "start_remote_session")
    assert "token" not in cmd["params"] and cmd["params"]["session_id"] == sid
    token, delivered = poll_token(agent, sid)
    assert len(token) >= 40 and delivered["params"]["mode"] == "view"
    assert delivered["params"]["requester_email"] == "admin@example.com"
    assert delivered["params"]["consent_timeout_seconds"] == 60
    rs = session_row(sid)
    assert rs.token_hash == rsvc.hash_token(token) and token not in json.dumps(
        admin.get(f"/api/devices/{dev}/commands").json())
    with db.get_session("default") as s:
        stored = s.get(DeviceCommand, delivered["id"])
        assert "token" not in stored.params
    # Command TTL = token TTL (2 minutes)
    assert (rs.token_expires_at - utcnow()) <= timedelta(seconds=121)


def test_token_single_use_replay_and_wrong_token(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    token, _ = poll_token(agent, sid)
    with agent_ws(admin, agent, sid, "x" * 43) as ws:
        assert closed_code(ws) == rsvc.CLOSE_AUTH
    with agent_ws(admin, agent, sid, token) as first:
        with agent_ws(admin, agent, sid, token) as replay:
            assert closed_code(replay) == rsvc.CLOSE_DUPLICATE
        first.send_json({"t": "consent", "allow": False})
        assert closed_code(first) == rsvc.CLOSE_ENDED
    # Replaying after the session is over is refused too.
    with agent_ws(admin, agent, sid, token) as again:
        assert closed_code(again) == rsvc.CLOSE_DUPLICATE
    assert session_row(sid).state == "denied"


def test_expired_token_fails_the_session(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    token, _ = poll_token(agent, sid)
    with db.get_session("default") as s:
        s.get(RemoteSession, sid).token_expires_at = utcnow() - timedelta(seconds=1)
        s.commit()
    with agent_ws(admin, agent, sid, token) as ws:
        assert closed_code(ws) == rsvc.CLOSE_EXPIRED
    rs = session_row(sid)
    assert rs.state == "failed" and rs.error_code == "ERR_TOKEN_EXPIRED"
    assert [a.action for a in audits()][-1] == "remote_session_failed"


def test_device_that_never_polls_times_out(admin):
    _, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    with db.get_session("default") as s:
        rs = s.get(RemoteSession, sid)
        s.get(DeviceCommand, rs.command_id).expires_at = utcnow() - timedelta(seconds=1)
        s.commit()
    r = admin.get(f"/api/remote-sessions/{sid}").json()
    assert r["state"] == "failed" and r["error_code"] == "ERR_DEVICE_TIMEOUT"


def test_agent_reports_unsupported_platform(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    _, cmd = poll_token(agent, sid)
    r = agent.post(f"/api/agent/commands/{cmd['id']}/result", json={
        "nonce": cmd["nonce"], "status": "failed", "output": "remote sessions are not supported on darwin yet",
        "result_data": {"error_code": "ERR_UNSUPPORTED_PLATFORM"}})
    assert r.status_code == 204, r.text
    rs = session_row(sid)
    assert rs.state == "failed" and rs.error_code == "ERR_UNSUPPORTED_PLATFORM"
    failed = audits()[-1]
    assert failed.action == "remote_session_failed" and failed.detail["error_code"] == "ERR_UNSUPPORTED_PLATFORM"
    assert "session_failed" in events()


def test_no_attended_user(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    _, cmd = poll_token(agent, sid)
    agent.post(f"/api/agent/commands/{cmd['id']}/result", json={
        "nonce": cmd["nonce"], "status": "failed", "output": "no signed-in user",
        "result_data": {"error_code": "ERR_NO_ATTENDED_USER"}})
    assert admin.get(f"/api/remote-sessions/{sid}").json()["error_code"] == "ERR_NO_ATTENDED_USER"


# --------------------------------------------------------------------------- relay
def test_full_session_relay_and_audit_trail(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    v, a = connected(admin, agent, sid)
    try:
        a.send_text(json.dumps({"t": "monitors", "monitors": [{"id": 0, "w": 1920, "h": 1080, "scale": 1.25}]}))
        assert next_json(v)["t"] == "monitors"
        a.send_bytes(TILE)
        m = recv(v)
        assert m.get("bytes") == TILE
        # View only: input and Ctrl+Alt+Del never reach the agent; acks do.
        v.send_json({"t": "input", "kind": "key", "code": "KeyA", "down": True})
        v.send_json({"t": "cad"})
        v.send_json({"t": "ack", "seq": 1})
        assert next_json(a) == {"t": "ack", "seq": 1}
        v.send_json({"t": "end"})
        assert closed_code(v) == rsvc.CLOSE_ENDED
        assert next_json(a) == {"t": "end", "reason": "ended_by_viewer"}
        assert closed_code(a) == rsvc.CLOSE_ENDED
    finally:
        v.__exit__(None, None, None)
        a.__exit__(None, None, None)
    rs = session_row(sid)
    assert rs.state == "ended" and rs.end_reason == "ended_by_viewer" and rs.open_device_id is None
    assert rs.bytes_to_viewer >= len(TILE) and rs.bytes_to_agent > 0
    trail = audits()
    assert [x.action for x in trail] == ["remote_session_requested", "remote_session_consented",
                                         "remote_session_started", "remote_session_ended"]
    ended = trail[-1]
    assert ended.actor_email == "admin@example.com" and ended.detail["mode"] == "view"
    assert ended.detail["reason"] == "user reports a frozen Outlook" and ended.detail["end_reason"] == "ended_by_viewer"
    assert "duration_s" in ended.detail and ended.detail["hostname"] == "LAPTOP-001"
    assert all(x.ip for x in trail)
    assert sorted(events()) == ["session_ended", "session_requested", "session_started"]
    # Metadata only: nothing of the frame or the keystroke was stored anywhere.
    blob = json.dumps([x.detail for x in trail])
    assert "jpeg-bytes" not in blob and "KeyA" not in blob


def test_control_mode_forwards_input(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev, "control").json()["id"]
    v, a = connected(admin, agent, sid)
    try:
        v.send_json({"t": "input", "kind": "key", "code": "KeyA", "down": True})
        assert next_json(a)["code"] == "KeyA"
        v.send_json({"t": "cad"})
        assert next_json(a) == {"t": "cad"}
        a.send_json({"t": "ended", "reason": "user_ended"})
        assert closed_code(v) == rsvc.CLOSE_ENDED
    finally:
        v.__exit__(None, None, None)
        a.__exit__(None, None, None)
    rs = session_row(sid)
    assert rs.state == "ended" and rs.end_reason == "user_ended"
    assert audits()[-1].actor_email == f"device:{dev}"


def test_no_frames_before_consent_and_deny_is_audited(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    token, _ = poll_token(agent, sid)
    with viewer_ws(admin, admin, sid) as v, agent_ws(admin, agent, sid, token) as a:
        until_state(v, "awaiting_consent")
        a.send_bytes(TILE)  # dropped: the user has not allowed anything yet
        a.send_json({"t": "consent", "allow": False})
        d = until_state(v, "ended")
        assert d["reason"] == "user_denied"
        assert closed_code(a) == rsvc.CLOSE_ENDED
    rs = session_row(sid)
    assert rs.state == "denied" and rs.end_reason == "user_denied" and rs.bytes_to_viewer == 0
    assert [x.action for x in audits()] == ["remote_session_requested", "remote_session_denied"]
    assert "session_denied" in events()


def test_consent_timeout_is_denied(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    token, _ = poll_token(agent, sid)
    with agent_ws(admin, agent, sid, token) as a:
        a.send_json({"t": "consent", "allow": False, "reason": "timeout"})
        assert closed_code(a) == rsvc.CLOSE_ENDED
    assert session_row(sid).end_reason == "consent_timeout"


def test_server_side_consent_deadline(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    token, _ = poll_token(agent, sid)
    with agent_ws(admin, agent, sid, token) as a:
        with db.get_session("default") as s:
            s.get(RemoteSession, sid).consent_deadline_at = utcnow() - timedelta(seconds=1)
            s.commit()
        assert closed_code(a) == rsvc.CLOSE_ENDED
    rs = session_row(sid)
    assert rs.state == "denied" and rs.end_reason == "consent_timeout"


def test_second_viewer_rejected_and_only_requester_views(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    other = user_client(admin, "admin", "admin2@example.com")
    with viewer_ws(admin, other, sid) as ws:
        assert closed_code(ws) == rsvc.CLOSE_FORBIDDEN
    with viewer_ws(admin, admin, sid) as v:
        until_state(v, "requested")
        with viewer_ws(admin, admin, sid) as dup:
            assert closed_code(dup) == rsvc.CLOSE_DUPLICATE
        v.send_json({"t": "end"})
        assert closed_code(v) == rsvc.CLOSE_ENDED


def test_origin_is_checked(admin):
    _, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    for origin in ("https://evil.example", None):
        with viewer_ws(admin, admin, sid, origin=origin) as ws:
            assert closed_code(ws) == rsvc.CLOSE_FORBIDDEN
    with viewer_ws(admin, admin, sid, origin="http://localhost:5173") as ws:  # Vite dev (CORS_ORIGINS default)
        assert until_state(ws, "requested")
        ws.send_json({"t": "end"})


def _fake_ws(host="console.example.com", scheme="wss", origin=None):
    headers = {"host": host}
    if origin:
        headers["origin"] = origin
    return SimpleNamespace(headers=headers, url=SimpleNamespace(scheme=scheme))


def test_origin_rules_in_production(monkeypatch):
    from app.api import remote_relay

    s = config.settings
    monkeypatch.setattr(s, "environment", "production")
    monkeypatch.setattr(s, "cors_origins", ["https://other.example.com"])
    monkeypatch.setattr(s, "public_base_url", "https://console.example.com")
    allowed = remote_relay.allowed_origins(_fake_ws())
    assert allowed == {"https://console.example.com"}
    assert not remote_relay.origin_ok(_fake_ws(origin="https://other.example.com"))
    assert remote_relay.origin_ok(_fake_ws(origin="https://console.example.com"))
    assert not remote_relay.origin_ok(_fake_ws(origin="http://console.example.com"))
    # Outside production: explicit CORS origins only, never '*' or wildcards.
    monkeypatch.setattr(s, "environment", "development")
    monkeypatch.setattr(s, "cors_origins", ["*", "https://*.example.com", "http://localhost:5173"])
    allowed = remote_relay.allowed_origins(_fake_ws())
    assert "http://localhost:5173" in allowed and not any("*" in o for o in allowed)
    assert not remote_relay.origin_ok(_fake_ws(origin="https://evil.example"))
    assert not remote_relay.origin_ok(_fake_ws(origin="*"))


def test_relay_audits_the_client_ip_through_trusted_proxies(admin, monkeypatch):
    monkeypatch.setattr(config.settings, "trust_proxy_headers", True)
    monkeypatch.setattr(config.settings, "trusted_proxy_cidrs", ["10.0.0.0/8"])
    agent, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    token, _ = poll_token(agent, sid)
    monkeypatch.setattr(admin._transport, "client", ("10.0.0.2", 50000))  # nginx
    with admin.websocket_connect(f"/api/agent/remote/{sid}", headers={
            "authorization": agent.headers["Authorization"], "x-remote-session-token": token,
            "x-forwarded-for": "203.0.113.7"}) as a:
        a.send_json({"t": "consent", "allow": True})
        a.send_json({"t": "started"})
        a.send_json({"t": "ended", "reason": "user_ended"})
        assert closed_code(a) == rsvc.CLOSE_ENDED
    trail = {x.action: x for x in audits()}
    for action in ("remote_session_consented", "remote_session_started", "remote_session_ended"):
        assert trail[action].ip == "203.0.113.7", action
    # A peer that is not a trusted proxy cannot inject an address.
    sid2 = start(admin, dev).json()["id"]
    token2, _ = poll_token(agent, sid2)
    monkeypatch.setattr(admin._transport, "client", ("198.51.100.9", 50000))
    with admin.websocket_connect(f"/api/agent/remote/{sid2}", headers={
            "authorization": agent.headers["Authorization"], "x-remote-session-token": token2,
            "x-forwarded-for": "203.0.113.7"}) as a:
        a.send_json({"t": "consent", "allow": True})
        a.send_json({"t": "ended", "reason": "user_ended"})
        assert closed_code(a) == rsvc.CLOSE_ENDED
    assert audits()[-1].ip == "198.51.100.9"


def test_fast_drag_is_not_rate_limited(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev, "control").json()["id"]
    v, a = connected(admin, agent, sid)
    try:
        sent = 0
        t0 = time.monotonic()
        # 3 s of a drag as the viewer sends it: one coalesced move per animation
        # frame (60/s) plus button events.
        for i in range(180):
            if i % 30 == 0:
                v.send_json({"t": "input", "kind": "button", "button": 0, "down": i % 60 == 0})
                sent += 1
            v.send_json({"t": "input", "kind": "move", "x": i * 100, "y": i * 50})
            sent += 1
            time.sleep(max(0.0, t0 + (i + 1) / 60 - time.monotonic()))
        for _ in range(sent):
            assert next_json(a)["t"] == "input"
        assert session_row(sid).state == "active"
    finally:
        v.send_json({"t": "end"})
        v.__exit__(None, None, None)
        a.__exit__(None, None, None)


def test_flooding_viewer_is_rate_limited(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev, "control").json()["id"]
    v, a = connected(admin, agent, sid)
    try:
        for _ in range(400):
            v.send_json({"t": "activity"})
        assert closed_code(v) == rsvc.CLOSE_RATE
    finally:
        v.__exit__(None, None, None)
        a.__exit__(None, None, None)
    assert session_row(sid).end_reason == "viewer_rate_limited"


def test_message_size_limits(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    v, a = connected(admin, agent, sid)
    try:
        v.send_text(json.dumps({"t": "activity", "pad": "x" * 20000}))
        assert closed_code(v) == 1009
    finally:
        v.__exit__(None, None, None)
        a.__exit__(None, None, None)
    assert session_row(sid).end_reason == "protocol_error"


# --------------------------------------------------------------------------- termination
@pytest.mark.parametrize("how", ["revoke", "lost_mode", "isolate", "demote", "disable", "admin_end"])
def test_termination_closes_both_sockets(admin, how):
    agent, dev = enroll_device(admin)
    analyst = user_client(admin, "analyst")
    sid = start(analyst, dev).json()["id"]
    v, a = connected(admin, agent, sid, viewer_c=analyst)
    try:
        if how == "revoke":
            assert admin.post(f"/api/devices/{dev}/revoke", json={"reason": "stolen laptop"}).status_code == 200
        elif how == "lost_mode":
            r = admin.post(f"/api/devices/{dev}/commands", json={
                "type": "enable_lost_mode", "reason": "left on a train", "confirm_hostname": "LAPTOP-001",
                "params": {"message": "Please return", "phone": "+234 800 000"}})
            assert r.status_code == 201, r.text
        elif how == "isolate":
            assert admin.post(f"/api/devices/{dev}/commands",
                              json={"type": "isolate_host", "reason": "malware"}).status_code == 201
        elif how in ("demote", "disable"):
            uid = next(u["id"] for u in admin.get("/api/users").json() if u["email"] == "analyst@example.com")
            body = {"role": "viewer"} if how == "demote" else {"is_active": False}
            assert admin.patch(f"/api/users/{uid}", json=body).status_code == 200
        else:
            assert admin.post(f"/api/remote-sessions/{sid}/end").status_code == 200
        assert closed_code(v, timeout=10) == rsvc.CLOSE_ENDED
        assert closed_code(a, timeout=10) == rsvc.CLOSE_ENDED
    finally:
        v.__exit__(None, None, None)
        a.__exit__(None, None, None)
    expected = {"revoke": "device_revoked", "lost_mode": "device_lost_mode", "isolate": "device_isolated",
                "demote": "requester_access_revoked", "disable": "requester_access_revoked",
                "admin_end": "ended_by_admin"}[how]
    rs = session_row(sid)
    assert rs.state == "ended" and rs.end_reason == expected
    assert audits()[-1].action == "remote_session_ended"


@pytest.mark.parametrize("how", ["logout", "expired", "revoked_all"])
def test_signing_out_ends_the_open_viewer(admin, how):
    """The viewer's socket outlives nothing its sign-in session does not: logout,
    expiry and sign-out everywhere (password reset) end the remote session."""
    from app.models import UserSession

    agent, dev = enroll_device(admin)
    analyst = user_client(admin, "analyst")
    sid = start(analyst, dev).json()["id"]
    v, a = connected(admin, agent, sid, viewer_c=analyst)
    try:
        if how == "logout":
            assert analyst.post("/api/auth/logout").status_code == 204
        else:
            with db.get_session("default") as s:
                for us in s.scalars(select(UserSession).where(UserSession.user_id == session_row(sid).requested_by_id)):
                    if how == "expired":
                        us.expires_at = utcnow() - timedelta(seconds=1)
                    else:
                        us.revoked_at = utcnow()
                s.commit()
        assert closed_code(v, timeout=10) == rsvc.CLOSE_ENDED
        assert closed_code(a, timeout=10) == rsvc.CLOSE_ENDED
    finally:
        v.__exit__(None, None, None)
        a.__exit__(None, None, None)
    rs = session_row(sid)
    assert rs.state == "ended" and rs.end_reason == "viewer_session_revoked"


def test_viewer_activity_keeps_its_sign_in_session_alive(admin, monkeypatch):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    v, a = connected(admin, agent, sid)
    v.__exit__(None, None, None)
    a.__exit__(None, None, None)
    from app.models import UserSession

    monkeypatch.setattr(config.settings, "session_idle_minutes", 30.0)
    with db.get_session("default") as s:
        us = s.scalars(select(UserSession).where(UserSession.revoked_at.is_(None))).first()
        now = utcnow()
        us.last_seen_at = now - timedelta(minutes=29)
        assert rsvc.viewer_session_live(s, us.id, activity_at=now, now=now)
        assert us.last_seen_at == now  # touched, as a REST request would
        us.last_seen_at = now - timedelta(minutes=31)
        assert not rsvc.viewer_session_live(s, us.id, now=now)  # idle
        assert not rsvc.viewer_session_live(s, "0" * 64, now=now)  # deleted
        assert rsvc.viewer_session_live(s, None, now=now)  # no viewer has connected yet
        s.rollback()


def test_viewer_caused_ends_audit_the_viewers_ip(admin, monkeypatch):
    monkeypatch.setattr(config.settings, "trust_proxy_headers", True)
    monkeypatch.setattr(config.settings, "trusted_proxy_cidrs", ["10.0.0.0/8"])
    monkeypatch.setattr(admin._transport, "client", ("10.0.0.2", 50000))  # nginx
    agent, dev = enroll_device(admin)
    sid = start(admin, dev, "control").json()["id"]
    token, _ = poll_token(agent, sid)
    with admin.websocket_connect(f"/api/remote/{sid}", headers={
            "cookie": cookie(admin), "origin": ORIGIN, "x-forwarded-for": "203.0.113.50"}) as v, \
            admin.websocket_connect(f"/api/agent/remote/{sid}", headers={
                "authorization": agent.headers["Authorization"], "x-remote-session-token": token,
                "x-forwarded-for": "198.51.100.20"}) as a:
        until_state(v, "awaiting_consent")
        a.send_json({"t": "consent", "allow": True})
        until_state(v, "active")
        for _ in range(400):
            v.send_json({"t": "activity"})
        assert closed_code(v) == rsvc.CLOSE_RATE
    ended = audits()[-1]
    assert ended.action == "remote_session_ended" and ended.ip == "203.0.113.50"
    assert next(x for x in audits() if x.action == "remote_session_consented").ip == "198.51.100.20"


def test_heartbeat_grace_follows_the_recheck_interval(monkeypatch):
    monkeypatch.setattr(config.settings, "remote_session_recheck_seconds", 5.0)
    assert rsvc.heartbeat_grace() == timedelta(seconds=60)
    monkeypatch.setattr(config.settings, "remote_session_recheck_seconds", 60.0)
    assert rsvc.heartbeat_grace() == timedelta(seconds=180)


def test_send_to_a_stuck_socket_gives_up(monkeypatch):
    """A peer that stopped reading cannot stall the relay (finish(), the other end)."""
    from starlette.websockets import WebSocketState

    from app import remote_hub

    class Stuck:
        application_state = WebSocketState.CONNECTED

        async def send_text(self, data):
            await anyio.sleep(3600)

        send_bytes = send_text

        async def close(self, code, reason):
            await anyio.sleep(3600)

    monkeypatch.setattr(remote_hub, "SEND_TIMEOUT", 0.1)
    pair = remote_hub.Pair(session_id="x" * 32, org_id="default", mode="view")
    hub = remote_hub.Hub()

    async def go():
        t0 = time.monotonic()
        await hub.send_text(pair, Stuck(), {"t": "ping"})
        assert not await hub.send_bytes(pair, Stuck(), b"tile")
        return time.monotonic() - t0
    assert anyio.run(go) < 1.0


def test_relay_listeners_have_their_own_size_caps(monkeypatch):
    from app import relay_main

    monkeypatch.setattr(config.settings, "remote_relay_mode", "relay")
    agent, viewer = relay_main._servers()
    s = config.settings
    assert (agent.config.port, viewer.config.port) == (8001, 8002)
    assert agent.config.ws_max_size > s.remote_session_agent_max_message_bytes
    assert viewer.config.ws_max_size == 2 * s.remote_session_viewer_max_message_bytes < 1024 * 1024

    def reach(app, path) -> int:
        # Not `with TestClient(...)`: the relay's lifespan would re-initialise the
        # process-wide database engine. These refusals need no database.
        c = TestClient(app, base_url=BASE_URL)
        try:
            with c.websocket_connect(path) as ws:
                return closed_code(ws)
        except WebSocketDisconnect as e:
            return -e.code  # refused before accepting: no such route here

    # Each listener serves only its own end (bad ids: refused before any lookup).
    assert reach(agent.config.app, "/api/agent/remote/not-a-session") == rsvc.CLOSE_NOT_FOUND
    assert reach(agent.config.app, "/api/remote/not-a-session") < 0
    assert reach(viewer.config.app, "/api/remote/not-a-session") == rsvc.CLOSE_FORBIDDEN  # no Origin
    assert reach(viewer.config.app, "/api/agent/remote/not-a-session") < 0


def test_agent_disconnect_ends_the_session(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    v, a = connected(admin, agent, sid)
    try:
        a.close()
        assert until_state(v, "ended")["reason"] == "agent_disconnected"
    finally:
        v.__exit__(None, None, None)
        a.__exit__(None, None, None)


def test_idle_and_hard_limits(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    v, a = connected(admin, agent, sid)
    v.__exit__(None, None, None)
    a.__exit__(None, None, None)
    with db.get_session("default") as s:
        rs = s.get(RemoteSession, sid)
        now = utcnow()
        assert rsvc.check_live(s, rs, now) in (None, "agent_disconnected", "ended_by_viewer")
    with db.get_session("default") as s:
        rs = RemoteSession(device_id=dev, requested_by_id=session_row(sid).requested_by_id,
                           requested_by_email="admin@example.com", mode="view", reason="r", state="active",
                           consented_at=utcnow(), last_activity_at=utcnow())
        s.add(rs)
        s.flush()
        lim = rsvc.limits()
        assert rsvc.check_live(s, rs, utcnow()) is None
        assert rsvc.check_live(s, rs, utcnow() + lim.idle + timedelta(seconds=1)) == "idle"
        rs.last_activity_at = utcnow() + lim.max_duration
        assert rsvc.check_live(s, rs, utcnow() + lim.max_duration + timedelta(seconds=1)) == "max_duration"
        s.rollback()


def test_session_history(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    admin.post(f"/api/remote-sessions/{sid}/end")
    hist = admin.get(f"/api/devices/{dev}/remote-sessions").json()
    assert [h["id"] for h in hist] == [sid]
    assert hist[0]["requested_by_email"] == "admin@example.com" and hist[0]["state"] == "ended"
    assert hist[0]["end_reason"] == "ended_by_viewer" and hist[0]["duration_seconds"] is None


# --------------------------------------------------------------------------- organisations
def test_organisation_isolation_of_api_and_relay(admin):
    agent, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    create_org("acme", ACME_ADMIN, ACME_PASSWORD, name="Acme Ltd")
    acme = org_client(admin.app, ACME_ADMIN, ACME_PASSWORD)
    assert acme.get(f"/api/remote-sessions/{sid}").status_code == 404
    assert acme.post(f"/api/remote-sessions/{sid}/end").status_code == 404
    assert acme.get(f"/api/devices/{dev}/remote-sessions").status_code == 404
    assert start(acme, dev).status_code == 404
    with viewer_ws(admin, acme, sid) as ws:
        assert closed_code(ws) == rsvc.CLOSE_NOT_FOUND
    # An Acme device credential with the default organisation's session id.
    token = new_token(acme)
    acme_agent = agent_client(admin.app)
    r = enroll(acme_agent, token, machine_id="d" * 64, hostname="ACME-1")
    acme_agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    real_token, _ = poll_token(agent, sid)
    with agent_ws(admin, acme_agent, sid, real_token) as ws:
        assert closed_code(ws) == rsvc.CLOSE_NOT_FOUND
    assert session_row(sid).state == "requested"  # the real device can still connect
    with db.get_session("default") as s:
        assert s.get(RemoteSession, sid).organization_id == "default"


def test_relay_refused_in_api_mode(admin, monkeypatch):
    monkeypatch.setattr(config.settings, "remote_relay_mode", "api")
    _, dev = enroll_device(admin)
    sid = start(admin, dev).json()["id"]
    with viewer_ws(admin, admin, sid) as ws:
        assert closed_code(ws) == rsvc.CLOSE_UNAVAILABLE


def test_settings_are_validated(monkeypatch):
    monkeypatch.setattr(config.settings, "remote_relay_mode", "both")
    monkeypatch.setattr(config.settings, "remote_session_max_fps", 120)
    problems = config.settings.remote_session_problems()
    assert any("REMOTE_RELAY_MODE" in p for p in problems) and any("MAX_FPS" in p for p in problems)
