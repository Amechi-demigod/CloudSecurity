"""Authentication, sessions, CSRF, RBAC, user admin, audit log and bootstrap."""
from __future__ import annotations

import io
import re
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import config, db
from app.models import AuditLog, User, UserSession, utcnow
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, AUTH, BASE_URL, login, make_user, reset_database

GENERIC = "Invalid email or password"


def new_client(app) -> TestClient:
    """Second browser against the same running app (no `with`: that would re-run startup)."""
    return TestClient(app, base_url=BASE_URL)


def audit_actions() -> list[str]:
    with db.get_session() as s:
        return [a.action for a in s.scalars(select(AuditLog).order_by(AuditLog.id))]


def first_finding(c) -> dict:
    return c.get("/api/findings").json()[0]


# --- login / logout / me ------------------------------------------------------------

def test_login_success_sets_hardened_cookie(anon_client):
    r = anon_client.post("/api/auth/login", json={"email": "  ADMIN@example.COM ", "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["user"]["email"] == ADMIN_EMAIL and body["user"]["role"] == "admin"
    assert body["csrf_token"] and "password_hash" not in body["user"]
    cookie = r.headers["set-cookie"]
    assert cookie.startswith("cnapp_session=")
    for attr in ("HttpOnly", "Secure", "SameSite=lax", "Path=/", "Max-Age=28800"):
        assert attr.lower() in cookie.lower(), cookie
    me = anon_client.get("/api/auth/me")
    assert me.status_code == 200 and me.json()["user"]["email"] == ADMIN_EMAIL
    assert me.json()["csrf_token"] == body["csrf_token"]
    with db.get_session() as s:
        token = anon_client.cookies.get("cnapp_session")
        assert s.get(UserSession, token) is None  # only the hash is stored
        assert s.scalar(select(User).where(User.email == ADMIN_EMAIL)).last_login_at is not None
    assert "login_success" in audit_actions()


def test_cookie_secure_flag_configurable(anon_client, monkeypatch):
    monkeypatch.setattr(config.settings, "cookie_secure", False)
    r = anon_client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert "secure" not in r.headers["set-cookie"].lower()


def test_login_failures_are_generic(anon_client):
    wrong = anon_client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": "nope-nope-nope"})
    unknown = anon_client.post("/api/auth/login", json={"email": "ghost@example.com", "password": "nope-nope-nope"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["detail"] == unknown.json()["detail"] == GENERIC
    assert "set-cookie" not in wrong.headers
    assert anon_client.get("/api/auth/me").status_code == 401
    assert audit_actions().count("login_failure") == 2


def test_login_requires_json(anon_client):
    r = anon_client.post("/api/auth/login", content=f"email={ADMIN_EMAIL}&password={ADMIN_PASSWORD}",
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code in (415, 422)
    assert anon_client.get("/api/auth/me").status_code == 401


def test_logout_revokes_session(client):
    cookie = client.cookies.get("cnapp_session")
    r = client.post("/api/auth/logout")
    assert r.status_code == 204
    assert 'cnapp_session=""' in r.headers["set-cookie"] or "max-age=0" in r.headers["set-cookie"].lower()
    # Replaying the old cookie no longer works: the session was revoked server-side.
    client.cookies.set("cnapp_session", cookie)
    me = client.get("/api/auth/me")
    assert me.status_code == 401 and me.json()["detail"] == "Session expired"
    assert "logout" in audit_actions()


def test_idle_timeout_expires_session(client):
    with db.get_session() as s:
        for sess in s.scalars(select(UserSession)):
            sess.last_seen_at = utcnow() - timedelta(minutes=config.settings.session_idle_minutes + 1)
        s.commit()
    r = client.get("/api/dashboard")
    assert r.status_code == 401 and r.json()["detail"] == "Session expired"


def test_absolute_expiry(client):
    with db.get_session() as s:
        for sess in s.scalars(select(UserSession)):
            sess.expires_at = utcnow() - timedelta(seconds=1)
        s.commit()
    assert client.get("/api/auth/me").status_code == 401


def test_activity_extends_idle_window(client):
    with db.get_session() as s:
        for sess in s.scalars(select(UserSession)):
            sess.last_seen_at = utcnow() - timedelta(minutes=config.settings.session_idle_minutes - 1)
        s.commit()
    assert client.get("/api/auth/me").status_code == 200
    with db.get_session() as s:
        assert all(utcnow() - x.last_seen_at < timedelta(minutes=1) for x in s.scalars(select(UserSession)))


# --- brute force ------------------------------------------------------------------

def test_account_lockout(anon_client, monkeypatch):
    monkeypatch.setattr(config.settings, "login_max_failures", 3)
    for _ in range(3):
        r = anon_client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": "wrong-password-x"})
        assert r.status_code == 401
    # Correct password is refused while locked, with the same generic message.
    r = anon_client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 401 and r.json()["detail"] == GENERIC
    assert "login_locked" in audit_actions()
    with db.get_session() as s:
        u = s.scalar(select(User).where(User.email == ADMIN_EMAIL))
        assert u.locked_until is not None and u.locked_until > utcnow() + timedelta(minutes=14)
        u.locked_until = utcnow() - timedelta(seconds=1)  # lockout elapses
        s.commit()
    login(anon_client)
    with db.get_session() as s:
        u = s.scalar(select(User).where(User.email == ADMIN_EMAIL))
        assert u.failed_login_count == 0 and u.locked_until is None


def test_per_ip_rate_limit(anon_client, monkeypatch):
    monkeypatch.setattr(config.settings, "login_rate_limit", 3)
    for _ in range(3):
        anon_client.post("/api/auth/login", json={"email": "x@example.com", "password": "whatever-password"})
    r = anon_client.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 429 and "Retry-After" in r.headers
    assert "login_rate_limited" in audit_actions()


def test_rate_limit_uses_forwarded_ip_only_when_trusted(anon_client, monkeypatch):
    monkeypatch.setattr(config.settings, "login_rate_limit", 1)
    bad = {"email": "x@example.com", "password": "whatever-password"}
    monkeypatch.setattr(config.settings, "trust_proxy_headers", True)
    assert anon_client.post("/api/auth/login", json=bad, headers={"X-Forwarded-For": "203.0.113.1"}).status_code == 401
    assert anon_client.post("/api/auth/login", json=bad, headers={"X-Forwarded-For": "203.0.113.2"}).status_code == 401
    assert anon_client.post("/api/auth/login", json=bad, headers={"X-Forwarded-For": "203.0.113.2"}).status_code == 429


# --- CSRF ---------------------------------------------------------------------------

def test_csrf_required_for_state_changes(client):
    f = first_finding(client)
    token = client.headers.pop("X-CSRF-Token")
    r = client.patch(f"/api/findings/{f['id']}", json={"status": "suppressed"})
    assert r.status_code == 403 and "CSRF" in r.json()["detail"]
    r = client.patch(f"/api/findings/{f['id']}", json={"status": "suppressed"}, headers={"X-CSRF-Token": "forged"})
    assert r.status_code == 403
    assert client.post("/api/auth/logout").status_code == 403
    # Reads do not need the token.
    assert client.get("/api/findings").status_code == 200
    r = client.patch(f"/api/findings/{f['id']}", json={"status": "suppressed"}, headers={"X-CSRF-Token": token})
    assert r.status_code == 200


def test_csrf_token_is_per_session(anon_client):
    first = login(anon_client).json()["csrf_token"]
    second = login(anon_client).json()["csrf_token"]
    assert first != second
    f = first_finding(anon_client)
    r = anon_client.patch(f"/api/findings/{f['id']}", json={"status": "suppressed"}, headers={"X-CSRF-Token": first})
    assert r.status_code == 403


# --- unauthenticated access -----------------------------------------------------------

PUBLIC = {("GET", "/api/health"), ("POST", "/api/auth/login"), ("POST", "/api/runtime/events"), ("GET", "/docs")}
# MFA second step / forced enrolment (challenge-token auth) and SSO (tested in test_mfa.py / test_sso.py).
PUBLIC |= {("POST", "/api/auth/login/mfa"), ("POST", "/api/auth/login/mfa/enroll/start"),
           ("POST", "/api/auth/login/mfa/enroll/confirm"), ("GET", "/api/auth/providers"),
           ("GET", "/api/auth/sso/entra/login"), ("GET", "/api/auth/sso/entra/callback")}


def test_every_endpoint_requires_auth(anon_client):
    # Every route in the OpenAPI schema (= every API endpoint); hidden docs routes are tested below.
    paths = anon_client.app.openapi()["paths"]
    checked = 0
    for route_path, ops in paths.items():
        path = re.sub(r"\{[^}]+\}", "x", route_path)
        for method in ops:
            method = method.upper()
            if (method, route_path) in PUBLIC:
                continue
            r = anon_client.request(method, path, json={})
            assert r.status_code == 401, f"{method} {route_path} -> {r.status_code}"
            checked += 1
    assert checked >= 30


def test_public_endpoints(anon_client):
    assert anon_client.get("/api/health").json()["status"] == "ok"
    assert anon_client.get("/docs", follow_redirects=False).headers["location"] == "/api/docs"


def test_api_docs_locked_unless_public(anon_client, monkeypatch):
    assert anon_client.get("/api/openapi.json").status_code == 401
    assert anon_client.get("/api/docs").status_code == 401
    assert anon_client.get("/openapi.json").status_code == 404
    login(anon_client)
    spec = anon_client.get("/api/openapi.json").json()
    assert "/api/auth/login" in spec["paths"]
    assert anon_client.get("/api/docs").status_code == 200
    monkeypatch.setenv("API_DOCS_PUBLIC", "true")
    config.reload_settings()
    from app.main import create_app

    with new_client(create_app()) as c:
        assert c.get("/api/openapi.json").status_code == 200
    monkeypatch.setenv("API_DOCS_PUBLIC", "false")
    config.reload_settings()


# --- sensor ingest keeps its own token ---------------------------------------------------

def test_sensor_ingest_uses_bearer_token_not_session(anon_client):
    ev = {"event_type": "file_access", "file": {"path": "/etc/shadow"}}
    assert anon_client.post("/api/runtime/events", json=ev, headers=AUTH).status_code == 202
    login(anon_client)
    # A user session (even an admin's, with CSRF) is not a sensor credential.
    assert anon_client.post("/api/runtime/events", json=ev).status_code == 401


# --- roles -------------------------------------------------------------------------------

def test_role_enforcement(client):
    make_user(client, "viewer")
    make_user(client, "analyst")
    f = first_finding(client)
    alert = client.get("/api/alerts").json()[0]
    app = client.app

    viewer = new_client(app)
    assert login(viewer, "viewer@example.com", "a-long-test-password").json()["user"]["role"] == "viewer"
    for path in ("/api/dashboard", "/api/assets", "/api/findings", "/api/vulnerabilities", "/api/alerts",
                 "/api/attack-paths", "/api/connectors", "/api/scans"):
        assert viewer.get(path).status_code == 200, path
    assert viewer.patch(f"/api/findings/{f['id']}", json={"status": "suppressed"}).status_code == 403
    assert viewer.patch(f"/api/alerts/{alert['id']}", json={"status": "resolved"}).status_code == 403
    assert viewer.post("/api/scans", json={"connector": "azure"}).status_code == 403
    assert viewer.get("/api/users").status_code == 403
    assert viewer.get("/api/audit-log").status_code == 403

    analyst = new_client(app)
    login(analyst, "analyst@example.com", "a-long-test-password")
    assert analyst.patch(f"/api/findings/{f['id']}", json={"status": "suppressed"}).status_code == 200
    assert analyst.patch(f"/api/alerts/{alert['id']}", json={"status": "resolved"}).status_code == 200
    assert analyst.post("/api/scans", json={"connector": "azure"}).status_code == 400  # allowed, not configured
    assert analyst.get("/api/users").status_code == 403
    assert analyst.post("/api/users", json={"email": "z@example.com", "role": "admin",
                                            "password": "a-long-test-password"}).status_code == 403

    assert client.get("/api/users").status_code == 200
    actions = audit_actions()
    assert "finding_updated" in actions and "alert_updated" in actions


# --- user management ------------------------------------------------------------------

def test_user_admin_lifecycle(client):
    u = make_user(client, "viewer", email="Dana@Example.com")
    assert u["email"] == "dana@example.com"
    dup = client.post("/api/users", json={"email": "dana@example.com", "password": "a-long-test-password"})
    assert dup.status_code == 409
    weak = client.post("/api/users", json={"email": "weak@example.com", "password": "short"})
    assert weak.status_code == 422

    dana = new_client(client.app)
    login(dana, "dana@example.com", "a-long-test-password")
    # Promote: takes effect on the existing session.
    assert client.patch(f"/api/users/{u['id']}", json={"role": "analyst"}).json()["role"] == "analyst"
    assert dana.get("/api/auth/me").json()["user"]["role"] == "analyst"
    # Deactivate: existing sessions die and login fails generically.
    assert client.patch(f"/api/users/{u['id']}", json={"is_active": False}).json()["is_active"] is False
    assert dana.get("/api/auth/me").status_code == 401
    r = dana.post("/api/auth/login", json={"email": "dana@example.com", "password": "a-long-test-password"})
    assert r.status_code == 401 and r.json()["detail"] == GENERIC

    client.patch(f"/api/users/{u['id']}", json={"is_active": True})
    assert client.post(f"/api/users/{u['id']}/reset-password", json={"password": "short"}).status_code == 422
    assert client.post(f"/api/users/{u['id']}/reset-password",
                       json={"password": "brand-new-password-1"}).status_code == 200
    login(new_client(client.app), "dana@example.com", "brand-new-password-1")

    log = client.get("/api/audit-log").json()
    actions = {e["action"] for e in log}
    assert {"user_created", "user_updated", "password_reset", "login_success", "login_failure"} <= actions
    upd = next(e for e in log if e["action"] == "user_updated" and "role" in e["detail"]["changes"])
    assert upd["actor_email"] == ADMIN_EMAIL and upd["target"] == "dana@example.com"
    assert client.get("/api/audit-log", params={"action": "user_created"}).json()[0]["action"] == "user_created"
    assert client.patch("/api/users/nope", json={"role": "viewer"}).status_code == 404


def test_cannot_remove_last_admin(client):
    me = client.get("/api/auth/me").json()["user"]
    assert client.patch(f"/api/users/{me['id']}", json={"role": "viewer"}).status_code == 409
    assert client.patch(f"/api/users/{me['id']}", json={"is_active": False}).status_code == 409
    other = make_user(client, "admin", email="admin2@example.com")
    assert client.patch(f"/api/users/{other['id']}", json={"role": "analyst"}).status_code == 200


def test_change_password(client):
    other = new_client(client.app)
    login(other)
    bad = client.post("/api/auth/change-password",
                      json={"current_password": "wrong-password!", "new_password": "another-good-password"})
    assert bad.status_code == 400
    short = client.post("/api/auth/change-password",
                        json={"current_password": ADMIN_PASSWORD, "new_password": "short"})
    assert short.status_code == 422
    ok = client.post("/api/auth/change-password",
                     json={"current_password": ADMIN_PASSWORD, "new_password": "another-good-password"})
    assert ok.status_code == 204
    assert client.get("/api/auth/me").status_code == 200  # this session survives
    assert other.get("/api/auth/me").status_code == 401   # other sessions are revoked
    r = other.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 401
    login(other, ADMIN_EMAIL, "another-good-password")
    assert "password_changed" in audit_actions()


# --- bootstrap & CLI -------------------------------------------------------------------

def test_bootstrap_admin_created_once(anon_client):
    with db.get_session() as s:
        users = list(s.scalars(select(User)))
    assert [(u.email, u.role) for u in users] == [(ADMIN_EMAIL, "admin")]
    assert users[0].password_hash.startswith("$argon2id$")
    assert "user_bootstrapped" in audit_actions()

    from app.auth import bootstrap_admin

    with db.get_session() as s:
        assert bootstrap_admin(s) is None  # users exist: no-op


@pytest.mark.parametrize("email,password", [(None, None), ("a@example.com", None), ("a@example.com", "tooshort")])
def test_no_admin_without_valid_env(monkeypatch, email, password):
    for k, v in (("ADMIN_EMAIL", email), ("ADMIN_PASSWORD", password)):
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)
    config.reload_settings()
    reset_database()
    from app.main import create_app

    try:
        with new_client(create_app()) as c:
            with db.get_session() as s:
                assert s.scalars(select(User)).first() is None
            r = c.post("/api/auth/login", json={"email": "a@example.com", "password": password or "x" * 12})
            assert r.status_code == 401
    finally:
        monkeypatch.undo()
        config.reload_settings()


def test_cli_create_user_and_reset(session, monkeypatch, capsys):
    from app import cli

    monkeypatch.setattr(db, "init_engine", lambda url, **kw: None)  # keep the fixture's in-memory DB
    monkeypatch.setattr("sys.stdin", io.StringIO("cli-password-123\n"))
    assert cli.main(["create-user", "--email", "Ops@Example.com", "--role", "admin", "--password-stdin"]) == 0
    u = session.scalar(select(User).where(User.email == "ops@example.com"))
    assert u is not None and u.role == "admin"
    from app.auth import verify_password

    assert verify_password(u.password_hash, "cli-password-123")
    monkeypatch.setattr("sys.stdin", io.StringIO("cli-password-123\n"))
    with pytest.raises(SystemExit):
        cli.main(["create-user", "--email", "ops@example.com", "--password-stdin"])
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    with pytest.raises(SystemExit):
        cli.main(["create-user", "--email", "new@example.com", "--password-stdin"])
    monkeypatch.setattr("sys.stdin", io.StringIO("cli-password-456\n"))
    assert cli.main(["reset-password", "--email", "ops@example.com", "--password-stdin"]) == 0
    session.expire_all()
    assert verify_password(session.scalar(select(User).where(User.email == "ops@example.com")).password_hash,
                           "cli-password-456")
