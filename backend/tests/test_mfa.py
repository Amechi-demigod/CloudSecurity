"""TOTP MFA: enrolment, two-step login, replay prevention, recovery codes,
lockout, forced enrolment, self-service disable/regenerate and admin reset."""
from __future__ import annotations

import time
from datetime import timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import config, db, mfa
from app.models import AuditLog, MfaChallenge, MfaRecoveryCode, User, UserMfa, utcnow
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, BASE_URL, login, make_user

USER_PW = "a-long-test-password"


class Clock:
    """Controls the time the TOTP verifier sees (codes are generated for the same instant)."""

    def __init__(self) -> None:
        self.now = float(int(time.time() // 30) * 30 + 5)

    def time(self) -> float:
        return self.now

    def advance(self, steps: int = 1) -> None:
        self.now += 30 * steps


@pytest.fixture()
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(mfa.time, "time", c.time)
    return c


def code_at(secret: str, clock: Clock, offset_steps: int = 0) -> str:
    return pyotp.TOTP(secret).at(clock.now + 30 * offset_steps)


def audit_actions() -> list[str]:
    with db.get_session() as s:
        return [a.action for a in s.scalars(select(AuditLog).order_by(AuditLog.id))]


def audit_rows(action: str) -> list[AuditLog]:
    with db.get_session() as s:
        return list(s.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id)))


def enable_mfa(c: TestClient, clock: Clock) -> tuple[str, list[str]]:
    r = c.post("/api/auth/mfa/totp/setup")
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    r = c.post("/api/auth/mfa/totp/enable", json={"code": code_at(secret, clock)})
    assert r.status_code == 200, r.text
    return secret, r.json()["recovery_codes"]


def password_step(c: TestClient, email: str = ADMIN_EMAIL, password: str = ADMIN_PASSWORD) -> dict:
    r = c.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def new_browser(c: TestClient) -> TestClient:
    return TestClient(c.app, base_url=BASE_URL)


def mfa_login(c: TestClient, code: str, email: str = ADMIN_EMAIL, password: str = ADMIN_PASSWORD):
    body = password_step(c, email, password)
    assert body["mfa_required"] and body["purpose"] == "verify", body
    return c.post("/api/auth/login/mfa", json={"mfa_token": body["mfa_token"], "code": code})


# --- enrolment ---------------------------------------------------------------------------

def test_enrolment_is_verified_before_enable(client, clock):
    st = client.get("/api/auth/mfa").json()
    assert st == {"enabled": False, "enabled_at": None, "required": False, "recovery_codes_remaining": 0,
                  "has_password": True, "sso_user": False}
    r = client.post("/api/auth/mfa/totp/setup")
    body = r.json()
    secret = body["secret"]
    assert body["qr_svg"].startswith("data:image/svg+xml") and body["digits"] == 6 and body["period"] == 30
    assert body["otpauth_uri"].startswith("otpauth://totp/") and "issuer=CloudSecurity" in body["otpauth_uri"]
    assert not client.get("/api/auth/mfa").json()["enabled"]  # pending only

    wrong = client.post("/api/auth/mfa/totp/enable", json={"code": "000000" if code_at(secret, clock) != "000000"
                                                            else "111111"})
    assert wrong.status_code == 400
    assert not client.get("/api/auth/mfa").json()["enabled"]

    r = client.post("/api/auth/mfa/totp/enable", json={"code": code_at(secret, clock)})
    assert r.status_code == 200
    codes = r.json()["recovery_codes"]
    assert len(codes) == 10 and len(set(codes)) == 10 and all(len(x) == 19 for x in codes)
    st = client.get("/api/auth/mfa").json()
    assert st["enabled"] and st["recovery_codes_remaining"] == 10
    assert client.post("/api/auth/mfa/totp/setup").status_code == 409

    with db.get_session() as s:
        row = s.scalar(select(UserMfa))
        assert secret not in row.totp_secret_enc and row.pending_secret_enc is None
        assert mfa.decrypt_secret(row.totp_secret_enc) == secret
        hashes = [rc.code_hash for rc in s.scalars(select(MfaRecoveryCode))]
        assert len(hashes) == 10 and not any(c.replace("-", "") in h for c in codes for h in hashes)
    actions = audit_actions()
    assert "mfa_setup_started" in actions and "mfa_enable_failure" in actions and "mfa_enabled" in actions


def test_setup_expires(client, clock):
    secret = client.post("/api/auth/mfa/totp/setup").json()["secret"]
    with db.get_session() as s:
        s.scalar(select(UserMfa)).pending_created_at = utcnow() - timedelta(minutes=16)
        s.commit()
    assert client.post("/api/auth/mfa/totp/enable", json={"code": code_at(secret, clock)}).status_code == 409


# --- two-step login ------------------------------------------------------------------------

def test_login_requires_second_factor(client, clock):
    secret, _ = enable_mfa(client, clock)
    b = new_browser(client)
    body = password_step(b)
    assert set(body) == {"mfa_required", "purpose", "mfa_token", "expires_in"} and body["expires_in"] == 300
    assert "cnapp_session" not in b.cookies
    assert b.get("/api/auth/me").status_code == 401
    # the challenge token is not a session
    assert b.get("/api/auth/me", cookies={"cnapp_session": body["mfa_token"]}).status_code == 401

    bad = b.post("/api/auth/login/mfa", json={"mfa_token": body["mfa_token"], "code": "12345x"})
    assert bad.status_code == 401 and bad.json()["detail"] == "Invalid verification code"
    clock.advance()
    r = b.post("/api/auth/login/mfa", json={"mfa_token": body["mfa_token"], "code": code_at(secret, clock)})
    assert r.status_code == 200, r.text
    assert r.json()["csrf_token"] and r.json()["user"]["mfa_enabled"] is True
    b.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    assert b.get("/api/auth/me").status_code == 200
    assert b.post("/api/auth/logout").status_code == 204
    # the challenge is single use
    clock.advance()
    again = b.post("/api/auth/login/mfa", json={"mfa_token": body["mfa_token"], "code": code_at(secret, clock)})
    assert again.status_code == 401
    success = audit_rows("login_success")[-1]
    assert success.detail == {"method": "password", "mfa": "totp"}
    assert "mfa_challenge_issued" in audit_actions() and "mfa_failure" in audit_actions()


def test_totp_code_cannot_be_reused(client, clock):
    secret, _ = enable_mfa(client, clock)
    b = new_browser(client)
    # the code used for enabling is burnt
    assert mfa_login(b, code_at(secret, clock)).status_code == 401
    # a fresh code works once ...
    code = code_at(secret, clock, 1)
    assert mfa_login(b, code).status_code == 200
    # ... and never again, nor does an older one
    assert mfa_login(new_browser(client), code).status_code == 401
    assert mfa_login(new_browser(client), code_at(secret, clock, -1)).status_code == 401
    clock.advance(2)
    assert mfa_login(new_browser(client), code_at(secret, clock)).status_code == 200


def test_clock_drift_window(client, clock):
    secret, _ = enable_mfa(client, clock)
    clock.advance(5)
    assert mfa_login(new_browser(client), code_at(secret, clock, -2)).status_code == 401  # too old
    assert mfa_login(new_browser(client), code_at(secret, clock, 2)).status_code == 401  # too far ahead
    assert mfa_login(new_browser(client), code_at(secret, clock, 1)).status_code == 200  # one step of drift


def test_recovery_codes_are_single_use(client, clock):
    _, codes = enable_mfa(client, clock)
    r = mfa_login(new_browser(client), codes[0].upper().replace("-", " "))  # formatting is forgiving
    assert r.status_code == 200, r.text
    assert mfa_login(new_browser(client), codes[0]).status_code == 401
    assert client.get("/api/auth/mfa").json()["recovery_codes_remaining"] == 9
    used = audit_rows("mfa_recovery_code_used")
    assert len(used) == 1 and used[0].detail["remaining"] == 9
    assert audit_rows("login_success")[-1].detail["mfa"] == "recovery_code"


def test_wrong_codes_lock_the_account(client, clock, monkeypatch):
    secret, _ = enable_mfa(client, clock)
    monkeypatch.setattr(config.settings, "login_max_failures", 4)
    b = new_browser(client)
    token = password_step(b)["mfa_token"]
    for _ in range(2):
        assert b.post("/api/auth/login/mfa", json={"mfa_token": token, "code": "000000"}).status_code == 401
    # A correct password must not reset the counter while MFA is pending.
    token = password_step(b)["mfa_token"]
    for _ in range(2):
        assert b.post("/api/auth/login/mfa", json={"mfa_token": token, "code": "999999"}).status_code == 401
    with db.get_session() as s:
        assert s.scalar(select(User).where(User.email == ADMIN_EMAIL)).locked_until is not None
    clock.advance()
    r = b.post("/api/auth/login/mfa", json={"mfa_token": token, "code": code_at(secret, clock)})
    assert r.status_code == 401
    locked = b.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert locked.status_code == 401
    assert any("locked_until" in a.detail for a in audit_rows("mfa_failure"))


def test_challenge_attempt_limit_and_expiry(client, clock, monkeypatch):
    secret, _ = enable_mfa(client, clock)
    monkeypatch.setattr(config.settings, "mfa_challenge_max_attempts", 2)
    b = new_browser(client)
    token = password_step(b)["mfa_token"]
    for _ in range(2):
        b.post("/api/auth/login/mfa", json={"mfa_token": token, "code": "000000"})
    clock.advance()
    r = b.post("/api/auth/login/mfa", json={"mfa_token": token, "code": code_at(secret, clock)})
    assert r.status_code == 401 and "sign in again" in r.json()["detail"]

    token = password_step(b)["mfa_token"]
    with db.get_session() as s:
        for ch in s.scalars(select(MfaChallenge)):
            ch.expires_at = utcnow() - timedelta(seconds=1)
        s.commit()
    assert b.post("/api/auth/login/mfa", json={"mfa_token": token, "code": code_at(secret, clock)}).status_code == 401


def test_mfa_endpoint_is_rate_limited(client, clock, monkeypatch):
    enable_mfa(client, clock)
    b = new_browser(client)
    token = password_step(b)["mfa_token"]
    monkeypatch.setattr(config.settings, "login_rate_limit", 2)
    codes = [b.post("/api/auth/login/mfa", json={"mfa_token": token, "code": "000000"}).status_code
             for _ in range(3)]
    assert codes[-1] == 429


def test_mfa_login_requires_json(client, clock):
    enable_mfa(client, clock)
    b = new_browser(client)
    token = password_step(b)["mfa_token"]
    r = b.post("/api/auth/login/mfa", content=f"mfa_token={token}&code=1",
               headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code in (415, 422)


# --- self-service disable / regenerate ---------------------------------------------------

def test_disable_requires_password_and_code(client, clock):
    secret, codes = enable_mfa(client, clock)
    other = new_browser(client)
    clock.advance()
    assert mfa_login(other, code_at(secret, clock)).status_code == 200
    clock.advance()
    good = code_at(secret, clock)
    assert client.post("/api/auth/mfa/totp/disable", json={"password": "wrong-password!", "code": good}
                       ).status_code == 400
    assert client.post("/api/auth/mfa/totp/disable", json={"code": good}).status_code == 400
    assert client.post("/api/auth/mfa/totp/disable", json={"password": ADMIN_PASSWORD, "code": "000000"}
                       ).status_code == 400
    r = client.post("/api/auth/mfa/totp/disable", json={"password": ADMIN_PASSWORD, "code": good})
    assert r.status_code == 204
    assert client.get("/api/auth/mfa").json()["enabled"] is False
    assert other.get("/api/auth/me").status_code == 401  # other sessions signed out
    assert "cnapp_session" in client.cookies and client.get("/api/auth/me").status_code == 200
    # plain password login again
    assert password_step(new_browser(client)).get("csrf_token")
    with db.get_session() as s:
        assert s.scalar(select(MfaRecoveryCode)) is None
    assert audit_rows("mfa_disabled")[0].detail["verified_with"] == "totp"
    assert "mfa_disable_failure" in audit_actions()


def test_disable_with_recovery_code(client, clock):
    _, codes = enable_mfa(client, clock)
    r = client.post("/api/auth/mfa/totp/disable", json={"password": ADMIN_PASSWORD, "code": codes[3]})
    assert r.status_code == 204


def test_regenerate_recovery_codes(client, clock):
    secret, old = enable_mfa(client, clock)
    clock.advance()
    r = client.post("/api/auth/mfa/recovery-codes", json={"password": "nope-nope-nope", "code": code_at(secret, clock)})
    assert r.status_code == 400
    r = client.post("/api/auth/mfa/recovery-codes", json={"password": ADMIN_PASSWORD, "code": code_at(secret, clock)})
    assert r.status_code == 200
    new = r.json()["recovery_codes"]
    assert len(new) == 10 and not set(new) & set(old)
    assert mfa_login(new_browser(client), old[1]).status_code == 401
    assert mfa_login(new_browser(client), new[1]).status_code == 200
    assert "mfa_recovery_codes_regenerated" in audit_actions()


def test_manage_requires_csrf(client, clock):
    secret, _ = enable_mfa(client, clock)
    del client.headers["X-CSRF-Token"]
    r = client.post("/api/auth/mfa/totp/disable", json={"password": ADMIN_PASSWORD, "code": code_at(secret, clock, 1)})
    assert r.status_code == 403


# --- forced enrolment (MFA_REQUIRED_ROLES) -----------------------------------------------

def test_forced_enrolment(client, clock, monkeypatch):
    make_user(client, "analyst")
    make_user(client, "viewer")
    monkeypatch.setattr(config.settings, "mfa_required_roles", ["admin", "analyst"])
    # viewer: not required
    assert "csrf_token" in password_step(new_browser(client), "viewer@example.com", USER_PW)

    b = new_browser(client)
    body = password_step(b, "analyst@example.com", USER_PW)
    assert body["purpose"] == "enroll" and "cnapp_session" not in b.cookies
    token = body["mfa_token"]
    # the enrolment token cannot be used as a verify token
    assert b.post("/api/auth/login/mfa", json={"mfa_token": token, "code": "123456"}).status_code == 401
    assert b.post("/api/auth/login/mfa/enroll/confirm", json={"mfa_token": token, "code": "123456"}
                  ).status_code == 409
    setup = b.post("/api/auth/login/mfa/enroll/start", json={"mfa_token": token}).json()
    secret = setup["secret"]
    assert setup["qr_svg"].startswith("data:image/svg+xml")
    assert b.post("/api/auth/login/mfa/enroll/confirm", json={"mfa_token": token, "code": "000000"}
                  ).status_code == 400
    r = b.post("/api/auth/login/mfa/enroll/confirm", json={"mfa_token": token, "code": code_at(secret, clock)})
    assert r.status_code == 200, r.text
    assert len(r.json()["recovery_codes"]) == 10 and r.json()["user"]["mfa_enabled"]
    b.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    st = b.get("/api/auth/mfa").json()
    assert st["enabled"] and st["required"]
    # required: cannot be switched off
    clock.advance()
    assert b.post("/api/auth/mfa/totp/disable", json={"password": USER_PW, "code": code_at(secret, clock)}
                  ).status_code == 409
    # next login asks for a code
    clock.advance()
    assert mfa_login(new_browser(client), code_at(secret, clock), "analyst@example.com", USER_PW).status_code == 200
    actions = audit_actions()
    assert "mfa_enrollment_required" in actions and "mfa_enabled" in actions
    assert any(a.detail.get("forced") for a in audit_rows("mfa_enabled"))


def test_unknown_required_role_refuses_to_start(monkeypatch):
    monkeypatch.setenv("MFA_REQUIRED_ROLES", "admin,superuser")
    config.reload_settings()
    try:
        from app.main import create_app

        with pytest.raises(RuntimeError, match="MFA_REQUIRED_ROLES"):
            create_app()
    finally:
        monkeypatch.delenv("MFA_REQUIRED_ROLES")
        config.reload_settings()


# --- admin -------------------------------------------------------------------------------

def test_admin_reset_mfa(client, clock):
    analyst = make_user(client, "analyst")
    a = new_browser(client)
    login(a, "analyst@example.com", USER_PW)
    secret, _ = enable_mfa(a, clock)
    users = {u["email"]: u for u in client.get("/api/users").json()}
    assert users["analyst@example.com"]["mfa_enabled"] is True
    assert users["analyst@example.com"]["auth_sources"] == ["password"]

    # not for non-admins
    assert a.post(f"/api/users/{analyst['id']}/reset-mfa").status_code == 403
    r = client.post(f"/api/users/{analyst['id']}/reset-mfa")
    assert r.status_code == 200 and r.json()["mfa_enabled"] is False
    assert a.get("/api/auth/me").status_code == 401  # signed out
    assert "csrf_token" in password_step(new_browser(client), "analyst@example.com", USER_PW)
    entry = audit_rows("mfa_reset")[0]
    assert entry.actor_email == ADMIN_EMAIL and entry.target == "analyst@example.com" and entry.detail["had_mfa"]
    assert client.post("/api/users/nope/reset-mfa").status_code == 404


# --- crypto --------------------------------------------------------------------------------

def test_encryption_key_rotation(monkeypatch):
    monkeypatch.setattr(config.settings, "mfa_encryption_keys", ["a" * 40])
    token = mfa.encrypt_secret("JBSWY3DPEHPK3PXP")
    monkeypatch.setattr(config.settings, "mfa_encryption_keys", ["b" * 40, "a" * 40])
    assert mfa.decrypt_secret(token) == "JBSWY3DPEHPK3PXP"
    monkeypatch.setattr(config.settings, "mfa_encryption_keys", ["b" * 40])
    with pytest.raises(mfa.MfaError):
        mfa.decrypt_secret(token)


def test_match_totp_step_rejects_garbage():
    secret = mfa.new_secret()
    assert mfa.match_totp_step(secret, "") is None
    assert mfa.match_totp_step(secret, "abcdef") is None
    assert mfa.match_totp_step(secret, "1234567") is None
    now = time.time()
    assert mfa.match_totp_step(secret, pyotp.TOTP(secret).at(now), now) == int(now // 30)
