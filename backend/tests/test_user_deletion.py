"""Permanent deletion of deactivated user accounts (DELETE /api/users/{id} and
`python -m app.cli delete-user`). Runs on SQLite and PostgreSQL."""
from __future__ import annotations

import io
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from app import config, db
from app.models import (
    AuditLog,
    MfaChallenge,
    MfaRecoveryCode,
    OrganizationInvitation,
    OrganizationMembership,
    User,
    UserIdentity,
    UserMfa,
    UserSession,
    utcnow,
)
from tests.conftest import BASE_URL, login, make_user
from tests.test_invitations import accept, token_of
from tests.test_tenancy import ACME_ADMIN, ACME_PASSWORD, create_org, org_client

PASSWORD = "a-long-test-password"


def new_client(app) -> TestClient:
    return TestClient(app, base_url=BASE_URL)


def deactivate(c: TestClient, user_id: str) -> None:
    r = c.patch(f"/api/users/{user_id}", json={"is_active": False})
    assert r.status_code == 200, r.text


def count(model, *where) -> int:
    with db.get_session(unscoped=True) as s:
        return s.scalar(select(func.count()).select_from(model).where(*where)) or 0


def test_delete_deactivated_user_removes_account_and_keeps_history(client):
    u = make_user(client, "analyst", email="gone@example.com")
    uid = u["id"]
    login(new_client(client.app), "gone@example.com", PASSWORD)  # a session row
    now = utcnow()
    with db.get_session(unscoped=True) as s:  # MFA, SSO link, an open challenge, a pending invitation
        s.add(UserMfa(user_id=uid, totp_secret_enc="x", enabled_at=now))
        s.add(MfaRecoveryCode(user_id=uid, code_hash="a" * 64))
        s.add(MfaChallenge(id="c" * 64, user_id=uid, purpose="verify", expires_at=now + timedelta(minutes=5)))
        s.add(UserIdentity(user_id=uid, provider="entra", tenant_id="t", subject="oid-1", email="gone@example.com"))
        s.add(OrganizationInvitation(organization_id="default", email="gone@example.com", role="viewer",
                                     token_hash="b" * 64, expires_at=now + timedelta(days=1)))
        s.commit()

    # Still active: refused, nothing removed.
    r = client.delete(f"/api/users/{uid}")
    assert r.status_code == 409 and "deactivate" in r.json()["detail"]
    assert count(User, User.id == uid) == 1

    deactivate(client, uid)
    assert client.delete(f"/api/users/{uid}").status_code == 204
    assert client.delete(f"/api/users/{uid}").status_code == 404
    assert "gone@example.com" not in {x["email"] for x in client.get("/api/users").json()}
    assert count(User, User.id == uid) == 0
    for model in (OrganizationMembership, UserSession, UserMfa, MfaRecoveryCode, MfaChallenge, UserIdentity):
        assert count(model, model.user_id == uid) == 0, model.__name__
    assert count(OrganizationInvitation, OrganizationInvitation.email == "gone@example.com") == 0

    # History stays as it was, and the deletion is audited.
    with db.get_session(unscoped=True) as s:
        rows = list(s.scalars(select(AuditLog).where(AuditLog.target == "gone@example.com")))
        assert {"user_created", "user_updated", "user_deleted"} <= {a.action for a in rows}
        deleted = next(a for a in rows if a.action == "user_deleted")
        assert deleted.actor_email == "admin@example.com" and deleted.organization_id == "default"
        assert deleted.detail["role"] == "analyst" and deleted.detail["removed"]["users"] == 1
        assert s.scalar(select(func.count()).select_from(AuditLog).where(
            AuditLog.actor_id == uid, AuditLog.action == "login_success")) == 1

    # The address can be invited again, and the invitation accepted.
    r = client.post("/api/organization/invitations", json={"email": "gone@example.com", "role": "viewer"})
    assert r.status_code == 201, r.text
    back, r = accept(client.app, token_of(r.json()["invite_url"]), password="new-password-1234", name="Back")
    assert r.status_code == 200, r.text
    assert r.json()["user"]["id"] != uid and r.json()["user"]["role"] == "viewer"


def test_delete_refusals(client, monkeypatch):
    me = client.get("/api/auth/me").json()["user"]
    r = client.delete(f"/api/users/{me['id']}")
    assert r.status_code == 409 and "own account" in r.json()["detail"]

    owner = make_user(client, "viewer", email="owner@example.com")
    deactivate(client, owner["id"])
    with db.get_session(unscoped=True) as s:
        s.execute(update(User).where(User.id == owner["id"]).values(is_platform_admin=True))
        s.commit()
    r = client.delete(f"/api/users/{owner['id']}")
    assert r.status_code == 409 and "platform owner" in r.json()["detail"]

    listed = make_user(client, "viewer", email="listed@example.com")
    deactivate(client, listed["id"])
    monkeypatch.setenv("PLATFORM_ADMIN_EMAILS", "listed@example.com")
    config.reload_settings()
    assert client.delete(f"/api/users/{listed['id']}").status_code == 409
    monkeypatch.delenv("PLATFORM_ADMIN_EMAILS")

    glass = make_user(client, "admin", email="glass@example.com")
    deactivate(client, glass["id"])
    monkeypatch.setenv("AUTH_BREAK_GLASS_EMAILS", "glass@example.com")
    config.reload_settings()
    try:
        r = client.delete(f"/api/users/{glass['id']}")
        assert r.status_code == 409 and "break-glass" in r.json()["detail"]
    finally:
        monkeypatch.delenv("AUTH_BREAK_GLASS_EMAILS")
        config.reload_settings()
    # Without the setting it can go (another active admin remains).
    assert client.delete(f"/api/users/{glass['id']}").status_code == 204
    assert count(User, User.id.in_([owner["id"], listed["id"]])) == 2
    assert client.delete("/api/users/nope").status_code == 404


def test_last_admin_cannot_be_deleted(client, monkeypatch, capsys):
    """Through the API the caller is always another active admin, so the rule is
    reachable from the CLI: an organisation whose only admin is deactivated."""
    from app import cli

    acme_id = create_org("acme", ACME_ADMIN, ACME_PASSWORD, name="Acme Ltd")
    with db.get_session(unscoped=True) as s:
        s.execute(update(User).where(User.email == ACME_ADMIN).values(is_active=False))
        s.commit()
    monkeypatch.setattr(db, "init_engine", lambda url, **kw: None)
    with pytest.raises(SystemExit, match="last admin"):
        cli.main(["delete-user", "--email", ACME_ADMIN, "--yes"])
    assert count(OrganizationMembership, OrganizationMembership.organization_id == acme_id) == 1


def test_other_organisation_and_roles(client):
    acme_id = create_org("acme", ACME_ADMIN, ACME_PASSWORD, name="Acme Ltd")
    acme = org_client(client.app, ACME_ADMIN, ACME_PASSWORD)
    other = make_user(acme, "viewer", email="v@acme.test")
    deactivate(acme, other["id"])
    # Another organisation's user is not found, and stays.
    assert client.delete(f"/api/users/{other['id']}").status_code == 404
    assert count(OrganizationMembership, OrganizationMembership.organization_id == acme_id,
                 OrganizationMembership.user_id == other["id"]) == 1

    target = make_user(client, "viewer", email="target@example.com")
    deactivate(client, target["id"])
    for role in ("viewer", "analyst"):
        make_user(client, role)
        c = new_client(client.app)
        login(c, f"{role}@example.com", PASSWORD)
        assert c.delete(f"/api/users/{target['id']}").status_code == 403
    assert count(User, User.id == target["id"]) == 1
    # Acme's own admin can delete it.
    assert acme.delete(f"/api/users/{other['id']}").status_code == 204
    assert count(User, User.id == other["id"]) == 0


def test_cli_delete_user(client, monkeypatch, capsys):
    from app import cli

    u = make_user(client, "viewer", email="cli-gone@example.com")
    monkeypatch.setattr(db, "init_engine", lambda url, **kw: None)
    with pytest.raises(SystemExit, match="deactivate"):
        cli.main(["delete-user", "--email", "cli-gone@example.com", "--yes"])
    deactivate(client, u["id"])
    monkeypatch.setattr("sys.stdin", io.StringIO("someone-else@example.com\n"))
    with pytest.raises(SystemExit, match="did not match"):
        cli.main(["delete-user", "--email", "cli-gone@example.com"])
    assert count(User, User.id == u["id"]) == 1
    monkeypatch.setattr("sys.stdin", io.StringIO("CLI-Gone@example.com\n"))
    assert cli.main(["delete-user", "--email", "cli-gone@example.com"]) == 0
    assert "Deleted user cli-gone@example.com" in capsys.readouterr().out
    assert count(User, User.id == u["id"]) == 0
    with db.get_session(unscoped=True) as s:
        a = s.scalar(select(AuditLog).where(AuditLog.action == "user_deleted"))
        assert a.actor_email == "cli" and a.target == "cli-gone@example.com"
    # Break-glass (ADMIN_EMAIL) is refused even when deactivated.
    with db.get_session(unscoped=True) as s:
        s.execute(update(User).where(User.email == "admin@example.com").values(is_active=False))
        s.commit()
    with pytest.raises(SystemExit, match="break-glass"):
        cli.main(["delete-user", "--email", "admin@example.com", "--yes"])
    with pytest.raises(SystemExit, match="no user"):
        cli.main(["delete-user", "--email", "nobody@example.com", "--yes"])
