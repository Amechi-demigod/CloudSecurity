"""Invite-only onboarding and the platform console: a platform owner creates an
organisation and invites its first admin, who accepts the single-use link and
invites teammates; suspension; email (faked) or copy-the-link."""
from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app import config, db
from app.models import AuditLog, OrganizationInvitation, User
from app.notifications import channels
from tests.conftest import ADMIN_EMAIL, BASE_URL, login


def token_of(url: str) -> str:
    assert "/invite#token=" in url
    return url.split("#token=", 1)[1]


def new_client(app) -> TestClient:
    return TestClient(app, base_url=BASE_URL)


@pytest.fixture()
def platform(client):
    """The bootstrap admin, made a platform owner."""
    with db.get_session(unscoped=True) as s:
        s.execute(update(User).where(User.email == ADMIN_EMAIL).values(is_platform_admin=True))
        s.commit()
    return client


def create_org(c, name="Acme Ltd", admin_email="boss@acme.test", **kw):
    r = c.post("/api/platform/organizations", json={"name": name, "admin_email": admin_email, **kw})
    assert r.status_code == 201, r.text
    return r.json()


def accept(app, token, password="boss-password-123", name="Boss"):
    c = new_client(app)
    r = c.post("/api/invitations/accept", json={"token": token, "name": name, "password": password})
    return c, r


def test_platform_console_requires_platform_owner(client):
    assert client.get("/api/platform/organizations").status_code == 403
    assert client.post("/api/platform/organizations", json={"name": "X", "admin_email": "a@x.test"}).status_code == 403
    assert client.get("/api/auth/me").json()["platform_admin"] is False


def test_create_organisation_and_accept_the_invitation(platform):
    created = create_org(platform, contact_email="Billing@Acme.test")
    org = created["organization"]
    assert org["slug"] == "acme-ltd" and org["status"] == "active" and org["contact_email"] == "billing@acme.test"
    inv = created["invitation"]
    # No platform mail server in tests: the link is handed to the inviter.
    assert inv["emailed"] is False and inv["invitation"]["role"] == "admin" and inv["invitation"]["state"] == "pending"
    token = token_of(inv["invite_url"])
    with db.get_session(unscoped=True) as s:
        row = s.scalar(select(OrganizationInvitation))
        assert row.token_hash != token and token not in row.token_hash  # only a hash is stored

    anon = new_client(platform.app)
    info = anon.post("/api/invitations/lookup", json={"token": token}).json()
    assert info == {"organization": "Acme Ltd", "email": "boss@acme.test", "role": "admin",
                    "expires_at": info["expires_at"], "sso_available": False}
    assert anon.post("/api/invitations/accept", json={"token": token, "password": "short"}).status_code == 422
    boss, r = accept(platform.app, token)
    assert r.status_code == 200, r.text
    me = r.json()
    assert me["organization"]["id"] == org["id"] and me["user"]["role"] == "admin" and me["user"]["name"] == "Boss"
    boss.headers["X-CSRF-Token"] = me["csrf_token"]
    assert boss.get("/api/organization").json()["name"] == "Acme Ltd"
    assert [u["email"] for u in boss.get("/api/users").json()] == ["boss@acme.test"]
    # Single use.
    assert accept(platform.app, token)[1].status_code == 410
    assert anon.post("/api/invitations/lookup", json={"token": token}).status_code == 410
    # Normal password sign-in works afterwards.
    login(new_client(platform.app), "boss@acme.test", "boss-password-123")
    # Console view: usage, members, the accepted invitation; audited in the new organisation.
    detail = platform.get(f"/api/platform/organizations/{org['id']}").json()
    assert [m["email"] for m in detail["members"]] == ["boss@acme.test"]
    assert detail["usage"]["users"] == 1 and detail["invitations"][0]["state"] == "accepted"
    listed = {o["slug"]: o for o in platform.get("/api/platform/organizations").json()}
    assert set(listed) == {"default", "acme-ltd"} and listed["default"]["is_default"]
    with db.get_session(unscoped=True) as s:
        actions = {a.action for a in s.scalars(select(AuditLog).where(AuditLog.organization_id == org["id"]))}
    assert {"organization_created", "invitation_accepted", "login_success"} <= actions


@pytest.fixture()
def outbox(monkeypatch):
    """Platform mail configured, delivery faked: [(cfg, secrets, (subject, text, html))]."""
    sent = []

    def fake_send(ctype, cfg, secrets, msg, delivery_id, *, rendered=None):
        assert ctype == "email" and rendered is not None
        sent.append((cfg, secrets, rendered))
        return channels.SendResult(250, "accepted")

    monkeypatch.setattr(channels, "send", fake_send)
    env = {"PLATFORM_SMTP_HOST": "smtp.example.com", "PLATFORM_SMTP_FROM": "Acme Security <no-reply@example.com>",
           "PLATFORM_SMTP_USERNAME": "mailer", "PLATFORM_SMTP_PASSWORD": "smtp-pass",
           "PUBLIC_BASE_URL": "https://cnapp.example.com", "BRAND_NAME": "Acme Security"}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    config.reload_settings()
    yield sent
    for k in env:
        monkeypatch.delenv(k)
    config.reload_settings()


def link_of(text: str) -> str:
    return next(w for w in text.split() if "/invite#token=" in w)


def test_invitation_email_is_sent_when_mail_is_configured(platform, outbox):
    assert platform.get("/api/platform/mail").json() == {"configured": True}
    inv = create_org(platform)["invitation"]
    assert inv["emailed"] is True and inv["invite_url"] is None
    cfg, secrets, (subject, text, body_html) = outbox[0]
    assert cfg["to_addresses"] == ["boss@acme.test"] and cfg["host"] == "smtp.example.com"
    assert secrets == {"password": "smtp-pass"}
    # Platform variant: a transactional email from the brand, not an alert, and no person named.
    assert subject == "You've been invited to join Acme Ltd on Acme Security"
    assert "[CNAPP]" not in subject and "INFO" not in subject
    link = link_of(text)
    assert link.startswith("https://cnapp.example.com/invite#token=cnv_")
    assert "Acme Security invited you as admin to join Acme Ltd." in text
    assert f'href="{link}"' in body_html and "Accept invitation" in body_html
    assert "expires in 72 hours" in text and "ignore this email" in text and "please don't reply" in text
    for part in (text, body_html):
        assert ADMIN_EMAIL not in part and "severity" not in part.lower() and "notifications" not in part
    # The emailed link works.
    boss, r = accept(platform.app, token_of(link))
    assert r.status_code == 200

    # Organisation variant: the org admin invites a teammate; the email names them.
    boss.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    assert boss.post("/api/organization/invitations", json={"email": "ann@acme.test", "role": "analyst"}).json()[
        "emailed"] is True
    cfg, _, (subject, text, body_html) = outbox[1]
    assert cfg["to_addresses"] == ["ann@acme.test"]
    assert subject == "You have been invited to join Acme Ltd on Acme Security"
    assert "Boss (boss@acme.test) invited you as analyst to join Acme Ltd on Acme Security." in text
    assert "Boss (boss@acme.test)" in body_html and "[CNAPP]" not in subject
    assert accept(platform.app, token_of(link_of(text)), password="ann-password-1234", name="Ann")[1].status_code == 200


def test_org_admin_invites_teammates(platform):
    created = create_org(platform)
    boss, r = accept(platform.app, token_of(created["invitation"]["invite_url"]))
    boss.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    r = boss.post("/api/organization/invitations", json={"email": "Ann@Acme.test", "role": "analyst"})
    assert r.status_code == 201, r.text
    first = r.json()
    assert first["invitation"]["email"] == "ann@acme.test" and first["invite_url"]
    # Resend: a new link, the old one stops working.
    again = boss.post(f"/api/organization/invitations/{first['invitation']['id']}/resend").json()
    old, new = token_of(first["invite_url"]), token_of(again["invite_url"])
    assert old != new and again["invitation"]["sent_count"] == 2
    assert accept(platform.app, old)[1].status_code == 410
    ann, r = accept(platform.app, new, password="ann-password-1234", name="Ann")
    assert r.status_code == 200 and r.json()["user"]["role"] == "analyst"
    # An analyst cannot invite.
    ann.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    assert ann.post("/api/organization/invitations", json={"email": "x@acme.test"}).status_code == 403
    # Existing accounts (any organisation) cannot be invited: one organisation per account.
    assert boss.post("/api/organization/invitations", json={"email": ADMIN_EMAIL}).status_code == 409
    assert boss.post("/api/organization/invitations", json={"email": "ann@acme.test"}).status_code == 409
    # Revoked and expired invitations cannot be used.
    rv = boss.post("/api/organization/invitations", json={"email": "rev@acme.test"}).json()
    assert boss.delete(f"/api/organization/invitations/{rv['invitation']['id']}").json()["state"] == "revoked"
    assert accept(platform.app, token_of(rv["invite_url"]))[1].status_code == 410
    ex = boss.post("/api/organization/invitations", json={"email": "late@acme.test"}).json()
    with db.get_session(unscoped=True) as s:
        row = s.get(OrganizationInvitation, ex["invitation"]["id"])
        row.expires_at = row.created_at - timedelta(minutes=1)
        s.commit()
    assert accept(platform.app, token_of(ex["invite_url"]))[1].status_code == 410
    states = {i["email"]: i["state"] for i in boss.get("/api/organization/invitations").json()}
    assert states == {"ann@acme.test": "accepted", "rev@acme.test": "revoked", "late@acme.test": "expired",
                      "boss@acme.test": "accepted"}
    # The default organisation's admins see none of this.
    assert platform.get("/api/organization/invitations").json() == []
    assert boss.post(f"/api/organization/invitations/{ex['invitation']['id']}/resend").status_code == 200
    assert platform.post(f"/api/organization/invitations/{ex['invitation']['id']}/resend").status_code == 404
    assert platform.delete(f"/api/organization/invitations/{ex['invitation']['id']}").status_code == 404


def test_suspend_and_reactivate(platform):
    created = create_org(platform)
    oid = created["organization"]["id"]
    boss, r = accept(platform.app, token_of(created["invitation"]["invite_url"]))
    boss.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    assert platform.post("/api/platform/organizations/default/suspend", json={}).status_code == 409
    r = platform.post(f"/api/platform/organizations/{oid}/suspend", json={"reason": "contract ended"})
    assert r.status_code == 200 and r.json()["status"] == "suspended"
    assert boss.get("/api/organization").status_code == 401
    assert new_client(platform.app).post("/api/auth/login", json={"email": "boss@acme.test",
                                                                  "password": "boss-password-123"}).status_code == 403
    assert platform.post(f"/api/platform/organizations/{oid}/invitations",
                         json={"email": "new@acme.test"}).status_code == 409
    assert platform.post(f"/api/platform/organizations/{oid}/activate", json={}).json()["status"] == "active"
    login(new_client(platform.app), "boss@acme.test", "boss-password-123")


def test_platform_validation_and_updates(platform):
    create_org(platform, slug="acme")
    assert platform.post("/api/platform/organizations",
                         json={"name": "Other", "slug": "acme", "admin_email": "o@o.test"}).status_code == 409
    assert platform.post("/api/platform/organizations",
                         json={"name": "Bad", "slug": "-bad-", "admin_email": "o@o.test"}).status_code == 422
    assert platform.post("/api/platform/organizations",
                         json={"name": "Dup", "admin_email": ADMIN_EMAIL}).status_code == 409
    orgs = {o["slug"]: o for o in platform.get("/api/platform/organizations").json()}
    assert "bad" not in orgs and "dup" not in orgs  # rolled back
    oid = orgs["acme"]["id"]
    r = platform.patch(f"/api/platform/organizations/{oid}", json={"name": "Acme Group", "plan": "pro",
                                                                   "max_users": 25})
    assert r.status_code == 200 and r.json()["name"] == "Acme Group" and r.json()["max_users"] == 25
    assert platform.get("/api/platform/organizations/nope").status_code == 404


def test_invited_role_that_requires_mfa_signs_in_normally(platform, monkeypatch):
    monkeypatch.setattr(config.settings, "mfa_required_roles", ["admin"])
    created = create_org(platform)
    c, r = accept(platform.app, token_of(created["invitation"]["invite_url"]))
    assert r.status_code == 200 and r.json() == {"sign_in_required": True, "email": "boss@acme.test",
                                                 "reason": "mfa_enrollment_required"}
    assert c.get("/api/auth/me").status_code == 401
    r = new_client(platform.app).post("/api/auth/login", json={"email": "boss@acme.test",
                                                               "password": "boss-password-123"})
    assert r.status_code == 200 and r.json()["purpose"] == "enroll"


def test_org_admin_edits_profile(platform):
    created = create_org(platform)
    boss, r = accept(platform.app, token_of(created["invitation"]["invite_url"]))
    boss.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    r = boss.patch("/api/organization", json={"name": "Acme Holdings", "logo_url": "https://cdn.acme.test/logo.png"})
    assert r.status_code == 200 and r.json()["name"] == "Acme Holdings"
    assert boss.patch("/api/organization", json={"logo_url": "javascript:alert(1)"}).status_code == 422
    assert platform.get("/api/organization").json()["name"] != "Acme Holdings"
