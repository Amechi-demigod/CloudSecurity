"""The "Getting started" checklist of a new organisation
(GET /api/organization/onboarding, POST /api/organization/onboarding/dismiss):
each step's detection from the organisation's own data, isolation from other
organisations (the default one has plenty of data) and who may dismiss it."""
from __future__ import annotations

import secrets
from datetime import timedelta

from sqlalchemy import select

from app import auth, db, tenancy
from app.models import (
    AuditLog,
    ConnectorConfig,
    Device,
    OrganizationInvitation,
    ScanRun,
    User,
    UserMfa,
    utcnow,
)
from app.notifications.models import NotificationChannel
from tests.test_devices import new_token
from tests.test_tenancy import ACME_ADMIN, create_org, org_client, tenants  # noqa: F401 - fixture

STEPS = ["mfa", "team", "cloud", "agent", "scan", "alerts"]


def progress(c) -> dict:
    r = c.get("/api/organization/onboarding")
    assert r.status_code == 200, r.text
    return r.json()


def done(c) -> dict[str, bool]:
    body = progress(c)
    assert [s["key"] for s in body["steps"]] == STEPS
    assert body["total"] == len(STEPS) and body["completed"] == sum(s["done"] for s in body["steps"])
    return {s["key"]: s["done"] for s in body["steps"]}


def add(org_id: str, *rows) -> None:
    with db.get_session(org_id) as s:
        s.add_all(rows)
        s.commit()


def add_member(org_id: str, email: str, role: str, password: str = "a-long-member-password") -> None:
    with db.get_session(org_id) as s:
        u = User(email=email, name=email.split("@")[0], password_hash=auth.hash_password(password),
                 password_changed_at=utcnow())
        s.add(u)
        s.flush()
        auth.set_membership(s, u, org_id, role)
        s.commit()


def enable_mfa(email: str) -> None:
    with db.get_session(unscoped=True) as s:
        user = s.scalar(select(User).where(User.email == email))
        s.add(UserMfa(user_id=user.id, totp_secret_enc="x", enabled_at=utcnow()))
        s.commit()


def invitation(**kw) -> OrganizationInvitation:
    return OrganizationInvitation(email=f"{secrets.token_hex(4)}@acme.test", role="viewer",
                                  token_hash=secrets.token_hex(32), expires_at=utcnow() + timedelta(days=1), **kw)


def test_new_organisation_starts_with_nothing_done(tenants):  # noqa: F811
    body = progress(tenants.acme)
    assert body["completed"] == 0 and body["total"] == 6
    assert body["is_default"] is False and body["dismissed"] is False
    assert progress(tenants.default)["is_default"] is True


def test_each_step_is_detected(tenants):  # noqa: F811
    t, oid = tenants, tenants.acme_id

    enable_mfa(ACME_ADMIN)
    assert done(t.acme)["mfa"] is True

    # Expired and revoked invitations do not count; an open one does.
    add(oid, invitation(revoked_at=utcnow()))
    add(oid, OrganizationInvitation(email="old@acme.test", role="viewer", token_hash=secrets.token_hex(32),
                                    expires_at=utcnow() - timedelta(hours=1)))
    assert done(t.acme)["team"] is False
    add(oid, invitation())
    assert done(t.acme)["team"] is True

    # A disabled connector is not "connected".
    add(oid, ConnectorConfig(provider="aws", enabled=False, config={}, secret_hints={}))
    assert done(t.acme)["cloud"] is False
    add(oid, ConnectorConfig(provider="gcp", enabled=True, config={"project_ids": ["p"]}, secret_hints={}))
    assert done(t.acme)["cloud"] is True

    # An enrollment token alone, or a revoked device, does not count.
    new_token(t.acme)
    add(oid, Device(hostname="OLD", os_family="windows", status="revoked"))
    assert done(t.acme)["agent"] is False
    add(oid, Device(hostname="ACME-LAPTOP", os_family="windows"))
    assert done(t.acme)["agent"] is True

    add(oid, ScanRun(connector="aws", status="running"), ScanRun(connector="aws", status="failed"))
    assert done(t.acme)["scan"] is False
    add(oid, ScanRun(connector="aws", status="succeeded", finished_at=utcnow()))
    assert done(t.acme)["scan"] is True

    add(oid, NotificationChannel(name="off", type="slack", enabled=False))
    assert done(t.acme)["alerts"] is False
    add(oid, NotificationChannel(name="SOC", type="slack"))
    assert all(done(t.acme).values())
    assert progress(t.acme)["completed"] == 6


def test_another_member_completes_the_team_step(tenants):  # noqa: F811
    add_member(tenants.acme_id, "viewer@acme.test", "viewer")
    assert done(tenants.acme)["team"] is True


def test_mfa_step_is_the_signed_in_users(tenants):  # noqa: F811
    add_member(tenants.acme_id, "analyst@acme.test", "analyst")
    analyst = org_client(tenants.acme.app, "analyst@acme.test", "a-long-member-password")
    enable_mfa(ACME_ADMIN)
    assert done(tenants.acme)["mfa"] is True
    assert done(analyst)["mfa"] is False


def test_other_organisations_data_never_marks_a_step_done(tenants):  # noqa: F811
    # The default organisation has simulated scans and assets; give it one of everything else too.
    add(tenancy.DEFAULT_ORG_ID, invitation(), Device(hostname="DEFAULT-PC", os_family="windows"),
        ConnectorConfig(provider="aws", enabled=True, config={}, secret_hints={}),
        ScanRun(connector="aws", status="succeeded"), NotificationChannel(name="ops", type="slack"))
    add_member(tenancy.DEFAULT_ORG_ID, "someone@example.com", "viewer")
    enable_mfa("admin@example.com")
    # A third organisation with data of its own.
    other = create_org("globex", "admin@globex.test", "globex-admin-password")
    add(other, invitation(), Device(hostname="GLOBEX-PC", os_family="linux"),
        ScanRun(connector="gcp", status="succeeded"), NotificationChannel(name="ops", type="email"))
    globex = org_client(tenants.acme.app, "admin@globex.test", "globex-admin-password")
    enable_mfa("admin@globex.test")  # after signing in (no MFA challenge in the test)

    assert done(tenants.acme) == dict.fromkeys(STEPS, False)
    assert done(globex) == {"mfa": True, "team": True, "cloud": False, "agent": True, "scan": True, "alerts": True}


def test_only_admins_dismiss(tenants):  # noqa: F811
    oid = tenants.acme_id
    add_member(oid, "viewer@acme.test", "viewer")
    add_member(oid, "analyst@acme.test", "analyst")
    viewer = org_client(tenants.acme.app, "viewer@acme.test", "a-long-member-password")
    analyst = org_client(tenants.acme.app, "analyst@acme.test", "a-long-member-password")

    for c in (viewer, analyst):
        assert progress(c)["dismissed"] is False  # everyone sees the progress
        assert c.post("/api/organization/onboarding/dismiss").status_code == 403
    assert progress(tenants.acme)["dismissed"] is False

    r = tenants.acme.post("/api/organization/onboarding/dismiss")
    assert r.status_code == 200, r.text
    assert r.json()["dismissed"] is True and r.json()["dismissed_by"] == ACME_ADMIN
    assert progress(viewer)["dismissed"] is True  # for the whole organisation
    # Idempotent: a second dismiss keeps the first record and audits nothing new.
    assert tenants.acme.post("/api/organization/onboarding/dismiss").json()["dismissed_at"] == r.json()["dismissed_at"]
    with db.get_session(oid) as s:
        rows = s.scalars(select(AuditLog).where(AuditLog.action == "onboarding_dismissed")).all()
        assert [(a.actor_email, a.target) for a in rows] == [(ACME_ADMIN, "organization:acme")]
    # Another organisation's checklist is untouched.
    assert progress(tenants.default)["dismissed"] is False
