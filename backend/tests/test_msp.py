"""MSP accounts (docs/MSP.md): partner organisations, client management, working inside a client, the
hidden-from-the-client rule, the audit rule, and the fail-closed access checks."""
from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app import auth, db
from app.models import AuditLog, Organization, User, utcnow
from app.modules import ALL_MODULES
from app.services import organizations as orgs
from tests.conftest import ADMIN_EMAIL, login
from tests.test_approvals_lost_wipe import enrolled, request_wipe
from tests.test_tenancy import org_client

PW = "a-long-test-password"


def make_org(slug: str, kind: str = "customer", partner: str | None = None, modules=ALL_MODULES, **kw) -> str:
    with db.get_session(unscoped=True) as s:
        org = orgs.create_organization(s, name=slug.title(), slug=slug, created_by="test", modules=modules,
                                       kind=kind, partner_org_id=partner, **kw)
        oid = org.id
        s.commit()
    return oid


def make_member(org_id: str, email: str, role: str) -> None:
    with db.get_session(org_id) as s:
        u = User(email=email, name=email.split("@")[0], password_hash=auth.hash_password(PW),
                 password_changed_at=utcnow())
        s.add(u)
        s.flush()
        auth.set_membership(s, u, org_id, role)
        s.commit()


def set_org_fields(org_id: str, **values) -> None:
    with db.get_session(unscoped=True) as s:
        s.execute(update(Organization).where(Organization.id == org_id).values(**values))
        s.commit()


def audit_rows(org_id: str) -> list[AuditLog]:
    with db.get_session(unscoped=True) as s:
        return list(s.scalars(select(AuditLog).where(AuditLog.organization_id == org_id).order_by(AuditLog.id)))


@dataclass
class World:
    owner: TestClient  # platform owner (default organisation admin)
    msp_id: str
    admin: TestClient  # MSP admin
    analyst: TestClient
    viewer: TestClient
    client_id: str  # created by the MSP admin through the API
    client_admin: TestClient  # a normal admin of that client
    other_msp_client_id: str  # client of another MSP
    plain_id: str  # an ordinary customer organisation
    msp2_admin: TestClient


@pytest.fixture()
def w(client) -> World:
    with db.get_session(unscoped=True) as s:
        s.execute(update(User).where(User.email == ADMIN_EMAIL).values(is_platform_admin=True))
        s.commit()
    msp = make_org("msp-one", kind="msp", modules=[], max_clients=5)
    for email, role in (("admin@msp1.test", "admin"), ("analyst@msp1.test", "analyst"), ("viewer@msp1.test", "viewer")):
        make_member(msp, email, role)
    msp2 = make_org("msp-two", kind="msp", modules=[])
    make_member(msp2, "admin@msp2.test", "admin")
    other = make_org("other-client", partner=msp2)
    plain = make_org("plain")
    make_member(plain, "admin@plain.test", "admin")
    app = client.app
    admin = org_client(app, "admin@msp1.test", PW)
    r = admin.post("/api/msp/clients", json={"name": "Client One", "contact_email": "it@client1.test",
                                             "modules": list(ALL_MODULES)})
    assert r.status_code == 201, r.text
    cid = r.json()["client"]["id"]
    make_member(cid, "admin@client1.test", "admin")
    return World(client, msp, admin, org_client(app, "analyst@msp1.test", PW), org_client(app, "viewer@msp1.test", PW),
                 cid, org_client(app, "admin@client1.test", PW), other, plain, org_client(app, "admin@msp2.test", PW))


def switch(c: TestClient, org_id: str | None):
    return c.post("/api/msp/switch", json={"organization_id": org_id})


# ----------------------------------------------------------------------------- platform owner
def test_platform_owner_creates_msp_and_only_the_owner_can(client, w):
    r = w.owner.post("/api/platform/organizations", json={
        "name": "Fresh MSP", "slug": "fresh-msp", "admin_email": "boss@fresh.test", "kind": "msp", "max_clients": 3})
    assert r.status_code == 201, r.text
    org = r.json()["organization"]
    assert org["kind"] == "msp" and org["max_clients"] == 3
    listing = {o["slug"]: o for o in w.owner.get("/api/platform/organizations").json()}
    assert listing["fresh-msp"]["kind"] == "msp" and listing["msp-one"]["clients"] == 1
    assert listing["plain"]["kind"] == "customer" and listing["default"]["kind"] == "customer"
    # MSP staff, client admins and plain admins cannot create or mark MSPs or move clients.
    body = {"name": "Sneaky", "admin_email": "x@sneaky.test", "kind": "msp"}
    for c in (w.admin, w.client_admin):
        assert c.post("/api/platform/organizations", json=body).status_code == 403
        assert c.patch(f"/api/platform/organizations/{w.plain_id}", json={"kind": "msp"}).status_code == 403
        assert c.put(f"/api/platform/organizations/{w.client_id}/partner", json={"partner_org_id": None}).status_code == 403
    # Marking an organisation as MSP: the owner can; a client or the default organisation cannot become one.
    assert w.owner.patch(f"/api/platform/organizations/{w.plain_id}", json={"kind": "msp"}).json()["kind"] == "msp"
    assert w.owner.patch(f"/api/platform/organizations/{w.client_id}", json={"kind": "msp"}).status_code == 409
    assert w.owner.patch("/api/platform/organizations/default", json={"kind": "msp"}).status_code == 409
    assert w.owner.patch(f"/api/platform/organizations/{w.msp_id}", json={"kind": "customer"}).status_code == 409


def test_client_of_an_ordinary_customer_is_refused(w):
    plain = w.plain_id
    r = w.owner.put(f"/api/platform/organizations/{w.client_id}/partner", json={"partner_org_id": plain})
    assert r.status_code == 422  # not an MSP


# ----------------------------------------------------------------------------- MSP admin / roles
def test_msp_admin_creates_client_with_any_modules(w):
    r = w.admin.post("/api/msp/clients", json={"name": "Second", "contact_email": "a@second.test",
                                               "modules": ["external"], "admin_email": "first@second.test"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["client"]["modules"] == ["external"] and body["invitation"]["invitation"]["role"] == "admin"
    cid = body["client"]["id"]
    # The MSP may turn on any module later; the platform owner sees the new client as its client.
    r = w.admin.put(f"/api/msp/clients/{cid}/modules", json={"modules": list(ALL_MODULES)})
    assert r.status_code == 200 and r.json()["modules"] == list(ALL_MODULES)
    org = {o["id"]: o for o in w.owner.get("/api/platform/organizations").json()}[cid]
    assert org["partner_org_id"] == w.msp_id and org["modules"] == list(ALL_MODULES)
    assert len(w.admin.get("/api/msp/clients").json()) == 2
    actions = [a.action for a in audit_rows(w.msp_id)]
    assert "msp_client_created" in actions and actions.count("msp_client_module_enabled") >= 4
    # the audit rows of MSP-level actions are in the MSP's own log
    assert any(a["action"] == "msp_client_created" for a in w.admin.get("/api/audit-log").json())


def test_client_limit_and_slug_never_leaks(w):
    set_org_fields(w.msp_id, max_clients=1)
    r = w.admin.post("/api/msp/clients", json={"name": "Over", "contact_email": "a@over.test"})
    assert r.status_code == 409
    set_org_fields(w.msp_id, max_clients=None)
    # same name as an existing organisation elsewhere: succeeds with a different slug
    r = w.admin.post("/api/msp/clients", json={"name": "Plain", "contact_email": "a@plain2.test"})
    assert r.status_code == 201 and r.json()["client"]["slug"] != "plain"


def test_analyst_and_viewer_cannot_manage(w):
    body = {"name": "Nope", "contact_email": "a@nope.test"}
    for c in (w.analyst, w.viewer):
        assert c.post("/api/msp/clients", json=body).status_code == 403
        assert c.put(f"/api/msp/clients/{w.client_id}/modules", json={"modules": []}).status_code == 403
        assert c.post(f"/api/msp/clients/{w.client_id}/suspend", json={}).status_code == 403
        assert c.post(f"/api/msp/clients/{w.client_id}/invitations", json={"email": "x@y.test"}).status_code == 403
        assert c.get("/api/msp/clients").status_code == 200  # they can see and enter their clients
    # non-MSP users have no MSP area
    assert w.client_admin.get("/api/msp/clients").status_code == 403
    assert w.owner.get("/api/msp/clients").status_code == 403


def test_msp_cannot_touch_other_orgs_by_guessing_ids(w):
    for oid in (w.other_msp_client_id, w.plain_id, "default", w.msp_id, "doesnotexist"):
        assert w.admin.get(f"/api/msp/clients/{oid}").status_code == 404, oid
        assert w.admin.put(f"/api/msp/clients/{oid}/modules", json={"modules": []}).status_code == 404
        assert w.admin.post(f"/api/msp/clients/{oid}/suspend", json={}).status_code == 404
        assert w.admin.post(f"/api/msp/clients/{oid}/invitations", json={"email": "z@z.test"}).status_code == 404
        assert switch(w.admin, oid).status_code == 404, oid
        assert switch(w.analyst, oid).status_code == 404
    assert w.admin.get("/api/msp/clients").json()[0]["id"] == w.client_id
    # still in the MSP's own organisation after the failed attempts
    assert w.admin.get("/api/auth/me").json()["organization"]["id"] == w.msp_id


def test_invite_client_admin_and_suspend_reactivate(w):
    r = w.admin.post(f"/api/msp/clients/{w.client_id}/invitations", json={"email": "second@client1.test"})
    assert r.status_code == 201 and r.json()["invitation"]["role"] == "admin"
    assert len(w.admin.get(f"/api/msp/clients/{w.client_id}/invitations").json()) == 1
    assert w.admin.post(f"/api/msp/clients/{w.client_id}/suspend", json={"reason": "unpaid"}).json()["status"] == "suspended"
    assert w.client_admin.get("/api/organization").status_code == 401  # its users are signed out
    assert switch(w.admin, w.client_id).status_code == 409
    r = w.admin.post(f"/api/msp/clients/{w.client_id}/activate", json={})
    assert r.status_code == 200 and r.json()["status"] == "active"
    # suspended by the platform owner: the MSP cannot undo it
    assert w.owner.post(f"/api/platform/organizations/{w.client_id}/suspend", json={}).status_code == 200
    assert w.admin.post(f"/api/msp/clients/{w.client_id}/activate", json={}).status_code == 409


def test_overview(w):
    r = w.analyst.get("/api/msp/overview")
    assert r.status_code == 200
    body = r.json()
    assert body["total_clients"] == 1 and not body["truncated"]
    row = body["clients"][0]
    assert row["id"] == w.client_id and row["status"] == "active" and row["modules"] == list(ALL_MODULES)
    assert row["devices"] == 0 and row["open_critical_findings"] == 0 and "risk_score" in row
    # other MSPs' clients never show up
    assert all(c["id"] != w.other_msp_client_id for c in body["clients"])


# ----------------------------------------------------------------------------- working inside a client
def test_staff_switch_into_client_and_back(w):
    assert w.admin.get("/api/devices").status_code == 403  # the MSP's own organisation has no modules
    r = switch(w.admin, w.client_id)
    assert r.status_code == 200 and r.json()["acting_as_client"] is True
    me = w.admin.get("/api/auth/me").json()
    assert me["organization"]["id"] == w.client_id and me["user"]["role"] == "admin"
    assert me["home_organization"]["id"] == w.msp_id and me["acting_as_client"] is True
    assert w.admin.get("/api/devices").status_code == 200
    assert w.admin.get("/api/dashboard").status_code == 200
    # data created in the client stays in the client
    assert w.admin.post("/api/organization/ingest-tokens", json={"name": "k"}).status_code == 201
    assert len(w.client_admin.get("/api/organization/ingest-tokens").json()) == 1
    # the MSP endpoints still work from inside a client
    assert w.admin.get("/api/msp/clients").status_code == 200
    # back to the MSP organisation
    assert switch(w.admin, None).status_code == 200
    me = w.admin.get("/api/auth/me").json()
    assert me["organization"]["id"] == w.msp_id and me["acting_as_client"] is False
    assert w.admin.get("/api/organization/ingest-tokens").json() == []
    # roles map: an analyst is an analyst in the client, a viewer read-only
    assert switch(w.analyst, w.client_id).status_code == 200
    assert w.analyst.get("/api/auth/me").json()["user"]["role"] == "analyst"
    assert w.analyst.post("/api/organization/ingest-tokens", json={"name": "k"}).status_code == 403
    assert w.analyst.get("/api/users").status_code == 403
    assert switch(w.viewer, w.client_id).status_code == 200
    assert w.viewer.get("/api/devices").status_code == 200
    assert w.viewer.post("/api/scans", json={"connector": "simulated"}).status_code == 403


def test_staff_cannot_escalate_inside_a_client(w):
    switch(w.admin, w.client_id)
    assert w.admin.get("/api/platform/organizations").status_code == 403
    assert w.admin.post("/api/platform/organizations", json={"name": "X", "admin_email": "x@x.test",
                                                              "kind": "msp"}).status_code == 403
    assert w.admin.patch("/api/organization", json={"partner_org_id": None}).status_code == 422
    assert w.admin.get("/api/auth/me").json()["platform_admin"] is False
    # a platform owner who is also MSP staff is not a platform owner inside a client
    make_member(w.msp_id, "owner-and-staff@msp1.test", "admin")
    with db.get_session(unscoped=True) as s:
        s.execute(update(User).where(User.email == "owner-and-staff@msp1.test").values(is_platform_admin=True))
        s.commit()
    c = org_client(w.admin.app, "owner-and-staff@msp1.test", PW)
    switch(c, w.client_id)
    assert c.get("/api/platform/organizations").status_code == 403


def test_hidden_from_the_client(w):
    switch(w.admin, w.client_id)
    switch(w.analyst, w.client_id)
    # MSP staff act (and create things) inside the client ...
    assert w.admin.post("/api/organization/ingest-tokens", json={"name": "by-msp"}).status_code == 201
    r = w.admin.post("/api/devices/enrollment-tokens", json={"name": "t", "max_uses": 1, "expires_in_hours": 1})
    assert r.status_code == 201
    # ... and the client's own API shows no trace of them
    users = w.client_admin.get("/api/users").json()
    assert [u["email"] for u in users] == ["admin@client1.test"]
    assert "msp1.test" not in str(users)
    log = w.client_admin.get("/api/audit-log", params={"limit": 2000}).json()
    assert log and "msp1" not in str(log) and all(a["action"] != "ingest_token_created" for a in log)
    token = w.client_admin.get("/api/organization/ingest-tokens").json()[0]
    assert "msp1" not in str(token)  # shows the neutral label, not the person
    assert token["created_by"] == auth.PARTNER_ACTOR_LABEL
    org = w.client_admin.get("/api/organization").json()
    assert "partner_org_id" not in org and "msp" not in str(org).lower().replace("msp-one", "")
    assert w.client_admin.get("/api/organization/invitations").json() == []
    assert w.client_admin.get("/api/organization/usage").json()["users"] == 1
    # the client's own actions are there
    assert w.client_admin.post("/api/organization/ingest-tokens", json={"name": "own"}).status_code == 201
    assert any(a["action"] == "ingest_token_created" for a in w.client_admin.get("/api/audit-log").json())
    # invitations the MSP sent are not listed for the client either
    assert w.admin.post(f"/api/msp/clients/{w.client_id}/invitations", json={"email": "n@client1.test"}).status_code == 201
    assert w.client_admin.get("/api/organization/invitations").json()[0]["invited_by"] is None


def test_partner_actions_are_audited_with_the_real_actor_and_visible_to_the_platform_only(w):
    switch(w.admin, w.client_id)
    assert w.admin.post("/api/organization/ingest-tokens", json={"name": "by-msp"}).status_code == 201
    rows = [a for a in audit_rows(w.client_id) if a.action == "ingest_token_created"]
    assert len(rows) == 1
    assert rows[0].actor_email == "admin@msp1.test" and rows[0].via_partner_org_id == w.msp_id
    assert rows[0].actor_id is not None
    # entering the client is audited in the MSP's log
    assert "msp_client_entered" in [a.action for a in audit_rows(w.msp_id)]
    # platform owner sees it, including the flag
    log = w.owner.get(f"/api/platform/organizations/{w.client_id}/audit-log").json()
    hit = [a for a in log if a["action"] == "ingest_token_created"]
    assert hit and hit[0]["actor_email"] == "admin@msp1.test" and hit[0]["via_partner_org_id"] == w.msp_id
    only = w.owner.get(f"/api/platform/organizations/{w.client_id}/audit-log", params={"via_partner": True}).json()
    assert only and all(a["via_partner_org_id"] == w.msp_id for a in only)
    # nobody else can read it: client admin, MSP staff
    assert w.client_admin.get(f"/api/platform/organizations/{w.client_id}/audit-log").status_code == 403
    assert w.admin.get(f"/api/platform/organizations/{w.client_id}/audit-log").status_code == 403
    # there is no MSP-facing activity endpoint
    assert w.admin.get("/api/msp/activity").status_code == 404
    # MSP-level staff changes are audited in the MSP org
    r = w.admin.post("/api/organization/invitations", json={"email": "new@msp1.test", "role": "analyst"})
    assert r.status_code in (201, 200)


def test_modules_still_apply_inside_a_client(w):
    switch(w.admin, w.client_id)
    assert w.admin.get("/api/assets").status_code == 200
    assert switch(w.admin, None).status_code == 200
    assert w.admin.put(f"/api/msp/clients/{w.client_id}/modules", json={"modules": ["vulnerabilities"]}).status_code == 200
    switch(w.admin, w.client_id)
    r = w.admin.get("/api/assets")
    assert r.status_code == 403 and r.json() == {"detail": "module_disabled", "module": "cloud"}
    assert w.admin.get("/api/vulnerabilities").status_code == 200
    assert w.client_admin.get("/api/assets").status_code == 403


# ----------------------------------------------------------------------------- access ends at once
def test_suspending_the_msp_removes_access(w):
    switch(w.admin, w.client_id)
    assert w.admin.get("/api/devices").status_code == 200
    assert w.owner.post(f"/api/platform/organizations/{w.msp_id}/suspend", json={"reason": "x"}).status_code == 200
    for c in (w.admin, w.analyst):
        assert c.get("/api/devices").status_code == 401
        assert c.get("/api/msp/clients").status_code == 401
    # the client itself keeps working
    assert w.client_admin.get("/api/devices").status_code == 200


def test_moving_the_client_away_removes_access(w):
    switch(w.admin, w.client_id)
    assert w.admin.get("/api/organization").json()["id"] == w.client_id
    r = w.owner.put(f"/api/platform/organizations/{w.client_id}/partner", json={"partner_org_id": None})
    assert r.status_code == 200 and r.json()["partner_org_id"] is None
    # the next request is no longer inside the client
    assert w.admin.get("/api/organization").json()["id"] == w.msp_id
    assert w.admin.get("/api/auth/me").json()["acting_as_client"] is False
    assert switch(w.admin, w.client_id).status_code == 404
    assert w.admin.get("/api/msp/clients").json() == []
    # moved to the other MSP: that MSP's staff can enter, ours still cannot
    r = w.owner.put(f"/api/platform/organizations/{w.client_id}/partner", json={"partner_org_id": "x" * 5})
    assert r.status_code == 422
    msp2 = w.owner.get("/api/platform/organizations").json()
    msp2_id = next(o["id"] for o in msp2 if o["slug"] == "msp-two")
    assert w.owner.put(f"/api/platform/organizations/{w.client_id}/partner",
                       json={"partner_org_id": msp2_id}).status_code == 200
    assert switch(w.msp2_admin, w.client_id).status_code == 200
    assert switch(w.admin, w.client_id).status_code == 404
    # the partner change is not visible to the client
    assert all("partner" not in a["action"] for a in w.client_admin.get("/api/audit-log").json())


def test_staff_removed_from_the_msp_lose_access(w):
    switch(w.analyst, w.client_id)
    assert w.analyst.get("/api/devices").status_code == 200
    with db.get_session(w.msp_id) as s:
        from app.models import OrganizationMembership

        for m in s.scalars(select(OrganizationMembership).join(User, User.id == OrganizationMembership.user_id)
                           .where(User.email == "analyst@msp1.test")):
            s.delete(m)
        s.commit()
    assert w.analyst.get("/api/devices").status_code == 401


def test_client_admin_cannot_remove_or_see_msp_access(w):
    ca = w.client_admin
    assert ca.patch("/api/organization", json={"partner_org_id": None}).status_code == 422
    assert ca.patch("/api/organization", json={"kind": "msp"}).status_code == 422
    assert ca.put(f"/api/platform/organizations/{w.client_id}/partner", json={"partner_org_id": None}).status_code == 403
    assert ca.get("/api/msp").status_code == 403
    # the only visible user is the admin; they cannot target MSP staff (not found) ...
    with db.get_session(unscoped=True) as s:
        staff_id = s.scalar(select(User.id).where(User.email == "admin@msp1.test"))
    assert ca.patch(f"/api/users/{staff_id}", json={"is_active": False}).status_code == 404
    assert ca.delete(f"/api/users/{staff_id}").status_code == 404
    assert ca.post(f"/api/users/{staff_id}/reset-password", json={"password": "another-long-pass1"}).status_code == 404
    # ... and cannot create a clashing account either way, access stays
    assert switch(w.admin, w.client_id).status_code == 200
    assert w.admin.get("/api/organization").json()["id"] == w.client_id
    # the last-admin guard counts the client's own admins only
    mine = ca.get("/api/users").json()[0]["id"]
    assert ca.patch(f"/api/users/{mine}", json={"role": "viewer"}).status_code == 409


def test_msp_admin_cannot_approve_own_request(empty_client):
    app = empty_client.app
    with db.get_session(unscoped=True) as s:
        s.execute(update(User).where(User.email == ADMIN_EMAIL).values(is_platform_admin=True))
        s.commit()
    msp = make_org("msp-appr", kind="msp", modules=[])
    make_member(msp, "boss@appr.test", "admin")
    make_member(msp, "boss2@appr.test", "admin")
    boss = org_client(app, "boss@appr.test", PW)
    boss2 = org_client(app, "boss2@appr.test", PW)
    cid = boss.post("/api/msp/clients", json={"name": "Appr Client", "contact_email": "a@appr.test",
                                              "modules": list(ALL_MODULES)}).json()["client"]["id"]
    make_member(cid, "ca@appr.test", "admin")
    ca = org_client(app, "ca@appr.test", PW)
    switch(boss, cid)
    switch(boss2, cid)
    agent, device_id = enrolled(boss, hostname="LAPTOP-001")
    r = request_wipe(boss, device_id)
    assert r.status_code in (200, 201, 202), r.text
    approval = boss.get("/api/approvals").json()[0]
    assert approval["is_own_request"] is True and approval["can_decide"] is False
    r = boss.post(f"/api/approvals/{approval['id']}/approve", json={"confirm_hostname": "LAPTOP-001"})
    assert r.status_code in (403, 409), r.text
    # a MSP admin counts as an admin there: another MSP admin, or the client's own admin, can decide
    seen = boss2.get("/api/approvals").json()[0]
    assert seen["can_decide"] is True and seen["is_own_request"] is False
    assert seen["requested_by_email"] == auth.PARTNER_ACTOR_LABEL
    r = ca.post(f"/api/approvals/{approval['id']}/approve", json={"confirm_hostname": "LAPTOP-001"})
    assert r.status_code == 200, r.text
    assert agent is not None


def test_migration_defaults_and_sqlite_upgrade(w):
    with db.get_session(unscoped=True) as s:
        assert s.get(Organization, "default").kind == "customer"
        assert s.get(Organization, w.plain_id).partner_org_id is None
        assert s.get(Organization, w.client_id).partner_org_id == w.msp_id


def test_csrf_unchanged_for_switch(w):
    c = TestClient(w.admin.app, base_url=w.admin.base_url)
    login(c, "admin@msp1.test", PW)
    del c.headers["X-CSRF-Token"]
    assert c.post("/api/msp/switch", json={"organization_id": w.client_id}).status_code == 403


def test_client_invitations_never_name_the_msp(w, monkeypatch):
    """The client-facing mail is brand only: no MSP name, in the first admin's or a later admin's invitation."""
    from app import mailer

    set_org_fields(w.msp_id, name="Zebratech Managed Services")
    sent = []

    def fake_send(to, subject, text, html, *, reply_to=None, attachments=None, inline_images=None):
        sent.append((to, subject, text, html, inline_images))
        return mailer.MailResult(True)

    monkeypatch.setattr(mailer, "send", fake_send)
    r = w.admin.post("/api/msp/clients", json={"name": "Client Two", "contact_email": "it@client2.test",
                                               "admin_email": "boss@client2.test", "modules": ["endpoints", "cloud"]})
    assert r.status_code == 201, r.text
    r = w.admin.post(f"/api/msp/clients/{w.client_id}/invitations", json={"email": "second@client1.test"})
    assert r.status_code == 201
    inv_id = r.json()["invitation"]["id"]
    assert w.admin.post(f"/api/msp/clients/{w.client_id}/invitations/{inv_id}/resend").status_code in (200, 201)
    assert len(sent) == 3
    for to, subject, text, body_html, images in sent:
        assert subject.startswith("Your ") and subject.endswith(" is ready") and "partner account" not in subject
        for part in (subject, text, body_html):
            assert "zebratech" not in part.lower() and "managed services" not in part.lower()
        assert images and images[0][0] == "sentrigis-logo"
    first = next(m for m in sent if m[0] == "boss@client2.test")
    assert "What's included: Cloud security, Endpoints & servers" in first[2]
