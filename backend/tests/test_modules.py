"""Product modules (app/modules.py, docs: Platform > Organisations): the `require_module` dependency,
the migration default, the platform endpoint and its audit trail, the agent rules of an
Assets-only organisation, and the schedulers."""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text, update

from app import db as dbmod
from app.connectors.base import CollectionResult, Connector
from app.directory import collectors as dir_collectors
from app.directory.scheduler import DirectoryScheduler
from app.models import AuditLog, Organization, User, utcnow
from app.modules import ALL_MODULES
from app.services import organizations as orgs
from app.services import scan_schedule as sched
from tests.conftest import ADMIN_EMAIL, AUTH, BASE_URL, IS_POSTGRES, TEST_DATABASE_URL, login, reset_database
from tests.test_devices import agent_client, enroll, new_token, windows_checkin
from tests.test_tenancy import create_org


def set_modules(org_id: str, modules: list[str] | None) -> None:
    with dbmod.get_session(unscoped=True) as s:
        s.get(Organization, org_id).modules = modules
        s.commit()


def modules_of(org_id: str) -> list[str] | None:
    with dbmod.get_session(unscoped=True) as s:
        return s.get(Organization, org_id).modules


# One read endpoint per module (every one is a plain GET for an admin of the organisation).
PROBES = {
    "cloud": ["/api/assets", "/api/findings", "/api/exposure", "/api/attack-paths", "/api/connectors", "/api/scans",
              "/api/organization/connectors"],
    "endpoints": ["/api/devices", "/api/alerts", "/api/runtime/events", "/api/scripts", "/api/devices/summary"],
    "vulnerabilities": ["/api/vulnerabilities", "/api/vulnerabilities/stats"],
    "assets": ["/api/it-assets", "/api/directory/sources", "/api/network/scans", "/api/collectors"],
    "external": ["/api/external/overview", "/api/external/targets", "/api/external/findings", "/api/external/hosts",
                 "/api/external/scans", "/api/external/reports", "/api/external/report/preview"],
}


def test_each_module_gates_its_apis(client):
    # All on (the default organisation): every probe answers.
    for urls in PROBES.values():
        for url in urls:
            assert client.get(url).status_code == 200, url
    for module, urls in PROBES.items():
        set_modules("default", [m for m in ALL_MODULES if m != module])
        for url in urls:
            r = client.get(url)
            assert r.status_code == 403, url
            assert r.json() == {"detail": "module_disabled", "module": module}, url
        # The other modules keep working.
        for other, other_urls in PROBES.items():
            if other != module:
                assert client.get(other_urls[0]).status_code == 200, (module, other_urls[0])
    # Turning a module back on shows its data again (nothing was deleted).
    set_modules("default", list(ALL_MODULES))
    assert len(client.get("/api/assets").json()) > 0



def test_asset_drawer_opens_without_cloud_and_hides_other_modules_sections(client):
    """The asset drawer is opened from the vulnerability and runtime-threat pages too."""
    asset_id = client.get("/api/assets").json()[0]["id"]
    set_modules("default", ["vulnerabilities"])
    r = client.get("/api/assets/detail", params={"id": asset_id})
    assert r.status_code == 200
    assert r.json()["findings"] == [] and r.json()["alerts"] == []
    assert client.get("/api/rules/detection").status_code == 403
    set_modules("default", ["assets"])
    assert client.get("/api/assets/detail", params={"id": asset_id}).status_code == 403
    set_modules("default", ["endpoints"])
    assert client.get("/api/rules/detection").status_code == 200
    set_modules("default", list(ALL_MODULES))

def test_no_bypass_for_platform_admins_and_writes_are_gated(client):
    with dbmod.get_session(unscoped=True) as s:
        s.execute(update(User).where(User.email == ADMIN_EMAIL).values(is_platform_admin=True))
        s.commit()
    set_modules("default", [])
    assert client.get("/api/devices").status_code == 403
    assert client.post("/api/scans", json={"connector": "simulated"}).json()["module"] == "cloud"
    assert client.post("/api/devices/bulk-commands", json={}).status_code in (403, 422)
    assert client.get("/api/vulnerabilities/CVE-2024-0001").json()["module"] == "vulnerabilities"
    assert client.put("/api/organization/connectors/azure", json={}).json()["module"] == "cloud"
    # Always on: dashboards, compliance, notifications, approvals, organisation, users, audit log.
    for url in ("/api/dashboards", "/api/compliance", "/api/notifications/channels", "/api/approvals",
                "/api/organization", "/api/users", "/api/audit-log"):
        assert client.get(url).status_code == 200, url
    me = client.get("/api/auth/me").json()
    assert me["organization"]["modules"] == []


def test_session_info_lists_modules(client):
    assert client.get("/api/auth/me").json()["organization"]["modules"] == list(ALL_MODULES)
    set_modules("default", ["assets", "cloud"])
    assert client.get("/api/auth/me").json()["organization"]["modules"] == ["cloud", "assets"]
    assert client.get("/api/organization").json()["modules"] == ["cloud", "assets"]
    # NULL (never set, e.g. a SQLite database from before modules) means all on.
    set_modules("default", None)
    assert client.get("/api/auth/me").json()["organization"]["modules"] == list(ALL_MODULES)
    assert client.get("/api/devices").status_code == 200


# --- platform console ---------------------------------------------------------------

@pytest.fixture()
def platform(client):
    with dbmod.get_session(unscoped=True) as s:
        s.execute(update(User).where(User.email == ADMIN_EMAIL).values(is_platform_admin=True))
        s.commit()
    return client


def test_new_organisations_start_with_no_modules(platform):
    r = platform.post("/api/platform/organizations", json={"name": "Acme Ltd", "admin_email": "boss@acme.test"})
    assert r.status_code == 201, r.text
    assert r.json()["organization"]["modules"] == []
    with dbmod.get_session(unscoped=True) as s:
        assert orgs.create_organization(s, name="Other", slug="other").modules == []
        s.rollback()
    # ... or with the ones ticked in the New organisation dialog.
    r = platform.post("/api/platform/organizations", json={"name": "Beta Ltd", "admin_email": "boss@beta.test",
                                                           "modules": ["endpoints", "cloud"]})
    assert r.json()["organization"]["modules"] == ["cloud", "endpoints"]
    assert platform.post("/api/platform/organizations", json={"name": "Bad", "admin_email": "x@bad.test",
                                                              "modules": ["nope"]}).status_code == 422
    # The default organisation is switchable like any other.
    assert platform.get("/api/platform/organizations").json()[0]["modules"] == list(ALL_MODULES)


def test_platform_switches_modules_and_audits(platform):
    oid = platform.post("/api/platform/organizations", json={"name": "Acme Ltd", "admin_email": "boss@acme.test"}
                        ).json()["organization"]["id"]
    r = platform.put(f"/api/platform/organizations/{oid}/modules/cloud", json={"enabled": True})
    assert r.status_code == 200 and r.json()["modules"] == ["cloud"]
    r = platform.put(f"/api/platform/organizations/{oid}/modules/assets", json={"enabled": True})
    assert r.json()["modules"] == ["cloud", "assets"]
    assert platform.get(f"/api/platform/organizations/{oid}").json()["modules"] == ["cloud", "assets"]
    r = platform.put(f"/api/platform/organizations/{oid}/modules/cloud", json={"enabled": False})
    assert r.json()["modules"] == ["assets"]
    # Repeating a state writes no audit entry.
    platform.put(f"/api/platform/organizations/{oid}/modules/cloud", json={"enabled": False})
    assert platform.put(f"/api/platform/organizations/{oid}/modules/bogus", json={"enabled": True}).status_code == 422
    assert platform.put("/api/platform/organizations/nope/modules/cloud", json={"enabled": True}).status_code == 404
    with dbmod.get_session(unscoped=True) as s:
        rows = list(s.scalars(select(AuditLog).where(AuditLog.organization_id == oid,
                                                     AuditLog.action.in_(["org_module_enabled", "org_module_disabled"]))
                              .order_by(AuditLog.id)))
    assert [(a.action, a.detail["module"]) for a in rows] == [
        ("org_module_enabled", "cloud"), ("org_module_enabled", "assets"), ("org_module_disabled", "cloud")]
    assert rows[0].actor_email == ADMIN_EMAIL and rows[0].target.startswith("organization:")


def test_only_platform_admins_can_switch_modules(client):
    assert client.put("/api/platform/organizations/default/modules/cloud", json={"enabled": False}).status_code == 403
    assert modules_of("default") == list(ALL_MODULES)


# --- migration ------------------------------------------------------------------------

def test_migration_turns_every_existing_organisation_fully_on(tmp_path):
    """0031: the four modules of that time; `external` (0032, bought separately) stays off."""
    if IS_POSTGRES:
        reset_database()
        eng = dbmod.create_db_engine(TEST_DATABASE_URL)
    else:
        eng = dbmod.create_db_engine(f"sqlite:///{tmp_path / 'modules.db'}")
    try:
        dbmod.run_migrations(eng, "0030_linux_agent")
        now = datetime(2026, 11, 1)
        with eng.begin() as conn:
            conn.execute(text("INSERT INTO organizations (id, name, slug, status, is_default, created_at, updated_at) "
                              "VALUES ('old1', 'Old', 'old', 'active', :f, :n, :n)"), {"f": False, "n": now})
        dbmod.run_migrations(eng)
        with eng.connect() as conn:
            rows = dict(conn.execute(text("SELECT id, modules FROM organizations")).all())
        assert set(rows) == {"default", "old1"}
        for oid, value in rows.items():
            assert (value if isinstance(value, list) else json.loads(value)) == [m for m in ALL_MODULES if m != "external"], oid
    finally:
        eng.dispose()


# --- agents ---------------------------------------------------------------------------

def test_agent_enrolment_needs_endpoints_or_assets(client):
    for modules, status in (([], 403), (["cloud", "vulnerabilities"], 403), (["assets"], 200), (["endpoints"], 200)):
        set_modules("default", list(ALL_MODULES))
        token = new_token(client)  # (tokens can be made while Endpoints or Assets is on)
        set_modules("default", modules)
        r = enroll(agent_client(client.app), token)
        assert r.status_code == status, (modules, r.text)
        if status == 403:
            assert r.json()["detail"] == "module_disabled"
            # A refused enrolment does not use up the token.
            set_modules("default", ["assets"])
            assert enroll(agent_client(client.app), token).status_code == 200


def test_assets_only_organisation_agent_feeds_inventory_but_gets_no_remote_actions(client):
    token = new_token(client)
    agent = agent_client(client.app)
    r = enroll(agent, token)
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    device_id = r.json()["device_id"]
    assert agent.post("/api/agent/checkin", json=windows_checkin()).status_code == 200
    cmd = client.post(f"/api/devices/{device_id}/commands", json={"type": "recheck_posture", "reason": "test"})
    assert cmd.status_code == 201, cmd.text

    # Endpoints off, Assets on: the agent still checks in (inventory feeds IT assets), but nothing is handed out ...
    set_modules("default", ["assets"])
    assert agent.post("/api/agent/checkin", json=windows_checkin()).status_code == 200
    assert agent.get("/api/agent/commands").json()["commands"] == []
    # ... scripts are refused, the console cannot list or act on devices or start remote support ...
    assert agent.get(f"/api/agent/scripts/bundles/{'a' * 32}/manifest").status_code == 403
    assert client.get("/api/devices").json() == {"detail": "module_disabled", "module": "endpoints"}
    assert client.post(f"/api/devices/{device_id}/commands",
                       json={"type": "recheck_posture", "reason": "test"}).status_code == 403
    assert client.get(f"/api/devices/{device_id}/remote-sessions").status_code == 403
    # ... but enrolment tokens and installers stay available to deploy more agents,
    assert client.get("/api/devices/enrollment-tokens").status_code == 200
    # the runtime sensor is refused,
    r = client.post("/api/runtime/events", json=[], headers=AUTH)
    assert r.status_code == 403 and r.json() == {"detail": "module_disabled", "module": "endpoints"}
    # and the pending command waits until Endpoints is switched back on.
    set_modules("default", list(ALL_MODULES))
    assert [c["type"] for c in agent.get("/api/agent/commands").json()["commands"]] == ["recheck_posture"]


def test_sensor_ingest_accepted_with_endpoints(client):
    r = client.post("/api/runtime/events", json=[], headers=AUTH)
    assert r.status_code in (200, 202), r.text


def test_other_organisations_modules_are_independent(client):
    acme = create_org("acme", "admin@acme.test", "acme-admin-password")
    set_modules(acme, ["cloud"])
    c = TestClient(client.app, base_url=BASE_URL)
    login(c, "admin@acme.test", "acme-admin-password")
    assert c.get("/api/findings").status_code == 200
    assert c.get("/api/devices").status_code == 403
    assert client.get("/api/devices").status_code == 200


# --- schedulers -----------------------------------------------------------------------

class FakeConnector(Connector):
    provider = "fake"
    name = "fake"

    def is_configured(self) -> bool:
        return True

    def collect(self) -> CollectionResult:
        return CollectionResult()


def test_scan_scheduler_skips_organisations_without_cloud(session):
    launched: list[str] = []
    t0 = datetime(2026, 10, 23, 12, 0, 0)
    s = sched.ScanScheduler(startup_delay_seconds=0, clock=lambda: t0,
                            registry_factory=lambda *_: {"fake": FakeConnector()},
                            launcher=lambda conn, org_id="default": launched.append(conn.name))
    try:
        set_modules("default", ["endpoints", "assets", "vulnerabilities"])
        assert s.tick(t0).started == [] and launched == []
        set_modules("default", ["cloud"])
        assert s.tick(t0 + timedelta(minutes=1)).started == ["fake"]
    finally:
        s.stop()


def test_directory_scheduler_skips_organisations_without_assets(session, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(dir_collectors, "check_offline", lambda db, now: calls.append("collectors"))
    s = DirectoryScheduler()
    out: dict[str, list[str]] = {"queued": [], "failed": [], "failed_over": []}
    set_modules("default", ["cloud", "endpoints", "vulnerabilities"])
    with dbmod.get_session("default") as db:
        s.tick_org(db, "default", utcnow(), out)
    assert calls == []
    set_modules("default", ["assets"])
    with dbmod.get_session("default") as db:
        s.tick_org(db, "default", utcnow(), out)
    assert calls == ["collectors"]


def test_fresh_default_organisation_has_every_module(session):
    from app import tenancy

    with dbmod.get_session(unscoped=True) as s:
        tenancy.ensure_default_org(s)
        s.commit()
        assert s.get(Organization, "default").modules == list(ALL_MODULES)


def test_no_notification_events_from_a_disabled_module(session):
    from app.notifications.events import Event, emit

    def queue(source: str):
        with dbmod.get_session("default") as db:
            row = emit(db, Event(source=source, event_type="created", severity="high", title="t"))
            db.rollback()
            return row

    set_modules("default", ["cloud"])
    assert queue("posture_finding") is not None
    assert queue("runtime_alert") is None and queue("vulnerability") is None and queue("directory_source") is None
    # Sources that belong to no module (approvals, agent security) are never dropped.
    assert queue("device_approvals") is not None
