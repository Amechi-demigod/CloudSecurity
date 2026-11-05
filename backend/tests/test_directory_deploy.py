"""Deploy agent from Discovery: route planning per machine (pure), plans and
deployments through the API (route overrides, token scoping and caps, the
deployment's installers), progress through the existing directory matching,
revocation, RBAC, audit and tenant isolation. No directory is written to; the
tests play the collector agent and add Entra / Intune / Google records directly."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app import db
from app.directory import deploy, reconcile
from app.directory.deploy import Record, plan_machine
from app.directory.models import DirectoryComputer, DirectorySource
from app.models import AuditLog, EnrollmentToken, utcnow
from tests.conftest import login, make_user
from tests.test_devices import agent_client, enroll
from tests.test_directory import add_device, checkin, collector, computer, join, make_source, run_sync  # noqa: F401
from tests.test_installers import all_db_text, bundle, ca_pem  # noqa: F401
from tests.test_tenancy import ACME_ADMIN, ACME_PASSWORD, create_org, org_client


# ----------------------------------------------------------------------------- planning (pure)
def r(kind: str, platform: str, *, expected: bool = True, enabled: bool = True) -> Record:
    return Record(kind, platform, expected, enabled)


@pytest.mark.parametrize(("records", "route", "allowed", "reason"), [
    ([r("ad", "windows")], "gpo", ("gpo", "rmm", "manual"), ""),
    # One machine in AD, Entra ID and Intune: Intune first, Group Policy still possible.
    ([r("ad", "windows"), r("entra", "windows"), r("intune", "windows")], "intune",
     ("intune", "gpo", "rmm", "manual"), ""),
    ([r("intune", "macos"), r("entra", "macos")], "intune", ("intune", "rmm", "manual"), ""),
    ([r("entra", "windows")], "manual", ("rmm", "manual"), ""),  # Entra-joined, no Intune
    ([r("endpoint", "macos")], "manual", ("rmm", "manual"), ""),  # Google endpoint
    ([r("ad", "macos")], "manual", ("rmm", "manual"), ""),  # a Mac bound to AD: no GPO
    ([r("chromeos", "chromeos", expected=False)], None, (), "mobile"),
    ([r("intune", "ios", expected=False)], None, (), "mobile"),
    ([r("mobile", "android", expected=False)], None, (), "mobile"),
    ([r("intune", "windows", expected=False)], None, (), "no_agent_expected"),  # personal
    ([r("entra", "windows", expected=False)], None, (), "no_agent_expected"),  # registered only
    ([r("ad", "windows", enabled=False)], None, (), "disabled"),
    ([r("ad", "linux")], None, (), "linux"),
    ([r("ad", "")], None, (), "unknown_os"),
    ([r("ad", "other")], None, (), "unknown_os"),
    ([], None, (), "gone"),
])
def test_plan_machine_routes(records, route, allowed, reason):
    p = plan_machine(records, has_agent=False)
    assert (p.route, p.allowed, p.reason) == (route, allowed, reason)


def test_plan_machine_platform_and_agent():
    # The MDM's platform wins over a name-based guess; an agent excludes the machine.
    assert deploy.machine_platform([r("ad", ""), r("intune", "windows")]) == "windows"
    assert plan_machine([r("ad", "windows")], has_agent=True).reason == "has_agent"
    # A disabled AD record does not block the machine's enabled Intune record.
    assert plan_machine([r("ad", "windows", enabled=False), r("intune", "windows")], has_agent=False).route == "intune"


def test_batch_cap():
    assert [deploy.batch_cap(n) for n in (1, 10, 40, 1000)] == [3, 12, 44, 1100]
    assert deploy.batch_cap(10 ** 6) == 100000


# ----------------------------------------------------------------------------- API
@pytest.fixture()
def admin(bundle, empty_client):  # noqa: F811 - pytest fixture
    from app.api import devices as devices_api

    devices_api.installer_limiter.reset()
    return empty_client


def mac(n: int, name: str, ou: str = "OU=Macs") -> dict:
    c = computer(n, name, ou=ou)
    c["operating_system"] = "macOS"
    return c


def add_record(source_id: str, ext: str, name: str, kind: str, platform: str, *, expected: bool = True,
               os_name: str = "") -> None:
    with db.get_session("default") as s:
        s.add(DirectoryComputer(source_id=source_id, external_id=ext, name=name, short_name=name.lower(),
                                device_kind=kind, platform=platform, agent_expected=expected,
                                operating_system=os_name or platform.title(), enabled=True, last_logon_at=utcnow()))
        s.commit()


def reconcile_now(org: str = "default") -> None:
    with db.get_session(org) as s:
        reconcile.reconcile(s)


@pytest.fixture()
def estate(admin, collector):  # noqa: F811 - pytest fixture
    """An AD domain (collector + PC1, PC2 in two OUs, MAC1), plus an Intune macOS
    laptop, an Entra-only Windows laptop and a Chromebook added as cloud records."""
    agent, dev = collector
    src = make_source(admin, [dev])
    run_sync(admin, agent, src["id"], computers=[computer(1, "COLLECTOR1", rid=1100), computer(2, "PC1", rid=2001),
                                                 computer(3, "PC2", ou="OU=Desktops", rid=2002), mac(4, "MAC1")])
    add_record(src["id"], "mdm:1", "MBP-7", "intune", "macos")
    add_record(src["id"], "entra:1", "LT-ENTRA", "entra", "windows")
    add_record(src["id"], "cros:1", "CHROMEBOOK-1", "chromeos", "chromeos", expected=False, os_name="ChromeOS")
    reconcile_now()
    comps = {c["name"]: c["id"] for c in admin.get("/api/directory/computers?limit=100").json()["items"]}
    return src, comps


def plan_of(c, ids) -> dict:
    r = c.post("/api/directory/deployments/plan", json={"computer_ids": ids})
    assert r.status_code == 200, r.text
    return r.json()


def test_plan_groups_by_route(admin, estate):
    _, comps = estate
    p = plan_of(admin, list(comps.values()))
    routes = {g["route"]: sorted(i["name"] for i in g["items"]) for g in p["routes"]}
    assert routes == {"gpo": ["PC1", "PC2"], "intune": ["MBP-7"], "manual": ["LT-ENTRA", "MAC1"]}
    gpo = next(g for g in p["routes"] if g["route"] == "gpo")
    assert sorted((o["ou"], o["count"]) for o in gpo["ous"]) == [("OU=Desktops,DC=corp,DC=example,DC=com", 1),
                                                                 ("OU=Laptops,DC=corp,DC=example,DC=com", 1)]
    assert gpo["platforms"] == {"windows": 2}
    excluded = {g["reason"]: sorted(i["name"] for i in g["items"]) for g in p["excluded"]}
    assert excluded == {"has_agent": ["COLLECTOR1"], "mobile": ["CHROMEBOOK-1"]}
    assert (p["total"], p["deployable"]) == (7, 5)
    assert p["installers"]["macos-pkg"]["available"] is True
    # The same machines from the "No agent" issue filter (the collector has an agent).
    f = admin.post("/api/directory/deployments/plan", json={"use_filter": True, "issue_type": "not_managed"}).json()
    assert {i["name"] for g in f["routes"] for i in g["items"]} == {"PC1", "PC2", "MAC1", "MBP-7", "LT-ENTRA"}
    assert admin.post("/api/directory/deployments/plan", json={"use_filter": True, "issue_type": "privileged_stale"}
                      ).status_code == 422
    assert admin.post("/api/directory/deployments/plan", json={"computer_ids": ["e" * 32]}).status_code == 404
    assert admin.post("/api/directory/deployments/plan",
                      json={"computer_ids": [comps["PC1"]], "use_filter": True}).status_code == 422


def test_create_with_overrides_token_and_installer(admin, estate):
    _, comps = estate
    ids = [comps[n] for n in ("PC1", "PC2", "MAC1", "MBP-7", "CHROMEBOOK-1")]
    bad = admin.post("/api/directory/deployments", json={"name": "Wave 1", "computer_ids": ids,
                                                         "routes": {comps["MBP-7"]: "gpo"}})
    assert bad.status_code == 422 and "not possible" in bad.text  # a Mac cannot get a GPO
    r = admin.post("/api/directory/deployments", json={
        "name": "Wave 1", "computer_ids": ids, "routes": {comps["PC2"]: "rmm"}, "expires_in_days": 7,
        "device_group": "Wave 1", "command_line_token": True})
    assert r.status_code == 201, r.text
    dep = r.json()
    token = dep["token"]
    assert token.startswith("cne_")
    assert dep["route_counts"] == {"gpo": 1, "rmm": 1, "manual": 1, "intune": 1}
    assert dep["excluded_counts"] == {"mobile": 1}
    assert dep["progress"] == {"total": 4, "enrolled": 0, "pending": 4, "gone": 0, "pct": 0.0,
                               "enrolled_with_tokens": 0, "age_days": 0}
    assert [t["max_uses"] for t in dep["tokens"]] == [deploy.batch_cap(4)]
    assert dep["tokens"][0]["state"] == "active" and dep["expires_at"].endswith("Z")
    # Shown once: never stored or returned again.
    assert token not in all_db_text()
    again = admin.get(f"/api/directory/deployments/{dep['id']}").json()
    assert "token" not in again and token not in str(again)
    with db.get_session("default") as s:
        t = s.get(EnrollmentToken, dep["tokens"][0]["id"])
        assert t.device_group == "Wave 1" and t.package_platform is None
        assert abs((t.expires_at - t.created_at).days - 7) <= 1
    # Installer for the deployment's Macs: its own package-bound token, capped to them.
    pkg = admin.post(f"/api/directory/deployments/{dep['id']}/installer", json={"platform": "macos-pkg"})
    assert pkg.status_code == 200, pkg.text
    assert pkg.headers["content-disposition"].endswith('"cnapp-agent-setup.pkg"')
    tok = pkg.headers["x-enrollment-token-id"]
    detail = admin.get(f"/api/directory/deployments/{dep['id']}").json()
    by_id = {t["id"]: t for t in detail["tokens"]}
    assert by_id[tok]["package_platform"] == "macos-pkg" and by_id[tok]["max_uses"] == deploy.batch_cap(2)
    # Windows machines exist but this server has no MSI bundled in this test: 503 / 422 for an OS not in the batch.
    only_win = admin.post("/api/directory/deployments", json={"name": "Win", "computer_ids": [comps["PC1"]]}).json()
    assert "token" not in only_win and only_win["tokens"] == []
    assert admin.post(f"/api/directory/deployments/{only_win['id']}/installer",
                      json={"platform": "macos-pkg"}).status_code == 422
    # Nothing deployable.
    none = admin.post("/api/directory/deployments", json={"name": "x", "computer_ids": [comps["CHROMEBOOK-1"]]})
    assert none.status_code == 422 and "none of the selected machines can get the agent" in none.text
    with db.get_session("default") as s:
        actions = [a.action for a in s.scalars(select(AuditLog))]
        detail_rows = [a.detail for a in s.scalars(select(AuditLog).where(AuditLog.action == "agent_installer_created"))]
    assert actions.count("agent_deployment_created") == 2
    assert detail_rows[-1]["deployment_id"] == dep["id"]


def test_progress_via_matching_and_revoke(admin, estate):
    _, comps = estate
    dep = admin.post("/api/directory/deployments", json={
        "name": "Laptops", "computer_ids": [comps["PC1"], comps["PC2"]], "command_line_token": True}).json()
    # PC1 enrolls with the deployment's token; the next matching run links it.
    agent = agent_client(admin.app)
    e = enroll(agent, dep["token"], machine_id="5" * 64, hostname="PC1")
    assert e.status_code == 200, e.text
    agent.headers["Authorization"] = f"Bearer {e.json()['device_secret']}"
    checkin(agent, "PC1", join_facts=join("PC1", 2001))
    pending = admin.get(f"/api/directory/deployments/{dep['id']}").json()
    assert pending["progress"]["enrolled"] == 0 and pending["progress"]["enrolled_with_tokens"] == 1
    reconcile_now()
    got = admin.get(f"/api/directory/deployments/{dep['id']}").json()
    assert got["progress"]["enrolled"] == 1 and got["progress"]["pending"] == 1 and got["progress"]["pct"] == 50.0
    pc1 = next(i for i in got["items"] if i["name"] == "PC1")
    assert pc1["status"] == "enrolled" and pc1["via_deployment"] is True and pc1["device_hostname"] == "PC1"
    assert next(i for i in got["items"] if i["name"] == "PC2")["status"] == "pending"
    listed = admin.get("/api/directory/deployments").json()
    assert [d["progress"]["enrolled"] for d in listed] == [1] and "items" not in listed[0]
    # Revoke: its tokens stop enrolling; enrolled devices stay.
    r = admin.post(f"/api/directory/deployments/{dep['id']}/revoke")
    assert r.status_code == 200 and r.json()["state"] == "revoked"
    assert r.json()["tokens"][0]["state"] == "revoked"
    assert enroll(agent_client(admin.app), dep["token"], machine_id="6" * 64, hostname="PC2").status_code in (401, 403)
    assert admin.post(f"/api/directory/deployments/{dep['id']}/installer",
                      json={"platform": "macos-pkg"}).status_code == 409
    assert admin.get(f"/api/directory/deployments/{dep['id']}").json()["progress"]["enrolled"] == 1
    with db.get_session("default") as s:
        rev = s.scalars(select(AuditLog).where(AuditLog.action == "agent_deployment_revoked")).one()
        assert rev.detail["tokens_revoked"] == 1 and rev.actor_email


def test_rbac(admin, estate):
    _, comps = estate
    dep = admin.post("/api/directory/deployments", json={"name": "w", "computer_ids": [comps["PC1"]]}).json()
    make_user(admin, "viewer", "viewer@example.com")
    viewer = agent_client(admin.app)
    login(viewer, "viewer@example.com", "a-long-test-password")
    assert viewer.get("/api/directory/deployments").status_code == 200
    assert viewer.get(f"/api/directory/deployments/{dep['id']}").json()["progress"]["total"] == 1
    for path, body in (("/api/directory/deployments/plan", {"computer_ids": [comps["PC1"]]}),
                       ("/api/directory/deployments", {"name": "x", "computer_ids": [comps["PC1"]]}),
                       (f"/api/directory/deployments/{dep['id']}/installer", {"platform": "macos-pkg"}),
                       (f"/api/directory/deployments/{dep['id']}/revoke", None)):
        assert viewer.post(path, **({"json": body} if body is not None else {})).status_code == 403, path


def test_tenant_isolation(admin, estate):
    _, comps = estate
    dep = admin.post("/api/directory/deployments", json={"name": "w", "computer_ids": [comps["MAC1"]]}).json()
    create_org("acme", ACME_ADMIN, ACME_PASSWORD)
    acme = org_client(admin.app, ACME_ADMIN, ACME_PASSWORD)
    assert acme.get("/api/directory/deployments").json() == []
    for method, path, body in (("get", f"/api/directory/deployments/{dep['id']}", None),
                               ("post", f"/api/directory/deployments/{dep['id']}/revoke", None),
                               ("post", f"/api/directory/deployments/{dep['id']}/installer", {"platform": "macos-pkg"}),
                               ("post", "/api/directory/deployments/plan", {"computer_ids": [comps["PC1"]]}),
                               ("post", "/api/directory/deployments", {"name": "x", "computer_ids": [comps["PC1"]]})):
        r = getattr(acme, method)(path, **({"json": body} if body is not None else {}))
        assert r.status_code == 404, (method, path, r.status_code)
    assert acme.post("/api/directory/deployments/plan", json={"use_filter": True}).status_code == 422
    assert admin.get(f"/api/directory/deployments/{dep['id']}").json()["state"] == "active"
    with db.get_session("default") as s:
        assert s.scalars(select(DirectorySource)).one()
