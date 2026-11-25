"""Device tracking (docs/DEVICE_TRACKING.md): IP lookup with a fixture MMDB (no network), private ranges, office
matching, history rows, retention, roles, tenancy, module gating, audit, and check-ins that never fail."""
from __future__ import annotations

from datetime import timedelta

import maxminddb
import pytest
from sqlalchemy import select

from app import db, geoip
from app.geoip import update as geoip_update
from app.models import AuditLog, Device, Organization, utcnow
from app.tracking import service
from app.tracking.models import DeviceLocation
from tests import mmdb_fixture as mm
from tests.test_devices import admin, device, windows_checkin  # noqa: F401 - fixtures
from tests.test_onboarding import add_member
from tests.test_tenancy import acme_device, org_client, tenants  # noqa: F401 - fixtures

CITY = {
    "8.8.8.0/24": mm.city("Springfield", "Region A", "US", "United States", 39.78, -89.65),
    "9.9.9.0/24": mm.city("Lyon", "Auvergne", "FR", "France", 45.76, 4.84, acc=10),
    "1.1.1.0/24": mm.city("Lyon", "Auvergne", "FR", "France", 45.76, 4.84, acc=10),
    "4.4.4.0/24": mm.city("Osaka", "Kansai", "JP", "Japan", 34.69, 135.5),
}
ASN = {"8.8.8.0/24": mm.asn(64500, "Example Telecom"), "9.9.9.0/24": mm.asn(64501, "Other ISP")}
SETTINGS = "/api/device-tracking/settings"


@pytest.fixture(autouse=True)
def fixture_db(tmp_path):
    (tmp_path / "city.mmdb").write_bytes(mm.build(CITY))
    (tmp_path / "asn.mmdb").write_bytes(mm.build(ASN))
    geoip.set_readers(maxminddb.open_database(str(tmp_path / "city.mmdb")),
                      maxminddb.open_database(str(tmp_path / "asn.mmdb")))
    yield tmp_path
    geoip.reset()


@pytest.fixture()
def seen_ip(monkeypatch):
    """Control the public address the server sees for agent requests."""
    holder = {"ip": "8.8.8.8"}
    monkeypatch.setattr("app.api.agent.client_ip", lambda request: holder["ip"])
    return holder


def checkin(agent, ip_holder, ip):
    ip_holder["ip"] = ip
    r = agent.post("/api/agent/checkin", json=windows_checkin())
    assert r.status_code == 200, r.text


def rows(device_id):
    with db.get_session("default") as s:
        return list(s.scalars(select(DeviceLocation).where(DeviceLocation.device_id == device_id)
                              .order_by(DeviceLocation.first_seen_at)))


# --------------------------------------------------------------------------- lookup
def test_lookup_fixture_database():
    g = geoip.lookup("8.8.8.8")
    assert g.available and g.city == "Springfield" and g.country_code == "US" and g.region == "Region A"
    assert g.asn == 64500 and g.provider == "Example Telecom" and g.accuracy_km == 25.0
    assert geoip.lookup("9.9.9.9").accuracy_km == 10.0
    unknown = geoip.lookup("7.7.7.7")
    assert not unknown.available and not unknown.is_private


@pytest.mark.parametrize("ip", ["10.1.2.3", "192.168.0.9", "127.0.0.1", "100.64.1.1", "100.127.255.1", "169.254.1.1",
                                "192.0.2.5", "198.51.100.7", "203.0.113.9", "::1", "2001:db8::1", "fe80::1"])
def test_private_loopback_cgnat_documentation_are_not_looked_up(ip):
    g = geoip.lookup(ip)
    assert g.is_private and not g.available and g.city is None


def test_missing_database_never_raises():
    geoip.set_readers(None, None)
    g = geoip.lookup("8.8.8.8")
    assert not g.available and not geoip.database_available()


def test_lookup_cache_and_reader_failure(monkeypatch):
    class Boom:
        def get(self, ip):
            raise RuntimeError("corrupt")

    geoip.set_readers(Boom(), Boom())
    assert not geoip.lookup("8.8.8.8").available


# --------------------------------------------------------------------------- offices
def test_office_matching_single_ip_and_cidr(admin):  # noqa: F811
    r = admin.post("/api/device-tracking/offices", json={"name": "HQ", "networks": ["8.8.8.8", "9.9.0.0/16", "8.8.8.8"],
                                                          "timezone": "Europe/Paris"})
    assert r.status_code == 201, r.text
    assert r.json()["networks"] == ["8.8.8.8", "9.9.0.0/16"]
    with db.get_session("default") as s:
        offs = service.offices(s)
        assert service.match_office(offs, "8.8.8.8").name == "HQ"
        assert service.match_office(offs, "9.9.200.1").name == "HQ"
        assert service.match_office(offs, "8.8.8.9") is None
        assert service.match_office(offs, "not-an-ip") is None


def test_office_validation(admin):  # noqa: F811
    url = "/api/device-tracking/offices"
    assert admin.post(url, json={"name": "A", "networks": ["nope"]}).status_code == 422
    assert admin.post(url, json={"name": "A", "networks": ["0.0.0.0/0"]}).status_code == 422
    assert admin.post(url, json={"name": "A", "networks": [f"8.8.{i}.1" for i in range(51)]}).status_code == 422
    assert admin.post(url, json={"name": "A", "networks": ["8.8.8.8"], "timezone": "Mars/Base"}).status_code == 422
    assert admin.post(url, json={"name": "A", "networks": ["8.8.8.8"]}).status_code == 201
    assert admin.post(url, json={"name": "a", "networks": []}).status_code == 409


def test_office_edit_delete_and_audit(admin):  # noqa: F811
    o = admin.post("/api/device-tracking/offices", json={"name": "HQ", "networks": ["8.8.8.8"]}).json()
    r = admin.patch(f"/api/device-tracking/offices/{o['id']}", json={"networks": ["9.9.9.0/24"], "timezone": "Asia/Tokyo"})
    assert r.status_code == 200 and r.json()["networks"] == ["9.9.9.0/24"] and r.json()["timezone"] == "Asia/Tokyo"
    r = admin.patch(f"/api/device-tracking/offices/{o['id']}", json={"clear_timezone": True})
    assert r.json()["timezone"] is None
    assert admin.delete(f"/api/device-tracking/offices/{o['id']}").status_code == 204
    assert admin.get("/api/device-tracking/offices").json() == []
    with db.get_session("default") as s:
        actions = [a.action for a in s.scalars(select(AuditLog).order_by(AuditLog.id))]
    for a in ("tracking_office_created", "tracking_office_changed", "tracking_office_deleted"):
        assert a in actions


# --------------------------------------------------------------------------- recording
def test_disabled_by_default_records_nothing(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    checkin(agent, seen_ip, "8.8.8.8")
    assert rows(did) == []
    st = admin.get(SETTINGS).json()
    assert st["enabled"] is False and st["timezone"] == "UTC" and st["allowed_countries"] == []
    loc = admin.get(f"/api/devices/{did}/location").json()
    assert loc["enabled"] is False and loc["current"] is None


def test_history_rows_and_last_seen_update(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    assert admin.put(SETTINGS, json={"enabled": True}).status_code == 200
    checkin(agent, seen_ip, "8.8.8.8")
    checkin(agent, seen_ip, "8.8.8.8")  # same place: only last_seen_at moves
    r = rows(did)
    assert len(r) == 1 and r[0].city == "Springfield" and r[0].provider == "Example Telecom"
    first_last = r[0].last_seen_at
    checkin(agent, seen_ip, "8.8.8.8")
    assert len(rows(did)) == 1 and rows(did)[0].last_seen_at >= first_last
    checkin(agent, seen_ip, "9.9.9.9")  # new address and city
    checkin(agent, seen_ip, "10.0.0.7")  # private network
    assert [x.city for x in rows(did)] == ["Springfield", "Lyon", None]
    assert rows(did)[2].is_private
    # Poll path records too.
    seen_ip["ip"] = "4.4.4.4"
    assert agent.get("/api/agent/commands").status_code == 200
    assert rows(did)[-1].city == "Osaka"


def test_office_arrival_and_events(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    admin.post("/api/device-tracking/offices", json={"name": "Head office", "networks": ["8.8.8.0/24"]})
    admin.put(SETTINGS, json={"enabled": True})
    checkin(agent, seen_ip, "8.8.8.8")
    checkin(agent, seen_ip, "9.9.9.9")
    checkin(agent, seen_ip, "4.4.4.4")
    loc = admin.get(f"/api/devices/{did}/location").json()
    assert loc["current"]["city"] == "Osaka" and loc["current"]["network"] == "away"
    kinds = [(e["kind"], e["office"] or e["city"]) for e in loc["history"]]
    assert kinds == [("new_country", "Osaka"), ("new_country", "Lyon"), ("arrived", "Head office")]
    offices = admin.get("/api/device-tracking/offices").json()
    assert offices[0]["devices_now"] == 0
    checkin(agent, seen_ip, "8.8.8.8")
    assert admin.get("/api/device-tracking/offices").json()[0]["devices_now"] == 1
    assert admin.get(f"/api/devices/{did}/location").json()["current"]["office"] == "Head office"


def test_linux_and_server_devices_are_skipped(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    admin.put(SETTINGS, json={"enabled": True})
    with db.get_session("default") as s:
        d = s.get(Device, did)
        d.device_class = "server"
        assert not service.qualifies(d)
        d.device_class = "domain_controller"
        assert not service.qualifies(d)
        d.device_class = "workstation"
        d.os_family = "linux"
        assert not service.qualifies(d)
        d.os_family = "macos"
        assert service.qualifies(d)
        d.os_family = "windows"
        s.commit()
    seen_ip["ip"] = "8.8.8.8"
    body = windows_checkin()
    body["device"]["classification"] = {"role": "server"}  # the agent reports a server
    assert agent.post("/api/agent/checkin", json=body).status_code == 200
    assert rows(did) == []
    loc = admin.get(f"/api/devices/{did}/location").json()
    assert loc["eligible"] is False and loc["current"] is None
    assert admin.post(f"/api/devices/{did}/location/refresh").status_code == 409


def test_checkin_never_fails_when_lookup_raises(admin, device, seen_ip, monkeypatch):  # noqa: F811
    agent, did = device
    admin.put(SETTINGS, json={"enabled": True})

    def boom(ip):
        raise RuntimeError("lookup exploded")

    monkeypatch.setattr(geoip, "lookup", boom)
    checkin(agent, seen_ip, "8.8.8.8")
    assert rows(did) == []
    assert agent.get("/api/agent/commands").status_code == 200


def test_retention_pruning(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    admin.put(SETTINGS, json={"enabled": True})
    checkin(agent, seen_ip, "8.8.8.8")
    now = utcnow()
    with db.get_session("default") as s:
        d = s.get(Device, did)
        old = DeviceLocation(device_id=did, first_seen_at=now - timedelta(days=120),
                             last_seen_at=now - timedelta(days=100), ip="9.9.9.9", city="Lyon")
        s.add(old)
        s.commit()
        assert service.prune(s, now) == 1
        s.commit()
        assert d.location_id is not None
    assert [x.city for x in rows(did)] == ["Springfield"]
    # A device whose newest row aged out loses its pointer instead of dangling.
    with db.get_session("default") as s:
        assert service.prune(s, now + timedelta(days=91)) == 1
        s.commit()
        assert s.get(Device, did).location_id is None


# --------------------------------------------------------------------------- API: roles, settings, audit
def test_settings_validation_roles_and_audit(admin, device):  # noqa: F811
    from tests.conftest import login, make_user

    assert admin.put(SETTINGS, json={"timezone": "Mars/Base"}).status_code == 422
    assert admin.put(SETTINGS, json={"allowed_countries": ["ZZ"]}).status_code == 422
    r = admin.put(SETTINGS, json={"enabled": True, "timezone": "Asia/Tokyo", "allowed_countries": ["jp", "US", "jp"]})
    assert r.status_code == 200 and r.json()["allowed_countries"] == ["JP", "US"] and r.json()["enabled"] is True
    assert admin.put(SETTINGS, json={"enabled": True}).status_code == 200  # no change: no audit entry
    with db.get_session("default") as s:
        entries = list(s.scalars(select(AuditLog).where(AuditLog.action == "device_tracking_settings_changed")))
    assert len(entries) == 1 and entries[0].detail["changes"]["timezone"] == ["UTC", "Asia/Tokyo"]
    make_user(admin, "viewer")
    make_user(admin, "analyst")
    from fastapi.testclient import TestClient

    from tests.conftest import BASE_URL

    for role, can_read in (("viewer", False), ("analyst", True)):
        c = TestClient(admin.app, base_url=BASE_URL)
        login(c, f"{role}@example.com", "a-long-test-password")
        assert (c.get(SETTINGS).status_code == 200) is can_read
        assert c.put(SETTINGS, json={"enabled": False}).status_code == 403
        assert c.get("/api/device-tracking/offices").status_code == 403
        assert c.post("/api/device-tracking/offices", json={"name": "x", "networks": []}).status_code == 403


def test_viewer_sees_city_and_country_only(admin, device, seen_ip):  # noqa: F811
    from fastapi.testclient import TestClient

    from tests.conftest import BASE_URL, login, make_user

    agent, did = device
    admin.put(SETTINGS, json={"enabled": True})
    checkin(agent, seen_ip, "8.8.8.8")
    make_user(admin, "viewer")
    make_user(admin, "analyst")
    full = admin.get(f"/api/devices/{did}/location").json()
    assert full["detail"] == "full" and full["current"]["ip"] == "8.8.8.8" and full["current"]["latitude"] == 39.78
    assert full["current"]["provider"] == "Example Telecom"
    v = TestClient(admin.app, base_url=BASE_URL)
    login(v, "viewer@example.com", "a-long-test-password")
    loc = v.get(f"/api/devices/{did}/location").json()
    assert loc["detail"] == "basic" and loc["current"]["city"] == "Springfield" and loc["current"]["country"] == "United States"
    for hidden in ("ip", "latitude", "longitude", "accuracy_km", "provider", "asn", "region"):
        assert hidden not in loc["current"]
        assert all(hidden not in e for e in loc["history"])
    assert v.post(f"/api/devices/{did}/location/refresh").status_code == 403
    a = TestClient(admin.app, base_url=BASE_URL)
    login(a, "analyst@example.com", "a-long-test-password")
    assert a.get(f"/api/devices/{did}/location").json()["current"]["ip"] == "8.8.8.8"
    assert a.post(f"/api/devices/{did}/location/refresh").status_code == 202


def test_locate_now_queues_recheck(admin, device):  # noqa: F811
    agent, did = device
    assert admin.post(f"/api/devices/{did}/location/refresh").status_code == 409  # tracking off
    admin.put(SETTINGS, json={"enabled": True})
    r = admin.post(f"/api/devices/{did}/location/refresh")
    assert r.status_code == 202 and r.json()["status"] == "queued"
    cmds = admin.get(f"/api/devices/{did}/commands").json()
    assert cmds[0]["type"] == "recheck_posture" and cmds[0]["reason"] == "Locate now"


def test_history_days_parameter(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    admin.put(SETTINGS, json={"enabled": True})
    checkin(agent, seen_ip, "8.8.8.8")
    with db.get_session("default") as s:
        s.add(DeviceLocation(device_id=did, first_seen_at=utcnow() - timedelta(days=30),
                             last_seen_at=utcnow() - timedelta(days=29), ip="9.9.9.9", city="Lyon", country_code="FR"))
        s.commit()
    assert len(admin.get(f"/api/devices/{did}/location").json()["history"]) == 1
    assert len(admin.get(f"/api/devices/{did}/location?days=60").json()["history"]) == 2
    assert admin.get(f"/api/devices/{did}/location?days=0").status_code == 422


# --------------------------------------------------------------------------- tenancy and modules
def test_tenancy_isolation(tenants, seen_ip):  # noqa: F811
    t = tenants
    a_agent, a_dev = acme_device(t)
    t.acme.put(SETTINGS, json={"enabled": True})
    t.acme.post("/api/device-tracking/offices", json={"name": "Acme HQ", "networks": ["8.8.8.8"]})
    checkin(a_agent, seen_ip, "8.8.8.8")
    assert t.acme.get(f"/api/devices/{a_dev}/location").json()["current"]["office"] == "Acme HQ"
    # The default organisation cannot see Acme's device, offices or settings.
    assert t.default.get(f"/api/devices/{a_dev}/location").status_code == 404
    assert t.default.post(f"/api/devices/{a_dev}/location/refresh").status_code == 404
    assert t.default.get("/api/device-tracking/offices").json() == []
    assert t.default.get(SETTINGS).json()["enabled"] is False
    oid = t.acme.get("/api/device-tracking/offices").json()[0]["id"]
    assert t.default.patch(f"/api/device-tracking/offices/{oid}", json={"name": "x"}).status_code == 404
    assert t.default.delete(f"/api/device-tracking/offices/{oid}").status_code == 404


def test_module_gating(tenants):  # noqa: F811
    with db.get_session(unscoped=True) as s:
        org = s.get(Organization, tenants.acme_id)
        org.modules = ["cloud"]
        s.commit()
    assert tenants.acme.get(SETTINGS).status_code == 403
    assert tenants.acme.get("/api/device-tracking/offices").status_code == 403


def test_viewer_role_in_other_org(tenants):  # noqa: F811
    add_member(tenants.acme_id, "viewer@acme.test", "viewer")
    c = org_client(tenants.acme.app, "viewer@acme.test", "a-long-member-password")
    assert c.get(SETTINGS).status_code == 403


# --------------------------------------------------------------------------- updater (no network)
def test_updater_installs_and_falls_back(tmp_path, monkeypatch):
    import gzip
    from datetime import UTC, datetime

    good = gzip.compress(mm.build(CITY))
    calls: list[str] = []

    def fetch(url):
        calls.append(url)
        if "2026-11" in url:
            raise OSError("404")
        return good

    dest = tmp_path / "sub" / "city.mmdb"
    assert geoip_update.install("city", str(dest), fetch, datetime(2026, 11, 3, tzinfo=UTC))
    assert calls[0].endswith("dbip-city-lite-2026-11.mmdb.gz") and calls[1].endswith("dbip-city-lite-2026-10.mmdb.gz")
    assert dest.exists()
    # A corrupt download leaves the existing file alone.
    bad = gzip.compress(b"not a database")
    before = dest.read_bytes()
    assert not geoip_update.install("city", str(dest), lambda u: bad, datetime(2026, 11, 3, tzinfo=UTC))
    assert dest.read_bytes() == before
    assert not list(dest.parent.glob("*.part"))
