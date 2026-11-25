# ruff: noqa: F811
"""Device tracking B (docs/DEVICE_TRACKING.md): the fleet map data and the alerts. Fixture MMDB, no network."""
from __future__ import annotations

from datetime import datetime, timedelta

import maxminddb
import pytest
from sqlalchemy import select

from app import db, geoip
from app.models import AuditLog, Device, DeviceCommand, Organization, utcnow
from app.notifications.models import NotificationEvent
from app.tracking import alerts, service
from app.tracking.alert_models import DeviceTrackingEvent, DeviceTrackingState
from app.tracking.worker import TrackingAlertWorker
from tests import mmdb_fixture as mm
from tests.test_device_tracking import SETTINGS, checkin  # noqa: F401 - fixtures live below
from tests.test_devices import admin, device, windows_checkin  # noqa: F401 - fixtures
from tests.test_tenancy import acme_device, tenants  # noqa: F401 - fixtures

CITY = {
    "8.8.8.0/24": mm.city("Springfield", "Region A", "US", "United States", 39.78, -89.65),
    "9.9.9.0/24": mm.city("Lyon", "Auvergne", "FR", "France", 45.76, 4.84, acc=10),
    "4.4.4.0/24": mm.city("Osaka", "Kansai", "JP", "Japan", 34.69, 135.5),
    "5.5.5.0/24": mm.city("Accra", "Greater Accra", "GH", "Ghana", 5.6, -0.19),
}
FLEET = "/api/device-tracking/fleet"
NOW = datetime(2026, 11, 25, 12, 0, 0)


@pytest.fixture(autouse=True)
def fixture_db(tmp_path):
    (tmp_path / "city.mmdb").write_bytes(mm.build(CITY))
    (tmp_path / "asn.mmdb").write_bytes(mm.build({}))
    geoip.set_readers(maxminddb.open_database(str(tmp_path / "city.mmdb")),
                      maxminddb.open_database(str(tmp_path / "asn.mmdb")))
    yield
    geoip.reset()


@pytest.fixture()
def seen_ip(monkeypatch):
    holder = {"ip": "8.8.8.8"}
    monkeypatch.setattr("app.api.agent.client_ip", lambda request: holder["ip"])
    return holder


def observe_at(did: str, ip: str, now: datetime, org: str = "default") -> None:
    with db.get_session(org) as s:
        d = s.get(Device, did)
        d.last_ip = ip
        service.observe(s, d, now)
        s.commit()


def tracking_events(did: str | None = None, kind: str | None = None) -> list[DeviceTrackingEvent]:
    with db.get_session("default") as s:
        q = select(DeviceTrackingEvent).order_by(DeviceTrackingEvent.at)
        if did:
            q = q.where(DeviceTrackingEvent.device_id == did)
        if kind:
            q = q.where(DeviceTrackingEvent.kind == kind)
        return list(s.scalars(q))


def notifications(kind: str | None = None) -> list[NotificationEvent]:
    with db.get_session("default") as s:
        q = select(NotificationEvent).where(NotificationEvent.source == "device_tracking")
        if kind:
            q = q.where(NotificationEvent.event_type == kind)
        return list(s.scalars(q))


def configure(admin, **body):
    body.setdefault("enabled", True)
    r = admin.put(SETTINGS, json=body)
    assert r.status_code == 200, r.text
    return r.json()


def second_device(admin, hostname: str, machine: str, group: str | None = None) -> tuple:
    from tests.test_devices import agent_client, enroll, new_token

    agent = agent_client(admin.app)
    r = enroll(agent, new_token(admin), machine_id=machine, hostname=hostname)
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    body = windows_checkin()
    body["device"]["hostname"] = hostname
    assert agent.post("/api/agent/checkin", json=body).status_code == 200
    return agent, r.json()["device_id"]


# --------------------------------------------------------------------------- fleet map
def test_fleet_off_and_empty(admin, device):  # noqa: F811
    r = admin.get(FLEET)
    assert r.status_code == 200 and r.json()["enabled"] is False and r.json()["cities"] == []


def test_fleet_aggregation_tiles_and_filters(admin, device, seen_ip):  # noqa: F811
    agent, d1 = device
    a2, d2 = second_device(admin, "FIN-LT-021", "b" * 64)
    a3, d3 = second_device(admin, "FIN-LT-022", "c" * 64)
    admin.post("/api/device-tracking/offices", json={"name": "HQ", "networks": ["8.8.8.0/24"]})
    configure(admin, allowed_countries=["US"], alert_not_seen_days=7)
    checkin(agent, seen_ip, "8.8.8.8")  # at the office
    seen_ip["ip"] = "9.9.9.9"
    for ag, name in ((a2, "FIN-LT-021"), (a3, "FIN-LT-022")):  # both in Lyon: outside US
        body = windows_checkin()
        body["device"]["hostname"] = name
        assert ag.post("/api/agent/checkin", json=body).status_code == 200
    with db.get_session("default") as s:
        s.get(Device, d3).last_seen_at = utcnow() - timedelta(days=9)
        s.get(Device, d3).device_group = "Finance"
        s.commit()
    f = admin.get(FLEET).json()
    assert f["enabled"] and f["detail"] == "full"
    assert f["tiles"] == {"at_office": 1, "away": 2, "outside_countries": 2, "missing": 0, "unlocated": 0}
    by_city = {c["city"]: c for c in f["cities"]}
    assert by_city["Lyon"]["count"] == 2 and by_city["Lyon"]["flagged"] is True
    assert by_city["Springfield"]["count"] == 1 and by_city["Springfield"]["flagged"] is False
    assert by_city["Lyon"]["latitude"] == pytest.approx(45.76)
    row = {x["hostname"]: x for x in f["devices"]}
    assert row["FIN-LT-021"]["network"] == "away" and row["FIN-LT-021"]["outside_countries"] is True
    assert row["LAPTOP-001"]["office"] == "HQ" and row["FIN-LT-022"]["not_seen"] is True
    assert f["groups"] == ["Finance"]
    only = admin.get(FLEET + "?not_seen=true").json()
    assert [x["hostname"] for x in only["devices"]] == ["FIN-LT-022"] and len(only["cities"]) == 1
    assert [x["hostname"] for x in admin.get(FLEET + "?group=Finance").json()["devices"]] == ["FIN-LT-022"]
    assert {x["hostname"] for x in admin.get(FLEET + "?status=active").json()["devices"]} == {
        "LAPTOP-001", "FIN-LT-021"}
    assert admin.get(FLEET + "?status=bogus").status_code == 422
    # Lost mode counts as missing (until the missing-device mode exists).
    with db.get_session("default") as s:
        s.get(Device, d2).lost_mode_status = "active"
        s.commit()
    assert admin.get(FLEET).json()["tiles"]["missing"] == 1


def test_fleet_viewer_gets_no_coordinates(admin, device, seen_ip):  # noqa: F811
    from fastapi.testclient import TestClient

    from tests.conftest import BASE_URL, login, make_user

    agent, did = device
    configure(admin)
    checkin(agent, seen_ip, "8.8.8.8")
    make_user(admin, "viewer")
    v = TestClient(admin.app, base_url=BASE_URL)
    login(v, "viewer@example.com", "a-long-test-password")
    f = v.get(FLEET).json()
    assert f["detail"] == "basic" and f["cities"][0]["city"] == "Springfield"
    text = str(f)
    for hidden in ("latitude", "longitude", "8.8.8.8", "Example"):
        assert hidden not in text
    assert "ip" not in f["devices"][0]


def test_fleet_tenancy_isolation(tenants, seen_ip):  # noqa: F811
    t = tenants
    a_agent, a_dev = acme_device(t)
    t.acme.put(SETTINGS, json={"enabled": True})
    checkin(a_agent, seen_ip, "8.8.8.8")
    assert [x["id"] for x in t.acme.get(FLEET).json()["devices"]] == [a_dev]
    assert t.default.get(FLEET).json()["enabled"] is False  # the other organisation: tracking off, no devices
    t.default.put(SETTINGS, json={"enabled": True})
    assert t.default.get(FLEET).json()["devices"] == []


def test_fleet_module_gating(tenants):  # noqa: F811
    with db.get_session(unscoped=True) as s:
        s.get(Organization, tenants.acme_id).modules = ["cloud"]
        s.commit()
    assert tenants.acme.get(FLEET).status_code == 403


# --------------------------------------------------------------------------- outside allowed countries
def test_outside_countries_alert_and_dedup(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    configure(admin, allowed_countries=["US"], alert_outside_countries=True)
    observe_at(did, "8.8.8.8", NOW)  # allowed
    assert tracking_events(did) == []
    observe_at(did, "5.5.5.5", NOW + timedelta(minutes=5))  # Accra
    ev = tracking_events(did, "outside_countries")
    assert len(ev) == 1 and ev[0].title == "LAPTOP-001 connected from Accra, Ghana" and ev[0].severity == "high"
    n = notifications("outside_countries")
    assert len(n) == 1 and n[0].severity == "high" and n[0].title == ev[0].title and n[0].rule_id == "outside_countries"
    assert "5.5.5.5" not in n[0].summary + n[0].title + str(n[0].attributes)
    observe_at(did, "5.5.5.5", NOW + timedelta(minutes=10))  # same place: nothing new
    observe_at(did, "8.8.8.8", NOW + timedelta(minutes=20))
    observe_at(did, "5.5.5.5", NOW + timedelta(minutes=30))  # back again within the rate limit window
    assert len(tracking_events(did, "outside_countries")) == 1
    observe_at(did, "8.8.8.8", NOW + timedelta(hours=7))
    observe_at(did, "5.5.5.5", NOW + timedelta(hours=8))  # later: alerted again
    assert len(tracking_events(did, "outside_countries")) == 2
    # It also shows in the device's location history, for viewers as city and country only.
    hist = admin.get(f"/api/devices/{did}/location?days=90").json()["history"]
    alerts_in_history = [e for e in hist if e.get("alert")]
    assert alerts_in_history and alerts_in_history[0]["title"].startswith("LAPTOP-001 connected from Accra")
    assert "ip" not in alerts_in_history[0]


def test_outside_countries_silent_cases(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    configure(admin, allowed_countries=["US"], alert_outside_countries=False)  # toggle off
    observe_at(did, "5.5.5.5", NOW)
    assert tracking_events(did) == []
    configure(admin, allowed_countries=[], alert_outside_countries=True)  # no country rule
    observe_at(did, "9.9.9.9", NOW + timedelta(hours=1))
    assert tracking_events(did) == []
    configure(admin, allowed_countries=["US"])
    admin.post("/api/device-tracking/offices", json={"name": "Paris", "networks": ["4.4.4.0/24"]})
    observe_at(did, "4.4.4.4", NOW + timedelta(hours=2))  # an office is never "outside"
    assert tracking_events(did) == []


def test_alerts_silent_when_tracking_off_or_module_off(tenants, seen_ip):  # noqa: F811
    t = tenants
    a_agent, a_dev = acme_device(t)
    t.acme.put(SETTINGS, json={"enabled": True, "allowed_countries": ["US"], "alert_outside_countries": True,
                               "alert_hardware_changed": True, "alert_after_hours": True})
    t.acme.put(SETTINGS, json={"enabled": False})
    observe_at(a_dev, "5.5.5.5", NOW, org=tenants.acme_id)
    t.acme.put(SETTINGS, json={"enabled": True})
    with db.get_session(unscoped=True) as s:
        s.get(Organization, tenants.acme_id).modules = ["cloud"]
        s.commit()
    observe_at(a_dev, "5.5.5.5", NOW + timedelta(hours=1), org=tenants.acme_id)
    with db.get_session(unscoped=True) as s:
        assert s.scalar(select(DeviceTrackingEvent.id)) is None
        assert s.scalar(select(NotificationEvent.id).where(NotificationEvent.source == "device_tracking")) is None


# --------------------------------------------------------------------------- not seen for N days
def tick(now: datetime):
    worker = TrackingAlertWorker()
    try:
        return worker.tick(now)
    finally:
        worker.stop()


def set_last_seen(did: str, when: datetime) -> None:
    with db.get_session("default") as s:
        s.get(Device, did).last_seen_at = when
        s.commit()


def test_not_seen_alert_once_per_absence(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    configure(admin, alert_not_seen_days=7)
    observe_at(did, "9.9.9.9", NOW - timedelta(days=9))
    set_last_seen(did, NOW - timedelta(days=6))
    assert tick(NOW) == {}  # only 6 days
    set_last_seen(did, NOW - timedelta(days=8))
    assert tick(NOW) == {"default": {"not_seen": 1, "agent_stopped": 0}}
    assert tick(NOW + timedelta(days=1)) == {}  # same absence: once
    ev = tracking_events(did, "not_seen")
    assert len(ev) == 1 and ev[0].title == "LAPTOP-001 has not been seen for 8 days (last seen in Lyon, France)"
    assert len(notifications("not_seen")) == 1
    # It comes back, then goes quiet again: a new absence.
    set_last_seen(did, NOW + timedelta(days=1))
    set_last_seen(did, NOW + timedelta(days=1))
    assert tick(NOW + timedelta(days=2)) == {}
    assert tick(NOW + timedelta(days=20))["default"]["not_seen"] == 1


def test_not_seen_off_revoked_and_ancient(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    set_last_seen(did, NOW - timedelta(days=30))
    configure(admin, alert_not_seen_days=None)  # off
    assert tick(NOW) == {}
    configure(admin, alert_not_seen_days=7)
    set_last_seen(did, NOW - timedelta(days=400))  # retired machine
    assert tick(NOW) == {}
    set_last_seen(did, NOW - timedelta(days=30))
    with db.get_session("default") as s:
        s.get(Device, did).status = "revoked"
        s.commit()
    assert tick(NOW) == {}
    assert tracking_events() == []
    configure(admin, enabled=False)
    with db.get_session("default") as s:
        s.get(Device, did).status = "active"
        s.commit()
    assert tick(NOW) == {}  # tracking off


# --------------------------------------------------------------------------- after hours (time zones)
@pytest.mark.parametrize("tz,utc,expected", [
    ("Europe/London", datetime(2026, 7, 1, 19, 30), "2026-07-01"),  # BST: 20:30 local, night starts that day
    ("Europe/London", datetime(2026, 7, 1, 17, 30), None),  # 18:30 local: office hours
    ("Europe/London", datetime(2026, 12, 2, 5, 0), "2026-12-01"),  # 05:00 GMT: still the night of the 1st
    ("America/Toronto", datetime(2026, 7, 1, 22, 30), None),  # 18:30 EDT
    ("America/Toronto", datetime(2026, 7, 1, 23, 30), "2026-07-01"),  # 19:30 EDT
    ("America/Toronto", datetime(2026, 12, 2, 12, 30), None),  # 07:30 EST: after the night
    ("America/Toronto", datetime(2026, 12, 2, 4, 30), "2026-12-01"),  # 23:30 EST
    ("Africa/Lagos", datetime(2026, 7, 1, 18, 30), "2026-07-01"),  # 19:30 WAT
    ("UTC", datetime(2026, 7, 1, 12, 0), None),
])
def test_night_key_time_zones(tz, utc, expected):
    assert alerts.night_key(utc, tz, "19:00", "07:00", [0, 1, 2, 3, 4, 5, 6]) == expected


def test_night_key_weekdays_and_same_day_window():
    sat = datetime(2026, 11, 28, 22, 0)  # a Saturday
    assert alerts.night_key(sat, "UTC", "19:00", "07:00", [0, 1, 2, 3, 4]) is None
    assert alerts.night_key(sat, "UTC", "19:00", "07:00", [5]) == "2026-11-28"
    # Sunday 03:00 belongs to Saturday's night.
    assert alerts.night_key(datetime(2026, 11, 29, 3, 0), "UTC", "19:00", "07:00", [5]) == "2026-11-28"
    assert alerts.night_key(datetime(2026, 11, 25, 13, 0), "UTC", "12:00", "14:00", [2]) == "2026-11-25"
    assert alerts.night_key(datetime(2026, 11, 25, 14, 0), "UTC", "12:00", "14:00", [2]) is None


def test_after_hours_alert_uses_last_office_zone(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    admin.post("/api/device-tracking/offices", json={
        "name": "Toronto office", "networks": ["8.8.8.0/24"], "timezone": "America/Toronto"})
    configure(admin, timezone="Europe/London", alert_after_hours=True, after_hours_start="19:00",
              after_hours_end="07:00")
    observe_at(did, "8.8.8.8", datetime(2026, 7, 1, 23, 0))  # at the office: never after-hours
    assert tracking_events(did) == []
    # Away at 22:30 UTC = 18:30 in Toronto (last office zone): office hours, no alert.
    observe_at(did, "9.9.9.9", datetime(2026, 7, 1, 22, 30))
    assert tracking_events(did) == []
    # 23:30 UTC = 19:30 in Toronto: the night starts, alert once.
    observe_at(did, "9.9.9.9", datetime(2026, 7, 1, 23, 30))
    observe_at(did, "9.9.9.9", datetime(2026, 7, 2, 1, 30))  # same night
    ev = tracking_events(did, "after_hours")
    assert len(ev) == 1 and "away from offices after hours (Lyon, France)" in ev[0].title
    assert len(notifications("after_hours")) == 1
    # Next evening: a new night (rate limit has passed).
    observe_at(did, "9.9.9.9", datetime(2026, 7, 2, 23, 30))
    assert len(tracking_events(did, "after_hours")) == 2


def test_after_hours_uses_org_zone_without_office_and_toggle(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    configure(admin, timezone="Europe/London", alert_after_hours=False)
    observe_at(did, "9.9.9.9", datetime(2026, 7, 1, 19, 30))
    assert tracking_events(did) == []  # toggle off
    configure(admin, alert_after_hours=True)
    observe_at(did, "9.9.9.9", datetime(2026, 7, 1, 17, 30))  # 18:30 BST
    assert tracking_events(did) == []
    observe_at(did, "9.9.9.9", datetime(2026, 7, 1, 19, 30))  # 20:30 BST
    assert len(tracking_events(did, "after_hours")) == 1
    configure(admin, after_hours_weekdays=[0])  # Mondays only; 2026-07-02 is a Thursday
    observe_at(did, "9.9.9.9", datetime(2026, 7, 2, 20, 30))
    assert len(tracking_events(did, "after_hours")) == 1


# --------------------------------------------------------------------------- hardware
def checkin_hw(agent, seen_ip, **device_over):
    body = windows_checkin()
    body["device"].update(device_over)
    seen_ip["ip"] = "9.9.9.9"
    assert agent.post("/api/agent/checkin", json=body).status_code == 200


def test_hardware_changed(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    configure(admin, alert_hardware_changed=True)
    checkin_hw(agent, seen_ip)  # first look: the baseline, no alert
    checkin_hw(agent, seen_ip)
    assert tracking_events(did) == []
    checkin_hw(agent, seen_ip, memory_bytes=8589934592)  # 16 GB -> 8 GB
    ev = tracking_events(did, "hardware_changed")
    assert len(ev) == 1 and "memory decreased (16 GB to 8 GB)" in ev[0].title and ev[0].title.startswith("LAPTOP-001")
    checkin_hw(agent, seen_ip, memory_bytes=8589934592)  # unchanged now: no repeat
    assert len(tracking_events(did, "hardware_changed")) == 1
    checkin_hw(agent, seen_ip, memory_bytes=17179869184)  # memory added back: not an alert
    assert len(tracking_events(did, "hardware_changed")) == 1
    assert len(notifications("hardware_changed")) == 1


def test_hardware_serial_model_and_disk_changes(admin, device, seen_ip, monkeypatch):  # noqa: F811
    agent, did = device
    monkeypatch.setattr(alerts, "MIN_GAP", {**alerts.MIN_GAP, "hardware_changed": timedelta(0)})
    configure(admin, alert_hardware_changed=True)
    checkin_hw(agent, seen_ip)
    checkin_hw(agent, seen_ip, serial_number="PF99999")
    checkin_hw(agent, seen_ip, serial_number="PF99999", model="20ZZ")
    disk = {"mount": "C:", "filesystem": "NTFS", "size_bytes": 256000000000, "free_bytes": 1}
    checkin_hw(agent, seen_ip, serial_number="PF99999", model="20ZZ", disks=[disk])
    titles = [e.title for e in tracking_events(did, "hardware_changed")]
    assert any("serial number changed" in t for t in titles)
    assert any("system maker or model changed" in t for t in titles)
    assert any("disk C: size changed" in t for t in titles)
    # A removed disk counts only when it was there for a while (a USB stick is never "removed").
    usb = {"mount": "E:", "filesystem": "FAT32", "size_bytes": 64000000000, "free_bytes": 1}
    keep = dict(serial_number="PF99999", model="20ZZ")
    checkin_hw(agent, seen_ip, disks=[disk, usb], **keep)
    checkin_hw(agent, seen_ip, disks=[disk], **keep)
    assert not any("disk E:" in e.title for e in tracking_events(did, "hardware_changed"))
    with db.get_session("default") as s:
        st = s.get(DeviceTrackingState, did)
        hw = dict(st.hardware)
        hw["disks"] = {**hw["disks"], "E:": {"size": 64000000000, "since": (utcnow() - timedelta(days=3)).isoformat()}}
        st.hardware = hw
        s.commit()
    checkin_hw(agent, seen_ip, disks=[disk], **keep)
    assert any("disk E: removed" in e.title for e in tracking_events(did, "hardware_changed"))


def test_hardware_toggle_off(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    configure(admin, alert_hardware_changed=False)
    checkin_hw(agent, seen_ip)
    checkin_hw(agent, seen_ip, memory_bytes=1073741824)
    assert tracking_events(did) == []


# --------------------------------------------------------------------------- agent stopped
def poll_every_minute(did: str, start: datetime, n: int) -> datetime:
    t = start
    for _ in range(n):
        observe_at(did, "9.9.9.9", t)
        t += timedelta(seconds=60)
    return t - timedelta(seconds=60)


def test_agent_stopped_once_per_gap(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    configure(admin, alert_agent_stopped=True)
    last = poll_every_minute(did, NOW, 8)
    assert tick(last + timedelta(hours=1)) == {}  # silent for 1 h only
    assert tick(last + timedelta(hours=3)) == {"default": {"not_seen": 0, "agent_stopped": 1}}
    assert tick(last + timedelta(hours=9)) == {}  # same gap: once
    ev = tracking_events(did, "agent_stopped")
    assert len(ev) == 1 and ev[0].title == "LAPTOP-001: the agent stopped reporting"
    assert len(notifications("agent_stopped")) == 1
    # Back, polling again, silent again: a new gap.
    again = poll_every_minute(did, last + timedelta(days=1), 8)
    assert tick(again + timedelta(hours=1)) == {}
    assert tick(again + timedelta(hours=3))["default"]["agent_stopped"] == 1


def test_agent_stopped_needs_regular_polling_and_toggle(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    configure(admin, alert_agent_stopped=True)
    observe_at(did, "9.9.9.9", NOW)
    observe_at(did, "9.9.9.9", NOW + timedelta(minutes=15))  # a 15 minute check-in cycle, not polling
    observe_at(did, "9.9.9.9", NOW + timedelta(minutes=30))
    assert tick(NOW + timedelta(hours=10)) == {}
    last = poll_every_minute(did, NOW + timedelta(days=1), 8)
    configure(admin, alert_agent_stopped=False)
    assert tick(last + timedelta(hours=3)) == {}
    configure(admin, alert_agent_stopped=True)
    with db.get_session("default") as s:  # a revoked device is not alerted on
        s.get(Device, did).status = "revoked"
        s.commit()
    assert tick(last + timedelta(hours=3)) == {}


# --------------------------------------------------------------------------- automatic lost mode
def lost_commands(did: str) -> list[DeviceCommand]:
    with db.get_session("default") as s:
        return list(s.scalars(select(DeviceCommand).where(DeviceCommand.device_id == did,
                                                          DeviceCommand.type == "enable_lost_mode")))


def test_auto_lost_mode_requires_phone(admin, device):  # noqa: F811
    r = admin.put(SETTINGS, json={"auto_lost_mode_outside_countries": True})
    assert r.status_code == 422 and "phone" in r.json()["detail"]
    assert admin.put(SETTINGS, json={"auto_lost_mode_phone": "abc"}).status_code == 422
    r = admin.put(SETTINGS, json={"auto_lost_mode_outside_countries": True, "auto_lost_mode_phone": "+234 800 000 0000"})
    assert r.status_code == 200 and r.json()["auto_lost_mode_phone"] == "+234 800 000 0000"
    assert admin.put(SETTINGS, json={"alert_not_seen_days": 91}).status_code == 422
    assert admin.put(SETTINGS, json={"alert_not_seen_days": 90}).status_code == 200


def test_auto_lost_mode_queued_once_and_audited(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    configure(admin, allowed_countries=["US"], auto_lost_mode_outside_countries=True,
              auto_lost_mode_phone="+234 800 000 0000")
    observe_at(did, "8.8.8.8", NOW)
    assert lost_commands(did) == []
    observe_at(did, "5.5.5.5", NOW + timedelta(minutes=5))
    cmds = lost_commands(did)
    assert len(cmds) == 1 and cmds[0].reason == "Automatic: outside allowed countries"
    assert cmds[0].requested_by_id is None and cmds[0].requested_by_email == "Automatic: device tracking"
    assert cmds[0].params["phone"] == "+234 800 000 0000" and cmds[0].params["message"]
    with db.get_session("default") as s:
        d = s.get(Device, did)
        assert d.lost_mode_status == "enabling" and d.wipe_status is None
        assert not s.scalars(select(DeviceCommand).where(DeviceCommand.type == "wipe_device")).all()
        a = s.scalars(select(AuditLog).where(AuditLog.action == "device_command_created",
                                             AuditLog.actor_email == "Automatic: device tracking")).all()
        assert len(a) == 1 and a[0].detail["type"] == "enable_lost_mode" and a[0].detail["automatic"] is True
    assert len(tracking_events(did, "auto_lost_mode")) == 1
    # Moving on to another outside country while lost mode is on / pending: nothing more.
    observe_at(did, "4.4.4.4", NOW + timedelta(hours=1))
    observe_at(did, "5.5.5.5", NOW + timedelta(hours=2))
    assert len(lost_commands(did)) == 1
    # A person clears lost mode; the next trip outside the allowed countries locks again.
    with db.get_session("default") as s:
        s.get(Device, did).lost_mode_status = None
        s.commit()
    observe_at(did, "8.8.8.8", NOW + timedelta(hours=3))
    assert len(lost_commands(did)) == 1
    observe_at(did, "9.9.9.9", NOW + timedelta(hours=4))
    assert len(lost_commands(did)) == 2


def test_auto_lost_mode_never_when_off_or_not_outside(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    configure(admin, allowed_countries=["US"], auto_lost_mode_outside_countries=False,
              auto_lost_mode_phone="+234 800 000 0000", alert_outside_countries=True)
    observe_at(did, "5.5.5.5", NOW)
    assert lost_commands(did) == []
    assert len(tracking_events(did, "outside_countries")) == 1  # the alert is independent of auto lost mode
    configure(admin, auto_lost_mode_outside_countries=True, allowed_countries=[])  # no rule: never outside
    observe_at(did, "9.9.9.9", NOW + timedelta(hours=1))
    assert lost_commands(did) == []
    configure(admin, allowed_countries=["US"], enabled=False)  # tracking off
    observe_at(did, "4.4.4.4", NOW + timedelta(hours=2))
    assert lost_commands(did) == []


def test_auto_lost_mode_skipped_during_wipe(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    configure(admin, allowed_countries=["US"], auto_lost_mode_outside_countries=True,
              auto_lost_mode_phone="+234 800 000 0000")
    with db.get_session("default") as s:
        s.get(Device, did).wipe_status = "queued"
        s.commit()
    observe_at(did, "5.5.5.5", NOW)
    assert lost_commands(did) == []


# --------------------------------------------------------------------------- misc
def test_notification_source_registered(admin):  # noqa: F811
    from app.notifications import sources

    src = next(s for s in sources() if s.name == "device_tracking")
    assert src.label == "Device tracking" and "outside_countries" in src.event_types


def test_alert_rate_limit_per_org(admin, device, seen_ip, monkeypatch):  # noqa: F811
    agent, did = device
    monkeypatch.setattr(alerts, "MAX_ALERTS_PER_ORG_HOUR", 2)
    monkeypatch.setattr(alerts, "MIN_GAP", {k: timedelta(0) for k in alerts.MIN_GAP})
    configure(admin, allowed_countries=["US"], alert_outside_countries=True)
    for i, ip in enumerate(["5.5.5.5", "8.8.8.8", "9.9.9.9", "8.8.8.8", "4.4.4.4"]):
        observe_at(did, ip, NOW + timedelta(minutes=i))
    assert len(tracking_events(did, "outside_countries")) == 2


def test_pruning_of_alert_events(admin, device):  # noqa: F811
    agent, did = device
    configure(admin)
    with db.get_session("default") as s:
        for age in (1, 200):
            s.add(DeviceTrackingEvent(device_id=did, organization_id="default", at=utcnow() - timedelta(days=age),
                                      kind="not_seen", severity="medium", title="x"))
        s.commit()
    tick(utcnow())
    assert len(tracking_events(did)) == 1
    assert service.get_settings  # (module imported)
