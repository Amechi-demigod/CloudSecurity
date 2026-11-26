# ruff: noqa: F811
"""Recent tracking alerts (GET /api/device-tracking/alerts, docs/DEVICE_TRACKING.md#recent-alerts)."""
from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app import db
from app.models import Device, Organization, utcnow
from app.notifications.models import NotificationChannel, NotificationRule
from app.tracking.alert_models import DeviceTrackingEvent
from tests.conftest import BASE_URL, login, make_user
from tests.test_device_tracking_b import SETTINGS, configure, seen_ip  # noqa: F401 - fixtures
from tests.test_devices import admin, device  # noqa: F401 - fixtures
from tests.test_tenancy import acme_device, tenants  # noqa: F401 - fixtures

URL = "/api/device-tracking/alerts"


def add_event(did: str, kind: str, ago: timedelta, org: str = "default", city="Accra", country="Ghana"):
    with db.get_session(org) as s:
        s.add(DeviceTrackingEvent(device_id=did, organization_id=s.get(Device, did).organization_id,
                                  at=utcnow() - ago, kind=kind, severity="medium", title=f"{kind} title",
                                  city=city, country_code="GH", country=country))
        s.commit()


def add_rule(sources, enabled=True, with_channel=True, channel_enabled=True, org: str = "default"):
    with db.get_session(org) as s:
        ch = NotificationChannel(name="c", type="slack", enabled=channel_enabled, config={})
        s.add(ch)
        s.flush()
        s.add(NotificationRule(name="r", enabled=enabled, sources=sources, channel_ids=[ch.id] if with_channel else []))
        s.commit()


def test_off_and_empty(admin, device):
    r = admin.get(URL)
    assert r.status_code == 200 and r.json()["enabled"] is False and r.json()["items"] == []
    configure(admin)
    j = admin.get(URL).json()
    assert j["enabled"] is True and j["items"] == [] and j["count_24h"] == 0 and j["notified"] is False


def test_order_window_count_and_limit(admin, device):
    _, did = device
    configure(admin)
    add_event(did, "outside_countries", timedelta(hours=2))
    add_event(did, "not_seen", timedelta(hours=30))
    add_event(did, "hardware_changed", timedelta(days=6))
    add_event(did, "agent_stopped", timedelta(days=9))  # older than the default 7 days
    j = admin.get(URL).json()
    assert [i["kind"] for i in j["items"]] == ["outside_countries", "not_seen", "hardware_changed"]
    assert j["count_24h"] == 1 and j["total"] == 3
    it = j["items"][0]
    assert it["hostname"] == "LAPTOP-001" and it["device_id"] == did and it["city"] == "Accra"
    assert it["detail_line"] == "Outside allowed countries · Accra, Ghana"
    assert len(admin.get(URL + "?days=14").json()["items"]) == 4
    assert len(admin.get(URL + "?days=1").json()["items"]) == 1
    j = admin.get(URL + "?limit=2").json()
    assert len(j["items"]) == 2 and j["total"] == 3
    assert admin.get(URL + "?days=91").status_code == 422
    assert admin.get(URL + "?limit=0").status_code == 422
    assert admin.get(URL + "?limit=100000").status_code == 422


@pytest.mark.parametrize("group,kind", [("outside_countries", "outside_countries"), ("not_seen", "not_seen"),
                                        ("hardware", "hardware_changed"), ("locked", "auto_lost_mode"),
                                        ("after_hours", "after_hours"), ("agent_stopped", "agent_stopped")])
def test_group_filters(admin, device, group, kind):
    _, did = device
    configure(admin)
    for k in ("outside_countries", "not_seen", "hardware_changed", "auto_lost_mode", "after_hours", "agent_stopped"):
        add_event(did, k, timedelta(hours=1))
    j = admin.get(f"{URL}?group={group}").json()
    assert [i["kind"] for i in j["items"]] == [kind] and j["total"] == 1
    assert j["count_24h"] == 6  # the header count ignores the filter
    assert admin.get(URL + "?group=nope").status_code == 422


def test_viewer_gets_basic_detail_without_address(admin, device):
    _, did = device
    configure(admin)
    add_event(did, "outside_countries", timedelta(hours=1))
    make_user(admin, "viewer")
    v = TestClient(admin.app, base_url=BASE_URL)
    login(v, "viewer@example.com", "a-long-test-password")
    j = v.get(URL).json()
    assert j["detail"] == "basic" and j["items"][0]["city"] == "Accra"
    assert admin.get(URL).json()["detail"] == "full"
    for hidden in ("ip", "provider", "latitude", "longitude", "asn"):
        assert hidden not in j["items"][0]


def test_notified_cases(admin, device):
    configure(admin)
    assert admin.get(URL).json()["notified"] is False
    add_rule(["cloud"])  # another source
    add_rule([])  # no sources: does not count
    add_rule(["device_tracking"], enabled=False)
    add_rule(["device_tracking"], with_channel=False)
    add_rule(["device_tracking"], channel_enabled=False)
    assert admin.get(URL).json()["notified"] is False
    add_rule(["cloud", "device_tracking"])
    assert admin.get(URL).json()["notified"] is True


def test_tenancy_isolation(tenants, seen_ip):
    t = tenants
    _, a_dev = acme_device(t)
    t.acme.put(SETTINGS, json={"enabled": True})
    t.default.put(SETTINGS, json={"enabled": True})
    add_event(a_dev, "not_seen", timedelta(hours=1), org=t.acme_id)
    add_rule(["device_tracking"], org=t.acme_id)
    a = t.acme.get(URL).json()
    assert [i["device_id"] for i in a["items"]] == [a_dev] and a["notified"] is True
    d = t.default.get(URL).json()
    assert d["items"] == [] and d["count_24h"] == 0 and d["notified"] is False


def test_tracking_off_hides_alerts_and_module_gating(tenants, seen_ip):
    t = tenants
    _, a_dev = acme_device(t)
    t.acme.put(SETTINGS, json={"enabled": True})
    add_event(a_dev, "not_seen", timedelta(hours=1), org=t.acme_id)
    t.acme.put(SETTINGS, json={"enabled": False})
    j = t.acme.get(URL).json()
    assert j["enabled"] is False and j["items"] == []
    with db.get_session(unscoped=True) as s:
        s.get(Organization, t.acme_id).modules = ["cloud"]
        s.commit()
    assert t.acme.get(URL).status_code == 403
