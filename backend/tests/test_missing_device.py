# ruff: noqa: F811  (pytest fixtures are imported and used as arguments)
"""Missing-device mode (docs/DEVICE_TRACKING.md#missing-device-mode): mark / recover lifecycle and the commands it
queues, validation, RBAC and the viewer's limited data, sightings, the reconnect alert (once), the PDF report,
tenancy, module gating, and Linux / server refusal. No network: the IP database is a fixture MMDB."""
from __future__ import annotations

import re
import zlib
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import db
from app.models import AuditLog, Device, DeviceCommand, Organization, utcnow
from app.notifications.models import NotificationEvent
from tests.conftest import BASE_URL, login, make_user
from tests.test_device_tracking import SETTINGS, checkin, fixture_db, rows, seen_ip  # noqa: F401 - fixtures
from tests.test_devices import admin, device  # noqa: F401 - fixtures
from tests.test_tenancy import acme_device, tenants  # noqa: F401 - fixtures

MARK = {"reason": "Left on a train, INC-77", "confirm_hostname": "laptop-001",
        "message": "This laptop is lost. Please call us.", "phone": "+234 1 234 5678"}


def url(did, tail=""):
    return f"/api/devices/{did}/missing{tail}"


def as_role(admin, role):
    make_user(admin, role)
    c = TestClient(admin.app, base_url=BASE_URL)
    login(c, f"{role}@example.com", "a-long-test-password")
    return c


def commands(did):
    with db.get_session("default") as s:
        return [(c.type, c.status, c.params) for c in s.scalars(
            select(DeviceCommand).where(DeviceCommand.device_id == did).order_by(DeviceCommand.created_at,
                                                                                 DeviceCommand.id))]


def audit_actions():
    with db.get_session("default") as s:
        return [a.action for a in s.scalars(select(AuditLog).order_by(AuditLog.id))]


def finish_commands(agent):
    """The agent polls and reports success for everything queued."""
    for cmd in agent.get("/api/agent/commands").json()["commands"]:
        r = agent.post(f"/api/agent/commands/{cmd['id']}/result",
                       json={"nonce": cmd["nonce"], "status": "succeeded", "output": "ok"})
        assert r.status_code == 204, r.text


@pytest.fixture()
def tracked(admin, device, seen_ip):  # noqa: F811
    agent, did = device
    assert admin.put(SETTINGS, json={"enabled": True}).status_code == 200
    return agent, did


# --------------------------------------------------------------------------- lifecycle
def test_mark_and_recover_lifecycle(admin, tracked, seen_ip):  # noqa: F811
    agent, did = tracked
    with db.get_session("default") as s:
        s.get(Device, did).check_in_interval_seconds = 900
        s.commit()
    assert admin.get(url(did)).json()["missing"] is False
    r = admin.post(url(did), json=MARK)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["missing"] is True and body["reason"] == MARK["reason"] and body["by"] == "Administrator"
    assert body["lost_mode"]["status"] == "enabling" and body["check_in_seconds"] == 300
    assert body["previous_check_in_seconds"] == 900
    cmds = commands(did)
    assert [c[0] for c in cmds] == ["enable_lost_mode", "update_check_in_interval"]
    assert cmds[0][2] == {"message": MARK["message"], "phone": MARK["phone"]}
    assert cmds[1][2] == {"interval_seconds": 300}
    # Device list / summary expose it.
    listed = admin.get("/api/devices").json()[0]
    assert listed["missing"] is True and admin.get("/api/devices?missing=true").json()[0]["id"] == did
    assert admin.get("/api/devices?missing=false").json() == []
    assert admin.get("/api/devices/summary").json()["missing"] == 1
    assert admin.get(f"/api/devices/{did}").json()["missing"] is True
    assert admin.post(url(did), json=MARK).status_code == 409  # already missing
    finish_commands(agent)
    d = admin.get(f"/api/devices/{did}").json()
    assert d["lost_mode"]["status"] == "active" and d["check_in_interval_seconds"] == 300
    # Recover, also exiting lost mode.
    r = admin.post(url(did, "/recover"), json={"exit_lost_mode": True})
    assert r.status_code == 200, r.text
    assert r.json()["lost_mode_action"] == "exit_queued" and r.json()["interval_action"] == "restore_queued"
    assert r.json()["missing"] is False and r.json()["recovered_by"] == "Administrator"
    types = [(c[0], c[2]) for c in commands(did)][2:]
    assert ("disable_lost_mode", {}) in types and ("update_check_in_interval", {"interval_seconds": 900}) in types
    finish_commands(agent)
    d = admin.get(f"/api/devices/{did}").json()
    assert d["lost_mode"]["status"] is None and d["check_in_interval_seconds"] == 900 and d["missing"] is False
    assert admin.get("/api/devices/summary").json()["missing"] == 0
    assert admin.post(url(did, "/recover"), json={}).status_code == 409  # not missing any more
    acts = audit_actions()
    assert "device_missing_marked" in acts and "device_missing_recovered" in acts
    # It can be marked again later.
    assert admin.post(url(did), json=MARK).status_code == 201


def test_recover_can_keep_lost_mode_and_cancels_unsent_commands(admin, tracked):
    agent, did = tracked
    assert admin.post(url(did), json=MARK).status_code == 201
    # The device never came back online: nothing was delivered yet.
    r = admin.post(url(did, "/recover"), json={"exit_lost_mode": True})
    assert r.status_code == 200 and r.json()["lost_mode_action"] == "cancelled"
    assert {c[1] for c in commands(did)} == {"cancelled"}
    d = admin.get(f"/api/devices/{did}").json()
    assert d["lost_mode"]["status"] is None and d["missing"] is False
    # Keep lost mode on.
    assert admin.post(url(did), json=MARK).status_code == 201
    finish_commands(agent)
    r = admin.post(url(did, "/recover"), json={"exit_lost_mode": False})
    assert r.json()["lost_mode_action"] == "kept"
    assert "disable_lost_mode" not in [c[0] for c in commands(did)]
    assert admin.get(f"/api/devices/{did}").json()["lost_mode"]["status"] == "active"


def test_lost_mode_already_on_is_not_queued_again(admin, tracked):
    agent, did = tracked
    body = {"type": "enable_lost_mode", "reason": "lost", "confirm_hostname": "LAPTOP-001",
            "params": {"message": "Lost device", "phone": "0800 123"}}
    assert admin.post(f"/api/devices/{did}/commands", json=body).status_code == 201
    finish_commands(agent)
    r = admin.post(url(did), json={"reason": "stolen", "confirm_hostname": "LAPTOP-001"})  # no message / phone needed
    assert r.status_code == 201 and r.json()["lost_mode"]["status"] == "active"
    assert [c[0] for c in commands(did)].count("enable_lost_mode") == 1


def test_validation(admin, tracked):
    agent, did = tracked
    bad = [{**MARK, "reason": "ab"}, {**MARK, "reason": "x" * 501}, {**MARK, "reason": "bad\x07text"},
           {**MARK, "confirm_hostname": "other"}, {**MARK, "confirm_hostname": ""}, {**MARK, "phone": "abc"},
           {**MARK, "message": ""}, {k: v for k, v in MARK.items() if k != "phone"}, {**MARK, "extra": 1}]
    for b in bad:
        r = admin.post(url(did), json=b)
        assert r.status_code == 422, (b, r.text)
    assert commands(did) == [] and admin.get(url(did)).json()["missing"] is False


def test_tracking_off_refuses(admin, device):  # noqa: F811
    agent, did = device
    r = admin.post(url(did), json=MARK)
    assert r.status_code == 409 and "tracking is off" in r.json()["detail"]


def test_linux_and_servers_refused(admin, tracked):
    agent, did = tracked
    with db.get_session("default") as s:
        s.get(Device, did).device_class = "server"
        s.commit()
    assert admin.post(url(did), json=MARK).status_code == 409
    with db.get_session("default") as s:
        d = s.get(Device, did)
        d.device_class, d.os_family = "workstation", "linux"
        s.commit()
    r = admin.post(url(did), json=MARK)
    assert r.status_code == 409 and "Windows and macOS" in r.json()["detail"]
    assert admin.get("/api/devices?missing=true").json() == []


def test_wipe_in_progress_blocks(admin, tracked):
    agent, did = tracked
    with db.get_session("default") as s:
        s.get(Device, did).wipe_status = "queued"
        s.commit()
    assert admin.post(url(did), json=MARK).status_code == 409


# --------------------------------------------------------------------------- RBAC
def test_roles(admin, tracked, seen_ip):  # noqa: F811
    agent, did = tracked
    analyst, viewer = as_role(admin, "analyst"), as_role(admin, "viewer")
    for c in (analyst, viewer):
        assert c.post(url(did), json=MARK).status_code == 403
        assert c.post(url(did, "/recover"), json={}).status_code == 403
    checkin(agent, seen_ip, "8.8.8.8")
    assert admin.post(url(did), json=MARK).status_code == 201
    checkin(agent, seen_ip, "9.9.9.9")
    for c in (analyst, viewer):
        assert c.post(url(did, "/recover"), json={}).status_code == 403
    assert analyst.get(url(did, "/report.pdf")).status_code == 200
    assert viewer.get(url(did, "/report.pdf")).status_code == 403
    full = analyst.get(url(did)).json()
    assert full["detail"] == "full" and full["sightings"][-1]["ip"] == "9.9.9.9"
    assert full["sightings"][-1]["provider"] == "Other ISP"
    v = viewer.get(url(did)).json()
    assert v["detail"] == "basic" and v["missing"] is True and v["reason"] == MARK["reason"]
    assert v["sightings"][-1]["city"] == "Lyon" and v["sightings"][-1]["country"] == "France"
    for hidden in ("ip", "provider", "region"):
        assert all(hidden not in s for s in v["sightings"])
    assert "ip" not in v["last_seen"] and "provider" not in v["last_seen"]
    assert "8.8.8.8" not in viewer.get(url(did)).text and "9.9.9.9" not in viewer.get(url(did)).text


# --------------------------------------------------------------------------- sightings and alert
def test_sightings_recorded_per_change_and_last_seen_updates(admin, tracked, seen_ip):  # noqa: F811
    agent, did = tracked
    checkin(agent, seen_ip, "8.8.8.8")
    assert admin.post(url(did), json=MARK).status_code == 201
    checkin(agent, seen_ip, "8.8.8.8")  # same place: the existing row moves on
    seen_ip["ip"] = "9.9.9.9"
    assert agent.get("/api/agent/commands").status_code == 200  # the 60 s poll sees a new address
    seen_ip["ip"] = "4.4.4.4"
    assert agent.get("/api/agent/commands").status_code == 200
    assert [r.city for r in rows(did)] == ["Springfield", "Lyon", "Osaka"]
    v = admin.get(url(did)).json()
    assert [s["city"] for s in v["sightings"]] == ["Springfield", "Lyon", "Osaka"]
    assert v["last_seen"]["city"] == "Osaka" and v["last_seen"]["provider"] is None
    assert v["sightings"][0]["when"] >= v["since"]  # the first row is clipped to when it went missing
    before = rows(did)[-1].last_seen_at
    agent.get("/api/agent/commands")
    assert len(rows(did)) == 3 and rows(did)[-1].last_seen_at >= before
    # Signed-in user from the check-in data.
    checkin(agent, seen_ip, "4.4.4.4")
    assert admin.get(url(did)).json()["sightings"][-1]["signed_in"] == "CORP\\alice"
    # A sighting before it went missing is not listed.
    assert len(admin.get(f"/api/devices/{did}/location").json()["history"]) >= 3


def test_hardware_changes_against_baseline(admin, tracked):
    agent, did = tracked
    assert admin.post(url(did), json=MARK).status_code == 201
    assert admin.get(url(did)).json()["hardware_changes"] == []
    with db.get_session("default") as s:
        d = s.get(Device, did)
        d.inventory = {**d.inventory, "memory_bytes": 1}
        s.commit()
    assert admin.get(url(did)).json()["hardware_changes"] == ["memory"]


def missing_events():
    with db.get_session("default") as s:
        return list(s.scalars(select(NotificationEvent).where(NotificationEvent.event_type == "missing_device_online")))


def test_reconnect_after_offline_alerts_once(admin, tracked, seen_ip):  # noqa: F811
    agent, did = tracked
    checkin(agent, seen_ip, "8.8.8.8")
    assert admin.post(url(did), json=MARK).status_code == 201
    agent.get("/api/agent/commands")
    agent.get("/api/agent/commands")
    assert missing_events() == []  # a short gap is not an alert
    with db.get_session("default") as s:  # ... but an hour and a half offline is
        s.get(Device, did).missing_last_contact_at = utcnow() - timedelta(minutes=90)
        s.commit()
    seen_ip["ip"] = "9.9.9.9"
    agent.get("/api/agent/commands")
    agent.get("/api/agent/commands")
    checkin(agent, seen_ip, "9.9.9.9")
    (ev,) = missing_events()
    assert ev.source == "device" and ev.severity == "high" and "LAPTOP-001" in ev.title
    assert "Lyon" in ev.summary and "9.9.9.9" not in ev.summary + ev.title
    # Offline again later: a second alert.
    with db.get_session("default") as s:
        s.get(Device, did).missing_last_contact_at = utcnow() - timedelta(hours=3)
        s.commit()
    agent.get("/api/agent/commands")
    assert len(missing_events()) == 2


def test_no_alert_for_normal_or_recovered_devices(admin, tracked, seen_ip):  # noqa: F811
    agent, did = tracked
    with db.get_session("default") as s:
        s.get(Device, did).missing_last_contact_at = utcnow() - timedelta(hours=5)
        s.commit()
    agent.get("/api/agent/commands")
    assert missing_events() == []
    assert admin.post(url(did), json=MARK).status_code == 201
    assert admin.post(url(did, "/recover"), json={}).status_code == 200
    with db.get_session("default") as s:
        s.get(Device, did).missing_last_contact_at = utcnow() - timedelta(hours=5)
        s.commit()
    agent.get("/api/agent/commands")
    assert missing_events() == []


# --------------------------------------------------------------------------- PDF
def pdf_text(blob: bytes) -> str:
    out = []
    for m in re.finditer(rb"stream\n(.*?)\nendstream", blob, re.S):
        out.append(zlib.decompress(m.group(1)).decode("latin-1"))
    return "\n".join(re.findall(r"\((.*?)\) Tj", "\n".join(out)))


def test_pdf_report(admin, tracked, seen_ip):  # noqa: F811
    agent, did = tracked
    assert admin.get(url(did, "/report.pdf")).status_code == 409  # never marked missing
    admin.put(SETTINGS, json={"timezone": "Africa/Lagos"})
    checkin(agent, seen_ip, "8.8.8.8")
    admin.post(url(did), json=MARK)
    checkin(agent, seen_ip, "9.9.9.9")
    admin.post(f"/api/devices/{did}/commands", json={"type": "isolate_host", "reason": "stolen",
                                                      "confirm_hostname": "LAPTOP-001"})
    r = admin.get(url(did, "/report.pdf"))
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF-1.4") and r.content.rstrip().endswith(b"%%EOF")
    text = pdf_text(r.content)
    for expected in ("MISSING DEVICE REPORT", "LAPTOP-001", "PF12345", "LENOVO", "CORP\\\\alice", MARK["reason"],
                     "Administrator", "Lyon", "9.9.9.9", "Other ISP", "Lost mode turned on",
                     "Marked as missing", "approximate", "internet address", "Page 1 of", "WAT"):
        assert expected in text, expected
    assert "Managed security team" not in text and "Generated by Sentrigis" in text
    assert "8.8.8.8" not in text  # seen before it was marked missing
    # Recovered devices still produce a report listing the recovery.
    admin.post(url(did, "/recover"), json={})
    text = pdf_text(admin.get(url(did, "/report.pdf")).content)
    assert "Marked as recovered" in text and "Status: Recovered" in text
    assert "device_missing_report_downloaded" in audit_actions()


def test_pdf_rate_limit(admin, tracked, monkeypatch):
    from app.tracking import missing_api

    agent, did = tracked
    admin.post(url(did), json=MARK)
    monkeypatch.setattr(missing_api, "PDF_LIMIT", 2)
    missing_api.pdf_limiter._hits.clear()
    assert admin.get(url(did, "/report.pdf")).status_code == 200
    assert admin.get(url(did, "/report.pdf")).status_code == 200
    assert admin.get(url(did, "/report.pdf")).status_code == 429
    missing_api.pdf_limiter._hits.clear()


def test_pdf_many_sightings_paginate(admin, tracked):
    from app.models import utcnow as now
    from app.tracking.models import DeviceLocation

    agent, did = tracked
    admin.post(url(did), json=MARK)
    with db.get_session("default") as s:
        for i in range(120):
            t = now() + timedelta(seconds=i)
            s.add(DeviceLocation(device_id=did, first_seen_at=t, last_seen_at=t, ip=f"8.8.8.{i % 250}",
                                 city="Springfield", country="United States", country_code="US"))
        s.commit()
    text = pdf_text(admin.get(url(did, "/report.pdf")).content)
    assert "Page 1 of" in text and "Page 3 of" in text


# --------------------------------------------------------------------------- tenancy, modules
def test_tenancy_isolation(tenants, seen_ip):  # noqa: F811
    t = tenants
    a_agent, a_dev = acme_device(t)
    t.acme.put(SETTINGS, json={"enabled": True})
    assert t.acme.post(url(a_dev), json={**MARK, "confirm_hostname": "ACME-LAPTOP"}).status_code == 201
    assert t.default.get(url(a_dev)).status_code == 404
    assert t.default.post(url(a_dev), json={**MARK, "confirm_hostname": "ACME-LAPTOP"}).status_code == 404
    assert t.default.post(url(a_dev, "/recover"), json={}).status_code == 404
    assert t.default.get(url(a_dev, "/report.pdf")).status_code == 404
    assert t.default.get("/api/devices?missing=true").json() == []
    assert t.default.get("/api/devices/summary").json()["missing"] == 0
    assert t.acme.get("/api/devices/summary").json()["missing"] == 1


def test_module_gating(tenants):  # noqa: F811
    a_agent, a_dev = acme_device(tenants)
    with db.get_session(unscoped=True) as s:
        s.get(Organization, tenants.acme_id).modules = ["cloud"]
        s.commit()
    assert tenants.acme.get(url(a_dev)).status_code == 403
    assert tenants.acme.post(url(a_dev), json=MARK).status_code == 403
    assert tenants.acme.get(url(a_dev, "/report.pdf")).status_code == 403
