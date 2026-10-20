"""IT asset lifecycle: asset records (manual + agent devices), custody timeline,
assignment / return / status / offboarding, disposal certificates, CSV
import / export (incl. formula-injection guard), utilization, dashboard,
notifications and RBAC. Runs on SQLite and PostgreSQL."""
from __future__ import annotations

import csv
import io
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import db
from app.models import AuditLog, Device, utcnow
from tests.conftest import BASE_URL, login, make_user

PDF = b"%PDF-1.7\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


@pytest.fixture()
def admin(empty_client):
    return empty_client


def role_client(admin, role: str) -> TestClient:
    make_user(admin, role)
    c = TestClient(admin.app, base_url=BASE_URL)
    login(c, f"{role}@example.com", "a-long-test-password")
    return c


def new_asset(c, **kw):
    body = {"asset_tag": "WK-0001", "asset_type": "laptop", "manufacturer": "Lenovo", "model": "ThinkPad T14",
            "serial_number": "SN-1", "purchase_cost": "850000.50", "warranty_end": "2030-01-01", **kw}
    r = c.post("/api/it-assets", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def add_device(**kw) -> str:
    with db.get_session() as s:
        d = Device(hostname=kw.pop("hostname", "LAPTOP-001"), os_family="windows",
                   serial_number=kw.pop("serial_number", "PF12345"), manufacturer="LENOVO",
                   model=kw.pop("model", "ThinkPad X1 Carbon"), last_seen_at=kw.pop("last_seen_at", utcnow()),
                   enrolled_at=kw.pop("enrolled_at", utcnow() - timedelta(days=90)), **kw)
        s.add(d)
        s.commit()
        return d.id


def audit_actions() -> list[str]:
    with db.get_session() as s:
        return [a.action for a in s.scalars(select(AuditLog).order_by(AuditLog.id))]


def events(c, asset_id: str) -> list[dict]:
    r = c.get(f"/api/it-assets/{asset_id}/events")
    assert r.status_code == 200, r.text
    return r.json()


# --------------------------------------------------------------------------- records
def test_create_validate_and_update(admin):
    a = new_asset(admin, currency=None)
    assert a["status"] == "in_stock" and a["currency"] == "NGN" and a["purchase_cost"] == 850000.5
    assert a["source"] == "manual" and a["device_id"] is None
    # duplicate tag (case-insensitive), bad values
    assert admin.post("/api/it-assets", json={"asset_tag": "wk-0001"}).status_code == 409
    for bad in ({"asset_tag": "=cmd|' /C calc'!A0"}, {"asset_tag": "X", "asset_type": "spaceship"},
                {"asset_tag": "X", "purchase_cost": "-1"}, {"asset_tag": "X", "currency": "naira"},
                {"asset_tag": "X", "notes": "bad\x00char"}, {"asset_tag": "X", "status": "disposed"},
                {"asset_tag": "X", "purchase_date": "2030-01-01", "warranty_end": "2029-01-01"},
                {"asset_tag": "X", "custom_fields": {"cost_centre": "x"}}, {"asset_tag": "X", "unknown": 1},
                {"asset_tag": "X", "status": "assigned"}):
        assert admin.post("/api/it-assets", json=bad).status_code == 422, bad
    r = admin.patch(f"/api/it-assets/{a['id']}", json={"location": "Lagos HQ", "notes": "spare", "note": "move"})
    assert r.status_code == 200 and r.json()["location"] == "Lagos HQ"
    ev = events(admin, a["id"])
    assert [e["event_type"] for e in ev] == ["updated", "created"]
    assert ev[0]["detail"]["changes"]["location"] == ["", "Lagos HQ"] and ev[0]["actor_email"] == "admin@example.com"
    assert {"it_asset_created", "it_asset_updated"} <= set(audit_actions())
    assert admin.get(f"/api/it-assets/{'0' * 32}").status_code == 404


def test_custom_fields_and_settings(admin):
    r = admin.put("/api/it-assets/settings", json={
        "default_currency": "usd", "locations": ["Lagos HQ", "Abuja", "Lagos HQ"], "idle_days": 14,
        "custom_fields": [{"key": "cost_centre", "label": "Cost centre"}]})
    assert r.status_code == 200, r.text
    st = r.json()
    assert st["default_currency"] == "USD" and st["locations"] == ["Abuja", "Lagos HQ"] and st["idle_days"] == 14
    assert admin.put("/api/it-assets/settings", json={"custom_fields": [{"key": "Bad Key", "label": "x"}]}
                     ).status_code == 422
    a = new_asset(admin, custom_fields={"cost_centre": "CC-42"})
    assert a["custom_fields"] == {"cost_centre": "CC-42"} and a["currency"] == "USD"
    assert "it_asset_settings_updated" in audit_actions()
    # null resets to the env default
    assert admin.put("/api/it-assets/settings", json={"default_currency": None}).json()["default_currency"] == "NGN"


# --------------------------------------------------------------------------- custody
def test_assign_return_status_timeline(admin):
    a = new_asset(admin)
    r = admin.post(f"/api/it-assets/{a['id']}/assign", json={
        "assignee_name": "Ada Obi", "assignee_email": "Ada@Wakanow.example", "assignee_department": "Finance",
        "notes": "new joiner"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "assigned" and r.json()["assignee_email"] == "ada@wakanow.example"
    # reassign keeps custody chain
    r = admin.post(f"/api/it-assets/{a['id']}/assign", json={"assignee_email": "bola@wakanow.example"})
    assert r.status_code == 200 and r.json()["assignee_department"] == ""
    r = admin.post(f"/api/it-assets/{a['id']}/status", json={"status": "in_repair", "notes": "screen"})
    assert r.json()["status"] == "in_repair" and r.json()["assignee_email"] == "bola@wakanow.example"
    r = admin.post(f"/api/it-assets/{a['id']}/return", json={"notes": "fixed, back to stock", "location": "Abuja"})
    assert r.json()["status"] == "in_stock" and r.json()["assignee_email"] == "" and r.json()["location"] == "Abuja"
    assert admin.post(f"/api/it-assets/{a['id']}/return", json={}).status_code == 409
    assert admin.post(f"/api/it-assets/{a['id']}/status", json={"status": "retrieval_pending"}).status_code == 409
    assert admin.post(f"/api/it-assets/{a['id']}/status", json={"status": "assigned"}).status_code == 422
    ev = events(admin, a["id"])
    assert [e["event_type"] for e in ev] == ["returned", "status_changed", "assigned", "assigned", "created"]
    assert ev[2]["from_assignee"] == "ada@wakanow.example" and ev[2]["to_assignee"] == "bola@wakanow.example"
    assert ev[3]["notes"] == "new joiner" and ev[0]["from_status"] == "in_repair" and ev[0]["to_status"] == "in_stock"
    acts = audit_actions()
    assert acts.count("it_asset_assigned") == 2 and "it_asset_returned" in acts and "it_asset_status_changed" in acts


def test_offboarding_retrieval_and_overdue(admin):
    a1 = new_asset(admin, asset_tag="WK-1")
    a2 = new_asset(admin, asset_tag="WK-2", asset_type="phone")
    a3 = new_asset(admin, asset_tag="WK-3")
    for a in (a1, a2):
        admin.post(f"/api/it-assets/{a['id']}/assign", json={"assignee_email": "leaver@example.com",
                                                             "assignee_name": "Lee Ver", "assignee_department": "Ops"})
    admin.post(f"/api/it-assets/{a3['id']}/assign", json={"assignee_email": "stayer@example.com"})
    leave = (utcnow() - timedelta(days=20)).date()
    r = admin.post("/api/it-assets/offboardings", json={"person_email": "LEAVER@example.com",
                                                         "leave_date": leave.isoformat()})
    assert r.status_code == 201, r.text
    ob = r.json()
    assert ob["person_name"] == "Lee Ver" and ob["department"] == "Ops" and ob["assets_total"] == 2
    assert ob["retrieval_due"] == (leave + timedelta(days=7)).isoformat() and ob["overdue"] is True
    assert {x["status"] for x in ob["assets"]} == {"retrieval_pending"}
    # one open offboarding per person
    assert admin.post("/api/it-assets/offboardings", json={"person_email": "leaver@example.com",
                                                            "leave_date": leave.isoformat()}).status_code == 409
    overdue = admin.get("/api/it-assets?flag=retrieval_overdue").json()
    assert {x["asset_tag"] for x in overdue} == {"WK-1", "WK-2"}
    assert admin.get("/api/it-assets/summary").json()["retrieval_overdue"] == 2
    assert admin.get(f"/api/it-assets/{a3['id']}").json()["status"] == "assigned"
    # retrieve one, mark the other lost -> offboarding completes
    r = admin.post(f"/api/it-assets/{a1['id']}/return", json={"notes": "collected at exit interview"})
    assert r.json()["status"] == "retrieved"
    assert admin.get(f"/api/it-assets/offboardings/{ob['id']}").json()["assets_outstanding"] == 1
    assert admin.post(f"/api/it-assets/{a2['id']}/status", json={"status": "lost", "notes": "not returned"}
                      ).json()["status"] == "lost"
    d = admin.get(f"/api/it-assets/offboardings/{ob['id']}").json()
    assert d["status"] == "completed" and d["assets_outstanding"] == 0 and len(d["assets"]) == 2
    assert "it_asset_offboarding_created" in audit_actions()


def test_cancel_offboarding_restores_assignment(admin):
    a = new_asset(admin)
    admin.post(f"/api/it-assets/{a['id']}/assign", json={"assignee_email": "x@example.com"})
    ob = admin.post("/api/it-assets/offboardings", json={"person_email": "x@example.com",
                                                          "leave_date": "2026-11-30", "retrieval_due": "2026-12-05"}
                    ).json()
    assert ob["retrieval_due"] == "2026-12-05"
    r = admin.post(f"/api/it-assets/offboardings/{ob['id']}/cancel", json={"notes": "stays"})
    assert r.status_code == 200 and r.json()["status"] == "cancelled"
    assert admin.get(f"/api/it-assets/{a['id']}").json()["status"] == "assigned"
    assert admin.post(f"/api/it-assets/offboardings/{ob['id']}/cancel", json={}).status_code == 409
    assert [o["status"] for o in admin.get("/api/it-assets/offboardings").json()] == ["cancelled"]


# --------------------------------------------------------------------------- disposal + certificates
def test_disposal_and_certificate_validation(admin):
    a = new_asset(admin)
    admin.post(f"/api/it-assets/{a['id']}/assign", json={"assignee_email": "x@example.com"})
    body = {"method": "recycled", "disposal_date": utcnow().date().isoformat(), "vendor": "GreenIT Ltd"}
    assert admin.post(f"/api/it-assets/{a['id']}/dispose", json=body).status_code == 409  # still assigned
    admin.post(f"/api/it-assets/{a['id']}/return", json={})
    assert admin.post(f"/api/it-assets/{a['id']}/dispose", json={**body, "method": "burned"}).status_code == 422
    future = {**body, "disposal_date": (utcnow() + timedelta(days=30)).date().isoformat()}
    assert admin.post(f"/api/it-assets/{a['id']}/dispose", json=future).status_code == 422
    r = admin.post(f"/api/it-assets/{a['id']}/dispose", json=body)
    assert r.status_code == 200 and r.json()["status"] == "disposed" and r.json()["disposal_vendor"] == "GreenIT Ltd"
    assert admin.post(f"/api/it-assets/{a['id']}/status", json={"status": "in_stock"}).status_code == 409
    assert admin.post(f"/api/it-assets/{a['id']}/assign", json={"assignee_email": "y@example.com"}).status_code == 409

    url = f"/api/it-assets/certificates/{a['id']}"
    up = lambda data, ctype, name="wipe.pdf": admin.post(  # noqa: E731
        f"{url}?filename={name}", content=data, headers={"Content-Type": ctype})
    assert up(PDF, "text/html").status_code == 415
    assert up(b"<html><script>alert(1)</script>", "application/pdf").status_code == 415  # magic mismatch
    assert up(PNG, "application/pdf").status_code == 415
    assert up(b"", "application/pdf").status_code in (415, 422)
    assert up(b"%PDF-" + b"x" * (5 * 1024 * 1024), "application/pdf").status_code == 413
    r = up(PDF, "application/pdf", "../../etc/passwd<script>.exe")
    assert r.status_code == 201, r.text
    cert = r.json()
    assert cert["filename"] == "passwd_script_.pdf" and cert["size_bytes"] == len(PDF)
    assert up(PNG, "image/png", "photo.png").status_code == 201
    lst = admin.get(f"/api/it-assets/{a['id']}/certificates").json()
    assert len(lst) == 2 and "data" not in lst[0]
    dl = admin.get(f"/api/it-assets/{a['id']}/certificates/{cert['id']}")
    assert dl.status_code == 200 and dl.content == PDF and dl.headers["content-type"] == "application/pdf"
    assert "attachment" in dl.headers["content-disposition"] and "sandbox" in dl.headers["content-security-policy"]
    assert admin.delete(f"/api/it-assets/{a['id']}/certificates/{cert['id']}?reason=wrong%20file").status_code == 204
    assert [e["event_type"] for e in events(admin, a["id"])][:4] == [
        "certificate_deleted", "certificate_uploaded", "certificate_uploaded", "disposed"]
    acts = audit_actions()
    assert {"it_asset_disposed", "it_asset_certificate_uploaded", "it_asset_certificate_downloaded",
            "it_asset_certificate_deleted"} <= set(acts)


# --------------------------------------------------------------------------- agent devices
def test_agent_devices_get_asset_records(admin):
    manual = new_asset(admin, asset_tag="WK-LAPTOP-9", serial_number="pf12345", manufacturer="", model="")
    dev1 = add_device()  # same serial as the manual record -> linked, not duplicated
    dev2 = add_device(hostname="MAC-01", serial_number="C02XYZ", model="MacBookPro18,1",
                      last_seen_at=utcnow() - timedelta(days=45))
    lst = admin.get("/api/it-assets").json()
    assert len(lst) == 2
    linked = admin.get(f"/api/it-assets/by-device/{dev1}").json()
    assert linked["id"] == manual["id"] and linked["device_hostname"] == "LAPTOP-001"
    assert linked["manufacturer"] == "LENOVO" and linked["model"] == "ThinkPad X1 Carbon"  # blanks filled
    auto = admin.get(f"/api/it-assets/by-device/{dev2}").json()
    assert auto["source"] == "agent" and auto["asset_type"] == "laptop" and auto["serial_number"] == "C02XYZ"
    assert auto["asset_tag"].startswith("AGT-") and auto["idle"] is True and linked["idle"] is False
    assert [x["id"] for x in admin.get("/api/it-assets?flag=idle").json()] == [auto["id"]]
    assert admin.get("/api/it-assets?agent=no").json() == []
    assert admin.get("/api/it-assets?q=mac-01").json()[0]["id"] == auto["id"]
    s = admin.get("/api/it-assets/summary").json()
    assert s["idle"] == 1 and s["with_agent"] == 2 and s["total"] == 2
    # idempotent
    assert len(admin.get("/api/it-assets").json()) == 2
    # linking a device that is already linked elsewhere is refused
    other = new_asset(admin, asset_tag="WK-X", serial_number="")
    assert admin.patch(f"/api/it-assets/{other['id']}", json={"device_id": dev1}).status_code == 409
    # device deleted -> asset kept, link cleared
    assert admin.delete(f"/api/devices/{dev2}?reason=gone").status_code == 204
    kept = admin.get(f"/api/it-assets/{auto['id']}").json()
    assert kept["device_id"] is None and kept["asset_tag"] == auto["asset_tag"]
    assert admin.get(f"/api/it-assets/by-device/{dev2}").status_code == 404


def test_dashboard_summary(admin):
    new_asset(admin, asset_tag="A1", purchase_cost="100", warranty_end=(utcnow() + timedelta(days=10)).date().isoformat())
    new_asset(admin, asset_tag="A2", purchase_cost="50.25", currency="USD", asset_type="monitor")
    gone = new_asset(admin, asset_tag="A3", purchase_cost="999")
    admin.post(f"/api/it-assets/{gone['id']}/dispose", json={"method": "destroyed",
                                                             "disposal_date": utcnow().date().isoformat()})
    s = admin.get("/api/it-assets/summary").json()
    assert s["total"] == 3 and s["active"] == 2 and s["by_status"]["disposed"] == 1 and s["by_status"]["in_stock"] == 2
    assert s["value_by_currency"] == {"NGN": 100.0, "USD": 50.25}
    assert s["by_type"] == {"laptop": 1, "monitor": 1}
    assert s["warranty_expiring"] == 1 and s["warranty_expiring_assets"][0]["asset_tag"] == "A1"
    assert [x["asset_tag"] for x in admin.get("/api/it-assets?flag=warranty_expiring").json()] == ["A1"]
    assert [x["asset_tag"] for x in admin.get("/api/it-assets?status=active").json()] == ["A1", "A2"]
    assert [x["asset_tag"] for x in admin.get("/api/it-assets?type=monitor").json()] == ["A2"]


# --------------------------------------------------------------------------- CSV
def test_csv_export_neutralises_formulas(admin):
    new_asset(admin, asset_tag="WK-9", model="=HYPERLINK(\"http://evil\")", notes="+SUM(A1)",
              manufacturer="@cmd", supplier="-2+3", serial_number="\tTAB")
    r = admin.get("/api/it-assets/export.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == 1
    row = rows[0]
    assert row["model"] == "'=HYPERLINK(\"http://evil\")" and row["notes"] == "'+SUM(A1)"
    assert row["manufacturer"] == "'@cmd" and row["supplier"] == "'-2+3"
    for v in row.values():
        assert not v.startswith(("=", "+", "-", "@", "\t", "\r")), v
    assert "it_assets_exported" in audit_actions()


def test_csv_import_round_trip_and_validation(admin):
    admin.put("/api/it-assets/settings", json={"custom_fields": [{"key": "cost_centre", "label": "Cost centre"}]})
    existing = new_asset(admin, asset_tag="WK-1", model="=SUM(1)")
    exported = admin.get("/api/it-assets/export.csv").text
    # re-importing the export is a no-op (quote prefix stripped again)
    r = admin.post("/api/it-assets/import", content=exported.encode(), headers={"Content-Type": "text/csv"})
    assert r.status_code == 200, r.text
    assert r.json()["unchanged"] == 1 and r.json()["created"] == 0
    assert admin.get(f"/api/it-assets/{existing['id']}").json()["model"] == "=SUM(1)"

    good = ("﻿asset_tag,asset_type,model,status,assignee_email,assignee_name,purchase_cost,currency,"
            "warranty_end,custom.cost_centre\n"
            "WK-1,laptop,ThinkPad T14,assigned,ada@example.com,Ada,\"1,200,000.00\",NGN,2029-05-01,CC-1\n"
            "MON-7,monitor,Dell U2723QE,,,,350000,,,\n"
            "PH-1,phone,iPhone 15,assigned,bola@example.com,Bola,,,,\n")
    r = admin.post("/api/it-assets/import?dry_run=true", content=good.encode(), headers={"Content-Type": "text/csv"})
    assert r.status_code == 200 and r.json()["dry_run"] is True and r.json()["created"] == 2
    assert len(admin.get("/api/it-assets").json()) == 1  # dry run wrote nothing
    r = admin.post("/api/it-assets/import", content=good.encode(), headers={"Content-Type": "text/csv"})
    assert r.status_code == 200, r.text
    assert (r.json()["created"], r.json()["updated"]) == (2, 1)
    wk1 = admin.get(f"/api/it-assets/{existing['id']}").json()
    assert wk1["status"] == "assigned" and wk1["assignee_email"] == "ada@example.com"
    assert wk1["purchase_cost"] == 1200000.0 and wk1["custom_fields"] == {"cost_centre": "CC-1"}
    mon = admin.get("/api/it-assets?q=MON-7").json()[0]
    assert mon["status"] == "in_stock" and mon["source"] == "import" and mon["currency"] == "NGN"
    assert events(admin, existing["id"])[0]["event_type"] == "imported"
    assert "it_assets_imported" in audit_actions()

    # all-or-nothing with per-row errors
    bad = ("asset_tag,status,purchase_date,purchase_cost,assignee_email\n"
           "NEW-1,in_stock,2025-01-01,10,\n"
           "NEW-2,disposed,,,\n"
           "NEW-3,,not-a-date,,\n"
           "NEW-4,,,-5,\n"
           "NEW-5,,,,not-an-email\n"
           "NEW-1,,,,\n"
           ",in_stock,,,\n")
    r = admin.post("/api/it-assets/import", content=bad.encode(), headers={"Content-Type": "text/csv"})
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert [e["row"] for e in detail["errors"]] == [3, 4, 5, 6, 7, 8]
    assert admin.get("/api/it-assets?q=NEW-1").json() == []
    for body, msg in ((b"", "body"), (b"serial_number\nx\n", "asset_tag"), (b"asset_tag,foo\nx,y\n", "unknown"),
                      (b"asset_tag,custom.nope\nx,y\n", "undefined custom"), ("asset_tag\n\xe9\n".encode("latin-1"),
                                                                              "UTF-8")):
        r = admin.post("/api/it-assets/import", content=body, headers={"Content-Type": "text/csv"})
        assert r.status_code == 422 and msg in r.text, (body, r.text)


def test_csv_import_limits(admin, monkeypatch):
    monkeypatch.setenv("ASSET_IMPORT_MAX_ROWS", "2")
    from app import config

    config.reload_settings()
    body = "asset_tag\nA\nB\nC\n"
    r = admin.post("/api/it-assets/import", content=body.encode(), headers={"Content-Type": "text/csv"})
    assert r.status_code == 422 and "too many rows" in r.text


# --------------------------------------------------------------------------- notifications
def test_notifications_overdue_warranty_unseen_lost(admin):
    from app.notifications import dispatcher
    from app.notifications.models import NotificationEvent

    soon = (utcnow() + timedelta(days=5)).date().isoformat()
    a = new_asset(admin, asset_tag="WK-W", warranty_end=soon)
    b = new_asset(admin, asset_tag="WK-R", warranty_end="2035-01-01")
    admin.post(f"/api/it-assets/{b['id']}/assign", json={"assignee_email": "gone@example.com"})
    admin.post("/api/it-assets/offboardings", json={"person_email": "gone@example.com",
                                                    "leave_date": (utcnow() - timedelta(days=30)).date().isoformat()})
    add_device(hostname="OLD-PC", serial_number="OLD1", model="OptiPlex 7090",
               last_seen_at=utcnow() - timedelta(days=60))
    admin.get("/api/it-assets")  # sync creates the device's asset record

    def asset_events():
        with db.get_session() as s:
            return sorted((e.event_type, e.attributes.get("asset_tag")) for e in s.scalars(
                select(NotificationEvent).where(NotificationEvent.source == "asset_lifecycle")))

    with db.get_session() as s:
        dispatcher.poll_sources(s, force=True)
    got = asset_events()
    types = [t for t, _ in got]
    assert ("warranty_expiring", "WK-W") in got and ("retrieval_overdue", "WK-R") in got
    assert types.count("device_unseen") == 1 and len(got) == 3
    # no repeats while nothing changes
    with db.get_session() as s:
        dispatcher.poll_sources(s, force=True)
    assert len(asset_events()) == 3
    # push event for lost / stolen
    admin.post(f"/api/it-assets/{a['id']}/status", json={"status": "stolen", "notes": "car break-in"})
    assert ("lost_or_stolen", "WK-W") in asset_events()
    meta = admin.get("/api/notifications/meta").json()
    src = next(x for x in meta["sources"] if x["name"] == "asset_lifecycle")
    assert set(src["event_types"]) == {"retrieval_overdue", "warranty_expiring", "device_unseen", "lost_or_stolen"}


# --------------------------------------------------------------------------- RBAC
def test_rbac(admin):
    a = new_asset(admin)
    viewer = role_client(admin, "viewer")
    analyst = role_client(admin, "analyst")
    reads = ["/api/it-assets", "/api/it-assets/summary", "/api/it-assets/settings", "/api/it-assets/offboardings",
             f"/api/it-assets/{a['id']}", f"/api/it-assets/{a['id']}/events", f"/api/it-assets/{a['id']}/certificates",
             "/api/it-assets/export.csv"]
    for path in reads:
        assert viewer.get(path).status_code == 200, path
    analyst_writes = [
        ("POST", "/api/it-assets", {"asset_tag": "V-1"}),
        ("PATCH", f"/api/it-assets/{a['id']}", {"notes": "x"}),
        ("POST", f"/api/it-assets/{a['id']}/assign", {"assignee_email": "v@example.com"}),
        ("POST", f"/api/it-assets/{a['id']}/status", {"status": "in_repair"}),
        ("POST", f"/api/it-assets/{a['id']}/return", {}),
        ("POST", "/api/it-assets/offboardings", {"person_email": "v@example.com", "leave_date": "2026-12-01"}),
        ("POST", f"/api/it-assets/{a['id']}/dispose", {"method": "recycled", "disposal_date": "2026-10-01"}),
    ]
    for method, path, body in analyst_writes:
        assert viewer.request(method, path, json=body).status_code == 403, (method, path)
    assert viewer.post(f"/api/it-assets/certificates/{a['id']}", content=PDF,
                       headers={"Content-Type": "application/pdf"}).status_code == 403
    assert viewer.post("/api/it-assets/import", content=b"asset_tag\nV-9\n",
                       headers={"Content-Type": "text/csv"}).status_code == 403
    for method, path, body in analyst_writes:
        assert analyst.request(method, path, json=body).status_code in (200, 201), (method, path)
    r = analyst.post(f"/api/it-assets/certificates/{a['id']}", content=PDF, headers={"Content-Type": "application/pdf"})
    assert r.status_code == 201
    cert = r.json()
    assert viewer.get(f"/api/it-assets/{a['id']}/certificates/{cert['id']}").status_code == 403
    assert analyst.get(f"/api/it-assets/{a['id']}/certificates/{cert['id']}").status_code == 200
    assert analyst.post("/api/it-assets/import", content=b"asset_tag\nV-9\n",
                        headers={"Content-Type": "text/csv"}).status_code == 200
    admin_only = [("PUT", "/api/it-assets/settings", {"idle_days": 5}),
                  ("DELETE", f"/api/it-assets/{a['id']}/certificates/{cert['id']}?reason=test", None),
                  ("DELETE", f"/api/it-assets/{a['id']}?reason=test", None)]
    for method, path, body in admin_only:
        assert analyst.request(method, path, json=body).status_code == 403, (method, path)
        assert viewer.request(method, path, json=body).status_code == 403, (method, path)
    for method, path, body in admin_only:
        assert admin.request(method, path, json=body).status_code in (200, 204), (method, path)
    assert admin.get(f"/api/it-assets/{a['id']}").status_code == 404
    assert "it_asset_deleted" in audit_actions()
    anon = TestClient(admin.app, base_url=BASE_URL)
    assert anon.get("/api/it-assets").status_code == 401
    # CSRF is enforced like everywhere else
    no_csrf = TestClient(admin.app, base_url=BASE_URL)
    login(no_csrf, "analyst@example.com", "a-long-test-password")
    no_csrf.headers.pop("X-CSRF-Token")
    assert no_csrf.post("/api/it-assets", json={"asset_tag": "CSRF-1"}).status_code == 403
