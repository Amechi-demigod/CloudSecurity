"""CSV / JSON exports of Computers & servers and Cloud resources (/api/devices/export, /api/assets/export)."""
from __future__ import annotations

import csv
import io

from sqlalchemy import select

from app import db
from app.models import Asset, AuditLog, Device, Finding
from tests.test_devices import agent_client, enroll, new_token, windows_checkin
from tests.test_tenancy import acme_device, tenants  # noqa: F401  (fixture)


def parse_csv(resp) -> list[dict]:
    assert resp.status_code == 200, resp.text
    assert resp.content.startswith(b"\xef\xbb\xbf")  # BOM for Excel
    return list(csv.DictReader(io.StringIO(resp.content.decode("utf-8-sig"))))


def add_asset(c, aid: str, name: str, **kw):
    with db.get_session("default") as s:
        s.add(Asset(id=aid, name=name, type=kw.pop("type", "vm"), **kw))
        s.commit()


def enroll_device(c, machine: str, hostname: str):
    token = new_token(c)
    agent = agent_client(c.app)
    r = enroll(agent, token, machine_id=machine, hostname=hostname)
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    body = windows_checkin()
    body["device"]["hostname"] = hostname
    assert agent.post("/api/agent/checkin", json=body).status_code == 200
    return r.json()["device_id"]


# ----------------------------------------------------------------------------- cloud resources
def test_assets_csv_json_filters_and_shadow_assets(empty_client):
    c = empty_client
    add_asset(c, "a1", "web-1", provider="aws", region="eu-west-1", internet_exposed=True, source="aws")
    add_asset(c, "a2", "db-1", type="sql_database", provider="azure", region="uksouth", source="azure")
    add_asset(c, "n1", "10.0.0.9", provider="network", source="network")  # network shadow asset
    with db.get_session("default") as s:
        s.add(Finding(rule_id="R1", asset_id="a1", severity="high", title="t", status="open", source="x"))
        s.commit()

    rows = parse_csv(c.get("/api/assets/export?format=csv"))
    assert {r["name"] for r in rows} == {"web-1", "db-1"}
    web = next(r for r in rows if r["name"] == "web-1")
    assert web["internet_exposed"] == "yes" and web["open_findings"] == "1" and web["provider"] == "aws"
    assert web["first_seen"].endswith("+00:00")

    r = c.get("/api/assets/export?format=json&provider=aws")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert r.headers["content-disposition"].endswith('.json"') and "cloud-resources-" in r.headers["content-disposition"]
    data = r.json()
    assert data["count"] == 1 and [i["name"] for i in data["items"]] == ["web-1"] and data["exported_at"]
    assert data["items"][0]["internet_exposed"] is True


def test_assets_csv_formula_injection_escaped(empty_client):
    c = empty_client
    add_asset(c, "a1", '=HYPERLINK("http://x","click")', provider="aws", source="aws", resource_group="@grp")
    row = parse_csv(c.get("/api/assets/export?format=csv"))[0]
    assert row["name"] == '\'=HYPERLINK("http://x","click")'
    assert row["resource_group"] == "'@grp"


def test_assets_export_writes_audit_row(empty_client):
    c = empty_client
    add_asset(c, "a1", "one", source="aws")
    assert c.get("/api/assets/export?format=csv").status_code == 200
    with db.get_session("default") as s:
        a = s.scalars(select(AuditLog).where(AuditLog.action == "export_downloaded")).one()
        assert a.detail == {"table": "cloud_resources", "format": "csv", "rows": 1}


def test_export_rejects_bad_format(empty_client):
    assert empty_client.get("/api/assets/export?format=xml").status_code == 422
    assert empty_client.get("/api/devices/export?format=xml").status_code == 422


def test_export_requires_sign_in(anon_client):
    assert anon_client.get("/api/assets/export").status_code in (401, 403)
    assert anon_client.get("/api/devices/export").status_code in (401, 403)


def test_export_row_cap(empty_client, monkeypatch):
    from app.services import exports

    monkeypatch.setattr(exports, "MAX_EXPORT_ROWS", 1)
    add_asset(empty_client, "a1", "one", source="aws")
    add_asset(empty_client, "a2", "two", source="aws")
    r = empty_client.get("/api/assets/export?format=csv")
    assert r.status_code == 413 and "Too many rows" in r.json()["detail"]


# ----------------------------------------------------------------------------- devices
def test_devices_csv_json_and_filter(empty_client):
    c = empty_client
    enroll_device(c, "a" * 64, "LAPTOP-A")
    enroll_device(c, "b" * 64, "SERVER-B")
    rows = parse_csv(c.get("/api/devices/export?format=csv"))
    assert {r["name"] for r in rows} == {"LAPTOP-A", "SERVER-B"}
    a = next(r for r in rows if r["name"] == "LAPTOP-A")
    assert a["encryption"] == "on" and a["firewall"] == "on" and a["ip_addresses"] == "10.0.0.5"
    assert a["last_seen"].endswith("+00:00") and a["status"] == "active" and a["user"] == "CORP\\alice"

    r = c.get("/api/devices/export?format=json&q=server")
    assert r.status_code == 200 and "computers-" in r.headers["content-disposition"]
    data = r.json()
    assert data["count"] == 1 and data["items"][0]["name"] == "SERVER-B"
    assert data["items"][0]["ip_addresses"] == ["10.0.0.5"]


def test_devices_export_escapes_formulas_and_audits(empty_client):
    c = empty_client
    enroll_device(c, "a" * 64, "=cmd|' /C calc'!A0")
    row = parse_csv(c.get("/api/devices/export?format=csv"))[0]
    assert row["name"].startswith("'=cmd")
    with db.get_session("default") as s:
        a = s.scalars(select(AuditLog).where(AuditLog.action == "export_downloaded")).one()
        assert a.detail == {"table": "devices", "format": "csv", "rows": 1}
        assert s.scalar(select(Device.id)) is not None


# ----------------------------------------------------------------------------- tenancy
def test_exports_never_include_another_organisations_rows(tenants):  # noqa: F811
    acme_device(tenants)
    with db.get_session(tenants.acme_id) as s:
        s.add(Asset(id="acme-1", name="acme-bucket", type="storage_account", source="aws", provider="aws"))
        s.commit()
    acme_assets = parse_csv(tenants.acme.get("/api/assets/export?format=csv"))
    assert [r["name"] for r in acme_assets] == ["acme-bucket"]
    default_assets = parse_csv(tenants.default.get("/api/assets/export?format=csv"))
    assert "acme-bucket" not in {r["name"] for r in default_assets}
    assert [r["name"] for r in parse_csv(tenants.acme.get("/api/devices/export?format=csv"))] == ["ACME-LAPTOP"]
    assert "ACME-LAPTOP" not in {r["name"] for r in parse_csv(tenants.default.get("/api/devices/export?format=csv"))}
    with db.get_session(tenants.acme_id) as s:
        assert s.scalars(select(AuditLog).where(AuditLog.action == "export_downloaded")).all()
