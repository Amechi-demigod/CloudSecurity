"""Missing OS updates (docs/PATCHING.md): the agent's Windows Update report,
derived issues and notifications, "Check for updates now" (RBAC, version
gating, audit), CSV export and tenancy. Runs on SQLite and PostgreSQL."""
from __future__ import annotations

import csv
import io
from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

from app import db
from app.models import Device, DeviceOsUpdates, Vulnerability, utcnow
from tests.conftest import BASE_URL, login, make_user
from tests.test_cross_feature import device_events
from tests.test_devices import agent_client, enroll, new_token, queue, windows_checkin
from tests.test_tenancy import acme_device, tenants  # noqa: F401  (fixture)

FEATURES = "check_for_update,host_isolation,directory_collector,remote_session,windows_updates"


def days_ago(n: int) -> str:
    return (date.today() - timedelta(days=n)).isoformat()


def update(title: str, *, kb: str = "KB5044284", cls: str = "security", sev: str = "Important", age: int = 40,
           cves: list[str] | None = None, **extra) -> dict:
    return {"update_id": "a1b2c3d4-0000-4000-8000-000000000001", "kb_ids": [kb], "title": title,
            "classification": cls, "msrc_severity": sev, "release_date": days_ago(age), "cve_ids": cves or [],
            "reboot_behavior": "can_request", "size_bytes": 734003200, "downloaded": False, **extra}


def report(**over) -> dict:
    body = {
        "schema_version": 1, "scanned_at": utcnow().isoformat() + "Z", "status": "ok", "trigger": "schedule",
        "duration_seconds": 42, "source": "wsus", "source_detail": "https://wsus.corp.example:8531",
        "service_state": "running", "service_start_type": "manual", "reboot_pending": False,
        "last_search_success_at": utcnow().isoformat() + "Z", "last_install_success_at": None,
        "updates": [
            update("2026-10 Cumulative Update for Windows 11 Version 23H2 (KB5044284)", sev="Critical", age=20,
                   cves=["CVE-2026-21001", "CVE-2026-21002"]),
            update("2026-09 .NET Framework security update (KB5043050)", kb="KB5043050", age=45),
            update("Security Intelligence Update for Microsoft Defender (KB2267602)", kb="KB2267602",
                   cls="definition", sev="", age=0),
        ],
    }
    body.update(over)
    return body


@pytest.fixture()
def device(empty_client):
    """(agent client advertising windows_updates, device_id)."""
    agent = agent_client(empty_client.app)
    r = enroll(agent, new_token(empty_client))
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    agent.headers["X-CNAPP-Agent-Features"] = FEATURES
    assert agent.post("/api/agent/checkin", json=windows_checkin()).status_code == 200
    return agent, r.json()["device_id"]


def test_report_stored_and_shown(empty_client, device):
    admin = empty_client
    agent, device_id = device
    view = admin.get(f"/api/devices/{device_id}/os-updates").json()
    assert view["supported"] is True and view["report"] is None
    assert agent.post("/api/agent/os-updates", json=report()).status_code == 204
    view = admin.get(f"/api/devices/{device_id}/os-updates").json()
    rep = view["report"]
    assert (rep["missing_count"], rep["security_count"], rep["critical_count"]) == (3, 2, 1)
    assert rep["source"] == "wsus" and rep["source_detail"] == "https://wsus.corp.example:8531"
    # critical first, then other security updates, then the rest
    assert [u["kb_ids"][0] for u in rep["updates"]] == ["KB5044284", "KB5043050", "KB2267602"]
    assert rep["updates"][0]["age_days"] == 20 and rep["updates"][0]["security"] is True
    assert rep["updates"][2]["security"] is False and rep["oldest_security_days"] == 45
    assert rep["scanned_at"].endswith("Z") and rep["last_success_at"].endswith("Z")  # UTC for the browser
    # summary on the Devices list
    d = next(x for x in admin.get("/api/devices").json() if x["id"] == device_id)
    assert d["os_updates"]["missing"] == 3 and d["os_updates"]["security"] == 2


def test_failed_search_keeps_the_last_list(empty_client, device):
    agent, device_id = device
    agent.post("/api/agent/os-updates", json=report())
    r = agent.post("/api/agent/os-updates", json=report(status="failed", error="0x8024401C: WSUS timed out",
                                                        updates=[], last_search_success_at=None))
    assert r.status_code == 204
    rep = empty_client.get(f"/api/devices/{device_id}/os-updates").json()["report"]
    assert rep["scan_status"] == "failed" and "8024401C" in rep["scan_error"]
    assert rep["missing_count"] == 3 and len(rep["updates"]) == 3 and rep["last_success_at"]
    assert rep["listed_at"] and rep["listed_at"] != rep["scanned_at"]  # the list is from the earlier search
    # a later successful search with nothing missing replaces it
    agent.post("/api/agent/os-updates", json=report(updates=[]))
    rep = empty_client.get(f"/api/devices/{device_id}/os-updates").json()["report"]
    assert rep["missing_count"] == 0 and rep["updates"] == [] and rep["scan_status"] == "ok"


@pytest.mark.parametrize("mutate", [
    lambda b: b.update(unexpected=1),
    lambda b: b["updates"][0].update(kb_ids=["5044284"]),
    lambda b: b["updates"][0].update(cve_ids=["CVE-2026-1;rm"]),
    lambda b: b["updates"][0].update(classification="malware"),
    lambda b: b.update(source="somewhere"),
    lambda b: b.update(updates=[update(f"u{i}") for i in range(1001)]),
])
def test_report_strict_validation(device, mutate):
    agent, _ = device
    body = report()
    mutate(body)
    assert agent.post("/api/agent/os-updates", json=body).status_code == 422


def test_report_requires_device_credential_and_windows(empty_client, device):
    assert TestClient(empty_client.app, base_url=BASE_URL).post("/api/agent/os-updates", json=report()).status_code == 401
    assert empty_client.post("/api/agent/os-updates", json=report()).status_code == 401  # a user session is not enough
    mac = agent_client(empty_client.app)
    r = enroll(mac, new_token(empty_client), machine_id="b" * 64, os_family="macos", hostname="MAC-1")
    mac.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    assert mac.post("/api/agent/os-updates", json=report()).status_code == 409


def _set(device_id: str, **values) -> None:
    with db.get_session("default") as s:
        st = s.get(DeviceOsUpdates, device_id)
        for k, v in values.items():
            setattr(st, k, v)
        s.commit()


def codes(admin, device_id) -> list[str]:
    return [i["code"] for i in admin.get(f"/api/devices/{device_id}").json()["issues"]]


def test_issues_and_health(empty_client, device):
    admin = empty_client
    agent, device_id = device
    # pending posture count is superseded by the report
    body = windows_checkin()
    body["posture"]["os_updates"] = {"status": "fail", "detail": "3 pending", "data": {"pending_count": 3}}
    agent.post("/api/agent/checkin", json=body)
    with db.get_session("default") as s:
        s.get(Device, device_id).updates_pending_since = utcnow() - timedelta(days=30)
        s.commit()
    assert "os_updates_pending" in codes(admin, device_id)
    # critical update 20 days old (> 14), security update 45 days old (> 30)
    agent.post("/api/agent/os-updates", json=report())
    c = codes(admin, device_id)
    assert "os_updates_pending" not in c
    assert {"os_critical_updates_missing", "os_security_updates_missing"} <= set(c)
    d = admin.get(f"/api/devices/{device_id}").json()
    assert d["health"] == "critical"
    issue = next(i for i in d["issues"] if i["code"] == "os_critical_updates_missing")
    assert issue["severity"] == "high" and "20 days" in issue["detail"]
    # young updates only: no issue
    agent.post("/api/agent/os-updates", json=report(updates=[update("new", sev="Critical", age=3),
                                                             update("newer", age=10)]))
    assert not {"os_critical_updates_missing", "os_security_updates_missing"} & set(codes(admin, device_id))
    # restart pending: only after 7 days
    agent.post("/api/agent/os-updates", json=report(updates=[], reboot_pending=True))
    assert "os_reboot_pending" not in codes(admin, device_id)
    _set(device_id, reboot_pending_since=utcnow() - timedelta(days=8))
    assert "os_reboot_pending" in codes(admin, device_id)
    agent.post("/api/agent/os-updates", json=report(updates=[], reboot_pending=False))
    assert "os_reboot_pending" not in codes(admin, device_id)
    # Windows Update service disabled
    agent.post("/api/agent/os-updates", json=report(updates=[], service_start_type="disabled",
                                                    service_state="stopped"))
    assert "windows_update_disabled" in codes(admin, device_id)
    # no successful search for 8 days
    agent.post("/api/agent/os-updates", json=report(updates=[], status="failed", error="0x80070422",
                                                    last_search_success_at=None))
    assert "os_update_scan_stale" not in codes(admin, device_id)
    _set(device_id, last_success_at=utcnow() - timedelta(days=8))
    issue = next(i for i in admin.get(f"/api/devices/{device_id}").json()["issues"]
                 if i["code"] == "os_update_scan_stale")
    assert "8 days" in issue["detail"] and "0x80070422" in issue["detail"]
    types = {t["code"] for t in admin.get("/api/devices/issue-types").json()}
    assert {"os_critical_updates_missing", "os_update_scan_stale", "windows_update_disabled"} <= types


def test_issue_notifications_on_check_in(empty_client, device):
    agent, _ = device
    agent.post("/api/agent/os-updates", json=report())
    assert device_events("os_critical_updates_missing") == []  # raised with the next check-in
    agent.post("/api/agent/checkin", json=windows_checkin())
    [ev] = device_events("os_critical_updates_missing")
    assert ev.severity == "high" and "LAPTOP-001" in ev.title
    agent.post("/api/agent/checkin", json=windows_checkin())
    assert len(device_events("os_critical_updates_missing")) == 1  # only when it appears


def test_devices_list_filter_and_dashboard(empty_client, device):
    admin = empty_client
    agent, device_id = device
    other = agent_client(admin.app)
    r = enroll(other, new_token(admin), machine_id="d" * 64, hostname="LAPTOP-002")
    other.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    other_id = r.json()["device_id"]

    def listed(v):
        return {d["id"] for d in admin.get("/api/devices", params={"updates": v}).json()}

    assert listed("unknown") >= {device_id, other_id}
    # a device whose first search failed is not "up to date"
    agent.post("/api/agent/os-updates", json=report(status="failed", error="0x80070422", updates=[]))
    assert device_id not in listed("none") and device_id not in listed("unknown")
    d = next(x for x in admin.get("/api/devices").json() if x["id"] == device_id)
    assert d["os_updates"]["listed"] is False
    assert admin.get("/api/dashboards/endpoints").json()["os_updates"]["reporting"] == 0
    agent.post("/api/agent/os-updates", json=report())
    assert device_id in listed("security") and device_id in listed("any")
    assert device_id not in listed("none") and device_id not in listed("unknown") and other_id in listed("unknown")
    assert admin.get("/api/devices", params={"updates": "bogus"}).status_code == 422
    tile = admin.get("/api/dashboards/endpoints").json()["os_updates"]
    assert tile["reporting"] == 1 and tile["devices_missing_security"] == 1 and tile["oldest_security_days"] == 45
    agent.post("/api/agent/os-updates", json=report(updates=[]))
    assert device_id in listed("none")


def test_scan_now_rbac_gating_and_audit(empty_client, device):
    admin = empty_client
    agent, device_id = device
    make_user(admin, "viewer")
    make_user(admin, "analyst")
    viewer, analyst = TestClient(admin.app, base_url=BASE_URL), TestClient(admin.app, base_url=BASE_URL)
    login(viewer, "viewer@example.com", "a-long-test-password")
    login(analyst, "analyst@example.com", "a-long-test-password")
    assert viewer.get(f"/api/devices/{device_id}/os-updates").status_code == 200
    assert viewer.post(f"/api/devices/{device_id}/os-updates/scan", json={}).status_code == 403
    # not through the generic command endpoint
    assert queue(admin, device_id, "scan_os_updates").status_code == 422
    r = analyst.post(f"/api/devices/{device_id}/os-updates/scan", json={"reason": "patch Tuesday check"})
    assert r.status_code == 201, r.text
    cid = r.json()["command_id"]
    assert analyst.post(f"/api/devices/{device_id}/os-updates/scan").status_code == 409  # already queued
    view = admin.get(f"/api/devices/{device_id}/os-updates").json()
    assert view["pending_scan"]["command_id"] == cid and view["pending_scan"]["requested_by"] == "analyst@example.com"
    audit = admin.get("/api/audit-log?action=device_command_created").json()[0]
    assert audit["detail"]["type"] == "scan_os_updates" and audit["detail"]["reason"] == "patch Tuesday check"
    [cmd] = agent.get("/api/agent/commands").json()["commands"]
    assert cmd["type"] == "scan_os_updates" and cmd["params"] == {}
    assert agent.post(f"/api/agent/commands/{cid}/result",
                      json={"nonce": cmd["nonce"], "status": "succeeded", "output": "search started"}).status_code == 204
    assert admin.get(f"/api/devices/{device_id}/os-updates").json()["pending_scan"] is None
    # an analyst may cancel a pending check
    cid = analyst.post(f"/api/devices/{device_id}/os-updates/scan").json()["command_id"]
    r = analyst.post(f"/api/devices/{device_id}/commands/{cid}/cancel", json={"reason": "not needed"})
    assert r.status_code == 200 and r.json()["status"] == "cancelled"


def test_scan_now_needs_new_agent_and_windows(empty_client):
    admin = empty_client
    old = agent_client(admin.app)
    r = enroll(old, new_token(admin))
    old.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    old.headers["X-CNAPP-Agent-Features"] = "check_for_update,host_isolation"
    old.post("/api/agent/checkin", json=windows_checkin())
    old_id = r.json()["device_id"]
    view = admin.get(f"/api/devices/{old_id}/os-updates").json()
    assert view["supported"] is False and view["agent_update_required"] is True
    assert "Agent update required" in view["unsupported_reason"] and "1.4.0" in view["unsupported_reason"]
    r = admin.post(f"/api/devices/{old_id}/os-updates/scan")
    assert r.status_code == 409 and "Agent update required" in r.json()["detail"]
    mac = agent_client(admin.app)
    r = enroll(mac, new_token(admin), machine_id="b" * 64, os_family="macos", hostname="MAC-1")
    mac_id = r.json()["device_id"]
    view = admin.get(f"/api/devices/{mac_id}/os-updates").json()
    assert view["supported"] is False and view["agent_update_required"] is False
    assert "Windows only" in admin.post(f"/api/devices/{mac_id}/os-updates/scan").json()["detail"]


def test_known_cves_link_to_vulnerabilities(empty_client, device):
    agent, device_id = device
    with db.get_session("default") as s:
        s.add(Vulnerability(device_id=device_id, cve_id="CVE-2026-21002", package="Windows 11", version="23H2",
                            cvss=8.8, severity="high"))
        s.commit()
    agent.post("/api/agent/os-updates", json=report())
    u = empty_client.get(f"/api/devices/{device_id}/os-updates").json()["report"]["updates"][0]
    assert u["cve_ids"] == ["CVE-2026-21001", "CVE-2026-21002"] and u["known_cves"] == ["CVE-2026-21002"]


def test_csv_export(empty_client, device):
    agent, device_id = device
    agent.post("/api/agent/os-updates", json=report(updates=[
        update("=HYPERLINK(\"http://evil\")", kb="KB5000001", age=50), update("Defender", kb="KB2267602",
                                                                             cls="definition", sev="")]))
    r = empty_client.get("/api/os-updates/export.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == 1  # security only by default
    row = rows[0]
    assert row["hostname"] == "LAPTOP-001" and row["kb_ids"] == "KB5000001" and row["age_days"] == "50"
    assert not row["title"].startswith("=")  # spreadsheet formulas neutralised
    assert row["catalog_url"].endswith("q=KB5000001")
    rows = list(csv.DictReader(io.StringIO(empty_client.get("/api/os-updates/export.csv?scope=all").text)))
    assert len(rows) == 2
    audit = empty_client.get("/api/audit-log?action=os_updates_exported").json()[0]
    assert audit["detail"]["rows"] == 2 and audit["detail"]["scope"] == "all"


def test_reports_stay_in_their_organisation(tenants):  # noqa: F811
    agent, acme_id = acme_device(tenants)
    agent.post("/api/agent/os-updates", json=report())
    assert tenants.acme.get(f"/api/devices/{acme_id}/os-updates").json()["report"]["missing_count"] == 3
    assert tenants.default.get(f"/api/devices/{acme_id}/os-updates").status_code == 404
    assert tenants.default.post(f"/api/devices/{acme_id}/os-updates/scan").status_code == 404
    assert "ACME-LAPTOP" not in tenants.default.get("/api/os-updates/export.csv").text
    assert "ACME-LAPTOP" in tenants.acme.get("/api/os-updates/export.csv").text
    with db.get_session(unscoped=True) as s:
        assert s.get(DeviceOsUpdates, acme_id).organization_id == tenants.acme_id


def test_deleting_the_device_removes_the_report(empty_client, device):
    agent, device_id = device
    agent.post("/api/agent/os-updates", json=report())
    assert empty_client.delete(f"/api/devices/{device_id}?reason=decommissioned").status_code == 204
    with db.get_session("default") as s:
        assert s.get(DeviceOsUpdates, device_id) is None
