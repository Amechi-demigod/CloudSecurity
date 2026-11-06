"""Vulnerability fixes (docs/VULNERABILITIES.md#fixes-and-guidance): the MSRC CVRF feed (recorded-style
fixture, no network), Windows CVE -> KB / build, offline degradation, fix grouping per device, the CVE
page, PDF exports, RBAC / audit and tenancy."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app import db
from app.models import AuditLog, Device, Vulnerability, VulnFeedCache, VulnFeedStatus
from app.services import vuln_fixes as svc
from app.services.vuln_sla import fix_due
from app.vulnmatch import feeds, msrc
from tests.conftest import BASE_URL, login, make_user
from tests.test_os_updates import FEATURES, report, update
from tests.test_tenancy import acme_device, tenants  # noqa: F401  (fixture)
from tests.test_vuln_matching import new_device, run
from tests.vuln_fakes import MSRC_DOCS, FakeFeeds

OLD_WIN = {"os_name": "Microsoft Windows 11 Pro 23H2", "os_version": "10.0.22631", "os_build": "22631.3447"}
OLD_CHROME = [{"name": "Google Chrome", "version": "127.0.6533.120", "publisher": "Google LLC"}]


@pytest.fixture()
def fake():
    f = FakeFeeds()
    feeds.set_transport(f.transport(), f.sleep)
    yield f
    feeds.set_transport(None)


@pytest.fixture()
def admin(empty_client):
    return empty_client


def fixes(c, device_id):
    r = c.get(f"/api/devices/{device_id}/vulnerability-fixes")
    assert r.status_code == 200, r.text
    return r.json()


def refresh_msrc(**kw):
    with db.get_session(unscoped=True) as s:
        out = msrc.refresh(s, **kw)
        s.commit()
    return out


# --------------------------------------------------------------------------- MSRC parsing / feed
def test_parse_document_keeps_windows_fixes_only():
    out = msrc.parse_document(MSRC_DOCS["2024-May"])
    assert set(out) == {"CVE-2024-30040"}  # the Edge-only CVE is not a Windows operating system fix
    r = out["CVE-2024-30040"]
    assert r["t"] == "Windows MSHTML Platform Security Feature Bypass Vulnerability"
    assert r["rel"] == "2024-05-14" and "Exploited:Yes" in r["expl"]
    assert {(f["p"], f["kb"], f["b"]) for f in r["fix"]} == {
        ("Windows 11 Version 23H2 for x64-based Systems", "5037771", "10.0.22631.3593"),
        ("Windows 11 Version 23H2 for ARM64-based Systems", "5037771", "10.0.22631.3593"),
        ("Windows 10 Version 22H2 for x64-based Systems", "5037768", "10.0.19045.4412")}
    assert all(f["rs"] is True for f in r["fix"][:2])
    # "Microsoft has not identified any mitigating factors / workarounds" is not guidance
    assert "mit" not in r and "wk" not in r
    june = msrc.parse_document(MSRC_DOCS["2024-Jun"])["CVE-2024-30080"]
    assert "Message Queuing" in june["mit"][0]


def test_clean_text_and_builds():
    assert msrc.clean_text("Disable the <b>service</b>.<br/>Then &amp; restart.") == "Disable the service.\nThen & restart."
    assert msrc.parse_build("10.0.22631.3593") == (22631, 3593)
    assert msrc.parse_build("22631.3593") == (22631, 3593)
    assert msrc.parse_build("Windows") is None


def test_refresh_caches_months_and_is_incremental(admin, fake):
    ok, err = refresh_msrc()
    assert ok and err is None
    with db.get_session("default") as s:
        st = s.get(VulnFeedStatus, "msrc")
        assert st.last_success_at is not None and st.last_error is None and st.items == 3
        assert set(msrc.load(s)) == {"CVE-2024-30040", "CVE-2024-30080", "CVE-2024-43547"}
        assert msrc.lookup(s, "CVE-2024-30040")["fix"][0]["kb"] == "5037771"
    assert fake.count("msrc.invalid") == 4  # index + three monthly documents
    fake.requests.clear()
    assert refresh_msrc()[0]
    assert fake.count("msrc.invalid") == 1  # only the index: nothing changed
    # Microsoft revises May: only that document is downloaded again
    fake.msrc_updates["value"][2]["CurrentReleaseDate"] = "2024-05-20T07:00:00Z"
    fake.requests.clear()
    assert refresh_msrc()[0]
    assert [r.url.path.rsplit("/", 1)[-1] for r in fake.requests] == ["updates", "2024-May"]


def test_refresh_offline_keeps_last_good_copy(admin, fake):
    assert refresh_msrc()[0]
    fake.offline = True
    fake.msrc_updates["value"][0]["CurrentReleaseDate"] = "2024-12-01T00:00:00Z"
    ok, err = refresh_msrc()
    assert not ok and "cannot reach msrc.invalid" in err
    with db.get_session("default") as s:
        st = s.get(VulnFeedStatus, "msrc")
        assert st.last_error and st.last_success_at is not None
        assert msrc.lookup(s, "CVE-2024-30080") is not None  # last good copy still serves
    # never fetched and unreachable: recorded, nothing raised
    with db.get_session("default") as s:
        s.delete(s.get(VulnFeedCache, "msrc"))
        s.commit()
    assert refresh_msrc()[0] is False
    with db.get_session("default") as s:
        assert msrc.lookup(s, "CVE-2024-30080") is None


def test_month_failure_keeps_other_months(admin, fake):
    del fake.msrc_docs["2024-Jun"]  # 404 for one document
    ok, err = refresh_msrc()
    assert not ok and "2024-Jun" in err
    with db.get_session("default") as s:
        assert set(msrc.load(s)) == {"CVE-2024-30040", "CVE-2024-43547"}


def test_worker_refreshes_msrc_only_with_windows_devices(admin, fake):
    run()
    assert fake.count("msrc.invalid") == 0  # no Windows device yet
    new_device(admin, software=OLD_CHROME, **OLD_WIN)
    run()
    assert fake.count("msrc.invalid") == 4
    status = admin.get("/api/vulnerabilities/status").json()
    msrc_feed = next(f for f in status["feeds"] if f["feed"] == "msrc")
    assert msrc_feed["host"] == "api.msrc.microsoft.com" and msrc_feed["items"] == 3
    assert msrc_feed["last_success_at"] and not msrc_feed["last_error"]


# --------------------------------------------------------------------------- device fixes
def test_device_groups_os_cves_into_one_cumulative_update(admin, fake):
    _, dev = new_device(admin, software=OLD_CHROME, **OLD_WIN)
    run()
    d = fixes(admin, dev)
    # CVE-2024-30040 + 30080 + 43547 on Windows (one update), Chrome 127: two CVEs (one update)
    assert d["summary"]["fixes"] == 2 and d["summary"]["open"] == 5 and d["summary"]["kev"] == 2
    win, chrome = d["fixes"]  # KEV first, then severity, then CVE count
    assert win["kind"] == "windows_update" and win["title"] == "Install the latest Windows cumulative update"
    assert [c["cve_id"] for c in win["cves"]][0] == "CVE-2024-30040"  # KEV first
    assert {c["cve_id"] for c in win["cves"]} == {"CVE-2024-30040", "CVE-2024-30080", "CVE-2024-43547"}
    # the one update that closes all three is the October one: highest fixed build among the CVEs
    assert win["target"] == {"kb": "5044285", "build": "22631.4317", "os": "Windows 11 23H2", "source": "msrc"}
    assert win["restart_required"] is True and win["kev_count"] == 1 and win["max_severity"] == "critical"
    assert win["msrc_covered"] and win["unmapped_cves"] == 0
    assert {m["id"] for m in win["methods"]} == {"windows_update", "intune", "wsus"}
    wsus = next(m for m in win["methods"] if m["id"] == "wsus")
    assert any(c["code"] == "Get-HotFix -Id KB5044285" for c in wsus["commands"])
    assert win["os_updates_tab"] == f"/devices/{dev}?tab=OS%20updates"
    assert chrome["kind"] == "app_update"
    assert chrome["title"] == "Update Google Chrome 127.0.6533.120 → 130.0.6723.91 or later"
    assert chrome["cve_count"] == 2 and chrome["kev_count"] == 1
    cmds = {c["code"] for m in chrome["methods"] for c in m["commands"]}
    assert "winget upgrade --id Google.Chrome -e" in cmds
    assert {m["id"] for m in chrome["methods"]} == {"winget", "vendor"}


def test_cve_2024_30040_on_windows_11_23h2_needs_kb5037771(admin, fake):
    _, dev = new_device(admin, software=[], **OLD_WIN)
    run()
    r = admin.get("/api/vulnerabilities/CVE-2024-30040")
    assert r.status_code == 200, r.text
    c = r.json()
    row, = c["guidance"]["windows"]["table"]
    assert row["os"] == "Windows 11 23H2" and row["kb"] == "5037771" and row["fixed_build"] == "22631.3593"
    assert row["devices"] == 1 and row["restart"] is True and row["source"] == "msrc"
    assert c["fixed_in"] == "KB5037771" and c["fix_type"] == "windows_update" and c["patch_available"]
    assert c["devices"][0]["needs"] == "Latest cumulative update (KB5037771, build 22631.3593)"
    assert {"label": "KB5037771 article", "url": "https://support.microsoft.com/help/5037771"} in c["references"]
    assert any(r["label"].startswith("Microsoft Security Update Guide") for r in c["references"])
    assert c["guidance"]["mitigations"] == [] and c["guidance"]["workarounds"] == []
    assert c["exploit"]["msrc"].startswith("Publicly Disclosed:No;Exploited:Yes")
    # a CVE with a real mitigation shows its text
    m = admin.get("/api/vulnerabilities/CVE-2024-30080").json()
    assert "Message Queuing" in m["guidance"]["mitigations"][0]


def test_fix_degrades_without_msrc_data(admin, fake):
    fake.fail_hosts.add("msrc.invalid")
    _, dev = new_device(admin, software=[], **OLD_WIN)
    run()  # MSRC unreachable: recorded, matching still works
    with db.get_session("default") as s:
        assert s.get(VulnFeedStatus, "msrc").last_error
    d = fixes(admin, dev)
    win, = d["fixes"]
    assert win["title"] == "Install the latest Windows cumulative update"
    assert win["target"]["kb"] is None and win["target"]["source"] == "nvd"
    assert win["target"]["build"] == "22631.4317"  # NVD still names the build
    assert not win["msrc_covered"] and win["links"] == []
    assert any("latest cumulative update" in s for s in win["steps"])
    assert d["msrc"]["has_data"] is False and d["msrc"]["error"]
    c = admin.get("/api/vulnerabilities/CVE-2024-30040").json()
    assert c["guidance"]["windows"]["degraded"] is True
    assert c["guidance"]["windows"]["table"][0]["kb"] is None
    assert c["fixed_in"] == "Latest cumulative update"
    assert c["devices"][0]["needs"].startswith("Latest cumulative update (build 22631.3593")


def test_state_from_os_updates_report(admin, fake):
    agent, dev = new_device(admin, software=[], **OLD_WIN)
    agent.headers["X-CNAPP-Agent-Features"] = FEATURES
    from tests.test_vuln_matching import checkin_body
    assert agent.post("/api/agent/checkin", json=checkin_body([], **OLD_WIN)).status_code == 200  # advertises the feature
    run()
    # nothing reported yet
    assert fixes(admin, dev)["fixes"][0]["state"]["code"] == "unknown"
    # Windows Update offers the October cumulative update
    up = update("2024-10 Cumulative Update for Windows 11 Version 23H2 (KB5044285)", kb="KB5044285",
                sev="Critical", age=20, cves=["CVE-2024-43547"])
    assert agent.post("/api/agent/os-updates", json=report(updates=[up])).status_code == 204
    s = fixes(admin, dev)["fixes"][0]["state"]
    assert s["code"] == "offered" and s["label"] == "Update offered, not installed" and "KB5044285" in s["detail"]
    # nothing offered, restart pending
    assert agent.post("/api/agent/os-updates", json=report(updates=[], reboot_pending=True)).status_code == 204
    assert fixes(admin, dev)["fixes"][0]["state"]["code"] == "restart_pending"
    # nothing offered from WSUS and no restart: say why
    assert agent.post("/api/agent/os-updates", json=report(updates=[])).status_code == 204
    s = fixes(admin, dev)["fixes"][0]["state"]
    assert s["code"] == "not_offered" and "WSUS" in s["detail"]
    # Windows Update service disabled / search failing
    assert agent.post("/api/agent/os-updates", json=report(updates=[], service_start_type="disabled")).status_code == 204
    assert fixes(admin, dev)["fixes"][0]["state"]["label"] == "Updates paused/failing"
    assert agent.post("/api/agent/os-updates", json=report(status="failed", error="0x80244022")).status_code == 204
    s = fixes(admin, dev)["fixes"][0]["state"]
    assert s["code"] == "failing" and "0x80244022" in s["detail"]
    # the CVE page counts devices per state
    assert admin.get("/api/vulnerabilities/CVE-2024-30040").json()["progress"]["failing"] == 1


def test_app_upgrade_grouping_and_sort(admin, fake):
    soft = [{"name": "Google Chrome", "version": "127.0.6533.120", "publisher": "Google LLC"},
            {"name": "7-Zip 24.08 (x64 edition)", "version": "24.00", "publisher": "Igor Pavlov"}]
    _, dev = new_device(admin, software=soft, os_name="Microsoft Windows 11 Pro 23H2", os_build="22631.4400",
                        os_version="10.0.22631")
    run()
    d = fixes(admin, dev)
    assert [f["package"] for f in d["fixes"]] == ["Google Chrome", "7-Zip"]  # KEV first
    z = d["fixes"][1]
    assert z["title"] == "Update 7-Zip 24.00 → 24.07 or later" and z["cve_count"] == 1
    assert {m["id"] for m in z["methods"]} == {"winget", "vendor"}
    assert svc.fix_sort_key({"kev_count": 0, "max_severity": "critical", "cve_count": 9, "title": "a"}) > \
        svc.fix_sort_key({"kev_count": 1, "max_severity": "low", "cve_count": 1, "title": "b"})
    assert svc.fix_sort_key({"kev_count": 0, "max_severity": "high", "cve_count": 1, "title": "a"}) > \
        svc.fix_sort_key({"kev_count": 0, "max_severity": "critical", "cve_count": 1, "title": "a"})
    assert svc.fix_sort_key({"kev_count": 0, "max_severity": "high", "cve_count": 1, "title": "a"}) > \
        svc.fix_sort_key({"kev_count": 0, "max_severity": "high", "cve_count": 4, "title": "a"})


def test_fixed_devices_count_as_patched(admin, fake):
    agent, dev = new_device(admin, software=OLD_CHROME, **OLD_WIN)
    run()
    c = admin.get("/api/vulnerabilities/CVE-2024-7971").json()
    assert c["progress"] == {"total": 1, "patched": 0, "open": 1, "restart_pending": 0, "offered": 0,
                             "failing": 0, "not_offered": 0}
    assert c["fix_type"] == "package_upgrade" and c["fixed_in"] == "128.0.6613.84"
    app, = c["guidance"]["apps"]
    assert app["title"] == "Update Google Chrome 127.0.6533.120 → 128.0.6613.84 or later"
    assert app["advisory"].endswith("CVE-2024-7971")
    # Chrome is updated
    from tests.test_vuln_matching import checkin_body
    body = checkin_body([{"name": "Google Chrome", "version": "131.0.6778.1", "publisher": "Google LLC"}], **OLD_WIN)
    assert agent.post("/api/agent/checkin", json=body).status_code == 200
    run()
    c = admin.get("/api/vulnerabilities/CVE-2024-7971").json()
    assert c["progress"]["patched"] == 1 and c["progress"]["open"] == 0 and c["devices"] == []
    assert c["fix_due"] is None and c["affected"]["open_devices"] == 0
    assert any("Most recent fix confirmed" in t["label"] for t in c["timeline"])


# --------------------------------------------------------------------------- CVE page facts
def test_cve_page_facts(admin, fake):
    _, dev = new_device(admin, software=[], **OLD_WIN)
    run()
    c = admin.get("/api/vulnerabilities/CVE-2024-30040").json()
    assert c["cve_id"] == "CVE-2024-30040" and c["title"].startswith("Windows MSHTML Platform")
    assert c["severity"] == "high" and c["cvss"] == 8.8 and c["cvss_label"] == "CVSS v3.1"
    assert c["kev"] and c["kev_info"]["due"] == "2024-06-04" and c["epss"] == 0.42
    assert c["affected"]["open_devices"] == 1 and c["affected"]["fleet_devices"] == 1
    assert c["affected"]["fleet_label"] == "Windows"
    # KEV with a known due date: that date; long overdue
    assert c["fix_due"]["basis"] == "CISA KEV due date" and c["fix_due"]["overdue_days"] > 100
    assert c["fix_due"]["due_at"].startswith("2024-06-04")
    assert c["days_open"] == 0 and c["first_seen"]
    text = " ".join(c["business_impact"])
    assert "exploited in real attacks" in text and "42.0% chance" in text and "1 device" in text
    assert "network" in text and "overdue" in text
    assert [r["label"] for r in c["references"]][:2] == ["Microsoft Security Update Guide (MSRC)", "NVD"]
    assert any(r["label"] == "CISA KEV entry" for r in c["references"])
    labels = [t["label"] for t in c["timeline"]]
    assert any("Added to CISA KEV" in x for x in labels) and any("First seen" in x for x in labels)
    # compliance chips come from the framework mapping files, not invented
    assert c["compliance"] and all({"framework", "control", "title"} <= set(x) for x in c["compliance"])
    assert any(x["control"] == "CIS v8 7.7" for x in c["compliance"])
    assert c["devices"][0]["hostname"] == "LAPTOP-001" and c["devices"][0]["current"] == "22631.3447"
    assert admin.get("/api/vulnerabilities/CVE-1999-0001").status_code == 404
    assert admin.get("/api/vulnerabilities/stats").status_code == 200  # fixed paths still win


def test_fix_due_sla():
    t0 = datetime(2026, 1, 1)
    now = t0 + timedelta(days=10)
    assert fix_due(t0, "critical", now=now)["overdue_days"] == 3
    assert fix_due(t0, "high", now=now)["days_left"] == 4
    assert fix_due(t0, "medium", now=now)["days_left"] == 20
    assert fix_due(t0, "low", now=now)["days_left"] == 80
    k = fix_due(t0, "low", kev=True, now=now)  # KEV without a date: 14 days
    assert k["days_left"] == 4 and "14 days" in k["basis"]
    k = fix_due(t0, "low", kev=True, kev_due="2025-12-01", now=now)
    assert k["basis"] == "CISA KEV due date" and k["overdue_days"] > 30


# --------------------------------------------------------------------------- PDF, RBAC, audit
def test_pdf_reports_are_analyst_only_and_audited(admin, fake):
    _, dev = new_device(admin, software=OLD_CHROME, **OLD_WIN)
    run()
    r = admin.get("/api/vulnerabilities/CVE-2024-30040/report.pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF") and r.headers["content-type"] == "application/pdf"
    assert "CVE-2024-30040" in r.headers["content-disposition"] and r.headers["cache-control"] == "no-store"
    r = admin.get(f"/api/devices/{dev}/vulnerability-fixes/report.pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    with db.get_session("default") as s:
        acts = [(a.action, a.target) for a in s.scalars(select(AuditLog).where(AuditLog.action.like("%vulnerability_report%")))]
    assert ("vulnerability_report_exported", "CVE-2024-30040") in acts
    assert ("device_vulnerability_report_exported", dev) in acts
    make_user(admin, "viewer")
    v = type(admin)(admin.app, base_url=BASE_URL)
    login(v, "viewer@example.com", "a-long-test-password")
    assert v.get("/api/vulnerabilities/CVE-2024-30040").status_code == 200  # reading is for viewers
    assert v.get(f"/api/devices/{dev}/vulnerability-fixes").status_code == 200
    assert v.get("/api/vulnerabilities/CVE-2024-30040/report.pdf").status_code == 403
    assert v.get(f"/api/devices/{dev}/vulnerability-fixes/report.pdf").status_code == 403
    anon = type(admin)(admin.app, base_url=BASE_URL)
    assert anon.get("/api/vulnerabilities/CVE-2024-30040").status_code == 401
    assert anon.get(f"/api/devices/{dev}/vulnerability-fixes").status_code == 401


def test_pdf_rate_limit(admin, fake):
    from app.api import vuln_fixes as api
    new_device(admin, software=[], **OLD_WIN)
    run()
    api.pdf_limiter = type(api.pdf_limiter)()
    old = api.PDF_LIMIT
    api.PDF_LIMIT = 2
    try:
        codes = [admin.get("/api/vulnerabilities/CVE-2024-30040/report.pdf").status_code for _ in range(3)]
    finally:
        api.PDF_LIMIT = old
    assert codes == [200, 200, 429]


# --------------------------------------------------------------------------- tenancy
def test_other_organisations_cannot_see_fixes(tenants, fake):  # noqa: F811
    _, acme_id = acme_device(tenants)
    with db.get_session(tenants.acme_id) as s:
        d = s.get(Device, acme_id)
        d.os_name, d.os_build, d.os_version = "Microsoft Windows 11 Pro 23H2", "22631.3447", "10.0.22631"
        s.add(Vulnerability(device_id=acme_id, cve_id="CVE-2024-30040", package="Windows 11 23H2", version="22631.3447",
                            fixed_version="10.0.22631.3593", title="MSHTML", cvss=8.8, severity="high", kev=True,
                            match_key="os", source="nvd", status="open", priority="high", risk_score=50.0,
                            evidence={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}))
        s.commit()
    refresh_msrc()
    mine = tenants.acme.get("/api/vulnerabilities/CVE-2024-30040")
    assert mine.status_code == 200 and mine.json()["devices"][0]["hostname"] == "ACME-LAPTOP"
    assert mine.json()["guidance"]["windows"]["table"][0]["kb"] == "5037771"  # global MSRC data, tenant rows
    assert tenants.acme.get(f"/api/devices/{acme_id}/vulnerability-fixes").json()["summary"]["open"] == 1
    # the default organisation has no record of it and cannot reach the device
    assert tenants.default.get("/api/vulnerabilities/CVE-2024-30040").status_code == 404
    assert tenants.default.get("/api/vulnerabilities/CVE-2024-30040/report.pdf").status_code == 404
    assert tenants.default.get(f"/api/devices/{acme_id}/vulnerability-fixes").status_code == 404
    assert tenants.default.get(f"/api/devices/{acme_id}/vulnerability-fixes/report.pdf").status_code == 404
