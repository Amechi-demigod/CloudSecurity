"""Compliance reports (docs/COMPLIANCE.md): mapping integrity, scoring, check
evaluation, API / RBAC / tenancy, snapshots, scheduled emailed reports and the
PDF writer. Runs on SQLite and PostgreSQL."""
from __future__ import annotations

import base64
import json
import re
import socket
import zlib
from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, select

from app import config, db, mailer
from app.compliance import catalog, checks, pdf, reports, scoring, service
from app.compliance.models import ComplianceReportSchedule, ComplianceSnapshot
from app.directory.models import FINDING_TYPES
from app.engine import posture
from app.models import Asset, AuditLog, Finding, Vulnerability, utcnow
from app.services import devices as device_svc
from app.tenancy import DEFAULT_ORG_ID
from tests.conftest import login, make_user
from tests.test_devices import agent_client, enroll, new_token, windows_checkin
from tests.test_tenancy import ACME_ADMIN, ACME_PASSWORD, create_org, org_client

EXPECTED_CONTROLS = {"iso27001-2022": 93, "soc2-2017": 33, "nist-csf-2.0": 106, "pci-dss-4.0": 63}


# ----------------------------------------------------------------------------- mapping integrity
def test_all_v1_frameworks_load_with_expected_control_counts():
    fws = catalog.frameworks()
    assert list(fws) == list(catalog.ORDER)
    for fid, n in EXPECTED_CONTROLS.items():
        assert len(fws[fid].controls) == n, fid
    for fw in fws.values():
        assert fw.notice and fw.publisher and fw.mapping_version >= 1
        assert any(c.checks for c in fw.controls), f"{fw.id} has no automated evidence at all"


def test_every_referenced_check_exists():
    """Every check a framework (or check set) names is a real check of the platform."""
    known = checks.registry()
    rules = {r.id for r in posture.RULES}
    for name, s in catalog.check_sets().items():
        for cid in s["checks"]:
            assert cid in known, f"check set {name}: unknown check {cid}"
    for fw in catalog.frameworks().values():
        for c in fw.controls:
            for ref in c.refs:
                if ref.startswith("@"):
                    assert ref[1:] in catalog.check_sets(), f"{fw.id} {c.id}: unknown set {ref}"
            for cid in c.checks:
                assert cid in known, f"{fw.id} {c.id}: unknown check {cid}"
                kind, _, rest = cid.partition(":")
                if kind == "cloud":
                    assert rest in rules
                elif kind == "endpoint":
                    assert device_svc.ISSUE_DEFS.get(checks.ENDPOINT[rest][1])
                elif kind == "directory":
                    assert rest in FINDING_TYPES


def test_unknown_check_set_is_rejected():
    with pytest.raises(catalog.MappingError):
        catalog.expand(["@no-such-set"], "test")


def test_every_cloud_rule_is_in_a_check_set():
    """A new posture rule must be mapped somewhere (add it to checksets.json)."""
    in_sets = {c for s in catalog.check_sets().values() for c in s["checks"]}
    missing = [r.id for r in posture.RULES if f"cloud:{r.id}" not in in_sets]
    assert missing == []


def test_cis_file_matches_the_rule_tags():
    """Every CIS benchmark tag the rules carry is a control of cis.json with the same rules."""
    cis = {c.id: set(c.checks) for c in catalog.frameworks()["cis"].controls}
    for tag, rule_ids in posture.compliance_controls().items():
        if tag.startswith("CIS "):
            assert cis.get(tag) == {f"cloud:{r}" for r in rule_ids}, tag


def test_titles_are_short_paraphrases_and_coverage_is_honest():
    for fw in catalog.frameworks().values():
        for c in fw.controls:
            assert 0 < len(c.title) <= 90, (fw.id, c.id)
            if c.checks:
                assert c.coverage in ("full", "partial")
            else:
                assert c.coverage is None
            if fw.id != "cis":
                # only CIS benchmark recommendations that one rule checks exactly are "full"
                assert c.coverage != "full", (fw.id, c.id)


# ----------------------------------------------------------------------------- scoring
@pytest.mark.parametrize("coverage,statuses,expected", [
    (None, [], "manual"),
    ("partial", ["pass", "fail"], "fail"),
    ("full", ["pass", "fail", "no_data"], "fail"),
    ("full", ["pass", "pass"], "pass"),
    ("full", ["pass", "no_data"], "partial"),
    ("partial", ["pass"], "partial"),
    ("partial", ["no_data", "out_of_scope"], "no_data"),
    ("full", ["out_of_scope"], "no_data"),
])
def test_control_status(coverage, statuses, expected):
    assert scoring.control_status(coverage, statuses) == expected


def test_summary_score_and_coverage():
    s = scoring.summarize(["pass", "partial", "fail", "fail", "manual", "no_data", "manual", "pass"])
    assert (s["pass"], s["partial"], s["fail"], s["manual"], s["no_data"]) == (2, 1, 2, 2, 1)
    assert s["assessed"] == 5 and s["total"] == 8 and s["mapped"] == 6
    assert s["score"] == 60.0 and s["coverage"] == 62.5
    assert scoring.summarize(["manual"])["score"] is None


# ----------------------------------------------------------------------------- check evaluation
def _asset(s, aid: str, type_: str, account: str = "sub-1", provider: str = "aws") -> Asset:
    a = Asset(id=aid, name=aid.rsplit("/", 1)[-1], type=type_, provider=provider, subscription_id=account,
              source="test")
    s.add(a)
    return a


def test_cloud_checks_pass_fail_no_data_and_account_scope(empty_client):
    with db.get_session(DEFAULT_ORG_ID) as s:
        _asset(s, "arn:aws:iam::1:root", "aws_account", "111")
        _asset(s, "arn:aws:iam::2:root", "aws_account", "222")
        s.flush()
        s.add(Finding(rule_id="AWS-IAM-001", asset_id="arn:aws:iam::1:root", title="Root user has no MFA",
                      severity="critical", status="open", source="test"))
        s.commit()
        ids = ["cloud:AWS-IAM-001", "cloud:AWS-IAM-002", "cloud:AZ-STG-001"]
        r = checks.evaluate(s, ids)
        assert r["cloud:AWS-IAM-001"].status == "fail" and r["cloud:AWS-IAM-001"].failing == 1
        assert r["cloud:AWS-IAM-001"].items[0]["link"].startswith("/findings?finding=")
        assert r["cloud:AWS-IAM-002"].status == "pass" and r["cloud:AWS-IAM-002"].total == 2
        assert r["cloud:AZ-STG-001"].status == "no_data"
        only_222 = checks.evaluate(s, ids, checks.Scope(account="222"))
        assert only_222["cloud:AWS-IAM-001"].status == "pass"
        # a cloud-account report leaves endpoint and directory checks out
        out = checks.evaluate(s, ["endpoint:firewall", "directory:not_managed", "inventory:directory_sync"],
                              checks.Scope(account="222"))
        assert {x.status for x in out.values()} == {"out_of_scope"}
        # CIS AWS 1.5 is fully covered: fail; once resolved, pass
        cis = catalog.get("cis")
        p = service.posture(s, cis)
        ctl = {c["id"]: c for g in p["groups"] for c in g["controls"]}
        assert ctl["CIS AWS 1.5"]["status"] == "fail" and ctl["CIS AWS 1.4"]["status"] == "pass"
        assert ctl["CIS Azure 3.7"]["status"] == "no_data"
        f = s.scalar(select(Finding))
        f.status = "resolved"
        s.commit()
        p = service.posture(s, cis)
        ctl = {c["id"]: c for g in p["groups"] for c in g["controls"]}
        assert ctl["CIS AWS 1.5"]["status"] == "pass"


def _device(c, hostname: str, machine: str, group: str | None = None, **posture_over):
    token = new_token(c)
    agent = agent_client(c.app)
    r = enroll(agent, token, machine_id=machine, hostname=hostname)
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    body = windows_checkin()
    body["device"]["hostname"] = hostname
    body["collected_at"] = utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    body["posture"].update(posture_over)
    assert agent.post("/api/agent/checkin", json=body).status_code == 200
    did = r.json()["device_id"]
    if group:
        from app.models import Device
        with db.get_session(DEFAULT_ORG_ID) as s:
            s.get(Device, did).device_group = group
            s.commit()
    return did


def test_endpoint_checks_and_device_group_scope(empty_client):
    c = empty_client
    _device(c, "LAPTOP-OK", "a" * 64, "finance")
    bad = _device(c, "LAPTOP-BAD", "b" * 64, "sales", firewall={"status": "fail", "detail": "public profile off"})
    with db.get_session(DEFAULT_ORG_ID) as s:
        ids = ["endpoint:firewall", "endpoint:disk_encryption", "endpoint:sip", "endpoint:checkin"]
        r = checks.evaluate(s, ids)
        assert r["endpoint:firewall"].status == "fail" and r["endpoint:firewall"].failing == 1
        assert r["endpoint:firewall"].total == 2
        assert r["endpoint:firewall"].items[0]["link"] == f"/devices/{bad}"
        assert r["endpoint:disk_encryption"].status == "pass"
        assert r["endpoint:sip"].status == "no_data"  # no macOS device reports SIP
        assert r["endpoint:checkin"].status == "pass"
        fin = checks.evaluate(s, ids, checks.Scope(device_group="finance"))
        assert fin["endpoint:firewall"].status == "pass" and fin["endpoint:firewall"].total == 1
        cloud = checks.evaluate(s, ["cloud:AWS-IAM-001"], checks.Scope(device_group="finance"))
        assert cloud["cloud:AWS-IAM-001"].status == "out_of_scope"


def test_vulnerability_checks(empty_client):
    did = _device(empty_client, "LAPTOP-V", "d" * 64)
    with db.get_session(DEFAULT_ORG_ID) as s:
        r = checks.evaluate(s, ["vuln:kev", "vuln:critical_sla"])
        assert r["vuln:kev"].status == "pass"  # a managed device, nothing open
        s.add(Vulnerability(device_id=did, cve_id="CVE-2024-0001", package="7-Zip", version="24.08", cvss=9.8,
                            severity="critical", status="open", kev=True, source="nvd",
                            first_seen=utcnow() - timedelta(days=40)))
        s.commit()
        r = checks.evaluate(s, ["vuln:kev", "vuln:critical_sla", "vuln:high_sla"])
        assert r["vuln:kev"].status == "fail" and r["vuln:critical_sla"].status == "fail"
        assert r["vuln:kev"].items[0]["detail"] == "LAPTOP-V"
        assert r["vuln:high_sla"].status == "pass"


def test_directory_and_inventory_checks_without_sources(empty_client):
    with db.get_session(DEFAULT_ORG_ID) as s:
        r = checks.evaluate(s, ["directory:not_managed", "inventory:directory_sync", "inventory:cloud_scan"])
        assert {x.status for x in r.values()} == {"no_data"}


# ----------------------------------------------------------------------------- API, RBAC, tenancy
def test_api_overview_posture_csv_and_scopes(client):
    r = client.get("/api/compliance/frameworks")
    assert r.status_code == 200, r.text
    body = r.json()
    assert [f["id"] for f in body["frameworks"]] == list(catalog.ORDER)
    assert "not an audit opinion" in body["disclaimer"]
    for f in body["frameworks"]:
        assert f["summary"]["total"] == f["controls"]
    r = client.get("/api/compliance/frameworks/iso27001-2022")
    assert r.status_code == 200
    p = r.json()
    assert p["summary"]["manual"] > 0 and p["groups"][0]["id"] == "A.5"
    a815 = next(c for g in p["groups"] for c in g["controls"] if c["id"] == "A.8.15")
    assert a815["checks"] and a815["coverage"] == "partial"
    assert client.get("/api/compliance/frameworks/nope").status_code == 404
    assert client.get("/api/compliance/frameworks/cis?account=a&device_group=b").status_code == 422
    r = client.get("/api/compliance/frameworks/cis/export.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "not an audit opinion" in r.text.splitlines()[0]
    assert "CIS Azure 3.7" in r.text
    # the posture read wrote today's snapshot; the trend returns it
    t = client.get("/api/compliance/frameworks/cis/trend").json()
    assert len(t["points"]) == 1 and t["points"][0]["total"] == len(catalog.get("cis").controls)


def test_pdf_export_and_rate_limit(client, monkeypatch):
    r = client.get("/api/compliance/report.pdf?frameworks=cis,soc2-2017")
    assert r.status_code == 200, r.text
    assert r.content.startswith(b"%PDF-1.4") and r.headers["content-type"] == "application/pdf"
    assert client.get("/api/compliance/report.pdf?frameworks=bogus").status_code == 404
    with db.get_session(DEFAULT_ORG_ID) as s:
        assert s.scalar(select(func.count()).select_from(AuditLog).where(
            AuditLog.action == "compliance_report_exported")) == 1
    from app.compliance import api as capi
    monkeypatch.setattr(capi, "PDF_LIMIT", 1)
    capi.pdf_limiter._hits.clear()
    assert client.get("/api/compliance/report.pdf?frameworks=cis").status_code == 200
    assert client.get("/api/compliance/report.pdf?frameworks=cis").status_code == 429


def _schedule(c, **over):
    body = {"name": "Monthly board pack", "frameworks": ["iso27001-2022", "cis"], "frequency": "monthly",
            "day": 1, "hour": 6, "recipients": ["admin@example.com"], **over}
    return c.post("/api/compliance/schedules", json=body)


def test_viewer_reads_and_exports_but_cannot_schedule(client):
    make_user(client, "viewer")
    from fastapi.testclient import TestClient
    v = TestClient(client.app, base_url="https://testserver")
    login(v, "viewer@example.com", "a-long-test-password")
    assert v.get("/api/compliance/frameworks").status_code == 200
    assert v.get("/api/compliance/frameworks/pci-dss-4.0/export.csv").status_code == 200
    assert v.get("/api/compliance/schedules").status_code == 200
    assert _schedule(v).status_code == 403
    assert v.get("/api/compliance/recipients").status_code == 403
    r = _schedule(client)
    assert r.status_code == 201, r.text
    assert v.post(f"/api/compliance/schedules/{r.json()['id']}/send").status_code == 403
    assert v.delete(f"/api/compliance/schedules/{r.json()['id']}").status_code == 403


def test_schedule_validation(client):
    r = _schedule(client, recipients=["outsider@elsewhere.test"])
    assert r.status_code == 422 and "not an active member" in r.text
    assert _schedule(client, frameworks=["gdpr"]).status_code == 422
    assert _schedule(client, frequency="weekly", day=7).status_code == 422
    assert _schedule(client, frequency="monthly", day=0).status_code == 422
    assert _schedule(client, account="111", device_group="x").status_code == 422
    r = _schedule(client, frequency="weekly", day=0, hour=7)
    assert r.status_code == 201
    nxt = datetime.fromisoformat(r.json()["next_run_at"].rstrip("Z"))
    assert nxt.weekday() == 0 and nxt.hour == 7 and nxt > utcnow()
    sid = r.json()["id"]
    r = client.patch(f"/api/compliance/schedules/{sid}", json={"frequency": "monthly", "day": 15})
    assert r.status_code == 200 and r.json()["day"] == 15
    assert client.delete(f"/api/compliance/schedules/{sid}").status_code == 204
    with db.get_session(DEFAULT_ORG_ID) as s:
        actions = set(s.scalars(select(AuditLog.action).where(AuditLog.action.like("compliance_schedule_%"))))
    assert actions == {"compliance_schedule_created", "compliance_schedule_updated", "compliance_schedule_deleted"}


def test_schedules_and_scores_are_per_organisation(client):
    create_org("acme", ACME_ADMIN, ACME_PASSWORD, name="Acme Ltd")
    acme = org_client(client.app, ACME_ADMIN, ACME_PASSWORD)
    sid = _schedule(client).json()["id"]
    assert acme.get("/api/compliance/schedules").json()["items"] == []
    assert acme.patch(f"/api/compliance/schedules/{sid}", json={"name": "x"}).status_code == 404
    assert acme.post(f"/api/compliance/schedules/{sid}/send").status_code == 404
    # acme's recipients are acme's members only
    assert _schedule(acme, recipients=["admin@example.com"]).status_code == 422
    assert _schedule(acme, recipients=[ACME_ADMIN]).status_code == 201
    # the default org has the simulated environment; acme has nothing to evaluate
    acme_cis = acme.get("/api/compliance/frameworks/cis").json()["summary"]
    assert acme_cis["fail"] == 0 and acme_cis["pass"] == 0 and acme_cis["score"] is None
    default_cis = client.get("/api/compliance/frameworks/cis").json()["summary"]
    assert default_cis["fail"] > 0


# ----------------------------------------------------------------------------- scheduled reports
def test_next_run_slots():
    mon = datetime(2026, 11, 2, 6)  # a Monday
    assert reports.next_run("weekly", 0, 6, mon) == datetime(2026, 11, 9, 6)
    assert reports.next_run("weekly", 0, 6, mon - timedelta(minutes=1)) == mon
    assert reports.next_run("weekly", 4, 9, mon) == datetime(2026, 11, 6, 9)
    assert reports.next_run("monthly", 1, 6, datetime(2026, 11, 1, 6)) == datetime(2026, 12, 1, 6)
    assert reports.next_run("monthly", 28, 0, datetime(2026, 12, 30)) == datetime(2027, 1, 28)


def test_runner_emails_pdf_to_members_and_reschedules(client, monkeypatch):
    sent = []
    monkeypatch.setattr(mailer, "configured", lambda: True)

    def fake_send(to, subject, text, html, *, reply_to=None, attachments=None):
        sent.append((to, subject, attachments))
        return mailer.MailResult(True)

    monkeypatch.setattr(mailer, "send", fake_send)
    sid = _schedule(client, frequency="weekly", day=0, hour=6).json()["id"]
    worker = reports.ComplianceReportWorker()
    try:
        first = worker.tick(utcnow())
        assert first.leader and first.sent == {}  # not due yet
        with db.get_session(DEFAULT_ORG_ID) as s:
            due = s.get(ComplianceReportSchedule, sid).next_run_at
        tick = worker.tick(due + timedelta(minutes=1))
    finally:
        worker.stop()
    assert tick.sent == {DEFAULT_ORG_ID: 1}
    assert len(sent) == 1
    to, subject, attachments = sent[0]
    assert to == "admin@example.com" and "compliance report" in subject
    (fname, ctype, data), = attachments
    assert ctype == "application/pdf" and data.startswith(b"%PDF") and fname.endswith(".pdf")
    with db.get_session(DEFAULT_ORG_ID) as s:
        sch = s.get(ComplianceReportSchedule, sid)
        assert sch.last_status == "sent" and sch.next_run_at == due + timedelta(days=7)
        assert s.scalar(select(func.count()).select_from(AuditLog).where(
            AuditLog.action == "compliance_report_sent")) == 1


def test_send_now_reports_mail_not_configured(client):
    sid = _schedule(client).json()["id"]
    r = client.post(f"/api/compliance/schedules/{sid}/send")
    assert r.status_code == 200
    assert r.json()["status"] == "failed" and "mail server" in r.json()["errors"][0]
    with db.get_session(DEFAULT_ORG_ID) as s:
        assert s.get(ComplianceReportSchedule, sid).last_status == "failed"


def test_removed_member_is_skipped(client, monkeypatch):
    monkeypatch.setattr(mailer, "configured", lambda: True)
    monkeypatch.setattr(mailer, "send", lambda *a, **k: mailer.MailResult(True))
    make_user(client, "viewer", "leaver@example.com")
    sid = _schedule(client, recipients=["admin@example.com", "leaver@example.com"]).json()["id"]
    uid = next(u["id"] for u in client.get("/api/users").json() if u["email"] == "leaver@example.com")
    assert client.patch(f"/api/users/{uid}", json={"is_active": False}).status_code == 200
    r = client.post(f"/api/compliance/schedules/{sid}/send").json()
    assert r["status"] == "sent" and r["sent"] == 1
    assert any("no longer members" in e for e in r["errors"])


# ----------------------------------------------------------------------------- snapshots
def test_daily_snapshots_are_idempotent(client):
    with db.get_session(DEFAULT_ORG_ID) as s:
        day = utcnow().date()
        n = service.snapshot_all(s, day)
        assert n >= len(catalog.frameworks())
        assert service.snapshot_all(s, day) == 0
        rows = s.scalar(select(func.count()).select_from(ComplianceSnapshot).where(
            ComplianceSnapshot.day == day, ComplianceSnapshot.scope == ""))
        assert rows == len(catalog.frameworks())


def test_snapshot_worker_writes_compliance_snapshots(client):
    from app.services.dashboard_snapshots import DashboardSnapshotWorker

    w = DashboardSnapshotWorker()
    try:
        tick = w.tick(utcnow())
    finally:
        w.stop()
    assert tick.compliance.get(DEFAULT_ORG_ID, 0) >= len(catalog.frameworks())


# ----------------------------------------------------------------------------- PDF
def _xref_ok(data: bytes) -> int:
    start = int(re.search(rb"startxref\n(\d+)\n%%EOF", data).group(1))
    assert data[start:start + 4] == b"xref"
    entries = re.findall(rb"(\d{10}) 00000 n ", data[start:])
    for i, off in enumerate(entries, start=1):
        assert data[int(off):].startswith(f"{i} 0 obj".encode())
    return len(entries)


def test_pdf_writer_smoke(client):
    with db.get_session(DEFAULT_ORG_ID) as s:
        data, summaries = reports.build_pdf(s, list(catalog.frameworks()), checks.Scope(), name="Quarterly")
    assert data.startswith(b"%PDF-1.4") and data.rstrip().endswith(b"%%EOF")
    assert _xref_ok(data) > 5
    pages = int(re.search(rb"/Type /Pages /Kids \[[^\]]*\] /Count (\d+)", data).group(1))
    assert pages >= 5 and len(summaries) == 5
    streams = [zlib.decompress(m) for m in re.findall(rb"stream\n(.*?)\nendstream", data, re.S)]
    text = b"".join(streams)
    assert b"not an audit opinion" in text and b"Page 1 of" in text and b"A.8.15" in text


def test_pdf_text_escaping_and_wrapping():
    c = pdf.Canvas()
    c.text(40, 40, "Paren (x) back\\slash € 中")
    out = c.render("t", "a", utcnow())
    body = zlib.decompress(re.search(rb"stream\n(.*?)\nendstream", out, re.S).group(1))
    assert b"\\(x\\) back\\\\slash \x80 ?" in body
    lines = pdf.wrap("word " * 50, 100, 9)
    assert all(pdf.text_width(ln, 9) <= 100 for ln in lines)
    assert pdf.wrap("x" * 500, 100, 9, max_lines=2)[-1].endswith("...")


# ----------------------------------------------------------------------------- mail attachments
@pytest.fixture()
def mail_env(monkeypatch):
    def set_env(**env):
        for k in ("PLATFORM_SMTP_HOST", "PLATFORM_SMTP_FROM", "PLATFORM_ACS_CONNECTION_STRING",
                  "PLATFORM_ACS_SENDER"):
            monkeypatch.delenv(k, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        config.reload_settings()

    yield set_env
    monkeypatch.undo()
    config.reload_settings()


def test_smtp_and_acs_carry_the_pdf_attachment(monkeypatch, mail_env):
    from app.notifications import channels as ch
    from app.notifications import ssrf

    mail_env(PLATFORM_SMTP_HOST="smtp.example.com", PLATFORM_SMTP_FROM="no-reply@example.com")
    monkeypatch.setattr(ssrf.socket, "getaddrinfo", lambda host, port, *a, **kw: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))])
    sent = []

    class FakeSMTP:
        def __init__(self, ip, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def connect(self, host, port):
            pass

        def ehlo(self):
            pass

        def has_extn(self, name):
            return True

        def starttls(self, context):
            pass

        def send_message(self, em):
            sent.append(em)
            return {}

    monkeypatch.setattr(ch, "_PinnedSMTP", FakeSMTP)
    subject, text, body = reports.render_email(
        org="Acme <Ltd>", report="Monthly", link="https://console.example.com/compliance",
        summaries=[{"name": "CIS Benchmarks", "score": 80.0, "coverage": 100.0, "fail": 3}])
    assert "Acme &lt;Ltd&gt;" in body and "<Ltd>" not in body and "not an audit opinion" in text
    data = b"%PDF-1.4 test"
    assert mailer.send("a@acme.test", subject, text, body, attachments=[("r.pdf", "application/pdf", data)]).sent
    att = list(sent[0].iter_attachments())
    assert len(att) == 1 and att[0].get_filename() == "r.pdf" and att[0].get_content() == data

    key = base64.b64encode(b"k" * 32).decode()
    mail_env(PLATFORM_ACS_CONNECTION_STRING=f"endpoint=https://acs-demo.communication.azure.com/;accesskey={key}",
             PLATFORM_ACS_SENDER="DoNotReply@example.com")
    got = {}
    monkeypatch.setattr(ssrf, "post", lambda url, b, headers, *, kind: got.update(
        body=b) or ssrf.HttpResponse(202, b"{}", {}))
    assert mailer.send("a@acme.test", subject, text, body, attachments=[("r.pdf", "application/pdf", data)]).sent
    assert json.loads(got["body"])["attachments"] == [{"name": "r.pdf", "contentType": "application/pdf",
                                                       "contentInBase64": base64.b64encode(data).decode()}]
