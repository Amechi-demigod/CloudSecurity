"""Executive report (docs/EXECUTIVE_REPORT.md): data assembly, period comparison, PDF, schedules, unsubscribe,
RBAC, tenant isolation and the MSP stand-in. Mail is always mocked."""
from __future__ import annotations

import base64
import re
import zlib
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app import config, db, mailer
from app.executive import data, delivery, pdf
from app.executive.models import ExecReportRecipient, ExecReportSubscription
from app.models import Asset, AuditLog, ExternalFinding, ExternalTarget, Finding, ReputationDomain, Vulnerability, utcnow
from app.modules import CLOUD, ENDPOINTS, EXTERNAL, VULNERABILITIES
from app.services import dashboards
from app.tenancy import DEFAULT_ORG_ID
from tests.conftest import login, make_user
from tests.test_msp import PW, make_member, make_org, switch, w  # noqa: F401 - w is a fixture
from tests.test_tenancy import ACME_ADMIN, ACME_PASSWORD, create_org, org_client

BASE = "/api/reports/executive"


def pdf_text(blob: bytes) -> str:
    """All text drawn on the pages (content streams are Flate-compressed)."""
    out = []
    for m in re.finditer(rb"stream\n(.*?)\nendstream", blob, re.S):
        out.append(zlib.decompress(m.group(1)).decode("cp1252"))
    return " ".join(re.findall(r"\((.*?)\) Tj", " ".join(out)))


def seed(org: str = DEFAULT_ORG_ID, tag: str = "A") -> None:
    """One critical cloud finding, an overdue known-exploited vulnerability, an exposed weakness and a domain grade."""
    with db.get_session(org) as s:
        s.add(Asset(id=f"arn:{tag}:bucket", name=f"bucket-{tag}", type="s3_bucket", provider="aws",
                    subscription_id=f"acct-{tag}", source="test"))
        s.flush()
        s.add(Finding(rule_id=f"RULE-{tag}", asset_id=f"arn:{tag}:bucket", title=f"Secret storage {tag} is public",
                      description="Anyone can read the files.", severity="critical", status="open", source="test",
                      first_seen=utcnow() - timedelta(days=3)))
        s.add(Vulnerability(asset_id=f"arn:{tag}:bucket", cve_id="CVE-2024-0001", package="openssl", version="1",
                            cvss=9.8, severity="critical", status="open", kev=True, source="test",
                            first_seen=utcnow() - timedelta(days=40)))
        s.add(ExternalFinding(seq=1, key=f"k-{tag}", check_id="tls", title=f"Login page {tag} has no encryption",
                              severity="high", host=f"www.{tag.lower()}.test", status="open",
                              detail={"impact": "Passwords can be read by anyone on the network."}))
        s.add(ExternalTarget(kind="domain", value=f"{tag.lower()}.test", token="t", verified_at=utcnow()))
        s.add(ReputationDomain(domain=f"{tag.lower()}.test", score=42, grade="D", counts={"high": 2}))
        s.commit()


# ----------------------------------------------------------------------------- data assembly
def test_full_report_has_every_section_and_plain_headline(empty_client):
    seed()
    r = empty_client.get(BASE, params={"period": "monthly"})
    assert r.status_code == 200
    rep = r.json()
    assert rep["organization"] and rep["period"]["name"] == "Monthly"
    assert re.search(r"Your overall risk is \d+ out of 100", rep["headline"]["text"])
    assert any("Secret storage A is public" in t["title"] for t in rep["top_risks"])
    assert any("already using" in t["title"] for t in rep["top_risks"])
    assert 1 <= len(rep["top_risks"]) <= 5
    for t in rep["top_risks"]:
        assert t["why"] and t["who"] and t["severity"]
    assert rep["overdue"]["total"] == 1 and rep["overdue"]["oldest_days"] >= 25
    assert rep["exposure"]["findings"]["high"] == 1
    assert rep["exposure"]["domains"][0]["grade"] == "D"
    assert rep["compliance"]["frameworks"] and "not an audit opinion" in rep["compliance"]["disclaimer"]
    assert rep["coverage"]["data"]["domains_monitored"] == 1
    assert len(rep["next_steps"]) == 3
    assert "overdue" in rep["next_steps"][0]


def test_only_sections_for_modules_the_org_has(client):
    cid = make_org("partial", modules=[VULNERABILITIES])
    make_member(cid, "admin@partial.test", "admin")
    with db.get_session(cid) as s:
        rep = data.build(s, "weekly")
    assert set(rep["modules"]) == {VULNERABILITIES}
    assert "exposure" not in rep and "overdue" in rep and "compliance" in rep
    assert rep["headline"]["score"] is None and "risk is" not in rep["headline"]["text"]
    assert rep["coverage"]["lines"] == []
    none_id = make_org("nothing", modules=[])
    with db.get_session(none_id) as s:
        rep = data.build(s, "weekly")
    assert not {"exposure", "overdue", "compliance"} & rep.keys()
    assert len(rep["next_steps"]) == 3
    blob = pdf.render(rep)
    assert blob.startswith(b"%PDF") and "Overdue fixes" not in pdf_text(blob)
    ext = make_org("ext-only", modules=[EXTERNAL])
    with db.get_session(ext) as s:
        rep = data.build(s, "weekly")
    assert "exposure" in rep and "overdue" not in rep and "compliance" not in rep


def test_period_comparison_uses_the_snapshot_one_period_earlier(empty_client):
    seed()
    now = utcnow()
    with db.get_session(DEFAULT_ORG_ID) as s:
        cur = data.build(s, "monthly", now)["headline"]
    assert cur["direction"] == "unknown" and "not available yet" in cur["text"]
    with db.get_session(DEFAULT_ORG_ID) as s:
        score = dashboards.current_metrics(s)["risk_score"]
        s.add(dashboards.DashboardSnapshot(day=(now - timedelta(days=30)).date(), account="",
                                           metrics={"risk_score": score + 6, "open_critical": 5, "vulns_critical": 0}))
        s.commit()
    with db.get_session(DEFAULT_ORG_ID) as s:
        rep = data.build(s, "monthly", now)
    assert round(rep["headline"]["delta"]) == -6 and rep["headline"]["direction"] == "better"
    assert "6 points better than last month" in rep["headline"]["text"]
    assert rep["changes"]["comparison_available"] is True
    assert any("fell" in x for x in rep["changes"]["improved"])  # 5 critical before, 1 now
    with db.get_session(DEFAULT_ORG_ID) as s:  # other periods compare with their own earlier snapshot
        assert data.build(s, "weekly", now)["headline"]["direction"] == "unknown"


def test_fixed_and_new_counts(empty_client):
    seed()
    with db.get_session(DEFAULT_ORG_ID) as s:
        s.add(Finding(rule_id="OLD", asset_id="arn:A:bucket", title="Old", severity="high", status="resolved",
                      source="test", first_seen=utcnow() - timedelta(days=90),
                      resolved_at=utcnow() - timedelta(days=2)))
        s.commit()
        rep = data.build(s, "monthly")
    assert any("1 cloud security issue was fixed" in x for x in rep["changes"]["improved"])
    assert any("new cloud security issue" in x for x in rep["changes"]["worse"])


# ----------------------------------------------------------------------------- PDF
def test_pdf_is_valid_short_and_has_the_expected_text(empty_client):
    seed()
    r = empty_client.get(f"{BASE}/pdf", params={"period": "quarterly"})
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert "no-store" in r.headers["cache-control"]
    blob = r.content
    assert blob.startswith(b"%PDF-1.4") and blob.rstrip().endswith(b"%%EOF")
    n_pages = int(re.search(rb"/Count (\d+)", blob).group(1))
    assert 1 <= n_pages <= 3
    text = pdf_text(blob)
    for needle in ("EXECUTIVE SECURITY REPORT", "Your overall risk is", "The top risks to act on",
                   "Secret storage A is public", "Overdue fixes", "Recommended next steps",
                   "not an audit opinion", f"Page 1 of {n_pages}", "Sentrigis", "Period:", "Generated"):
        assert needle in text, needle
    audit_rows = _audit("exec_report_downloaded")
    assert len(audit_rows) == 1 and audit_rows[0].detail["period"] == "quarterly"


def test_pdf_download_is_rate_limited(empty_client, monkeypatch):
    from app.executive import api
    monkeypatch.setattr(api, "PDF_LIMIT", 2)
    api.pdf_limiter.reset()
    assert [empty_client.get(f"{BASE}/pdf").status_code for _ in range(3)] == [200, 200, 429]


def _audit(action: str, org: str = DEFAULT_ORG_ID) -> list[AuditLog]:
    with db.get_session(org) as s:
        return list(s.scalars(select(AuditLog).where(AuditLog.action == action).order_by(AuditLog.id)))


# ----------------------------------------------------------------------------- cadence
def test_next_run_for_each_frequency():
    mon = datetime(2026, 11, 2, 6)  # a Monday
    assert delivery.next_run("daily", 0, 6, mon) == datetime(2026, 11, 3, 6)
    assert delivery.next_run("daily", 0, 6, mon - timedelta(minutes=1)) == mon
    assert delivery.next_run("weekly", 0, 6, mon) == datetime(2026, 11, 9, 6)
    assert delivery.next_run("weekly", 4, 9, mon) == datetime(2026, 11, 6, 9)
    assert delivery.next_run("monthly", 1, 6, datetime(2026, 11, 1, 6)) == datetime(2026, 12, 1, 6)
    assert delivery.next_run("monthly", 28, 0, datetime(2026, 12, 30)) == datetime(2027, 1, 28)
    assert delivery.next_run("quarterly", 1, 6, datetime(2026, 11, 25)) == datetime(2027, 1, 1, 6)
    assert delivery.next_run("quarterly", 15, 6, datetime(2026, 10, 1, 7)) == datetime(2026, 10, 15, 6)
    assert delivery.next_run("quarterly", 1, 6, datetime(2026, 10, 1, 6)) == datetime(2027, 1, 1, 6)
    assert delivery.next_run("quarterly", 10, 6, datetime(2026, 12, 31)) == datetime(2027, 1, 10, 6)


@pytest.fixture()
def sent(monkeypatch):
    box: list[dict] = []
    monkeypatch.setattr(mailer, "configured", lambda: True)

    def fake_send(to, subject, text, html, *, reply_to=None, attachments=None):
        box.append({"to": to, "subject": subject, "text": text, "html": html, "attachments": attachments})
        return mailer.MailResult(True)

    monkeypatch.setattr(mailer, "send", fake_send)
    return box


def _sub(c, **kw):
    body = {"name": "Board pack", "frequency": "monthly", "day": 1, "hour": 6, **kw}
    r = c.post(f"{BASE}/subscriptions", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def _external(c, sid, email="ceo@client.test", name="Ada Obi", title="CEO"):
    r = c.post(f"{BASE}/subscriptions/{sid}/recipients",
               json={"kind": "external", "name": name, "email": email, "job_title": title})
    assert r.status_code == 201, r.text
    return r.json()


@pytest.mark.parametrize("freq,day,step", [("daily", 0, timedelta(days=1)), ("weekly", 0, timedelta(days=7))])
def test_worker_fires_at_the_right_cadence(empty_client, sent, freq, day, step):
    sub = _sub(empty_client, frequency=freq, day=day)
    _external(empty_client, sub["id"])
    worker = delivery.ExecReportWorker()
    try:
        assert worker.tick(utcnow()).sent == {}  # not due yet
        with db.get_session(DEFAULT_ORG_ID) as s:
            due = s.get(ExecReportSubscription, sub["id"]).next_run_at
        assert worker.tick(due - timedelta(minutes=1)).sent == {}
        assert worker.tick(due + timedelta(minutes=1)).sent == {DEFAULT_ORG_ID: 1}
        assert worker.tick(due + timedelta(minutes=2)).sent == {}  # once, not repeated
    finally:
        worker.stop()
    with db.get_session(DEFAULT_ORG_ID) as s:
        row = s.get(ExecReportSubscription, sub["id"])
        assert row.last_status == "sent" and row.next_run_at == due + step
    assert len(sent) == 1


def test_monthly_and_quarterly_reschedule_and_use_their_own_period(empty_client, sent):
    for freq, nxt_month in (("monthly", 1), ("quarterly", 1)):
        sub = _sub(empty_client, name=freq, frequency=freq, day=1, hour=6)
        _external(empty_client, sub["id"], email=f"{freq}@client.test")
        with db.get_session(DEFAULT_ORG_ID) as s:
            row = s.get(ExecReportSubscription, sub["id"])
            assert row.next_run_at.day == 1 and (freq == "monthly" or row.next_run_at.month in (1, 4, 7, 10))
            now = row.next_run_at
            delivery.send_subscription(s, row, now=now)
            assert row.next_run_at > now
    subjects = [m["subject"] for m in sent]
    assert "Monthly" in subjects[0] and "Quarterly" in subjects[1]


# ----------------------------------------------------------------------------- delivery
def test_send_now_emails_summary_with_pdf_and_unsubscribe_link(empty_client, sent, monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://console.test")
    config.reload_settings()
    seed()
    sub = _sub(empty_client)
    admin_id = empty_client.get(f"{BASE}/subscriptions").json()["admins"][0]["id"]
    assert empty_client.post(f"{BASE}/subscriptions/{sub['id']}/recipients",
                             json={"kind": "admin", "user_id": admin_id}).status_code == 201
    _external(empty_client, sub["id"])
    r = empty_client.post(f"{BASE}/subscriptions/{sub['id']}/send")
    assert r.status_code == 200 and r.json()["status"] == "sent" and r.json()["sent"] == 2
    by_to = {m["to"]: m for m in sent}
    assert set(by_to) == {"admin@example.com", "ceo@client.test"}
    ceo = by_to["ceo@client.test"]
    (fname, ctype, blob), = ceo["attachments"]
    assert ctype == "application/pdf" and blob.startswith(b"%PDF") and fname.startswith("executive-report-")
    assert "Hello Ada Obi" in ceo["text"] and "Secret storage A is public" in ceo["text"]
    token = re.search(r"unsubscribe\?token=([\w.\-]+)", ceo["text"]).group(1)
    assert "console.test/api/reports/executive/unsubscribe" in ceo["text"] and token in ceo["html"]
    assert "unsubscribe" not in by_to["admin@example.com"]["text"].lower()  # admins manage it in the console
    assert [a.detail["recipients"] for a in _audit("exec_report_sent")] == [2]


def test_mail_not_configured_and_no_recipients(empty_client):
    sub = _sub(empty_client)
    r = empty_client.post(f"{BASE}/subscriptions/{sub['id']}/send").json()
    assert r["status"] == "failed" and "no recipient" in r["errors"][0]
    _external(empty_client, sub["id"])
    r = empty_client.post(f"{BASE}/subscriptions/{sub['id']}/send").json()
    assert r["status"] == "failed" and "mail server" in r["errors"][0]


def test_demoted_admin_and_unsubscribed_person_are_skipped(empty_client, sent):
    make_user(empty_client, "admin", "second@example.com")
    sub = _sub(empty_client)
    admins = {a["email"]: a["id"] for a in empty_client.get(f"{BASE}/subscriptions").json()["admins"]}
    empty_client.post(f"{BASE}/subscriptions/{sub['id']}/recipients",
                      json={"kind": "admin", "user_id": admins["second@example.com"]})
    _external(empty_client, sub["id"], email="cfo@client.test", name="Tunde", title="CFO")
    _external(empty_client, sub["id"], email="gone@client.test", name="Gone")
    with db.get_session(DEFAULT_ORG_ID) as s:
        gone = s.scalars(select(ExecReportRecipient).where(ExecReportRecipient.email == "gone@client.test")).one()
        gone.unsubscribed_at = utcnow()
        s.commit()
    users = empty_client.get("/api/users").json()
    uid = next(u["id"] for u in (users["items"] if isinstance(users, dict) else users) if u["email"] == "second@example.com")
    assert empty_client.patch(f"/api/users/{uid}", json={"role": "viewer"}).status_code == 200
    out = empty_client.post(f"{BASE}/subscriptions/{sub['id']}/send").json()
    assert out["sent"] == 1 and {m["to"] for m in sent} == {"cfo@client.test"}
    states = {x["email"]: x["state"] for x in out["subscription"]["recipients"]}
    assert states == {"second@example.com": "not_admin", "cfo@client.test": "active", "gone@client.test": "unsubscribed"}


def test_send_now_is_rate_limited(empty_client, sent, monkeypatch):
    from app.executive import api
    monkeypatch.setattr(api, "SEND_LIMIT", 2)
    api.send_limiter.reset()
    sub = _sub(empty_client)
    _external(empty_client, sub["id"])
    codes = [empty_client.post(f"{BASE}/subscriptions/{sub['id']}/send").status_code for _ in range(3)]
    assert codes == [200, 200, 429] and len(sent) == 2


# ----------------------------------------------------------------------------- unsubscribe
def _token(org: str, rid: str) -> str:
    return delivery.make_token(org, rid)


def _rid(org: str, email: str) -> str:
    with db.get_session(org) as s:
        return s.scalars(select(ExecReportRecipient).where(ExecReportRecipient.email == email)).one().id


def test_unsubscribe_link_works_without_signing_in(empty_client, anon_http=None):
    from fastapi.testclient import TestClient
    sub = _sub(empty_client)
    _external(empty_client, sub["id"])
    token = _token(DEFAULT_ORG_ID, _rid(DEFAULT_ORG_ID, "ceo@client.test"))
    anon = TestClient(empty_client.app, base_url="https://testserver")
    page = anon.get(f"{BASE}/unsubscribe", params={"token": token})
    assert page.status_code == 200 and "Stop receiving this report?" in page.text
    with db.get_session(DEFAULT_ORG_ID) as s:  # opening the link changes nothing
        assert s.scalars(select(ExecReportRecipient)).one().unsubscribed_at is None
    done = anon.post(f"{BASE}/unsubscribe", params={"token": token})
    assert done.status_code == 200 and "You are unsubscribed" in done.text
    with db.get_session(DEFAULT_ORG_ID) as s:
        assert s.scalars(select(ExecReportRecipient)).one().unsubscribed_at is not None
    assert [a.actor_email for a in _audit("exec_report_unsubscribed")] == ["ceo@client.test"]
    # the link never signs anybody in
    assert "set-cookie" not in done.headers and anon.get("/api/auth/me").status_code == 401
    assert anon.get(BASE).status_code == 401
    assert anon.get(f"{BASE}/subscriptions").status_code == 401


def test_unsubscribe_rejects_forged_and_foreign_tokens(empty_client):
    from fastapi.testclient import TestClient
    acme_id = create_org("acme", ACME_ADMIN, ACME_PASSWORD, name="Acme Ltd")
    sub = _sub(empty_client)
    _external(empty_client, sub["id"])
    rid = _rid(DEFAULT_ORG_ID, "ceo@client.test")
    anon = TestClient(empty_client.app, base_url="https://testserver")
    good = _token(DEFAULT_ORG_ID, rid)
    payload, _, sig = good.partition(".")
    forged = [payload + "." + "0" * 40, "x." + sig, "", "garbage", base64.urlsafe_b64encode(b"a:b").decode() + "." + sig,
              _token(acme_id, rid)]  # signed, but the recipient does not exist in Acme
    for t in forged:
        r = anon.post(f"{BASE}/unsubscribe", params={"token": t})
        assert "not valid" in r.text, t
    with db.get_session(DEFAULT_ORG_ID) as s:
        assert s.scalars(select(ExecReportRecipient)).one().unsubscribed_at is None
    # a token never reaches an admin recipient
    admin_id = empty_client.get(f"{BASE}/subscriptions").json()["admins"][0]["id"]
    r = empty_client.post(f"{BASE}/subscriptions/{sub['id']}/recipients", json={"kind": "admin", "user_id": admin_id})
    arid = _rid(DEFAULT_ORG_ID, "admin@example.com")
    assert "not valid" in anon.post(f"{BASE}/unsubscribe", params={"token": _token(DEFAULT_ORG_ID, arid)}).text


# ----------------------------------------------------------------------------- RBAC and validation
def test_only_admins_manage_viewers_and_analysts_read_only(empty_client):
    sub = _sub(empty_client)
    make_user(empty_client, "viewer")
    make_user(empty_client, "analyst")
    for role in ("viewer", "analyst"):
        c = org_client(empty_client.app, f"{role}@example.com", "a-long-test-password")
        assert c.get(BASE).status_code == 200  # the on-screen report
        assert c.get(f"{BASE}/pdf").status_code == 200
        assert c.get(f"{BASE}/subscriptions").status_code == 403
        assert c.post(f"{BASE}/subscriptions", json={"name": "x"}).status_code == 403
        assert c.patch(f"{BASE}/subscriptions/{sub['id']}", json={"enabled": False}).status_code == 403
        assert c.delete(f"{BASE}/subscriptions/{sub['id']}").status_code == 403
        assert c.post(f"{BASE}/subscriptions/{sub['id']}/recipients",
                      json={"kind": "external", "name": "A", "email": "a@b.test"}).status_code == 403
        assert c.post(f"{BASE}/subscriptions/{sub['id']}/send").status_code == 403
    assert empty_client.__class__(empty_client.app, base_url="https://testserver").get(BASE).status_code == 401


def test_validation(empty_client):
    sub = _sub(empty_client)
    url = f"{BASE}/subscriptions/{sub['id']}/recipients"
    bad = [{"kind": "external", "name": "A", "email": "not-an-email"},
           {"kind": "external", "name": "A", "email": "a@b"},
           {"kind": "external", "name": "A\r\nBcc: x@y.test", "email": "a@b.test"},
           {"kind": "external", "name": "", "email": "a@b.test"},
           {"kind": "external", "email": "a@b.test"},
           {"kind": "external", "name": "A", "email": "a@b.test", "job_title": "x" * 200},
           {"kind": "admin", "user_id": "f" * 32},
           {"kind": "admin"},
           {"kind": "external", "name": "A", "email": "a@b.test", "extra": 1}]
    for body in bad:
        assert empty_client.post(url, json=body).status_code == 422, body
    _external(empty_client, sub["id"], email="A@B.test")
    assert empty_client.post(url, json={"kind": "external", "name": "Dup", "email": "a@b.test"}).status_code == 409
    assert empty_client.post(f"{BASE}/subscriptions", json={"name": "x", "frequency": "yearly"}).status_code == 422
    assert empty_client.post(f"{BASE}/subscriptions", json={"name": "x", "frequency": "weekly", "day": 9}).status_code == 422
    assert empty_client.post(f"{BASE}/subscriptions", json={"name": "x", "frequency": "monthly", "day": 0}).status_code == 422
    assert empty_client.patch(f"{BASE}/subscriptions/{sub['id']}", json={"frequency": "weekly", "day": 8}).status_code == 422
    assert empty_client.get(BASE, params={"period": "yearly"}).status_code == 422


def test_subscription_crud_and_audit_of_recipient_changes(empty_client):
    sub = _sub(empty_client, frequency="daily")
    assert sub["next_run_at"] and sub["recipients"] == []
    r = empty_client.patch(f"{BASE}/subscriptions/{sub['id']}", json={"enabled": False, "name": "Renamed"}).json()
    assert r["enabled"] is False and r["name"] == "Renamed"
    r = _external(empty_client, sub["id"])
    rid = r["recipients"][0]["id"]
    assert r["recipients"][0]["job_title"] == "CEO" and r["recipients"][0]["state"] == "active"
    out = empty_client.delete(f"{BASE}/subscriptions/{sub['id']}/recipients/{rid}")
    assert out.status_code == 200 and out.json()["recipients"] == []
    assert empty_client.delete(f"{BASE}/subscriptions/{sub['id']}/recipients/{rid}").status_code == 404
    assert [a.detail["recipient"] for a in _audit("exec_report_recipient_added")] == ["ceo@client.test"]
    assert [a.detail["recipient"] for a in _audit("exec_report_recipient_removed")] == ["ceo@client.test"]
    assert empty_client.delete(f"{BASE}/subscriptions/{sub['id']}").status_code == 204
    assert empty_client.get(f"{BASE}/subscriptions").json()["items"] == []
    for _ in range(10):
        _sub(empty_client)
    assert empty_client.post(f"{BASE}/subscriptions", json={"name": "eleven"}).status_code == 409


# ----------------------------------------------------------------------------- tenant isolation
def test_one_organisation_never_gets_anothers_data(empty_client, sent):
    acme_id = create_org("acme", ACME_ADMIN, ACME_PASSWORD, name="Acme Ltd")
    seed(DEFAULT_ORG_ID, "A")
    seed(acme_id, "B")
    acme = org_client(empty_client.app, ACME_ADMIN, ACME_PASSWORD)
    rep = acme.get(BASE).json()
    text = str(rep) + pdf_text(acme.get(f"{BASE}/pdf").content)
    assert "Secret storage B" in text and "Secret storage A" not in text
    assert "www.a.test" not in text and "a.test" not in str(rep["exposure"]["domains"])
    assert rep["organization"] == "Acme Ltd"
    mine = empty_client.get(BASE).json()
    assert "Secret storage B" not in str(mine) and mine["organization"] != "Acme Ltd"
    # subscriptions and recipients are private too
    sub = _sub(empty_client)
    _external(empty_client, sub["id"])
    assert acme.get(f"{BASE}/subscriptions").json()["items"] == []
    for call in (acme.patch(f"{BASE}/subscriptions/{sub['id']}", json={"enabled": False}),
                 acme.delete(f"{BASE}/subscriptions/{sub['id']}"),
                 acme.post(f"{BASE}/subscriptions/{sub['id']}/send"),
                 acme.post(f"{BASE}/subscriptions/{sub['id']}/recipients",
                           json={"kind": "external", "name": "X", "email": "x@y.test"})):
        assert call.status_code == 404
    acme_sub = acme.post(f"{BASE}/subscriptions", json={"name": "Acme pack"}).json()
    assert acme.post(f"{BASE}/subscriptions/{acme_sub['id']}/recipients",
                     json={"kind": "admin", "user_id": empty_client.get(f"{BASE}/subscriptions").json()["admins"][0]["id"]}
                     ).status_code == 422  # another organisation's admin cannot be a recipient
    # what is emailed: Acme's send carries Acme's data only
    acme.post(f"{BASE}/subscriptions/{acme_sub['id']}/recipients",
              json={"kind": "external", "name": "Bola", "email": "bola@acme.test"})
    out = acme.post(f"{BASE}/subscriptions/{acme_sub['id']}/send").json()
    assert out["sent"] == 1
    mail = sent[-1]
    assert "Secret storage B" in mail["text"] and "Secret storage A" not in mail["text"]
    assert "Secret storage A" not in pdf_text(mail["attachments"][0][2])
    # the worker keeps organisations apart too
    assert all(a.organization_id == acme_id for a in _audit("exec_report_sent", acme_id))
    assert _audit("exec_report_sent", DEFAULT_ORG_ID) == []


# ----------------------------------------------------------------------------- MSP
def test_msp_staff_manage_a_clients_reports_with_the_stand_in_identity(w, sent):  # noqa: F811
    assert switch(w.admin, w.client_id).status_code == 200
    sub = w.admin.post(f"{BASE}/subscriptions", json={"name": "Client board", "frequency": "monthly"})
    assert sub.status_code == 201
    sid = sub.json()["id"]
    assert w.admin.post(f"{BASE}/subscriptions/{sid}/recipients",
                        json={"kind": "external", "name": "Chief", "email": "chief@client1.test"}).status_code == 201
    # the client's own admin sees and manages it; the MSP's own organisation does not
    assert [s["name"] for s in w.client_admin.get(f"{BASE}/subscriptions").json()["items"]] == ["Client board"]
    assert w.client_admin.get(BASE).status_code == 200
    r = w.admin.post(f"{BASE}/subscriptions/{sid}/send")
    assert r.status_code == 200 and r.json()["sent"] == 1
    # no MSP branding anywhere in what the client receives
    mail = sent[-1]
    assert "MSP" not in mail["text"] and "Msp" not in pdf_text(mail["attachments"][0][2])
    # the audit rows name the real person but are hidden from the client
    with db.get_session(w.client_id) as s:
        rows = list(s.scalars(select(AuditLog).where(AuditLog.action.like("exec_report%"))))
    assert rows and all(x.via_partner_org_id == w.msp_id for x in rows)
    client_log = w.client_admin.get("/api/audit-log").json()
    items = client_log["items"] if isinstance(client_log, dict) else client_log
    assert not [e for e in items if e["action"].startswith("exec_report")]
    # staff with the viewer role cannot manage
    assert switch(w.viewer, w.client_id).status_code == 200
    assert w.viewer.get(f"{BASE}/subscriptions").status_code == 403
    assert w.viewer.get(BASE).status_code == 200
    switch(w.admin, None)
    assert w.admin.get(f"{BASE}/subscriptions").json()["items"] == []
    # another MSP cannot reach it
    assert switch(w.msp2_admin, w.client_id).status_code in (403, 404)


def test_modules_keep_applying_in_a_client(w):  # noqa: F811
    cid = make_org("only-cloud", partner=w.msp_id, modules=[CLOUD])
    make_member(cid, "admin@onlycloud.test", "admin")
    c = org_client(w.owner.app, "admin@onlycloud.test", PW)
    rep = c.get(BASE).json()
    assert "overdue" not in rep and "exposure" not in rep and rep["modules"] == [CLOUD]
    _ = (ENDPOINTS, login, config)
