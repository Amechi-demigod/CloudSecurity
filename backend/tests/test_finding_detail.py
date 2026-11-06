"""Posture finding detail: guidance completeness, API additions, SLA, evidence masking, PDF export."""
from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient

from app.engine import guidance, posture, posture_aws, posture_azure, posture_gcp  # noqa: F401 - register rules
from app.models import Finding, utcnow
from app.services import finding_detail
from tests.conftest import BASE_URL, login, make_user
from tests.test_tenancy import tenants  # noqa: F401 - fixture


# ----------------------------------------------------------------------------- guidance data
def test_every_rule_has_complete_guidance():
    missing = [r.id for r in posture.RULES if r.id not in guidance.GUIDANCE]
    assert not missing, f"rules without guidance: {missing}"
    assert not set(guidance.GUIDANCE) - {r.id for r in posture.RULES}, "guidance for an unknown rule id"
    for r in posture.RULES:
        g = guidance.GUIDANCE[r.id]
        for key in guidance.REQUIRED_KEYS:
            assert g.get(key) not in (None, "", [], {}), f"{r.id}: {key} is empty"
        assert all(i["title"] and i["text"] for i in g["impact"]), r.id
        assert g["cwe"]["id"].startswith("CWE-") and g["cwe"]["name"], r.id
        assert all(a["id"].startswith("T") and a["name"] for a in g["attack"]), r.id
        lo, hi = guidance.SCORE_BANDS[r.severity]
        assert lo <= g["risk_score"] <= hi, f"{r.id}: score {g['risk_score']} outside the {r.severity} band"
        assert len(g["verify_steps"]) >= 2 and len(g["fix_console"]) >= 2, r.id
        assert len(g["impact"]) >= 2, r.id
        refs = g["references"]
        assert len(refs) >= 3, r.id
        for ref in refs:
            assert ref["title"], r.id
            assert ref["url"].startswith("https://"), f"{r.id}: non-https reference {ref['url']}"
        # read-only verification: never a mutating verb
        for bad in (" delete", " update ", " create", " put-", " set "):
            assert bad not in " " + g["verify_cli"].lower(), f"{r.id}: verify command looks mutating"


def test_render_substitutes_only_safe_values():
    g = guidance.render("AZ-STG-001", name="stprod01", resource_group="rg-prod", region="westeurope", account="sub-1")
    assert "-n stprod01 -g rg-prod" in g["fix_cli"]
    assert "<name>" not in g["fix_terraform"]
    hostile = guidance.render("AZ-STG-001", name="x; rm -rf /", resource_group="rg", region=None, account=None)
    assert "<name>" in hostile["fix_cli"] and "rm -rf" not in hostile["fix_cli"]
    assert guidance.render("NO-SUCH-RULE", name="a", resource_group=None, region=None, account=None) is None


def test_sla_and_masking_helpers():
    f = Finding(severity="critical", status="open", first_seen=utcnow() - timedelta(days=10), last_seen=utcnow())
    s = finding_detail.sla_state(f)
    assert s["sla_days"] == 7 and s["days_open"] == 10 and s["overdue_days"] == 3
    f.status, f.resolved_at = "resolved", utcnow()
    assert finding_detail.sla_state(f)["overdue_days"] is None
    f2 = Finding(severity="low", status="open", first_seen=utcnow() - timedelta(days=5), last_seen=utcnow())
    assert finding_detail.sla_state(f2)["overdue_days"] is None
    info = Finding(severity="info", status="open", first_seen=utcnow(), last_seen=utcnow())
    assert finding_detail.sla_state(info)["sla_due"] is None
    raw = {"storage_account_key": "abc", "nested": {"password": "p", "port": 22}, "ok": 1}
    masked = finding_detail.mask_evidence(raw)
    assert masked == {"storage_account_key": "********", "nested": {"password": "********", "port": 22}, "ok": 1}


# ----------------------------------------------------------------------------- API
def _first_finding(client) -> dict:
    return client.get("/api/findings").json()[0]


def test_detail_carries_guidance_sla_and_context(client):
    f = _first_finding(client)
    d = client.get(f"/api/findings/{f['id']}").json()
    assert d["id"] == f["id"]
    assert d["guidance"]["fix_cli"] and d["guidance"]["references"]
    assert d["risk_score"] == d["guidance"]["risk_score"]
    assert d["days_open"] >= 0
    assert set(d["context"]) == {"internet_exposed", "sensitive_data", "attack_paths"}
    assert d["asset"]["name"] == f["asset_name"]
    assert "sla_due" in d and "overdue_days" in d


def test_detail_masks_secret_looking_evidence(client):
    from app import db

    f = _first_finding(client)
    with db.get_session("default") as s:
        row = s.get(Finding, f["id"])
        row.evidence = {"api_token": "tok-123", "allow_blob_public_access": True}
        s.commit()
    d = client.get(f"/api/findings/{f['id']}").json()
    assert d["evidence"]["api_token"] == "********" and d["evidence"]["allow_blob_public_access"] is True


# ----------------------------------------------------------------------------- PDF
def test_pdf_export_content_and_audit(client):
    f = _first_finding(client)
    r = client.get(f"/api/findings/{f['id']}/report.pdf")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    assert r.headers["content-disposition"].startswith("attachment;")
    assert r.content.startswith(b"%PDF-1.4") and r.content.rstrip().endswith(b"%%EOF")
    import re
    import zlib

    streams = re.findall(rb"stream\n(.*?)\nendstream", r.content, re.S)
    text = b"".join(zlib.decompress(m) for m in streams).decode("cp1252", "replace")
    for needle in ("Description", "Business impact", "Evidence", "How to verify", "How to fix", "Terraform",
                   "Prevent it coming back", "References", "https://"):
        assert needle in text, needle


def test_pdf_export_needs_analyst(client):
    f = _first_finding(client)
    make_user(client, "viewer", "viewer@example.com")
    v = TestClient(client.app, base_url=BASE_URL)
    login(v, "viewer@example.com", "a-long-test-password")
    assert v.get(f"/api/findings/{f['id']}/report.pdf").status_code == 403
    assert v.get(f"/api/findings/{f['id']}").status_code == 200  # reading stays open to viewers
    make_user(client, "analyst", "analyst@example.com")
    an = TestClient(client.app, base_url=BASE_URL)
    login(an, "analyst@example.com", "a-long-test-password")
    assert an.get(f"/api/findings/{f['id']}/report.pdf").status_code == 200
    anon = TestClient(client.app, base_url=BASE_URL)
    assert anon.get(f"/api/findings/{f['id']}/report.pdf").status_code in (401, 403)


def test_pdf_and_detail_do_not_cross_tenants(tenants):  # noqa: F811
    f = _first_finding(tenants.default)
    assert tenants.acme.get(f"/api/findings/{f['id']}").status_code == 404
    assert tenants.acme.get(f"/api/findings/{f['id']}/report.pdf").status_code == 404
    assert tenants.acme.get("/api/findings/nope/report.pdf").status_code == 404


def test_audit_action_recorded(client):
    f = _first_finding(client)
    assert client.get(f"/api/findings/{f['id']}/report.pdf").status_code == 200
    from app import db
    from app.models import AuditLog

    with db.get_session("default") as s:
        rows = s.query(AuditLog).filter(AuditLog.action == "finding_report_exported").all()
        assert rows and rows[-1].target == f["id"]
