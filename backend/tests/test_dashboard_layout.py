"""Overview dashboard layout (GET / PUT /api/dashboard/layout): roles, validation, audit,
per-organisation isolation and the round trip."""
from __future__ import annotations

from sqlalchemy import select

from app import db
from app.models import AuditLog, DashboardLayout
from app.services.dashboard_layout import WIDGET_IDS, clean
from tests.test_onboarding import add_member
from tests.test_tenancy import ACME_ADMIN, ACME_PASSWORD, org_client, tenants  # noqa: F401 - fixture

URL = "/api/dashboard/layout"
LAYOUT = {"order": ["trend", "summary", "risk"], "hidden": ["risk"], "widths": {"trend": 12, "summary": 6}}


def test_no_layout_saved_returns_null(client):
    r = client.get(URL)
    assert r.status_code == 200
    assert r.json() == {"layout": None, "updated_at": None, "updated_by": None}


def test_round_trip_and_audit(client):
    r = client.put(URL, json=LAYOUT)
    assert r.status_code == 200, r.text
    assert r.json()["layout"] == LAYOUT and r.json()["updated_by"]
    assert client.get(URL).json()["layout"] == LAYOUT
    # Saving again replaces it (one row per organisation).
    client.put(URL, json={"order": ["summary"], "hidden": [], "widths": {}})
    assert client.get(URL).json()["layout"] == {"order": ["summary"], "hidden": [], "widths": {}}
    with db.get_session(unscoped=True) as s:
        assert len(s.scalars(select(DashboardLayout)).all()) == 1
        audits = s.scalars(select(AuditLog).where(AuditLog.action == "dashboard_layout_updated")).all()
        assert len(audits) == 2 and audits[0].detail["widgets"] == 3


def test_every_widget_id_is_accepted_and_empty_layout_is_valid(client):
    assert client.put(URL, json={"order": list(WIDGET_IDS), "hidden": list(WIDGET_IDS[:2]),
                                 "widths": {i: 6 for i in WIDGET_IDS}}).status_code == 200
    assert client.put(URL, json={}).status_code == 200


def test_validation_rejects_bad_layouts(client):
    bad = [
        {"order": ["nope"]},
        {"order": ["summary", "summary"]},
        {"hidden": ["risk", "risk"]},
        {"hidden": ["nope"]},
        {"widths": {"summary": 8}},
        {"widths": {"summary": "12"}},
        {"widths": {"nope": 6}},
        {"order": list(WIDGET_IDS) + ["summary"]},
        {"order": "summary"},
        {"extra": 1},
    ]
    for body in bad:
        assert client.put(URL, json=body).status_code == 422, body
    assert client.get(URL).json()["layout"] is None  # nothing was stored


def test_unknown_ids_in_a_stored_layout_are_ignored_on_read(client):
    client.put(URL, json=LAYOUT)
    with db.get_session("default") as s:
        row = s.get(DashboardLayout, "default")
        row.layout = {"order": ["gone", "trend", "trend"], "hidden": ["old", "risk"],
                      "widths": {"gone": 6, "trend": 7, "top": 6}}
        s.commit()
    assert client.get(URL).json()["layout"] == {"order": ["trend"], "hidden": ["risk"], "widths": {"top": 6}}
    assert clean(None) is None and clean({"order": 1}) is not None


def test_roles(tenants):  # noqa: F811
    a = tenants.acme
    add_member(tenants.acme_id, "viewer@acme.test", "viewer")
    add_member(tenants.acme_id, "analyst@acme.test", "analyst")
    assert a.put(URL, json=LAYOUT).status_code == 200
    for email in ("viewer@acme.test", "analyst@acme.test"):
        c = org_client(a.app, email, "a-long-member-password")
        assert c.get(URL).json()["layout"] == LAYOUT  # everyone sees the organisation's layout
        assert c.put(URL, json={"order": ["risk"]}).status_code == 403
    assert a.get(URL).json()["layout"] == LAYOUT


def test_requires_sign_in(client):
    from fastapi.testclient import TestClient

    from tests.conftest import BASE_URL
    anon = TestClient(client.app, base_url=BASE_URL)
    assert anon.get(URL).status_code == 401
    assert anon.put(URL, json=LAYOUT).status_code == 401


def test_organisations_never_share_a_layout(tenants):  # noqa: F811
    d, a = tenants.default, tenants.acme
    d.put(URL, json={"order": ["summary"], "hidden": [], "widths": {}})
    assert a.get(URL).json()["layout"] is None
    a.put(URL, json=LAYOUT)
    assert d.get(URL).json()["layout"] == {"order": ["summary"], "hidden": [], "widths": {}}
    assert a.get(URL).json()["layout"] == LAYOUT
    with db.get_session(unscoped=True) as s:
        rows = {r.organization_id: r.updated_by for r in s.scalars(select(DashboardLayout))}
    assert set(rows) == {"default", tenants.acme_id} and rows[tenants.acme_id] == ACME_ADMIN
    # the audit entry belongs to the acting organisation only
    with db.get_session(unscoped=True) as s:
        acme_audit = s.scalars(select(AuditLog).where(AuditLog.action == "dashboard_layout_updated",
                                                       AuditLog.organization_id == tenants.acme_id)).all()
    assert len(acme_audit) == 1 and acme_audit[0].actor_email == ACME_ADMIN and ACME_PASSWORD not in str(acme_audit[0].detail)
