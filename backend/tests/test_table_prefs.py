"""Per-user table preferences (GET / PUT /api/table-prefs/{table_id}): round trip, validation and isolation
between users and organisations."""
from __future__ import annotations

from sqlalchemy import select

from app import db
from app.models import TablePreference
from tests.test_onboarding import add_member
from tests.test_tenancy import ACME_ADMIN, org_client, tenants  # noqa: F401 - fixture

URL = "/api/table-prefs/devices"
PREFS = {"widths": {"name": 320, "os": 140}, "hidden": ["usb"], "density": "compact"}


def test_nothing_saved_returns_empty_object(client):
    r = client.get(URL)
    assert r.status_code == 200 and r.json() == {}


def test_round_trip_and_replace(client):
    r = client.put(URL, json=PREFS)
    assert r.status_code == 200, r.text
    assert client.get(URL).json() == PREFS
    client.put(URL, json={"widths": {}, "hidden": [], "density": "comfortable"})
    assert client.get(URL).json() == {"widths": {}, "hidden": [], "density": "comfortable"}
    with db.get_session(unscoped=True) as s:
        assert len(s.scalars(select(TablePreference)).all()) == 1  # replaced, not duplicated


def test_validation_rejects_bad_bodies(client):
    bad = [
        {"widths": {"name": 39}},
        {"widths": {"name": 1201}},
        {"widths": {"name": "wide"}},
        {"widths": {"bad key!": 100}},
        {"hidden": ["c"] * 51},
        {"hidden": [1]},
        {"density": "huge"},
        {"extra": 1},
        {"widths": [1]},
    ]
    for body in bad:
        assert client.put(URL, json=body).status_code == 422, body
    assert client.get(URL).json() == {}


def test_table_id_and_size_limits(client):
    assert client.put("/api/table-prefs/Bad_Id", json=PREFS).status_code == 422
    assert client.get("/api/table-prefs/Bad_Id").status_code == 422
    assert client.put("/api/table-prefs/" + "a" * 65, json=PREFS).status_code == 422
    assert client.put("/api/table-prefs/a-1", json=PREFS).status_code == 200
    big = '{"widths": {}, "hidden": [], "density": "compact"}' + " " * 9000
    assert client.put(URL, content=big, headers={"Content-Type": "application/json"}).status_code == 413


def test_requires_sign_in(client):
    from fastapi.testclient import TestClient

    from tests.conftest import BASE_URL
    anon = TestClient(client.app, base_url=BASE_URL)
    assert anon.get(URL).status_code == 401
    assert anon.put(URL, json=PREFS).status_code == 401


def test_users_in_one_organisation_do_not_share(tenants):  # noqa: F811
    a = tenants.acme
    add_member(tenants.acme_id, "viewer@acme.test", "viewer")
    v = org_client(a.app, "viewer@acme.test", "a-long-member-password")
    a.put(URL, json=PREFS)
    assert v.get(URL).json() == {}  # a viewer has their own, and may save it
    other = {"widths": {"name": 200}, "hidden": [], "density": "comfortable"}
    assert v.put(URL, json=other).status_code == 200
    assert v.get(URL).json() == other and a.get(URL).json() == PREFS


def test_organisations_never_share(tenants):  # noqa: F811
    d, a = tenants.default, tenants.acme
    d.put(URL, json=PREFS)
    assert a.get(URL).json() == {}
    a.put(URL, json={"widths": {}, "hidden": ["os"], "density": "comfortable"})
    assert d.get(URL).json() == PREFS
    with db.get_session(unscoped=True) as s:
        rows = {r.organization_id for r in s.scalars(select(TablePreference))}
    assert rows == {"default", tenants.acme_id} and ACME_ADMIN
