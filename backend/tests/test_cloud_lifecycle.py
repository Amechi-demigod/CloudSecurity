"""Cloud resource lifecycle (docs/CLOUD_INVENTORY.md): removal after missed successful scans, per-scope success,
restore, permanent deletion, exclusion from the active views, and removing a subscription / account / project."""
from __future__ import annotations

import datetime as dt

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text

from app import config, db
from app.connectors.azure import AzureConnector
from app.connectors.base import AssetRecord, CollectionResult, VulnerabilityRecord
from app.models import (
    Alert,
    Asset,
    AssetPackage,
    AuditLog,
    Finding,
    Relationship,
    RuntimeEvent,
    ScanRun,
    Vulnerability,
    get_asset,
    utcnow,
)
from app.services import cloud_lifecycle
from app.services.ingest import ingest_collection
from tests.conftest import BASE_URL, login, make_user
from tests.test_tenancy import ACME_ADMIN, tenants  # noqa: F401 - fixture

SUB_A = "aaaaaaaa-1111-2222-3333-444444444444"
SUB_B = "bbbbbbbb-1111-2222-3333-444444444444"


def stg(sub: str, name: str, public: bool = True) -> AssetRecord:
    return AssetRecord(id=f"/subscriptions/{sub}/resourcegroups/rg/providers/microsoft.storage/storageaccounts/{name}",
                       name=name, type="storage_account", subscription_id=sub, subscription_name=sub,
                       properties={"allow_blob_public_access": public})


def sub_asset(sub: str) -> AssetRecord:
    return AssetRecord(id=f"/subscriptions/{sub}", name=sub, type="subscription", subscription_id=sub,
                       subscription_name=sub)


def scan(session, assets: list[AssetRecord], read: list[str] | None, source: str = "azure", **kw) -> dict:
    return ingest_collection(session, CollectionResult(assets=assets, scopes_read=read or [], **kw), source)


def asset(session, rec: AssetRecord) -> Asset:
    session.expire_all()
    return get_asset(session, rec.id)


def nopen(session, asset_id: str | None = None) -> int:
    session.expire_all()
    stmt = select(func.count()).select_from(Finding).where(Finding.status == "open")
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    return session.scalar(stmt) or 0


@pytest.fixture()
def world(session):
    a1, a2 = stg(SUB_A, "st1"), stg(SUB_A, "st2")
    b1 = stg(SUB_B, "stb")
    base = [sub_asset(SUB_A), sub_asset(SUB_B), a1, a2, b1]
    scan(session, base, [SUB_A, SUB_B])
    return session, a1, a2, b1, base


# ----------------------------------------------------------------------------- removal rule
def test_removed_after_two_successful_scans_and_findings_close(world):
    s, a1, a2, b1, base = world
    n1, total = nopen(s, a1.id), nopen(s)
    assert n1 >= 1 and total > n1
    rest = [x for x in base if x.id != a1.id]
    out = scan(s, rest, [SUB_A, SUB_B])
    assert out["assets_removed"] == 0 and asset(s, a1).missed_scans == 1 and asset(s, a1).removed_at is None
    assert nopen(s, a1.id) == n1
    out = scan(s, rest, [SUB_A, SUB_B])
    assert out["assets_removed"] == 1 and out["findings_closed"] == n1
    assert asset(s, a1).removed_at is not None
    for f in s.scalars(select(Finding).where(Finding.asset_id == a1.id)):
        assert f.status == "resolved" and f.close_reason == "resource_removed" and f.resolved_at is not None
    # the others stay active, with their findings open and the counter reset
    assert asset(s, a2).missed_scans == 0 and asset(s, a2).removed_at is None
    assert nopen(s) == total - n1


def test_returned_asset_resets_its_counter(world):
    s, a1, _, _, base = world
    scan(s, [x for x in base if x.id != a1.id], [SUB_A, SUB_B])
    assert asset(s, a1).missed_scans == 1
    scan(s, base, [SUB_A, SUB_B])
    assert asset(s, a1).missed_scans == 0
    scan(s, [x for x in base if x.id != a1.id], [SUB_A, SUB_B])
    assert asset(s, a1).missed_scans == 1 and asset(s, a1).removed_at is None  # not "two in a row"


def test_threshold_is_a_setting(world, monkeypatch):
    s, a1, _, _, base = world
    monkeypatch.setattr(config.settings, "cloud_remove_after_misses", 3)
    rest = [x for x in base if x.id != a1.id]
    scan(s, rest, [SUB_A, SUB_B])
    scan(s, rest, [SUB_A, SUB_B])
    assert asset(s, a1).removed_at is None
    scan(s, rest, [SUB_A, SUB_B])
    assert asset(s, a1).removed_at is not None


def test_scope_not_read_counts_nothing_and_scopes_are_independent(world):
    s, a1, a2, b1, base = world
    # subscription A failed (not in scopes_read), B was read: only B's missing asset counts
    rest = [x for x in base if x.id not in (a1.id, b1.id)]
    for _ in range(3):
        scan(s, rest, [SUB_B], errors=[f"{SUB_A}: HttpError"])
    assert asset(s, a1).missed_scans == 0 and asset(s, a1).removed_at is None
    assert asset(s, b1).removed_at is not None


def test_no_scopes_read_counts_nothing(world):
    s, a1, _, _, base = world
    rest = [x for x in base if x.id != a1.id]
    for _ in range(3):
        scan(s, rest, [])
    assert asset(s, a1).missed_scans == 0 and asset(s, a1).removed_at is None


def test_scope_with_nothing_returned_counts_nothing(world):
    s, a1, a2, _, base = world
    # a scan that "read" A but returned no asset of it at all is not evidence that all of A is gone
    for _ in range(3):
        scan(s, [x for x in base if x.subscription_id == SUB_B], [SUB_A, SUB_B])
    assert asset(s, a1).removed_at is None and asset(s, a2).removed_at is None


def test_only_cloud_assets_of_the_connector_take_part(world):
    s, a1, _, _, base = world
    # sensor host / simulated workload / other connector's asset in the same "subscription"
    other = [stg(SUB_A, "sensor-host"), stg(SUB_A, "sim")]
    scan(s, other[:1], [SUB_A], source="sensor")
    scan(s, other[1:], [SUB_A], source="simulated")
    for _ in range(3):
        scan(s, base, [SUB_A, SUB_B], source="azure")
        scan(s, [sub_asset(SUB_A)], [SUB_A], source="aws")  # other provider reads A: no effect on azure rows
    for rec in other:
        assert asset(s, rec).removed_at is None and asset(s, rec).missed_scans == 0
    assert asset(s, a1).removed_at is None


def test_vulnerabilities_of_removed_assets_close(session):
    a, b = stg(SUB_A, "st1"), stg(SUB_A, "st2")
    vuln = VulnerabilityRecord(asset_id=a.id, cve_id="CVE-2024-0001", package="openssl", version="1", cvss=9.0)
    scan(session, [sub_asset(SUB_A), a, b], [SUB_A], vulnerabilities=[vuln])
    rest = [sub_asset(SUB_A), b]
    scan(session, rest, [SUB_A])
    scan(session, rest, [SUB_A])
    session.expire_all()
    v = session.scalar(select(Vulnerability).where(Vulnerability.asset_id == a.id))
    assert v.status == "resolved" and v.resolved_at is not None


# ----------------------------------------------------------------------------- restore
def test_reappearing_asset_is_active_again_and_findings_reopen(world):
    s, a1, _, _, base = world
    rest = [x for x in base if x.id != a1.id]
    scan(s, rest, [SUB_A, SUB_B])
    scan(s, rest, [SUB_A, SUB_B])
    assert asset(s, a1).removed_at is not None
    out = scan(s, base, [SUB_A, SUB_B])
    assert out["assets_restored"] == 1 and out["findings_opened"] >= 1
    x = asset(s, a1)
    assert x.removed_at is None and x.missed_scans == 0
    for f in s.scalars(select(Finding).where(Finding.asset_id == a1.id)):
        assert f.status == "open" and f.close_reason is None and f.resolved_at is None


def test_restored_asset_that_now_passes_is_no_longer_closed_for_removal(world):
    s, a1, _, _, base = world
    rest = [x for x in base if x.id != a1.id]
    scan(s, rest, [SUB_A, SUB_B])
    scan(s, rest, [SUB_A, SUB_B])
    fixed = stg(SUB_A, "st1", public=False)
    scan(s, [sub_asset(SUB_A), sub_asset(SUB_B), fixed, *base[3:]], [SUB_A, SUB_B])
    fs = list(s.scalars(select(Finding).where(Finding.asset_id == a1.id)))
    assert fs and all(f.close_reason is None for f in fs)  # no longer "closed: resource removed"
    assert any(f.status == "resolved" for f in fs)  # the rule the fix resolved


# ----------------------------------------------------------------------------- permanent deletion
def _remove(s, a1, base):
    rest = [x for x in base if x.id != a1.id]
    scan(s, rest, [SUB_A, SUB_B])
    scan(s, rest, [SUB_A, SUB_B])


def test_purge_deletes_after_retention_with_dependents(world):
    s, a1, a2, b1, base = world
    s.add(Relationship(source_id=a1.id, target_id=a2.id, type="connects_to", source="azure"))
    s.add(Vulnerability(asset_id=a1.id, cve_id="CVE-2024-1", package="p", version="1", cvss=5.0, severity="medium",
                        source="azure"))
    s.add(AssetPackage(asset_id=a1.id, name="p", version="1"))
    s.add(Alert(rule_id="R", title="t", severity="high", asset_id=a1.id, mitre_tactic="x", mitre_technique_id="T1",
                mitre_technique_name="n"))
    s.add(RuntimeEvent(asset_id=a1.id, event_type="process_exec"))
    s.commit()
    _remove(s, a1, base)
    now = utcnow()
    assert cloud_lifecycle.purge_expired(s, now + dt.timedelta(days=59)) == {}
    assert asset(s, a1) is not None
    counts = cloud_lifecycle.purge_expired(s, now + dt.timedelta(days=61))
    s.commit()
    assert counts["assets"] == 1 and counts["findings"] >= 1 and counts["relationships"] == 1
    assert counts["vulnerabilities"] == 1 and counts["packages"] == 1 and counts["alerts"] == 1
    assert counts["runtime_events"] == 1
    assert asset(s, a1) is None
    for model in (Finding, Vulnerability, AssetPackage, Alert, RuntimeEvent):
        col = model.asset_id
        assert s.scalar(select(func.count()).select_from(model).where(col == a1.id)) == 0
    assert asset(s, a2) is not None and asset(s, b1) is not None  # neighbours untouched


def test_purge_ignores_active_and_non_cloud_assets(world):
    s, a1, _, _, base = world
    sensor = stg(SUB_A, "host")
    scan(s, [sensor], [], source="sensor")
    x = asset(s, sensor)
    x.removed_at = utcnow() - dt.timedelta(days=500)  # not something the cloud lifecycle ever sets
    s.commit()
    assert cloud_lifecycle.purge_expired(s, utcnow() + dt.timedelta(days=400)) == {}
    assert asset(s, a1) is not None and asset(s, sensor) is not None


def test_purge_worker_tick_is_per_organisation_and_audited(world):
    s, a1, _, _, base = world
    _remove(s, a1, base)
    s.close()
    worker = cloud_lifecycle.CloudPurgeWorker()
    try:
        assert worker.tick(utcnow() + dt.timedelta(days=10)) == {}
        out = worker.tick(utcnow() + dt.timedelta(days=61))
        assert out["default"]["assets"] == 1
        with db.get_session("default") as s2:
            audit = s2.scalar(select(AuditLog).where(AuditLog.action == "cloud_resources_purged"))
            assert audit.detail["assets"] == 1 and audit.detail["retention_days"] == 60
    finally:
        worker._leader.release()


def test_retention_is_a_setting(world, monkeypatch):
    s, a1, _, _, base = world
    monkeypatch.setattr(config.settings, "cloud_removed_retention_days", 5)
    _remove(s, a1, base)
    assert cloud_lifecycle.purge_expired(s, utcnow() + dt.timedelta(days=6))["assets"] == 1


# ----------------------------------------------------------------------------- connectors report scopes
def _azure(monkeypatch, behaviour: dict):
    monkeypatch.setattr(config.settings, "azure_subscription_ids", list(behaviour))
    conn = AzureConnector(config.settings, client_factory=lambda *_: None)

    def fake(factory, sub, res):
        how = behaviour[sub]
        if how == "raise":
            raise RuntimeError("boom")
        if how == "step_error":
            res.errors.append(f"{sub}/compute: Forbidden")

    monkeypatch.setattr(conn, "_collect_subscription", fake)
    return conn


def test_azure_scope_is_read_only_when_it_finished_without_errors(monkeypatch):
    conn = _azure(monkeypatch, {SUB_A: "ok", SUB_B: "raise", "cccccccc-1111-2222-3333-444444444444": "step_error"})
    res = conn.collect()
    assert res.scopes_read == [SUB_A]
    assert len(res.errors) == 2


# ----------------------------------------------------------------------------- active views
def test_removed_assets_leave_the_active_views(world):
    s, a1, a2, b1, base = world
    s.close()
    with db.get_session("default") as s2:
        _remove(s2, a1, base)
    from app.services import analytics, dashboards

    with db.get_session("default") as s2:
        dash = analytics.dashboard(s2)
        assert dash["assets"]["total"] == 4  # 5 ingested, 1 removed
        assert dash["assets"]["by_type"]["storage_account"] == 2
        assert a1.id not in {p.entry_id for p in analytics.attack_paths(s2)}
        assert dashboards.accounts(s2)  # the subscriptions still having active assets


def test_api_lists_active_and_removed_separately(tenants):  # noqa: F811
    oid = tenants.acme_id
    base = [sub_asset(SUB_A), stg(SUB_A, "st1"), stg(SUB_A, "st2")]
    with db.get_session(oid) as s:
        scan(s, base, [SUB_A])
        rest = [base[0], base[2]]
        scan(s, rest, [SUB_A])
        scan(s, rest, [SUB_A])
    c = tenants.acme
    active = {a["name"] for a in c.get("/api/assets").json()}
    assert "st1" not in active and {"st2", SUB_A} <= active
    removed = c.get("/api/assets", params={"removed": "true"}).json()
    assert [a["name"] for a in removed] == ["st1"] and removed[0]["removed_at"]
    facets = c.get("/api/assets/facets").json()
    assert facets["counts"] == {"active": 2, "removed": 1, "retention_days": 60}
    # findings: not open any more; closed with the reason, filterable
    assert not [f for f in c.get("/api/findings").json() if f["asset_name"] == "st1"]
    closed = c.get("/api/findings", params={"status": "resolved", "close_reason": "resource_removed"}).json()
    assert closed and {f["asset_name"] for f in closed} == {"st1"}
    assert all(f["close_reason"] == "resource_removed" for f in closed)
    # exposure / compliance / risk do not count it
    assert c.get("/api/exposure").status_code == 200
    assert c.get("/api/compliance").status_code == 200


# ----------------------------------------------------------------------------- remove a subscription / account / project
@pytest.fixture()
def acme(tenants):  # noqa: F811
    """Acme with an Azure config listing SUB_A and data for SUB_A plus a leftover SUB_B (a failed first scan)."""
    c = tenants.acme
    r = c.put("/api/organization/connectors/azure", json={"config": {"subscription_ids": [SUB_A]}})
    assert r.status_code == 200, r.text
    left = AssetRecord(id=f"/subscriptions/{SUB_B}", name=SUB_B, type="subscription", subscription_id=SUB_B,
                       subscription_name=SUB_B)
    with db.get_session(tenants.acme_id) as s:
        scan(s, [sub_asset(SUB_A), stg(SUB_A, "st1"), stg(SUB_A, "st2")], [SUB_A])
        scan(s, [left], [])
        s.add(ScanRun(connector="azure", status="failed", errors=[f"{SUB_B}: ClientAuthenticationError"],
                      finished_at=utcnow()))
        s.commit()
    return tenants


def scopes(c: TestClient, provider="azure"):
    r = c.get(f"/api/organization/connectors/{provider}/scopes")
    assert r.status_code == 200, r.text
    return {x["id"]: x for x in r.json()}


def test_scope_list_has_configured_and_data_only_scopes(acme):
    got = scopes(acme.acme)
    assert set(got) == {SUB_A, SUB_B}
    assert got[SUB_A]["configured"] and got[SUB_A]["resources"] == 3
    assert not got[SUB_B]["configured"] and got[SUB_B]["resources"] == 1
    assert got[SUB_B]["last_scan_status"] == "failed" and got[SUB_B]["last_scanned"]
    assert scopes(acme.default) is not None and SUB_B not in scopes(acme.default)  # tenant isolation


def test_remove_leftover_subscription(acme):
    c = acme.acme
    r = c.delete(f"/api/organization/connectors/azure/scopes/{SUB_B}", params={"confirm": SUB_B[:8]})
    assert r.status_code == 200, r.text
    assert r.json()["deleted"]["assets"] == 1 and r.json()["config_updated"] is False
    assert set(scopes(c)) == {SUB_A}
    with db.get_session(acme.acme_id) as s:
        a = s.scalar(select(AuditLog).where(AuditLog.action == "cloud_scope_removed"))
        assert a.actor_email == ACME_ADMIN and a.detail["scope_id"] == SUB_B and a.detail["assets"] == 1
        assert a.detail["provider"] == "azure"


def test_remove_configured_subscription_updates_config_and_deletes_data(acme):
    c = acme.acme
    r = c.delete(f"/api/organization/connectors/azure/scopes/{SUB_A}", params={"confirm": SUB_A[:8].upper()})
    assert r.status_code == 200, r.text
    assert r.json()["deleted"]["assets"] == 3 and r.json()["deleted"]["findings"] >= 2
    assert r.json()["config_updated"] is True
    assert c.get("/api/organization/connectors").json()[0]["config"]["subscription_ids"] == []
    with db.get_session(acme.acme_id) as s:
        assert not s.scalar(select(func.count()).select_from(Asset).where(Asset.subscription_id == SUB_A))
        assert not s.scalar(select(func.count()).select_from(Finding))
        a = s.scalar(select(AuditLog).where(AuditLog.action == "cloud_scope_removed"))
        assert a.detail["findings"] >= 2 and a.detail["config_updated"] is True


def test_remove_needs_the_confirmation_and_a_known_scope(acme):
    c = acme.acme
    assert c.delete(f"/api/organization/connectors/azure/scopes/{SUB_B}").status_code == 422
    assert c.delete(f"/api/organization/connectors/azure/scopes/{SUB_B}", params={"confirm": "nope"}).status_code == 422
    other = "dddddddd-1111-2222-3333-444444444444"
    assert c.delete(f"/api/organization/connectors/azure/scopes/{other}",
                    params={"confirm": other[:8]}).status_code == 404
    assert set(scopes(c)) == {SUB_A, SUB_B}


def test_remove_is_tenant_isolated(acme):
    # the default organisation cannot remove (or even see) acme's subscription
    d = acme.default
    r = d.delete(f"/api/organization/connectors/azure/scopes/{SUB_B}", params={"confirm": SUB_B[:8]})
    assert r.status_code == 404
    assert set(scopes(acme.acme)) == {SUB_A, SUB_B}


def test_remove_requires_admin(acme):
    make_user(acme.acme, "analyst", "analyst@acme.test")
    an = TestClient(acme.acme.app, base_url=BASE_URL)
    login(an, "analyst@acme.test", "a-long-test-password")
    assert an.get("/api/organization/connectors/azure/scopes").status_code == 403
    r = an.delete(f"/api/organization/connectors/azure/scopes/{SUB_B}", params={"confirm": SUB_B[:8]})
    assert r.status_code == 403
    assert set(scopes(acme.acme)) == {SUB_A, SUB_B}


def test_remove_is_gated_by_the_cloud_module(acme):
    from tests.test_modules import set_modules

    set_modules(acme.acme_id, ["endpoints"])
    c = acme.acme
    assert c.get("/api/organization/connectors/azure/scopes").status_code == 403
    r = c.delete(f"/api/organization/connectors/azure/scopes/{SUB_B}", params={"confirm": SUB_B[:8]})
    assert r.status_code == 403 and r.json()["module"] == "cloud"


def test_remove_refuses_while_a_scan_runs(acme):
    from app.locks import advisory_lock
    from app.services.scans import scan_lock_name

    with advisory_lock(scan_lock_name(acme.acme_id, "azure")):
        r = acme.acme.delete(f"/api/organization/connectors/azure/scopes/{SUB_B}", params={"confirm": SUB_B[:8]})
    assert r.status_code == 409


def test_aws_account_is_removed_from_role_arns(tenants):  # noqa: F811
    c = tenants.acme
    arns = ["arn:aws:iam::111111111111:role/ro", "arn:aws:iam::222222222222:role/ro"]
    assert c.put("/api/organization/connectors/aws", json={"config": {"role_arns": arns}}).status_code == 200
    got = scopes(c, "aws")
    assert set(got) == {"111111111111", "222222222222"}
    r = c.delete("/api/organization/connectors/aws/scopes/111111111111", params={"confirm": "11111111"})
    assert r.status_code == 200
    cfg = c.get("/api/organization/connectors").json()
    assert [x for x in cfg if x["provider"] == "aws"][0]["config"]["role_arns"] == [arns[1]]


def test_gcp_project_found_through_the_organisation_is_not_removable(tenants):  # noqa: F811
    c = tenants.acme
    assert c.put("/api/organization/connectors/gcp", json={"config": {
        "project_ids": ["acme-prod"], "organization_id": "1234567890"}}).status_code == 200
    with db.get_session(tenants.acme_id) as s:
        scan(s, [AssetRecord(id="//cloudresourcemanager.googleapis.com/projects/found-proj", name="found-proj",
                             type="gcp_project", provider="gcp", subscription_id="found-proj")], [], source="gcp")
    r = c.delete("/api/organization/connectors/gcp/scopes/found-proj", params={"confirm": "found-pr"})
    assert r.status_code == 409


# ----------------------------------------------------------------------------- migration
def test_migration_keeps_every_existing_asset_active(tmp_path):
    eng = db.create_db_engine(f"sqlite:///{tmp_path / 'lifecycle.db'}")
    try:
        db.run_migrations(eng, "0032_attack_surface")
        now = dt.datetime(2026, 11, 1)
        with eng.begin() as c:
            for i in range(3):
                c.execute(text("INSERT INTO assets (organization_id, id, name, type, provider, subscription_id, "
                               "tags, internet_exposed, sensitive_data, properties, source, first_seen, last_seen) "
                               "VALUES ('default', :id, :n, 'vm', 'azure', 'sub', '{}', :f, :f, '{}', 'azure', :t, :t)"),
                          {"id": f"/subscriptions/sub/vm{i}", "n": f"vm{i}", "f": False, "t": now})
            c.execute(text("INSERT INTO findings (id, rule_id, asset_id, title, description, severity, status, "
                           "remediation, compliance, evidence, source, first_seen, last_seen, organization_id) "
                           "VALUES ('f1', 'R', '/subscriptions/sub/vm0', 't', '', 'high', 'resolved', '', '[]', "
                           "'{}', 'azure', :t, :t, 'default')"), {"t": now})
        db.run_migrations(eng)
        with eng.connect() as c:
            rows = c.execute(text("SELECT missed_scans, removed_at FROM assets")).all()
            assert len(rows) == 3 and all(m == 0 and r is None for m, r in rows)
            assert c.execute(text("SELECT close_reason FROM findings")).scalar() is None
        # and a rollback works
        from alembic import command

        command.downgrade(db.alembic_config(eng), "0032_attack_surface")
        with eng.connect() as c:
            assert c.execute(text("SELECT count(*) FROM assets")).scalar() == 3
    finally:
        eng.dispose()
