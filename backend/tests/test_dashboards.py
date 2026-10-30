"""Dashboards API (/api/dashboards/*): response shape, numbers on a seeded
dataset, range and account filters, roles, organisation isolation, the daily
snapshot job and the "vs previous period" changes. Runs on SQLite and PostgreSQL."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app import db
from app.models import Alert, Asset, DashboardSnapshot, Device, Finding, Vulnerability, utcnow
from app.services import dashboards as svc
from app.services.dashboard_snapshots import DashboardSnapshotWorker
from tests.conftest import BASE_URL, login, make_user
from tests.test_tenancy import tenants  # noqa: F401 - fixture

TABS = ["overview", "vulnerabilities", "exposure", "identities", "endpoints"]
SUB_A, SUB_B = "sub-a", "sub-b"


def _asset(aid: str, type_: str, sub: str, **kw) -> Asset:
    return Asset(id=aid, name=aid, type=type_, provider="azure", subscription_id=sub,
                 subscription_name=f"Sub {sub[-1].upper()}", source="test", **kw)


def seed(org_id: str, now: datetime) -> None:
    """A small, fully known dataset (see the expected numbers in the tests)."""
    d = lambda n: now - timedelta(days=n)  # noqa: E731
    with db.get_session(org_id) as s:
        s.add_all([
            _asset("vm1", "vm", SUB_A, internet_exposed=True,
                   properties={"exposure_methods": [{"kind": "public_ip", "detail": "public IP", "ports": ["22"],
                                                     "level": "open"}],
                               "effective_ports": ["22", "443"]}),
            _asset("st1", "storage_account", SUB_A, internet_exposed=True, sensitive_data=True),
            _asset("id1", "identity", SUB_A, properties={"roles": ["Owner"], "scope": "subscription"}),
            _asset("pod1", "pod", SUB_B),
            _asset("role1", "iam_role", SUB_B, properties={"admin": False, "roles": ["ReadOnly"]}),
        ])
        s.flush()
        f = lambda rule, asset, sev, seen, **kw: Finding(rule_id=rule, asset_id=asset, title=rule,  # noqa: E731
                                                        severity=sev, first_seen=d(seen), last_seen=now, **kw)
        s.add_all([
            f("AZ-NSG-001", "vm1", "high", 2),
            f("AZ-STG-001", "st1", "critical", 10, compliance=["CIS Azure 3.1"]),
            f("AZ-ID-001", "id1", "high", 40),
            f("AZ-POD-001", "pod1", "medium", 100),
            f("XYZ-001", "pod1", "low", 1),  # unknown service code: categorised by asset type (pod)
            f("AZ-STG-002", "st1", "critical", 12, status="resolved", resolved_at=d(7)),  # 5 days: SLA met
            f("AZ-VM-001", "vm1", "high", 45, status="resolved", resolved_at=d(5)),  # 40 days: SLA missed
        ])
        dev_old = Device(hostname="laptop-1", os_family="windows", agent_version="1.0.0", last_checkin_at=now,
                         last_seen_at=now, isolation_status="isolated",
                         posture={"firewall": {"status": "fail"}})
        dev_new = Device(hostname="mac-1", os_family="macos", agent_version="1.2.0", last_checkin_at=now,
                         last_seen_at=now, posture={"firewall": {"status": "pass"}})
        s.add_all([dev_old, dev_new])
        s.flush()
        v = lambda cve, sev, seen, **kw: Vulnerability(cve_id=cve, package="pkg", version="1.0", cvss=9.0,  # noqa: E731
                                                      severity=sev, first_seen=d(seen), **kw)
        s.add_all([
            v("CVE-1", "critical", 20, asset_id="vm1", kev=True, in_use=True, internet_exposed=True,
              fixed_version="1.2", epss=0.9, risk_score=98.0, priority="critical"),
            v("CVE-2", "high", 3, asset_id="pod1", epss=0.1, risk_score=10.0, priority="low"),
            v("CVE-3", "critical", 50, asset_id="vm1", status="resolved", resolved_at=d(15)),
            v("CVE-4", "medium", 1, device_id=dev_old.id),
        ])
        s.add_all([
            Alert(rule_id="R1", title="shell", severity="critical", asset_id="vm1", mitre_tactic="Execution",
                  mitre_technique_id="T1059", mitre_technique_name="Command"),
            Alert(rule_id="R2", title="old", severity="high", asset_id="vm1", status="resolved",
                  mitre_tactic="Execution", mitre_technique_id="T1059", mitre_technique_name="Command"),
        ])
        s.commit()


@pytest.fixture()
def seeded(tenants):  # noqa: F811
    seed(tenants.acme_id, utcnow())
    return tenants


def _get(c, tab: str, **params):
    r = c.get(f"/api/dashboards/{tab}", params=params)
    assert r.status_code == 200, r.text
    return r.json()


# ----------------------------------------------------------------------------- shape + numbers
def test_every_tab_answers_in_one_response(seeded):
    a = seeded.acme
    meta = a.get("/api/dashboards").json()
    assert meta["tabs"] == {"vulnerabilities": 3, "exposure": 2, "identities": 2, "endpoints": 2}
    assert [x["id"] for x in meta["accounts"]] == [SUB_A, SUB_B]
    assert meta["sla_days"] == {"critical": 7.0, "high": 30.0}
    for tab in TABS:
        for rng in ("7d", "30d", "90d"):
            d = _get(a, tab, range=rng)
            assert d["tab"] == tab and d["range"] == rng and d["days"] == int(rng[:-1])
    assert len(_get(a, "overview", range="7d")["issue_trend"]["points"]) == 7
    assert len(_get(a, "overview", range="30d")["issue_trend"]["points"]) == 30
    ninety = _get(a, "overview", range="90d")["issue_trend"]
    assert ninety["bucket"] == "week" and len(ninety["points"]) == 13


def test_overview_numbers(seeded):
    d = _get(seeded.acme, "overview")
    k = d["kpis"]
    assert k["open_issues"]["value"] == 5
    assert k["open_issues"]["parts"] == {"critical": 1, "high": 2, "medium": 1, "low": 1}
    assert k["critical_high"]["value"] == 3 and k["critical_high"]["parts"] == {"critical": 1, "high": 2}
    assert k["mttr"]["value"] == 22.5 and k["mttr"]["critical"] == 5.0 and k["mttr"]["high"] == 40.0
    assert k["mttr"]["sla_met_pct"] == 50.0 and k["mttr"]["resolved"] == 2
    assert k["mttr"]["delta"] is None  # nothing resolved in the previous 30 days
    assert k["exposed_assets"]["value"] == 2
    assert {p["key"]: p["count"] for p in k["exposed_assets"]["parts"]} == {"vms": 1, "storage": 1}
    assert k["runtime_threats"]["value"] == 1 and k["runtime_threats"]["parts"]["critical"] == 1
    # no snapshot 30 days ago: every point-in-time change is unknown, never 0
    assert all(k[x]["delta"] is None for x in ("open_issues", "critical_high", "exposed_assets", "runtime_threats",
                                               "attack_paths"))
    assert d["risk_score"]["delta"] is None and 0 <= d["risk_score"]["value"] <= 100
    trend = d["issue_trend"]["points"]
    assert sum(p["new"] for p in trend) == 4 and sum(p["resolved"] for p in trend) == 2
    assert {a["bucket"]: (a["critical"], a["high"], a["medium"], a["low"]) for a in d["age"]} == {
        "0-7": (0, 1, 0, 1), "8-30": (1, 0, 0, 0), "31-90": (0, 1, 0, 0), "90+": (0, 0, 1, 0)}
    cats = {c["category"]: c["total"] for c in d["categories"]}
    assert cats == {"Network": 1, "Storage": 1, "Identity": 1, "Kubernetes": 2}
    assert [c["framework"] for c in d["compliance"]] and all(c["delta"] is None for c in d["compliance"])
    top = d["top_assets"]
    assert top[0]["name"] == "vm1" and top[0]["risk"] == 98  # riskiest open vulnerability
    assert top[1]["name"] == "st1" and top[1]["risk"] == 85  # floor of its critical finding
    ep = d["endpoints"]
    assert (ep["managed"], ep["healthy"], ep["failing"], ep["suspended"], ep["outdated"]) == (2, 1, 1, 1, 1)
    assert ep["latest_agent_version"] == "1.2.0"


def test_vulnerabilities_numbers(seeded):
    d = _get(seeded.acme, "vulnerabilities")
    k = d["kpis"]
    assert d["total"] == 3
    assert (k["critical"]["value"], k["critical"]["fix_available"], k["critical"]["no_fix"]) == (1, 1, 0)
    assert k["kev"]["value"] == 1 and k["kev"]["parts"]["critical"] == 1
    assert k["in_use"]["value"] == 1
    assert k["fix_available"]["value"] == 33.3 and k["fix_available"]["fixable"] == 1
    pts = d["over_time"]["points"]
    assert pts[0]["critical"] == 1 and pts[0]["high"] == 0  # CVE-3 was still open 30 days ago, CVE-1 not yet seen
    assert pts[-1]["critical"] == 1 and pts[-1]["high"] == 1
    wl = {w["key"]: w["total"] for w in d["workloads"]}
    assert wl == {"vms": 1, "pods": 1, "endpoints": 1}
    top = d["top_cves"]
    assert top[0]["cve_id"] == "CVE-1" and top[0]["kev"] and top[0]["runtime"] and top[0]["internet"]
    assert {c["cve_id"] for c in top} == {"CVE-1", "CVE-2", "CVE-4"}
    assert next(c for c in top if c["cve_id"] == "CVE-4")["endpoint"]


def test_exposure_identities_endpoints_numbers(seeded):
    a = seeded.acme
    e = _get(a, "exposure")
    assert e["kpis"]["exposed_assets"]["value"] == 2
    assert e["kpis"]["mgmt_ports"]["value"] == 1 and e["kpis"]["mgmt_ports"]["parts"][0]["key"] == "ssh"
    assert e["kpis"]["data_stores"]["value"] == 1
    assert {t["type"]: t["count"] for t in e["by_type"]} == {"vm": 1, "storage_account": 1}
    i = _get(a, "identities")
    assert i["kpis"]["identities"]["value"] == 2 and i["kpis"]["privileged"]["value"] == 1
    assert i["kpis"]["findings"]["value"] == 1 and i["kpis"]["findings"]["parts"]["high"] == 1
    assert next(r for r in i["identities"] if r["name"] == "id1")["privileged"]
    ep = _get(a, "endpoints")
    assert ep["kpis"]["managed"]["value"] == 2 and ep["kpis"]["suspended"]["value"] == 1
    assert ep["vulnerabilities"]["total"] == 1 and ep["vulnerabilities"]["by_severity"]["medium"] == 1
    assert any(x["code"] == "firewall_off" and x["devices"] == 1 for x in ep["issues"])


def test_range_changes_the_window(seeded):
    a = seeded.acme
    week = _get(a, "overview", range="7d")
    assert sum(p["new"] for p in week["issue_trend"]["points"]) == 2  # f1 (2 days), XYZ-001 (1 day)
    assert week["kpis"]["mttr"]["value"] == 40.0  # only AZ-VM-001 was resolved in the last 7 days
    ninety = _get(a, "overview", range="90d")
    assert sum(p["new"] for p in ninety["issue_trend"]["points"]) == 6


def test_account_filter(seeded):
    a = seeded.acme
    b = _get(a, "overview", account=SUB_B)
    assert b["account"] == SUB_B
    assert b["kpis"]["open_issues"]["value"] == 2 and b["kpis"]["exposed_assets"]["value"] == 0
    assert b["kpis"]["runtime_threats"]["value"] == 0
    assert {c["category"] for c in b["categories"]} == {"Kubernetes"}
    v = _get(a, "vulnerabilities", account=SUB_B)
    assert v["total"] == 1 and {c["cve_id"] for c in v["top_cves"]} == {"CVE-2"}  # device CVE-4 left out
    assert _get(a, "exposure", account=SUB_A)["kpis"]["exposed_assets"]["value"] == 2
    assert _get(a, "identities", account=SUB_B)["kpis"]["privileged"]["value"] == 0
    assert a.get("/api/dashboards", params={"account": SUB_B}).json()["tabs"]["vulnerabilities"] == 1
    # endpoints are not tied to a cloud account
    assert _get(a, "endpoints", account=SUB_B)["kpis"]["managed"]["value"] == 2
    # an unknown account is simply empty
    assert _get(a, "overview", account="nope")["kpis"]["open_issues"]["value"] == 0


def test_validation(seeded):
    a = seeded.acme
    assert a.get("/api/dashboards/overview", params={"range": "1y"}).status_code == 422
    assert a.get("/api/dashboards/overview", params={"account": "x" * 65}).status_code == 422
    assert a.get("/api/dashboards/nope").status_code == 404


def test_roles(client):
    make_user(client, "viewer")
    anon = TestClient(client.app, base_url=BASE_URL)
    assert anon.get("/api/dashboards/overview").status_code == 401
    assert anon.get("/api/dashboards").status_code == 401
    viewer = TestClient(client.app, base_url=BASE_URL)
    login(viewer, "viewer@example.com", "a-long-test-password")
    for tab in TABS:
        assert viewer.get(f"/api/dashboards/{tab}").status_code == 200, tab
    assert viewer.get("/api/dashboards").status_code == 200


def test_empty_organisation_degrades_gracefully(tenants):  # noqa: F811
    a = tenants.acme
    meta = a.get("/api/dashboards").json()
    assert meta["tabs"] == {"vulnerabilities": 0, "exposure": 0, "identities": 0, "endpoints": 0}
    assert meta["accounts"] == []
    o = _get(a, "overview")
    assert o["kpis"]["open_issues"]["value"] == 0 and o["kpis"]["mttr"]["value"] is None
    assert o["risk_score"]["value"] == 0 and o["top_assets"] == [] and o["categories"] == []
    assert o["compliance"] == []  # no assets: no framework applies
    v = _get(a, "vulnerabilities")
    assert v["total"] == 0 and v["kpis"]["fix_available"]["value"] is None and v["top_cves"] == []
    assert _get(a, "exposure")["paths"] == []
    assert _get(a, "identities")["identities"] == []
    assert _get(a, "endpoints")["managed"] == 0


# ----------------------------------------------------------------------------- isolation
def test_organisations_never_see_each_other(seeded):
    d, a = seeded.default, seeded.acme
    dm = d.get("/api/dashboards").json()
    am = a.get("/api/dashboards").json()
    assert {x["id"] for x in am["accounts"]} == {SUB_A, SUB_B}
    assert not {x["id"] for x in dm["accounts"]} & {SUB_A, SUB_B}
    assert dm["tabs"]["vulnerabilities"] > am["tabs"]["vulnerabilities"]
    # acme's numbers are exactly its own seeded data, whatever the default org holds
    assert _get(a, "overview")["kpis"]["open_issues"]["value"] == 5
    assert _get(d, "overview")["kpis"]["open_issues"]["value"] != 5
    # another org's account id behaves like an unknown account
    other = next(iter(dm["accounts"]))["id"]
    assert _get(a, "overview", account=other)["kpis"]["open_issues"]["value"] == 0
    assert _get(a, "vulnerabilities", account=other)["total"] == 0
    # snapshots: each organisation only reads and writes its own rows
    with db.get_session(seeded.acme_id) as s:
        acme_rows = s.scalar(select(func.count()).select_from(DashboardSnapshot))
    with db.get_session(unscoped=True) as s:
        orgs = {o for (o,) in s.execute(select(DashboardSnapshot.organization_id).distinct())}
    assert acme_rows >= 1 and orgs == {"default", seeded.acme_id}
    with db.get_session(seeded.acme_id) as s:
        assert {r.organization_id for r in s.scalars(select(DashboardSnapshot))} == {seeded.acme_id}


# ----------------------------------------------------------------------------- snapshots + deltas
def test_snapshot_is_written_lazily_once_per_day(seeded):
    a = seeded.acme
    _get(a, "overview")
    _get(a, "overview")
    _get(a, "overview", account=SUB_A)
    with db.get_session(seeded.acme_id) as s:
        rows = list(s.scalars(select(DashboardSnapshot)))
    assert sorted(r.account for r in rows) == ["", SUB_A]
    assert all(r.day == utcnow().date() for r in rows)
    whole = next(r for r in rows if r.account == "")
    assert whole.metrics["open_issues"] == 5 and whole.metrics["exposed_assets"] == 2
    assert whole.metrics["devices_managed"] == 2
    assert "devices_managed" not in next(r for r in rows if r.account == SUB_A).metrics


def test_snapshot_all_is_idempotent(seeded):
    day = utcnow().date()
    with db.get_session(seeded.acme_id) as s:
        assert svc.snapshot_all(s, day) == 3  # all accounts + sub-a + sub-b
        assert svc.snapshot_all(s, day) == 0
        assert svc.snapshot_all(s, day + timedelta(days=1)) == 3
        assert s.scalar(select(func.count()).select_from(DashboardSnapshot)) == 6


def test_snapshot_worker_writes_one_row_per_org_and_day(seeded):
    worker = DashboardSnapshotWorker()
    try:
        now = utcnow()
        first = worker.tick(now)
        assert first.leader and first.written[seeded.acme_id] == 3 and first.written.get("default", 0) >= 1
        assert worker.tick(now + timedelta(hours=1)).written == {}  # same day: nothing new
        nxt = worker.tick(now + timedelta(days=1))
        assert nxt.written[seeded.acme_id] == 3
    finally:
        worker.stop()
    with db.get_session(seeded.acme_id) as s:
        per_day = dict(s.execute(select(DashboardSnapshot.day, func.count()).where(DashboardSnapshot.account == "")
                                 .group_by(DashboardSnapshot.day)).all())
    assert sorted(per_day.values()) == [1, 1]


def _put_snapshot(org_id: str, day, metrics: dict, account: str = "") -> None:
    with db.get_session(org_id) as s:
        s.add(DashboardSnapshot(day=day, account=account, metrics=metrics))
        s.commit()


def test_deltas_against_the_snapshot_one_period_ago(seeded):
    a = seeded.acme
    today = utcnow().date()
    _put_snapshot(seeded.acme_id, today - timedelta(days=30),
                  {"open_issues": 3, "critical_high": 5, "exposed_assets": 2, "risk_score": 10.0,
                   "runtime_threats": 4, "compliance": {"CIS Azure": 50.0}})
    k = _get(a, "overview")["kpis"]
    assert k["open_issues"]["delta"] == 2  # 5 now vs 3
    assert k["critical_high"]["delta"] == -2
    assert k["exposed_assets"]["delta"] == 0
    assert k["runtime_threats"]["delta"] == -3
    assert k["attack_paths"]["delta"] is None  # key missing in that snapshot
    # a 7-day range compares with a week ago, where there is no snapshot
    assert _get(a, "overview", range="7d")["kpis"]["open_issues"]["delta"] is None
    # the account scope has its own snapshots
    assert _get(a, "overview", account=SUB_A)["kpis"]["open_issues"]["delta"] is None


def test_delta_tolerates_a_missed_day_but_never_uses_a_newer_snapshot(seeded):
    today = utcnow().date()
    w = svc.window("30d")
    with db.get_session(seeded.acme_id) as s:
        assert svc.baseline(s, w) is None
    _put_snapshot(seeded.acme_id, today - timedelta(days=29), {"open_issues": 1})  # too recent
    with db.get_session(seeded.acme_id) as s:
        assert svc.baseline(s, w) is None
    _put_snapshot(seeded.acme_id, today - timedelta(days=33), {"open_issues": 2})  # too old
    with db.get_session(seeded.acme_id) as s:
        assert svc.baseline(s, w) is None
    _put_snapshot(seeded.acme_id, today - timedelta(days=32), {"open_issues": 7})  # within tolerance
    with db.get_session(seeded.acme_id) as s:
        assert svc.baseline(s, w) == {"open_issues": 7}


def test_delta_helper():
    assert svc.delta(5, None, "x") is None
    assert svc.delta(None, {"x": 1}, "x") is None
    assert svc.delta(5, {}, "x") is None
    assert svc.delta(5, {"x": None}, "x") is None
    assert svc.delta(5, {"x": 7}, "x") == -2
    assert svc.delta(5.25, {"x": 5.0}, "x") == 0.2


def test_snapshot_trend_series(seeded):
    today = utcnow().date()
    _put_snapshot(seeded.acme_id, today - timedelta(days=3), {"exposed_assets": 1, "crown_jewel_paths": 0})
    e = _get(seeded.acme, "exposure", range="7d")
    pts = e["trend"]["points"]
    assert len(pts) == 7
    assert pts[-4]["exposed_assets"] == 1 and pts[-1]["exposed_assets"] == 2  # today's lazy snapshot
    assert pts[0]["exposed_assets"] is None  # no snapshot: a gap, not a zero
    assert e["history_since"] == str(today - timedelta(days=3))


def test_category_mapping():
    assert svc.service_code("AZ-STG-001") == "STG" and svc.service_code("AWS-S3-002") == "S3"
    assert svc.service_code("XYZ-001") is None
    assert svc.category_of("AZ-NSG-001", "nsg") == "Network"
    assert svc.category_of("AWS-IAM-003", None) == "Identity"
    assert svc.category_of("GCP-SQL-001", None) == "Databases"
    assert svc.category_of("AZ-KV-002", None) == "Secrets"
    assert svc.category_of("AWS-EKS-001", None) == "Kubernetes"
    assert svc.category_of("AWS-LMB-001", None) == "Compute"
    assert svc.category_of("XYZ-001", "s3_bucket") == "Storage"
    assert svc.category_of("AWS-CT-001", "cloudtrail_trail") == "Other"


def test_findings_list_filters_by_dashboard_category(seeded):
    a = seeded.acme
    kube = a.get("/api/findings", params={"category": "Kubernetes"}).json()
    assert sorted(f["rule_id"] for f in kube) == ["AZ-POD-001", "XYZ-001"]
    assert [f["rule_id"] for f in a.get("/api/findings", params={"category": "Identity"}).json()] == ["AZ-ID-001"]
    assert a.get("/api/findings", params={"category": "Other"}).json() == []
    assert a.get("/api/findings", params={"category": "Bogus"}).status_code == 422
    # the dashboard's category counts match the list behind them
    for c in _get(a, "overview")["categories"]:
        assert len(a.get("/api/findings", params={"category": c["category"]}).json()) == c["total"], c
