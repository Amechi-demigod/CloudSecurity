"""Whitelisted server-side sorting (?sort=&dir=) of the lists that are capped by a limit, so the order applies to
the whole result and not to the rows that happen to fit."""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.api.devices import DEVICE_SORT
from app.sorting import sort_rows
from tests.conftest import AUTH, login, reset_database  # noqa: F401
from tests.test_external import _seed_findings


def test_sort_rows_text_is_case_insensitive_numbers_numeric_and_missing_values_last():
    rows = [{"n": "b", "v": 10}, {"n": "A", "v": 9}, {"n": None, "v": None}, {"n": "c", "v": 100}]
    assert [r["n"] for r in sort_rows(rows, {"n": lambda r: r["n"]}, "n", "asc")] == ["A", "b", "c", None]
    assert [r["n"] for r in sort_rows(rows, {"n": lambda r: r["n"]}, "n", "desc")] == ["c", "b", "A", None]
    assert [r["v"] for r in sort_rows(rows, {"v": lambda r: r["v"]}, "v", "asc")] == [9, 10, 100, None]  # not "10" < "9"
    assert [r["v"] for r in sort_rows(rows, {"v": lambda r: r["v"]}, "v", "desc")] == [100, 10, 9, None]
    assert sort_rows(rows, {}, None) == rows
    with pytest.raises(HTTPException) as e:
        sort_rows(rows, {"n": lambda r: r["n"]}, "__import__('os')")
    assert e.value.status_code == 422


def test_device_sort_keys():
    mk = lambda h, health, issues, upd: {"hostname": h, "os_name": "Windows", "os_version": "11", "status": "active",  # noqa: E731
                                         "health": health, "issues": issues, "logged_in_users": [], "last_seen_at": None,
                                         "agent_version": "1", "usb_storage": None, "os_updates": upd}
    rows = [mk("b", "healthy", [], None), mk("A", "critical", [1, 2], {"security": 2, "missing": 3}),
            mk("c", "warning", [1], {"security": 0, "missing": 1})]
    assert [d["hostname"] for d in sort_rows(rows, DEVICE_SORT, "name")] == ["A", "b", "c"]
    assert [d["hostname"] for d in sort_rows(rows, DEVICE_SORT, "health", "desc")] == ["A", "c", "b"]
    assert [d["hostname"] for d in sort_rows(rows, DEVICE_SORT, "updates", "desc")] == ["A", "c", "b"]
    assert [d["hostname"] for d in sort_rows(rows, DEVICE_SORT, "issues")] == ["b", "c", "A"]


def test_findings_sort_applies_to_the_whole_result_before_the_limit(client):
    allf = client.get("/api/findings", params={"status": "all", "limit": 5000}).json()
    assert len(allf) > 5
    titles = sorted((f["title"] for f in allf), key=str.casefold)
    r = client.get("/api/findings", params={"status": "all", "sort": "title", "dir": "asc", "limit": 5})
    assert [f["title"] for f in r.json()] == titles[:5]
    r = client.get("/api/findings", params={"status": "all", "sort": "title", "dir": "desc", "limit": 5})
    assert [f["title"] for f in r.json()] == titles[::-1][:5]
    rank = ["info", "low", "medium", "high", "critical"].index
    r = client.get("/api/findings", params={"status": "all", "sort": "severity", "dir": "desc", "limit": 3})
    top = [rank(f["severity"]) for f in r.json()]
    assert top[0] == max(rank(f["severity"]) for f in allf) and top == sorted(top, reverse=True)
    assert client.get("/api/findings", params={"sort": "title; DROP TABLE findings"}).status_code == 422
    assert client.get("/api/findings", params={"sort": "title", "dir": "sideways"}).status_code == 422


def test_vulnerabilities_sort_keys_and_direction(client):
    base = client.get("/api/vulnerabilities", params={"status": "all", "limit": 5000}).json()
    if not base:
        pytest.skip("no vulnerabilities in the simulated environment")
    for key, field in (("cve", "cve_id"), ("software", "package"), ("cvss", "cvss")):
        for d in ("asc", "desc"):
            r = client.get("/api/vulnerabilities", params={"status": "all", "sort": key, "dir": d, "limit": 5000})
            assert r.status_code == 200, r.text
            vals = [v[field] for v in r.json() if v[field] is not None]
            norm = [v.casefold() if isinstance(v, str) else v for v in vals]
            assert norm == sorted(norm, reverse=d == "desc"), (key, d)
    assert client.get("/api/vulnerabilities", params={"sort": "id; --"}).status_code == 422
    assert client.get("/api/vulnerabilities/by-cve", params={"sort": "cvss", "dir": "desc"}).status_code == 200
    assert client.get("/api/vulnerabilities/by-software", params={"sort": "cves", "dir": "desc"}).status_code == 200
    assert client.get("/api/vulnerabilities/by-software", params={"sort": "nope"}).status_code == 422


def test_audit_log_sort_is_a_whitelist_over_the_whole_log(client):
    for i in range(3):
        client.post("/api/auth/logout")
        login(client)
    rows = client.get("/api/audit-log", params={"limit": 2000}).json()
    assert len(rows) >= 3
    r = client.get("/api/audit-log", params={"sort": "action", "dir": "asc", "limit": 2000}).json()
    acts = [a["action"].casefold() for a in r]
    assert acts == sorted(acts)
    r = client.get("/api/audit-log", params={"sort": "time", "dir": "asc", "limit": 2000}).json()
    assert [a["id"] for a in r] == sorted(a["id"] for a in rows)
    assert client.get("/api/audit-log", params={"sort": "id;drop table audit_log"}).status_code == 422
    assert client.get("/api/audit-log").json()[0]["id"] == max(a["id"] for a in rows)  # default: newest first


def test_external_findings_sort(client):
    _seed_findings()
    asc = client.get("/api/external/findings", params={"sort": "cvss", "dir": "asc"}).json()
    assert [f["cvss"] for f in asc] == sorted(f["cvss"] for f in asc)
    top = client.get("/api/external/findings", params={"sort": "severity", "dir": "desc"}).json()
    assert top[0]["severity"] == "medium" and top[-1]["severity"] == "low"
    by_title = client.get("/api/external/findings", params={"sort": "title", "dir": "desc"}).json()
    assert [f["title"] for f in by_title] == sorted((f["title"] for f in by_title), reverse=True)
    assert client.get("/api/external/findings", params={"sort": "x"}).status_code == 422
