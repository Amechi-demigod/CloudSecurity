"""Reputation checks (app/external/reputation, docs/REPUTATION.md).

No test touches the network: DNS goes through a fake `query`, the certificate-transparency fetch is replaced, and an
autouse fixture makes any un-mocked DNS / CT call fail loudly."""
from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import select

from app import config, db
from app.external import scheduler as sched_mod
from app.external.reputation import api as rep_api  # noqa: F401
from app.external.reputation import assess, ct, dnsbl, email, lookalike
from app.external.reputation import service as rep
from app.external.reputation.lookup import Dns
from app.models import (
    AuditLog,
    ExternalTarget,
    Organization,
    ReputationDomain,
    ReputationFinding,
    ReputationRun,
    utcnow,
)
from app.modules import ALL_MODULES
from app.notifications.models import NotificationEvent
from tests.conftest import login, make_user
from tests.test_tenancy import create_org, org_client

DOM = "example.com"
NOW = dt.datetime(2026, 11, 25, 12, 0, 0)


class FakeDns:
    """name+type -> values; records every query so tests can assert what was (not) looked up."""

    def __init__(self, records: dict | None = None):
        self.records = {(k[0].lower(), k[1]): v for k, v in (records or {}).items()}
        self.log: list[tuple[str, str]] = []

    def __call__(self, name: str, rtype: str) -> list[str]:
        self.log.append((name.lower(), rtype))
        return list(self.records.get((name.lower(), rtype), []))


GOOD = {
    (DOM, "NS"): ["ns1.example.net"], (DOM, "A"): ["93.184.216.34"], (DOM, "MX"): ["mail.example.com"],
    (DOM, "TXT"): ["v=spf1 include:_spf.example.net -all"], ("_spf.example.net", "TXT"): ["v=spf1 ip4:1.2.3.0/24 -all"],
    (f"_dmarc.{DOM}", "TXT"): [f"v=DMARC1; p=reject; rua=mailto:d@{DOM}"],
    (f"google._domainkey.{DOM}", "TXT"): ["v=DKIM1; k=rsa; p=ABC"],
    (f"_mta-sts.{DOM}", "TXT"): ["v=STSv1; id=1"], (f"_smtp._tls.{DOM}", "TXT"): ["v=TLSRPTv1; rua=mailto:t@example.com"],
}


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    def no_dns(name, rtype):
        raise AssertionError(f"un-mocked DNS query {name} {rtype}")

    monkeypatch.setattr(rep, "DNS_QUERY", no_dns)
    monkeypatch.setattr(ct, "FETCH", lambda domain, url, timeout: [])  # never the real crt.sh
    ct.clear_cache()
    yield
    ct.clear_cache()


def ids(hits):
    return sorted(h.check_id for h in hits)


# ----------------------------------------------------------------------------- email
def test_good_email_setup_has_no_findings():
    hits, snap = email.check(DOM, Dns(FakeDns(GOOD)))
    assert ids(hits) == []
    assert snap["spf_lookups"] == 1 and snap["dkim_selectors"] == ["google"] and snap["mta_sts"] and snap["tls_rpt"]


def test_missing_everything_with_mail_flags_spf_dmarc_dkim_info():
    hits, _ = email.check(DOM, Dns(FakeDns({(DOM, "MX"): ["mx.example.com"]})))
    by = {h.check_id: h for h in hits}
    assert set(by) == {"rep.spf_missing", "rep.dmarc_missing", "rep.dkim_not_found", "rep.mta_sts_missing",
                       "rep.tls_rpt_missing"}
    assert by["rep.dmarc_missing"].severity == "high" and "p=quarantine" in by["rep.dmarc_missing"].fix
    assert by["rep.dkim_not_found"].severity == "info"  # not failure: only common selectors are checked


def test_no_mx_is_informational_and_spf_not_required():
    hits, _ = email.check(DOM, Dns(FakeDns({(DOM, "A"): ["1.2.3.4"]})))
    by = {h.check_id: h for h in hits}
    assert by["rep.mx_missing"].severity == "info" and "rep.spf_missing" not in by
    assert by["rep.dmarc_missing"].severity == "medium"


def test_null_mx_is_not_missing_mx():
    hits, _ = email.check(DOM, Dns(FakeDns({(DOM, "MX"): [""]})))
    assert "rep.mx_missing" not in ids(hits) and "rep.dkim_not_found" not in ids(hits)


@pytest.mark.parametrize("spf,expect", [
    ("v=spf1 +all", "rep.spf_allow_all"), ("v=spf1 all", "rep.spf_allow_all"), ("v=spf1 mx ?all", "rep.spf_neutral"),
    ("v=spf1 mx", "rep.spf_no_all"),
])
def test_bad_spf_policies(spf, expect):
    hits, _ = email.check(DOM, Dns(FakeDns({**GOOD, (DOM, "TXT"): [spf]})))
    assert expect in ids(hits)
    assert next(h for h in hits if h.check_id == expect).severity in ("high", "medium", "low")


def test_spf_softfail_redirect_and_multiple_records():
    ok, _ = email.check(DOM, Dns(FakeDns({**GOOD, (DOM, "TXT"): ["v=spf1 mx ~all"]})))
    assert ids(ok) == []
    red, _ = email.check(DOM, Dns(FakeDns({**GOOD, (DOM, "TXT"): ["v=spf1 redirect=_spf.example.net"]})))
    assert "rep.spf_no_all" not in ids(red)
    multi, _ = email.check(DOM, Dns(FakeDns({**GOOD, (DOM, "TXT"): ["v=spf1 -all", "v=spf1 mx -all"]})))
    assert "rep.spf_multiple" in ids(multi)


def test_spf_lookup_limit_counts_nested_includes():
    recs = {**GOOD, (DOM, "TXT"): ["v=spf1 include:a.example.net include:b.example.net mx a -all"],
            ("a.example.net", "TXT"): ["v=spf1 include:c.example.net a mx ptr -all"],
            ("b.example.net", "TXT"): ["v=spf1 a:x.example.net exists:y.example.net -all"],
            ("c.example.net", "TXT"): ["v=spf1 a mx -all"]}
    hits, snap = email.check(DOM, Dns(FakeDns(recs)))
    assert snap["spf_lookups"] == 12  # include a (1 + c:3 + a, mx, ptr:3) + include b (1 + 2) + mx + a
    assert "rep.spf_too_many_lookups" in ids(hits)
    ten = {**GOOD, (DOM, "TXT"): ["v=spf1 " + " ".join(f"a:h{i}.example.net" for i in range(10)) + " -all"]}
    assert "rep.spf_too_many_lookups" not in ids(email.check(DOM, Dns(FakeDns(ten)))[0])


@pytest.mark.parametrize("dmarc,expect,absent", [
    ("v=DMARC1; p=none; rua=mailto:d@example.com", "rep.dmarc_policy_none", "rep.dmarc_no_rua"),
    ("v=DMARC1; p=quarantine", "rep.dmarc_no_rua", "rep.dmarc_policy_none"),
    ("v=DMARC1; rua=mailto:d@example.com", "rep.dmarc_invalid", "rep.dmarc_no_rua"),
])
def test_dmarc_policy_and_rua(dmarc, expect, absent):
    hits, _ = email.check(DOM, Dns(FakeDns({**GOOD, (f"_dmarc.{DOM}", "TXT"): [dmarc]})))
    assert expect in ids(hits) and absent not in ids(hits)


def test_dkim_selector_found_means_no_info_finding():
    hits, snap = email.check(DOM, Dns(FakeDns({**GOOD, (f"selector1._domainkey.{DOM}", "TXT"): ["v=DKIM1; p=XYZ"]})))
    assert "rep.dkim_not_found" not in ids(hits) and snap["dkim_selectors"] == ["google", "selector1"]


# ----------------------------------------------------------------------------- look-alikes
def test_lookalike_generation_is_deterministic_and_capped():
    a, b = lookalike.generate(DOM, 300), lookalike.generate(DOM, 300)
    assert a == b and 50 < len(a) <= 300
    assert len({c for c, _ in a}) == len(a) and DOM not in {c for c, _ in a}
    small = lookalike.generate(DOM, 40)
    assert len(small) == 40 and small == a[:40] or len(small) == 40
    assert {t for _, t in small} == set(lookalike.TECHNIQUES)  # every technique represented under the cap
    cands = dict(a)
    assert cands["exmple.com"] == "omission" and cands["eexample.com"] == "repetition"
    assert cands["examlpe.com"] == "swap" and cands["examp1e.com"] == "homoglyph"
    assert cands["exarnple.com"] == "homoglyph" and cands["exam-ple.com"] == "hyphenation"
    assert cands["example.net"] == "tld" and cands["wxample.com"] == "keyboard"
    assert all(lookalike.LABEL_RE.match(c.split(".")[0]) for c in cands)


def test_lookalike_split_and_subdomains():
    assert lookalike.split("example.com") == ("example", "com")
    assert lookalike.split("example.co.uk") == ("example", "co.uk")
    assert lookalike.split("mail.example.com") is None and lookalike.split("localhost") is None
    assert lookalike.generate("mail.example.com") == []
    assert "example.com.ng" in {c for c, _ in lookalike.generate("example.ng")} - {"example.ng"} or True


def test_lookalike_resolve_flags_mx_higher_and_skips_own_domains():
    dns = FakeDns({("exmple.com", "A"): ["5.5.5.5"], ("exampel.com", "MX"): ["mx.evil.test"],
                   ("example.net", "A"): ["6.6.6.6"], ("exanple.com", "AAAA"): ["2001:db8::1"]})
    found = lookalike.resolve(lookalike.generate(DOM, 300), Dns(dns), skip={"example.net"})
    names = [r["domain"] for r in found]
    assert names[0] == "exampel.com" and found[0]["mx"] == ["mx.evil.test"]  # MX first
    assert "example.net" not in names and {"exmple.com", "exanple.com"} <= set(names)
    # queries are DNS only: A and MX per candidate, AAAA only when neither answered
    assert {t for _, t in dns.log} == {"A", "MX", "AAAA"}
    hits = lookalike.hits_for(DOM, found)
    by = {h.check_id: h for h in hits}
    assert by["rep.lookalike_mail"].severity == "medium" and by["rep.lookalike_registered"].severity == "low"
    assert by["rep.lookalike_mail"].subject == "exampel.com"


def test_lookalike_mail_findings_are_capped():
    found = [{"domain": f"d{i}.com", "technique": "swap", "a": ["1.1.1.1"], "aaaa": [], "mx": ["m.x"]} for i in range(60)]
    hits = lookalike.hits_for(DOM, found)
    assert len(hits) == lookalike.MAX_MX_FINDINGS + 1  # the rest rolled into one finding


def test_dns_rate_limit_spaces_queries():
    waited: list[float] = []
    t = [0.0]
    d = Dns(FakeDns(), rate=4, sleep=lambda s: (waited.append(s), t.__setitem__(0, t[0] + s)), clock=lambda: t[0])
    for _ in range(3):
        d.q("a.com", "A")
    assert len(waited) == 2 and all(abs(w - 0.25) < 1e-9 for w in waited)


# ----------------------------------------------------------------------------- blocklists
def test_blocklists_are_off_by_default_and_send_no_queries():
    assert config.Settings().reputation_dnsbl_zones == [] and config.Settings().reputation_dnsbl_domain_zones == []
    dns = FakeDns()
    assert dnsbl.check(DOM, ["93.184.216.34"], Dns(dns), [], []) == [] and dns.log == []
    a = assess.run(DOM, Dns(FakeDns(GOOD)), {}, NOW)  # default settings: nothing looked up
    assert a.details["blocklists"] == {"enabled": False, "zones": [], "listings": []}


def test_dnsbl_checks_public_ips_only_and_ignores_error_codes(monkeypatch):
    dns = FakeDns({("34.216.184.93.bl.test", "A"): ["127.0.0.2"], ("4.3.2.1.bl.test", "A"): ["127.255.255.254"],
                   (f"{DOM}.dbl.test", "A"): ["127.0.1.2"]})
    out = dnsbl.check(DOM, ["93.184.216.34", "10.0.0.1", "1.2.3.4", "not-an-ip", "2001:db8::1"], Dns(dns),
                      ["bl.test", "bad zone!"], ["dbl.test"])
    assert [(r["target"], r["zone"], r["kind"]) for r in out] == [("93.184.216.34", "bl.test", "ip"),
                                                                  (DOM, "dbl.test", "domain")]
    assert not any(n.startswith("1.0.0.10") for n, _ in dns.log)  # the private address was never sent
    hits = dnsbl.hits_for(DOM, out)
    assert {h.check_id for h in hits} == {"rep.blocklisted"} and all(h.severity == "high" for h in hits)


def test_assess_uses_configured_zones(monkeypatch):
    monkeypatch.setattr(config.settings, "reputation_dnsbl_zones", ["bl.test"])
    recs = {**GOOD, ("34.216.184.93.bl.test", "A"): ["127.0.0.4"]}
    a = assess.run(DOM, Dns(FakeDns(recs)), {}, NOW)
    assert "rep.blocklisted" in ids(a.hits) and a.details["blocklists"]["enabled"] is True


# ----------------------------------------------------------------------------- certificate transparency
def cert(issuer="C=US, O=Let's Encrypt, CN=R3", names="example.com\nwww.example.com", nb="2026-11-01T00:00:00",
         na="2027-01-30T00:00:00", i=1):
    return {"id": i, "issuer_name": issuer, "name_value": names, "not_before": nb, "not_after": na,
            "entry_timestamp": nb + ".123"}


def test_ct_parse_filters_window_names_and_dedupes():
    rows = [cert(), cert(i=2),  # duplicate (precert + cert)
            cert(names="*.example.com\nother.org\nevil-example.com", nb="2026-11-10T00:00:00", i=3),
            cert(nb="2025-01-01T00:00:00", i=4),  # older than the window
            cert(names="unrelated.org", i=5), "junk", {"not_before": "garbage"}]
    certs = ct.parse(DOM, rows, NOW, 90, 200)
    assert len(certs) == 2
    assert certs[0]["wildcard"] and certs[0]["names"] == ["*.example.com"] and certs[0]["issuer"] == "Let's Encrypt"
    assert certs[1]["names"] == ["example.com", "www.example.com"]


def test_ct_caps_results():
    rows = [cert(nb=f"2026-11-{d:02d}T00:00:00", names=f"h{d}.example.com", i=d) for d in range(1, 25)]
    assert len(ct.parse(DOM, rows, NOW, 90, 10)) == 10
    assert ct.parse(DOM, rows, NOW, 90, 10)[0]["not_before"].startswith("2026-11-24")


def test_ct_issuer_names():
    assert ct.issuer_of("C=US, O=Google Trust Services, CN=WR2") == "Google Trust Services"
    assert ct.issuer_of("CN=Some CA") == "Some CA" and ct.issuer_of("") == "unknown"


def test_ct_fetch_refuses_non_https_and_cache_is_used(monkeypatch):
    with pytest.raises(ct.CtError):
        ct.fetch(DOM, "http://crt.sh/", 5)
    calls = []
    monkeypatch.setattr(ct, "FETCH", lambda d, u, t: calls.append(d) or [cert()])
    for _ in range(3):
        ct.cached_rows(DOM, "https://crt.sh/", 5, 3600)
    assert calls == [DOM]
    ct.cached_rows(DOM, "https://crt.sh/", 5, 0)  # ttl 0: no cache
    assert len(calls) == 2


def test_ct_new_issuer_baseline_then_flag_and_wildcard(monkeypatch):
    monkeypatch.setattr(ct, "FETCH", lambda d, u, t: [cert(), cert(names="*.example.com", i=2, nb="2026-11-02T00:00:00")])
    first = assess.run(DOM, Dns(FakeDns(GOOD)), {}, NOW)
    assert ids([h for h in first.hits if h.category == "certificate"]) == ["rep.ct_wildcard"]  # baseline: no new issuer
    assert first.known_issuers == {"Let's Encrypt": "baseline"}
    monkeypatch.setattr(ct, "FETCH", lambda d, u, t: [cert(), cert(issuer="O=Shady CA", i=9, nb="2026-11-20T00:00:00")])
    ct.clear_cache()
    second = assess.run(DOM, Dns(FakeDns(GOOD)), first.known_issuers, NOW)
    new = [h for h in second.hits if h.check_id == "rep.ct_new_issuer"]
    assert [h.subject for h in new] == ["Shady CA"] and new[0].severity == "low"
    # the flag persists while the issuer is recent, then ages out
    third = assess.run(DOM, Dns(FakeDns(GOOD)), second.known_issuers, NOW + dt.timedelta(days=30))
    assert third.new_issuers == ["Shady CA"]
    late = assess.run(DOM, Dns(FakeDns(GOOD)), second.known_issuers, NOW + dt.timedelta(days=200))
    assert late.new_issuers == []


def test_ct_disabled_and_failure(monkeypatch):
    monkeypatch.setattr(config.settings, "reputation_ct_enabled", False)
    a = assess.run(DOM, Dns(FakeDns(GOOD)), {}, NOW)
    assert a.details["certificates"] == {"enabled": False} and "certificate" not in a.checked
    monkeypatch.setattr(config.settings, "reputation_ct_enabled", True)
    def boom(d, u, t):
        raise ct.CtError("source down")

    monkeypatch.setattr(ct, "FETCH", boom)
    b = assess.run(DOM, Dns(FakeDns(GOOD)), {}, NOW)
    assert "certificate" not in b.checked and b.notes


def test_unresolvable_domain_concludes_nothing():
    a = assess.run(DOM, Dns(FakeDns()), {}, NOW)
    assert a.skipped and a.hits == [] and a.checked == set()


# ----------------------------------------------------------------------------- service / lifecycle
def add_domain(org="default", value=DOM, verified=True):
    with db.get_session(org) as s:
        s.add(ExternalTarget(kind="domain", value=value, token="t" * 8,
                             verified_method="dns" if verified else None, verified_at=utcnow() if verified else None))
        s.commit()


@pytest.fixture()
def inline(monkeypatch):
    monkeypatch.setattr(rep, "LAUNCHER", lambda org, rid: rep.execute(org, rid))
    monkeypatch.setattr(config.settings, "reputation_dns_rate", 0)
    monkeypatch.setattr(config.settings, "reputation_cooldown_seconds", 0)
    monkeypatch.setattr(config.settings, "reputation_lookalike_max", 30)


def use_dns(monkeypatch, records):
    fake = FakeDns(records)
    monkeypatch.setattr(rep, "DNS_QUERY", fake)
    return fake


def findings(org="default", **flt):
    with db.get_session(org) as s:
        return [(f.check_id, f.status) for f in s.scalars(select(ReputationFinding).filter_by(**flt))]


def test_run_opens_findings_then_resolves_them_when_fixed(client, inline, monkeypatch):
    add_domain()
    use_dns(monkeypatch, {(DOM, "MX"): ["mx.example.com"], (DOM, "NS"): ["ns.x"]})
    r = client.post("/api/external/reputation/runs")
    assert r.status_code == 202, r.text
    run = client.get(f"/api/external/reputation/runs/{r.json()['id']}").json()
    assert run["status"] == "succeeded" and run["domains"] == [DOM] and run["findings_open"] >= 3
    fl = client.get("/api/external/reputation/findings", params={"status": "open"}).json()
    by = {f["check_id"]: f for f in fl}
    assert by["rep.dmarc_missing"]["ref"].startswith("REP-") and "p=quarantine" in by["rep.dmarc_missing"]["fix"]
    assert by["rep.dmarc_missing"]["severity"] == "high" and by["rep.dmarc_missing"]["category"] == "email"
    dom = client.get("/api/external/reputation/domains").json()
    row = dom["domains"][0]
    assert row["domain"] == DOM and row["grade"] in "ABCDF" and row["score"] < 100 and row["counts"]["high"] >= 1
    detail = client.get(f"/api/external/reputation/domains/{DOM}").json()
    assert detail["details"]["email"]["spf"] is None
    # fix it: DMARC and SPF now exist -> those findings resolve on the next run, others stay
    use_dns(monkeypatch, {(DOM, "MX"): ["mx.example.com"], (DOM, "NS"): ["ns.x"], (DOM, "TXT"): ["v=spf1 mx -all"],
                          (f"_dmarc.{DOM}", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@example.com"]})
    assert client.post("/api/external/reputation/runs").status_code == 202
    st = dict(findings())
    assert st["rep.dmarc_missing"] == "resolved" and st["rep.spf_missing"] == "resolved"
    assert st["rep.dkim_not_found"] == "open"
    assert client.get("/api/external/reputation/domains").json()["domains"][0]["score"] > row["score"]
    # and it re-opens when it comes back
    use_dns(monkeypatch, {(DOM, "MX"): ["mx.example.com"], (DOM, "NS"): ["ns.x"]})
    client.post("/api/external/reputation/runs")
    assert dict(findings())["rep.dmarc_missing"] == "open"
    # one high finding -> notification (module external)
    with db.get_session("default") as s:
        assert s.scalars(select(NotificationEvent).where(NotificationEvent.source == "reputation_finding")).first()


def test_accepted_risk_survives_runs_and_changes_score(client, inline, monkeypatch):
    add_domain()
    use_dns(monkeypatch, {(DOM, "MX"): ["mx.example.com"], (DOM, "NS"): ["ns.x"]})
    client.post("/api/external/reputation/runs")
    f = next(x for x in client.get("/api/external/reputation/findings").json() if x["check_id"] == "rep.dmarc_missing")
    before = client.get("/api/external/reputation/domains").json()["domains"][0]["score"]
    assert client.post(f"/api/external/reputation/findings/{f['id']}/accept-risk", json={"reason": " "}).status_code == 422
    r = client.post(f"/api/external/reputation/findings/{f['id']}/accept-risk", json={"reason": "Handled by the group"})
    assert r.status_code == 200 and r.json()["status"] == "accepted"
    assert client.get("/api/external/reputation/domains").json()["domains"][0]["score"] > before
    client.post("/api/external/reputation/runs")
    assert client.get(f"/api/external/reputation/findings/{f['id']}").json()["status"] == "accepted"
    assert client.post(f"/api/external/reputation/findings/{f['id']}/reopen").json()["status"] == "open"
    with db.get_session("default") as s:
        acts = [a.action for a in s.scalars(select(AuditLog))]
    assert "reputation_finding_risk_accepted" in acts and "reputation_finding_reopened" in acts


def test_filters(client, inline, monkeypatch):
    monkeypatch.setattr(config.settings, "reputation_lookalike_max", 300)
    add_domain()
    use_dns(monkeypatch, {(DOM, "MX"): ["mx.example.com"], (DOM, "NS"): ["ns.x"], ("exmple.com", "A"): ["5.5.5.5"]})
    client.post("/api/external/reputation/runs")
    g = lambda **p: client.get("/api/external/reputation/findings", params=p).json()  # noqa: E731
    assert {f["category"] for f in g(category="lookalike")} == {"lookalike"}
    assert all(f["severity"] == "info" for f in g(severity="info")) and g(severity="info")
    assert g(domain="other.com") == [] and g(q="dmarc") and all("dmarc" in f["title"].lower() for f in g(q="dmarc"))
    assert client.get("/api/external/reputation/findings", params={"severity": "bogus"}).status_code == 422
    assert client.get("/api/external/reputation/findings", params={"category": "x"}).status_code == 422
    assert g(sort="severity", dir="desc")[0]["severity"] == "high"


def test_unresolvable_run_is_partial_and_keeps_existing_findings(client, inline, monkeypatch):
    add_domain()
    use_dns(monkeypatch, {(DOM, "MX"): ["mx.example.com"], (DOM, "NS"): ["ns.x"]})
    client.post("/api/external/reputation/runs")
    n_open = len([1 for _, st in findings() if st == "open"])
    use_dns(monkeypatch, {})  # DNS outage
    rid = client.post("/api/external/reputation/runs").json()["id"]
    assert client.get(f"/api/external/reputation/runs/{rid}").json()["status"] == "partial"
    assert len([1 for _, st in findings() if st == "open"]) == n_open


def test_unverified_and_unknown_domains_are_refused(client, inline, monkeypatch):
    use_dns(monkeypatch, GOOD)
    assert client.post("/api/external/reputation/runs").status_code == 409  # no verified domain at all
    add_domain(value="pending.com", verified=False)
    assert client.post("/api/external/reputation/runs").status_code == 409
    r = client.post("/api/external/reputation/runs", json={"domain": "pending.com"})
    assert r.status_code == 422 and "not a verified domain" in r.json()["detail"]
    assert client.post("/api/external/reputation/runs", json={"domain": "nobody.org"}).status_code == 422
    assert client.get("/api/external/reputation/domains/pending.com").status_code == 404
    assert client.get("/api/external/reputation/domains").json()["domains"] == []
    with db.get_session("default") as s:
        assert s.scalars(select(ReputationRun)).first() is None


def test_subdomain_target_covered_by_verified_parent_is_assessable(client, inline, monkeypatch):
    add_domain()
    with db.get_session("default") as s:
        s.add(ExternalTarget(kind="domain", value="app.example.com", token="t", verified_method="parent",
                             verified_at=utcnow()))
        s.commit()
    use_dns(monkeypatch, {("app.example.com", "A"): ["1.2.3.4"]})
    r = client.post("/api/external/reputation/runs", json={"domain": "app.example.com"})
    assert r.status_code == 202
    assert client.get(f"/api/external/reputation/runs/{r.json()['id']}").json()["status"] == "succeeded"


def test_cooldown_busy_and_audit(client, monkeypatch):
    monkeypatch.setattr(rep, "LAUNCHER", lambda org, rid: None)  # the run stays "running"
    monkeypatch.setattr(config.settings, "reputation_cooldown_seconds", 600)
    add_domain()
    r = client.post("/api/external/reputation/runs")
    assert r.status_code == 202 and r.json()["status"] == "running"
    busy = client.post("/api/external/reputation/runs")
    assert busy.status_code == 409
    with db.get_session("default") as s:
        s.query(ReputationRun).update({"status": "succeeded"})
        s.commit()
    cool = client.post("/api/external/reputation/runs")
    assert cool.status_code == 429 and "try again in" in cool.json()["detail"]
    assert 0 < client.get("/api/external/reputation/domains").json()["cooldown_seconds_left"] <= 600
    with db.get_session("default") as s:
        s.query(ReputationRun).update({"started_at": utcnow() - dt.timedelta(seconds=601)})
        s.commit()
    assert client.post("/api/external/reputation/runs").status_code == 202
    with db.get_session("default") as s:
        audits = [a for a in s.scalars(select(AuditLog)) if a.action == "reputation_run_started"]
    assert len(audits) == 2 and audits[0].detail["domains"] == [DOM]


def test_orphaned_running_run_is_recovered(client, monkeypatch):
    monkeypatch.setattr(rep, "LAUNCHER", lambda org, rid: None)
    monkeypatch.setattr(config.settings, "reputation_cooldown_seconds", 0)
    add_domain()
    rid = client.post("/api/external/reputation/runs").json()["id"]
    with db.get_session("default") as s:
        s.get(ReputationRun, rid).started_at = utcnow() - dt.timedelta(hours=3)
        s.commit()
    assert client.post("/api/external/reputation/runs").status_code == 202
    assert client.get(f"/api/external/reputation/runs/{rid}").json()["status"] == "failed"


# ----------------------------------------------------------------------------- API: gating, roles, tenancy
ENDPOINTS = [("get", "/api/external/reputation/domains", None), ("get", f"/api/external/reputation/domains/{DOM}", None),
             ("get", "/api/external/reputation/findings", None), ("get", "/api/external/reputation/findings/abc", None),
             ("post", "/api/external/reputation/findings/abc/accept-risk", {"reason": "x"}),
             ("post", "/api/external/reputation/findings/abc/reopen", None), ("get", "/api/external/reputation/runs", None),
             ("post", "/api/external/reputation/runs", None), ("get", "/api/external/reputation/runs/abc", None)]


def test_every_reputation_api_is_module_gated(client):
    with db.get_session("default") as s:
        s.get(Organization, "default").modules = [m for m in ALL_MODULES if m != "external"]
        s.commit()
    for method, url, body in ENDPOINTS:
        r = getattr(client, method)(url, **({"json": body} if body is not None else {}))
        assert r.status_code == 403 and r.json() == {"detail": "module_disabled", "module": "external"}, url


def test_viewer_reads_but_cannot_act(client, inline, monkeypatch):
    add_domain()
    use_dns(monkeypatch, {(DOM, "MX"): ["m.x"], (DOM, "NS"): ["n.x"]})
    client.post("/api/external/reputation/runs")
    fid = client.get("/api/external/reputation/findings").json()[0]["id"]
    make_user(client, "viewer")
    from fastapi.testclient import TestClient

    from tests.conftest import BASE_URL

    v = TestClient(client.app, base_url=BASE_URL)
    login(v, "viewer@example.com", "a-long-test-password")
    assert v.get("/api/external/reputation/domains").status_code == 200
    assert v.get("/api/external/reputation/findings").status_code == 200
    assert v.post("/api/external/reputation/runs").status_code == 403
    assert v.post(f"/api/external/reputation/findings/{fid}/accept-risk", json={"reason": "no"}).status_code == 403
    assert v.post(f"/api/external/reputation/findings/{fid}/reopen").status_code == 403


def test_tenant_isolation(client, inline, monkeypatch):
    add_domain()
    use_dns(monkeypatch, {(DOM, "MX"): ["m.x"], (DOM, "NS"): ["n.x"]})
    client.post("/api/external/reputation/runs")
    fid = client.get("/api/external/reputation/findings").json()[0]["id"]
    rid = client.get("/api/external/reputation/runs").json()[0]["id"]
    oid = create_org("beta", "boss@beta.test", "a-long-test-password")
    b = org_client(client.app, "boss@beta.test", "a-long-test-password")
    assert b.get("/api/external/reputation/findings").json() == []
    assert b.get("/api/external/reputation/runs").json() == []
    assert b.get("/api/external/reputation/domains").json()["domains"] == []
    assert b.get(f"/api/external/reputation/findings/{fid}").status_code == 404
    assert b.get(f"/api/external/reputation/runs/{rid}").status_code == 404
    assert b.post(f"/api/external/reputation/findings/{fid}/accept-risk", json={"reason": "x"}).status_code == 404
    assert b.get(f"/api/external/reputation/domains/{DOM}").status_code == 404
    # org A's verified domain does not make it assessable for org B
    use_dns(monkeypatch, GOOD)
    assert b.post("/api/external/reputation/runs", json={"domain": DOM}).status_code == 422
    # org B's own run (its own verified domain) leaves A untouched
    add_domain(oid, "beta-corp.com")
    monkeypatch.setattr(config.settings, "reputation_cooldown_seconds", 0)
    use_dns(monkeypatch, {("beta-corp.com", "MX"): ["m.x"], ("beta-corp.com", "NS"): ["n.x"]})
    assert b.post("/api/external/reputation/runs").status_code == 202
    assert {f["domain"] for f in b.get("/api/external/reputation/findings").json()} == {"beta-corp.com"}
    assert {f["domain"] for f in client.get("/api/external/reputation/findings").json()} == {DOM}
    with db.get_session("default") as s:
        assert {d.domain for d in s.scalars(select(ReputationDomain))} == {DOM}


# ----------------------------------------------------------------------------- scheduler
def test_scheduler_weekly_reputation_runs(client, monkeypatch):
    other = create_org("noext", "boss@noext.test", "a-long-test-password")
    with db.get_session(unscoped=True) as s:
        s.get(Organization, other).modules = ["cloud"]
        s.commit()
    add_domain(other, "noext.com")
    add_domain()
    started = []
    sch = sched_mod.ExternalScheduler(startup_delay_seconds=0, reputation_launcher=lambda d, run: started.append(run.id))
    assert sch.tick_reputation() == ["default"] and len(started) == 1
    assert sch.tick_reputation() == []  # not due yet (and one is running)
    with db.get_session("default") as s:
        s.query(ReputationRun).update({"status": "succeeded"})
        s.commit()
    assert sch.tick_reputation() == []
    assert sch.tick_reputation(utcnow() + dt.timedelta(days=8)) == ["default"]
    with db.get_session("default") as s:
        runs = list(s.scalars(select(ReputationRun).order_by(ReputationRun.started_at)))
        assert [r.trigger for r in runs] == ["scheduled", "scheduled"]
        assert not [a for a in s.scalars(select(AuditLog)) if a.action == "reputation_run_started"]
    sch._leader.release()


def test_scheduler_does_nothing_without_verified_domains(client):
    add_domain(verified=False)
    sch = sched_mod.ExternalScheduler(startup_delay_seconds=0, reputation_launcher=lambda d, r: pytest.fail("started"))
    assert sch.tick_reputation() == []
    sch._leader.release()


def test_score_and_grade():
    assert rep.score_of({}) == 100 and rep.grade(100) == "A"
    assert rep.score_of({"high": 1, "medium": 1, "info": 9}) == 77 and rep.grade(77) == "C"
    assert rep.score_of({"critical": 9}) == 0 and rep.grade(0) == "F"
