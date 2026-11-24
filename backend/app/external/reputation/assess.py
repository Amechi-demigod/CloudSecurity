"""One domain's assessment: runs the four check groups and returns hits plus the data behind them. No database."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from ... import config
from . import ct, dnsbl, email, lookalike
from .hits import Hit
from .lookup import Dns


@dataclass
class Assessment:
    domain: str
    hits: list[Hit] = field(default_factory=list)
    checked: set[str] = field(default_factory=set)  # categories that ran to completion (their old findings may close)
    details: dict = field(default_factory=dict)
    known_issuers: dict | None = None  # updated map (None = unchanged)
    new_issuers: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    skipped: bool = False  # the domain does not resolve at all: nothing was concluded


def known_issuers_update(known: dict, certs: list[dict], now: datetime, days: int) -> tuple[dict, list[str]]:
    """(updated known-issuers map, issuers that are new). The first successful run only records a baseline."""
    baseline = not known
    new_map = dict(known)
    for c in certs:
        if c["issuer"] not in new_map:
            new_map[c["issuer"]] = "baseline" if baseline else now.date().isoformat()
    fresh = []
    for iss, first in new_map.items():
        try:
            if first != "baseline" and (now.date() - datetime.fromisoformat(first).date()).days <= days:
                fresh.append(iss)
        except ValueError:
            continue
    return new_map, sorted(set(fresh))


def run(domain: str, dns: Dns, known_issuers: dict, now: datetime, own_domains: set[str] | None = None) -> Assessment:
    s = config.settings
    a = Assessment(domain)
    if not any(dns.q(domain, t) for t in ("NS", "A", "MX", "TXT")):
        a.skipped = True
        a.notes.append(f"{domain} did not answer any DNS query; nothing was concluded (retry later).")
        return a
    # 1. email security
    hits, snap = email.check(domain, dns)
    a.hits += hits
    a.details["email"] = snap
    a.checked.add("email")
    # 2. look-alike domains
    cands = lookalike.generate(domain, s.reputation_lookalike_max)
    if lookalike.split(domain) is None:
        a.details["lookalikes"] = {"candidates": 0, "registered": [],
                                   "note": "Look-alike domains are checked for registrable domains only (not subdomains)."}
    else:
        found = lookalike.resolve(cands, dns, skip=own_domains)
        a.details["lookalikes"] = {"candidates": len(cands), "registered": found[:150]}
        a.hits += lookalike.hits_for(domain, found)
        a.checked.add("lookalike")
    # 3. blocklists (nothing is looked up unless the operator configured zones)
    zones, dzones = dnsbl.valid_zones(s.reputation_dnsbl_zones), dnsbl.valid_zones(s.reputation_dnsbl_domain_zones)
    if zones or dzones:
        ips = list(dns.q(domain, "A"))
        for m in snap.get("mx", [])[:5]:
            if m:
                ips += dns.q(m, "A")
        listings = dnsbl.check(domain, ips, dns, zones, dzones)
        a.details["blocklists"] = {"enabled": True, "zones": zones + dzones, "listings": listings}
        a.hits += dnsbl.hits_for(domain, listings)
    else:
        a.details["blocklists"] = {"enabled": False, "zones": [], "listings": []}
    a.checked.add("blocklist")
    # 4. certificate transparency
    if s.reputation_ct_enabled:
        try:
            rows = ct.cached_rows(domain, s.reputation_ct_url, s.reputation_ct_timeout, s.reputation_ct_cache_seconds)
            certs = ct.parse(domain, rows, now, s.reputation_ct_days, s.reputation_ct_max_certs)
            known, new = known_issuers_update(known_issuers, certs, now, s.reputation_ct_days)
            a.known_issuers, a.new_issuers = known, new
            a.details["certificates"] = {"enabled": True, "days": s.reputation_ct_days, "count": len(certs),
                                         "issuers": sorted({c["issuer"] for c in certs}), "recent": certs[:25]}
            a.hits += ct.hits_for(domain, certs, new)
            a.checked.add("certificate")
        except ct.CtError as e:
            a.notes.append(str(e))
            a.details["certificates"] = {"enabled": True, "error": str(e)}
    else:
        a.details["certificates"] = {"enabled": False}
    return a
