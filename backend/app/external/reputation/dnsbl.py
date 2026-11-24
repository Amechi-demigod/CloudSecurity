"""Pluggable DNS blocklist (DNSBL) checker. NO zone is enabled by default: the terms of use of each list differ
(Spamhaus, for instance, requires a paid DQS key for commercial use), so the operator chooses the zones with
REPUTATION_DNSBL_ZONES (lists of IPv4 addresses) and REPUTATION_DNSBL_DOMAIN_ZONES (lists of domain names) after
reading each list's terms. With no zones configured nothing is looked up."""
from __future__ import annotations

import ipaddress
import re

from .hits import Hit
from .lookup import Dns

ZONE_RE = re.compile(r"^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def valid_zones(zones: list[str]) -> list[str]:
    return [z.strip().lower().rstrip(".") for z in zones if ZONE_RE.match(z.strip().lower().rstrip("."))]


def _is_listing(answers: list[str]) -> list[str]:
    """Return codes that mean 'listed'. 127.255.255.x are error codes (query refused / over limit), not listings."""
    return [a for a in answers if a.startswith("127.") and not a.startswith("127.255.255.")]


def public_ipv4(values: list[str]) -> list[str]:
    out: list[str] = []
    for v in values:
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            continue
        if isinstance(ip, ipaddress.IPv4Address) and ip.is_global and str(ip) not in out:
            out.append(str(ip))
    return out


def check(domain: str, ips: list[str], dns: Dns, ip_zones: list[str], domain_zones: list[str]) -> list[dict]:
    """[{target, zone, kind, codes}] for every listing. Empty (and no query sent) without configured zones."""
    ip_zones, domain_zones = valid_zones(ip_zones), valid_zones(domain_zones)
    out: list[dict] = []
    for ip in public_ipv4(ips):
        rev = ".".join(reversed(ip.split(".")))
        for z in ip_zones:
            codes = _is_listing(dns.q(f"{rev}.{z}", "A"))
            if codes:
                out.append({"target": ip, "zone": z, "kind": "ip", "codes": codes[:3]})
    for z in domain_zones:
        codes = _is_listing(dns.q(f"{domain}.{z}", "A"))
        if codes:
            out.append({"target": domain, "zone": z, "kind": "domain", "codes": codes[:3]})
    return out


def hits_for(domain: str, listings: list[dict]) -> list[Hit]:
    hits = []
    for row in listings:
        what = "mail or web server address" if row["kind"] == "ip" else "domain name"
        hits.append(Hit(
            "rep.blocklisted", "blocklist", domain, "high", f"{row['target']} is on the blocklist {row['zone']}",
            f"The {what} {row['target']} is listed on {row['zone']}. Mail servers that use this list may reject or "
            "junk your email, and some security products may block the site.",
            "Find out why it is listed (the list's lookup page gives the reason), fix the cause (compromised "
            "mailbox or server, open relay, missing reverse DNS) and then follow the list's removal process.",
            subject=f"{row['zone']}|{row['target']}", evidence=row))
    return hits
