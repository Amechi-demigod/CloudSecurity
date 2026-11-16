"""Scan engine: discovery, port scan, banners, TLS and web checks for ONE organisation. Pure network logic: it
never touches the database (service.py persists the result) and never talks to an address the guard refuses.

Flow
  1. domains (verified): DNS records, subdomains from certificate transparency (filtered to the verified domain),
     every name resolved and checked against the guard;
  2. IP targets: each address is scanned only if it is approved by a platform owner, a public IP of the
     organisation's cloud inventory, or resolved by a verified domain; everything else is skipped (never scanned);
  3. TCP connect scan of ports.TOP_PORTS per unique IP, banners of server-first services;
  4. per open port: TLS profile, web checks, risky-service hits, optional default-credential check.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from .. import config
from . import checks, dnsclient, guard, tlsprobe
from .net import Net, ScanDeadline
from .ports import BANNER_PORTS, HTTP_PORTS, HTTPS_PORTS, SERVICE_NAMES, TLS_ONLY_PORTS, TOP_PORTS

log = logging.getLogger(__name__)
NAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


@dataclass
class DomainIn:
    target_id: str
    domain: str
    default_passwords: bool = False


@dataclass
class IpTargetIn:
    target_id: str
    value: str  # IPv4 or CIDR (at most /24)
    approved: bool = False  # platform-owner approval
    default_passwords: bool = False


@dataclass
class Plan:
    domains: list[DomainIn] = field(default_factory=list)
    ip_targets: list[IpTargetIn] = field(default_factory=list)
    cloud_ips: set[str] = field(default_factory=set)
    ports: tuple[int, ...] = TOP_PORTS
    default_password_delay: float = 1.5
    ct_lookup: Callable[[str], list[str]] | None = None  # names from certificate transparency (tests inject)
    dns_query: Callable[[str, str], list[str]] | None = None
    max_hosts: int = 512
    only_host: str | None = None  # re-test of one host


@dataclass
class HostOut:
    host: str
    ip: str | None
    target_id: str | None
    method: str  # how it came into scope: domain | cloud | platform | parent
    dns: dict = field(default_factory=dict)
    ports: list[dict] = field(default_factory=list)
    tls: dict = field(default_factory=dict)  # port -> slim TLS profile
    software: list[dict] = field(default_factory=list)
    hits: list[checks.Hit] = field(default_factory=list)
    web: dict = field(default_factory=dict)  # port -> {status, server, title}


@dataclass
class ScanOut:
    hosts: list[HostOut] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    truncated: bool = False
    connections: int = 0
    refused: list[str] = field(default_factory=list)


def expand_cidr(value: str) -> list[str]:
    net = ipaddress.ip_network(value, strict=False)
    if not isinstance(net, ipaddress.IPv4Network):
        raise ValueError("IPv4 only")
    hosts = [str(h) for h in net.hosts()] if net.prefixlen < 31 else [str(h) for h in net]
    return hosts


def crtsh_names(domain: str) -> list[str]:
    """Names from certificate transparency (crt.sh JSON) for a verified domain, filtered to that domain."""
    import httpx

    r = httpx.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=20,
                  headers={"User-Agent": "Sentrigis-AttackSurface/1.0 (+https://sentrigis.com/scanner)"})
    r.raise_for_status()
    names: set[str] = set()
    for row in r.json():
        for n in str(row.get("name_value", "")).split("\n"):
            names.add(n.strip().lower())
    return sorted(names)


def filter_names(domain: str, names: list[str], cap: int = 200) -> list[str]:
    """Only well-formed names equal to or below the verified domain (wildcards stripped)."""
    out: set[str] = set()
    for n in names:
        n = n.strip().lower().removeprefix("*.").rstrip(".")
        if (n == domain or n.endswith("." + domain)) and NAME_RE.match(n):
            out.add(n)
    return sorted(out)[:cap]


def _discover_domain(plan: Plan, d: DomainIn) -> tuple[list[str], dict, list[str]]:
    q = plan.dns_query or dnsclient.query
    dns: dict[str, list[str]] = {}
    for rt in ("AAAA", "CNAME", "MX", "NS"):
        try:
            vals = q(d.domain, rt)
        except Exception:
            vals = []
        if vals:
            dns[rt] = vals[:10]
    errors: list[str] = []
    names = [d.domain]
    if config.settings.external_crtsh_enabled or plan.ct_lookup:
        try:
            names += filter_names(d.domain, (plan.ct_lookup or crtsh_names)(d.domain))
        except Exception as e:
            errors.append(f"certificate transparency lookup for {d.domain} failed: {type(e).__name__}")
    return sorted(set(names)), dns, errors


def _service_for(port: int, tls: bool) -> str:
    return SERVICE_NAMES.get(port) or ("https" if tls else "http" if port in HTTP_PORTS else "unknown")


async def _scan_ports(net: Net, ip: str, ports: tuple[int, ...]) -> list[dict]:
    """TCP connect scan of one IP; server-first services also return their banner."""
    out: list[dict] = []

    async def one(port: int) -> None:
        try:
            if port in BANNER_PORTS:
                b = await net.banner(ip, port, wait=2.5)
                if b is None:
                    return
                out.append({"port": port, "banner": b.decode("latin-1", "replace").strip()[:200]})
            else:
                try:
                    r, w, _i, release = await net.open(ip, port)
                except (OSError, TimeoutError, guard.BlockedAddress):
                    return
                w.close()
                release()
                out.append({"port": port, "banner": ""})
        except ScanDeadline:
            raise
        except Exception:  # one port never aborts the scan
            return

    await _gather(*(one(p) for p in ports))
    return sorted(out, key=lambda x: x["port"])


def _slim_tls(t: dict) -> dict:
    c = t.get("cert") or {}
    return {"protocols": t.get("protocols"), "cipher": t.get("cipher"), "weak_ciphers": t.get("weak_ciphers"),
            "trusted": t.get("trusted"), "verify_error": t.get("verify_error"),
            "subject": c.get("subject"), "issuer": c.get("issuer"), "not_after": c.get("not_after"),
            "days_left": c.get("days_left"), "self_signed": c.get("self_signed"),
            "key": f"{c.get('key_type')} {c.get('key_bits')}"}


def tls_hits(host: str, ip: str, port: int, t: dict) -> list[checks.Hit]:
    hits: list[checks.Hit] = []
    ev_base = {"protocols": {k: v for k, v in (t.get("protocols") or {}).items()}}
    for name, cid in (("SSLv3", "tls-sslv3"), ("TLS1.0", "tls-tls10"), ("TLS1.1", "tls-tls11")):
        if (t.get("protocols") or {}).get(name):
            hits.append(checks.Hit(cid, host, ip, port, evidence=dict(ev_base), extra={}, key=""))
    for cls in t.get("weak_ciphers") or []:
        hits.append(checks.Hit("tls-weak-" + cls.lower().replace(" ", "-"), host, ip, port,
                               evidence={"accepted_class": cls}, key=""))
    c = t.get("cert")
    if c:
        ev = {k: c.get(k) for k in ("subject", "issuer", "not_before", "not_after", "names", "key_type", "key_bits",
                                    "signature")}
        if c["expired"]:
            hits.append(checks.Hit("tls-cert-expired", host, ip, port, evidence=ev))
        elif c["days_left"] < 30:
            hits.append(checks.Hit("tls-cert-expiring", host, ip, port, evidence=ev))
        if c["self_signed"]:
            hits.append(checks.Hit("tls-cert-self-signed", host, ip, port, evidence=ev))
        elif t.get("trusted") is False and not c["expired"] and c.get("hostname_ok") is not False:
            hits.append(checks.Hit("tls-cert-untrusted", host, ip, port, evidence={**ev, "error": t.get("verify_error")}))
        if c.get("hostname_ok") is False:
            hits.append(checks.Hit("tls-cert-mismatch", host, ip, port, evidence=ev))
        weak_key = c.get("key_type") == "RSA" and (c.get("key_bits") or 4096) < 2048
        if weak_key or c.get("signature") in ("sha1", "md5"):
            hits.append(checks.Hit("tls-cert-weak-key", host, ip, port, evidence=ev))
    return hits


async def _scan_host(net: Net, plan: Plan, h: HostOut, open_ports: list[dict], connect_host: str) -> None:
    """Service detection and checks of one host (name or IP) given the open ports of its IP."""
    from .catalog import RISKY

    default_pw = False
    for t in plan.domains:
        if h.target_id == t.target_id:
            default_pw = t.default_passwords
    for t in plan.ip_targets:
        if h.target_id == t.target_id:
            default_pw = t.default_passwords
    h.ports = []
    for p in open_ports:
        port, banner = p["port"], p["banner"]
        entry = {"port": port, "service": _service_for(port, port in HTTPS_PORTS | TLS_ONLY_PORTS), "banner": banner,
                 "product": None, "version": None}
        pv = checks.product_from_banner(banner)
        if pv:
            entry["product"], entry["version"] = pv
            h.software.append({"product": pv[0], "version": pv[1], "port": port, "source": "banner"})
        h.ports.append(entry)
        if port in RISKY:
            risky = RISKY[port][0]
            h.hits.append(checks.Hit(f"risky-{risky}", h.host, h.ip, port,
                                     evidence={"port": port, "service": SERVICE_NAMES.get(port, risky),
                                               "banner": banner[:120]}))
        is_web = port in HTTP_PORTS or port in HTTPS_PORTS
        unknown = port not in RISKY and not is_web and port not in TLS_ONLY_PORTS and port not in BANNER_PORTS
        tprof = None
        if port in HTTPS_PORTS or port in TLS_ONLY_PORTS or unknown:
            tprof = await tlsprobe.probe(net, connect_host, port, sni=None if guard.is_ip_literal(h.host) else h.host)
            if tprof:
                h.tls[str(port)] = _slim_tls(tprof)
                h.hits.extend(tls_hits(h.host, h.ip or "", port, tprof))
                entry["service"] = "https" if port not in TLS_ONLY_PORTS else entry["service"]
        if not (is_web or unknown):
            continue
        tls = bool(tprof)
        web = await checks.web_checks(net, connect_host, port, tls)
        if web is None:
            continue
        if unknown:
            entry["service"] = "https" if tls else "http"
        h.web[str(port)] = {"status": web.status, "server": web.server, "title": web.title}
        for sw in web.software:
            h.software.append({**sw, "port": port})
            if not entry["product"]:
                entry["product"], entry["version"] = sw["product"], sw["version"]
        for hit in web.hits:
            hit.host = h.host
        h.hits.extend(web.hits)
        if default_pw and web.basic_paths:
            hit = await checks.default_password_check(net, connect_host, port, tls, web.basic_paths[0],
                                                      delay=plan.default_password_delay)
            if hit:
                hit.host = h.host
                h.hits.append(hit)


async def _gather(*aws):
    """gather() that lets the scan deadline stop the whole scan (other failures stay per task)."""
    res = await asyncio.gather(*aws, return_exceptions=True)
    for r in res:
        if isinstance(r, ScanDeadline):
            raise r
    return res


async def run(plan: Plan, *, net: Net | None = None) -> ScanOut:
    s = config.settings
    out = ScanOut()
    net = net or Net(deadline=time.monotonic() + s.external_max_scan_seconds)
    loop = asyncio.get_running_loop()
    entries: list[HostOut] = []  # (host, ip) to scan
    domain_ips: set[str] = set()
    try:
        # 1. verified domains
        for d in plan.domains:
            names, dns, errs = await loop.run_in_executor(None, _discover_domain, plan, d)
            out.errors.extend(errs)
            for name in names:
                try:
                    ips = await loop.run_in_executor(None, guard.resolve_public_sync, name)
                except guard.BlockedAddress as e:
                    out.skipped.append({"value": name, "reason": f"refused: {e}"})
                    continue
                domain_ips.update(ips)
                ho = HostOut(host=name, ip=ips[0], target_id=d.target_id, method="domain",
                             dns={**(dns if name == d.domain else {}), "A": ips})
                entries.append(ho)
        # 2. IP targets (each address needs its own proof)
        for t in plan.ip_targets:
            try:
                addrs = expand_cidr(t.value)
            except ValueError as e:
                out.skipped.append({"value": t.value, "reason": str(e)})
                continue
            for a in addrs:
                method = "platform" if t.approved else "cloud" if a in plan.cloud_ips else \
                    "domain" if a in domain_ips else None
                if method is None:
                    out.skipped.append({"value": a, "reason": "not verified: no verified domain resolves to it, it is "
                                        "not a public IP of your cloud inventory and no platform owner approved it"})
                    continue
                try:
                    guard.check_ip(a)
                except guard.BlockedAddress as e:
                    out.skipped.append({"value": a, "reason": f"refused: {e}"})
                    continue
                if not any(e.host == a for e in entries):
                    entries.append(HostOut(host=a, ip=a, target_id=t.target_id, method=method, dns={"A": [a]}))
        if plan.only_host:
            entries = [e for e in entries if e.host == plan.only_host]
        if len(entries) > plan.max_hosts:
            for e in entries[plan.max_hosts:]:
                out.skipped.append({"value": e.host, "reason": f"over the {plan.max_hosts} hosts per scan limit"})
            entries = entries[:plan.max_hosts]
        # 3. ports, once per IP
        ips = sorted({e.ip for e in entries if e.ip})
        sem = asyncio.Semaphore(8)
        open_by_ip: dict[str, list[dict]] = {}

        async def scan_ip(ip: str) -> None:
            async with sem:
                open_by_ip[ip] = await _scan_ports(net, ip, plan.ports)

        await _gather(*(scan_ip(i) for i in ips))

        # 4. services and checks (per name: virtual hosts differ)
        async def scan_entry(e: HostOut) -> None:
            async with sem:
                try:
                    await _scan_host(net, plan, e, open_by_ip.get(e.ip or "", []), e.host)
                except ScanDeadline:
                    raise
                except Exception as ex:  # never let one host kill the scan
                    log.exception("host %s failed", e.host)
                    out.errors.append(f"{e.host}: {type(ex).__name__}")

        await _gather(*(scan_entry(e) for e in entries))
    except ScanDeadline:
        out.truncated = True
        out.errors.append("the maximum scan duration was reached; results are partial")
    out.hosts = entries
    out.connections = net.connections
    out.refused = net.refused[:50]
    return out
