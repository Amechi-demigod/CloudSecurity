"""Address safety: the scanner only ever connects to public IPv4 addresses.

Refused (always, in production without exception): private (RFC 1918), loopback, link-local (incl. the cloud
metadata address 169.254.169.254), CGNAT (100.64/10, incl. Alibaba metadata 100.100.100.200), multicast, reserved,
documentation, benchmarking and "this network" ranges, every IPv6 address (IPv4 only in v1; this covers fd00:ec2::254
and IPv4-mapped forms), the server's own addresses and EXTERNAL_BLOCKED_CIDRS.

Names are resolved here and every resolved address is checked, immediately before each connection; callers then
connect to the checked IP literal (never to the name again), so a DNS answer that changes between check and connect
(DNS rebinding) cannot redirect a connection to an internal address. If ANY address a name resolves to is refused,
the whole name is refused."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from collections.abc import Iterator
from contextlib import contextmanager

from .. import config

log = logging.getLogger(__name__)

BLOCKED_V4 = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4"))
# Documented explicitly (all are inside the ranges above or IPv6, which is refused entirely).
METADATA_ADDRESSES = ("169.254.169.254", "169.254.170.2", "100.100.100.200", "192.0.0.192", "fd00:ec2::254")


class BlockedAddress(Exception):
    """The scanner refuses to connect to this address / name."""


# Tests only: networks that are allowed in addition (e.g. 127.0.0.0/8 for a local test server).
_test_allow: tuple[ipaddress.IPv4Network, ...] = ()


@contextmanager
def allow_for_tests(*cidrs: str) -> Iterator[None]:
    """Let tests connect to a local server. Refused outright in production."""
    global _test_allow
    if config.settings.is_production:
        raise RuntimeError("the address guard cannot be relaxed in production")
    saved, _test_allow = _test_allow, tuple(ipaddress.ip_network(c) for c in cidrs)
    try:
        yield
    finally:
        _test_allow = saved


def own_addresses() -> set[str]:
    out: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            out.add(info[4][0])
    except OSError:
        pass
    try:  # the address of the default route (a UDP "connect" sends nothing)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            out.add(s.getsockname()[0])
    except OSError:
        pass
    egress = config.settings.external_scanner_egress_ip
    if egress:
        out.add(egress)
    return out


def _extra_blocked() -> list[ipaddress.IPv4Network]:
    nets = []
    for c in config.settings.external_blocked_cidrs:
        try:
            n = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if isinstance(n, ipaddress.IPv4Network):
            nets.append(n)
    return nets


def check_ip(value: str) -> str:
    """Return the normalised public IPv4 address, or raise BlockedAddress."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        raise BlockedAddress(f"{value!r} is not an IP address") from None
    if not isinstance(ip, ipaddress.IPv4Address):
        raise BlockedAddress("IPv6 and IPv4-mapped addresses are not scanned (IPv4 only)")
    if not any(ip in n for n in _test_allow):
        if any(ip in n for n in BLOCKED_V4) or ip.is_private or ip.is_loopback or ip.is_link_local \
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified or not ip.is_global:
            raise BlockedAddress(f"{ip} is a private, loopback, link-local, CGNAT, multicast or reserved address")
        if any(ip in n for n in _extra_blocked()):
            raise BlockedAddress(f"{ip} is in EXTERNAL_BLOCKED_CIDRS")
        if str(ip) in own_addresses():
            raise BlockedAddress(f"{ip} is an address of this server")
    return str(ip)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


async def resolve_public(host: str) -> str:
    """The IPv4 address to connect to for `host` (a name or an IPv4 literal), after checking every address it
    resolves to. Called before every connection: nothing is cached."""
    if is_ip_literal(host):
        return check_ip(host)
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except OSError as e:
        raise BlockedAddress(f"{host} does not resolve ({e})") from None
    addrs = sorted({i[4][0] for i in infos})
    if not addrs:
        raise BlockedAddress(f"{host} has no IPv4 address")
    checked = [check_ip(a) for a in addrs]  # raises if any one is refused
    return checked[0]


def resolve_public_sync(host: str) -> list[str]:
    """All checked IPv4 addresses of a name (for discovery); raises BlockedAddress."""
    if is_ip_literal(host):
        return [check_ip(host)]
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError as e:
        raise BlockedAddress(f"{host} does not resolve ({e})") from None
    addrs = sorted({i[4][0] for i in infos})
    if not addrs:
        raise BlockedAddress(f"{host} has no IPv4 address")
    return [check_ip(a) for a in addrs]
