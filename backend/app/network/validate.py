"""Validation of scan targets and exclusions (docs/NETWORK_DISCOVERY.md#validation).

A target is an IPv4 CIDR (`10.10.1.0/24`) or an inclusive range (`10.30.0.10-10.30.0.50`).
Limits: no single target above /16 (65,536 addresses), at most 262,144 addresses per scan, and
never 0.0.0.0/8, 127/8, 169.254/16 or 224/4 and above (multicast, reserved, broadcast).
Exclusions use the same syntax (without the size caps) and are removed from the total.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

MAX_TARGET_ADDRESSES = 65_536
MAX_SCAN_ADDRESSES = 262_144
MAX_ITEMS = 200
CONCURRENCY = (20, 64)
FORBIDDEN = tuple(ipaddress.ip_network(n) for n in ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3"))
_RANGE = re.compile(r"^\s*([0-9.]+)\s*-\s*([0-9.]+)\s*$")


class TargetError(ValueError):
    pass


Interval = tuple[int, int]  # inclusive start, end of integer addresses


def _addr(s: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(s.strip())
    except ValueError:
        if ":" in s:
            raise TargetError(f"{s!r}: IPv6 is not supported yet") from None
        raise TargetError(f"{s!r} is not a valid IPv4 address") from None


def parse(item: str, *, forbid: bool = True) -> Interval:
    """One CIDR / range / single address as an inclusive integer interval."""
    s = (item or "").strip()
    if not s or len(s) > 64:
        raise TargetError("empty or too long target")
    m = _RANGE.match(s)
    if m:
        a, b = _addr(m[1]), _addr(m[2])
        if int(b) < int(a):
            raise TargetError(f"{s!r}: the range ends before it starts")
        lo, hi = int(a), int(b)
    elif "/" in s:
        if ":" in s:
            raise TargetError(f"{s!r}: IPv6 is not supported yet")
        try:
            net = ipaddress.IPv4Network(s, strict=False)
        except ValueError:
            raise TargetError(f"{s!r} is not a valid CIDR") from None
        lo, hi = int(net.network_address), int(net.broadcast_address)
    else:
        lo = hi = int(_addr(s))
    if forbid:
        for f in FORBIDDEN:
            if lo <= int(f.broadcast_address) and hi >= int(f.network_address):
                raise TargetError(f"{s!r} includes {f} which is never scanned (unspecified, loopback, link-local, "
                                  "multicast and reserved ranges)")
    return lo, hi


def merge(intervals: Iterable[Interval]) -> list[Interval]:
    out: list[list[int]] = []
    for lo, hi in sorted(intervals):
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return [(a, b) for a, b in out]


def count(intervals: Iterable[Interval]) -> int:
    return sum(b - a + 1 for a, b in merge(intervals))


def subtract(a: list[Interval], b: list[Interval]) -> list[Interval]:
    a, b = merge(a), merge(b)
    out: list[Interval] = []
    for lo, hi in a:
        cur = lo
        for xl, xh in b:
            if xh < cur or xl > hi:
                continue
            if xl > cur:
                out.append((cur, xl - 1))
            cur = max(cur, xh + 1)
            if cur > hi:
                break
        if cur <= hi:
            out.append((cur, hi))
    return out


def clean(items: Iterable[str], *, what: str, size_caps: bool) -> tuple[list[str], list[Interval]]:
    items = [i.strip() for i in items if i and i.strip()]
    if len(items) > MAX_ITEMS:
        raise TargetError(f"at most {MAX_ITEMS} {what} entries")
    ivs: list[Interval] = []
    for i in items:
        lo, hi = parse(i)
        if size_caps and hi - lo + 1 > MAX_TARGET_ADDRESSES:
            raise TargetError(f"{i!r} has {hi - lo + 1:,} addresses: a single target may not exceed /16 "
                              f"({MAX_TARGET_ADDRESSES:,} addresses); split it")
        ivs.append((lo, hi))
    return items, ivs


def validate(targets: list[str], exclude: list[str] | None = None, concurrency: int | None = None
             ) -> tuple[list[str], list[str], int]:
    """(cleaned targets, cleaned exclusions, addresses to scan). Raises TargetError."""
    if concurrency is not None and concurrency not in CONCURRENCY:
        raise TargetError(f"concurrency must be {CONCURRENCY[0]} or {CONCURRENCY[1]}")
    t, tiv = clean(targets, what="target", size_caps=True)
    if not t:
        raise TargetError("add at least one subnet or range to scan")
    e, eiv = clean(exclude or [], what="exclusion", size_caps=False)
    total = count(subtract(tiv, eiv))
    if total > MAX_SCAN_ADDRESSES:
        raise TargetError(f"{total:,} addresses is more than the {MAX_SCAN_ADDRESSES:,} allowed per scan: "
                          "split it into several scans")
    if total == 0:
        raise TargetError("every target address is excluded")
    return t, e, total


def subnet_of(ip: str, targets: list[str]) -> str:
    """The configured target that contains `ip` ("" when none)."""
    try:
        n = int(ipaddress.IPv4Address(ip))
    except ValueError:
        return ""
    for t in targets:
        try:
            lo, hi = parse(t, forbid=False)
        except TargetError:
            continue
        if lo <= n <= hi:
            return t
    return ""
