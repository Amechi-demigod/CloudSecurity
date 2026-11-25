"""A tiny MMDB writer for tests (IPv4, 24-bit records): builds a few-hundred-byte database that the real
`maxminddb` reader opens, so lookups are tested without any download."""
from __future__ import annotations

import ipaddress
import struct
from typing import Any


def _ctrl(t: int, size: int) -> bytes:
    assert size < 285
    sz, extra = (size, b"") if size < 29 else (29, bytes([size - 29]))
    if t <= 7:
        return bytes([(t << 5) | sz]) + extra
    return bytes([sz, t - 7]) + extra


class U(int):
    """An integer with an explicit MMDB type (5 = uint16, 6 = uint32, 9 = uint64)."""

    def __new__(cls, value: int, t: int):
        o = super().__new__(cls, value)
        o.t = t
        return o


def enc(v: Any) -> bytes:
    if isinstance(v, U):
        n = (int(v).bit_length() + 7) // 8
        return _ctrl(v.t, n) + int(v).to_bytes(n, "big")
    if isinstance(v, bool):
        raise TypeError("bool unsupported")
    if isinstance(v, str):
        b = v.encode()
        return _ctrl(2, len(b)) + b
    if isinstance(v, float):
        return _ctrl(3, 8) + struct.pack(">d", v)
    if isinstance(v, int):
        n = max(1, (v.bit_length() + 7) // 8) if v else 0
        return _ctrl(5 if n <= 2 else 6, n) + v.to_bytes(n, "big")
    if isinstance(v, dict):
        return _ctrl(7, len(v)) + b"".join(enc(k) + enc(x) for k, x in v.items())
    if isinstance(v, list):
        return _ctrl(11, len(v)) + b"".join(enc(x) for x in v)
    raise TypeError(type(v))


def build(entries: dict[str, dict], db_type: str = "Test") -> bytes:
    """entries: IPv4 CIDR -> record. Returns the MMDB file bytes."""
    data = b""
    offsets: dict[str, int] = {}
    for cidr, rec in entries.items():
        offsets[cidr] = len(data)
        data += enc(rec)
    nets = [(ipaddress.ip_network(c), c) for c in entries]
    nodes: list[list] = []  # each [left, right]: ("node", i) | ("data", cidr) | None

    def new_node() -> int:
        nodes.append([None, None])
        return len(nodes) - 1

    new_node()
    for net, cidr in nets:
        bits = int(net.network_address)
        cur = 0
        for depth in range(net.prefixlen):
            bit = (bits >> (31 - depth)) & 1
            if depth == net.prefixlen - 1:
                nodes[cur][bit] = ("data", cidr)
            else:
                nxt = nodes[cur][bit]
                if nxt is None or nxt[0] != "node":
                    nxt = ("node", new_node())
                    nodes[cur][bit] = nxt
                cur = nxt[1]
    count = len(nodes)

    def rec_val(r) -> int:
        if r is None:
            return count
        return r[1] if r[0] == "node" else count + 16 + offsets[r[1]]

    tree = b"".join(rec_val(n[0]).to_bytes(3, "big") + rec_val(n[1]).to_bytes(3, "big") for n in nodes)
    meta = {"node_count": U(count, 6), "record_size": U(24, 5), "ip_version": U(4, 5), "database_type": db_type,
            "languages": ["en"], "binary_format_major_version": U(2, 5), "binary_format_minor_version": U(0, 5),
            "build_epoch": U(1700000000, 9), "description": {"en": "test"}}
    return tree + b"\x00" * 16 + data + b"\xab\xcd\xefMaxMind.com" + enc(meta)


def city(name: str, region: str, cc: str, country: str, lat: float, lon: float, acc: int | None = None) -> dict:
    loc = {"latitude": lat, "longitude": lon}
    if acc is not None:
        loc["accuracy_radius"] = acc
    return {"city": {"names": {"en": name}}, "subdivisions": [{"names": {"en": region}}],
            "country": {"iso_code": cc, "names": {"en": country}}, "location": loc}


def asn(number: int, org: str) -> dict:
    return {"autonomous_system_number": number, "autonomous_system_organization": org}
