"""A minimal DNS client (UDP with TCP fallback) for TXT / MX / NS / CNAME / AAAA records, so no DNS library is needed.
Address (A) lookups use the system resolver through `guard`. Uses the resolvers of /etc/resolv.conf (fallback 1.1.1.1,
9.9.9.9). Tests replace `query` with a fake."""
from __future__ import annotations

import random
import socket
import struct

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
_NAMES = {v: k for k, v in TYPES.items()}


def resolvers() -> list[str]:
    out: list[str] = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                p = line.split()
                if len(p) >= 2 and p[0] == "nameserver" and ":" not in p[1]:
                    out.append(p[1])
    except OSError:
        pass
    return out[:3] + ["1.1.1.1", "9.9.9.9"]


def _encode(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna")
        if not 0 < len(raw) < 64:
            raise ValueError("bad DNS label")
        out += bytes([len(raw)]) + raw
    return out + b"\0"


def _read_name(msg: bytes, pos: int) -> tuple[str, int]:
    labels: list[str] = []
    end = None
    hops = 0
    while True:
        n = msg[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = ((n & 0x3F) << 8) | msg[pos + 1]
            if end is None:
                end = pos + 2
            pos = ptr
            hops += 1
            if hops > 20:
                raise ValueError("DNS compression loop")
            continue
        labels.append(msg[pos + 1:pos + 1 + n].decode("ascii", "replace"))
        pos += 1 + n
    return ".".join(labels), (end if end is not None else pos)


def parse(msg: bytes) -> list[tuple[str, str]]:
    """[(type, value)] of the answer section."""
    _id, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", msg[:12])
    pos = 12
    for _ in range(qd):
        _, pos = _read_name(msg, pos)
        pos += 4
    out: list[tuple[str, str]] = []
    for _ in range(an):
        _, pos = _read_name(msg, pos)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", msg[pos:pos + 10])
        pos += 10
        rd = msg[pos:pos + rdlen]
        t = _NAMES.get(rtype)
        if t == "TXT":
            i, parts = 0, []
            while i < len(rd):
                ln = rd[i]
                parts.append(rd[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                i += 1 + ln
            out.append((t, "".join(parts)))
        elif t in ("NS", "CNAME"):
            out.append((t, _read_name(msg, pos)[0]))
        elif t == "MX":
            out.append((t, _read_name(msg, pos + 2)[0]))
        elif t == "A" and rdlen == 4:
            out.append((t, socket.inet_ntoa(rd)))
        elif t == "AAAA" and rdlen == 16:
            out.append((t, socket.inet_ntop(socket.AF_INET6, rd)))
        pos += rdlen
    return out


def query(name: str, rtype: str, timeout: float = 3.0) -> list[str]:
    """Values of the records of `rtype` (empty on NXDOMAIN / no data / failure)."""
    qid = random.randrange(65536)
    pkt = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _encode(name) + struct.pack(">HH", TYPES[rtype], 1)
    for server in resolvers():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(pkt, (server, 53))
                data, _ = s.recvfrom(4096)
            if struct.unpack(">H", data[:2])[0] != qid:
                continue
            if data[2] & 0x02:  # truncated: retry over TCP
                with socket.create_connection((server, 53), timeout=timeout) as t:
                    t.sendall(struct.pack(">H", len(pkt)) + pkt)
                    ln = struct.unpack(">H", t.recv(2))[0]
                    data = b""
                    while len(data) < ln:
                        chunk = t.recv(ln - len(data))
                        if not chunk:
                            break
                        data += chunk
            return [v for t_, v in parse(data) if t_ == rtype]
        except (OSError, ValueError, struct.error, IndexError):
            continue
    return []
