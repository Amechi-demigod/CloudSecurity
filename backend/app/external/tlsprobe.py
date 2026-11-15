"""TLS assessment without exploiting anything: protocol support (SSLv3 / TLS 1.0 / 1.1 are probed with a hand-built
ClientHello and only the ServerHello is read, so the result does not depend on the scanner's OpenSSL build; TLS 1.2 /
1.3 with the ssl module), weak cipher classes (a ClientHello offering only that class), and the certificate
(expiry, self-signed, hostname, key size, signature, trust chain). No data is sent after the handshake."""
from __future__ import annotations

import asyncio
import os
import ssl
import struct
from datetime import UTC, datetime

from . import guard
from .net import Net, unverified_ctx

VERSIONS = {"SSLv3": 0x0300, "TLS1.0": 0x0301, "TLS1.1": 0x0302}
# Broad lists of legacy-compatible suites, so a server that supports the version has something to pick.
COMMON_SUITES = [0xC02F, 0xC030, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035, 0x003C, 0x003D, 0x000A, 0x0005,
                 0x0004, 0x0016, 0x0033, 0x0039, 0x0032, 0x0038]
WEAK_CLASSES: dict[str, list[int]] = {
    "RC4": [0x0005, 0x0004, 0xC011, 0xC007, 0xC002, 0xC00C],
    "3DES": [0x000A, 0x0016, 0x0013, 0xC012, 0xC008, 0xC003, 0xC00D],
    "EXPORT": [0x0003, 0x0006, 0x0008, 0x0011, 0x0014, 0x0017, 0x0019],
    "NULL": [0x0001, 0x0002, 0x003B, 0xC010, 0xC006, 0xC001, 0xC00B],
    "anonymous DH": [0x0018, 0x001B, 0x0034, 0x003A, 0xC015, 0xC018],
}


def client_hello(version: int, suites: list[int], sni: str | None) -> bytes:
    exts = b""
    if version >= 0x0301:
        if sni and not guard.is_ip_literal(sni):
            name = sni.encode("idna")
            entry = b"\x00" + struct.pack(">H", len(name)) + name
            exts += struct.pack(">HH", 0, len(entry) + 2) + struct.pack(">H", len(entry)) + entry
        groups = struct.pack(">HHH", 0x001D, 0x0017, 0x0018)
        exts += struct.pack(">HH", 10, len(groups) + 2) + struct.pack(">H", len(groups)) + groups
        exts += struct.pack(">HH", 11, 2) + b"\x01\x00"
        if version >= 0x0303:
            algs = b"".join(struct.pack(">H", a) for a in (0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603, 0x0201))
            exts += struct.pack(">HH", 13, len(algs) + 2) + struct.pack(">H", len(algs)) + algs
    body = (struct.pack(">H", version) + os.urandom(32) + b"\x00"
            + struct.pack(">H", 2 * len(suites)) + b"".join(struct.pack(">H", s) for s in suites) + b"\x01\x00")
    if exts:
        body += struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    rec_version = 0x0300 if version == 0x0300 else 0x0301
    return b"\x16" + struct.pack(">HH", rec_version, len(hs)) + hs


def parse_server_hello(data: bytes) -> tuple[bool, int | None, int | None]:
    """(accepted, server version, chosen cipher suite)."""
    if len(data) >= 6 and data[0] == 0x16 and data[5] == 0x02 and len(data) >= 44:
        version = struct.unpack(">H", data[9:11])[0]
        sid = data[43]
        off = 44 + sid
        cipher = struct.unpack(">H", data[off:off + 2])[0] if len(data) >= off + 2 else None
        return True, version, cipher
    return False, None, None


async def hello_probe(net: Net, host: str, port: int, version: int, suites: list[int], sni: str | None
                      ) -> tuple[bool, int | None, int | None]:
    try:
        r, w, _ip, release = await net.open(host, port)
    except (OSError, TimeoutError, guard.BlockedAddress):
        return False, None, None
    try:
        w.write(client_hello(version, suites, sni))
        await w.drain()
        data = b""
        try:
            while len(data) < 64:
                chunk = await asyncio.wait_for(r.read(4096), net.read_timeout)
                if not chunk:
                    break
                data += chunk
                if data[:1] == b"\x15":  # alert: handshake refused
                    break
        except (TimeoutError, OSError):
            pass
        return parse_server_hello(data)
    except (OSError, TimeoutError):
        return False, None, None
    finally:
        w.close()
        release()


def _ctx(version: ssl.TLSVersion) -> ssl.SSLContext:
    ctx = unverified_ctx()
    ctx.minimum_version = ctx.maximum_version = version
    return ctx


async def handshake(net: Net, host: str, port: int, sni: str | None, ctx: ssl.SSLContext):
    """(der cert, negotiated (protocol, cipher, bits)) or raises."""
    r, w, _ip, release = await net.open(host, port, tls=True, sni=sni, ctx=ctx)
    try:
        obj = w.get_extra_info("ssl_object")
        return obj.getpeercert(binary_form=True), obj.cipher(), obj.version()
    finally:
        w.close()
        release()
        try:
            await asyncio.wait_for(w.wait_closed(), 1)
        except (OSError, TimeoutError, ssl.SSLError):
            pass


def hostname_matches(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.count(".") == pattern.count(".") and host.endswith(pattern[1:])
    return pattern == host


def describe_cert(der: bytes, host: str, now: datetime | None = None) -> dict:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    now = now or datetime.now(UTC).replace(tzinfo=None)
    cert = x509.load_der_x509_certificate(der)
    cn = next((a.value for a in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)), "")
    issuer_cn = next((a.value for a in cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)), "")
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    names = sans or ([cn] if cn else [])
    key = cert.public_key()
    key_bits = key.key_size if isinstance(key, rsa.RSAPublicKey | ec.EllipticCurvePublicKey) else None
    key_type = "RSA" if isinstance(key, rsa.RSAPublicKey) else "EC" if isinstance(key, ec.EllipticCurvePublicKey) \
        else type(key).__name__
    sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""
    not_after = cert.not_valid_after_utc.replace(tzinfo=None)
    not_before = cert.not_valid_before_utc.replace(tzinfo=None)
    return {
        "subject": cn, "issuer": issuer_cn, "self_signed": cert.issuer == cert.subject, "names": names[:20],
        "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
        "expired": not_after < now, "days_left": (not_after - now).days,
        "hostname_ok": any(hostname_matches(n, host) for n in names) if not guard.is_ip_literal(host) else None,
        "key_type": key_type, "key_bits": key_bits, "signature": sig,
    }


async def probe(net: Net, host: str, port: int, sni: str | None = None, *, full: bool = True) -> dict | None:
    """The TLS profile of host:port, or None when the port does not speak TLS."""
    sni = sni if sni is not None else (None if guard.is_ip_literal(host) else host)
    protocols: dict[str, bool | None] = {}
    der = cipher = None
    negotiated = None
    for name, ver in (("TLS1.3", ssl.TLSVersion.TLSv1_3), ("TLS1.2", ssl.TLSVersion.TLSv1_2)):
        try:
            d, c, v = await handshake(net, host, port, sni, _ctx(ver))
            protocols[name] = True
            if der is None:
                der, cipher, negotiated = d, c, v
        except (ssl.SSLError, OSError, TimeoutError, ValueError):
            protocols[name] = False
        except guard.BlockedAddress:
            return None
    if der is None:  # no modern TLS: maybe a legacy-only server; accept any version for the certificate
        try:
            ctx = unverified_ctx()
            ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            d, c, v = await handshake(net, host, port, sni, ctx)
            der, cipher, negotiated = d, c, v
        except (ssl.SSLError, OSError, TimeoutError, ValueError, guard.BlockedAddress):
            pass
    legacy: dict[str, bool] = {}
    for name, ver in VERSIONS.items():
        ok, srv_ver, _c = await hello_probe(net, host, port, ver, COMMON_SUITES, sni)
        legacy[name] = bool(ok and srv_ver == ver)
    protocols.update(legacy)
    if not any(protocols.values()) and der is None:
        return None
    out: dict = {"protocols": protocols, "negotiated": negotiated, "cipher": cipher[0] if cipher else None,
                 "weak_ciphers": [], "cert": None, "trusted": None, "verify_error": None}
    if full:
        for cls, suites in WEAK_CLASSES.items():
            ok, _v, _c = await hello_probe(net, host, port, 0x0303, suites, sni)
            if not ok:
                ok, _v, _c = await hello_probe(net, host, port, 0x0301, suites, sni)
            if ok:
                out["weak_ciphers"].append(cls)
    if der is not None:
        try:
            out["cert"] = describe_cert(der, sni or host)
        except Exception:  # unparsable certificate: report nothing rather than guess
            out["cert"] = None
        ctx = ssl.create_default_context()
        try:
            r, w, _ip, release = await net.open(host, port, tls=True, sni=sni, ctx=ctx)
            out["trusted"] = True
            w.close()
            release()
        except ssl.SSLCertVerificationError as e:
            out["trusted"] = False
            out["verify_error"] = (e.verify_message or str(e))[:120]
        except (ssl.SSLError, OSError, TimeoutError):
            pass
    return out
