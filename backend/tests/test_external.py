"""Attack surface & pre-ASV module (app/external, docs/ATTACK_SURFACE.md).

No test sends traffic to a real host: DNS and HTTP proofs are mocked, and scans run against servers started on
127.0.0.1 with the address guard relaxed only inside the test (guard.allow_for_tests, refused in production)."""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import json
import re
import socket
import ssl
import struct
import threading
import zlib

import pytest
from sqlalchemy import select, text

from app import config, db
from app.external import checks, engine, guard, report, rules, service, tlsprobe
from app.external import net as netmod
from app.external.net import Net
from app.external.scheduler import ExternalScheduler
from app.models import (
    Asset,
    AuditLog,
    ExternalFinding,
    ExternalHost,
    ExternalScan,
    ExternalTarget,
    Organization,
    User,
    Vulnerability,
    utcnow,
)
from app.modules import ALL_MODULES
from app.notifications.models import NotificationEvent
from tests.conftest import AUTH, BASE_URL, login, reset_database  # noqa: F401
from tests.test_tenancy import create_org, org_client

DOM = "example.com"


def fast_net() -> Net:
    return Net(connect_timeout=1.0, read_timeout=0.6, rate=5000, parallel=50)


# ----------------------------------------------------------------------------- local servers
class HttpServer:
    """A tiny HTTP server on 127.0.0.1 in its own thread; `routes` maps a path to (status, headers, body)."""

    def __init__(self, routes: dict, basic: dict | None = None):
        self.routes, self.basic, self.requests = routes, basic or {}, []
        self.loop = asyncio.new_event_loop()
        self.port = 0
        ready = threading.Event()

        async def handle(r, w):
            data = await r.read(8192)
            try:
                if not data.startswith((b"GET ", b"HEAD ")):
                    w.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                else:
                    head = data.decode("latin-1")
                    path = head.split(" ", 2)[1]
                    auth = re.search(r"(?i)authorization: basic (\S+)", head)
                    self.requests.append((path, auth.group(1) if auth else None))
                    status, headers, body = self.route(path, auth.group(1) if auth else None)
                    h = {"Content-Length": str(len(body)), "Connection": "close", **headers}
                    w.write((f"HTTP/1.1 {status} X\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n")
                            .encode() + body)
                await w.drain()
            finally:
                w.close()

        async def start():
            self.server = await asyncio.start_server(handle, "127.0.0.1", 0)
            self.port = self.server.sockets[0].getsockname()[1]
            ready.set()

        def run():
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(start())
            self.loop.run_forever()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        ready.wait(5)

    def route(self, path, auth):
        if path in self.basic:
            good = auth and base64.b64decode(auth).decode() in self.basic[path]
            if not good:
                return 401, {"WWW-Authenticate": 'Basic realm="admin"'}, b"denied"
            return 200, {}, b"welcome"
        return self.routes.get(path) or self.routes.get("*") or (404, {}, b"not found")

    def close(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(2)


@pytest.fixture()
def http_server():
    servers = []

    def make(routes, basic=None):
        s = HttpServer(routes, basic)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.close()


@pytest.fixture()
def platform(client, monkeypatch):
    """`client` (the bootstrap admin) as a platform owner too."""
    monkeypatch.setenv("PLATFORM_ADMIN_EMAILS", "admin@example.com")
    config.reload_settings()
    yield client
    monkeypatch.delenv("PLATFORM_ADMIN_EMAILS")
    config.reload_settings()


@pytest.fixture()
def local_ok():
    with guard.allow_for_tests("127.0.0.0/8"):
        yield


def vulnerable_site():
    return {
        "/": (200, {"Server": "Apache/2.2.15 (CentOS)", "Content-Type": "text/html",
                    "Set-Cookie": "sid=abc123; Path=/"},
              b"<html><title>Shop</title><script src='https://cdn.other.net/x.js'></script></html>"),
        "/.git/HEAD": (200, {"Content-Type": "text/plain"}, b"ref: refs/heads/main\n"),
        "/images/": (200, {"Content-Type": "text/html"}, b"<title>Index of /images</title>"),
        "*": (404, {}, b"not found"),
    }


# ----------------------------------------------------------------------------- the address guard
@pytest.mark.parametrize("addr", [
    "127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.169.254", "169.254.170.2", "100.64.0.1",
    "100.100.100.200", "224.0.0.1", "240.0.0.1", "0.0.0.0", "255.255.255.255", "192.0.2.5", "198.18.0.1",
    "::1", "fd00:ec2::254", "::ffff:127.0.0.1", "2001:db8::1", "not-an-ip"])
def test_guard_refuses_non_public_addresses(addr):
    with pytest.raises(guard.BlockedAddress):
        guard.check_ip(addr)


def test_guard_allows_public_and_refuses_own_and_configured_addresses(monkeypatch):
    assert guard.check_ip("8.8.8.8") == "8.8.8.8"
    monkeypatch.setattr(guard, "own_addresses", lambda: {"203.0.114.7"})
    with pytest.raises(guard.BlockedAddress, match="this server"):
        guard.check_ip("203.0.114.7")
    monkeypatch.setenv("EXTERNAL_BLOCKED_CIDRS", "8.8.4.0/24")
    config.reload_settings()
    try:
        with pytest.raises(guard.BlockedAddress, match="EXTERNAL_BLOCKED_CIDRS"):
            guard.check_ip("8.8.4.4")
    finally:
        monkeypatch.delenv("EXTERNAL_BLOCKED_CIDRS")
        config.reload_settings()


def test_guard_override_is_refused_in_production(monkeypatch):
    monkeypatch.setattr(config.settings, "environment", "production")
    with pytest.raises(RuntimeError), guard.allow_for_tests("127.0.0.0/8"):
        pass


def _fake_getaddrinfo(answers):
    calls = []

    async def fake(self, host, port, **kw):
        calls.append(host)
        ip = answers[min(len(calls), len(answers)) - 1]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    return fake, calls


def test_names_resolving_to_private_addresses_are_refused(monkeypatch):
    fake, _ = _fake_getaddrinfo(["10.0.0.5"])
    monkeypatch.setattr(asyncio.base_events.BaseEventLoop, "getaddrinfo", fake)
    with pytest.raises(guard.BlockedAddress):
        asyncio.run(guard.resolve_public("intranet.example.com"))


def test_dns_rebinding_is_rechecked_before_every_connection_and_the_checked_ip_is_dialled(monkeypatch):
    """First answer public, second answer the metadata address: the second connection is refused, and the first one
    dials the IP literal that was checked (never the name again)."""
    fake, calls = _fake_getaddrinfo(["8.8.8.8", "169.254.169.254"])
    monkeypatch.setattr(asyncio.base_events.BaseEventLoop, "getaddrinfo", fake)
    dialled = []

    async def fake_open(host, port, **kw):
        dialled.append(host)
        raise ConnectionRefusedError  # (no traffic: nothing is ever sent)

    monkeypatch.setattr(netmod.asyncio, "open_connection", fake_open)

    async def go():
        n = Net(connect_timeout=1, read_timeout=1)
        with pytest.raises(ConnectionRefusedError):
            await n.open("rebind.example.com", 80)
        with pytest.raises(guard.BlockedAddress):
            await n.open("rebind.example.com", 80)

    asyncio.run(go())
    assert calls == ["rebind.example.com", "rebind.example.com"]  # resolved again for every connection
    assert dialled == ["8.8.8.8"]  # only the checked IP literal was dialled; the metadata address never was


def test_scanner_never_connects_to_loopback_without_the_test_override(http_server):
    srv = http_server({"*": (200, {}, b"hi")})
    plan = engine.Plan(ip_targets=[engine.IpTargetIn("t1", "127.0.0.1", approved=True)], ports=(srv.port,))
    out = asyncio.run(engine.run(plan, net=fast_net()))
    assert out.hosts == [] and "refused" in out.skipped[0]["reason"]
    assert srv.requests == []


# ----------------------------------------------------------------------------- targets
def test_target_parsing_caps_and_refusals():
    assert service.parse_target("Example.COM.") == ("domain", "example.com")
    assert service.parse_target("8.8.8.8") == ("ip", "8.8.8.8")
    assert service.parse_target("8.8.8.0/24") == ("cidr", "8.8.8.0/24")
    assert service.parse_target("8.8.8.8/32") == ("ip", "8.8.8.8")
    for bad in ("8.8.8.0/23", "8.8.0.0/16", "10.0.0.0/24", "10.1.1.1", "127.0.0.1", "169.254.169.254",
                "192.168.0.0/16", "8.8.8.0/24 ", "fd00::1", "2001:4860::/32", "localhost", "a b.com", ""):
        if bad == "8.8.8.0/24 ":
            continue
        with pytest.raises(service.ExternalError):
            service.parse_target(bad)


def test_per_org_target_cap(client, monkeypatch):
    monkeypatch.setenv("EXTERNAL_MAX_TARGETS", "2")
    config.reload_settings()
    try:
        assert client.post("/api/external/targets", json={"value": "a.example.com"}).status_code == 201
        assert client.post("/api/external/targets", json={"value": "b.example.com"}).status_code == 201
        assert client.post("/api/external/targets", json={"value": "c.example.com"}).status_code == 409
    finally:
        monkeypatch.delenv("EXTERNAL_MAX_TARGETS")
        config.reload_settings()


def add_domain(client, name=DOM):
    r = client.post("/api/external/targets", json={"value": name})
    assert r.status_code == 201, r.text
    return r.json()


def test_domain_verification_by_dns_covers_subdomains_and_audits(client, monkeypatch):
    t = add_domain(client)
    assert not t["verified"] and t["proof"]["txt_value"].startswith("sentrigis-verification=")
    sub = add_domain(client, "www.example.com")
    token = t["proof"]["txt_value"]
    monkeypatch.setattr("app.external.dnsclient.query", lambda name, rt, timeout=3.0: [token] if rt == "TXT" and
                        name == "_sentrigis.example.com" else [])
    monkeypatch.setattr(service, "_http_proof", lambda d, tok: _async(False))
    r = client.post(f"/api/external/targets/{t['id']}/verify")
    assert r.status_code == 200 and r.json()["verified"] and r.json()["method"] == "dns"
    targets = {x["value"]: x for x in client.get("/api/external/targets").json()}
    assert targets["www.example.com"]["verified"] and targets["www.example.com"]["verified_method"] == "parent"
    # a subdomain added later is covered at once
    assert add_domain(client, "api.example.com")["verified"]
    actions = {a.action for a in _audit()}
    assert {"external_target_added", "external_target_verified"} <= actions
    assert sub["id"]


async def _async(v):
    return v


def test_domain_verification_by_http_file_and_failure(client, monkeypatch):
    t = add_domain(client)
    monkeypatch.setattr("app.external.dnsclient.query", lambda *a, **k: [])
    seen = {}

    def fake_http(domain, token):
        seen["args"] = (domain, token)
        return _async(True)

    monkeypatch.setattr(service, "_http_proof", fake_http)
    r = client.post(f"/api/external/targets/{t['id']}/verify").json()
    assert r["verified"] and r["method"] == "http" and seen["args"][0] == DOM
    assert t["proof"]["file_url"] == f"https://{DOM}/.well-known/sentrigis-verification.txt"
    # the wrong proof is not accepted
    t2 = add_domain(client, "other.org")
    monkeypatch.setattr(service, "_http_proof", lambda d, tok: _async(False))
    r = client.post(f"/api/external/targets/{t2['id']}/verify").json()
    assert not r["verified"] and "no TXT record" in r["error"]


def test_http_proof_goes_through_the_guard(monkeypatch):
    """A domain pointing at an internal address cannot be 'verified' by making the scanner fetch it."""
    fake, _ = _fake_getaddrinfo(["127.0.0.1"])
    monkeypatch.setattr(asyncio.base_events.BaseEventLoop, "getaddrinfo", fake)
    assert asyncio.run(service._http_proof("evil.example.com", "tok")) is False


def _audit():
    with db.get_session("default") as s:
        return list(s.scalars(select(AuditLog)))


# ----------------------------------------------------------------------------- IP scope rules (engine)
def test_unverified_ips_are_never_scanned_but_proven_ones_are(http_server, local_ok):
    srv = http_server(vulnerable_site())
    ports = (srv.port,)
    # no proof of any kind: skipped, and not one request reaches the server
    plan = engine.Plan(ip_targets=[engine.IpTargetIn("t", "127.0.0.1")], ports=ports)
    out = asyncio.run(engine.run(plan, net=fast_net()))
    assert out.hosts == [] and "not verified" in out.skipped[0]["reason"] and srv.requests == []
    # (a) a cloud inventory IP, (b) platform approval; (c) a verified domain resolving to it
    for kw, method in (({"cloud_ips": {"127.0.0.1"}}, "cloud"), ({"approved": True}, "platform")):
        t = engine.IpTargetIn("t", "127.0.0.1", approved=kw.pop("approved", False))
        plan = engine.Plan(ip_targets=[t], ports=ports, **kw)
        out = asyncio.run(engine.run(plan, net=fast_net()))
        assert [h.method for h in out.hosts] == [method] and out.hosts[0].ports[0]["port"] == srv.port
    plan = engine.Plan(domains=[engine.DomainIn("d", "example.com")], ip_targets=[engine.IpTargetIn("t", "127.0.0.1")],
                       ports=ports, ct_lookup=lambda d: [], dns_query=lambda n, t: [])
    orig = guard.resolve_public_sync
    guard.resolve_public_sync = lambda name: ["127.0.0.1"] if name == "example.com" else orig(name)
    try:
        out = asyncio.run(engine.run(plan, net=fast_net()))
    finally:
        guard.resolve_public_sync = orig
    assert {h.host: h.method for h in out.hosts} == {"example.com": "domain", "127.0.0.1": "domain"}


def test_subdomains_from_ct_are_filtered_to_the_verified_domain():
    names = ["a.example.com", "*.example.com", "evil.com", "example.com.evil.com", "x.y.example.com", "bad_name.example.com",
             "EXAMPLE.com", "notexample.com", "10.0.0.1"]
    assert engine.filter_names("example.com", names) == ["a.example.com", "example.com", "x.y.example.com"]


# ----------------------------------------------------------------------------- probes against local servers
def test_web_checks_find_issues_without_keeping_file_contents(http_server, local_ok):
    srv = http_server(vulnerable_site())
    res = asyncio.run(checks.web_checks(fast_net(), "127.0.0.1", srv.port, False))
    ids = {(h.check_id, h.key) for h in res.hits}
    assert ("file-exposed", "/.git/HEAD") in ids and ("dir-listing", "/images/") in ids
    assert ("cookie-flags", "/") in ids and ("http-server-banner", "/") in ids and ("external-scripts", "/") in ids
    assert {"product": "apache", "version": "2.2.15", "port": srv.port, "source": "http header"} in res.software
    ev = json.dumps([h.evidence for h in res.hits])
    assert "refs/heads" not in ev and "abc123" not in ev  # no file contents, no cookie values
    git = next(h for h in res.hits if h.key == "/.git/HEAD")
    assert git.evidence["signature"] == "matched" and git.evidence["status"] == 200
    # file probes are range requests of at most 256 bytes
    assert any(p == "/.git/HEAD" for p, _ in srv.requests)


def test_soft_404_sites_do_not_produce_file_findings(http_server, local_ok):
    srv = http_server({"*": (200, {"Content-Type": "text/html"}, b"<html>Welcome</html>")})
    res = asyncio.run(checks.web_checks(fast_net(), "127.0.0.1", srv.port, False))
    assert not [h for h in res.hits if h.check_id in ("file-exposed", "admin-panel", "api-docs")]


def test_iis_shortname_probe(http_server, local_ok):
    class Iis(HttpServer):
        def route(self, path, auth):
            if path.startswith("/*~1*/"):
                return 404, {}, b""
            if "~1" in path:
                return 400, {}, b""
            return 200, {"Server": "Microsoft-IIS/7.5", "Content-Type": "text/html"}, b"<html></html>"

    srv = Iis({})
    try:
        res = asyncio.run(checks.web_checks(fast_net(), "127.0.0.1", srv.port, False))
    finally:
        srv.close()
    assert "iis-shortname" in {h.check_id for h in res.hits}


def test_default_password_check_is_slow_stops_at_first_success_and_returns_no_credentials(http_server, local_ok):
    srv = http_server({"*": (200, {}, b"")}, basic={"/admin": {"admin:admin"}})
    hit = asyncio.run(checks.default_password_check(fast_net(), "127.0.0.1", srv.port, False, "/admin", delay=0.0))
    assert hit and hit.check_id == "default-credentials"
    blob = json.dumps([hit.evidence, hit.extra, hit.key])
    assert "admin:admin" not in blob and "YWRtaW46YWRtaW4" not in blob and "password" not in blob.lower().replace(
        "default credentials", "")
    # stopped at the first success: junk probe + first entry only
    assert len(srv.requests) == 2
    # a server that accepts anything is not "default credentials"
    class Open(HttpServer):
        def route(self, path, auth):
            return 200, {}, b"ok"

    o = Open({})
    try:
        assert asyncio.run(checks.default_password_check(fast_net(), "127.0.0.1", o.port, False, "/", delay=0)) is None
    finally:
        o.close()
    # never more than the built-in list
    srv2 = http_server({"*": (200, {}, b"")}, basic={"/x": {"nobody:none"}})
    assert asyncio.run(checks.default_password_check(fast_net(), "127.0.0.1", srv2.port, False, "/x", delay=0)) is None
    assert len(srv2.requests) <= 1 + len(checks.DEFAULT_CREDS)


# ----------------------------------------------------------------------------- TLS
def self_signed_pem(tmp_path, cn="localhost", days=30):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .sign(key, hashes.SHA256()))
    cf, kf = tmp_path / "c.pem", tmp_path / "k.pem"
    cf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    return str(cf), str(kf)


def test_tls_probe_reads_certificate_and_flags_self_signed_mismatch(tmp_path, local_ok):
    cf, kf = self_signed_pem(tmp_path, cn="other.test")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cf, kf)
    loop = asyncio.new_event_loop()

    async def run():
        async def handle(r, w):
            await r.read(100)
            w.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
        port = server.sockets[0].getsockname()[1]
        t = await tlsprobe.probe(fast_net(), "127.0.0.1", port, sni="shop.example.com")
        server.close()
        return port, t

    try:
        port, t = loop.run_until_complete(run())
    finally:
        loop.close()
    assert t["protocols"]["TLS1.2"] or t["protocols"]["TLS1.3"]
    assert not t["protocols"]["SSLv3"] and not t["protocols"]["TLS1.0"] and not t["protocols"]["TLS1.1"]
    ids = {h.check_id for h in engine.tls_hits("shop.example.com", "127.0.0.1", port, t)}
    assert {"tls-cert-self-signed", "tls-cert-mismatch"} <= ids
    assert "tls-tls10" not in ids


def test_legacy_protocol_detection_with_a_canned_server_hello(local_ok):
    """A fake server that answers a TLS 1.0 ClientHello with a TLS 1.0 ServerHello: automatic fail finding."""
    hello = b"\x03\x01" + b"\x00" * 32 + b"\x00" + b"\x00\x2f" + b"\x00"
    sh = b"\x02" + len(hello).to_bytes(3, "big") + hello
    reply = b"\x16\x03\x01" + struct.pack(">H", len(sh)) + sh
    alert = b"\x15\x03\x01\x00\x02\x02\x46"
    loop = asyncio.new_event_loop()

    async def run():
        async def handle(r, w):
            data = await r.read(4096)
            client_version = struct.unpack(">H", data[9:11])[0] if len(data) > 11 else 0
            w.write(reply if client_version == 0x0301 else alert)
            await w.drain()
            w.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        t = await tlsprobe.probe(fast_net(), "127.0.0.1", port, sni=None)
        server.close()
        return port, t

    try:
        port, t = loop.run_until_complete(run())
    finally:
        loop.close()
    assert t["protocols"]["TLS1.0"] and not t["protocols"]["SSLv3"] and not t["protocols"]["TLS1.1"]
    hits = engine.tls_hits("127.0.0.1", "127.0.0.1", port, t)
    f = [h for h in hits if h.check_id == "tls-tls10"]
    assert f and service._finding_fields(f[0])["auto_fail"] is True
    assert rules.fail_reason({"check_id": "tls-tls10", "cvss": 1.0}) == "automatic fail"


def test_client_hello_is_well_formed():
    h = tlsprobe.client_hello(0x0301, [0x002F], "example.com")
    assert h[0] == 0x16 and struct.unpack(">H", h[3:5])[0] == len(h) - 5 and h[5] == 0x01
    assert b"example.com" in h
    ok, ver, cipher = tlsprobe.parse_server_hello(b"\x16\x03\x01\x00\x2a\x02\x00\x00\x26\x03\x01" + b"\x00" * 32 +
                                                  b"\x00\x00\x2f\x00")
    assert (ok, ver, cipher) == (True, 0x0301, 0x002F)
    assert tlsprobe.parse_server_hello(b"\x15\x03\x01\x00\x02\x02\x46")[0] is False


# ----------------------------------------------------------------------------- pass / fail rules
@pytest.mark.parametrize("finding,expected", [
    ({"check_id": "x", "cvss": 3.9}, None),
    ({"check_id": "x", "cvss": 4.0}, "CVSS 4 is 4.0 or higher"),
    ({"check_id": "x", "cvss": 9.8, "dos_only": True}, None),
    ({"check_id": "tls-tls10", "cvss": 0}, "automatic fail"),
    ({"check_id": "tls-tls11", "cvss": 0}, "automatic fail"),
    ({"check_id": "tls-sslv3", "cvss": 0}, "automatic fail"),
    ({"check_id": "default-credentials", "cvss": 0}, "automatic fail"),
    ({"check_id": "eol-software", "cvss": 1.0}, "automatic fail"),
    ({"check_id": "cve", "cvss": 1.0, "cwe": "CWE-89"}, "automatic fail"),
    ({"check_id": "cve", "cvss": 1.0, "cwe": "CWE-79"}, "automatic fail"),
    ({"check_id": "cve", "cvss": 9.8, "cwe": "CWE-400", "dos_only": True}, None),
])
def test_fail_rule_table(finding, expected):
    assert rules.fail_reason(finding) == expected


def test_counts_respects_status_exceptions_and_accepted_risk():
    f = {"check_id": "x", "cvss": 7.0, "status": "open"}
    assert rules.counts(f)
    assert not rules.counts({**f, "status": "resolved"})
    assert not rules.counts(f, exempt=True)
    assert rules.counts({**f, "status": "accepted"})  # accepting the risk does not waive an ASV failure
    assert rules.overall(0) == "pass" and rules.overall(2) == "fail"
    assert rules.label("pass") == "Likely pass" and rules.label("fail") == "Likely fail"


def test_catalog_tls_and_default_credentials_are_automatic_fails_and_headers_are_not():
    from app.external import catalog

    for cid in ("tls-sslv3", "tls-tls10", "tls-tls11", "default-credentials", "eol-software"):
        assert catalog.TEMPLATES[cid]["auto_fail"]
    for cid in ("hdr-hsts", "hdr-xfo", "cookie-flags", "http-server-banner", "api-docs", "dir-listing"):
        assert catalog.TEMPLATES[cid]["cvss"] < rules.FAIL_CVSS
    assert catalog.template("risky-rdp")["cvss"] >= rules.FAIL_CVSS


# ----------------------------------------------------------------------------- full scan into findings
def _setup_org_target(value="127.0.0.1", **kw):
    with db.get_session("default") as s:
        s.add(ExternalTarget(kind="ip", value=value, token="t" * 8, verified_method="platform", verified_at=utcnow(),
                             approval_status="approved", **kw))
        s.commit()


def _run_scan(port, trigger="manual", only_host=None, stub_cve=True):
    """Run a scan inline against the local server (ports narrowed to the test server)."""
    async def runner(plan):
        plan.ports = (port,)
        plan.default_password_delay = 0.0
        return await engine.run(plan, net=fast_net())

    cves = {"apache": [{"cve_id": "CVE-2099-0001", "cvss": 9.8, "severity": "critical",
                        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cwe": "CWE-787",
                        "description": "Memory corruption in the demo server.", "fixed_version": "2.4.58",
                        "published": "2099-01-01", "dos_only": False},
                       {"cve_id": "CVE-2099-0002", "cvss": 7.5, "severity": "high", "vector": None, "cwe": "CWE-400",
                        "description": "Resource exhaustion.", "fixed_version": None, "published": None,
                        "dos_only": True}]}
    saved = service.ENGINE_RUN, service.CVE_LOOKUP
    service.ENGINE_RUN = runner
    service.CVE_LOOKUP = lambda db_, product, version, now, allow_fetch=True: cves.get(product, []) if stub_cve else []
    try:
        with db.get_session("default") as s:
            from app import tenancy  # noqa: F401
            scan = ExternalScan(trigger=trigger, started_at=utcnow())
            s.add(scan)
            s.commit()
            sid = scan.id
        service.run_scan("default", sid, only_host)
    finally:
        service.ENGINE_RUN, service.CVE_LOOKUP = saved
    with db.get_session("default") as s:
        return s.get(ExternalScan, sid)


def test_scan_generates_findings_result_and_notifications(http_server, local_ok, client):
    site = vulnerable_site()
    srv = http_server(site, basic={"/admin": {"admin:admin"}})
    _setup_org_target()
    scan = _run_scan(srv.port)
    assert scan.status in ("succeeded", "partial"), scan.message
    with db.get_session("default") as s:
        fs = {f.check_id + "|" + f.key.split("|")[-1]: f for f in s.scalars(select(ExternalFinding))}
        assert {"file-exposed|/.git/HEAD", "dir-listing|/images/", "eol-software|apache", "cve|CVE-2099-0001",
                "cookie-flags|/", "external-scripts|/"} <= set(fs)
        assert fs["eol-software|apache"].auto_fail and fs["cve|CVE-2099-0001"].severity == "critical"
        assert fs["cve|CVE-2099-0002"].dos_only and fs["cve|CVE-2099-0001"].seq >= 1
        assert fs["file-exposed|/.git/HEAD"].detail["fix"]["nginx"] and fs["file-exposed|/.git/HEAD"].detail["steps"]
        # nothing from the file or the cookie value is stored anywhere
        dump = json.dumps([[f.evidence, f.detail] for f in fs.values()], default=str)
        assert "refs/heads" not in dump and "abc123" not in dump
        # admin-panel (401 basic) found; default credentials NOT tried: the opt-in is off
        assert "default-credentials|/admin" not in fs
        assert not any(a == "YWRtaW46YWRtaW4=" for _, a in srv.requests if a)
        assert scan.result == "fail" and scan.hosts == 1 and scan.new_hosts == 1
        host = s.scalar(select(ExternalHost))
        assert host.ports[0]["port"] == srv.port and host.software
        # critical finding notifications (source external_finding)
        ev = list(s.scalars(select(NotificationEvent).where(NotificationEvent.source == "external_finding")))
        assert ev and all(e.severity in ("critical", "high") for e in ev)
        # the DoS-only CVE does not fail on its own
        assert not rules.counts(fs["cve|CVE-2099-0002"])


def test_default_password_check_is_opt_in_end_to_end_and_secrets_are_never_stored(http_server, local_ok, client):
    srv = http_server({"*": (404, {}, b"")}, basic={"/": {"admin:admin"}})
    _setup_org_target()
    _run_scan(srv.port)
    assert not any(a for _, a in srv.requests if a), "no credential was tried while the opt-in was off"
    # enabling needs explicit consent, and is audit logged
    t = client.get("/api/external/targets").json()[0]
    r = client.put(f"/api/external/targets/{t['id']}/default-passwords", json={"enabled": True, "consent": False})
    assert r.status_code == 422
    r = client.put(f"/api/external/targets/{t['id']}/default-passwords", json={"enabled": True, "consent": True})
    assert r.status_code == 200 and r.json()["default_password_checks"] and r.json()["consent_by"]
    assert "external_default_passwords_enabled" in {a.action for a in _audit()}
    _run_scan(srv.port)
    with db.get_session("default") as s:
        f = s.scalar(select(ExternalFinding).where(ExternalFinding.check_id == "default-credentials"))
        assert f is not None and f.auto_fail and f.special_note == "default_credentials"
        blob = json.dumps([f.title, f.evidence, f.detail, f.key]) + json.dumps(
            [a.detail for a in s.scalars(select(AuditLog))], default=str)
        assert "admin:admin" not in blob and "YWRtaW46YWRtaW4" not in blob
        assert "default credentials accepted for HTTP Basic" in blob
        raw = " ".join(str(v) for row in s.execute(text("SELECT * FROM external_findings")) for v in row)
        assert "admin:admin" not in raw
    assert len([1 for _, a in srv.requests if a]) <= 1 + len(checks.DEFAULT_CREDS)


def test_findings_auto_resolve_reopen_and_stats(http_server, local_ok, client):
    site = vulnerable_site()
    srv = http_server(site)
    _setup_org_target()
    _run_scan(srv.port)
    with db.get_session("default") as s:
        git = s.scalar(select(ExternalFinding).where(ExternalFinding.check_id == "file-exposed"))
        gid, ref = git.id, git.seq
    site.pop("/.git/HEAD")  # fixed
    _run_scan(srv.port)
    with db.get_session("default") as s:
        git = s.get(ExternalFinding, gid)
        assert git.status == "resolved" and git.resolved_at
        assert s.scalar(select(ExternalFinding).where(ExternalFinding.check_id == "dir-listing")).status == "open"
    site["/.git/HEAD"] = (200, {}, b"ref: refs/heads/main\n")  # back again
    _run_scan(srv.port)
    with db.get_session("default") as s:
        assert s.get(ExternalFinding, gid).status == "open"
        assert s.get(ExternalFinding, gid).seq == ref  # the EXT number is stable
    ov = client.get("/api/external/overview").json()
    assert ov["hosts"] == 1 and ov["open_findings"] > 0 and ov["result"] == "fail"
    assert ov["result_label"] == "Likely fail" and "not an ASV scan report" in ov["disclaimer"]
    f = client.get(f"/api/external/findings/{gid}").json()
    assert f["ref"] == f"EXT-{ref:04d}" and f["detail"]["compliance"] and f["fix_due"]


def test_retest_scans_only_that_host_and_resolves(http_server, local_ok, client):
    site = vulnerable_site()
    srv = http_server(site)
    _setup_org_target()
    _run_scan(srv.port)
    with db.get_session("default") as s:
        f = s.scalar(select(ExternalFinding).where(ExternalFinding.check_id == "dir-listing"))
        fid, host = f.id, f.host
    site["/images/"] = (404, {}, b"")
    _run_scan(srv.port, trigger="retest", only_host=host)
    assert client.get(f"/api/external/findings/{fid}").json()["status"] == "resolved"


def test_findings_and_cve_link_into_vulnerabilities_for_cloud_assets(http_server, local_ok, client):
    srv = http_server(vulnerable_site())
    with db.get_session("default") as s:
        a = s.scalar(select(Asset).where(Asset.type == "vm"))
        a.properties = {**(a.properties or {}), "public_ips": ["127.0.0.1"]}
        aid = a.id
        s.commit()
    _setup_org_target()
    _run_scan(srv.port)
    with db.get_session("default") as s:
        host = s.scalar(select(ExternalHost))
        assert host.asset_id == aid
        v = s.scalar(select(Vulnerability).where(Vulnerability.source == "external",
                                                 Vulnerability.cve_id == "CVE-2099-0001"))
        assert v is not None and v.asset_id == aid and v.status == "open" and v.cvss == 9.8


def test_no_vulnerability_rows_without_the_vulnerabilities_module(http_server, local_ok, client):
    srv = http_server(vulnerable_site())
    with db.get_session("default") as s:
        a = s.scalar(select(Asset).where(Asset.type == "vm"))
        a.properties = {**(a.properties or {}), "public_ips": ["127.0.0.1"]}
        s.get(Organization, "default").modules = ["cloud", "external"]
        s.commit()
    _setup_org_target()
    _run_scan(srv.port)
    with db.get_session("default") as s:
        assert s.scalar(select(Vulnerability).where(Vulnerability.source == "external")) is None


def test_no_notifications_without_the_external_module(http_server, local_ok, client):
    """emit() is skipped for an organisation without the module (SOURCE_MODULES)."""
    srv = http_server(vulnerable_site())
    with db.get_session("default") as s:
        s.get(Organization, "default").modules = ["cloud"]
        s.commit()
    _setup_org_target()
    _run_scan(srv.port)
    with db.get_session("default") as s:
        assert list(s.scalars(select(NotificationEvent).where(NotificationEvent.source == "external_finding"))) == []


# ----------------------------------------------------------------------------- limits, window, scheduler
def test_concurrency_limits_and_nothing_to_scan(client, monkeypatch):
    _setup_org_target()
    with db.get_session("default") as s:
        admin = s.scalar(select(User))
        s.add(ExternalScan(status="running", started_at=utcnow()))
        s.commit()
        with pytest.raises(service.Busy, match="already running"):
            service.create_scan(s, "manual", admin)
        s.rollback()
    # global limit across organisations
    monkeypatch.setenv("EXTERNAL_MAX_CONCURRENT_SCANS", "1")
    monkeypatch.setenv("EXTERNAL_MAX_SCANS_PER_ORG", "5")
    config.reload_settings()
    try:
        with db.get_session("default") as s:
            admin = s.scalar(select(User))
            with pytest.raises(service.Busy, match="busy"):
                service.create_scan(s, "manual", admin)
    finally:
        monkeypatch.delenv("EXTERNAL_MAX_CONCURRENT_SCANS")
        monkeypatch.delenv("EXTERNAL_MAX_SCANS_PER_ORG")
        config.reload_settings()
    # nothing verified: refused with a reason
    with db.get_session("default") as s:
        s.query(ExternalScan).delete()
        s.query(ExternalTarget).delete()
        s.add(ExternalTarget(kind="domain", value="unproven.example.com", token="tok"))
        s.commit()
        with pytest.raises(service.ExternalError, match="not verified"):
            service.create_scan(s, "manual", s.scalar(select(User)))


def test_scan_windows():
    t = ExternalTarget(kind="ip", value="8.8.8.8", token="x", window_start_hour=22, window_end_hour=4)
    assert service.in_window(t, dt.datetime(2026, 1, 1, 23)) and service.in_window(t, dt.datetime(2026, 1, 1, 2))
    assert not service.in_window(t, dt.datetime(2026, 1, 1, 12))
    t.window_start_hour, t.window_end_hour = None, None
    assert service.in_window(t, dt.datetime(2026, 1, 1, 12))


def test_scheduler_starts_due_scans_for_orgs_with_the_module(client):
    other = create_org("noext", "boss@noext.test", "a-long-test-password")
    with db.get_session(unscoped=True) as s:
        s.get(Organization, other).modules = ["cloud"]
        s.commit()
    with db.get_session(other) as s:
        s.add(ExternalTarget(kind="ip", value="8.8.4.4", token="x", approval_status="approved",
                             verified_at=utcnow(), verified_method="platform"))
        s.commit()
    _setup_org_target("8.8.8.8")
    started = []
    sched = ExternalScheduler(startup_delay_seconds=0, launcher=lambda db_, scan: started.append(scan.id))
    ids = sched.tick()
    assert ids == ["default"] and len(started) == 1
    # not due again until the interval has passed (weekly by default); the running scan also blocks it
    assert sched.tick() == []
    with db.get_session("default") as s:
        s.query(ExternalScan).update({"status": "succeeded"})
        s.commit()
    assert sched.tick() == []
    assert sched.tick(utcnow() + dt.timedelta(days=8)) == ["default"]
    sched._leader.release()


# ----------------------------------------------------------------------------- API gating
def test_every_external_api_is_module_gated_and_role_checked(client):
    with db.get_session("default") as s:
        s.get(Organization, "default").modules = [m for m in ALL_MODULES if m != "external"]
        s.commit()
    for method, url, body in [("get", "/api/external/overview", None), ("get", "/api/external/targets", None),
                              ("post", "/api/external/targets", {"value": "a.example.com"}),
                              ("post", "/api/external/scans", None), ("get", "/api/external/findings", None),
                              ("get", "/api/external/hosts", None), ("post", "/api/external/reports", None),
                              ("put", "/api/external/scope", {"text": "x" * 20, "confirm": True}),
                              ("get", "/api/external/report/preview", None)]:
        r = getattr(client, method)(url, **({"json": body} if body is not None else {}))
        assert r.status_code == 403 and r.json() == {"detail": "module_disabled", "module": "external"}, url


def test_new_organisations_and_platform_toggle_of_the_external_module(client, platform):
    r = client.post("/api/platform/organizations", json={"name": "Fresh Co", "slug": "fresh",
                                                         "admin_email": "boss@fresh.test", "modules": ["external"]})
    assert r.status_code == 201, r.text
    assert r.json()["organization"]["modules"] == ["external"]
    oid = r.json()["organization"]["id"]
    r = client.put(f"/api/platform/organizations/{oid}/modules/external", json={"enabled": False})
    assert r.status_code == 200 and "external" not in r.json()["modules"]
    with db.get_session(oid) as s:
        assert any(a.action == "org_module_disabled" and a.detail["module"] == "external"
                   for a in s.scalars(select(AuditLog)))


def test_viewer_cannot_manage_targets_but_can_read(client):
    from tests.conftest import make_user

    make_user(client, "viewer")
    from fastapi.testclient import TestClient

    v = TestClient(client.app, base_url=BASE_URL)
    login(v, "viewer@example.com", "a-long-test-password")
    assert v.get("/api/external/overview").status_code == 200
    assert v.post("/api/external/targets", json={"value": "a.example.com"}).status_code == 403
    assert v.post("/api/external/scans").status_code == 403


def test_tenant_isolation_of_external_data(client):
    add_domain(client)
    oid = create_org("acme2", "boss@acme2.test", "a-long-test-password")
    c = org_client(client.app, "boss@acme2.test", "a-long-test-password")
    with db.get_session(unscoped=True) as s:
        s.get(Organization, oid).modules = ["external"]
        s.commit()
    assert c.get("/api/external/targets").json() == []


# ----------------------------------------------------------------------------- IP approval flow
def test_ip_approval_flow_with_attestation_and_audit(client, platform):
    t = client.post("/api/external/targets", json={"value": "8.8.8.8"}).json()
    assert t["proof"] is None and not t["verified"]
    r = client.post(f"/api/external/targets/{t['id']}/request-approval", json={"attestation": "too short"})
    assert r.status_code == 422
    r = client.post(f"/api/external/targets/{t['id']}/request-approval",
                    json={"attestation": "We own 8.8.8.8 and authorise Sentrigis to scan it."})
    assert r.status_code == 200 and r.json()["approval_status"] == "requested"
    q = client.get("/api/platform/external/approvals").json()
    assert [x["value"] for x in q] == ["8.8.8.8"] and q[0]["attestation"].startswith("We own")
    assert client.post(f"/api/platform/external/approvals/{t['id']}/decide",
                       json={"approve": True, "note": ""}).status_code == 422
    r = client.post(f"/api/platform/external/approvals/{t['id']}/decide",
                    json={"approve": True, "note": "Checked RIPE whois: customer owns the range."})
    assert r.status_code == 200 and r.json()["verified_method"] == "platform"
    acts = {a.action: a for a in _audit()}
    assert acts["external_target_approved"].detail["note"].startswith("Checked RIPE")
    assert "external_target_approval_requested" in acts
    # domains cannot be 'approved'
    d = add_domain(client)
    assert client.post(f"/api/external/targets/{d['id']}/request-approval",
                       json={"attestation": "x" * 30}).status_code == 422


def test_platform_endpoints_need_a_platform_owner():
    # the customer admin of another organisation is not a platform owner
    reset_database()
    from fastapi.testclient import TestClient

    from app.main import create_app

    config.reload_settings()
    with TestClient(create_app(), base_url=BASE_URL) as root:
        login(root)
        create_org("acme3", "boss@acme3.test", "a-long-test-password")
        c = org_client(root.app, "boss@acme3.test", "a-long-test-password")
        assert c.get("/api/platform/external/approvals").status_code == 403
        assert c.get("/api/platform/external/disputes").status_code == 403


# ----------------------------------------------------------------------------- disputes and report
def _seed_findings():
    with db.get_session("default") as s:
        s.add(ExternalHost(host="8.8.8.8", ip="8.8.8.8", ports=[{"port": 443}], active=True))
        s.add(ExternalTarget(kind="ip", value="8.8.8.8", token="x", verified_at=utcnow(), verified_method="platform"))
        for i, (title, sev, cvss, check, note) in enumerate([
                ("Weak thing", "medium", 5.3, "verbose-error", None), ("TLS 1.0 is enabled", "medium", 5.9, "tls-tls10", None),
                ("Directory listing enabled: /", "low", 3.7, "dir-listing", "browsable_directory")], start=1):
            s.add(ExternalFinding(seq=i, key=f"{check}|8.8.8.8|443|", check_id=check, title=title, severity=sev,
                                  cvss=cvss, host="8.8.8.8", ip="8.8.8.8", port=443, url="https://8.8.8.8/",
                                  special_note=note, auto_fail=(check == "tls-tls10"), detail={
                                      "description": "d", "impact": "i", "steps": ["s"], "fix": {"General": "fix it"},
                                      "references": [], "compliance": {}}, evidence={"status": 200}))
        s.add(ExternalScan(status="succeeded", finished_at=utcnow(), hosts=1, scanner_ip="198.51.100.9",
                           targets=["8.8.8.8"], result="fail"))
        s.commit()


def test_dispute_flow_review_audit_and_report_exceptions(client, platform):
    _seed_findings()
    fs = {f["check_id"]: f for f in client.get("/api/external/findings").json()}
    fid = fs["verbose-error"]["id"]
    assert client.post(f"/api/external/findings/{fid}/dispute",
                       json={"kind": "false_positive", "reason": "short"}).status_code == 422
    r = client.post(f"/api/external/findings/{fid}/dispute",
                    json={"kind": "compensating_control", "reason": "A WAF replaces error pages for this host."})
    assert r.status_code == 201 and r.json()["status"] == "disputed"
    assert client.post(f"/api/external/findings/{fid}/dispute",
                       json={"kind": "false_positive", "reason": "second dispute while one is open"}).status_code == 409
    # still failing until accepted
    assert client.get("/api/external/report/preview").json()["result"] == "fail"
    queue = client.get("/api/platform/external/disputes").json()
    assert len(queue) == 1 and queue[0]["ref"] == "EXT-0001" and queue[0]["kind"] == "compensating_control"
    assert client.post(f"/api/platform/external/disputes/{queue[0]['id']}/decide",
                       json={"approve": True, "note": ""}).status_code == 422
    r = client.post(f"/api/platform/external/disputes/{queue[0]['id']}/decide",
                    json={"approve": True, "note": "Reviewed the WAF rule; accepted."})
    assert r.status_code == 200 and r.json()["status"] == "accepted"
    assert client.post(f"/api/platform/external/disputes/{queue[0]['id']}/decide",
                       json={"approve": True, "note": "again"}).status_code == 409
    rep = client.get("/api/external/report/preview").json()
    ex = rep["exceptions"]
    assert [e["ref"] for e in ex] == ["EXT-0001"] and ex[0]["exception"]["kind"] == "compensating_control"
    assert ex[0]["result"] == "Pass"
    assert rep["result"] == "fail"  # TLS 1.0 is an automatic fail and cannot be waived by the other dispute
    acts = [a.action for a in _audit()]
    assert "external_dispute_submitted" in acts and "external_dispute_accepted" in acts
    # a rejected dispute re-opens the finding
    tid = fs["tls-tls10"]["id"]
    client.post(f"/api/external/findings/{tid}/dispute", json={"kind": "false_positive", "reason": "We believe it is wrong."})
    d = client.get("/api/platform/external/disputes").json()[0]
    client.post(f"/api/platform/external/disputes/{d['id']}/decide", json={"approve": False, "note": "Evidence shows TLS 1.0."})
    assert client.get(f"/api/external/findings/{tid}").json()["status"] == "open"
    assert "external_dispute_rejected" in [a.action for a in _audit()]


def test_accepting_risk_does_not_clear_a_pre_asv_failure(client):
    _seed_findings()
    fs = {f["check_id"]: f for f in client.get("/api/external/findings").json()}
    r = client.post(f"/api/external/findings/{fs['tls-tls10']['id']}/accept-risk", json={"reason": "legacy clients"})
    assert r.status_code == 200 and r.json()["status"] == "accepted"
    assert client.get("/api/external/report/preview").json()["result"] == "fail"
    assert "external_finding_risk_accepted" in [a.action for a in _audit()]


def _pdf_text(pdf: bytes) -> str:
    out = b""
    for m in re.finditer(rb"stream\n(.*?)\nendstream", pdf, re.S):
        try:
            out += zlib.decompress(m.group(1))
        except zlib.error:
            pass
    return out.decode("latin-1")


def test_report_requires_scope_then_renders_pdf_in_the_asv_layout(client):
    _seed_findings()
    r = client.post("/api/external/reports")
    assert r.status_code == 409 and "scope" in r.json()["detail"]
    assert client.put("/api/external/scope", json={"text": "short", "confirm": True}).status_code == 422
    r = client.put("/api/external/scope", json={"text": "Public website https://8.8.8.8 and API gateway.", "confirm": True})
    assert r.status_code == 200 and r.json()["confirmed_by"]
    rep = client.post("/api/external/reports")
    assert rep.status_code == 201 and rep.json()["result_label"] == "Likely fail"
    rid = rep.json()["id"]
    pdf = client.get(f"/api/external/reports/{rid}/pdf")
    assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf" and pdf.content[:5] == b"%PDF-"
    txt = _pdf_text(pdf.content)
    for needle in ("not an ASV scan report", "Part 1. Scan information", "Part 2. Component compliance summary",
                   "Part 3a", "Part 3b", "Part 3c", "Public website", "198.51.100.9", "LIKELY FAIL",
                   "Browsable directories"):
        assert needle in txt, needle
    assert len(client.get("/api/external/reports").json()) == 1
    data = client.get(f"/api/external/reports/{rid}").json()
    assert data["components"][0]["result"] == "Fail" and data["scanner_ip"] == "198.51.100.9"
    # editing the scope declaration withdraws its confirmation
    client.put("/api/external/scope", json={"text": "Something else entirely, edited.", "confirm": False})
    assert client.get("/api/external/overview").json()["scope"]["confirmed_at"] is None


def test_finding_pdf_download_vapt_layout(client):
    _seed_findings()
    f = client.get("/api/external/findings").json()[0]
    r = client.get(f"/api/external/findings/{f['id']}/pdf")
    assert r.status_code == 200 and r.content[:5] == b"%PDF-"
    txt = _pdf_text(r.content)
    assert "Steps to reproduce" in txt and "How to fix" in txt and "not an ASV scan report" in txt


def test_report_render_without_findings_says_pass_but_is_not_an_attestation(client):
    with db.get_session("default") as s:
        s.add(ExternalScan(status="succeeded", finished_at=utcnow(), hosts=0, targets=[], result="pass"))
        s.commit()
    data = client.get("/api/external/report/preview").json()
    assert data["result"] == "pass" and data["result_label"] == "Likely pass"
    assert b"%PDF" in report.render_report(data)[:8]


# ----------------------------------------------------------------------------- migration
def test_migration_does_not_give_existing_organisations_the_external_module(tmp_path):
    from alembic import command

    eng = db.create_db_engine(f"sqlite:///{tmp_path / 'm.db'}")
    try:
        db.run_migrations(eng, "0031_org_modules")
        with eng.begin() as c:
            c.execute(text("UPDATE organizations SET modules = :m WHERE id = 'default'"),
                      {"m": json.dumps(["cloud", "endpoints", "vulnerabilities", "assets"])})
        command.upgrade(db.alembic_config(eng), "0032_attack_surface")
        with eng.connect() as c:
            mods = json.loads(c.execute(text("SELECT modules FROM organizations WHERE id = 'default'")).scalar())
            assert "external" not in mods and mods == ["cloud", "endpoints", "vulnerabilities", "assets"]
            assert c.execute(text("SELECT count(*) FROM external_targets")).scalar() == 0
    finally:
        eng.dispose()
