"""SSRF-safe outbound HTTP for webhooks.

Every outbound request (Teams, Slack, generic webhooks, ACS Email):

* must be https:// (http only with NOTIFICATIONS_ALLOW_INSECURE_DEV outside production);
* may not carry credentials in the URL; the host must match the channel type's
  allowlist when one is configured (e.g. hooks.slack.com);
* is resolved ONCE, every resolved address must be public (no loopback,
  private, link-local, CGNAT, multicast, reserved, cloud metadata such as
  169.254.169.254 / Azure's 168.63.129.16, IPv4-mapped/NAT64/6to4 tricks), and
  the connection is then made to that exact, already-validated address (TLS
  SNI and certificate verification still use the hostname). A DNS answer that
  changes between the check and the connection (DNS rebinding) is therefore
  never used;
* never follows redirects (a 3xx is reported as an error);
* has connect/read timeouts and a response-size cap.
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from . import settings as nsettings

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Addresses that are "global" per IANA but must never be reachable from here.
_EXTRA_BLOCKED = [ipaddress.ip_network(n) for n in (
    "168.63.129.16/32",    # Azure WireServer / host agent
    "169.254.0.0/16",      # link-local incl. 169.254.169.254 IMDS (also covered by is_link_local)
    "100.64.0.0/10",       # carrier-grade NAT (shared address space)
    "192.0.0.0/24",        # IETF protocol assignments
    "198.18.0.0/15",       # benchmarking
    "fd00::/8",            # unique local (e.g. AWS IMDSv6 fd00:ec2::254)
    "fc00::/7",
    "fe80::/10",
    "64:ff9b::/96",        # NAT64 (checked through the embedded IPv4 too)
    "64:ff9b:1::/48",
    "2002::/16",           # 6to4 (checked through the embedded IPv4 too)
    "2001::/32",           # Teredo
)]
_PRIVATE_OK = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8")]
_METADATA_HOSTS = {"metadata.google.internal", "metadata", "metadata.azure.internal", "instance-data"}


class BlockedDestination(ValueError):
    """The URL / host is not allowed (SSRF protection). Never retried."""


class DeliveryHTTPError(RuntimeError):
    """Transport-level failure (DNS, connect, TLS, timeout). Retried."""


@dataclass
class HttpResponse:
    status: int
    body: bytes
    headers: dict[str, str]
    truncated: bool = False


def _embedded_ipv4(addr: IPAddress) -> ipaddress.IPv4Address | None:
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped:
            return addr.ipv4_mapped
        if addr.sixtofour:
            return addr.sixtofour
        if addr.teredo:
            return addr.teredo[1]
        if addr in ipaddress.ip_network("64:ff9b::/96"):
            return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return None


def address_problem(addr: IPAddress, *, allow_private: bool = False, allow_loopback: bool = False) -> str | None:
    """Why `addr` must not be contacted, or None if it is a public address."""
    inner = _embedded_ipv4(addr)
    if inner is not None:
        problem = address_problem(inner, allow_private=allow_private, allow_loopback=allow_loopback)
        if problem:
            return f"{problem} (embedded in {addr})"
    if addr.is_loopback:
        return None if allow_loopback else f"{addr} is a loopback address"
    if addr.is_link_local:
        return f"{addr} is link-local (cloud metadata)"
    if addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return f"{addr} is not a unicast address"
    if allow_private and any(addr in n for n in _PRIVATE_OK):
        return None
    for net in _EXTRA_BLOCKED:
        if addr.version == net.version and addr in net:
            return f"{addr} is in blocked range {net}"
    if not addr.is_global or addr.is_private:
        return f"{addr} is a private or non-routable address"
    return None


def host_allowed(host: str, patterns: list[str]) -> bool:
    if not patterns:
        return True
    host = host.lower().rstrip(".")
    for p in patterns:
        p = p.lower().rstrip(".")
        if p.startswith("*."):
            if host.endswith(p[1:]) and host != p[2:]:
                return True
        elif host == p:
            return True
    return False


@dataclass
class Target:
    scheme: str
    host: str
    port: int
    path: str  # path + query
    ip: str


def resolve(host: str, port: int) -> list[IPAddress]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise DeliveryHTTPError(f"DNS resolution failed for {host}: {exc}") from None
    addrs: list[IPAddress] = []
    for info in infos:
        try:
            a = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        except ValueError:
            continue
        if a not in addrs:
            addrs.append(a)
    if not addrs:
        raise DeliveryHTTPError(f"DNS resolution returned no addresses for {host}")
    return addrs


def check_url(url: str, kind: str, *, resolve_dns: bool = True) -> Target:
    """Validate `url` for channel type `kind` and pin it to a vetted IP address.

    Raises BlockedDestination for policy violations (never retried) and
    DeliveryHTTPError for DNS failures (retried).
    """
    s = nsettings.get()
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError as exc:
        raise BlockedDestination(f"invalid URL: {exc}") from None
    scheme = (parts.scheme or "").lower()
    if scheme not in ("https", "http"):
        raise BlockedDestination("only https:// URLs are allowed")
    if scheme == "http" and not s.insecure_dev:
        raise BlockedDestination("only https:// URLs are allowed (http needs NOTIFICATIONS_ALLOW_INSECURE_DEV "
                                 "in development)")
    if parts.username or parts.password:
        raise BlockedDestination("credentials in the URL are not allowed")
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise BlockedDestination("URL has no host")
    if host.lower() in _METADATA_HOSTS:
        raise BlockedDestination(f"{host} is a cloud metadata endpoint")
    if not s.insecure_dev and (host.lower() == "localhost" or host.lower().endswith((".localhost", ".internal",
                                                                                   ".local", ".svc"))):
        raise BlockedDestination(f"{host} is an internal hostname")
    allowed = s.allowed_hosts(kind)
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None
    if allowed and (literal is not None or not host_allowed(host, allowed)):
        raise BlockedDestination(f"host {host} is not in the {kind} allowlist ({', '.join(allowed)})")
    port = port or (443 if scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    if not resolve_dns and literal is None:
        return Target(scheme, host, port, path, "")
    addrs = [literal] if literal is not None else resolve(host, port)
    for a in addrs:  # every answer must be safe, not just the first one
        problem = address_problem(a, allow_private=s.insecure_dev, allow_loopback=s.insecure_dev)
        if problem:
            raise BlockedDestination(f"{host} resolves to a blocked address: {problem}")
    return Target(scheme, host, port, path, str(addrs[0]))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to a pre-validated IP; SNI + certificate check use the hostname."""

    def __init__(self, host: str, ip: str, port: int, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, ip: str, port: int, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def post(url: str, body: bytes, headers: dict[str, str], *, kind: str) -> HttpResponse:
    """POST `body` to `url` with all the protections above. No redirects."""
    s = nsettings.get()
    t = check_url(url, kind)
    if t.scheme == "https":
        conn: http.client.HTTPConnection = _PinnedHTTPSConnection(t.host, t.ip, t.port, s.connect_timeout,
                                                                  _tls_context())
    else:
        conn = _PinnedHTTPConnection(t.host, t.ip, t.port, s.connect_timeout)
    try:
        try:
            conn.connect()
            conn.sock.settimeout(s.read_timeout)
            hdrs = {"User-Agent": "CloudSecurity-CNAPP-Notifier/1.0", "Content-Length": str(len(body)), **headers}
            conn.request("POST", t.path, body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read(s.max_response_bytes + 1)
        except (OSError, http.client.HTTPException) as exc:
            raise DeliveryHTTPError(f"{type(exc).__name__}: {exc}") from None
        return HttpResponse(status=resp.status, body=data[: s.max_response_bytes],
                            headers={k.lower(): v for k, v in resp.getheaders()},
                            truncated=len(data) > s.max_response_bytes)
    finally:
        conn.close()
