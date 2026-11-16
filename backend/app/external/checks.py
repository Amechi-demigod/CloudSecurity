"""Web and service checks. Everything is a read-only request: no exploit attempts, no injection, and files are only
ever touched with HEAD or a 256-byte range request (status, size and type are kept, never contents)."""
from __future__ import annotations

import asyncio
import base64
import re
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .net import Net


@dataclass
class Hit:
    check_id: str
    host: str
    ip: str | None
    port: int | None
    url: str | None = None
    evidence: dict = field(default_factory=dict)
    # Template overrides / format variables (title, severity, cvss, vector, cwe, description, path, product, ...).
    extra: dict = field(default_factory=dict)
    key: str = ""  # distinguishes several hits of one check on one host:port (e.g. the path)


FILE_CHECKS: list[tuple[str, str, bytes | re.Pattern]] = [
    ("/.git/HEAD", "Git repository", b"ref:"), ("/.git/config", "Git configuration", b"[core]"),
    ("/.env", "Environment file", re.compile(rb"(?m)^[A-Z][A-Z0-9_]{2,}=")),
    ("/.DS_Store", "macOS directory metadata", b"\x00\x00\x00\x01Bud1"),
    ("/.htpasswd", "Password file", re.compile(rb"(?m)^[\w.-]+:[$\w./]")),
    ("/backup.zip", "ZIP archive", b"PK\x03\x04"), ("/site.zip", "ZIP archive", b"PK\x03\x04"),
    ("/www.zip", "ZIP archive", b"PK\x03\x04"), ("/web.zip", "ZIP archive", b"PK\x03\x04"),
    ("/backup.tar.gz", "gzip archive", b"\x1f\x8b"), ("/backup.tgz", "gzip archive", b"\x1f\x8b"),
    ("/backup.sql", "SQL dump", re.compile(rb"(?i)(create table|insert into|mysqldump|pg_dump|-- sql dump)")),
    ("/db.sql", "SQL dump", re.compile(rb"(?i)(create table|insert into|mysqldump|pg_dump|-- sql dump)")),
    ("/dump.sql", "SQL dump", re.compile(rb"(?i)(create table|insert into|mysqldump|pg_dump|-- sql dump)")),
    ("/database.sql", "SQL dump", re.compile(rb"(?i)(create table|insert into|mysqldump|pg_dump|-- sql dump)")),
    ("/wp-config.php.bak", "PHP configuration backup", b"<?php"), ("/config.php.bak", "PHP configuration backup", b"<?php"),
    ("/config.php.old", "PHP configuration backup", b"<?php"),
    ("/web.config.bak", "IIS configuration backup", b"<configuration"),
    ("/phpinfo.php", "phpinfo() page", re.compile(rb"(?i)php version")),
    ("/server-status", "Apache server-status", re.compile(rb"(?i)apache server status")),
]
ADMIN_CHECKS: list[tuple[str, tuple[bytes, ...]]] = [
    ("/admin", (b"admin", b"login", b"password")), ("/administrator/", (b"joomla", b"login", b"password")),
    ("/wp-admin/", (b"wp-login", b"wordpress")), ("/wp-login.php", (b"wp-login", b"wordpress")),
    ("/phpmyadmin/", (b"phpmyadmin",)), ("/pma/", (b"phpmyadmin",)), ("/manager/html", (b"tomcat",)),
    ("/jenkins/", (b"jenkins",)), ("/grafana/login", (b"grafana",)), ("/actuator/env", (b"propertysources",)),
    ("/console/", (b"console", b"login")),
]
API_DOC_CHECKS: list[tuple[str, tuple[bytes, ...]]] = [
    ("/swagger-ui.html", (b"swagger",)), ("/swagger-ui/", (b"swagger",)), ("/swagger/index.html", (b"swagger",)),
    ("/openapi.json", (b'"openapi"', b'"swagger"')), ("/v3/api-docs", (b'"openapi"',)),
    ("/api-docs", (b'"openapi"', b'"swagger"')), ("/docs", (b"swagger",)), ("/redoc", (b"redoc",)),
    ("/graphql?query=%7B__typename%7D", (b"__typename",)), ("/graphiql", (b"graphiql",)),
    ("/playground", (b"graphql playground", b"graphql-playground")),
]
DIR_PATHS = ["/", "/images/", "/uploads/", "/files/", "/backup/", "/backups/", "/logs/", "/static/", "/assets/",
             "/data/", "/temp/"]
DIR_SIGNS = (b"index of /", b"<title>directory listing", b"parent directory", b"[to parent directory]")
ERROR_SIGNS = (b"server error in '/' application", b"traceback (most recent call last)", b"at java.lang.",
               b"stack trace:", b"fatal error</b>:", b"<b>warning</b>:", b"asp.net is configured to show verbose",
               b"php parse error", b"microsoft ole db provider", b"whitelabel error page", b"nullpointerexception",
               b"django.core.exceptions", b"werkzeug debugger")
# Vendor-default HTTP Basic credentials (opt-in check only). Never stored or displayed.
DEFAULT_CREDS: tuple[tuple[str, str], ...] = (("admin", "admin"), ("admin", "password"), ("admin", ""),
                                              ("root", "root"), ("admin", "1234"), ("tomcat", "tomcat"))


def _size(h: dict) -> int | None:
    cr = h.get("content-range", "")
    if "/" in cr and cr.rsplit("/", 1)[1].isdigit():
        return int(cr.rsplit("/", 1)[1])
    cl = h.get("content-length", "")
    return int(cl) if cl.isdigit() else None


def _signature(body: bytes, sig: bytes | re.Pattern) -> bool:
    return bool(sig.search(body)) if isinstance(sig, re.Pattern) else body.startswith(sig) or sig in body[:64]


def product_from_header(server: str) -> tuple[str, str] | None:
    """('apache'|'nginx'|'iis'|'lighttpd'|'php'..., version) from a Server / X-Powered-By value."""
    for rx, product in ((r"Apache/(\d[\w.]*)", "apache"), (r"nginx/(\d[\w.]*)", "nginx"),
                        (r"Microsoft-IIS/(\d[\w.]*)", "iis"), (r"lighttpd/(\d[\w.]*)", "lighttpd"),
                        (r"PHP/(\d[\w.]*)", "php"), (r"OpenSSL/(\d[\w.]*[a-z]?)", "openssl")):
        m = re.search(rx, server or "")
        if m:
            return product, m.group(1)
    return None


def product_from_banner(banner: str) -> tuple[str, str] | None:
    for rx, product in ((r"OpenSSH[_-](\d[\w.]*)", "openssh"), (r"ProFTPD (\d[\w.]*)", "proftpd"),
                        (r"vsFTPd (\d[\w.]*)", "vsftpd"), (r"Exim (\d[\w.]*)", "exim")):
        m = re.search(rx, banner)
        if m:
            return product, m.group(1)
    return None


@dataclass
class WebResult:
    hits: list[Hit] = field(default_factory=list)
    software: list[dict] = field(default_factory=list)
    status: int | None = None
    server: str | None = None
    title: str | None = None
    basic_paths: list[str] = field(default_factory=list)  # paths answering 401 with Basic auth


def _hit(check_id: str, host: str, ip: str | None, port: int, scheme: str, p: str = "", *, evidence=None, **extra):
    default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    url = f"{scheme}://{host}{'' if default_port else f':{port}'}{p}"
    return Hit(check_id, host, ip, port, url, evidence or {}, extra, key=p)


async def web_checks(net: Net, host: str, port: int, tls: bool, *, deep: bool = True) -> WebResult | None:
    """All HTTP(S) checks of one host:port; None when the port does not answer HTTP."""
    scheme = "https" if tls else "http"
    res = WebResult()
    root = await net.http(host, port, tls=tls, path="/", max_body=32768)
    if root is None:
        return None
    ip = root["ip"]
    h = root["headers"]
    res.status = root["status"]
    res.server = h.get("server")
    m = re.search(rb"(?is)<title[^>]*>(.{0,120}?)</title>", root["body"])
    res.title = m.group(1).decode("latin-1", "replace").strip() if m else None
    req_evidence = {"request": f"GET / HTTP/1.1 (Host: {host})", "status": root["status"],
                    "response_headers": {k: v for k, v in h.items()
                                         if k in ("server", "x-powered-by", "content-type", "strict-transport-security",
                                                  "content-security-policy", "x-frame-options",
                                                  "x-content-type-options", "location", "www-authenticate")}}

    # --- server banner / software
    for hv in (h.get("server"), h.get("x-powered-by")):
        pv = product_from_header(hv or "")
        if pv:
            res.software.append({"product": pv[0], "version": pv[1], "port": port, "source": "http header"})
    if h.get("server") and re.search(r"\d+\.\d+", h["server"] + h.get("x-powered-by", "")):
        res.hits.append(_hit("http-server-banner", host, ip, port, scheme, "/",
                             evidence={**req_evidence, "disclosed": [v for v in (h.get("server"), h.get("x-powered-by")) if v]}))

    # --- security headers (only meaningful on pages that render)
    if root["status"] < 500 and "html" in h.get("content-type", "html").lower():
        if tls and "strict-transport-security" not in h:
            res.hits.append(_hit("hdr-hsts", host, ip, port, scheme, "/", evidence=req_evidence))
        if "content-security-policy" not in h:
            res.hits.append(_hit("hdr-csp", host, ip, port, scheme, "/", evidence=req_evidence))
        if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
            res.hits.append(_hit("hdr-xfo", host, ip, port, scheme, "/", evidence=req_evidence))
        if "x-content-type-options" not in h:
            res.hits.append(_hit("hdr-xcto", host, ip, port, scheme, "/", evidence=req_evidence))

    # --- cookie flags (names and flags only, never values)
    weak = []
    for c in h.get("set-cookie", []):
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        missing = [f for f, ok in (("Secure", "secure" in low or not tls), ("HttpOnly", "httponly" in low),
                                   ("SameSite", "samesite" in low)) if not ok]
        if missing:
            weak.append({"cookie": name[:40], "missing": missing})
    if weak:
        res.hits.append(_hit("cookie-flags", host, ip, port, scheme, "/", evidence={**req_evidence, "cookies": weak[:10]}))

    # --- embedded scripts / frames from other domains (Part 3b)
    own = ".".join(host.split(".")[-2:])
    others = sorted({urlsplit(("https:" if u.startswith("//") else "") + u).hostname or ""
                     for u in re.findall(r"(?is)<(?:script|iframe)[^>]+src=[\"']((?:https?:)?//[^\"']+)",
                                         root["body"].decode("latin-1")) if u})
    others = [d for d in others if d and not d.endswith(own)]
    if others:
        res.hits.append(_hit("external-scripts", host, ip, port, scheme, "/",
                             evidence={"domains": others[:10]}))
    if root["status"] == 401 and "basic" in h.get("www-authenticate", "").lower():
        res.basic_paths.append("/")
    if not deep:
        return res

    # --- baseline for soft-404 detection and verbose errors
    rnd = f"/sentrigis-{secrets.token_hex(6)}/"
    base = await net.http(host, port, tls=tls, path=rnd, max_body=1024)
    bstatus = base["status"] if base else None
    bbody = (base["body"] if base else b"")[:200]
    if base and any(s in base["body"].lower() for s in ERROR_SIGNS):
        res.hits.append(_hit("verbose-error", host, ip, port, scheme, rnd, evidence={
            "request": f"GET {rnd}", "status": base["status"], "signature": "framework error page / stack trace"}))
    bad = await net.http(host, port, tls=tls, path="/%ZZ", max_body=1024)
    if bad and any(s in bad["body"].lower() for s in ERROR_SIGNS) and not any(x.check_id == "verbose-error" for x in res.hits):
        res.hits.append(_hit("verbose-error", host, ip, port, scheme, "/%ZZ", evidence={
            "request": "GET /%ZZ", "status": bad["status"], "signature": "framework error page / stack trace"}))

    def is_soft(r: dict) -> bool:
        return bstatus == 200 and r["status"] == 200 and r["body"][:200] == bbody

    # --- exposed files (HEAD-sized range requests; contents are never kept)
    for path, label, sig in FILE_CHECKS:
        r = await net.http(host, port, tls=tls, path=path, headers={"Range": "bytes=0-255"}, max_body=256)
        if r is None or r["status"] not in (200, 206) or is_soft(r):
            continue
        if _signature(r["body"], sig):
            rh = r["headers"]
            res.hits.append(_hit("file-exposed", host, ip, port, scheme, path, evidence={
                "request": f"GET {path} (Range: bytes=0-255)", "status": r["status"],
                "content_type": rh.get("content-type", ""), "size_bytes": _size(rh), "signature": "matched",
                "kind": label}, path=path, kind=label))

    # --- admin panels, API docs
    for path, keys in ADMIN_CHECKS:
        r = await net.http(host, port, tls=tls, path=path, max_body=4096)
        if r is None or bstatus == 401:
            continue
        rh = r["headers"]
        if r["status"] == 401 and rh.get("www-authenticate"):
            if "basic" in rh["www-authenticate"].lower():
                res.basic_paths.append(path)
            res.hits.append(_hit("admin-panel", host, ip, port, scheme, path, evidence={
                "request": f"GET {path}", "status": 401, "www_authenticate": rh["www-authenticate"][:80]}, path=path))
        elif r["status"] == 200 and not is_soft(r) and any(k in r["body"].lower() for k in keys):
            res.hits.append(_hit("admin-panel", host, ip, port, scheme, path, evidence={
                "request": f"GET {path}", "status": 200, "content_type": rh.get("content-type", "")}, path=path))
    for path, keys in API_DOC_CHECKS:
        r = await net.http(host, port, tls=tls, path=path, max_body=4096)
        if r and r["status"] == 200 and not is_soft(r) and any(k in r["body"].lower() for k in keys):
            res.hits.append(_hit("api-docs", host, ip, port, scheme, path, evidence={
                "request": f"GET {path}", "status": 200, "content_type": r["headers"].get("content-type", "")}, path=path))

    # --- directory listing
    for path in DIR_PATHS:
        r = await net.http(host, port, tls=tls, path=path, max_body=4096)
        if r and r["status"] == 200 and any(s in r["body"].lower() for s in DIR_SIGNS):
            res.hits.append(_hit("dir-listing", host, ip, port, scheme, path, evidence={
                "request": f"GET {path}", "status": 200, "signature": "automatic index page"}, path=path))

    # --- IIS short name (tilde) probe: the standard two requests, no enumeration
    if "microsoft-iis" in (h.get("server") or "").lower():
        a = await net.http(host, port, tls=tls, path="/*~1*/.aspx", max_body=0)
        b = await net.http(host, port, tls=tls, path="/zzqx9*~1*/.aspx", max_body=0)
        if a and b and a["status"] == 404 and b["status"] == 400:
            res.hits.append(_hit("iis-shortname", host, ip, port, scheme, "/", evidence={
                "probe_existing_pattern": 404, "probe_missing_pattern": 400}))
    return res


async def default_password_check(net: Net, host: str, port: int, tls: bool, path: str, *, delay: float = 1.5
                                 ) -> Hit | None:
    """Opt-in only. Tries a handful of vendor-default credentials on one HTTP Basic realm, slowly, stopping at the
    first success. Nothing about the credentials is returned or stored."""
    scheme = "https" if tls else "http"
    # a server that accepts any credentials is not "default credentials"
    junk = base64.b64encode(f"x{secrets.token_hex(4)}:{secrets.token_hex(6)}".encode()).decode()
    r = await net.http(host, port, tls=tls, path=path, headers={"Authorization": f"Basic {junk}"}, max_body=0)
    if r is None or r["status"] != 401:
        return None
    for user, pw in DEFAULT_CREDS:
        await asyncio.sleep(delay)
        tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
        r = await net.http(host, port, tls=tls, path=path, headers={"Authorization": f"Basic {tok}"}, max_body=0)
        if r and 200 <= r["status"] < 300:
            return _hit("default-credentials", host, r["ip"], port, scheme, path, evidence={
                "service": f"HTTP Basic authentication at {path}",
                "result": f"default credentials accepted for HTTP Basic at {path}"}, service=f"HTTP Basic at {path}")
    return None
