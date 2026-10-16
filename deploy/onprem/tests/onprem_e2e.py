#!/usr/bin/env python3
"""End-to-end checks against an on-prem install made by `cnapp-ctl install` (stdlib only).

Used by the `onprem` CI job; also handy after a real install:

    sudo cnapp-ctl show-secret INGEST_API_TOKEN > /tmp/t   # optional, for the ingest check
    python3 deploy/onprem/tests/onprem_e2e.py verify --base https://cnapp.corp.local \\
        --ca /opt/cnapp/tls/cnapp-root-ca.crt --email admin@corp.com --password-file pw.txt

Sub-commands:
  verify        TLS (rejected without the CA, trusted with it), HTTP->HTTPS redirect, security
                headers, login + CSRF, optional: agent enrollment (--ca-file) + check-in, sensor ingest
  mark NAME     create a marker (an enrollment token named NAME) to track data across backup/restore
  expect NAME present|absent
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # noqa: ANN002, ANN003
        return None


class Api:
    def __init__(self, base: str, ca: str | None):
        self.base = base.rstrip("/")
        ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), NoRedirect)
        self.cookie = ""
        self.csrf = ""

    def req(self, method: str, path: str, body=None, headers=None, raw: bytes | None = None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        h = {"User-Agent": "cnapp-onprem-e2e", **(headers or {})}
        if data is not None and "Content-Type" not in h:
            h["Content-Type"] = "application/json"
        if self.cookie:
            h["Cookie"] = self.cookie
        if self.csrf and method not in ("GET", "HEAD"):
            h["X-CSRF-Token"] = self.csrf
        url = path if path.startswith("http") else self.base + path
        r = urllib.request.Request(url, data=data, method=method, headers=h)  # noqa: S310
        try:
            resp = self.opener.open(r, timeout=30)
        except urllib.error.HTTPError as e:
            resp = e
        content = resp.read()
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.headers.get_all("Set-Cookie") or [], content

    def json(self, method: str, path: str, body=None, expect=(200, 201, 202)):
        status, _, _, content = self.req(method, path, body)
        if status not in expect:
            raise SystemExit(f"FAIL {method} {path}: HTTP {status} {content[:300]!r}")
        return json.loads(content) if content else None

    def login(self, email: str, password: str):
        status, _, cookies, content = self.req("POST", "/api/auth/login", {"email": email, "password": password})
        check(status == 200, f"login as {email} (HTTP {status} {content[:200]!r})")
        body = json.loads(content)
        check("csrf_token" in body, f"login completed without an MFA challenge ({list(body)})")
        self.csrf = body["csrf_token"]
        session = next(c for c in cookies if c.lower().startswith("cnapp_session="))
        flags = session.lower()
        check("secure" in flags and "httponly" in flags, "session cookie is Secure; HttpOnly")
        self.cookie = session.split(";", 1)[0]


def check(ok: bool, what: str) -> None:
    print(("PASS " if ok else "FAIL ") + what, flush=True)
    if not ok:
        raise SystemExit(1)


def wait_health(api: Api, timeout: float = 120) -> None:
    end = time.monotonic() + timeout
    last = ""
    while time.monotonic() < end:
        try:
            status, _, _, content = api.req("GET", "/api/health")
            if status == 200 and json.loads(content).get("status") == "ok":
                return
            last = f"HTTP {status}"
        except Exception as exc:  # noqa: BLE001
            last = repr(exc)
        time.sleep(3)
    raise SystemExit(f"FAIL /api/health not ok within {timeout}s: {last}")


def verify(a: argparse.Namespace) -> None:
    api = Api(a.base, a.ca)
    wait_health(api)
    # 1. TLS: the private CA is required (no "ignore TLS errors" anywhere).
    try:
        Api(a.base, None).req("GET", "/api/health")
        check(False, "TLS without the CA must fail")
    except urllib.error.URLError as exc:
        check("CERTIFICATE_VERIFY_FAILED" in str(exc), "TLS is rejected without the internal CA")
    status, hdrs, _, content = api.req("GET", "/api/health")
    check(status == 200 and json.loads(content)["status"] == "ok", "HTTPS /api/health ok with the internal CA")
    check("max-age=31536000" in hdrs.get("strict-transport-security", ""), "HSTS header")
    status, hdrs, _, content = api.req("GET", "/")
    check(status == 200 and b'id="root"' in content, "UI served over HTTPS")
    check(hdrs.get("x-frame-options") == "DENY" and "default-src 'self'" in hdrs.get("content-security-policy", ""),
          "security headers (X-Frame-Options, CSP)")
    # 2. HTTP -> HTTPS redirect to the canonical hostname.
    host = a.base.split("://", 1)[1].rstrip("/")
    status, hdrs, _, _ = api.req("GET", f"http://{host}/devices?x=1")
    check(status == 301 and hdrs.get("location") == f"https://{host}/devices?x=1",
          f"http:// redirects to https:// ({status} {hdrs.get('location')})")
    # 3. Body limits: agent API accepts > 1 MiB through nginx; other API paths do not.
    big = json.dumps({"device": {"hostname": "x"}, "software": [{"name": "p" * 200}] * 8000}).encode()
    status, *_ = api.req("POST", "/api/agent/checkin", raw=big, headers={"Authorization": "Bearer cnd_fake"})
    check(status == 401, f"2 MiB agent check-in passes nginx (8 MiB limit) and reaches auth (HTTP {status})")
    status, *_ = api.req("POST", "/api/runtime/events", raw=big, headers={"Authorization": "Bearer x"})
    check(status == 413, f"2 MiB request to a non-agent API is rejected by nginx (HTTP {status})")
    # 4. Login + CSRF.
    api.login(a.email, Path(a.password_file).read_text().strip())
    me = api.json("GET", "/api/auth/me")
    check(me["user"]["email"] == a.email.lower() and me["user"]["role"] == "admin", "logged in as the bootstrap admin")
    saved = api.csrf
    api.csrf = ""
    status, *_ = api.req("POST", "/api/devices/enrollment-tokens", {"name": "no-csrf"})
    check(status == 403, "state-changing request without the CSRF token is rejected (403)")
    api.csrf = saved
    # 5. Endpoint agent: enrollment needs --ca-file, then check-in.
    if a.agent:
        token = api.json("POST", "/api/devices/enrollment-tokens", {"name": "ci-onprem", "max_uses": 3})["token"]
        home = tempfile.mkdtemp(prefix="cnapp-agent-")
        env = {**os.environ, "CNAPP_AGENT_HOME": home}
        r = subprocess.run([a.agent, "enroll", "--server", a.base, "--token", token], env=env,
                           capture_output=True, text=True)
        check(r.returncode != 0 and "certificate" in (r.stderr + r.stdout),
              "agent enrollment without the CA fails closed (certificate error)")
        ca_copy = Path(tempfile.mkdtemp()) / "cnapp-root-ca.crt"
        ca_copy.write_bytes(Path(a.ca).read_bytes())
        r = subprocess.run([a.agent, "enroll", "--server", a.base, "--token", token, "--ca-file", str(ca_copy)],
                           env=env, capture_output=True, text=True)
        check(r.returncode == 0, f"agent enrolled with --ca-file: {r.stdout.strip()} {r.stderr.strip()}")
        ca_copy.unlink()  # the agent keeps its own protected copy
        r = subprocess.run([a.agent, "checkin"], env=env, capture_output=True, text=True)
        check(r.returncode == 0, f"agent check-in over HTTPS with the stored CA ({r.stderr.strip()[-300:]})")
        devices = api.json("GET", "/api/devices")
        check(any(d.get("last_seen_at") or d.get("last_check_in_at") or d.get("hostname") for d in devices),
              f"device listed in the console ({len(devices)} device(s))")
    # 6. Runtime sensor: real sensor process, ingest token, private CA.
    if a.sensor_dir and a.ingest_token_file:
        token = Path(a.ingest_token_file).read_text().strip()
        env = {**os.environ, "PYTHONPATH": a.sensor_dir, "SENSOR_API_TOKEN": token, "CNAPP_CA_FILE": a.ca}
        r = subprocess.run([sys.executable, "-m", "runtime_sensor", "--once", "--emit-existing",
                            "--collectors", "process", "--sensor-id", "ci-onprem-sensor", "--no-k8s-api",
                            "--api-url", f"{a.base}/api/runtime/events"], env=env, capture_output=True, text=True,
                           timeout=120)
        check(r.returncode == 0, f"sensor ran (--once) ({r.stderr.strip()[-300:]})")
        events = api.json("GET", "/api/runtime/events?source=sensor&limit=50")
        check(len(events) > 0, f"sensor events ingested over HTTPS with the token ({len(events)})")
        status, *_ = api.req("POST", "/api/runtime/events", [{"event_type": "process_exec"}],
                             headers={"Authorization": "Bearer wrong-token"})
        check(status == 401, f"ingest with a wrong token is rejected (HTTP {status})")
    print("all on-prem checks passed")


def marker(a: argparse.Namespace) -> None:
    api = Api(a.base, a.ca)
    wait_health(api)
    api.login(a.email, Path(a.password_file).read_text().strip())
    if a.cmd == "mark":
        api.json("POST", "/api/devices/enrollment-tokens", {"name": a.name})
        print(f"created marker {a.name}")
        return
    names = {t["name"] for t in api.json("GET", "/api/devices/enrollment-tokens")}
    check((a.name in names) == (a.state == "present"), f"marker {a.name} is {a.state}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base", required=True)
    p.add_argument("--ca", required=True)
    p.add_argument("--email", required=True)
    p.add_argument("--password-file", required=True)
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--agent")
    v.add_argument("--sensor-dir")
    v.add_argument("--ingest-token-file")
    m = sub.add_parser("mark")
    m.add_argument("name")
    e = sub.add_parser("expect")
    e.add_argument("name")
    e.add_argument("state", choices=["present", "absent"])
    a = p.parse_args()
    verify(a) if a.cmd == "verify" else marker(a)


if __name__ == "__main__":
    main()
