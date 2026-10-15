#!/usr/bin/env python3
"""End-to-end smoke test against a running deployment (stdlib only).

    python3 scripts/smoke_test.py --base-url http://localhost:5173
    SMOKE_ADMIN_EMAIL=... SMOKE_ADMIN_PASSWORD=... python3 scripts/smoke_test.py --base-url https://<app>.azurecontainerapps.io

Always checks: the UI is served, /api/health is ok through the frontend's /api
proxy, protected endpoints reject anonymous requests, security headers are set.
With credentials it also logs in, checks the session cookie flags, calls
authenticated endpoints and logs out (CSRF-protected).

The session cookie is handled by hand so the test also works over plain http
against a `Secure` cookie (local CI), exactly like a browser on localhost.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from http.client import HTTPResponse


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def request(method: str, url: str, body: dict | None = None, headers: dict | None = None,
            timeout: float = 20) -> tuple[int, dict[str, str], list[str], bytes]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={  # noqa: S310 - URL from the CLI
        "User-Agent": "cnapp-smoke-test", **({"Content-Type": "application/json"} if data else {}), **(headers or {})})
    try:
        resp: HTTPResponse = OPENER.open(req, timeout=timeout)
    except urllib.error.HTTPError as err:
        resp = err  # type: ignore[assignment]
    raw = resp.read()
    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    return resp.status, hdrs, resp.headers.get_all("Set-Cookie") or [], raw


class Smoke:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.failures: list[str] = []

    def check(self, ok: bool, what: str) -> bool:
        print(("PASS " if ok else "FAIL ") + what, flush=True)
        if not ok:
            self.failures.append(what)
        return ok

    def wait_healthy(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            try:
                status, _, _, raw = request("GET", f"{self.base}/api/health", timeout=10)
                if status == 200 and json.loads(raw).get("status") == "ok":
                    print(f"healthy: {raw.decode()}")
                    return
                last = f"HTTP {status}"
            except Exception as exc:  # connection refused, DNS, TLS while starting
                last = f"{type(exc).__name__}: {exc}"
            time.sleep(5)
        self.check(False, f"/api/health became ok within {timeout:.0f}s (last: {last})")
        raise SystemExit(1)

    def run(self, email: str | None, password: str | None) -> int:
        status, hdrs, _, raw = request("GET", f"{self.base}/")
        self.check(status == 200 and b'id="root"' in raw, "UI index.html served")
        self.check("default-src 'self'" in hdrs.get("content-security-policy", ""), "UI sends a CSP")
        self.check(hdrs.get("x-frame-options") == "DENY", "UI sends X-Frame-Options")
        if self.base.startswith("https://"):
            self.check("max-age=" in hdrs.get("strict-transport-security", ""), "HSTS on https")
        status, _, _, raw = request("GET", f"{self.base}/login")
        self.check(status == 200 and b'id="root"' in raw, "SPA route /login served")

        status, hdrs, _, raw = request("GET", f"{self.base}/api/health")
        self.check(status == 200 and json.loads(raw)["status"] == "ok", "/api/health ok through the /api proxy")
        self.check(hdrs.get("cache-control") == "no-store", "API responses are not cacheable")
        status, *_ = request("GET", f"{self.base}/api/dashboard")
        self.check(status == 401, "anonymous /api/dashboard is rejected (401)")
        status, *_ = request("GET", f"{self.base}/api/docs")
        print(f"info /api/docs -> HTTP {status} (404 expected in production)")
        status, *_ = request("POST", f"{self.base}/api/runtime/events", {"event_type": "process_exec"})
        self.check(status in (401, 503), "sensor ingest without a token is rejected")
        # Endpoint-agent API is routed through the proxy, needs a device credential,
        # and accepts check-ins larger than the 1 MiB default body cap.
        status, _, _, raw = request("GET", f"{self.base}/api/agent/commands")
        self.check(status == 401 and b"device credential" in raw, "agent API without a device credential is rejected (401)")
        big = {"device": {"hostname": "smoke", "os_family": "windows"},
               "software": [{"name": f"pkg-{i}", "version": "1.0", "publisher": "x" * 200} for i in range(8000)]}
        status, *_ = request("POST", f"{self.base}/api/agent/checkin", big,
                             headers={"Authorization": "Bearer cnd_not-a-real-device-credential"})
        self.check(status == 401, f"2 MiB agent check-in passes the proxy body limit and is rejected by auth (HTTP {status})")
        token = os.getenv("SMOKE_INGEST_TOKEN")
        if token:
            event = {"event_type": "file_access", "sensor_id": "smoke-test", "file": {"path": "/srv/smoke-test"}}
            status, _, _, raw = request("POST", f"{self.base}/api/runtime/events", event,
                                        headers={"Authorization": f"Bearer {token}"})
            self.check(status == 202, f"sensor ingest with the token through the proxy (HTTP {status} {raw[:200]!r})")

        if not (email and password):
            print("no credentials given: skipping the login checks")
            return self.done()
        status, _, cookies, raw = request("POST", f"{self.base}/api/auth/login",
                                          {"email": email, "password": password})
        if not self.check(status == 200, f"login as {email} (HTTP {status})"):
            return self.done()
        csrf = json.loads(raw)["csrf_token"]
        session = next((c for c in cookies if c.lower().startswith("cnapp_session=")), "")
        flags = session.lower()
        self.check("httponly" in flags and "secure" in flags and "samesite=lax" in flags,
                   "session cookie is HttpOnly; Secure; SameSite=Lax")
        cookie = {"Cookie": session.split(";", 1)[0]}
        status, _, _, raw = request("GET", f"{self.base}/api/auth/me", headers=cookie)
        self.check(status == 200 and json.loads(raw)["user"]["email"] == email.lower(), "/api/auth/me with the session")
        status, _, _, raw = request("GET", f"{self.base}/api/dashboard", headers=cookie)
        self.check(status == 200, "authenticated /api/dashboard")
        status, *_ = request("POST", f"{self.base}/api/auth/logout", headers=cookie)
        self.check(status == 403, "logout without the CSRF token is rejected (403)")
        status, *_ = request("POST", f"{self.base}/api/auth/logout", headers={**cookie, "X-CSRF-Token": csrf})
        self.check(status == 204, "logout with the CSRF token")
        status, *_ = request("GET", f"{self.base}/api/auth/me", headers=cookie)
        self.check(status == 401, "session is revoked after logout")
        return self.done()

    def done(self) -> int:
        if self.failures:
            print(f"\n{len(self.failures)} smoke check(s) failed", file=sys.stderr)
            return 1
        print("\nall smoke checks passed")
        return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base-url", required=True, help="frontend URL, e.g. https://cnapp-web.<env>.azurecontainerapps.io")
    p.add_argument("--wait", type=float, default=180, help="seconds to wait for /api/health (default 180)")
    a = p.parse_args()
    smoke = Smoke(a.base_url)
    smoke.wait_healthy(a.wait)
    return smoke.run(os.getenv("SMOKE_ADMIN_EMAIL"), os.getenv("SMOKE_ADMIN_PASSWORD"))


if __name__ == "__main__":
    sys.exit(main())
