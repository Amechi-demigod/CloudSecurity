#!/usr/bin/env python3
"""End-to-end test: real endpoint agent <-> real backend (stdlib only).

Starts the FastAPI backend on a throwaway SQLite database, creates an
enrollment token through the admin API, enrolls the agent binary given with
--agent, runs check-ins, queues remote commands (recheck_posture,
collect_logs, update_check_in_interval), verifies their results and the
uploaded log bundle, then revokes the device and checks the agent is rejected.

With --service (CI only: it installs a real Windows service / macOS
LaunchDaemon, using sudo on macOS) it also installs the agent as a service,
waits for the service's own check-in, sends restart_agent and checks that the
service manager brings the agent back, then uninstalls it.

CI runs it on Windows and macOS runners. Locally:

    python scripts/agent_e2e.py --agent ./endpoint-agent/cnapp-agent
"""
from __future__ import annotations

import argparse
import gzip
import http.cookiejar
import io
import json
import os
import platform
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADMIN_EMAIL = "e2e-admin@example.com"
ADMIN_PASSWORD = "e2e-admin-password-123"


class Api:
    def __init__(self, base: str):
        self.base = base
        self.csrf = ""
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, method: str, path: str, body=None, raw: bool = False):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.csrf and method not in ("GET", "HEAD"):
            req.add_header("X-CSRF-Token", self.csrf)
        try:
            with self.opener.open(req, timeout=60) as r:
                payload = r.read()
                if raw:
                    return payload
                return json.loads(payload) if payload else None
        except urllib.error.HTTPError as e:
            raise SystemExit(f"{method} {path} -> {e.code}: {e.read()[:500]!r}") from None


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


SUDO: list[str] = []


def run_agent(agent: str, home: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    cmd = [*SUDO, agent, *args, "--home", home]
    print("+", " ".join(a if not a.startswith("cne_") else "cne_***" for a in cmd), flush=True)
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    sys.stdout.write(p.stdout[-4000:])
    sys.stderr.write(p.stderr[-4000:])
    if check and p.returncode != 0:
        raise SystemExit(f"agent {args[0]} failed with exit code {p.returncode}")
    return p


def wait_health(base: str, proc: subprocess.Popen, timeout: float = 120) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit("backend exited early")
        try:
            with urllib.request.urlopen(base + "/api/health", timeout=5) as r:
                if r.status == 200:
                    return
        except OSError:
            time.sleep(1)
    raise SystemExit("backend did not become healthy")


def wait_for(what: str, fn, timeout: float) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if fn():
            print(f"ok: {what}", flush=True)
            return
        time.sleep(3)
    raise SystemExit(f"timed out waiting for: {what}")


def service_test(api: Api, agent: str, home: str, device_id: str) -> None:
    def checkins() -> int:
        return len(api.call("GET", f"/api/devices/{device_id}/history?limit=500"))

    before = checkins()
    run_agent(agent, home, "install")
    wait_for("check-in from the installed service", lambda: checkins() > before, 180)
    if platform.system() == "Windows":
        acl = subprocess.run(["icacls", str(Path(home, "state"))], capture_output=True, text=True).stdout
        print(acl)
        assert "NT AUTHORITY\\SYSTEM" in acl and "BUILTIN\\Administrators" in acl, "state dir ACL"
        assert "BUILTIN\\Users" not in acl and "Everyone" not in acl, "state dir readable by non-admins"
    cid = api.call("POST", f"/api/devices/{device_id}/commands",
                   {"type": "restart_agent", "reason": "e2e service restart"})["id"]
    before = checkins()

    def restarted() -> bool:
        cmd = next(c for c in api.call("GET", f"/api/devices/{device_id}/commands") if c["id"] == cid)
        return cmd["status"] == "succeeded"

    wait_for("restart_agent acknowledged by the service", restarted, 180)
    wait_for("service restarted by the service manager and checked in again", lambda: checkins() > before, 240)
    run_agent(agent, home, "uninstall")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--agent", required=True, help="path to the cnapp-agent binary")
    ap.add_argument("--python", default=sys.executable, help="python with the backend requirements installed")
    ap.add_argument("--service", action="store_true", help="also test the real OS service (CI runners only)")
    args = ap.parse_args()
    if args.service and platform.system() == "Darwin":
        SUDO[:] = ["sudo", "-n"]  # the LaunchDaemon runs as root; keep all agent state root-owned
    agent = str(Path(args.agent).resolve())
    expected_os = {"Windows": "windows", "Darwin": "macos", "Linux": "linux"}[platform.system()]

    with tempfile.TemporaryDirectory(prefix="cnapp-e2e-", ignore_cleanup_errors=True) as tmp:
        port = free_port()
        base = f"http://127.0.0.1:{port}"
        env = {**os.environ, "DATABASE_URL": f"sqlite:///{Path(tmp, 'e2e.db').as_posix()}", "SIMULATION_MODE": "false",
               "ADMIN_EMAIL": ADMIN_EMAIL, "ADMIN_PASSWORD": ADMIN_PASSWORD, "COOKIE_SECURE": "false",
               "APP_ENV": "development", "INGEST_API_TOKEN": "e2e-unused-token-000000000000"}
        log = open(Path(tmp, "backend.log"), "w")  # noqa: SIM115
        backend = subprocess.Popen([args.python, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port",
                                    str(port)], cwd=ROOT / "backend", env=env, stdout=log, stderr=subprocess.STDOUT)
        home = str(Path(tmp, "agent-home"))
        try:
            wait_health(base, backend)
            api = Api(base)
            api.csrf = api.call("POST", "/api/auth/login", {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})["csrf_token"]
            token = api.call("POST", "/api/devices/enrollment-tokens",
                             {"name": "e2e", "max_uses": 2, "expires_in_hours": 1})["token"]

            # 1. https is enforced unless --insecure-dev
            p = run_agent(agent, home, "enroll", "--server", base, "--token", token, check=False)
            assert p.returncode != 0 and "https" in p.stderr, "plain http must be refused without --insecure-dev"

            # 2. enroll + first check-in
            run_agent(agent, home, "enroll", "--server", base, "--token", token, "--insecure-dev")
            run_agent(agent, home, "status")
            run_agent(agent, home, "checkin")
            devices = api.call("GET", "/api/devices")
            assert len(devices) == 1, devices
            dev = api.call("GET", f"/api/devices/{devices[0]['id']}")
            assert dev["os_family"] == expected_os, dev["os_family"]
            for check in ("disk_encryption", "firewall", "antivirus", "os_updates", "local_admins"):
                assert check in dev["posture"], f"posture check {check} missing: {sorted(dev['posture'])}"
            software = api.call("GET", f"/api/devices/{dev['id']}/software")
            print(f"device {dev['hostname']} ({dev['os_name']} {dev['os_version']}), health={dev['health']}, "
                  f"{len(software)} apps, issues={[i['code'] for i in dev['issues']]}")
            print("posture:", json.dumps({k: v["status"] for k, v in dev["posture"].items()}))
            if dev["collection_errors"]:
                print("collector errors:", json.dumps(dev["collection_errors"], indent=1))
            if expected_os in ("windows", "macos"):
                assert len(software) > 0, "no installed software collected"

            # 3. remote commands
            ids = {}
            for t, params in (("recheck_posture", {}), ("collect_logs", {}),
                              ("update_check_in_interval", {"interval_seconds": 600})):
                ids[t] = api.call("POST", f"/api/devices/{dev['id']}/commands",
                                  {"type": t, "reason": "e2e test", "params": params})["id"]
            run_agent(agent, home, "checkin")
            cmds = {c["id"]: c for c in api.call("GET", f"/api/devices/{dev['id']}/commands")}
            for t, cid in ids.items():
                assert cmds[cid]["status"] == "succeeded", (t, cmds[cid])
            bundle = api.call("GET", f"/api/devices/{dev['id']}/log-bundles/{cmds[ids['collect_logs']]['log_bundle_id']}",
                              raw=True)
            names = tarfile.open(fileobj=io.BytesIO(gzip.decompress(bundle))).getnames()
            assert "inventory.json" in names and "state.json" in names, names
            with tarfile.open(fileobj=io.BytesIO(gzip.decompress(bundle))) as tf:
                state_json = tf.extractfile("state.json").read().decode()
            assert "cnd_" not in state_json, "log bundle leaks the device secret"
            assert api.call("GET", f"/api/devices/{dev['id']}")["check_in_interval_seconds"] == 600
            assert len(api.call("GET", f"/api/devices/{dev['id']}/history")) >= 2

            if args.service:
                service_test(api, agent, home, dev["id"])

            # 4. re-enrollment keeps the same device and rotates the secret
            run_agent(agent, home, "enroll", "--server", base, "--token", token, "--insecure-dev")
            assert len(api.call("GET", "/api/devices")) == 1

            # 5. revocation: the agent is rejected
            api.call("POST", f"/api/devices/{dev['id']}/revoke", {"reason": "e2e revoke"})
            p = run_agent(agent, home, "checkin", check=False)
            assert p.returncode != 0 and "403" in p.stderr, "revoked device was not rejected"
            print("E2E OK")
            return 0
        finally:
            backend.terminate()
            try:
                backend.wait(timeout=20)
            except subprocess.TimeoutExpired:
                backend.kill()
            log.close()
            if os.environ.get("E2E_SHOW_BACKEND_LOG"):
                print(Path(tmp, "backend.log").read_text()[-5000:])


if __name__ == "__main__":
    sys.exit(main())
