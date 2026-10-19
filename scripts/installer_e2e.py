#!/usr/bin/env python3
# ruff: noqa: S105, S310, S603, S607  (test harness: fixed local URLs, binaries and throwaway credentials)
"""End-to-end test of the one-click agent installers (stdlib only). CI only:
it installs real Windows services / macOS LaunchDaemons.

prepare  (Linux, against the real backend Docker image)
    Logs in to a backend started from the CI image (PUBLIC_BASE_URL and
    AGENT_CA_CERT_B64 set), downloads a pre-configured Windows MSI and macOS
    pkg through POST /api/devices/installers, checks their content, and leaves
    them in --out next to the image's SQLite database (which holds the hashed
    package tokens).

run      (windows-latest / macos-latest)
    Starts the backend over HTTPS (certificate from a private CA, so the CA
    embedded in the installers is exercised) on that database, then:
      Windows: msiexec /i <pre-configured.msi> /qn -> service running, device
               auto-enrolled, token deleted from disk; repair does not
               re-enroll; msiexec /x removes service, files and state; then the
               generic MSI with CNAPP_SERVER/CNAPP_TOKEN/CNAPP_CA_B64 properties.
      macOS:   installer -pkg <pre-configured.pkg> -> LaunchDaemon running,
               auto-enrolled, token deleted; reinstall does not re-enroll;
               cnapp-uninstall.sh removes everything; then the generic pkg +
               `cnapp-agent configure` (MDM flow).
"""
from __future__ import annotations

import argparse
import base64
import http.cookiejar
import json
import os
import platform
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADMIN_EMAIL = "installer-e2e@example.com"
ADMIN_PASSWORD = "installer-e2e-password-123"
PORT = 8443
SERVER = f"https://127.0.0.1:{PORT}"
GROUP = "CI rollout"


class Api:
    def __init__(self, base: str, cafile: str | None = None):
        self.base = base
        self.csrf = ""
        handlers: list = [urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
        if cafile:
            handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=cafile)))
        self.opener = urllib.request.build_opener(*handlers)

    def call(self, method: str, path: str, body=None, raw: bool = False):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.csrf and method not in ("GET", "HEAD"):
            req.add_header("X-CSRF-Token", self.csrf)
        try:
            with self.opener.open(req, timeout=120) as r:
                payload = r.read()
                if raw:
                    return payload, dict(r.headers)
                return json.loads(payload) if payload else None
        except urllib.error.HTTPError as e:
            raise SystemExit(f"{method} {path} -> {e.code}: {e.read()[:500]!r}") from None

    def login(self) -> None:
        self.csrf = self.call("POST", "/api/auth/login", {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})["csrf_token"]

    def tokens(self) -> list[dict]:
        return self.call("GET", "/api/devices/enrollment-tokens")

    def devices(self) -> list[dict]:
        return self.call("GET", "/api/devices?status=all")


def wait_for(what: str, fn, timeout: float, interval: float = 3) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if fn():
            print(f"ok: {what}", flush=True)
            return
        time.sleep(interval)
    raise SystemExit(f"timed out waiting for: {what}")


def read_log(path: Path) -> str:
    """msiexec logs are UTF-16 (with BOM) or ANSI depending on the options."""
    b = path.read_bytes()
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return b.decode("utf-16", errors="replace")
    return b.decode("utf-8", errors="replace")


def sh(*cmd: str, check: bool = True, quiet: bool = False) -> subprocess.CompletedProcess:
    if not quiet:
        print("+", " ".join(cmd), flush=True)
    p = subprocess.run(list(cmd), capture_output=True, text=True, timeout=900)
    if not quiet:
        sys.stdout.write(p.stdout[-3000:])
        sys.stderr.write(p.stderr[-3000:])
    if check and p.returncode != 0:
        raise SystemExit(f"{cmd[0]} failed with exit code {p.returncode}")
    return p


# ============================================================================ prepare
def prepare(args) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    api = Api(args.base)
    deadline = time.time() + 180
    while True:
        try:
            api.login()
            break
        except (SystemExit, OSError):
            if time.time() > deadline:
                raise
            time.sleep(2)
    info = api.call("GET", "/api/devices/installers")
    print(json.dumps({k: v for k, v in info.items() if k != "platforms"}))
    assert info["server_url"] == SERVER and info["ca_configured"], info
    for p in ("windows-msi", "macos-pkg"):
        assert info["platforms"][p]["available"], info["platforms"][p]
    for p, fname in (("windows-msi", "cnapp-agent-setup.msi"), ("macos-pkg", "cnapp-agent-setup.pkg")):
        data, headers = api.call("POST", "/api/devices/installers",
                                 {"platform": p, "max_devices": 5, "expires_in_days": 1, "device_group": GROUP},
                                 raw=True)
        headers = {k.lower(): v for k, v in headers.items()}
        assert headers["x-ca-included"] == "true", headers
        (out / fname).write_bytes(data)
        print(f"{p}: {len(data)} bytes, sha256 {headers['x-content-sha256']}, token id {headers['x-enrollment-token-id']}")
    tokens = api.tokens()
    assert sorted(t["package_platform"] for t in tokens) == ["macos-pkg", "windows-msi"], tokens
    return 0


# ============================================================================ run
def start_backend(bundle: Path, tmp: Path, python: str) -> tuple[subprocess.Popen, Path]:
    dbfile = tmp / "cnapp.db"
    for f in bundle.glob("cnapp.db*"):  # include a -wal file, if any
        (tmp / f.name).write_bytes(f.read_bytes())
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{dbfile.as_posix()}", "SIMULATION_MODE": "false",
           "ADMIN_EMAIL": ADMIN_EMAIL, "ADMIN_PASSWORD": ADMIN_PASSWORD, "APP_ENV": "development",
           "INGEST_API_TOKEN": "e2e-unused-token-000000000000", "PUBLIC_BASE_URL": SERVER,
           "AGENT_CA_CERT_B64": base64.b64encode((bundle / "ca.crt").read_bytes()).decode()}
    log = tmp / "backend.log"
    proc = subprocess.Popen([python, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(PORT),
                             "--ssl-keyfile", str(bundle / "server.key"), "--ssl-certfile", str(bundle / "server.crt")],
                            cwd=ROOT / "backend", env=env, stdout=log.open("w"), stderr=subprocess.STDOUT)
    return proc, log


def package_token(api: Api, plat: str) -> dict:
    return next(t for t in api.tokens() if t["package_platform"] == plat)


def windows_run(api: Api, bundle: Path, tmp: Path) -> None:
    pd = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "CNAPP Agent"
    pf = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "CNAPP Agent"
    setup = bundle / "cnapp-agent-setup.msi"
    generic = bundle / "cnapp-agent-windows-x64.msi"

    def svc_state() -> str:
        p = sh("sc.exe", "query", "CNAPPAgent", check=False, quiet=True)
        if p.returncode == 1060:
            return "missing"
        return "RUNNING" if "RUNNING" in p.stdout else p.stdout.strip()[-200:]

    def msi_property(msi: Path, name: str) -> str:
        """Read a Property-table value with Windows Installer itself (msilib, Python <= 3.12)."""
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            import msilib
        db = msilib.OpenDatabase(str(msi), msilib.MSIDBOPEN_READONLY)
        view = db.OpenView(f"SELECT `Value` FROM `Property` WHERE `Property` = '{name}'")  # noqa: S608
        view.Execute(None)
        rec = view.Fetch()
        value = rec.GetString(1) if rec is not None else ""
        view.Close()
        db.Close()
        return value

    def msiexec(*a: str, log: str) -> None:
        p = sh("msiexec.exe", *a, "/qn", "/norestart", "/l*v", str(tmp / log), check=False)
        if p.returncode not in (0, 3010):
            lines = read_log(tmp / log).splitlines()
            hits = [i for i, line in enumerate(lines) if "Return value 3" in line]
            hits += [i for i, line in enumerate(lines) if "actual error code" in line or "Error 1" in line
                     or "Product: " in line]
            shown: set[int] = set()
            for i in hits[:8]:
                for j in range(max(0, i - 40), min(len(lines), i + 3)):
                    if j not in shown:
                        print(lines[j])
                        shown.add(j)
            agent_log = pd / "logs" / "agent.log"
            if agent_log.exists():
                print("--- agent.log\n" + agent_log.read_text(errors="replace")[-3000:])
            raise SystemExit(f"msiexec {' '.join(a)} failed with {p.returncode}")

    def preset(msi: Path) -> dict | None:
        # msilib cannot return a 16,000-character string (ERROR_MORE_DATA), so read the
        # value with the backend's parser; msiexec below is what proves Windows reads it.
        sys.path.insert(0, str(ROOT / "backend"))
        from app.services import msipatch

        value = msipatch.read_preset(msi.read_bytes())
        if value is None:
            return None
        assert value.startswith("CNAPPPRESET:v1:"), value[:30]
        return json.loads(base64.b64decode(value[len("CNAPPPRESET:v1:"):]))

    cfg = preset(setup)
    assert cfg and cfg["server_url"] == SERVER and cfg.get("ca_pem"), "pre-configured MSI has no usable preset"
    token = cfg["token"]
    assert preset(generic) is None, "generic MSI must not carry a preset"
    assert msi_property(generic, "CNAPP_TOKEN") == ""
    pt = package_token(api, "windows-msi")
    assert token.startswith(pt["token_prefix"]) and pt["use_count"] == 0

    # 1. Silent install of the pre-configured MSI.
    msiexec("/i", str(setup), log="install.log")
    install_log = read_log(tmp / "install.log")
    assert token not in install_log, "the enrollment token leaked into the MSI log"
    wait_for("CNAPPAgent service running", lambda: svc_state() == "RUNNING", 120)
    wait_for("device auto-enrolled from the MSI", lambda: package_token(api, "windows-msi")["use_count"] == 1, 240)
    wait_for("first check-in", lambda: any(d["last_checkin_at"] for d in api.devices()), 240)
    devices = api.devices()
    assert len(devices) == 1 and devices[0]["os_family"] == "windows" and devices[0]["device_group"] == GROUP, devices
    device_id = devices[0]["id"]
    assert (pd / "state.json").exists() and (pd / "ca.pem").exists(), "credential / CA not stored"
    assert not (pd / "enroll.json").exists(), "enroll.json (token) left on disk"
    acl = sh("icacls", str(pd), quiet=True).stdout
    print(acl)
    assert "BUILTIN\\Users" not in acl and "Everyone" not in acl, "state dir readable by non-admins"
    print(sh(str(pf / "cnapp-agent.exe"), "status", quiet=True).stdout)

    # 2. Repair / re-install of the same package: no re-enrollment, identity kept.
    msiexec("/fa", str(setup), log="repair.log")
    sh("net", "stop", "CNAPPAgent", check=False)
    sh("net", "start", "CNAPPAgent")
    time.sleep(20)
    assert package_token(api, "windows-msi")["use_count"] == 1, "repair re-enrolled the device"
    assert [d["id"] for d in api.devices()] == [device_id]
    assert not (pd / "enroll.json").exists()

    # 3. Uninstall removes the service, the binary and the state.
    msiexec("/x", str(setup), log="uninstall.log")
    assert svc_state() == "missing", "service still registered"
    assert not pf.exists(), f"{pf} left behind"
    assert not (pd / "state.json").exists(), "credential left behind"
    print("ok: uninstall removed service, files and state")

    # 4. Generic MSI + properties (admin-signed MSI deployed via GPO/Intune).
    tok = api.call("POST", "/api/devices/enrollment-tokens", {"name": "e2e generic msi", "max_uses": 1,
                                                              "expires_in_hours": 1})["token"]
    ca_b64 = base64.b64encode((bundle / "ca.crt").read_bytes()).decode()
    msiexec("/i", str(generic), f"CNAPP_SERVER={SERVER}", f"CNAPP_TOKEN={tok}", f"CNAPP_CA_B64={ca_b64}",
            log="generic.log")
    assert tok not in read_log(tmp / "generic.log"), "token in MSI log"
    wait_for("re-enrolled with the generic MSI + properties",
             lambda: any(t["use_count"] == 1 for t in api.tokens() if t["name"] == "e2e generic msi"), 240)
    devices = api.devices()
    assert [d["id"] for d in devices] == [device_id], "same machine must keep its device record"
    msiexec("/x", str(generic), log="generic-uninstall.log")
    assert svc_state() == "missing" and not pf.exists()


def macos_run(api: Api, bundle: Path, tmp: Path) -> None:
    label = "system/com.cloudsecurity.cnapp-agent"
    state_dir = "/Library/Application Support/CNAPP Agent"
    agent = "/usr/local/cnapp-agent/bin/cnapp-agent"
    setup = bundle / "cnapp-agent-setup.pkg"
    generic = bundle / "cnapp-agent-macos-universal.pkg"

    def running() -> bool:
        p = sh("sudo", "-n", "launchctl", "print", label, check=False, quiet=True)
        return p.returncode == 0 and "state = running" in p.stdout

    def exists(path: str) -> bool:
        return sh("sudo", "-n", "test", "-e", path, check=False, quiet=True).returncode == 0

    sh("pkgutil", "--check-signature", str(setup), check=False)
    sh("pkgutil", "--payload-files", str(setup))
    pt = package_token(api, "macos-pkg")
    assert pt["use_count"] == 0

    # 1. Silent install of the pre-configured package.
    sh("sudo", "-n", "installer", "-pkg", str(setup), "-target", "/")
    wait_for("LaunchDaemon running", running, 120)
    wait_for("device auto-enrolled from the pkg", lambda: package_token(api, "macos-pkg")["use_count"] == 1, 240)
    wait_for("first check-in", lambda: any(d["last_checkin_at"] for d in api.devices()), 300)
    devices = api.devices()
    assert len(devices) == 1 and devices[0]["os_family"] == "macos" and devices[0]["device_group"] == GROUP, devices
    device_id = devices[0]["id"]
    assert exists(f"{state_dir}/state.json") and exists(f"{state_dir}/ca.pem")
    assert not exists(f"{state_dir}/enroll.json"), "enroll.json (token) left on disk"
    print(sh("sudo", "-n", agent, "status", quiet=True).stdout)

    # 2. Re-install: no re-enrollment.
    sh("sudo", "-n", "installer", "-pkg", str(setup), "-target", "/")
    wait_for("LaunchDaemon running after re-install", running, 120)
    time.sleep(15)
    assert package_token(api, "macos-pkg")["use_count"] == 1, "re-install re-enrolled the device"
    assert [d["id"] for d in api.devices()] == [device_id]
    assert not exists(f"{state_dir}/enroll.json")

    # 3. Uninstall.
    sh("sudo", "-n", "/usr/local/cnapp-agent/bin/cnapp-uninstall.sh")
    assert not running() and not exists("/Library/LaunchDaemons/com.cloudsecurity.cnapp-agent.plist")
    assert not exists("/usr/local/cnapp-agent") and not exists(f"{state_dir}/state.json")
    assert sh("pkgutil", "--pkg-info", "com.cloudsecurity.cnapp-agent", check=False, quiet=True).returncode != 0
    print("ok: uninstall removed daemon, files, state and receipt")

    # 4. Generic pkg (signable) + `cnapp-agent configure` from an MDM script.
    sh("sudo", "-n", "installer", "-pkg", str(generic), "-target", "/")
    wait_for("LaunchDaemon running (waiting for enrollment)", running, 120)
    tok = api.call("POST", "/api/devices/enrollment-tokens", {"name": "e2e generic pkg", "max_uses": 1,
                                                              "expires_in_hours": 1})["token"]
    p = subprocess.run(["sudo", "-n", agent, "configure", "--server", SERVER, "--token-stdin",
                        "--ca-file", str(bundle / "ca.crt")], input=tok + "\n", text=True, capture_output=True)
    print(p.stdout, p.stderr)
    assert p.returncode == 0
    wait_for("enrolled via configure (daemon polls for the config)",
             lambda: any(t["use_count"] == 1 for t in api.tokens() if t["name"] == "e2e generic pkg"), 200)
    assert [d["id"] for d in api.devices()] == [device_id]
    sh("sudo", "-n", "/usr/local/cnapp-agent/bin/cnapp-uninstall.sh")
    assert not running() and not exists("/usr/local/cnapp-agent")


def run(args) -> int:
    bundle = Path(args.bundle).resolve()
    with tempfile.TemporaryDirectory(prefix="cnapp-inst-e2e-", ignore_cleanup_errors=True) as t:
        tmp = Path(t)
        backend, log = start_backend(bundle, tmp, args.python)
        try:
            api = Api(SERVER, cafile=str(bundle / "ca.crt"))
            wait_for("backend healthy over HTTPS", lambda: _healthy(api, backend), 120, 1)
            api.login()
            if platform.system() == "Windows":
                windows_run(api, bundle, tmp)
            elif platform.system() == "Darwin":
                macos_run(api, bundle, tmp)
            else:
                raise SystemExit("run is for Windows and macOS runners")
            print("installer end-to-end: all checks passed")
            return 0
        finally:
            backend.terminate()
            try:
                backend.wait(15)
            except subprocess.TimeoutExpired:
                backend.kill()
            print("--- backend log (tail)")
            print(log.read_text(errors="replace")[-5000:])


def _healthy(api: Api, proc: subprocess.Popen) -> bool:
    if proc.poll() is not None:
        raise SystemExit("backend exited early")
    try:
        return api.call("GET", "/api/health")["status"] == "ok"
    except (OSError, SystemExit):
        return False


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--base", required=True)
    p.add_argument("--out", required=True)
    r = sub.add_parser("run")
    r.add_argument("--bundle", required=True)
    r.add_argument("--python", default=sys.executable)
    args = ap.parse_args()
    return prepare(args) if args.cmd == "prepare" else run(args)


if __name__ == "__main__":
    sys.exit(main())
