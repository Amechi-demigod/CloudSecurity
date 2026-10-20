#!/usr/bin/env python3
# ruff: noqa: S105, S310, S603, S607  (test harness: fixed local URLs, binaries and throwaway keys)
"""End-to-end test of signed agent self-update on a real Windows service / macOS LaunchDaemon.

CI only (installs a real OS service, uses sudo on macOS). It:

 1. creates two throwaway Ed25519 release keys: K1 (compiled into the agent
    builds) and K2 (trusted by the SERVER only, simulating a compromised or
    misconfigured server that accepts another key),
 2. builds agent versions A=1.0.0, B=1.1.0, C=1.2.0 (-tags e2e_broken: passes
    the pre-flight check but exits on start), D=1.3.0, E=1.4.0, all trusting K1,
 3. starts the real backend (SQLite) trusting K1 and K2, enrolls A and installs
    it as the OS service,
 4. imports B (signed by K1) via the admin API, targets the "All devices" ring
    -> the service downloads, verifies, swaps itself to B, restarts, checks in;
    device id and credential unchanged,
 5. imports C via the CLI, targets it -> C fails its health check -> the
    watchdog restores B automatically and B reports rolled_back,
 6. D signed only by K2 -> the server accepts it, the AGENT rejects it,
 7. E signed by K1, then its binary is altered in the server database -> the
    agent rejects the hash mismatch,
 8. a tampered bundle upload is refused by the server,
 9. uninstalls the service.

    python scripts/update_e2e.py
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent_release as rel  # noqa: E402
from agent_e2e import ADMIN_EMAIL, ADMIN_PASSWORD, Api, free_port, wait_health  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
AGENT_DIR = ROOT / "endpoint-agent"
PKG = "github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal"
WINDOWS = platform.system() == "Windows"
SUDO = [] if WINDOWS else ["sudo", "-n"]
EXE = ".exe" if WINDOWS else ""
INSTALLED = (Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "CNAPP Agent" / "cnapp-agent.exe"
             if WINDOWS else Path("/usr/local/cnapp-agent/bin/cnapp-agent"))


def sh(cmd: list[str], check: bool = True, **kw) -> subprocess.CompletedProcess:
    print("+", " ".join(str(c) for c in cmd), flush=True)
    p = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, timeout=900, **kw)
    if p.stdout.strip():
        print(p.stdout[-3000:])
    if p.stderr.strip():
        print(p.stderr[-3000:], file=sys.stderr)
    if check and p.returncode != 0:
        raise SystemExit(f"command failed ({p.returncode}): {cmd[0]}")
    return p


def go_env(key: str) -> str:
    return subprocess.run(["go", "env", key], capture_output=True, text=True, check=True, cwd=AGENT_DIR).stdout.strip()


def build(out: Path, version: str, trusted_line: str, tags: str = "") -> Path:
    ldflags = (f"-s -w -X '{PKG}/version.Version={version}' -X '{PKG}/update.ExtraTrustedKeys={trusted_line}'")
    cmd = ["go", "build", "-trimpath", "-ldflags", ldflags, "-o", str(out)]
    if tags:
        cmd += ["-tags", tags]
    sh([*cmd, "./cmd/cnapp-agent"], cwd=AGENT_DIR, env={**os.environ, "CGO_ENABLED": "0"})
    return out


def bundle(work: Path, version: str, binary: Path, keys, name: str) -> Path:
    d = work / f"stage-{version}"
    d.mkdir()
    art = d / f"cnapp-agent-{go_env('GOOS')}-{go_env('GOARCH')}{EXE}"
    shutil.copy2(binary, art)
    m = rel.build_manifest(version, [art], days=7, min_supported="0.0.0", notes=f"e2e {name}", rollback_from=[])
    out = work / f"{name}.tar.gz"
    rel.write_bundle(out, rel.sign_manifest(m, keys), [art])
    return out


def upload(api: Api, data: bytes, expect: int = 201) -> dict:
    import urllib.error
    import urllib.request

    req = urllib.request.Request(api.base + "/api/updates/releases", data=data, method="POST")
    req.add_header("Content-Type", "application/gzip")
    req.add_header("X-CSRF-Token", api.csrf)
    try:
        with api.opener.open(req, timeout=120) as r:
            assert r.status == expect, r.status
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        if e.code != expect:
            raise SystemExit(f"upload -> {e.code}: {body}") from None
        return json.loads(body)


def agent_cmd(binary: Path | str, home: str, *args: str, check: bool = True):
    return sh([*SUDO, binary, *args, "--home", home], check=check)


def read_state(home: str) -> dict:
    p = Path(home, "state", "state.json")
    raw = sh([*SUDO, "cat", p], check=True).stdout if SUDO else p.read_text()
    return json.loads(raw)


def service_running() -> bool:
    if WINDOWS:
        return "RUNNING" in subprocess.run(["sc.exe", "query", "CNAPPAgent"], capture_output=True, text=True).stdout
    out = subprocess.run([*SUDO, "launchctl", "print", "system/com.cloudsecurity.cnapp-agent"],
                         capture_output=True, text=True).stdout
    return "state = running" in out


def installed_version() -> str:
    return subprocess.run([str(INSTALLED), "version"], capture_output=True, text=True, timeout=30).stdout.strip()


def show_logs(home: str) -> None:
    f = Path(home, "logs", "agent.log")
    if WINDOWS:
        if f.exists():
            print("".join(f.read_text(errors="replace").splitlines(keepends=True)[-120:]))
    else:
        sh([*SUDO, "tail", "-n", "120", f], check=False)
        sh([*SUDO, "tail", "-n", "40", "/Library/Logs/CNAPP Agent/launchd.log"], check=False)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    work = Path(tempfile.mkdtemp(prefix="cnapp-upd-"))
    k1, k2 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    line1, line2 = rel.trusted_line(k1), rel.trusted_line(k2)
    goos = go_env("GOOS")
    print(f"agent trusts {line1.split()[0]}; server also trusts {line2.split()[0]}")

    bins = {v: build(work / f"agent-{v}{EXE}", v, line1, tags) for v, tags in
            (("1.0.0", ""), ("1.1.0", ""), ("1.2.0", "e2e_broken"), ("1.3.0", ""), ("1.4.0", ""))}

    port = free_port()
    base = f"http://127.0.0.1:{port}"
    dbfile = work / "e2e.db"
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{dbfile.as_posix()}", "SIMULATION_MODE": "false",
           "ADMIN_EMAIL": ADMIN_EMAIL, "ADMIN_PASSWORD": ADMIN_PASSWORD, "COOKIE_SECURE": "false",
           "APP_ENV": "development", "INGEST_API_TOKEN": "e2e-unused-token-000000000000",
           "AGENT_UPDATE_TRUSTED_KEYS": f"{line1};{line2}", "AGENT_UPDATE_JITTER_SECONDS": "0",
           "AGENT_UPDATE_HEALTH_TIMEOUT_SECONDS": "90"}
    log = open(work / "backend.log", "w")  # noqa: SIM115
    backend = subprocess.Popen([args.python, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port",
                                str(port)], cwd=ROOT / "backend", env=env, stdout=log, stderr=subprocess.STDOUT)
    home = str(work / "agent-home")
    installed = False
    ok = False
    try:
        wait_health(base, backend)
        api = Api(base)
        api.csrf = api.call("POST", "/api/auth/login", {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})["csrf_token"]
        token = api.call("POST", "/api/devices/enrollment-tokens", {"name": "upd-e2e", "max_uses": 1,
                                                                     "expires_in_hours": 1})["token"]

        # --- A: enroll + install as the OS service ------------------------------------------
        agent_cmd(bins["1.0.0"], home, "enroll", "--server", base, "--token", token, "--insecure-dev")
        agent_cmd(bins["1.0.0"], home, "install")
        installed = True
        dev_id = api.call("GET", "/api/devices")[0]["id"]
        secret_hash = hashlib.sha256(read_state(home)["device_secret"].encode()).hexdigest()
        print(f"device {dev_id}; binary {INSTALLED} reports {installed_version()}")
        assert installed_version() == "1.0.0"

        def device() -> dict:
            return api.call("GET", f"/api/devices/{dev_id}")

        def upd() -> dict:
            return api.call("GET", f"/api/updates/devices/{dev_id}")

        def wait(what: str, cond, timeout: float) -> None:
            deadline = time.time() + timeout
            last_kick = 0.0
            while time.time() < deadline:
                if cond():
                    print(f"ok: {what}", flush=True)
                    return
                if time.time() - last_kick > 90:  # make the agent check in (and see the offer) soon
                    try:
                        api.call("POST", f"/api/devices/{dev_id}/commands",
                                 {"type": "recheck_posture", "reason": "update e2e: check in now"})
                    except SystemExit as e:
                        print("queueing recheck failed:", e)
                    last_kick = time.time()
                time.sleep(5)
            print(json.dumps(upd(), indent=1))
            raise SystemExit(f"timed out waiting for: {what}")

        wait("service checked in as 1.0.0", lambda: device()["agent_version"] == "1.0.0" and
             len(api.call("GET", f"/api/devices/{dev_id}/history")) >= 1, 240)
        all_ring = next(r for r in api.call("GET", "/api/updates/rings") if r["name"] == "All devices")

        def target(release_id: str) -> None:
            api.call("PATCH", f"/api/updates/rings/{all_ring['id']}",
                     {"reason": "update e2e", "target_release_id": release_id, "rollout_percent": 100})

        # --- B: signed by K1 -> self-update ------------------------------------------------
        rb = upload(api, bundle(work, "1.1.0", bins["1.1.0"], [k1], "B").read_bytes())
        assert rb["key_id"] == line1.split()[0], rb
        target(rb["id"])
        wait("agent self-updated to 1.1.0 and reported installed",
             lambda: device()["agent_version"] == "1.1.0" and upd()["status"] == "installed", 600)
        hist = [h["status"] for h in upd()["history"]][::-1]
        print("history:", hist)
        for s in ("downloading", "verified", "installing", "installed"):
            assert s in hist, (s, hist)
        assert installed_version() == "1.1.0", installed_version()
        assert service_running(), "service not running after the update"
        assert [d["id"] for d in api.call("GET", "/api/devices")] == [dev_id], "device identity changed"
        assert hashlib.sha256(read_state(home)["device_secret"].encode()).hexdigest() == secret_hash, \
            "device credential changed"
        print("PASS: self-update 1.0.0 -> 1.1.0, identity and credential preserved")

        # --- C: broken release imported via the CLI -> automatic rollback ------------------
        c_bundle = bundle(work, "1.2.0", bins["1.2.0"], [k1], "C")
        sh([args.python, "-m", "app.cli", "agent-release-import", str(c_bundle), "--actor", "e2e-cli"],
           cwd=ROOT / "backend", env=env)
        rc = next(r for r in api.call("GET", "/api/updates/releases") if r["version"] == "1.2.0")
        target(rc["id"])
        wait("broken 1.2.0 installed, failed its health check and was rolled back to 1.1.0",
             lambda: upd()["status"] == "rolled_back" and device()["agent_version"] == "1.1.0", 900)
        h = upd()["history"][0]
        print("rollback:", h)
        assert h["to_version"] == "1.2.0" and "health check" in h["detail"], h
        assert installed_version() == "1.1.0"
        wait("service running 1.1.0 again", service_running, 120)
        time.sleep(70)  # the rolled-back release must not be retried
        assert device()["agent_version"] == "1.1.0" and upd()["status"] == "rolled_back", upd()
        print("PASS: failed health check -> automatic rollback to 1.1.0")

        # --- D: signed by a key the agent does not trust ------------------------------------
        rd = upload(api, bundle(work, "1.3.0", bins["1.3.0"], [k2], "D").read_bytes())
        target(rd["id"])
        wait("agent rejected 1.3.0 (untrusted key)",
             lambda: upd()["status"] == "rejected" and upd()["status_version"] == "1.3.0", 400)
        assert "not signed by a trusted key" in upd()["status_detail"], upd()
        assert installed_version() == "1.1.0" and device()["agent_version"] == "1.1.0"
        print("PASS: release signed by an untrusted key rejected by the agent")

        # --- E: valid signature, binary altered on the server --------------------------------
        re_ = upload(api, bundle(work, "1.4.0", bins["1.4.0"], [k1], "E").read_bytes())
        con = sqlite3.connect(dbfile, timeout=30)
        with con:
            n = con.execute("UPDATE agent_release_artifacts SET data = ? WHERE release_id = ?",
                            (b"MZ-evil" + bins["1.4.0"].read_bytes()[7:], re_["id"])).rowcount
        con.close()
        assert n == 1, n
        target(re_["id"])
        wait("agent rejected 1.4.0 (artifact hash mismatch)",
             lambda: upd()["status"] == "rejected" and upd()["status_version"] == "1.4.0", 400)
        assert "SHA-256" in upd()["status_detail"], upd()
        assert installed_version() == "1.1.0" and service_running()
        print("PASS: tampered artifact rejected by the agent")

        # --- tampered bundle upload refused by the server ------------------------------------
        bad = bytearray(bundle(work, "1.5.0", bins["1.4.0"], [k1], "F").read_bytes())
        import gzip
        import io
        import tarfile
        raw = gzip.decompress(bytes(bad))
        tf = tarfile.open(fileobj=io.BytesIO(raw))
        files = {m.name: tf.extractfile(m).read() for m in tf.getmembers()}
        name = next(n for n in files if n != "manifest.json")
        files[name] = files[name][:-1] + b"\0"
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w:gz") as t2:
            for n, d in files.items():
                ti = tarfile.TarInfo(n)
                ti.size = len(d)
                t2.addfile(ti, io.BytesIO(d))
        r = upload(api, out.getvalue(), expect=422)
        assert "SHA-256" in r["detail"], r
        print("PASS: tampered bundle refused on import")

        actions = {e["action"] for e in api.call("GET", "/api/audit-log?limit=1000")}
        for a in ("agent_release_imported", "agent_update_ring_changed", "agent_update_installed",
                  "agent_update_rolled_back", "agent_update_rejected", "agent_release_rejected"):
            assert a in actions, (a, sorted(actions))
        print(f"UPDATE E2E OK on {goos}")
        ok = True
        return 0
    finally:
        if not ok:
            show_logs(home)
            print((work / "backend.log").read_text(errors="replace")[-6000:])
        if installed:
            agent_cmd(INSTALLED, home, "uninstall", check=False)
            leftovers = [p.name for p in INSTALLED.parent.glob("cnapp-agent*")] if INSTALLED.parent.exists() else []
            print("left in the install directory after uninstall:", leftovers)
        backend.terminate()
        try:
            backend.wait(timeout=20)
        except subprocess.TimeoutExpired:
            backend.kill()
        log.close()
        if not args.keep:
            if SUDO:
                subprocess.run([*SUDO, "rm", "-rf", str(work)], check=False)
            else:
                shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
