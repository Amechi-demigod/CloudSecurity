#!/usr/bin/env python3
# ruff: noqa: S105, S310, S603, S607  (test harness: fixed local URLs, binaries and throwaway credentials)
"""End-to-end test of the pre-configured directory collector MSI (stdlib only,
plus the backend's msipatch to read the preset). CI only: it installs a real
Windows service. Mirrors scripts/installer_e2e.py (same backend, bundle and CA).

prepare  (Linux, against the real backend Docker image, after installer_e2e prepare)
    Downloads a pre-configured collector MSI and zip through POST
    /api/collectors/installer (real cnct_ tokens in the image's database).

run      (windows-latest)
    Starts the backend over HTTPS on that database, then:
      * GMSA validation: a malformed value and an unknown gMSA fail the install
        before anything changes (no service, no binary, token unused);
      * msiexec /i <pre-configured.msi> /qn on a member server (no
        ALLOW_DOMAIN_CONTROLLER): service running as LocalSystem, the collector
        ENROLLS (listed by the API, matched to its download, heartbeat), token
        removed from disk, state folder protected; repair keeps the identity;
      * diagnostics: the console's Test (unsaved settings, as the wizard does)
        runs on the collector and reports a clean "no DC" failure per step, and
        the local `diagnose` command fails cleanly (not domain-joined);
      * a simulated self-update (a different, unversioned binary on disk), then
        an MSI upgrade to a newer build: the package's binary replaces it, the
        enrollment and the identity are kept, the new version reports in;
      * uninstall removes the service, program files, credential and settings;
      * take-over: a zip-installed collector, then the MSI over it: same
        enrollment (no new one), MSI-managed service; uninstall cleans up.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime
from pathlib import Path

from installer_e2e import ROOT, SERVER, Api, _healthy, read_log, sh, start_backend, wait_for

MSI = "collector-setup.msi"
ZIP = "collector-setup.zip"
GENERIC = "cnapp-collector-windows-x64.msi"
NAME = "CI collector"


# ============================================================================ prepare
def prepare(args) -> int:
    out = Path(args.out)
    api = Api(args.base)
    api.login()
    info = api.call("GET", "/api/collectors/installer/info")
    print(json.dumps(info, indent=1))
    assert info["server_url"] == SERVER and info["ca_configured"], info
    assert info["msi"]["available"] and info["arches"]["amd64"]["available"], info
    for fmt, fname in (("msi", MSI), ("zip", ZIP)):
        data, headers = api.call("POST", "/api/collectors/installer",
                                 {"name": NAME, "format": fmt, "expires_in_hours": 24}, raw=True)
        headers = {k.lower(): v for k, v in headers.items()}
        (out / fname).write_bytes(data)
        print(f"{fmt}: {len(data)} bytes ({headers['content-disposition']}), sha256 {headers['x-content-sha256']}, "
              f"token id {headers['x-enrollment-token-id']}, collector {headers['x-collector-version']}")
    tokens = api.call("GET", "/api/collectors/enrollment-tokens/list")
    assert sorted(t["package"] for t in tokens) == ["collector-amd64", "collector-msi"], tokens
    assert all(t["max_uses"] == 1 and t["use_count"] == 0 for t in tokens), tokens
    return 0


# ============================================================================ run
def ts(s: str | None) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() if s else 0.0


def windows_run(api: Api, bundle: Path, tmp: Path, upgrade_msi: Path | None, upgrade_version: str) -> None:
    import winreg

    sys.path.insert(0, str(ROOT / "backend"))
    from app.services import msipatch

    pd = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "CNAPP Collector"
    pf = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "CNAPP Collector"
    exe = pf / "cnapp-collector.exe"
    log_file = pd / "logs" / "agent.log"
    setup, generic = bundle / MSI, bundle / GENERIC

    def svc_state() -> str:
        p = sh("sc.exe", "query", "CNAPPCollector", check=False, quiet=True)
        if p.returncode == 1060:
            return "missing"
        return "RUNNING" if "RUNNING" in p.stdout else p.stdout.strip()[-200:]

    def svc_config() -> str:
        return sh("sc.exe", "qc", "CNAPPCollector", quiet=True).stdout

    def msi_property(msi: Path, name: str) -> str:
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

    def registered(product_code: str) -> bool:
        try:
            winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                           rf"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{product_code}"))
            return True
        except OSError:
            return False

    def show_failure(log: str) -> None:
        lines = read_log(tmp / log).splitlines()
        hits = [i for i, line in enumerate(lines) if "Return value 3" in line or "Error 1" in line
                or "actual error code" in line]
        shown: set[int] = set()
        for i in hits[:6]:
            for j in range(max(0, i - 30), min(len(lines), i + 3)):
                if j not in shown:
                    print(lines[j])
                    shown.add(j)
        if log_file.exists():
            print("--- collector log\n" + log_file.read_text(errors="replace")[-3000:])

    def msiexec(*a: str, log: str, ok: bool = True) -> int:
        p = sh("msiexec.exe", *a, "/qn", "/norestart", "/l*v", str(tmp / log), check=False)
        if ok and p.returncode not in (0, 3010):
            show_failure(log)
            raise SystemExit(f"msiexec {' '.join(a)} failed with {p.returncode}")
        return p.returncode

    def tokens() -> dict[str, dict]:
        return {t["package"]: t for t in api.call("GET", "/api/collectors/enrollment-tokens/list")}

    def collectors() -> list[dict]:
        return [c for c in api.call("GET", "/api/collectors") if c["status"] == "active"]

    def assert_removed(what: str) -> None:
        assert svc_state() == "missing", f"{what}: service still registered"
        assert not pf.exists(), f"{what}: {pf} left behind"
        assert not (pd / "state.json").exists(), f"{what}: credential left behind"
        assert not (pd / "service.json").exists(), f"{what}: service settings left behind"
        print(f"ok: {what} removed the service, program files, credential and settings")

    # 0. The download is a collector preset in a copy of the generic MSI, with its own ProductCode.
    value = msipatch.read_preset(setup.read_bytes())
    cfg = json.loads(base64.b64decode(value[len(msipatch.PRESET_PREFIX):]))
    assert cfg["kind"] == "collector" and cfg["server_url"] == SERVER and cfg.get("ca_pem"), "bad preset"
    token = cfg["token"]
    assert token.startswith("cnct_") and msipatch.read_preset(generic.read_bytes()) is None
    product = msi_property(setup, "ProductCode")
    assert product and product != msi_property(generic, "ProductCode"), "the download kept the generic ProductCode"
    assert msi_property(setup, "UpgradeCode") == msi_property(generic, "UpgradeCode")
    t = tokens()["collector-msi"]
    assert token.startswith(t["token_prefix"]) and t["use_count"] == 0
    assert svc_state() == "missing" and not collectors()

    # 1. GMSA is validated before anything changes.
    for bad, why in (("not-a-gmsa", "GMSA must be"), (r"WORKGROUP\no-such-gmsa$", "no-such-gmsa")):
        rc = msiexec("/i", str(setup), f"GMSA={bad}", log="bad-gmsa.log", ok=False)
        assert rc == 1603, f"GMSA={bad}: expected 1603, got {rc}"
        assert svc_state() == "missing" and not exe.exists(), f"GMSA={bad}: something was installed"
        assert not registered(product)
        assert why in log_file.read_text(errors="replace"), f"GMSA={bad}: reason not in {log_file}"
        assert token not in read_log(tmp / "bad-gmsa.log")
    assert tokens()["collector-msi"]["use_count"] == 0
    print("ok: malformed / unknown GMSA rejected, nothing installed")

    # 2. Silent install of the pre-configured MSI on a member server (no ALLOW_DOMAIN_CONTROLLER).
    msiexec("/i", str(setup), log="install.log")
    assert token not in read_log(tmp / "install.log"), "the enrollment token leaked into the MSI log"
    wait_for("CNAPPCollector service running", lambda: svc_state() == "RUNNING", 120)
    qc = svc_config()
    print(qc)
    assert "AUTO_START" in qc and "LocalSystem" in qc, "service must run as LocalSystem, automatic start"
    assert sh("sc.exe", "qfailure", "CNAPPCollector", quiet=True).stdout.count("RESTART") >= 3
    assert registered(product), "not registered in Apps / Add or Remove Programs"
    wait_for("collector enrolled with the MSI's token", lambda: tokens()["collector-msi"]["use_count"] == 1, 240)
    wait_for("collector listed and online", lambda: any(c["healthy"] for c in collectors()), 120)
    [col] = collectors()
    print(json.dumps({k: col[k] for k in ("name", "hostname", "domain", "run_as", "run_as_kind", "version",
                                          "is_domain_controller", "state", "last_seen_at")}))
    assert col["enrollment_token_id"] == t["id"], "the console cannot match the collector to its download"
    assert col["run_as_kind"] == "computer_account" and not col["is_domain_controller"] and col["version"]
    cid, enrolled_at = col["id"], col["enrolled_at"]
    assert (pd / "state.json").exists() and (pd / "ca.pem").exists() and (pd / "service.json").exists()
    assert not (pd / "enroll.json").exists(), "enroll.json (token) left on disk"
    acl = sh("icacls", str(pd), quiet=True).stdout
    print(acl)
    assert "BUILTIN\\Users" not in acl and "Everyone" not in acl, "state folder readable by non-admins"
    st = json.loads(sh(str(exe), "status", quiet=True).stdout)
    assert st["enrolled"] and st["collector_id"] == cid and st["server"] == SERVER, st
    # Heartbeat / command polling keep it seen.
    first_seen = ts(col["last_seen_at"])
    wait_for("collector polling (last_seen advances)",
             lambda: ts(api.call("GET", f"/api/collectors/{cid}")["last_seen_at"]) > first_seen + 20, 180, 10)

    # 3. Repair keeps the identity (no re-enrollment).
    msiexec("/fa", str(setup), log="repair.log")
    wait_for("running after repair", lambda: svc_state() == "RUNNING", 120)
    time.sleep(15)
    c = api.call("GET", f"/api/collectors/{cid}")
    assert c["enrolled_at"] == enrolled_at and tokens()["collector-msi"]["use_count"] == 1, "repair re-enrolled"
    assert "LocalSystem" in svc_config()

    # 4. Diagnostics without a domain: a clean result per step, not a crash.
    r = api.call("POST", f"/api/collectors/{cid}/test", {"config": {"domain": "corp.example.invalid"}})
    wait_for("diagnostics result from the collector",
             lambda: api.call("GET", f"/api/collectors/{cid}")["diagnostics"].get("status") not in (None, "queued"),
             240, 5)
    d = api.call("GET", f"/api/collectors/{cid}")["diagnostics"]
    print(json.dumps(d, indent=1))
    assert d["command_id"] == r["command_id"] and d["status"] == "failed", d
    ids = [s["id"] for s in d["steps"]]
    assert ids[0] == "dc_locator" and "fail" in [s["status"] for s in d["steps"]], d
    assert all(s["label"] for s in d["steps"]) and "panic" not in json.dumps(d).lower()
    p = sh(str(exe), "diagnose", check=False)
    assert p.returncode == 1 and "panic" not in (p.stdout + p.stderr).lower()
    assert "not domain-joined" in p.stderr or "FAIL" in p.stdout, "diagnose without a domain: unclear result"
    p = sh(str(exe), "diagnose", "--domain", "corp.example.invalid", check=False)
    assert p.returncode == 1 and "FAIL" in p.stdout and "panic" not in (p.stdout + p.stderr).lower()
    print("ok: diagnostics report a clean failure without a domain")

    # 5. Simulated self-update (another unversioned binary on disk), then an MSI upgrade.
    final = setup
    if upgrade_msi is not None:
        sh("net", "stop", "CNAPPCollector")
        original = exe.read_bytes()
        exe.write_bytes(original + b"\0simulated self-update")
        sh("net", "start", "CNAPPCollector")
        wait_for("running the 'self-updated' binary", lambda: svc_state() == "RUNNING", 60)
        msiexec("/i", str(upgrade_msi), log="upgrade.log")
        wait_for("running after the upgrade", lambda: svc_state() == "RUNNING", 120)
        assert not exe.read_bytes().endswith(b"simulated self-update"), "the MSI kept the self-updated binary"
        v = sh(str(exe), "version", quiet=True).stdout.strip()
        assert v.startswith(upgrade_version + "+") or v == upgrade_version, f"installed {v}, want {upgrade_version}"
        assert "LocalSystem" in svc_config()
        upgraded = msi_property(upgrade_msi, "ProductCode")
        assert registered(upgraded) and not registered(product), "the upgrade did not replace the old product"
        wait_for(f"collector reports {upgrade_version}",
                 lambda: api.call("GET", f"/api/collectors/{cid}")["version"].startswith(upgrade_version), 240, 10)
        c = api.call("GET", f"/api/collectors/{cid}")
        assert c["enrolled_at"] == enrolled_at and len(collectors()) == 1, "the upgrade re-enrolled"
        assert tokens()["collector-msi"]["use_count"] == 1
        final = upgrade_msi
        print("ok: MSI upgrade over a self-updated binary: package binary in place, identity kept")

    # 6. Uninstall.
    msiexec("/x", str(final), log="uninstall.log")
    assert_removed("uninstall")
    assert not registered(product) and not registered(msi_property(final, "ProductCode"))

    # 7. Take-over of a zip-installed collector.
    zdir = tmp / "zip"
    with zipfile.ZipFile(bundle / ZIP) as z:
        z.extractall(zdir)
    sh(str(zdir / "cnapp-collector.exe"), "install", "--preset", str(zdir / "collector.json"))
    wait_for("zip-installed collector enrolled", lambda: tokens()["collector-amd64"]["use_count"] == 1, 240)
    wait_for("zip collector online", lambda: api.call("GET", f"/api/collectors/{cid}")["enrollment_token_id"]
             == tokens()["collector-amd64"]["id"], 60)
    zip_enrolled = api.call("GET", f"/api/collectors/{cid}")["enrolled_at"]
    shutil.rmtree(zdir, ignore_errors=True)
    msiexec("/i", str(setup), log="takeover.log")
    wait_for("running after the take-over", lambda: svc_state() == "RUNNING", 120)
    assert registered(product) and "LocalSystem" in svc_config()
    assert json.loads((pd / "service.json").read_text())["source"] == "msi"
    time.sleep(20)
    c = api.call("GET", f"/api/collectors/{cid}")
    assert c["enrolled_at"] == zip_enrolled and len(collectors()) == 1, "the take-over re-enrolled the collector"
    assert json.loads(sh(str(exe), "status", quiet=True).stdout)["collector_id"] == cid
    msiexec("/x", str(setup), log="takeover-uninstall.log")
    assert_removed("uninstall after the take-over")


def run(args) -> int:
    bundle = Path(args.bundle).resolve()
    upgrade = Path(args.upgrade_msi).resolve() if args.upgrade_msi else None
    with tempfile.TemporaryDirectory(prefix="cnapp-coll-e2e-", ignore_cleanup_errors=True) as t:
        tmp = Path(t)
        backend, log = start_backend(bundle, tmp, args.python)
        try:
            api = Api(SERVER, cafile=str(bundle / "ca.crt"))
            wait_for("backend healthy over HTTPS", lambda: _healthy(api, backend), 120, 1)
            api.login()
            if platform.system() != "Windows":
                raise SystemExit("run is for Windows runners")
            windows_run(api, bundle, tmp, upgrade, args.upgrade_version)
            print("collector installer end-to-end: all checks passed")
            return 0
        finally:
            backend.terminate()
            try:
                backend.wait(15)
            except subprocess.TimeoutExpired:
                backend.kill()
            print("--- backend log (tail)")
            print(log.read_text(errors="replace")[-5000:])


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--base", required=True)
    p.add_argument("--out", required=True)
    r = sub.add_parser("run")
    r.add_argument("--bundle", required=True)
    r.add_argument("--upgrade-msi", default="", help="a newer generic collector MSI (upgrade test)")
    r.add_argument("--upgrade-version", default="", help="the collector version inside --upgrade-msi")
    r.add_argument("--python", default=sys.executable)
    args = ap.parse_args()
    return prepare(args) if args.cmd == "prepare" else run(args)


if __name__ == "__main__":
    sys.exit(main())
