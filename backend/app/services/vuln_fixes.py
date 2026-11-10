"""Remediation guidance for vulnerabilities: what to install to close which CVEs.

Two views are built from the same facts (docs/VULNERABILITIES.md#fixes-and-guidance):

* `device_fixes(db, device)`  the fixes of one device grouped by remediation: one Windows
  cumulative update closes every OS CVE of the device, each application upgrade closes its CVEs.
* `cve_detail(db, cve_id)`    the CVE page: summary facts, fix guidance (Windows version -> KB
  and build from Microsoft's Security Update Guide, or package upgrades), affected devices with
  what each needs, progress and a timeline.

Everything here is guidance. Nothing installs or changes a device, and no agent command is
involved. Windows KB / build data comes from the MSRC cache (vulnmatch/msrc.py); when it is
missing (feed offline, CVE not in the cached months) the fix degrades to "Install the latest
cumulative update" without KB numbers, using the fixed build NVD gives when there is one. The
device's state ("update offered, not installed", "restart pending", "updates failing") is
derived from its Windows Update report (services/os_updates.py).
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime
from functools import cache
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, undefer

from .. import config
from ..models import Device, DeviceOsUpdates, Vulnerability, VulnFeedStatus, utcnow
from ..vulnmatch import msrc
from ..vulnmatch.versions import SERVER_BY_BUILD, WIN10_BY_BUILD, WIN11_BY_BUILD, compare_versions
from . import os_updates as os_svc
from .vuln_sla import fix_due

SEV_ORDER = ("critical", "high", "medium", "low", "info")
OS_KEY = "os"
CATALOG = os_svc.CATALOG_URL
MAX_DEVICES = 500
KB_ARTICLE = "https://support.microsoft.com/help/"

# winget package ids of the products in the curated mapping (vulnmatch/mapping.py), Windows only.
# Only products with a stable, well-known id are listed; anything else shows the vendor's updater.
WINGET_IDS = {
    "chrome": "Google.Chrome", "edge": "Microsoft.Edge", "firefox": "Mozilla.Firefox",
    "firefox_esr": "Mozilla.Firefox.ESR", "thunderbird": "Mozilla.Thunderbird", "brave": "Brave.Brave",
    "zoom": "Zoom.Zoom", "acrobat_reader": "Adobe.Acrobat.Reader.64-bit", "libreoffice":
    "TheDocumentFoundation.LibreOffice", "notepadpp": "Notepad++.Notepad++", "nodejs": "OpenJS.NodeJS",
    "git": "Git.Git", "vscode": "Microsoft.VisualStudioCode", "powershell": "Microsoft.PowerShell",
    "docker_desktop": "Docker.DockerDesktop", "wireshark": "WiresharkFoundation.Wireshark",
    "virtualbox": "Oracle.VirtualBox", "7zip": "7zip.7zip", "winrar": "RARLab.WinRAR", "putty": "PuTTY.PuTTY",
    "winscp": "WinSCP.WinSCP", "filezilla": "TimKosse.FileZilla.Client", "vlc": "VideoLAN.VLC",
    "anydesk": "AnyDeskSoftwareGmbH.AnyDesk", "teamviewer": "TeamViewer.TeamViewer",
    "keepass": "DominikReichl.KeePass", "onedrive": "Microsoft.OneDrive",
}
# Homebrew casks (macOS) of the same products.
BREW_CASKS = {
    "chrome": "google-chrome", "firefox": "firefox", "firefox_esr": "firefox@esr", "thunderbird": "thunderbird",
    "brave": "brave-browser", "zoom": "zoom", "libreoffice": "libreoffice", "vscode": "visual-studio-code",
    "docker_desktop": "docker", "wireshark": "wireshark", "virtualbox": "virtualbox", "vlc": "vlc",
    "gimp": "gimp", "teamviewer": "teamviewer", "anydesk": "anydesk",
}
VENDOR_UPDATER = {
    "chrome": "Open Chrome, then menu (three dots) > Help > About Google Chrome. It downloads the update and asks "
              "you to relaunch.",
    "edge": "Open Edge, then menu (three dots) > Help and feedback > About Microsoft Edge. It updates and asks "
            "you to restart the browser.",
    "firefox": "Open Firefox, then menu > Help > About Firefox. It downloads the update and offers to restart.",
    "firefox_esr": "Open Firefox, then menu > Help > About Firefox. It downloads the update and offers to restart.",
    "thunderbird": "Open Thunderbird, then menu > Help > About Thunderbird to check for and apply updates.",
    "zoom": "Open Zoom, click your profile picture > Check for Updates.",
    "vscode": "In VS Code, Help > Check for Updates (or restart it when the update banner appears).",
}

OS_ACCESS = {"x64": "x64-based", "arm64": "ARM64-based"}


# ----------------------------------------------------------------------------- helpers
def sev_rank(s: str) -> int:
    return SEV_ORDER.index(s) if s in SEV_ORDER else len(SEV_ORDER)


def worst(sevs) -> str:
    return min(list(sevs) or ["info"], key=sev_rank)


def _days(since: datetime | None, now: datetime) -> int | None:
    return None if since is None else max(0, int((now - since).total_seconds() // 86400))


def z(dt: datetime | None) -> str | None:
    return dt.isoformat() + "Z" if dt is not None else None


def _is_server(name: str) -> bool:
    return "server" in (name or "").lower()


def device_build(device: Device) -> tuple[int, int] | None:
    """(build, UBR) of a Windows device: 22631.3593 -> (22631, 3593)."""
    b = msrc.parse_build(device.os_build or "")
    if b is not None:
        return b
    return msrc.parse_build((device.os_version or "").removeprefix("10.0."))


def build_label(build: int, server: bool = False) -> str:
    """"Windows 11 23H2", "Windows Server 2022"; "Windows build 22631" when unknown."""
    if server:
        p = SERVER_BY_BUILD.get(build)
        if p:
            return "Windows Server " + p.removeprefix("windows_server_").replace("_", " ").upper()
    if build in WIN11_BY_BUILD:
        return f"Windows 11 {WIN11_BY_BUILD[build].upper()}"
    if build in WIN10_BY_BUILD:
        return f"Windows 10 {WIN10_BY_BUILD[build].upper()}"
    return f"Windows build {build}"


_PRODUCT_BUILD = (
    (re.compile(r"Windows 11 Version (\w+)", re.I), "11"),
    (re.compile(r"Windows 10 Version (\w+)", re.I), "10"),
)


def product_build(name: str) -> int | None:
    """Feature-release build of an MSRC product name (only used when the record has no FixedBuild)."""
    for rx, fam in _PRODUCT_BUILD:
        m = rx.search(name)
        if m:
            table = WIN11_BY_BUILD if fam == "11" else WIN10_BY_BUILD
            for b, rel in table.items():
                if rel.lower() == m.group(1).lower():
                    return b
    m = re.search(r"Windows Server (2016|2019|2022|2025)(?:, (23H2) Edition)?", name)
    if m:
        key = "windows_server_2022_23h2" if m.group(2) else f"windows_server_{m.group(1)}"
        for b, p in SERVER_BY_BUILD.items():
            if p == key:
                return b
    if re.fullmatch(r"Windows 10 for (?:x64|32)-based Systems", name):
        return 10240
    return None


def fix_entries(rec: dict | None) -> list[dict[str, Any]]:
    """MSRC fix entries with (major build, UBR, KB) resolved."""
    out = []
    for f in (rec or {}).get("fix") or []:
        b = msrc.parse_build(f.get("b") or "")
        major, ubr = (b if b else (product_build(f.get("p", "")), 0))
        if major is None:
            continue
        out.append({"build": major, "ubr": ubr, "kb": f.get("kb"), "product": f.get("p", ""),
                    "server": _is_server(f.get("p", "")), "restart": f.get("rs"), "supersedes": f.get("sup"),
                    "fixed_build": f.get("b") or ""})
    return out


def _arch_matches(product: str, arch: str) -> bool:
    key = OS_ACCESS.get((arch or "").lower())
    return bool(key) and key in product


def requirement_for_build(rec: dict | None, nvd_fixed: str | None, build: int, server: bool, arch: str = ""
                          ) -> dict[str, Any] | None:
    """What a Windows device on feature release `build` needs for one CVE: {ubr, kb, restart, source}
    from MSRC, else from the NVD fixed version; None when neither says."""
    cands = [e for e in fix_entries(rec) if e["build"] == build and e["server"] == server]
    if cands:
        preferred = [e for e in cands if _arch_matches(e["product"], arch)] or cands
        e = max(preferred, key=lambda x: x["ubr"])
        return {"ubr": e["ubr"], "kb": e["kb"], "restart": e["restart"], "source": "msrc",
                "fixed_build": e["fixed_build"], "supersedes": e["supersedes"]}
    nb = msrc.parse_build(nvd_fixed or "")
    if nb and nb[0] == build:
        return {"ubr": nb[1], "kb": None, "restart": None, "source": "nvd", "fixed_build": f"10.0.{nb[0]}.{nb[1]}",
                "supersedes": None}
    return None


def kb_links(kb: str | None) -> list[dict[str, str]]:
    if not kb:
        return []
    return [{"label": f"KB{kb} article", "url": f"{KB_ARTICLE}{kb}"},
            {"label": "Microsoft Update Catalog", "url": f"{CATALOG}KB{kb}"}]


# ----------------------------------------------------------------------------- device state
def os_state(st: DeviceOsUpdates | None, device: Device, *, kb: str | None, cves: set[str],
             now: datetime) -> dict[str, Any]:
    """Where a Windows device is with the OS update that closes `cves` (from its Windows Update report)."""
    unknown = {"code": "unknown", "label": "Update status unknown", "detail": ""}
    if device.os_family != "windows":
        return unknown
    supported, reason, _ = os_svc.support(device)
    if st is None or not supported:
        return {**unknown, "detail": reason or "No Windows Update report from this device yet."}
    s = config.settings
    if st.service_start_type == "disabled":
        return {"code": "failing", "label": "Updates paused/failing",
                "detail": "The Windows Update service (wuauserv) is disabled on this device."}
    offered = None
    if st.listed_at is not None:
        for u in st.updates or []:
            if not os_svc.is_security(u):
                continue
            kbs = [k.upper() for k in u.get("kb_ids") or []]
            if (kb and f"KB{kb}" in kbs) or (cves & set(u.get("cve_ids") or [])) or (
                    "cumulative" in (u.get("title") or "").lower() and u.get("classification") in
                    ("security", "critical", "update_rollup")):
                offered = u
                break
    if offered is not None:
        k = (offered.get("kb_ids") or [None])[0]
        return {"code": "offered", "label": "Update offered, not installed",
                "detail": "Windows Update is offering it now" + (f" ({k})." if k else "."),
                "offered_kb": k}
    ref = st.last_success_at or st.created_at
    stale = (now - ref).total_seconds() / 86400 >= s.device_os_updates_scan_stale_days
    if st.scan_status == "failed" or stale:
        detail = ("The last update search failed" + (f": {st.scan_error[:160]}" if st.scan_error else "."))\
            if st.scan_status == "failed" else (
                f"No successful update search for {int((now - ref).total_seconds() // 86400)} days.")
        return {"code": "failing", "label": "Updates paused/failing", "detail": detail}
    if st.reboot_pending:
        return {"code": "restart_pending", "label": "Installed, restart pending",
                "detail": "A restart is pending on this device; it may finish installing the update."}
    if st.listed_at is None:
        return {**unknown, "detail": "The device has not completed an update search yet."}
    hint = {"wsus": "The update source is WSUS: the update may not be approved yet.",
            "wufb": "The update source is Windows Update for Business: an update ring deferral may apply."
            }.get(st.source, "Windows Update is not offering it yet.")
    return {"code": "not_offered", "label": "Not offered yet", "detail": hint}


# ----------------------------------------------------------------------------- methods
def windows_methods(kb: str | None, label: str, *, fixed_build: str = "") -> list[dict[str, Any]]:
    kbtxt = f"KB{kb}" if kb else "the latest cumulative update"
    check = ("$v = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'; "
             "\"$($v.CurrentBuild).$($v.UBR)\"")
    cmds = [{"label": "Current build (read-only)", "code": check}]
    if kb:
        cmds.insert(0, {"label": f"Is KB{kb} installed? (read-only)", "code": f"Get-HotFix -Id KB{kb}"})
    target = f" The build must be {fixed_build.removeprefix('10.0.')} or higher." if fixed_build else ""
    return [
        {"id": "windows_update", "label": "Windows Update",
         "steps": ["On the device open Settings > Windows Update and select Check for updates.",
                   f"Install {kbtxt}" + (f" for {label}" if label else "") + ", then restart when asked.",
                   "Windows Update shows the update as installed under Update history." + target],
         "commands": []},
        {"id": "intune", "label": "Intune",
         "steps": ["In the Intune admin center open Devices > Windows updates.",
                   "Quality updates: create an expedited quality update profile for the month that contains "
                   f"{kbtxt}, assign it to the affected devices' group, and let it restart them.",
                   "Or tighten the update ring's quality update deadline so it installs without waiting.",
                   "Check the profile's report until the device shows the update as installed."],
         "commands": []},
        {"id": "wsus", "label": "WSUS / manual",
         "steps": ["WSUS or Configuration Manager: approve " + kbtxt + " (Security Updates / Updates classification) for "
                   "the device's target group and wait for the next detection and install window.",
                   "Manually: download it from the Microsoft Update Catalog for the device's edition, install it "
                   "and restart." + target,
                   "Then verify with the read-only commands below (the build number is the reliable check)."],
         "commands": cmds, "links": kb_links(kb)},
    ]


def app_methods(os_family: str, rule_id: str, package: str, current: str, fixed: str | None,
                evidence: dict | None = None) -> list[dict[str, Any]]:
    """Update methods for a package we can say something reliable about. May be empty."""
    methods: list[dict[str, Any]] = []
    target = f"{fixed} or later" if fixed else "the latest version"
    if os_family == "windows":
        wid = WINGET_IDS.get(rule_id)
        if wid:
            methods.append({"id": "winget", "label": "winget", "steps": [
                f"Run in a terminal on the device, then check the installed version is {target}."],
                "commands": [{"label": "Update with winget", "code": f"winget upgrade --id {wid} -e"},
                             {"label": "Installed version (read-only)", "code": f"winget list --id {wid} -e"}]})
    elif os_family == "macos":
        cask = BREW_CASKS.get(rule_id)
        if cask:
            methods.append({"id": "brew", "label": "Homebrew", "steps": [
                f"Only if the app was installed with Homebrew. Update to {target}."],
                "commands": [{"label": "Update with Homebrew", "code": f"brew upgrade --cask {cask}"}]})
    elif os_family == "linux":
        eco = str((evidence or {}).get("ecosystem") or "").split(":", 1)[0]
        pkgs = " ".join((evidence or {}).get("binaries") or [package][:1])[:200] or package
        if eco in ("Debian", "Ubuntu"):
            methods.append({"id": "apt", "label": "apt", "steps": [f"Upgrade to {target}, then restart services "
                                                                   "that use it."],
                            "commands": [{"label": "Upgrade with apt",
                                          "code": f"sudo apt-get update && sudo apt-get install --only-upgrade {pkgs}"}]})
        elif eco in ("Rocky Linux", "AlmaLinux", "Red Hat"):
            methods.append({"id": "dnf", "label": "dnf", "steps": [f"Upgrade to {target}, then restart services "
                                                                   "that use it."],
                            "commands": [{"label": "Upgrade with dnf", "code": f"sudo dnf upgrade {package}"}]})
        elif eco == "Alpine":
            methods.append({"id": "apk", "label": "apk", "steps": [f"Upgrade to {target}."],
                            "commands": [{"label": "Upgrade with apk",
                                          "code": f"sudo apk update && sudo apk upgrade {package}"}]})
        elif eco == "PyPI":
            methods.append({"id": "pip", "label": "pip", "steps": [f"Upgrade to {target}."],
                            "commands": [{"label": "Upgrade with pip", "code": f"python3 -m pip install --upgrade {package}"}]})
    hint = VENDOR_UPDATER.get(rule_id)
    methods.append({"id": "vendor", "label": "Vendor updater", "steps": [
        hint or "Use the application's own updater, or install the vendor's current installer over the existing "
                "version. Check the installed version afterwards.",
        f"The vulnerability is closed once {package} is at {target}."], "commands": []})
    return methods


# ----------------------------------------------------------------------------- device fixes
def _cve_row(v: Vulnerability) -> dict[str, Any]:
    return {"cve_id": v.cve_id, "severity": v.severity, "cvss": v.cvss, "kev": bool(v.kev), "title": v.title,
            "fixed_version": v.fixed_version, "first_seen": z(v.first_seen)}


def _sorted_cves(vs: list[Vulnerability]) -> list[dict[str, Any]]:
    return [_cve_row(v) for v in sorted(vs, key=lambda v: (not v.kev, sev_rank(v.severity), -v.cvss, v.cve_id))]


def _group_stats(vs: list[Vulnerability], now: datetime) -> dict[str, Any]:
    top = sorted(vs, key=lambda v: (not v.kev, sev_rank(v.severity), -v.cvss, v.cve_id))[0]
    return {"cve_count": len({v.cve_id for v in vs}), "kev_count": len({v.cve_id for v in vs if v.kev}),
            "max_severity": worst(v.severity for v in vs), "max_cvss": max(v.cvss for v in vs),
            "top_cve": top.cve_id, "top_cve_kev": bool(top.kev),
            "oldest_open_days": max(_days(v.first_seen, now) or 0 for v in vs)}


def _max_version(versions: list[str | None]) -> str | None:
    best: str | None = None
    for v in versions:
        if v and (best is None or compare_versions(v, best) > 0):
            best = v
    return best


def _windows_fix(device: Device, vs: list[Vulnerability], st: DeviceOsUpdates | None, now: datetime,
                 msrc_data: dict[str, dict]) -> dict[str, Any]:
    stats = _group_stats(vs, now)
    bld = device_build(device)
    server = _is_server(device.os_name)
    major, ubr = bld if bld else (0, 0)
    label = build_label(major, server) if major else (device.os_name or "Windows")
    needs: list[tuple[int, dict]] = []
    unknown = 0
    for v in vs:
        r = requirement_for_build(msrc_data.get(v.cve_id), v.fixed_version, major, server, device.architecture) \
            if major else None
        if r is None:
            unknown += 1
        else:
            needs.append((r["ubr"], r))
    target = max(needs, key=lambda x: (x[0], bool(x[1]["kb"])))[1] if needs else None
    # Prefer a requirement that has a KB when builds tie.
    if target is not None:
        same = [r for u, r in needs if u == target["ubr"] and r["kb"]]
        if same and not target["kb"]:
            target = same[0]
    kb = target["kb"] if target else None
    fixed_build = target["fixed_build"] if target else ""
    state = os_state(st, device, kb=kb, cves={v.cve_id for v in vs}, now=now)
    if kb:
        title = "Install the latest Windows cumulative update"
        steps_head = (f"Install {label} update KB{kb} (build {fixed_build.removeprefix('10.0.')}) or any later "
                      "cumulative update.") if fixed_build else f"Install KB{kb} or any later cumulative update."
    else:
        title = "Install the latest Windows cumulative update"
        steps_head = "Install the latest cumulative update for this Windows version."
    steps = [steps_head]
    if target and target["restart"] is not False:
        steps.append("Restart the device to finish the installation.")
    steps.append("The open CVEs below resolve at the device's next vulnerability check after the new build "
                 "is reported.")
    return {
        "id": "windows_cumulative", "kind": "windows_update", "title": title, "package": label,
        "current_version": f"{major}.{ubr}" if major else (device.os_build or ""),
        "target_version": fixed_build.removeprefix("10.0.") or None,
        "target": {"kb": kb, "build": fixed_build.removeprefix("10.0.") or None, "os": label,
                   "source": target["source"] if target else None},
        "restart_required": target["restart"] if target else None,
        "msrc_covered": unknown == 0 and bool(needs) and any(r["source"] == "msrc" for _, r in needs),
        "unmapped_cves": unknown,
        "state": state, "steps": steps, "methods": windows_methods(kb, label, fixed_build=fixed_build),
        "links": kb_links(kb), "cves": _sorted_cves(vs), **stats,
        "os_updates_tab": f"/devices/{device.id}?tab=OS%20updates",
    }


def _os_other_fix(device: Device, vs: list[Vulnerability], now: datetime) -> dict[str, Any]:
    stats = _group_stats(vs, now)
    target = _max_version([v.fixed_version for v in vs])
    name = {"macos": "macOS"}.get(device.os_family, device.os_name or device.os_family)
    cur = vs[0].version
    steps = [f"Update {name} {cur} to {target} or later." if target else f"Install the latest {name} update."]
    methods = []
    if device.os_family == "macos":
        steps.append("Open System Settings > General > Software Update and install the update.")
        methods.append({"id": "software_update", "label": "Software Update", "steps": steps,
                        "commands": [{"label": "List available updates (read-only)", "code": "softwareupdate --list"}]})
    return {"id": "os_update", "kind": "os_update",
            "title": f"Update {name} {cur} \u2192 {target} or later" if target else f"Install the latest {name} update",
            "package": name, "current_version": cur, "target_version": target, "target": {"version": target},
            "restart_required": None, "state": {"code": "unknown", "label": "", "detail": ""}, "steps": steps,
            "methods": methods, "links": [], "cves": _sorted_cves(vs), **stats, "os_updates_tab": None}


def _app_fix(device: Device, key: str, vs: list[Vulnerability], now: datetime) -> dict[str, Any]:
    stats = _group_stats(vs, now)
    pkg, cur = vs[0].package, vs[0].version
    target = _max_version([v.fixed_version for v in vs])
    missing = sum(1 for v in vs if not v.fixed_version)
    title = f"Update {pkg} {cur} \u2192 {target} or later" if target else f"Update {pkg} to the latest version"
    methods = app_methods(device.os_family, key, pkg, cur, target)
    steps = [f"Update {pkg} from {cur} to {target} or later." if target else
             f"Update {pkg} to the latest version (the vulnerability data names no fixed version).",
             f"The CVEs below resolve at the next vulnerability check once {pkg} is at the fixed version."]
    if missing and target:
        steps.append(f"{missing} of these CVEs list no fixed version; check the vendor advisory if they remain.")
    return {"id": f"app:{key}", "kind": "app_update", "title": title, "package": pkg, "current_version": cur,
            "target_version": target, "target": {"version": target}, "restart_required": None,
            "state": {"code": "unknown", "label": "", "detail": ""}, "steps": steps, "methods": methods,
            "links": [{"label": "NVD advisory", "url": f"https://nvd.nist.gov/vuln/detail/{stats['top_cve']}"}],
            "cves": _sorted_cves(vs), **stats, "os_updates_tab": None}


def fix_sort_key(f: dict[str, Any]) -> tuple:
    return (f["kev_count"] == 0, sev_rank(f["max_severity"]), -f["cve_count"], f["title"].lower())


def device_fixes(db: Session, device: Device, now: datetime | None = None) -> dict[str, Any]:
    """The device's open vulnerabilities grouped by the fix that closes them."""
    now = now or utcnow()
    vulns = list(db.scalars(select(Vulnerability).where(Vulnerability.device_id == device.id,
                                                        Vulnerability.status == "open")))
    st = db.get(DeviceOsUpdates, device.id, options=[undefer(DeviceOsUpdates.updates)])
    data = msrc.load(db)
    os_rows = [v for v in vulns if v.match_key == OS_KEY]
    groups: dict[str, list[Vulnerability]] = defaultdict(list)
    for v in vulns:
        if v.match_key != OS_KEY:
            groups[v.match_key or v.package].append(v)
    fixes: list[dict[str, Any]] = []
    if os_rows:
        fixes.append(_windows_fix(device, os_rows, st, now, data) if device.os_family == "windows"
                     else _os_other_fix(device, os_rows, now))
    fixes += [_app_fix(device, k, vs, now) for k, vs in groups.items()]
    fixes.sort(key=fix_sort_key)
    cves = {v.cve_id for v in vulns}
    kev = {v.cve_id for v in vulns if v.kev}
    return {
        "device": {"id": device.id, "hostname": device.hostname, "os_family": device.os_family,
                   "os_name": device.os_name, "os_version": device.os_version, "os_build": device.os_build},
        "summary": {"fixes": len(fixes), "open": len(cves), "kev": len(kev),
                    "oldest_open_days": max((_days(v.first_seen, now) or 0 for v in vulns), default=None)},
        "fixes": fixes,
        "os_updates_tab": f"/devices/{device.id}?tab=OS%20updates" if device.os_family == "windows" else None,
        "msrc": msrc_status(db),
        "generated_at": z(now),
    }


def msrc_status(db: Session) -> dict[str, Any]:
    st = db.get(VulnFeedStatus, "msrc")
    return {"enabled": config.settings.msrc_enabled, "has_data": bool(msrc.load(db)),
            "updated_at": z(st.last_success_at) if st else None,
            "error": st.last_error if st else None}


# ----------------------------------------------------------------------------- compliance
@cache
def compliance_refs() -> list[dict[str, str]]:
    """Framework controls whose automated evidence includes the vulnerability checks (patching SLAs)."""
    from ..compliance import catalog

    out = []
    for fw in catalog.frameworks().values():
        for c in fw.controls:
            if any(ck.startswith("vuln:") for ck in c.checks):
                out.append({"framework": fw.short_name, "control": c.id, "title": c.title})
    return out


# ----------------------------------------------------------------------------- CVE detail
def _attack_facts(vector: str | None) -> list[str]:
    if not vector or "/" not in vector:
        return []
    try:
        p = dict(x.split(":", 1) for x in vector.split("/")[1:])
    except ValueError:
        return []
    out = []
    av = {"N": "over the network", "A": "from an adjacent network", "L": "locally on the device",
          "P": "with physical access"}.get(p.get("AV", ""))
    if av:
        out.append(f"It can be attacked {av}" + (", without any privileges" if p.get("PR") == "N" else "")
                   + (" and needs a user to take an action (for example opening a file or page)"
                      if p.get("UI") == "R" else "") + ".")
    hi = [n for k, n in (("C", "confidentiality"), ("I", "integrity"), ("A", "availability")) if p.get(k) == "H"]
    if hi:
        out.append("Impact is rated high for " + ", ".join(hi) + ".")
    return out


def _cvss_label(vector: str | None) -> str:
    m = re.match(r"CVSS:(\d\.\d)/", vector or "")
    return f"CVSS v{m.group(1)}" if m else "CVSS"


def cve_detail(db: Session, cve_id: str, now: datetime | None = None) -> dict[str, Any] | None:
    """Everything the CVE page shows (None: this organisation has no record of the CVE)."""
    now = now or utcnow()
    rows = list(db.scalars(select(Vulnerability).where(Vulnerability.cve_id == cve_id)))
    if not rows:
        return None
    open_rows = [v for v in rows if v.status == "open"]
    cur = open_rows or rows
    dev_ids = {v.device_id for v in rows if v.device_id}
    devices = {d.id: d for d in db.scalars(select(Device).where(Device.id.in_(dev_ids)))} if dev_ids else {}
    msrc_rec = msrc.lookup(db, cve_id)
    kev = any(v.kev for v in rows)
    kev_info = next((v.evidence["kev"] for v in rows if (v.evidence or {}).get("kev")), None) or {}
    ev0 = max(rows, key=lambda v: len((v.evidence or {}).get("published") or ""))
    evidence = ev0.evidence or {}
    vector = next((v.evidence["vector"] for v in rows if (v.evidence or {}).get("vector")), None)
    cwe = next((v.evidence["cwe"] for v in rows if (v.evidence or {}).get("cwe")), None) or []
    epss = max((v.epss for v in rows if v.epss is not None), default=None)
    severity = worst(v.severity for v in cur)
    cvss = max(v.cvss for v in cur)
    description = max((v.title for v in rows), key=len)
    first_seen = min(v.first_seen for v in rows)
    open_first = min((v.first_seen for v in open_rows), default=None)
    title = (msrc_rec or {}).get("t") or (description if len(description) <= 90 else
                                         re.split(r"(?<=[.!?])\s", description, maxsplit=1)[0][:110])
    # --- affected devices and what each needs
    win_data = {cve_id: msrc_rec} if msrc_rec else {}
    os_updates = {}
    if dev_ids:
        os_updates = {u.device_id: u for u in db.scalars(select(DeviceOsUpdates).where(
            DeviceOsUpdates.device_id.in_(dev_ids)).options(undefer(DeviceOsUpdates.updates)))}
    affected: list[dict[str, Any]] = []
    states: Counter = Counter()
    for v in sorted((x for x in open_rows if x.device_id), key=lambda x: (devices[x.device_id].hostname.lower()
                                                                           if x.device_id in devices else "")):
        d = devices.get(v.device_id)
        if d is None:
            continue
        needs, state = "", None
        if v.match_key == OS_KEY and d.os_family == "windows":
            bld = device_build(d)
            req = requirement_for_build(win_data.get(cve_id), v.fixed_version, bld[0], _is_server(d.os_name),
                                        d.architecture) if bld else None
            needs = (f"Latest cumulative update (KB{req['kb']}" + (f", build {req['fixed_build'].removeprefix('10.0.')}"
                     if req["fixed_build"] else "") + ")") if req and req["kb"] else (
                f"Latest cumulative update (build {req['fixed_build'].removeprefix('10.0.')} or later)" if req else
                "Latest cumulative update")
            state = os_state(os_updates.get(d.id), d, kb=req["kb"] if req else None, cves={cve_id}, now=now)
            current = d.os_build or d.os_version
        elif v.match_key == OS_KEY:
            needs = f"Update to {v.fixed_version} or later" if v.fixed_version else "Latest OS update"
            current = d.os_version
        else:
            needs = f"Update {v.package} to {v.fixed_version} or later" if v.fixed_version else f"Update {v.package}"
            current = v.version
        if state:
            states[state["code"]] += 1
        affected.append({"device_id": d.id, "hostname": d.hostname, "device_group": d.device_group,
                         "os_name": d.os_name, "os_version": d.os_version, "current": current,
                         "package": v.package, "needs": needs, "state": state, "first_seen": z(v.first_seen),
                         "risk_score": v.risk_score, "os_family": d.os_family})
    assets = sorted({(v.asset.name if v.asset else v.asset_id) or "" for v in open_rows if v.asset_id})
    network = _network_affected(db, open_rows)
    # --- fix guidance
    guidance = _cve_guidance(db, cve_id, cur, msrc_rec, devices)
    guidance["network"] = _network_guidance(cve_id, network)
    if network and guidance["network"]["fixed_version"]:
        guidance["patch_available"] = True
        if guidance["fix_type"] == "none":
            guidance["fix_type"] = "firmware_upgrade"
    # --- counts
    ever = {v.device_id or v.asset_id or v.network_device_id for v in rows}
    patched = {v.device_id or v.asset_id or v.network_device_id for v in rows if v.status == "resolved"} - {
        v.device_id or v.asset_id or v.network_device_id for v in open_rows}
    fams = {d.os_family for d in devices.values()} or {"windows"}
    total_fleet = db.scalar(select(func.count()).select_from(Device).where(
        Device.status == "active", Device.os_family.in_(fams))) or 0
    open_dev = len({v.device_id for v in open_rows if v.device_id})
    sla = fix_due(open_first, severity, kev=kev, kev_due=kev_info.get("due"), now=now) if open_first else None
    groups = Counter((devices[v.device_id].device_group or "Ungrouped") for v in open_rows
                     if v.device_id in devices)
    fixed_versions = sorted({v.fixed_version for v in cur if v.fixed_version})
    fixed_in = _fixed_in(guidance, fixed_versions)
    products = sorted({v.package for v in cur})
    published = evidence.get("published")
    detail = {
        "cve_id": cve_id, "title": title, "description": description, "severity": severity, "cvss": cvss,
        "cvss_label": _cvss_label(vector), "vector": vector, "cwe": cwe,
        "kev": kev, "kev_info": kev_info, "epss": epss,
        "exploit": {"kev": kev, "ransomware": (kev_info.get("ransomware") or "").lower() == "known",
                    "msrc": (msrc_rec or {}).get("expl") or None},
        "published": published, "products": products, "patch_available": bool(guidance["patch_available"]),
        "fix_type": guidance["fix_type"], "fixed_in": fixed_in,
        "affected": {"open_devices": open_dev, "fleet_devices": total_fleet, "fleet_label":
                     "/".join(sorted(f.capitalize() if f != "macos" else "macOS" for f in fams)),
                     "assets": len(assets), "asset_names": assets[:20], "network_devices": len(network),
                     "open_findings": len(open_rows)},
        "first_seen": z(first_seen), "days_open": _days(open_first, now) if open_first else None,
        "fix_due": None if sla is None else {"due_at": z(sla["due_at"]), "basis": sla["basis"],
                                             "overdue_days": sla["overdue_days"], "days_left": sla["days_left"]},
        "guidance": guidance, "devices": affected[:MAX_DEVICES], "devices_total": len(affected),
        "network_devices": network[:MAX_DEVICES],
        "progress": {"total": len(ever), "patched": len(patched), "open": len(ever) - len(patched),
                     "restart_pending": states["restart_pending"], "offered": states["offered"],
                     "failing": states["failing"], "not_offered": states["not_offered"]},
        "compliance": compliance_refs(),
        "business_impact": _impact(cve_id, kev, kev_info, epss, open_dev, total_fleet, groups, vector, severity, cvss,
                                   guidance, sla),
        "references": _references(cve_id, kev, msrc_rec, guidance),
        "timeline": _timeline(rows, published, kev_info, msrc_rec, sla),
        "msrc": msrc_status(db), "generated_at": z(now),
    }
    return detail


def _fixed_in(guidance: dict, fixed_versions: list[str]) -> str | None:
    if guidance["windows"]:
        kbs = [f"KB{r['kb']}" for r in guidance["windows"]["table"] if r.get("kb")]
        if kbs:
            return ", ".join(dict.fromkeys(kbs[:3])) + (" and others" if len(kbs) > 3 else "")
        return "Latest cumulative update" if guidance["windows"]["table"] else None
    return fixed_versions[-1] if fixed_versions else None


def _cve_guidance(db: Session, cve_id: str, rows: list[Vulnerability], rec: dict | None,
                  devices: dict[str, Device]) -> dict[str, Any]:
    os_rows = [v for v in rows if v.match_key == OS_KEY and v.device_id in devices and
               devices[v.device_id].os_family == "windows"]
    app_rows = [v for v in rows if v.match_key != OS_KEY and not v.network_device_id]
    out: dict[str, Any] = {"windows": None, "apps": [], "fix_type": "none", "patch_available": False,
                           "mitigations": (rec or {}).get("mit") or [], "workarounds": (rec or {}).get("wk") or []}
    if os_rows:
        by_build: dict[tuple[int, bool], list[Vulnerability]] = defaultdict(list)
        for v in os_rows:
            d = devices[v.device_id]
            b = device_build(d)
            if b:
                by_build[(b[0], _is_server(d.os_name))].append(v)
        table = []
        for (major, server), vs in sorted(by_build.items(), reverse=True):
            r = requirement_for_build(rec, _max_version([v.fixed_version for v in vs]), major, server)
            table.append({"os": build_label(major, server), "build": major,
                          "kb": r["kb"] if r else None, "fixed_build": (r["fixed_build"] or "").removeprefix("10.0.")
                          if r else None, "restart": r["restart"] if r else None,
                          "supersedes": r["supersedes"] if r else None, "source": r["source"] if r else None,
                          "devices": len({v.device_id for v in vs}), "links": kb_links(r["kb"]) if r else []})
        have_kb = next((t["kb"] for t in table if t["kb"]), None)
        out["windows"] = {"table": table, "methods": windows_methods(
            have_kb, table[0]["os"] if len(table) == 1 else "", fixed_build=(
                table[0]["fixed_build"] or "") if len(table) == 1 else ""),
            "msrc": rec is not None, "degraded": rec is None}
        out["fix_type"] = "windows_update"
        out["patch_available"] = True  # a cumulative update is the fix path for every supported build
    by_pkg: dict[tuple[str, str], list[Vulnerability]] = defaultdict(list)
    for v in app_rows:
        by_pkg[(v.match_key or v.package, v.package)].append(v)
    for (key, pkg), vs in by_pkg.items():
        fixed = _max_version([v.fixed_version for v in vs])
        fam = (devices[vs[0].device_id].os_family if vs[0].device_id in devices else "linux")
        versions = sorted({v.version for v in vs})
        out["apps"].append({
            "package": pkg, "current": ", ".join(versions[:4]) + (" ..." if len(versions) > 4 else ""),
            "fixed_version": fixed, "devices": len({v.device_id for v in vs if v.device_id}),
            "assets": len({v.asset_id for v in vs if v.asset_id}),
            "methods": app_methods(fam, key, pkg, versions[0], fixed, vs[0].evidence),
            "advisory": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "title": f"Update {pkg} {versions[0]} \u2192 {fixed} or later" if fixed and len(versions) == 1 else (
                f"Update {pkg} to {fixed} or later" if fixed else f"Update {pkg} to the latest version")})
        if fixed:
            out["patch_available"] = True
    if app_rows and not os_rows:
        out["fix_type"] = "package_upgrade" if any(a["fixed_version"] for a in out["apps"]) else "none"
        if any(v.source == "osv" for v in app_rows):
            out["fix_type"] = "package_upgrade" if out["patch_available"] else "none"
    elif app_rows and os_rows:
        out["fix_type"] = "mixed"
    elif rows and not os_rows and any(v.match_key == OS_KEY and not v.network_device_id for v in rows):
        # macOS (or other) operating system
        fx = _max_version([v.fixed_version for v in rows if v.match_key == OS_KEY])
        out["fix_type"] = "os_update" if fx else "none"
        out["patch_available"] = bool(fx)
        out["apps"].append({"package": rows[0].package, "current": rows[0].version, "fixed_version": fx,
                            "devices": len({v.device_id for v in rows if v.device_id}), "assets": 0,
                            "methods": [], "advisory": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            "title": f"Update {rows[0].package} to {fx} or later" if fx else
                            f"Install the latest {rows[0].package} update"})
    return out


def _network_affected(db: Session, open_rows: list[Vulnerability]) -> list[dict[str, Any]]:
    """Open network-device rows of a CVE: the device, its firmware and the firmware that fixes it."""
    from ..network.models import NetworkDevice
    from ..network.service import display_name

    ids = {v.network_device_id for v in open_rows if v.network_device_id}
    devs = {d.id: d for d in db.scalars(select(NetworkDevice).where(NetworkDevice.id.in_(ids)))} if ids else {}
    out = []
    for v in open_rows:
        d = devs.get(v.network_device_id or "")
        if d is None:
            continue
        out.append({"network_device_id": d.id, "name": display_name(d), "ip": d.ip, "device_type": d.device_type,
                    "vendor": d.vendor, "model": d.model, "firmware": v.version or d.firmware,
                    "fixed_version": v.fixed_version,
                    "needs": f"Upgrade firmware to {v.fixed_version} or later" if v.fixed_version else
                    "Follow the vendor advisory (no fixed firmware named yet)",
                    "first_seen": z(v.first_seen), "risk_score": v.risk_score})
    out.sort(key=lambda r: r["name"].lower())
    return out


def _network_guidance(cve_id: str, network: list[dict[str, Any]]) -> dict[str, Any]:
    from ..network.insight import ADVISORY, WORKAROUNDS

    fixed = _max_version([n["fixed_version"] for n in network])
    vendors = sorted({n["vendor"] for n in network if n["vendor"]})
    return {"devices": len(network), "vendors": vendors, "fixed_version": fixed,
            "title": ((f"Upgrade the firmware to {fixed} or later" if fixed else "Follow the vendor advisory")
                      if network else None),
            "advisories": [{"label": ADVISORY[v][0], "url": ADVISORY[v][1]} for v in vendors if v in ADVISORY],
            "workaround": WORKAROUNDS.get(cve_id) if network else None,
            "steps": (["Back up the device configuration.", "Download the fixed firmware from the vendor support site.",
                       "Upgrade in a maintenance window, then re-scan the device to confirm the CVE closes."]
                      if network else [])}


def _impact(cve_id, kev, kev_info, epss, open_dev, fleet, groups, vector, severity, cvss, guidance, sla) -> list[str]:
    out: list[str] = []
    if kev:
        s = "CISA lists this vulnerability as exploited in real attacks (Known Exploited Vulnerabilities catalog)"
        if kev_info.get("added"):
            s += f", added {kev_info['added']}"
        out.append(s + ("; it is known to be used in ransomware campaigns." if (kev_info.get("ransomware") or ""
                                                                                ).lower() == "known" else "."))
    if epss is not None:
        out.append(f"FIRST EPSS estimates a {epss * 100:.1f}% chance of exploitation in the next 30 days.")
    out += _attack_facts(vector)
    if open_dev:
        s = f"{open_dev} device{'s' if open_dev != 1 else ''} currently affected"
        if fleet:
            s += f" (of {fleet} in the same OS family)"
        if groups:
            top = ", ".join(f"{g} {n}" for g, n in groups.most_common(4))
            s += f"; by device group: {top}"
        out.append(s + ".")
    if not guidance["patch_available"]:
        out.append("No fixed version is named in the vulnerability data yet; track the vendor advisory.")
    if sla and sla["overdue_days"]:
        out.append(f"The fix is overdue by {sla['overdue_days']} day{'s' if sla['overdue_days'] != 1 else ''} "
                   f"({sla['basis']}).")
    return out


def _references(cve_id, kev, rec, guidance) -> list[dict[str, str]]:
    refs = []
    if cve_id.startswith("CVE-"):
        if rec is not None or guidance["windows"]:
            refs.append({"label": "Microsoft Security Update Guide (MSRC)",
                         "url": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve_id}"})
        refs.append({"label": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"})
        if kev:
            refs.append({"label": "CISA KEV entry", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                         f"?search_api_fulltext={cve_id}"})
    for t in (guidance["windows"] or {}).get("table", []):
        for link in t.get("links", []):
            if link not in refs:
                refs.append(link)
    return refs


def _timeline(rows: list[Vulnerability], published, kev_info, rec, sla) -> list[dict[str, str]]:
    ev: list[tuple[str, str]] = []
    if published:
        ev.append((str(published)[:10], "Published (NVD)"))
    if rec and rec.get("rel"):
        ev.append((rec["rel"], f"Microsoft released the fix ({rec.get('m')} security updates)"))
    if kev_info.get("added"):
        ev.append((kev_info["added"], "Added to CISA KEV"))
    ev.append((min(v.first_seen for v in rows).date().isoformat(), "First seen on a device in this organisation"))
    res = [v.resolved_at for v in rows if v.resolved_at]
    if res:
        ev.append((max(res).date().isoformat(), f"Most recent fix confirmed ({len(res)} resolved)"))
    if kev_info.get("due"):
        ev.append((str(kev_info["due"])[:10], "CISA KEV due date"))
    elif sla:
        ev.append((sla["due_at"].date().isoformat(), f"Fix due ({sla['basis']})"))
    ev.sort()
    return [{"date": d, "label": label} for d, label in ev]

