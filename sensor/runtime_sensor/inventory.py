"""Host package inventory (schema: EVENT_SCHEMA.md#package-inventory).

Every ``SENSOR_INVENTORY_INTERVAL`` seconds (default 6 h) the sensor reads the
host's installed packages from package-manager *metadata* only and POSTs them
to ``/api/runtime/packages``; the platform matches them against OSV.dev.

Sources (all under ``--host-root``):

* ``/etc/os-release``                     distro id / version -> OSV ecosystem
* ``/var/lib/dpkg/status``                Debian / Ubuntu (with the Source package)
* ``/lib/apk/db/installed``               Alpine (with the origin package)
* ``/var/lib/rpm/rpmdb.sqlite``           Rocky / AlmaLinux / RHEL 9+ (sqlite rpmdb, read-only)
* ``/usr/local/lib/python3*/{site,dist}-packages/*.dist-info``  pip-installed
  Python packages (PyPI). Distro-managed Python packages are already covered
  by the OS package manager and are not reported twice.

Container images are not inventoried (only the host).
"""
from __future__ import annotations

import glob
import json
import logging
import os
import re
import sqlite3
import struct
import threading
from typing import Callable, Dict, List, Optional, Tuple

from .collectors.libraries import parse_dist_metadata
from .schema import utc_now_iso

log = logging.getLogger(__name__)

INVENTORY_SCHEMA_VERSION = "1.1"
MAX_PACKAGES = 50000

# RPM header tags / types (rpmtag.h)
_RPMTAG_NAME, _RPMTAG_VERSION, _RPMTAG_RELEASE, _RPMTAG_EPOCH = 1000, 1001, 1002, 1003
_RPMTAG_SOURCERPM = 1044
_RPM_INT32, _RPM_STRING, _RPM_I18NSTRING = 4, 6, 9


def _read(path: str, limit: int = 64 << 20) -> str:
    try:
        with open(path, errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def parse_os_release(content: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in content.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def ecosystem_for(os_id: Optional[str], version_id: Optional[str]) -> Optional[str]:
    """OSV ecosystem name for the OS packages (mirrors backend app/vulnmatch/inventory.py)."""
    os_id = (os_id or "").strip().lower()
    ver = (version_id or "").strip()
    major = ver.split(".", 1)[0]
    if not os_id or not ver:
        return None
    if os_id == "debian":
        return f"Debian:{major}"
    if os_id == "ubuntu":
        return f"Ubuntu:{ver}:LTS" if re.fullmatch(r"\d\d\.04", ver) and int(ver[:2]) % 2 == 0 else f"Ubuntu:{ver}"
    if os_id == "alpine":
        return "Alpine:v" + ".".join(ver.split(".")[:2])
    if os_id == "rocky":
        return f"Rocky Linux:{major}"
    if os_id == "almalinux":
        return f"AlmaLinux:{major}"
    if os_id == "rhel":
        return "Red Hat"
    return None


def parse_dpkg_packages(content: str) -> List[Dict[str, str]]:
    """Installed packages from /var/lib/dpkg/status, with their source package."""
    out: List[Dict[str, str]] = []
    cur: Dict[str, str] = {}
    for line in (content + "\n\n").splitlines():
        if not line.strip():
            if cur.get("Package") and cur.get("Version") and "installed" in cur.get("Status", "installed") \
                    and "not-installed" not in cur.get("Status", ""):
                src = cur.get("Source", "")
                m = re.match(r"^(\S+)(?:\s+\(([^)]+)\))?", src)
                out.append({"name": cur["Package"], "version": cur["Version"], "kind": "deb",
                            "source_name": m.group(1) if m else cur["Package"],
                            "source_version": (m.group(2) if m and m.group(2) else cur["Version"])})
            cur = {}
        elif not line.startswith((" ", "\t")) and ":" in line:
            k, v = line.split(":", 1)
            cur[k] = v.strip()
    return out


def parse_apk_packages(content: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    cur: Dict[str, str] = {}
    for line in (content + "\n\n").splitlines():
        if not line:
            if cur.get("P") and cur.get("V"):
                out.append({"name": cur["P"], "version": cur["V"], "kind": "apk",
                            "source_name": cur.get("o") or cur["P"]})
            cur = {}
            continue
        tag, _, val = line.partition(":")
        if tag in ("P", "V", "o"):
            cur[tag] = val
    return out


def parse_rpm_header(blob: bytes) -> Optional[Dict[str, str]]:
    """Name / version / source of one rpmdb.sqlite Packages blob (RPM header
    without the lead magic: index count, data size, 16-byte index entries, data)."""
    try:
        il, dl = struct.unpack(">II", blob[:8])
        data_start = 8 + 16 * il
        if il > 10000 or data_start + dl > len(blob):
            return None
        tags: Dict[int, object] = {}
        for i in range(il):
            tag, typ, off, cnt = struct.unpack(">iiii", blob[8 + 16 * i:24 + 16 * i])
            if tag not in (_RPMTAG_NAME, _RPMTAG_VERSION, _RPMTAG_RELEASE, _RPMTAG_EPOCH, _RPMTAG_SOURCERPM):
                continue
            pos = data_start + off
            if typ in (_RPM_STRING, _RPM_I18NSTRING):
                end = blob.index(b"\0", pos)
                tags[tag] = blob[pos:end].decode("utf-8", "replace")
            elif typ == _RPM_INT32 and cnt >= 1:
                tags[tag] = struct.unpack(">i", blob[pos:pos + 4])[0]
    except (struct.error, ValueError):
        return None
    name, ver, rel = tags.get(_RPMTAG_NAME), tags.get(_RPMTAG_VERSION), tags.get(_RPMTAG_RELEASE)
    if not isinstance(name, str) or not isinstance(ver, str) or name == "gpg-pubkey":
        return None
    epoch = tags.get(_RPMTAG_EPOCH)
    evr = (f"{epoch}:" if isinstance(epoch, int) and epoch else "") + ver + (f"-{rel}" if rel else "")
    srpm = tags.get(_RPMTAG_SOURCERPM)
    src = re.sub(r"-[^-]+-[^-]+\.src\.rpm$", "", srpm) if isinstance(srpm, str) else name
    return {"name": name, "version": evr, "kind": "rpm", "source_name": src}


def read_rpmdb(path: str) -> List[Dict[str, str]]:
    if not os.path.isfile(path):
        return []
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    except sqlite3.Error as exc:
        log.info("cannot open rpmdb %s: %s", path, exc)
        return []
    try:
        rows = conn.execute("SELECT blob FROM Packages").fetchall()
    except sqlite3.Error as exc:
        log.info("cannot read rpmdb %s: %s", path, exc)
        return []
    finally:
        conn.close()
    return [p for (blob,) in rows if (p := parse_rpm_header(bytes(blob))) is not None]


def python_packages(host_root: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    root = host_root.rstrip("/")
    for site in sorted(glob.glob(f"{root}/usr/local/lib/python3*/site-packages")
                       + glob.glob(f"{root}/usr/local/lib/python3*/dist-packages")):
        try:
            entries = os.listdir(site)
        except OSError:
            continue
        for e in sorted(entries):
            if not e.endswith(".dist-info"):
                continue
            name, version = parse_dist_metadata(_read(f"{site}/{e}/METADATA", 64 << 10))
            if name and version:
                out.append({"name": name, "version": version, "kind": "python", "ecosystem": "PyPI"})
    return out


def collect_inventory(host_root: str = "/") -> Tuple[Dict[str, Optional[str]], List[Dict[str, str]]]:
    """(os info, packages) of the host mounted at ``host_root``."""
    root = host_root.rstrip("/")
    osr = parse_os_release(_read(f"{root}/etc/os-release") or _read(f"{root}/usr/lib/os-release"))
    os_info = {"id": osr.get("ID"), "version_id": osr.get("VERSION_ID"), "pretty_name": osr.get("PRETTY_NAME")}
    eco = ecosystem_for(os_info["id"], os_info["version_id"])
    pkgs: List[Dict[str, str]] = []
    pkgs += parse_dpkg_packages(_read(f"{root}/var/lib/dpkg/status"))
    pkgs += parse_apk_packages(_read(f"{root}/lib/apk/db/installed"))
    pkgs += read_rpmdb(f"{root}/var/lib/rpm/rpmdb.sqlite") or read_rpmdb(f"{root}/usr/lib/sysimage/rpm/rpmdb.sqlite")
    for p in pkgs:
        if eco:
            p["ecosystem"] = eco
    pkgs += python_packages(host_root)
    return os_info, pkgs[:MAX_PACKAGES]


def build_payload(sensor_id: str, host: str, cloud, os_info, packages) -> Dict:
    return {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "sensor_id": sensor_id,
        "host": host,
        "collected_at": utc_now_iso(),
        "os": os_info,
        "cloud": ({"provider": cloud.provider, "resource_id": cloud.resource_id}
                  if cloud is not None and (cloud.provider or cloud.resource_id) else None),
        "packages": packages,
    }


def inventory_url(api_url: str) -> str:
    """The package endpoint next to the events endpoint:
    https://x/api/runtime/events -> https://x/api/runtime/packages."""
    url = api_url.rstrip("/")
    if url.endswith("/runtime/events"):
        return url[: -len("events")] + "packages"
    base = url.split("/api/", 1)[0]
    return base + "/api/runtime/packages"


class InventoryReporter:
    """Background thread: collect + POST the inventory every ``interval`` seconds."""

    def __init__(self, url: str, sensor_id: str, host: str, host_root: str, cloud, interval: float,
                 send: Callable[[str, bytes], None], dry_run: bool = False, out=None, first_delay: float = 30.0,
                 collect: Callable[[str], Tuple[Dict, List[Dict]]] = collect_inventory):
        self.url = url
        self.sensor_id = sensor_id
        self.host = host
        self.host_root = host_root
        self.cloud = cloud
        self.interval = interval
        self.send = send
        self.dry_run = dry_run
        self.out = out
        self.first_delay = first_delay
        self.collect = collect
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.stats = {"reports_sent": 0, "report_errors": 0, "last_packages": 0}
        self._unsupported_logged = False

    def report_once(self) -> bool:
        os_info, packages = self.collect(self.host_root)
        payload = build_payload(self.sensor_id, self.host, self.cloud, os_info, packages)
        body = json.dumps(payload, separators=(",", ":"))
        self.stats["last_packages"] = len(packages)
        if self.dry_run:
            import sys
            (self.out or sys.stdout).write(body + "\n")
            self.stats["reports_sent"] += 1
            return True
        try:
            self.send(self.url, body.encode())
        except Exception as exc:  # never take the sensor down
            self.stats["report_errors"] += 1
            msg = str(exc)
            if "HTTP 404" in msg or "HTTP 405" in msg:  # platform older than the inventory endpoint
                if not self._unsupported_logged:
                    log.info("the platform does not accept package inventories yet (%s); will retry", msg)
                    self._unsupported_logged = True
            else:
                log.warning("package inventory not sent: %s", msg)
            return False
        self.stats["reports_sent"] += 1
        log.info("package inventory sent (%d packages)", len(packages))
        return True

    def _run(self) -> None:
        if self._stop.wait(self.first_delay):
            return
        while True:
            try:
                self.report_once()
            except Exception:
                log.exception("package inventory failed")
            if self._stop.wait(self.interval):
                return

    def start(self) -> None:
        if self.interval <= 0:
            return
        self._thread = threading.Thread(target=self._run, name="inventory", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(5)
