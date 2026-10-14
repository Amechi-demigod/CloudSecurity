"""Loaded shared-library / Python-package collector.

Reads /proc/<pid>/maps to find which shared objects are *actually mapped* by
running processes and resolves them to OS packages (dpkg / apk) or Python
distributions (``*.dist-info``) inside the process' own root filesystem
(``/proc/<pid>/root``), so container images are resolved correctly.

This is what lets the platform say "CVE-X is in a package that is loaded in
memory right now" vs. "merely installed on disk".

Only metadata files (dpkg status/list files, apk installed db, dist-info
METADATA headers) are read; never application data.
"""
from __future__ import annotations

import os
import re
import time
from typing import Dict, List, Optional, Set, Tuple

from .. import procfs
from ..schema import LibraryInfo, RuntimeEvent
from .base import Collector
from .process import build_process_info

_SO_RE = re.compile(r"\.so(\.[0-9.]+)?$|\.so$")
_SONAME_RE = re.compile(r"^(?P<name>.+?)(?:-(?P<v1>\d[\w.]*))?\.so(?:\.(?P<v2>[0-9.]+))?$")
_PY_RE = re.compile(r"/(?:site|dist)-packages/(?P<top>[^/]+)/")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def is_interesting(path: str) -> bool:
    base = path.rsplit("/", 1)[-1]
    return bool(_SO_RE.search(base)) or "-packages/" in path


def parse_dpkg_status(content: str) -> Dict[str, str]:
    """package -> version from /var/lib/dpkg/status."""
    versions: Dict[str, str] = {}
    pkg = ver = None
    installed = True
    for line in (content + "\n\n").splitlines():
        if not line.strip():
            if pkg and ver and installed:
                versions[pkg] = ver
            pkg = ver = None
            installed = True
        elif line.startswith("Package:"):
            pkg = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            ver = line.split(":", 1)[1].strip()
        elif line.startswith("Status:"):
            installed = "installed" in line and "not-installed" not in line
    return versions


def parse_apk_installed(content: str) -> Dict[str, Tuple[str, str]]:
    """file path -> (package, version) from /lib/apk/db/installed."""
    index: Dict[str, Tuple[str, str]] = {}
    pkg = ver = ""
    cur_dir = ""
    for line in content.splitlines():
        if not line:
            pkg = ver = cur_dir = ""
            continue
        tag, _, val = line.partition(":")
        if tag == "P":
            pkg = val
        elif tag == "V":
            ver = val
        elif tag == "F":
            cur_dir = val
        elif tag == "R" and pkg:
            index["/" + "/".join(p for p in (cur_dir, val) if p)] = (pkg, ver)
    return index


def parse_dist_metadata(content: str) -> Tuple[Optional[str], Optional[str]]:
    name = version = None
    for line in content.splitlines():
        if not line.strip():
            break  # end of headers; never read the long description body
        if line.startswith("Name:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
    return name, version


def soname_guess(path: str) -> Tuple[str, Optional[str]]:
    base = path.rsplit("/", 1)[-1]
    m = _SONAME_RE.match(base)
    if not m:
        return base, None
    return m.group("name"), m.group("v1") or m.group("v2")


def _read(path: str, limit: int = 32 << 20) -> str:
    try:
        with open(path, errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


class PackageIndex:
    """Lazily-built file->package index for one root filesystem."""

    def __init__(self, root: str):
        self.root = root.rstrip("/")
        self.built = time.monotonic()
        self._files: Optional[Dict[str, Tuple[str, Optional[str], str]]] = None
        self._py: Dict[str, Dict[str, Tuple[str, Optional[str]]]] = {}

    def _build_os_index(self) -> Dict[str, Tuple[str, Optional[str], str]]:
        files: Dict[str, Tuple[str, Optional[str], str]] = {}
        info_dir = f"{self.root}/var/lib/dpkg/info"
        if os.path.isdir(info_dir):
            versions = parse_dpkg_status(_read(f"{self.root}/var/lib/dpkg/status"))
            try:
                names = os.listdir(info_dir)
            except OSError:
                names = []
            for fn in names:
                if not fn.endswith(".list"):
                    continue
                pkg = fn[:-5].split(":", 1)[0]
                for line in _read(f"{info_dir}/{fn}").splitlines():
                    if ".so" in line:
                        files[line] = (pkg, versions.get(pkg), "dpkg")
        apk_db = f"{self.root}/lib/apk/db/installed"
        if os.path.isfile(apk_db):
            for path, (pkg, ver) in parse_apk_installed(_read(apk_db)).items():
                files[path] = (pkg, ver, "apk")
        return files

    def lookup_os(self, path: str) -> Optional[Tuple[str, Optional[str], str]]:
        if self._files is None:
            self._files = self._build_os_index()
        candidates = [path]
        if path.startswith("/usr/lib/"):
            candidates.append(path[4:])  # usr-merge aliasing
        elif path.startswith("/lib/"):
            candidates.append("/usr" + path)
        for c in candidates:
            if c in self._files:
                return self._files[c]
        return None

    def lookup_python(self, site_dir: str, top: str) -> Tuple[str, Optional[str]]:
        if site_dir not in self._py:
            idx: Dict[str, Tuple[str, Optional[str]]] = {}
            full = f"{self.root}{site_dir}"
            try:
                entries = os.listdir(full)
            except OSError:
                entries = []
            for e in entries:
                if not e.endswith((".dist-info", ".egg-info")):
                    continue
                meta = _read(f"{full}/{e}/METADATA", 64 << 10) or _read(f"{full}/{e}/PKG-INFO", 64 << 10)
                name, version = parse_dist_metadata(meta)
                if not name:
                    name = e.rsplit(".", 1)[0].rsplit("-", 1)[0]
                tops = _read(f"{full}/{e}/top_level.txt", 64 << 10).split()
                for t in tops or [name]:
                    idx[_norm(t)] = (name, version)
                idx.setdefault(_norm(name), (name, version))
            self._py[site_dir] = idx
        key = _norm(top[:-5] if top.endswith(".libs") else top)
        return self._py[site_dir].get(key, (top, None))


def resolve_library(path: str, index: PackageIndex) -> LibraryInfo:
    m = _PY_RE.search(path)
    if m:
        site_dir = path[: m.start("top") - 1]
        name, version = index.lookup_python(site_dir, m.group("top"))
        return LibraryInfo(path=path, package=name, version=version, kind="python_package",
                           source="dist-info" if version else None)
    hit = index.lookup_os(path)
    if hit:
        return LibraryInfo(path=path, package=hit[0], version=hit[1], kind="shared_object", source=hit[2])
    name, version = soname_guess(path)
    return LibraryInfo(path=path, package=name, version=version, kind="shared_object", source="soname")


class LibraryCollector(Collector):
    """Periodically reports libraries loaded by running processes.

    Each (mount namespace, library path) is reported once, and re-reported
    after ``reemit_after`` seconds as a liveness heartbeat so the backend can
    expire libraries that are no longer loaded.
    """

    name = "library"

    def __init__(self, proc_root: str = "/proc", interval: float = 60.0, reemit_after: float = 3600.0,
                 max_events_per_scan: int = 5000):
        self.proc_root = proc_root
        self.interval = interval
        self.reemit_after = reemit_after
        self.max_events_per_scan = max_events_per_scan
        self.self_pid = os.getpid()
        self._last_scan = 0.0
        self._reported: Dict[Tuple[str, str], float] = {}
        self._indexes: Dict[str, PackageIndex] = {}

    def _index_for(self, mnt_ns: str, pid: int) -> PackageIndex:
        idx = self._indexes.get(mnt_ns)
        if idx is None or time.monotonic() - idx.built > self.reemit_after:
            idx = PackageIndex(f"{self.proc_root}/{pid}/root")
            self._indexes[mnt_ns] = idx
        return idx

    def poll(self) -> List[RuntimeEvent]:
        now = time.monotonic()
        if self._last_scan and now - self._last_scan < self.interval:
            return []
        self._last_scan = now
        events: List[RuntimeEvent] = []
        live_ns: Set[str] = set()
        for pid in procfs.list_pids(self.proc_root):
            if pid == self.self_pid or len(events) >= self.max_events_per_scan:
                continue
            try:
                mnt_ns = os.readlink(f"{self.proc_root}/{pid}/ns/mnt")
            except OSError:
                mnt_ns = "unknown"
            live_ns.add(mnt_ns)
            paths = [p for p in procfs.read_maps(pid, self.proc_root) if is_interesting(p)]
            new = [p for p in paths if now - self._reported.get((mnt_ns, p), -1e18) > self.reemit_after]
            if not new:
                continue
            proc = build_process_info(pid, self.proc_root)
            if proc is None:
                continue
            idx = self._index_for(mnt_ns, pid)
            for path in sorted(new):
                self._reported[(mnt_ns, path)] = now
                events.append(RuntimeEvent(event_type="library_loaded", library=resolve_library(path, idx),
                                           process=proc))
        # forget namespaces that no longer exist (bounded memory)
        self._indexes = {k: v for k, v in self._indexes.items() if k in live_ns}
        self._reported = {k: v for k, v in self._reported.items() if k[0] in live_ns}
        return events
