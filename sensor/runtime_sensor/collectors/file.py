"""Sensitive-path file activity collector.

Uses Linux inotify directly through ctypes (no third-party dependency) and
falls back to stat() polling when inotify is unavailable (non-Linux, seccomp,
or watch limits). Only *metadata* about access is reported: path + operation.
File contents are never read.

Limitation: inotify does not identify the acting process, so file events
carry no ``process`` section (the eBPF roadmap item would add it).
"""
from __future__ import annotations

import ctypes
import ctypes.util
import glob
import logging
import os
import stat
import struct
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from ..schema import FileInfo, RuntimeEvent
from .base import Collector

log = logging.getLogger(__name__)

IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_OPEN = 0x00000020
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_MASK_ADD = 0x20000000
IN_ISDIR = 0x40000000
IN_NONBLOCK = 0o4000
IN_CLOEXEC = 0o2000000

CHANGE_MASK = IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF
DIR_MASK = IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO
PARENT_MASK = IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO
_EVENT_HDR = struct.Struct("iIII")


@dataclass(frozen=True)
class WatchSpec:
    pattern: str  # absolute path, may contain globs (e.g. /home/*/.ssh)
    watch_reads: bool = False  # also report open() (noisy for /etc/passwd, so off there)


DEFAULT_WATCHES = [
    WatchSpec("/etc/passwd", watch_reads=False),
    WatchSpec("/etc/shadow", watch_reads=True),
    WatchSpec("/etc/gshadow", watch_reads=True),
    WatchSpec("/etc/sudoers", watch_reads=False),
    WatchSpec("/etc/sudoers.d", watch_reads=False),
    WatchSpec("/root/.ssh", watch_reads=True),
    WatchSpec("/home/*/.ssh", watch_reads=True),
    WatchSpec("/var/run/secrets/kubernetes.io", watch_reads=True),
]


def parse_watch_arg(value: str) -> WatchSpec:
    """CLI form: ``/path`` or ``/path:reads``."""
    if value.endswith(":reads"):
        return WatchSpec(value[: -len(":reads")], watch_reads=True)
    return WatchSpec(value, watch_reads=False)


def mask_to_operation(mask: int) -> Optional[str]:
    if mask & (IN_CREATE | IN_MOVED_TO):
        return "create" if mask & IN_CREATE else "rename"
    if mask & (IN_DELETE | IN_DELETE_SELF):
        return "delete"
    if mask & (IN_MOVED_FROM | IN_MOVE_SELF):
        return "rename"
    if mask & (IN_MODIFY | IN_CLOSE_WRITE):
        return "write"
    if mask & IN_ATTRIB:
        return "attrib"
    if mask & IN_OPEN:
        return "open"
    return None


def parse_inotify_buffer(buf: bytes) -> List[Tuple[int, int, int, str]]:
    """Decode raw inotify read() data into (wd, mask, cookie, name)."""
    out = []
    i = 0
    while i + _EVENT_HDR.size <= len(buf):
        wd, mask, cookie, length = _EVENT_HDR.unpack_from(buf, i)
        i += _EVENT_HDR.size
        name = buf[i : i + length].rstrip(b"\0").decode("utf-8", "replace")
        i += length
        out.append((wd, mask, cookie, name))
    return out


class _Inotify:
    def __init__(self) -> None:
        if not sys.platform.startswith("linux"):
            raise OSError("inotify requires Linux")
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        self._add = libc.inotify_add_watch
        self._add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self._rm = libc.inotify_rm_watch
        fd = libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        self.fd = fd

    def add(self, path: str, mask: int) -> int:
        wd = self._add(self.fd, os.fsencode(path), mask | IN_MASK_ADD)
        if wd < 0:
            raise OSError(ctypes.get_errno(), f"inotify_add_watch({path}) failed")
        return wd

    def read(self) -> List[Tuple[int, int, int, str]]:
        data = b""
        while True:
            try:
                chunk = os.read(self.fd, 65536)
            except BlockingIOError:
                break
            if not chunk:
                break
            data += chunk
        return parse_inotify_buffer(data)

    def close(self) -> None:
        os.close(self.fd)


class FileCollector(Collector):
    name = "file"

    def __init__(self, watches: Optional[List[WatchSpec]] = None, host_root: str = "/",
                 mode: str = "auto", rescan_interval: float = 30.0, dedupe_window: float = 2.0,
                 max_depth: int = 3):
        self.watches = watches or DEFAULT_WATCHES
        self.host_root = host_root.rstrip("/")
        self.mode = mode  # auto | inotify | poll
        self.rescan_interval = rescan_interval
        self.dedupe_window = dedupe_window
        self.max_depth = max_depth
        self._ino: Optional[_Inotify] = None
        # wd -> list of (kind, host_path, reported_path, watch_reads, filter_name)
        self._wds: Dict[int, List[Tuple[str, str, str, bool, Optional[str]]]] = {}
        self._wd_keys: Dict[int, List[Tuple[str, str, int]]] = {}
        self._watched: Set[Tuple[str, str, int]] = set()
        self._last_rescan = 0.0
        self._recent: Dict[Tuple[str, str], float] = {}
        self._snapshot: Dict[str, Tuple[int, int, int, int, int]] = {}

    # -- path helpers -----------------------------------------------------
    def _host(self, path: str) -> str:
        return self.host_root + path if self.host_root else path

    def _report(self, host_path: str) -> str:
        if self.host_root and host_path.startswith(self.host_root + "/"):
            return host_path[len(self.host_root):]
        return host_path

    def _resolve(self) -> List[Tuple[str, bool]]:
        out = []
        for spec in self.watches:
            for p in sorted(glob.glob(self._host(spec.pattern))):
                out.append((p, spec.watch_reads))
        return out

    def _walk_dirs(self, root: str) -> List[str]:
        dirs = [root]
        base_depth = root.rstrip("/").count("/")
        for dirpath, dirnames, _ in os.walk(root, followlinks=False):
            if dirpath.count("/") - base_depth >= self.max_depth:
                dirnames[:] = []
                continue
            for d in dirnames:
                dirs.append(os.path.join(dirpath, d))
        return dirs

    # -- setup --------------------------------------------------------------
    def setup(self) -> None:
        if self.mode in ("auto", "inotify"):
            try:
                self._ino = _Inotify()
            except (OSError, AttributeError) as exc:
                if self.mode == "inotify":
                    raise
                log.info("inotify unavailable (%s); using stat polling for file collector", exc)
        if self._ino:
            self._add_inotify_watches()
        else:
            self._snapshot = self._take_snapshot()
        self._last_rescan = time.monotonic()

    @property
    def backend(self) -> str:
        return "inotify" if self._ino else "poll"

    def _register(self, path: str, mask: int, entry: Tuple[str, str, str, bool, Optional[str]]) -> None:
        try:
            ino = os.stat(path).st_ino  # inode-aware so a replaced file gets a fresh watch
        except OSError:
            return
        key = (entry[0], path if entry[4] is None else path + "\0" + entry[4], ino)
        if key in self._watched:
            return
        try:
            wd = self._ino.add(path, mask)  # type: ignore[union-attr]
        except OSError as exc:
            log.debug("cannot watch %s: %s", path, exc)
            return
        self._watched.add(key)
        self._wds.setdefault(wd, []).append(entry)
        self._wd_keys.setdefault(wd, []).append(key)

    def _add_inotify_watches(self) -> None:
        for path, reads in self._resolve():
            if os.path.isdir(path):
                for d in self._walk_dirs(path):
                    self._register(d, DIR_MASK | (IN_OPEN if reads else 0),
                                   ("dir", d, self._report(d), reads, None))
            else:
                self._register(path, CHANGE_MASK | (IN_OPEN if reads else 0),
                               ("file", path, self._report(path), reads, None))
                parent, base = os.path.split(path)
                self._register(parent, PARENT_MASK, ("parent", parent, self._report(parent), reads, base))

    # -- polling fallback ---------------------------------------------------
    def _take_snapshot(self) -> Dict[str, Tuple[int, int, int, int, int]]:
        snap: Dict[str, Tuple[int, int, int, int, int]] = {}
        for path, reads in self._resolve():
            candidates = [path]
            if os.path.isdir(path):
                for d in self._walk_dirs(path):
                    try:
                        candidates.extend(os.path.join(d, n) for n in os.listdir(d))
                    except OSError:
                        pass
            for c in candidates:
                try:
                    st = os.lstat(c)
                except OSError:
                    continue
                snap[c] = (st.st_ino, st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_mode)
        return snap

    def _diff_snapshot(self) -> List[Tuple[str, str]]:
        new = self._take_snapshot()
        changes: List[Tuple[str, str]] = []
        for path, cur in new.items():
            old = self._snapshot.get(path)
            if old is None:
                changes.append((path, "create"))
            elif stat.S_ISDIR(cur[4]):
                if old[4] != cur[4]:  # dir mtime churns on every entry change; only report chmod
                    changes.append((path, "attrib"))
            elif old[0] != cur[0] or old[1] != cur[1] or old[3] != cur[3]:
                changes.append((path, "write"))
            elif old[2] != cur[2] or old[4] != cur[4]:
                changes.append((path, "attrib"))
        for path in self._snapshot.keys() - new.keys():
            changes.append((path, "delete"))
        self._snapshot = new
        return changes

    # -- main -----------------------------------------------------------------
    def _emit(self, host_path: str, op: str, now: float, events: List[RuntimeEvent]) -> None:
        reported = self._report(host_path)
        key = (reported, op)
        last = self._recent.get(key)
        if last is not None and now - last < self.dedupe_window:
            return
        self._recent[key] = now
        if len(self._recent) > 10_000:
            self._recent = {k: v for k, v in self._recent.items() if now - v < self.dedupe_window}
        events.append(RuntimeEvent(event_type="file_access", file=FileInfo(path=reported, operation=op)))

    def poll(self) -> List[RuntimeEvent]:
        events: List[RuntimeEvent] = []
        now = time.monotonic()
        if self._ino is None:
            for path, op in self._diff_snapshot():
                self._emit(path, op, now, events)
            return events

        rewatch = False
        for wd, mask, _cookie, name in self._ino.read():
            if mask & IN_Q_OVERFLOW:
                log.warning("inotify queue overflow; some file events were lost")
                continue
            if mask & IN_IGNORED:
                self._wds.pop(wd, None)
                for key in self._wd_keys.pop(wd, []):
                    self._watched.discard(key)
                rewatch = True
                continue
            op = mask_to_operation(mask)
            if op is None:
                continue
            for kind, hpath, _reported, reads, flt in self._wds.get(wd, []):
                if kind == "parent":
                    if name != flt:
                        continue
                    target = os.path.join(hpath, name)
                    if op in ("create", "rename"):
                        rewatch = True  # file was replaced; watch the new inode
                elif kind == "dir":
                    if (mask & IN_ISDIR) and op == "open":
                        continue  # directory listing, not a file read
                    if op == "open" and not reads:
                        continue
                    target = os.path.join(hpath, name) if name else hpath
                    if (mask & IN_ISDIR) and op == "create":
                        rewatch = True
                else:
                    target = hpath
                self._emit(target, op, now, events)
        if rewatch or now - self._last_rescan > self.rescan_interval:
            self._last_rescan = now
            self._add_inotify_watches()
        return events

    def close(self) -> None:
        if self._ino:
            self._ino.close()
            self._ino = None
