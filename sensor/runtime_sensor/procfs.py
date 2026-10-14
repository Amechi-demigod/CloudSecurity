"""Read-only helpers for parsing Linux procfs.

Every function takes an explicit ``proc_root`` so the sensor can read the
host's /proc from inside a container (``/host/proc``) and tests can point it at
fixture directories. Nothing here writes to /proc or signals processes.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import struct
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Set, Tuple

# TCP states from include/net/tcp_states.h
TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}

_CONTAINER_ID_RE = re.compile(r"([0-9a-f]{64})")
_POD_UID_RE = re.compile(r"pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})")


def _read(path: str, binary: bool = False, limit: int = 1 << 20):
    try:
        with open(path, "rb" if binary else "r", errors=None if binary else "replace") as fh:
            return fh.read(limit)
    except (OSError, ValueError):
        return None


def list_pids(proc_root: str = "/proc") -> List[int]:
    try:
        return sorted(int(d) for d in os.listdir(proc_root) if d.isdigit())
    except OSError:
        return []


@dataclass
class ProcStat:
    pid: int
    comm: str
    state: str
    ppid: int
    starttime: int  # clock ticks since boot (stable identity for pid reuse)


def parse_stat(content: str) -> Optional[ProcStat]:
    """Parse /proc/<pid>/stat. comm may contain spaces and parens."""
    if not content:
        return None
    lpar = content.find("(")
    rpar = content.rfind(")")
    if lpar < 0 or rpar < 0:
        return None
    try:
        pid = int(content[:lpar].strip())
        comm = content[lpar + 1 : rpar]
        rest = content[rpar + 2 :].split()
        # rest[0] = state (field 3), rest[1] = ppid (4), rest[19] = starttime (22)
        return ProcStat(pid=pid, comm=comm, state=rest[0], ppid=int(rest[1]), starttime=int(rest[19]))
    except (ValueError, IndexError):
        return None


def read_stat(pid: int, proc_root: str = "/proc") -> Optional[ProcStat]:
    return parse_stat(_read(f"{proc_root}/{pid}/stat") or "")


@dataclass
class ProcStatus:
    name: Optional[str] = None
    ppid: Optional[int] = None
    uid: Optional[int] = None  # real
    euid: Optional[int] = None  # effective
    tgid: Optional[int] = None


def parse_status(content: str) -> ProcStatus:
    st = ProcStatus()
    for line in (content or "").splitlines():
        key, _, val = line.partition(":")
        val = val.strip()
        try:
            if key == "Name":
                st.name = val
            elif key == "PPid":
                st.ppid = int(val)
            elif key == "Tgid":
                st.tgid = int(val)
            elif key == "Uid":
                parts = val.split()
                st.uid, st.euid = int(parts[0]), int(parts[1])
        except (ValueError, IndexError):
            continue
    return st


def read_status(pid: int, proc_root: str = "/proc") -> Optional[ProcStatus]:
    content = _read(f"{proc_root}/{pid}/status")
    return parse_status(content) if content else None


def parse_cmdline(raw: bytes) -> List[str]:
    if not raw:
        return []
    return [a.decode("utf-8", "replace") for a in raw.rstrip(b"\0").split(b"\0")]


def read_cmdline(pid: int, proc_root: str = "/proc") -> List[str]:
    return parse_cmdline(_read(f"{proc_root}/{pid}/cmdline", binary=True, limit=64 * 1024) or b"")


def read_exe(pid: int, proc_root: str = "/proc") -> Optional[str]:
    try:
        exe = os.readlink(f"{proc_root}/{pid}/exe")
    except OSError:
        return None
    return exe[: -len(" (deleted)")] if exe.endswith(" (deleted)") else exe


# --------------------------------------------------------------------------
# cgroup -> container / pod identity
# --------------------------------------------------------------------------


def parse_cgroup(content: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (container_id, pod_uid) from /proc/<pid>/cgroup content.

    Handles docker (``/docker/<id>``, ``docker-<id>.scope``), containerd
    (``cri-containerd-<id>.scope``), CRI-O (``crio-<id>.scope``), podman
    (``libpod-<id>.scope``) and kubepods hierarchies, both cgroup v1 and v2.
    """
    container_id = None
    pod_uid = None
    for line in (content or "").splitlines():
        path = line.split(":", 2)[-1]
        ids = _CONTAINER_ID_RE.findall(path)
        if ids:
            container_id = ids[-1]
        m = _POD_UID_RE.search(path)
        if m:
            pod_uid = m.group(1).replace("_", "-")
        if container_id and pod_uid:
            break
    return container_id, pod_uid


def read_cgroup(pid: int, proc_root: str = "/proc") -> Tuple[Optional[str], Optional[str]]:
    return parse_cgroup(_read(f"{proc_root}/{pid}/cgroup") or "")


# --------------------------------------------------------------------------
# memory maps -> loaded files
# --------------------------------------------------------------------------


def parse_maps(content: str) -> Set[str]:
    """Return the set of file-backed mapping paths from /proc/<pid>/maps."""
    paths: Set[str] = set()
    for line in (content or "").splitlines():
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        path = parts[5].strip()
        if not path.startswith("/"):
            continue  # [heap], [stack], [vdso], anon
        if path.endswith(" (deleted)"):
            path = path[: -len(" (deleted)")]
        paths.add(path)
    return paths


def read_maps(pid: int, proc_root: str = "/proc") -> Set[str]:
    return parse_maps(_read(f"{proc_root}/{pid}/maps", limit=8 << 20) or "")


# --------------------------------------------------------------------------
# TCP sockets
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TcpEntry:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    uid: int
    inode: int


def _decode_addr(hex_addr: str) -> Tuple[str, int]:
    ip_hex, port_hex = hex_addr.split(":")
    port = int(port_hex, 16)
    raw = bytes.fromhex(ip_hex)
    if len(raw) == 4:
        # stored as a host-order (little endian on x86/arm) 32-bit word
        ip = socket.inet_ntop(socket.AF_INET, struct.pack("<I", struct.unpack(">I", raw)[0]))
    elif len(raw) == 16:
        # four host-order 32-bit words
        words = struct.unpack(">4I", raw)
        packed = struct.pack("<4I", *words)
        ip = str(ipaddress.IPv6Address(packed))
        mapped = ipaddress.IPv6Address(packed).ipv4_mapped
        if mapped is not None:
            ip = str(mapped)
    else:
        raise ValueError(f"bad address {hex_addr}")
    return ip, port


def parse_net_tcp(content: str) -> List[TcpEntry]:
    """Parse /proc/net/tcp or /proc/net/tcp6."""
    entries: List[TcpEntry] = []
    for line in (content or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            lip, lport = _decode_addr(parts[1])
            rip, rport = _decode_addr(parts[2])
            entries.append(
                TcpEntry(
                    local_ip=lip,
                    local_port=lport,
                    remote_ip=rip,
                    remote_port=rport,
                    state=TCP_STATES.get(parts[3].upper(), parts[3]),
                    uid=int(parts[7]),
                    inode=int(parts[9]),
                )
            )
        except (ValueError, IndexError):
            continue
    return entries


def read_net_tcp(proc_root: str = "/proc", pid: Optional[int] = None) -> List[TcpEntry]:
    base = f"{proc_root}/{pid}/net" if pid is not None else f"{proc_root}/net"
    out: List[TcpEntry] = []
    for name in ("tcp", "tcp6"):
        out.extend(parse_net_tcp(_read(f"{base}/{name}") or ""))
    return out


def read_netns(pid: int, proc_root: str = "/proc") -> Optional[str]:
    try:
        return os.readlink(f"{proc_root}/{pid}/ns/net")
    except OSError:
        return None


_SOCKET_RE = re.compile(r"socket:\[(\d+)\]")


def socket_inodes(pid: int, proc_root: str = "/proc") -> Set[int]:
    inodes: Set[int] = set()
    fd_dir = f"{proc_root}/{pid}/fd"
    try:
        fds = os.listdir(fd_dir)
    except OSError:
        return inodes
    for fd in fds:
        try:
            link = os.readlink(f"{fd_dir}/{fd}")
        except OSError:
            continue
        m = _SOCKET_RE.match(link)
        if m:
            inodes.add(int(m.group(1)))
    return inodes


def socket_inode_map(proc_root: str = "/proc", pids: Optional[List[int]] = None) -> Dict[int, int]:
    """Map socket inode -> owning pid (first owner wins)."""
    mapping: Dict[int, int] = {}
    for pid in pids if pids is not None else list_pids(proc_root):
        for ino in socket_inodes(pid, proc_root):
            mapping.setdefault(ino, pid)
    return mapping


def iter_proc_dirs(proc_root: str = "/proc") -> Iterator[int]:
    yield from list_pids(proc_root)
