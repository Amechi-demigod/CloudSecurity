"""TCP connection collector (parses /proc/<pid>/net/tcp{,6} per network namespace)."""
from __future__ import annotations

import ipaddress
import os
from typing import Dict, List, Optional, Set, Tuple

from .. import procfs
from ..schema import NetworkInfo, RuntimeEvent
from .base import Collector
from .process import build_process_info

ConnKey = Tuple[str, str, int, str, int]
TRACKED_STATES = {"ESTABLISHED", "SYN_SENT"}
WILDCARDS = {"0.0.0.0", "::"}


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def classify(entries: List[procfs.TcpEntry]) -> List[Tuple[procfs.TcpEntry, str]]:
    """Return (entry, direction) for tracked connections in one netns.

    A connection whose local port matches a LISTEN socket in the same netns
    was accepted (inbound); everything else was initiated locally (outbound).
    """
    listening: Set[Tuple[str, int]] = {(e.local_ip, e.local_port) for e in entries if e.state == "LISTEN"}
    listen_any_ports = {port for ip, port in listening if ip in WILDCARDS}
    out = []
    for e in entries:
        if e.state not in TRACKED_STATES:
            continue
        inbound = (e.local_ip, e.local_port) in listening or e.local_port in listen_any_ports
        out.append((e, "inbound" if inbound else "outbound"))
    return out


class NetworkCollector(Collector):
    name = "network"

    def __init__(self, proc_root: str = "/proc", emit_existing: bool = False, ignore_loopback: bool = True,
                 outbound: bool = True, inbound: bool = True):
        self.proc_root = proc_root
        self.emit_existing = emit_existing
        self.ignore_loopback = ignore_loopback
        self.outbound = outbound
        self.inbound = inbound
        self.self_pid = os.getpid()
        self._seen: Set[ConnKey] = set()
        self._inode_pid: Dict[int, int] = {}
        self._primed = False

    def _namespaces(self) -> Dict[str, int]:
        """netns id -> one representative pid in that namespace."""
        ns: Dict[str, int] = {}
        for pid in procfs.list_pids(self.proc_root):
            nid = procfs.read_netns(pid, self.proc_root)
            if nid is None:
                continue
            ns.setdefault(nid, pid)
        if not ns:  # no permission to read ns links: fall back to our own netns
            ns["self"] = -1
        return ns

    def _owner(self, inode: int) -> Optional[int]:
        if inode not in self._inode_pid:
            self._inode_pid = procfs.socket_inode_map(self.proc_root)
        return self._inode_pid.get(inode)

    def poll(self) -> List[RuntimeEvent]:
        events: List[RuntimeEvent] = []
        current: Set[ConnKey] = set()
        for nid, pid in self._namespaces().items():
            entries = procfs.read_net_tcp(self.proc_root, None if pid < 0 else pid)
            for entry, direction in classify(entries):
                key: ConnKey = (nid, entry.local_ip, entry.local_port, entry.remote_ip, entry.remote_port)
                current.add(key)
                if key in self._seen or not (self._primed or self.emit_existing):
                    continue
                if self.ignore_loopback and _is_loopback(entry.remote_ip):
                    continue
                if (direction == "outbound" and not self.outbound) or (direction == "inbound" and not self.inbound):
                    continue
                owner = self._owner(entry.inode) if entry.inode else None
                if owner == self.self_pid:
                    continue  # never report the sensor's own traffic (avoids feedback loops)
                proc = build_process_info(owner, self.proc_root) if owner else None
                if direction == "outbound":
                    net = NetworkInfo(src_ip=entry.local_ip, src_port=entry.local_port,
                                      dst_ip=entry.remote_ip, dst_port=entry.remote_port,
                                      protocol="tcp", direction="outbound")
                    etype = "network_connect"
                else:
                    net = NetworkInfo(src_ip=entry.remote_ip, src_port=entry.remote_port,
                                      dst_ip=entry.local_ip, dst_port=entry.local_port,
                                      protocol="tcp", direction="inbound")
                    etype = "network_accept"
                events.append(RuntimeEvent(event_type=etype, network=net, process=proc))
        self._seen = current
        self._primed = True
        return events
