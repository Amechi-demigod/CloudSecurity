"""Process execution collector (portable /proc polling)."""
from __future__ import annotations

import os
from typing import Dict, List, Optional, Tuple

from .. import procfs
from ..redact import safe_cmdline
from ..schema import ProcessInfo, RuntimeEvent
from .base import Collector


def build_process_info(pid: int, proc_root: str = "/proc") -> Optional[ProcessInfo]:
    """Snapshot a process from /proc. Returns None if it already exited."""
    status = procfs.read_status(pid, proc_root)
    stat = procfs.read_stat(pid, proc_root)
    if status is None and stat is None:
        return None
    ppid = status.ppid if status and status.ppid is not None else (stat.ppid if stat else None)
    parent_name = None
    if ppid:
        pstat = procfs.read_stat(ppid, proc_root)
        parent_name = pstat.comm if pstat else None
    argv = procfs.read_cmdline(pid, proc_root)
    return ProcessInfo(
        pid=pid,
        ppid=ppid,
        name=(status.name if status and status.name else (stat.comm if stat else None)),
        exe=procfs.read_exe(pid, proc_root),
        cmdline=safe_cmdline(argv) if argv else None,
        uid=status.uid if status else None,
        euid=status.euid if status else None,
        parent_name=parent_name,
    )


class ProcessCollector(Collector):
    """Detects new processes by diffing /proc between polls.

    Identity is (pid, starttime) so pid reuse is handled. Also emits
    ``privilege_change`` when a live process' effective uid changes (e.g. a
    setuid transition to root). Processes that start *and* exit between two
    polls are missed; use the eBPF collector for complete coverage.
    """

    name = "process"

    def __init__(self, proc_root: str = "/proc", emit_existing: bool = False):
        self.proc_root = proc_root
        self.emit_existing = emit_existing
        self.self_pid = os.getpid()
        self._known: Dict[int, Tuple[int, Optional[int]]] = {}  # pid -> (starttime, euid)
        self._primed = False

    def poll(self) -> List[RuntimeEvent]:
        events: List[RuntimeEvent] = []
        current: Dict[int, Tuple[int, Optional[int]]] = {}
        for pid in procfs.list_pids(self.proc_root):
            stat = procfs.read_stat(pid, self.proc_root)
            if stat is None:
                continue
            prev = self._known.get(pid)
            if prev is not None and prev[0] == stat.starttime:
                euid = prev[1]
                if pid != self.self_pid:
                    status = procfs.read_status(pid, self.proc_root)
                    if status and status.euid is not None:
                        if prev[1] is not None and status.euid != prev[1]:
                            info = build_process_info(pid, self.proc_root)
                            if info:
                                events.append(RuntimeEvent(event_type="privilege_change", process=info,
                                                           tags=[f"euid:{prev[1]}->{status.euid}"]))
                        euid = status.euid
                current[pid] = (stat.starttime, euid)
                continue
            info = build_process_info(pid, self.proc_root)
            if info is None:
                continue
            current[pid] = (stat.starttime, info.euid)
            if pid == self.self_pid:
                continue
            if self._primed or self.emit_existing:
                events.append(RuntimeEvent(event_type="process_exec", process=info))
        self._known = current
        self._primed = True
        return events
