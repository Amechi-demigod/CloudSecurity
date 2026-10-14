"""Optional eBPF collector (BCC).

Hooks ``sched:sched_process_exec`` (every successful execve, including very
short-lived processes the /proc poller would miss) and ``tcp_v4_connect`` /
``tcp_v6_connect`` (outbound connects). Requires root (or CAP_BPF +
CAP_PERFMON + CAP_SYS_ADMIN on older kernels), kernel headers or BTF, and the
``bcc`` Python bindings. If any of that is missing, ``EbpfCollector.available``
returns a reason and the agent falls back to /proc polling.

The programs are read-only tracing programs: they cannot block or modify
syscalls.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import socket
from typing import List, Optional

from ..schema import NetworkInfo, RuntimeEvent
from .base import Collector
from .process import build_process_info

log = logging.getLogger(__name__)

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/sched.h>

struct exec_evt_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(exec_events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct exec_evt_t evt = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.ppid = task->real_parent->tgid;
    evt.uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    exec_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

struct conn_evt_t {
    u32 pid;
    u32 uid;
    u16 family;
    u16 dport;
    u16 sport;
    u8 saddr[16];
    u8 daddr[16];
};
BPF_HASH(currsock, u32, struct sock *);
BPF_PERF_OUTPUT(conn_events);

static int on_connect_entry(struct sock *sk) {
    u32 tid = bpf_get_current_pid_tgid();
    currsock.update(&tid, &sk);
    return 0;
}

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) { return on_connect_entry(sk); }
int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk) { return on_connect_entry(sk); }

static int on_connect_return(struct pt_regs *ctx, u16 family) {
    int ret = PT_REGS_RC(ctx);
    u32 tid = bpf_get_current_pid_tgid();
    struct sock **skpp = currsock.lookup(&tid);
    if (skpp == 0) return 0;
    currsock.delete(&tid);
    if (ret != 0) return 0;
    struct sock *skp = *skpp;
    struct conn_evt_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xffffffff;
    evt.family = family;
    evt.dport = skp->__sk_common.skc_dport;
    evt.sport = skp->__sk_common.skc_num;
    if (family == AF_INET) {
        bpf_probe_read_kernel(&evt.saddr, 4, &skp->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&evt.daddr, 4, &skp->__sk_common.skc_daddr);
    } else {
        bpf_probe_read_kernel(&evt.saddr, 16, skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&evt.daddr, 16, skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }
    conn_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
int kretprobe__tcp_v4_connect(struct pt_regs *ctx) { return on_connect_return(ctx, AF_INET); }
int kretprobe__tcp_v6_connect(struct pt_regs *ctx) { return on_connect_return(ctx, AF_INET6); }
"""


def ebpf_unavailable_reason() -> Optional[str]:
    """None if eBPF looks usable, otherwise a human-readable reason."""
    if not os.path.exists("/sys/kernel"):
        return "not a Linux host"
    if os.geteuid() != 0:
        return "not running as root"
    try:
        import bcc  # noqa: F401
    except Exception as exc:  # ImportError or broken install
        return f"bcc python bindings not importable ({exc.__class__.__name__})"
    return None


def decode_conn(family: int, saddr: bytes, daddr: bytes, sport: int, dport_be: int):
    """Convert raw BPF connect fields to (src_ip, src_port, dst_ip, dst_port)."""
    dport = socket.ntohs(dport_be)
    if family == socket.AF_INET:
        return socket.inet_ntop(socket.AF_INET, bytes(saddr[:4])), sport, \
            socket.inet_ntop(socket.AF_INET, bytes(daddr[:4])), dport
    src = ipaddress.IPv6Address(bytes(saddr[:16]))
    dst = ipaddress.IPv6Address(bytes(daddr[:16]))
    return (str(src.ipv4_mapped or src), sport, str(dst.ipv4_mapped or dst), dport)


class EbpfCollector(Collector):
    name = "ebpf"

    def __init__(self, proc_root: str = "/proc", exec_events: bool = True, connect_events: bool = True):
        self.proc_root = proc_root
        self.want_exec = exec_events
        self.want_connect = connect_events
        self.self_pid = os.getpid()
        self._bpf = None
        self._pending: List[RuntimeEvent] = []

    def setup(self) -> None:
        from bcc import BPF  # imported lazily; optional dependency

        self._bpf = BPF(text=BPF_PROGRAM)
        if self.want_exec:
            self._bpf["exec_events"].open_perf_buffer(self._on_exec, page_cnt=64)
        if self.want_connect:
            self._bpf["conn_events"].open_perf_buffer(self._on_conn, page_cnt=64)
        log.info("eBPF collector attached (exec=%s connect=%s)", self.want_exec, self.want_connect)

    def _on_exec(self, cpu, data, size) -> None:  # pragma: no cover - needs kernel
        evt = self._bpf["exec_events"].event(data)
        if evt.pid == self.self_pid:
            return
        info = build_process_info(evt.pid, self.proc_root)
        if info is None:  # already exited: keep what the kernel told us
            from ..schema import ProcessInfo
            info = ProcessInfo(pid=evt.pid, ppid=evt.ppid, uid=evt.uid,
                               name=evt.comm.decode("utf-8", "replace"))
        self._pending.append(RuntimeEvent(event_type="process_exec", process=info, tags=["source:ebpf"]))

    def _on_conn(self, cpu, data, size) -> None:  # pragma: no cover - needs kernel
        evt = self._bpf["conn_events"].event(data)
        if evt.pid == self.self_pid:
            return
        sip, sport, dip, dport = decode_conn(evt.family, bytes(evt.saddr), bytes(evt.daddr), evt.sport, evt.dport)
        if ipaddress.ip_address(dip).is_loopback:
            return
        proc = build_process_info(evt.pid, self.proc_root)
        self._pending.append(RuntimeEvent(
            event_type="network_connect", process=proc, tags=["source:ebpf"],
            network=NetworkInfo(src_ip=sip, src_port=sport, dst_ip=dip, dst_port=dport,
                                protocol="tcp", direction="outbound")))

    def poll(self) -> List[RuntimeEvent]:  # pragma: no cover - needs kernel
        if self._bpf is not None:
            self._bpf.perf_buffer_poll(timeout=0)
        out, self._pending = self._pending, []
        return out

    def close(self) -> None:  # pragma: no cover - needs kernel
        if self._bpf is not None:
            self._bpf.cleanup()
            self._bpf = None

