"""Lightweight local pre-filtering.

These rules only *annotate* events (``severity_hint`` + ``tags``) so the
platform can prioritise. They never block, kill or modify anything. The
authoritative detection logic lives in the backend.
"""
from __future__ import annotations

import re
from typing import Callable, List, Optional

from .schema import RuntimeEvent

SHELLS = {"sh", "bash", "dash", "zsh", "ash", "ksh", "csh", "tcsh", "fish", "busybox"}
WEB_SERVERS = {
    "nginx", "httpd", "apache", "apache2", "php-fpm", "php-fpm7", "php-fpm8", "lighttpd",
    "caddy", "tomcat", "catalina", "java", "node", "gunicorn", "uwsgi", "unicorn", "puma",
    "iis", "w3wp", "traefik", "envoy",
}
MINER_NAMES = re.compile(r"(?i)\b(xmrig|xmr-stak|minerd|cpuminer|cgminer|bfgminer|ethminer|nbminer|t-rex|phoenixminer|kdevtmpfsi|kinsing)\b")
MINER_ARGS = re.compile(r"(?i)(stratum\+(tcp|ssl)://|--donate-level|-o\s+pool\.|nicehash|moneroocean|supportxmr|nanopool)")
REVERSE_SHELL = [
    re.compile(r"(?i)\b(nc|ncat|netcat|nc\.traditional|nc\.openbsd)\b.*\s-[a-z]*[ec]\b"),
    re.compile(r"(?i)\b(bash|sh|zsh)\b.*\s-i\b.*(/dev/tcp/|/dev/udp/)"),
    re.compile(r"(?i)(/dev/tcp/|/dev/udp/)[\w.-]+/\d+"),
    re.compile(r"(?i)\bsocat\b.*\bexec:"),
    re.compile(r"(?i)\bpython[\d.]*\b.*socket.*(pty\.spawn|subprocess|os\.dup2)"),
    re.compile(r"(?i)\bperl\b.*-e.*socket.*(exec|open)"),
    re.compile(r"(?i)\bmkfifo\b.*\b(nc|ncat|netcat)\b"),
    re.compile(r"(?i)\bphp\b.*fsockopen"),
]
PIPE_TO_SHELL = re.compile(r"(?i)\b(curl|wget|fetch)\b[^|]*\|\s*(sudo\s+)?(ba|da|z|k)?sh\b")
MINING_PORTS = {3333, 4444, 5555, 7777, 14444, 14433, 45700}
REVERSE_SHELL_PORTS = {4444, 1337, 31337, 9001}
SENSITIVE_WRITE_PATHS = ("/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/gshadow")


def _proc_name(ev: RuntimeEvent) -> str:
    p = ev.process
    if not p:
        return ""
    if p.exe:
        return p.exe.rsplit("/", 1)[-1]
    return (p.name or "").strip()


def _rule_shell_from_web(ev: RuntimeEvent) -> None:
    if ev.event_type != "process_exec" or not ev.process:
        return
    parent = (ev.process.parent_name or "").lower()
    if _proc_name(ev).lower() in SHELLS and parent in WEB_SERVERS:
        ev.raise_severity("high")
        ev.add_tag("shell_spawned_by_web_server")
        ev.add_tag("mitre:T1505.003")


def _rule_reverse_shell(ev: RuntimeEvent) -> None:
    if ev.event_type != "process_exec" or not ev.process:
        return
    cmd = ev.process.cmdline or ""
    if any(p.search(cmd) for p in REVERSE_SHELL):
        ev.raise_severity("critical")
        ev.add_tag("reverse_shell")
        ev.add_tag("mitre:T1059")


def _rule_miner(ev: RuntimeEvent) -> None:
    if not ev.process:
        return
    text = " ".join(filter(None, [ev.process.name, ev.process.exe, ev.process.cmdline]))
    if MINER_NAMES.search(text) or MINER_ARGS.search(text):
        ev.raise_severity("high")
        ev.add_tag("crypto_miner")
        ev.add_tag("mitre:T1496")


def _rule_pipe_to_shell(ev: RuntimeEvent) -> None:
    if ev.event_type != "process_exec" or not ev.process:
        return
    if PIPE_TO_SHELL.search(ev.process.cmdline or ""):
        ev.raise_severity("high")
        ev.add_tag("download_and_execute")
        ev.add_tag("mitre:T1105")


def _rule_network(ev: RuntimeEvent) -> None:
    if ev.event_type != "network_connect" or not ev.network:
        return
    port = ev.network.dst_port
    if port in MINING_PORTS:
        ev.raise_severity("medium")
        ev.add_tag("suspicious_port:mining_pool")
    if port in REVERSE_SHELL_PORTS and ev.process and _proc_name(ev).lower() in SHELLS:
        ev.raise_severity("critical")
        ev.add_tag("reverse_shell")


def _rule_sensitive_file(ev: RuntimeEvent) -> None:
    if ev.event_type != "file_access" or not ev.file:
        return
    path, op = ev.file.path, ev.file.operation
    if op in ("write", "create", "delete", "rename", "attrib"):
        if path in SENSITIVE_WRITE_PATHS or path.startswith("/etc/sudoers.d/"):
            ev.raise_severity("high")
            ev.add_tag("sensitive_file_modified")
        elif "/.ssh/" in path and path.endswith("authorized_keys"):
            ev.raise_severity("high")
            ev.add_tag("ssh_authorized_keys_modified")
            ev.add_tag("mitre:T1098.004")
        else:
            ev.raise_severity("medium")
            ev.add_tag("sensitive_path_modified")
    elif op == "open":
        if "/.ssh/" in path and not path.endswith((".pub", "known_hosts", "authorized_keys", "config")):
            ev.raise_severity("medium")
            ev.add_tag("ssh_private_key_read")
        elif "/secrets/kubernetes.io/" in path:
            ev.raise_severity("low")
            ev.add_tag("k8s_service_account_token_read")
        elif path in ("/etc/shadow", "/etc/gshadow"):
            ev.raise_severity("low")
            ev.add_tag("credential_store_read")


def _rule_privilege(ev: RuntimeEvent) -> None:
    if ev.event_type == "privilege_change" and ev.process and ev.process.euid == 0:
        ev.raise_severity("medium")
        ev.add_tag("privilege_escalation_to_root")


RULES: List[Callable[[RuntimeEvent], None]] = [
    _rule_shell_from_web,
    _rule_reverse_shell,
    _rule_miner,
    _rule_pipe_to_shell,
    _rule_network,
    _rule_sensitive_file,
    _rule_privilege,
]


def apply_detections(ev: RuntimeEvent, rules: Optional[List[Callable[[RuntimeEvent], None]]] = None) -> RuntimeEvent:
    for rule in rules or RULES:
        rule(ev)
    return ev
