"""Runtime threat detection (CDR) rules engine.

Detection rules are declarative records with a `match(event) -> reason | None`
function operating on the normalized runtime event schema (see
`app/schemas.py::RuntimeEventIn` and the README). Each rule carries a MITRE
ATT&CK tactic/technique mapping.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

MatchFn = Callable[[dict[str, Any]], str | None]


@dataclass(frozen=True)
class DetectionRule:
    id: str
    title: str
    severity: str
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    description: str
    match: MatchFn


DETECTION_RULES: list[DetectionRule] = []


def detection(**kwargs) -> Callable[[MatchFn], MatchFn]:
    def deco(fn: MatchFn) -> MatchFn:
        DETECTION_RULES.append(DetectionRule(match=fn, **kwargs))
        return fn

    return deco


# Small built-in threat-intel list (documentation / TEST-NET ranges + examples).
# In production this would be fed from a TI provider.
MALICIOUS_IPS = {
    "185.220.101.47",  # example Tor exit / C2
    "45.155.205.233",
    "194.165.16.11",
    "91.240.118.172",
    "203.0.113.66",  # TEST-NET-3, used by the simulator
}
MINING_POOL_PORTS = {3333, 4444, 5555, 7777, 14444, 45700}
MINER_PROCESSES = {"xmrig", "minerd", "cpuminer", "kdevtmpfsi", "kinsing", "ethminer", "nbminer"}
SHELLS = {"sh", "bash", "dash", "zsh", "ash", "ksh"}
EXPECTED_EGRESS_PORTS = {53, 80, 123, 443, 1433, 5432, 3306, 6379, 9092, 8443}
SENSITIVE_PATHS = (
    "/etc/shadow",
    "/root/.ssh",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/.azure/",
    "/.aws/credentials",
    "/etc/kubernetes/admin.conf",
)
IMDS_IP = "169.254.169.254"

REVERSE_SHELL_PATTERNS = [
    re.compile(r"/dev/tcp/\d{1,3}(\.\d{1,3}){3}/\d+"),
    re.compile(r"\b(nc|ncat|netcat)\b.*\s-e\s+/bin/(ba)?sh"),
    re.compile(r"socket\.socket.*connect.*(pty\.spawn|subprocess|/bin/sh)", re.S),
    re.compile(r"\bsocat\b.*exec:.*(bash|sh)", re.I),
    re.compile(r"mkfifo .*\b(nc|ncat)\b"),
]


def _proc(e: dict) -> dict:
    return e.get("process") or {}


def _net(e: dict) -> dict:
    return e.get("network") or {}


def _is_public(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved)


@detection(
    id="CDR-001",
    title="Reverse shell",
    severity="critical",
    mitre_tactic="Execution",
    mitre_technique_id="T1059.004",
    mitre_technique_name="Command and Scripting Interpreter: Unix Shell",
    description="A process spawned an interactive shell bound to a remote network socket.",
)
def _reverse_shell(e):
    if e.get("event_type") != "process_exec":
        return None
    cmd = _proc(e).get("cmdline") or ""
    for pat in REVERSE_SHELL_PATTERNS:
        if pat.search(cmd):
            return f"reverse-shell pattern in command line: {cmd[:160]}"
    return None


@detection(
    id="CDR-002",
    title="Cryptocurrency miner",
    severity="high",
    mitre_tactic="Impact",
    mitre_technique_id="T1496",
    mitre_technique_name="Resource Hijacking",
    description="A known miner binary executed or a workload connected to a mining pool.",
)
def _miner(e):
    p = _proc(e)
    name = (p.get("name") or "").lower()
    cmd = (p.get("cmdline") or "").lower()
    if e.get("event_type") == "process_exec" and (name in MINER_PROCESSES or "stratum+tcp://" in cmd):
        return f"miner process '{name}' executed"
    n = _net(e)
    if e.get("event_type") == "network_connection" and n.get("direction", "outbound") == "outbound":
        if int(n.get("dst_port") or 0) in MINING_POOL_PORTS and _is_public(n.get("dst_ip")):
            return f"outbound connection to mining-pool port {n.get('dst_port')} on {n.get('dst_ip')}"
    return None


@detection(
    id="CDR-003",
    title="Connection to known-malicious IP",
    severity="high",
    mitre_tactic="Command and Control",
    mitre_technique_id="T1071",
    mitre_technique_name="Application Layer Protocol",
    description="A workload communicated with an IP address on the threat-intelligence blocklist.",
)
def _malicious_ip(e):
    if e.get("event_type") != "network_connection":
        return None
    n = _net(e)
    for ip in (n.get("dst_ip"), n.get("src_ip")):
        if ip in MALICIOUS_IPS:
            return f"traffic with threat-intel IP {ip}"
    return None


@detection(
    id="CDR-004",
    title="Interactive shell spawned in container",
    severity="medium",
    mitre_tactic="Execution",
    mitre_technique_id="T1609",
    mitre_technique_name="Container Administration Command",
    description="A shell process started inside a running container (e.g. kubectl exec or an exploited app).",
)
def _shell_in_container(e):
    if e.get("event_type") != "process_exec" or not e.get("container"):
        return None
    p = _proc(e)
    if (p.get("name") or "").lower() in SHELLS:
        parent = (p.get("parent_name") or "").lower()
        # Shells started by an entrypoint script at container start are expected.
        if parent in {"tini", "dumb-init", "entrypoint.sh"}:
            return None
        return f"shell '{p.get('name')}' started by '{parent or '?'}' in container {e['container'].get('name')}"
    return None


@detection(
    id="CDR-005",
    title="Privilege escalation",
    severity="high",
    mitre_tactic="Privilege Escalation",
    mitre_technique_id="T1068",
    mitre_technique_name="Exploitation for Privilege Escalation",
    description="A process gained root privileges from an unprivileged context.",
)
def _privesc(e):
    if e.get("event_type") == "privilege_escalation":
        pr = e.get("privilege") or {}
        return f"uid {pr.get('from_uid', '?')} -> {pr.get('to_uid', 0)} via {pr.get('method', 'unknown')}"
    p = _proc(e)
    if e.get("event_type") == "process_exec" and e.get("container") and (p.get("name") in {"sudo", "su", "pkexec"}):
        return f"'{p.get('name')}' executed inside container"
    return None


@detection(
    id="CDR-006",
    title="Sensitive credential file accessed",
    severity="high",
    mitre_tactic="Credential Access",
    mitre_technique_id="T1552.001",
    mitre_technique_name="Unsecured Credentials: Credentials In Files",
    description="A process read a credential store (shadow file, SSH keys, service-account token, cloud CLI creds).",
)
def _sensitive_file(e):
    if e.get("event_type") != "file_access":
        return None
    path = (e.get("file") or {}).get("path") or ""
    if any(s in path for s in SENSITIVE_PATHS):
        proc = (_proc(e).get("name") or "").lower()
        # The kubelet / app runtime legitimately reads the SA token.
        if "serviceaccount/token" in path and proc in {"kubelet", "java", "node", "python", "dotnet"}:
            return None
        return f"'{proc or '?'}' read {path}"
    return None


@detection(
    id="CDR-007",
    title="Unexpected outbound connection",
    severity="low",
    mitre_tactic="Exfiltration",
    mitre_technique_id="T1048",
    mitre_technique_name="Exfiltration Over Alternative Protocol",
    description="A workload opened an outbound connection to a public IP on an unusual port.",
)
def _unexpected_outbound(e):
    if e.get("event_type") != "network_connection":
        return None
    n = _net(e)
    if n.get("direction", "outbound") != "outbound":
        return None
    port = int(n.get("dst_port") or 0)
    ip = n.get("dst_ip")
    if ip in MALICIOUS_IPS or port in MINING_POOL_PORTS:
        return None  # covered by more specific rules
    if _is_public(ip) and port not in EXPECTED_EGRESS_PORTS:
        return f"outbound {n.get('protocol', 'tcp')}/{port} to {ip}"
    return None


@detection(
    id="CDR-008",
    title="Cloud instance metadata (IMDS) accessed from container",
    severity="medium",
    mitre_tactic="Credential Access",
    mitre_technique_id="T1552.005",
    mitre_technique_name="Unsecured Credentials: Cloud Instance Metadata API",
    description="A container process queried the instance metadata service, commonly used to steal managed-identity tokens.",
)
def _imds(e):
    if e.get("event_type") != "network_connection" or not e.get("container"):
        return None
    n = _net(e)
    if n.get("dst_ip") == IMDS_IP:
        proc = (_proc(e).get("name") or "").lower()
        if proc in {"curl", "wget", "python", "python3", "sh", "bash"}:
            return f"'{proc}' contacted IMDS {IMDS_IP}"
    return None


def evaluate_event(event: dict[str, Any]) -> list[tuple[DetectionRule, str]]:
    out = []
    for r in DETECTION_RULES:
        try:
            reason = r.match(event)
        except Exception:
            reason = None
        if reason:
            out.append((r, reason))
    return out


def get_detection_rule(rule_id: str) -> DetectionRule | None:
    return next((r for r in DETECTION_RULES if r.id == rule_id), None)
