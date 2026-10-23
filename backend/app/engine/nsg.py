"""Inbound rule evaluation shared by the posture rules, the Azure connector and the attack-path engine.

Works on the normalized rule shape every connector produces (`security_rules` on
an NSG / security group / firewall-rule asset)::

    {"name", "direction", "access", "protocol", "priority",
     "source_prefixes", "port_ranges",                 # plural (augmented) fields
     "source_asgs", "destination_asgs", "destination_prefixes"}  # optional

Azure semantics (https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview):

* inbound rules are processed by priority, lowest number first; the first rule
  matching a flow decides it (Allow *or* Deny) and processing stops;
* every NSG ends with the default rules AllowVNetInBound (65000),
  AllowAzureLoadBalancerInBound (65001) and DenyAllInBound (65500);
* a NIC in a subnet is reachable only if the subnet NSG *and* the NIC NSG allow
  the flow (inbound: subnet first, then NIC). No NSG at a level allows all.

Sources: `*`, `Internet`, `Any`, `0.0.0.0/0` and `::/0` are the whole internet.
Other service tags (VirtualNetwork, AzureLoadBalancer, Storage, ...), private
or shared ranges and application security groups (members are NICs in the
VNet) are not internet sources. A public (non RFC 1918) CIDR is a *partial*
exposure: reachable from that range only, reported with the CIDR.

AWS security groups (allow-only, no priority) and GCP firewall rules (one rule
per asset) evaluate to the same results as before with this engine.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

MAX_PORT = 65535
PortRanges = list[tuple[int, int]]
FULL: PortRanges = [(0, MAX_PORT)]

INTERNET_SOURCES = {"*", "internet", "any", "0.0.0.0/0", "::/0", "0.0.0.0"}
_SHARED = ipaddress.ip_network("100.64.0.0/10")  # carrier-grade NAT, not routable on the internet
TCP_PROTOCOLS = {"*", "any", "all", "tcp", "-1", "6"}
# Custom rules are 100-4096; rules without a priority (AWS, simulated data) sort after
# them but before the Azure defaults.
_NO_PRIORITY = 4096.5

AZURE_DEFAULT_INBOUND: list[dict[str, Any]] = [
    {"name": "AllowVNetInBound", "direction": "Inbound", "access": "Allow", "protocol": "*", "priority": 65000,
     "source_prefixes": ["VirtualNetwork"], "port_ranges": ["*"], "default": True},
    {"name": "AllowAzureLoadBalancerInBound", "direction": "Inbound", "access": "Allow", "protocol": "*",
     "priority": 65001, "source_prefixes": ["AzureLoadBalancer"], "port_ranges": ["*"], "default": True},
    {"name": "DenyAllInBound", "direction": "Inbound", "access": "Deny", "protocol": "*", "priority": 65500,
     "source_prefixes": ["*"], "port_ranges": ["*"], "default": True},
]


# ----------------------------------------------------------------------------- port sets
def _norm(ranges: Iterable[tuple[int, int]]) -> PortRanges:
    out: PortRanges = []
    for lo, hi in sorted((max(0, a), min(MAX_PORT, b)) for a, b in ranges if a <= b):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def parse_ports(values: Any) -> PortRanges:
    """'*', 'Any', '22', '80-443', '22,3389', ints or a list of those -> sorted, merged ranges."""
    if values is None:
        return []
    if isinstance(values, (str, int)):
        values = [values]
    out: PortRanges = []
    for v in values:
        if isinstance(v, int):
            out.append((v, v))
            continue
        for part in str(v).split(","):
            part = part.strip().lower()
            if part in {"*", "any", "all", "0-65535"}:
                out.append((0, MAX_PORT))
            elif "-" in part:
                lo, hi = part.split("-", 1)
                if lo.strip().isdigit() and hi.strip().isdigit():
                    out.append((int(lo), int(hi)))
            elif part.isdigit():
                out.append((int(part), int(part)))
    return _norm(out)


def intersect(a: PortRanges, b: PortRanges) -> PortRanges:
    out = []
    for lo1, hi1 in a:
        for lo2, hi2 in b:
            lo, hi = max(lo1, lo2), min(hi1, hi2)
            if lo <= hi:
                out.append((lo, hi))
    return _norm(out)


def subtract(a: PortRanges, b: PortRanges) -> PortRanges:
    out = list(a)
    for blo, bhi in b:
        nxt = []
        for lo, hi in out:
            if bhi < lo or blo > hi:
                nxt.append((lo, hi))
                continue
            if lo < blo:
                nxt.append((lo, blo - 1))
            if hi > bhi:
                nxt.append((bhi + 1, hi))
        out = nxt
    return _norm(out)


def contains(ranges: PortRanges, port: int) -> bool:
    return any(lo <= port <= hi for lo, hi in ranges)


def format_ports(ranges: PortRanges) -> list[str]:
    """['*'] for every port, else ['22', '80-443', ...]."""
    if ranges == FULL:
        return ["*"]
    return [str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in ranges]


# ----------------------------------------------------------------------------- sources
def classify_source(prefix: Any) -> str | None:
    """'internet' (the whole internet), 'partial' (a public CIDR / IP) or None (not internet)."""
    p = str(prefix or "").strip()
    if p.lower() in INTERNET_SOURCES:
        return "internet"
    try:
        net = ipaddress.ip_network(p, strict=False)
    except ValueError:
        return None  # service tag (VirtualNetwork, AzureLoadBalancer, Storage...), ASG, sg:/pl: reference
    if net.prefixlen == 0:
        return "internet"
    if (net.is_private or net.is_loopback or net.is_link_local or net.is_multicast or net.is_reserved
            or (net.version == 4 and net.subnet_of(_SHARED))):  # type: ignore[arg-type]
        return None
    return "partial"


def _sources(rule: dict) -> list[str]:
    src = rule.get("source_prefixes")
    if not src:
        single = rule.get("source", rule.get("source_prefix"))
        src = [single] if single not in (None, "") else []
    return [str(s) for s in src]


def _ports(rule: dict) -> PortRanges:
    pr = rule.get("port_ranges")
    if not pr:
        pr = rule.get("port_range", rule.get("destination_port_range"))
    return parse_ports(pr)


def _priority(rule: dict) -> float:
    p = rule.get("priority")
    return float(p) if isinstance(p, (int, float)) and not isinstance(p, bool) else _NO_PRIORITY


def _dest_matches(rule: dict, target_asgs: set[str] | None, target_ips: list[str] | None) -> bool:
    dasgs = {str(x).lower() for x in rule.get("destination_asgs") or []}
    if dasgs and target_asgs is not None and not dasgs & target_asgs:
        return False
    dests = [str(d) for d in rule.get("destination_prefixes") or [] if d not in (None, "")]
    if dests and target_ips:
        for d in dests:
            if d.lower() in {"*", "any", "virtualnetwork", "internet"}:
                return True
            try:
                net = ipaddress.ip_network(d, strict=False)
            except ValueError:
                return True  # service tag / unknown: assume it can match
            if any(_ip_in(ip, net) for ip in target_ips):
                return True
        return False
    return True


def _ip_in(ip: str, net: ipaddress._BaseNetwork) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


# ----------------------------------------------------------------------------- evaluation
@dataclass
class Exposure:
    """Result of evaluating one control (or several combined) for internet -> target TCP traffic."""

    #: (lo, hi, deciding rule(s)) reachable from the whole internet
    open: list[tuple[int, int, str]] = field(default_factory=list)
    #: (lo, hi, rule, source CIDR) reachable only from a public range
    partial: list[tuple[int, int, str, str]] = field(default_factory=list)

    def open_ports(self) -> PortRanges:
        return _norm((lo, hi) for lo, hi, _ in self.open)

    def partial_ports(self) -> PortRanges:
        return _norm((lo, hi) for lo, hi, _, _ in self.partial)

    def rules_for(self, port: int | None) -> list[str]:
        """Rules opening `port` to the internet; `port=None`: only if every port is open."""
        if port is None:
            if self.open_ports() != FULL:
                return []
            return list(dict.fromkeys(r for _, _, r in self.open))
        return list(dict.fromkeys(r for lo, hi, r in self.open if lo <= port <= hi))

    def all_open(self) -> bool:
        return self.open_ports() == FULL

    def partial_summary(self) -> list[dict[str, Any]]:
        out: dict[tuple[str, str], PortRanges] = {}
        for lo, hi, rule, cidr in self.partial:
            out.setdefault((cidr, rule), []).append((lo, hi))
        return [{"source": cidr, "rule": rule, "ports": format_ports(_norm(r))} for (cidr, rule), r in out.items()]


def evaluate_rules(rules: Iterable[dict] | None, *, azure_defaults: bool = False,
                   target_asgs: Iterable[str] | None = None, target_ips: list[str] | None = None,
                   protocol: str = "tcp") -> Exposure:
    """Evaluate one control's inbound rules for traffic from the internet (first match wins)."""
    inbound = [r for r in (rules or []) if str(r.get("direction", "inbound")).lower() == "inbound"]
    if azure_defaults:
        inbound += AZURE_DEFAULT_INBOUND
    asgs = {str(a).lower() for a in target_asgs} if target_asgs is not None else None
    protos = TCP_PROTOCOLS if protocol == "tcp" else {"*", "any", "all", "-1", protocol}
    undecided: PortRanges = list(FULL)
    exp = Exposure()
    for r in sorted(inbound, key=_priority):  # stable: rules without a priority keep their order
        if not undecided:
            break
        if str(r.get("protocol", "*") or "*").lower() not in protos:
            continue
        if not _dest_matches(r, asgs, target_ips):
            continue
        ports = _ports(r)
        if not ports:
            continue
        allow = str(r.get("access", "allow")).lower() == "allow"
        name = str(r.get("name") or "?")
        kinds = {s: classify_source(s) for s in _sources(r)}
        if r.get("source_asgs") and not kinds:
            continue  # application security groups: NICs inside the VNet
        if "internet" in kinds.values():
            hit = intersect(undecided, ports)
            if allow:
                exp.open += [(lo, hi, name) for lo, hi in hit]
            undecided = subtract(undecided, ports)
        elif allow:
            hit = intersect(undecided, ports)
            for src, kind in kinds.items():
                if kind == "partial":
                    exp.partial += [(lo, hi, name, src) for lo, hi in hit]
        # a Deny from a public range only blocks that range: the rest of the internet is undecided
    return exp


def _cidr_overlap(a: str, b: str) -> str | None:
    try:
        na, nb = ipaddress.ip_network(a, strict=False), ipaddress.ip_network(b, strict=False)
    except ValueError:
        return None
    if na.version != nb.version or not na.overlaps(nb):
        return None
    return str(na if na.prefixlen >= nb.prefixlen else nb)


def combine_levels(first: Exposure | None, second: Exposure | None) -> Exposure | None:
    """Traffic must pass both controls (Azure: subnet NSG, then NIC NSG). None = no control at that level."""
    if first is None:
        return second
    if second is None:
        return first
    out = Exposure()
    for lo1, hi1, r1 in first.open:
        for lo2, hi2, r2 in second.open:
            lo, hi = max(lo1, lo2), min(hi1, hi2)
            if lo <= hi:
                out.open.append((lo, hi, r1 if r1 == r2 else f"{r1} + {r2}"))
    # partial: one side partial and the other open or partial for an overlapping range
    for a, b in ((first, second), (second, first)):
        for lo1, hi1, r1, cidr in a.partial:
            for lo2, hi2, r2 in b.open:
                lo, hi = max(lo1, lo2), min(hi1, hi2)
                if lo <= hi:
                    out.partial.append((lo, hi, f"{r1} + {r2}", cidr))
    for lo1, hi1, r1, c1 in first.partial:
        for lo2, hi2, r2, c2 in second.partial:
            lo, hi = max(lo1, lo2), min(hi1, hi2)
            cidr = _cidr_overlap(c1, c2) if lo <= hi else None
            if cidr:
                out.partial.append((lo, hi, f"{r1} + {r2}", cidr))
    open_ports = out.open_ports()
    out.partial = [p for p in dict.fromkeys(out.partial) if not intersect([(p[0], p[1])], open_ports) == [(p[0], p[1])]]
    return out


def asset_exposure(asset: dict[str, Any], target_asgs: Iterable[str] | None = None) -> Exposure:
    """Evaluate a network-control asset (Azure NSG gets the Azure default rules)."""
    props = asset.get("properties") or {}
    return evaluate_rules(props.get("security_rules") or [], azure_defaults=asset.get("type") == "nsg",
                          target_asgs=target_asgs)
