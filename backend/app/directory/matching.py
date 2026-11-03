"""Directory object <-> agent device / IT asset owner matching (pure functions,
no database access; see docs/DIRECTORY_DISCOVERY.md#matching).

Directory computer records are first grouped into physical machines
(`cluster_computers`): the same object synced by two sources (same external
id), an Entra device and its Intune record (same Entra device id), an AD
computer and its hybrid-joined Entra device (same on-prem SID), records with
the same (real) serial number, and records an agent device ties together (it
reports the SID of one and the Entra device id of another).

Machines are then matched to agent devices in tiers, strongest first, using
the keys of all their records. A tier only matches when the key is unique on
BOTH sides among what is still unmatched; anything else at that tier is
"ambiguous" (flagged with its candidates, never guessed) and is not retried
with weaker keys:

1. directory_sid / directory_guid (100): the computer account SID / objectGUID
   the agent reported for itself.
2. entra_device_id (100): the Entra device id the agent reported (Entra and
   Intune records).
3. serial (95): when the directory knows the serial number (Intune, Google).
4. fqdn (90): dNSHostName vs the device FQDN (reported, or hostname + domain).
5. hostname_domain (75): short host name within the same domain (the device
   reported its AD domain).
6. hostname (50): short host name for devices that report no domain (older
   agents, Entra-only devices), only when the name exists once across ALL
   directory machines (otherwise ambiguous).
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

MATCHED, AMBIGUOUS, UNMATCHED = "matched", "ambiguous", "unmatched"
# Device record kinds, in the order a machine's representative record is chosen:
# AD computer, Entra device, Intune device, Google endpoint, ChromeOS, mobile.
DEVICE_KINDS = ("ad", "entra", "intune", "endpoint", "chromeos", "mobile")
# Serial numbers firmware ships when the vendor did not set one.
JUNK_SERIALS = frozenset({"", "0", "none", "n/a", "na", "default string", "to be filled by o.e.m.",
                          "system serial number", "not specified", "not applicable", "123456789", "0123456789",
                          "chassis serial number", "invalid", "unknown"})


def short_host(name: str) -> str:
    return (name or "").strip().rstrip(".").split(".")[0].lower()


def norm_serial(s: str) -> str:
    s = (s or "").strip().lower()
    return "" if s in JUNK_SERIALS else s


@dataclass(frozen=True)
class ComputerKey:
    id: str
    external_id: str = ""
    domain: str = ""
    short_name: str = ""
    dns_hostname: str = ""
    object_sid: str = ""
    serial: str = ""
    kind: str = "ad"            # device_kind (models.DEVICE_KINDS)
    cloud_device_id: str = ""   # Entra device id (Entra / Intune records)
    hybrid: bool = False        # Entra device hybrid-joined (synced from an AD computer of the same name)


@dataclass(frozen=True)
class DeviceKey:
    id: str
    hostname: str = ""
    ad_domain: str = ""
    ad_computer_sid: str = ""
    ad_object_guid: str = ""
    dns_hostname: str = ""
    serial: str = ""
    entra_device_id: str = ""

    @property
    def fqdn(self) -> str:
        if self.dns_hostname:
            return self.dns_hostname.lower().rstrip(".")
        h = (self.hostname or "").lower().rstrip(".")
        if "." in h:
            return h
        return f"{h}.{self.ad_domain.lower()}" if h and self.ad_domain else ""


@dataclass
class Match:
    status: str = UNMATCHED
    device_id: str | None = None
    method: str | None = None
    confidence: int | None = None
    candidates: list[str] = field(default_factory=list)


Tier = tuple[str, int, Callable[[ComputerKey], object], Callable[[DeviceKey], object]]


def _tiers() -> list[Tier]:
    def dom_pair_c(c: ComputerKey):
        return (c.short_name.lower(), c.domain.lower()) if c.short_name and c.domain else None

    def dom_pair_d(d: DeviceKey):
        return (short_host(d.hostname), d.ad_domain.lower()) if d.hostname and d.ad_domain else None

    return [
        ("directory_sid", 100, lambda c: c.object_sid.upper() or None, lambda d: d.ad_computer_sid.upper() or None),
        # objectGUID is an AD notion: cloud records' external ids are not comparable.
        ("directory_guid", 100, lambda c: c.external_id.lower() if c.kind == "ad" and c.external_id else None,
         lambda d: d.ad_object_guid.lower() or None),
        ("entra_device_id", 100, lambda c: c.cloud_device_id.lower() or None,
         lambda d: d.entra_device_id.lower() or None),
        ("serial", 95, lambda c: norm_serial(c.serial) or None, lambda d: norm_serial(d.serial) or None),
        ("fqdn", 90, lambda c: c.dns_hostname.lower().rstrip(".") or None, lambda d: d.fqdn or None),
        ("hostname_domain", 75, dom_pair_c, dom_pair_d),
        ("hostname", 50, lambda c: c.short_name.lower() or None,
         lambda d: short_host(d.hostname) if d.hostname and not d.ad_domain else None),
    ]


# Tiers strong enough that one agent device reporting two of them ties records together.
_LINK_TIERS = ("directory_sid", "directory_guid", "entra_device_id", "serial")
# Keys that make two directory records the same machine on their own.
_SAME_MACHINE: tuple[Callable[[ComputerKey], str], ...] = (
    lambda c: "x:" + c.external_id.lower() if c.external_id else "",
    lambda c: "e:" + c.cloud_device_id.lower() if c.cloud_device_id else "",
    lambda c: "s:" + c.object_sid.upper() if c.object_sid else "",
    lambda c: "n:" + norm_serial(c.serial) if norm_serial(c.serial) else "",
)


def _kind_rank(kind: str) -> int:
    return DEVICE_KINDS.index(kind) if kind in DEVICE_KINDS else len(DEVICE_KINDS)


def cluster_computers(computers: Iterable[ComputerKey], devices: Iterable[DeviceKey] = ()) -> dict[str, str]:
    """Group directory records into physical machines. Returns, per computer id,
    the id of its machine's representative record (the strongest kind: AD
    computer, then Entra device, Intune, Google endpoint, ChromeOS, mobile)."""
    computers = list(computers)
    parent: dict[str, str] = {c.id: c.id for c in computers}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    first: dict[str, str] = {}
    for c in computers:
        for key in _SAME_MACHINE:
            k = key(c)
            if k:
                if k in first:
                    union(first[k], c.id)
                else:
                    first[k] = c.id
    # A hybrid-joined Entra device is created by Entra Connect from an AD computer
    # and carries its name: linked when the short name is unique among AD
    # computers and among hybrid devices (two domains with a PC1 link nothing).
    ad_names: dict[str, set[str]] = defaultdict(set)
    hybrid_names: dict[str, set[str]] = defaultdict(set)
    for c in computers:
        if c.short_name and c.kind == "ad":
            ad_names[c.short_name.lower()].add(find(c.id))
        elif c.short_name and c.kind == "entra" and c.hybrid:
            hybrid_names[c.short_name.lower()].add(find(c.id))
    for name, hyb in hybrid_names.items():
        ads = {find(x) for x in ad_names.get(name, ())}
        hyb = {find(x) for x in hyb}
        if len(ads) == 1 and len(hyb) == 1:
            union(next(iter(ads)), next(iter(hyb)))
    # An agent device reporting e.g. the SID of an AD computer and the Entra
    # device id of an Entra record proves they are one machine (only keys that
    # point at exactly one record each: an ambiguous key ties nothing).
    tiers = [t for t in _tiers() if t[0] in _LINK_TIERS]
    index: list[dict[object, set[str]]] = []
    for _, _, ckey, _ in tiers:
        idx: dict[object, set[str]] = defaultdict(set)
        for c in computers:
            k = ckey(c)
            if k is not None:
                idx[k].add(find(c.id))
        index.append(idx)
    for d in devices:
        hits: set[str] = set()
        for (_, _, _, dkey), idx in zip(tiers, index, strict=True):
            k = dkey(d)
            if k is not None and len(idx.get(k, ())) == 1:
                hits |= idx[k]
        hits = {find(h) for h in hits}
        if len(hits) > 1:
            first_hit, *rest = sorted(hits)
            for h in rest:
                union(first_hit, h)
    groups: dict[str, list[ComputerKey]] = defaultdict(list)
    for c in computers:
        groups[find(c.id)].append(c)
    out: dict[str, str] = {}
    for members in groups.values():
        rep = min(members, key=lambda c: (_kind_rank(c.kind), c.id))
        for c in members:
            out[c.id] = rep.id
    return out


def match_computers(computers: Iterable[ComputerKey], devices: Iterable[DeviceKey],
                    clusters: dict[str, str] | None = None) -> dict[str, Match]:
    """Match directory computers to agent devices, one physical machine
    (`cluster_computers`) at a time. Returns a Match per computer id."""
    computers = list(computers)
    devices = list(devices)
    clusters = clusters if clusters is not None else cluster_computers(computers, devices)
    groups: dict[str, list[ComputerKey]] = defaultdict(list)
    for c in computers:
        groups[clusters.get(c.id, c.id)].append(c)
    short_count: dict[str, int] = defaultdict(int)
    for members in groups.values():
        for name in {c.short_name.lower() for c in members if c.short_name}:
            short_count[name] += 1
    result: dict[str, Match] = {}
    open_groups = set(groups)
    free_devices = {d.id: d for d in devices}

    def unique_short(name: str) -> bool:
        return short_count.get(name, 0) == 1

    for method, confidence, ckey, dkey in _tiers():
        by_dev: dict[object, list[str]] = defaultdict(list)
        for d in free_devices.values():
            k = dkey(d)
            if k is not None:
                by_dev[k].append(d.id)
        keys: dict[str, set[object]] = {}
        by_comp: dict[object, set[str]] = defaultdict(set)
        for g in open_groups:
            ks = {k for k in (ckey(c) for c in groups[g]) if k is not None}
            if ks:
                keys[g] = ks
                for k in ks:
                    by_comp[k].add(g)
        decided: dict[str, Match] = {}
        for g, ks in keys.items():
            hit = [k for k in ks if by_dev.get(k)]
            if not hit:
                continue
            devs = sorted({d for k in hit for d in by_dev[k]})
            rivals = set().union(*(by_comp[k] for k in hit))
            # Short names must be unique across ALL machines (also those already
            # matched): PC1 in two domains is never guessed for a domain-less device.
            unique = method != "hostname" or all(unique_short(str(k)) for k in hit)
            if len(devs) == 1 and rivals == {g} and unique:
                decided[g] = Match(MATCHED, devs[0], method, confidence, [devs[0]])
            else:
                decided[g] = Match(AMBIGUOUS, None, method, None, devs[:10])
        for g, m in decided.items():
            result[g] = m
            if m.device_id:
                free_devices.pop(m.device_id, None)
        open_groups.difference_update(decided)
    out: dict[str, Match] = {}
    for g, members in groups.items():
        m = result.get(g, Match())
        for c in members:
            out[c.id] = Match(m.status, m.device_id, m.method, m.confidence, list(m.candidates))
    return out


# ----------------------------------------------------------------------------- users
@dataclass(frozen=True)
class UserKey:
    id: str
    sam: str = ""      # lower-case sAMAccountName
    upn: str = ""      # lower-case
    mail: str = ""     # lower-case
    domain: str = ""   # lower-case DNS domain (from the DN)
    # Same person in two directories: an AD user and the Entra user synced from
    # it share the on-prem SID. Records with the same non-empty person are one.
    person: str = ""


# Sign-in "domains" that are never on-prem AD.
NON_AD_PREFIXES = frozenset({"azuread", "microsoftaccount", "nt authority", "nt service", "window manager",
                             "font driver host", "builtin"})


def parse_login(raw: str) -> tuple[str, str]:
    """`CORP\\alice` -> ("corp", "alice"); `alice@corp.example.com` -> ("@", "alice@corp.example.com");
    `alice` -> ("", "alice")."""
    raw = (raw or "").strip()
    if "\\" in raw:
        dom, _, name = raw.rpartition("\\")
        return dom.strip().lower(), name.strip().lower()
    if "@" in raw:
        return "@", raw.lower()
    return "", raw.lower()


class UserIndex:
    """Lookup of directory users by sAMAccountName / UPN / mail."""

    def __init__(self, users: Iterable[UserKey]):
        self.by_sam: dict[str, list[UserKey]] = defaultdict(list)
        self.by_upn: dict[str, list[UserKey]] = defaultdict(list)
        self.by_mail: dict[str, list[UserKey]] = defaultdict(list)
        for u in users:
            if u.sam:
                self.by_sam[u.sam].append(u)
            if u.upn:
                self.by_upn[u.upn].append(u)
            if u.mail:
                self.by_mail[u.mail].append(u)

    @staticmethod
    def _one(cands: list[UserKey]) -> UserKey | None:
        ids = {c.person or c.id for c in cands}
        return cands[0] if len(ids) == 1 else None

    def by_email(self, email: str) -> UserKey | None:
        email = (email or "").strip().lower()
        if not email:
            return None
        return self._one(self.by_upn.get(email, [])) or self._one(self.by_mail.get(email, []))

    def resolve(self, raw_login: str, *, device_domain: str = "", device_netbios: str = "",
                device_hostname: str = "", netbios_map: dict[str, str] | None = None) -> UserKey | None:
        """The directory user an OS sign-in name refers to, or None (unknown,
        a local / cloud account, or ambiguous)."""
        hint, name = parse_login(raw_login)
        if not name:
            return None
        if hint == "@":
            return self.by_email(name)
        if hint in NON_AD_PREFIXES or (hint and hint == short_host(device_hostname)):
            return None  # Entra ID / service / local account
        cands = self.by_sam.get(name, [])
        if not cands:
            return None
        domain = ""
        if hint:
            if device_netbios and hint == device_netbios.lower():
                domain = device_domain.lower()
            elif "." in hint:
                domain = hint
            else:
                domain = (netbios_map or {}).get(hint, "")
            if not domain:
                return self._one(cands) if len({c.domain for c in cands}) == 1 else None
        else:
            domain = device_domain.lower()
        if domain:
            scoped = [c for c in cands if c.domain == domain]
            return self._one(scoped)
        return self._one(cands)
