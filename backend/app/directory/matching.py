"""Directory object <-> agent device / IT asset owner matching (pure functions,
no database access; see docs/DIRECTORY_DISCOVERY.md#matching).

Computers are matched to agent devices in tiers, strongest first. A tier only
matches when the key is unique on BOTH sides among what is still unmatched;
anything else at that tier is "ambiguous" (flagged with its candidates, never
guessed) and is not retried with weaker keys:

1. directory_sid / directory_guid (100): the computer account SID / objectGUID
   the agent reported for itself.
2. serial (95): when the directory knows the serial number (not AD today).
3. fqdn (90): dNSHostName vs the device FQDN (reported, or hostname + domain).
4. hostname_domain (75): short host name within the same domain (the device
   reported its AD domain).
5. hostname (50): short host name for devices that report no domain (older
   agents), only when the name exists once across ALL directory computers
   (otherwise ambiguous).

The same directory object synced by two sources (overlapping configuration)
shares one external id and is matched as one.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

MATCHED, AMBIGUOUS, UNMATCHED = "matched", "ambiguous", "unmatched"
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


@dataclass(frozen=True)
class DeviceKey:
    id: str
    hostname: str = ""
    ad_domain: str = ""
    ad_computer_sid: str = ""
    ad_object_guid: str = ""
    dns_hostname: str = ""
    serial: str = ""

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
        ("directory_guid", 100, lambda c: c.external_id.lower() or None, lambda d: d.ad_object_guid.lower() or None),
        ("serial", 95, lambda c: norm_serial(c.serial) or None, lambda d: norm_serial(d.serial) or None),
        ("fqdn", 90, lambda c: c.dns_hostname.lower().rstrip(".") or None, lambda d: d.fqdn or None),
        ("hostname_domain", 75, dom_pair_c, dom_pair_d),
        ("hostname", 50, lambda c: c.short_name.lower() or None,
         lambda d: short_host(d.hostname) if d.hostname and not d.ad_domain else None),
    ]


def match_computers(computers: Iterable[ComputerKey], devices: Iterable[DeviceKey]) -> dict[str, Match]:
    """Match directory computers to agent devices. Returns a Match per computer id."""
    computers = list(computers)
    devices = list(devices)
    # One matching entity per external id (the same object synced by two sources).
    groups: dict[str, list[ComputerKey]] = defaultdict(list)
    for c in computers:
        groups[c.external_id.lower() or f"id:{c.id}"].append(c)
    reps = {g: members[0] for g, members in groups.items()}
    short_count: dict[str, int] = defaultdict(int)
    for rep in reps.values():
        if rep.short_name:
            short_count[rep.short_name.lower()] += 1
    result: dict[str, Match] = {}
    open_groups = set(reps)
    free_devices = {d.id: d for d in devices}
    def unique_short(name: str) -> bool:
        return short_count.get(name, 0) == 1

    for method, confidence, ckey, dkey in _tiers():
        by_dev: dict[object, list[str]] = defaultdict(list)
        for d in free_devices.values():
            k = dkey(d)
            if k is not None:
                by_dev[k].append(d.id)
        by_comp: dict[object, list[str]] = defaultdict(list)
        for g in open_groups:
            k = ckey(reps[g])
            if k is not None:
                by_comp[k].append(g)
        for k, gs in by_comp.items():
            devs = by_dev.get(k)
            if not devs:
                continue
            # Short names must be unique across ALL computers (also those already
            # matched): PC1 in two domains is never guessed for a domain-less device.
            unique = method != "hostname" or unique_short(str(k))
            if len(devs) == 1 and len(gs) == 1 and unique:
                result[gs[0]] = Match(MATCHED, devs[0], method, confidence, [devs[0]])
                free_devices.pop(devs[0], None)
            else:
                for g in gs:
                    result[g] = Match(AMBIGUOUS, None, method, None, sorted(devs)[:10])
            open_groups.difference_update(gs)
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
        ids = {c.id for c in cands}
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
