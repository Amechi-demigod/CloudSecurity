"""CPE 2.3 parsing and NVD configuration evaluation.

An NVD CVE lists *configurations*; each is one or more *nodes* (operator OR /
AND, optionally negated) of *cpeMatch* entries:

    {"vulnerable": true, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
     "versionStartIncluding": "130.0", "versionEndExcluding": "130.0.6723.91"}

A CVE matches an installed product when some configuration is satisfied with
a *vulnerable* entry for that product. Multi-node AND configurations ("Chrome
running on Windows") additionally need every other node to be satisfied by
the device's platform (its OS and other mapped software).

Rules that keep false positives out (desktop software is compared against
NVD data written for many purposes):

* An entry with no version information at all (`*` without a range, or `-`)
  never matches an installed *product*: NVD uses it for "all versions" of
  products whose fixes are tracked elsewhere (Microsoft 365 Apps, Office), so
  it says nothing about the installed build. It still satisfies a *platform*
  node ("on Windows").
* target_sw (e.g. `android`, `iphone_os`) must fit the device's OS, and
  target_hw (`x64`, `x86`, `arm64`) its architecture when known.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .versions import compare_versions, in_range

ANY = ("*", "")
NA = "-"

# target_sw values that fit each OS family.
TARGET_SW = {
    "windows": {"windows", "windows_10", "windows_11", "microsoft_windows", "windows_server"},
    "macos": {"macos", "mac_os_x", "mac_os", "macos_x", "os_x", "apple_macos"},
    "linux": {"linux", "linux_kernel"},
}
ARCH_ALIASES = {
    "x64": {"x64", "x86_64", "amd64", "x86-64", "64-bit"},
    "arm64": {"arm64", "aarch64", "arm"},
    "x86": {"x86", "i386", "i686", "32-bit"},
}


def split_cpe(cpe: str) -> list[str]:
    """Split a CPE 2.3 formatted string on unescaped ':' and unescape values."""
    parts: list[str] = []
    cur: list[str] = []
    i = 0
    while i < len(cpe):
        ch = cpe[i]
        if ch == "\\" and i + 1 < len(cpe):
            cur.append(cpe[i + 1])
            i += 2
            continue
        if ch == ":":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts


@dataclass(frozen=True)
class Criteria:
    part: str
    vendor: str
    product: str
    version: str
    update: str
    sw_edition: str
    target_sw: str
    target_hw: str

    @property
    def key(self) -> str:
        return f"{self.part}:{self.vendor}:{self.product}"


def parse_criteria(cpe: str) -> Criteria | None:
    p = split_cpe(cpe.lower())
    if len(p) < 13 or p[0] != "cpe" or p[1] != "2.3":
        return None
    return Criteria(part=p[2], vendor=p[3], product=p[4], version=p[5], update=p[6], sw_edition=p[9],
                    target_sw=p[10], target_hw=p[11])


def product_key(part: str, vendor: str, product: str) -> str:
    """Unescaped lower-case `part:vendor:product`, e.g. `a:notepad-plus-plus:notepad++`."""
    return f"{part}:{split_cpe(vendor.lower())[0]}:{split_cpe(product.lower())[0]}"


@dataclass
class Installed:
    """One installed product (or the OS) as a CPE-like value."""

    key: str  # part:vendor:product (unescaped)
    version: str
    update: str = ""
    os_family: str = ""  # windows | macos | linux
    arch: str = ""  # x64 | arm64 | x86 | ""
    sw_edition: str = ""  # e.g. Adobe "continuous" / "classic" track, when known


@dataclass
class MatchResult:
    criteria: str
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def fixed_version(self) -> str | None:
        """The first fixed version, when NVD states one (versionEndExcluding)."""
        return self.version_end_excluding


def _norm_update(u: str) -> str:
    return u.replace("_", "").replace("-", "").lower()


def _range_keys(entry: dict) -> dict[str, str | None]:
    return {
        "start_incl": entry.get("versionStartIncluding"), "start_excl": entry.get("versionStartExcluding"),
        "end_incl": entry.get("versionEndIncluding"), "end_excl": entry.get("versionEndExcluding"),
    }


def entry_matches(entry: dict, inst: Installed, *, platform: bool = False) -> bool:
    """Does one cpeMatch entry match `inst`? `platform` relaxes version checks
    for non-vulnerable platform nodes (any version of the OS satisfies them)."""
    c = parse_criteria(entry.get("criteria", ""))
    if c is None or c.key != inst.key:
        return False
    if c.target_sw not in ANY and c.target_sw != NA and inst.os_family:
        if c.target_sw not in TARGET_SW.get(inst.os_family, set()):
            return False
    if c.target_hw not in ANY and c.target_hw != NA and inst.arch:
        if c.target_hw not in ARCH_ALIASES.get(inst.arch, {inst.arch}):
            return False
    if c.sw_edition not in ANY and c.sw_edition != NA and inst.sw_edition and c.sw_edition != inst.sw_edition:
        return False
    ranges = _range_keys(entry)
    has_range = any(v is not None for v in ranges.values())
    if c.version not in ANY and c.version != NA:
        if not inst.version or compare_versions(inst.version, c.version) != 0:
            return False
        if c.update not in ANY and c.update != NA:
            return bool(inst.update) and _norm_update(inst.update) == _norm_update(c.update)
        return True
    if not has_range:
        return platform  # "all versions" / "no version": only good enough for a platform node
    if not inst.version:
        return platform
    return in_range(inst.version, **ranges)


def _node_matches(node: dict, items: list[Installed], *, vulnerable_only: bool, platform: bool
                  ) -> tuple[bool, dict | None]:
    entries = node.get("cpeMatch") or []
    hits: list[dict] = []
    results: list[bool] = []
    for e in entries:
        if vulnerable_only and not e.get("vulnerable", False):
            results.append(False)
            continue
        ok = any(entry_matches(e, it, platform=platform) for it in items)
        results.append(ok)
        if ok:
            hits.append(e)
    if (node.get("operator") or "OR").upper() == "AND":
        res = bool(entries) and all(results)
    else:
        res = any(results)
    if node.get("negate"):
        return (not res), None
    return res, (hits[0] if res and hits else None)


def config_matches(config: dict, target: Installed, platform: list[Installed]) -> dict | None:
    """The vulnerable cpeMatch entry through which `config` applies to
    `target` on a device with `platform` products, or None."""
    nodes = config.get("nodes") or []
    if not nodes:
        return None
    op = (config.get("operator") or ("AND" if len(nodes) > 1 else "OR")).upper()
    for i, node in enumerate(nodes):
        ok, hit = _node_matches(node, [target], vulnerable_only=True, platform=False)
        if not ok or hit is None:
            continue
        if op != "AND":
            return hit
        others = [n for j, n in enumerate(nodes) if j != i]
        if all(_node_matches(n, platform + [target], vulnerable_only=False, platform=True)[0] for n in others):
            return hit
    return None


def cve_matches(configurations: list[dict], target: Installed, platform: list[Installed]) -> MatchResult | None:
    for cfg in configurations or []:
        hit = config_matches(cfg, target, platform)
        if hit is not None:
            return MatchResult(
                criteria=hit.get("criteria", ""),
                version_start_including=hit.get("versionStartIncluding"),
                version_start_excluding=hit.get("versionStartExcluding"),
                version_end_including=hit.get("versionEndIncluding"),
                version_end_excluding=hit.get("versionEndExcluding"),
            )
    return None


def compact_configurations(configurations: list[dict], key: str) -> list[dict]:
    """Keep only the configurations that can apply to product `key`, and in
    OR nodes only that product's entries (storage: one NVD CVE can list
    hundreds of unrelated products)."""
    out = []
    for cfg in configurations or []:
        nodes = cfg.get("nodes") or []
        relevant = False
        new_nodes = []
        for node in nodes:
            entries = node.get("cpeMatch") or []
            mine = [e for e in entries if (c := parse_criteria(e.get("criteria", ""))) is not None and c.key == key]
            if mine and any(e.get("vulnerable") for e in mine):
                relevant = True
            if (node.get("operator") or "OR").upper() == "OR" and not node.get("negate") and mine and len(nodes) == 1:
                entries = mine
            new_nodes.append({k: v for k, v in {
                "operator": node.get("operator") or "OR", "negate": bool(node.get("negate")),
                "cpeMatch": [_slim_entry(e) for e in entries]}.items()})
        if relevant:
            c = {"nodes": new_nodes}
            if cfg.get("operator"):
                c["operator"] = cfg["operator"]
            out.append(c)
    return out


def _slim_entry(e: dict) -> dict:
    keep = ("vulnerable", "criteria", "versionStartIncluding", "versionStartExcluding", "versionEndIncluding",
            "versionEndExcluding")
    return {k: e[k] for k in keep if k in e}
