"""Version normalisation and comparison for CPE range evaluation.

Desktop software versions are dotted numbers with optional suffixes
(Chrome `130.0.6723.70`, Windows `10.0.22631.4317`, 7-Zip `24.08.00.0`,
Zoom `6.2.5 (47909)`). Comparison is segment by segment:

* numeric segments compare as integers (`08` == `8`, `10` > `9`);
* missing trailing segments count as 0 (`24.08` == `24.08.00.0`);
* an alphabetic segment sorts *before* a number at the same position, so
  pre-releases come first (`1.0rc1` < `1.0` < `1.0.1`).
"""
from __future__ import annotations

import math
import re

_SPLIT = re.compile(r"[.\-_+~:]")
_TOKEN = re.compile(r"\d+|[a-zA-Z]+")
_LEADING = re.compile(r"\d+(?:[.\-_+~][0-9A-Za-z]+)*")


def tokens(v: str) -> list[tuple[int, int | str]]:
    out: list[tuple[int, int | str]] = []
    for part in _SPLIT.split((v or "").strip().lower()):
        for t in _TOKEN.findall(part):
            out.append((2, int(t)) if t.isdigit() else (1, t))
    return out


def compare_versions(a: str, b: str) -> int:
    """-1 / 0 / 1 like a classic cmp()."""
    ta, tb = tokens(a), tokens(b)
    n = max(len(ta), len(tb))
    ta += [(2, 0)] * (n - len(ta))
    tb += [(2, 0)] * (n - len(tb))
    for x, y in zip(ta, tb, strict=True):
        if x == y:
            continue
        if x[0] != y[0]:
            return -1 if x[0] < y[0] else 1
        return -1 if x[1] < y[1] else 1  # type: ignore[operator]
    return 0


def normalize_version(raw: str | None) -> str:
    """Leading dotted version of an agent-reported version string, or "".

    `6.2.5 (47909)` -> `6.2.5`, `v2.46.0` -> `2.46.0`, `2.46.0.windows.1` ->
    `2.46.0`, `Unknown` -> ``.
    """
    v = (raw or "").strip()
    if v[:1] in ("v", "V") and v[1:2].isdigit():
        v = v[1:]
    m = _LEADING.match(v)
    if not m:
        return ""
    out = m.group(0)
    # Keep only the numeric dotted core when the tail is a word (2.46.0.windows.1).
    parts = out.split(".")
    core = []
    for p in parts:
        if not p[:1].isdigit():
            break
        core.append(p)
    return ".".join(core) if core else out


def in_range(version: str, *, start_incl: str | None = None, start_excl: str | None = None,
             end_incl: str | None = None, end_excl: str | None = None) -> bool:
    """CPE match-criteria version range check (NVD versionStart*/versionEnd*)."""
    if not version:
        return False
    if start_incl is not None and compare_versions(version, start_incl) < 0:
        return False
    if start_excl is not None and compare_versions(version, start_excl) <= 0:
        return False
    if end_incl is not None and compare_versions(version, end_incl) > 0:
        return False
    return not (end_excl is not None and compare_versions(version, end_excl) >= 0)


# --- operating systems --------------------------------------------------------------

# NVD has one CPE product per Windows feature release since 2022 (e.g.
# windows_11_23h2) with versions "10.0.<build>.<UBR>".
WIN11_BY_BUILD = {22000: "21h2", 22621: "22h2", 22631: "23h2", 26100: "24h2", 26200: "25h2"}
WIN10_BY_BUILD = {10240: "1507", 14393: "1607", 17763: "1809", 19044: "21h2", 19045: "22h2"}
SERVER_BY_BUILD = {14393: "windows_server_2016", 17763: "windows_server_2019", 20348: "windows_server_2022",
                   25398: "windows_server_2022_23h2", 26100: "windows_server_2025"}


def windows_os(os_name: str, os_version: str, os_build: str) -> tuple[str, str] | None:
    """(CPE product, version) of a Windows device, e.g. ("windows_11_23h2", "10.0.22631.4317").

    The agent reports os_name "Microsoft Windows 11 Pro 23H2", os_version
    "10.0.22631" and os_build "22631.4317" (build.UBR).
    """
    m = re.match(r"^(\d{4,6})(?:\.(\d+))?$", (os_build or "").strip())
    if not m:
        mv = re.match(r"^10\.0\.(\d{4,6})(?:\.(\d+))?$", (os_version or "").strip())
        if not mv:
            return None
        m = mv
    build, ubr = int(m.group(1)), m.group(2)
    version = f"10.0.{build}" + (f".{ubr}" if ubr else "")
    name = (os_name or "").lower()
    if "server" in name:
        product = SERVER_BY_BUILD.get(build)
        return (product, version) if product else None
    if "windows 11" in name or build >= 22000:
        rel = WIN11_BY_BUILD.get(build)
        return (f"windows_11_{rel}", version) if rel else None
    rel = WIN10_BY_BUILD.get(build)
    return (f"windows_10_{rel}", version) if rel else None


def macos_version(os_version: str) -> str:
    """`15.1`, `14.7.1`; drops a Rapid Security Response suffix (`13.4.1 (a)`)."""
    return normalize_version(os_version)


# --- CVSS ----------------------------------------------------------------------------

_V3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """CVSS v3.0/3.1 base score from a vector string (None if malformed)."""
    try:
        parts = dict(p.split(":", 1) for p in vector.strip().split("/")[1:])
        scope_changed = parts["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[parts["PR"]]
        iss = 1 - (1 - _V3["C"][parts["C"]]) * (1 - _V3["C"][parts["I"]]) * (1 - _V3["C"][parts["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * _V3["AV"][parts["AV"]] * _V3["AC"][parts["AC"]] * pr * _V3["UI"][parts["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + expl) if scope_changed else impact + expl
    return _roundup(min(raw, 10.0))
