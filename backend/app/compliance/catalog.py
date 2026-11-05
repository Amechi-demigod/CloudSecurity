"""Framework mapping files (app/compliance/frameworks/*.json, docs/COMPLIANCE.md).

One JSON file per framework: groups of controls, each control with its
identifier, OUR OWN short paraphrased title (never the publisher's text: CIS,
ISO, PCI SSC and AICPA texts are copyrighted) and, only where the platform's
checks genuinely provide evidence, the automated `checks` and how much of the
control they cover (`coverage`: "full" or "partial"). A control without checks
is "not assessed automatically" and needs manual evidence.

`checks` entries are check ids (app/compliance/checks.py) or "@<set>"
references to the named check sets in `checksets.json`. Files are loaded once
and validated; an unknown check id fails loudly (and in tests).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

DIR = Path(__file__).parent / "frameworks"
CHECKSETS = "checksets.json"
# Display order of the frameworks shipped in v1 (any other file is listed after them).
ORDER = ("cis", "iso27001-2022", "soc2-2017", "nist-csf-2.0", "pci-dss-4.0")
COVERAGE = ("full", "partial")


class MappingError(ValueError):
    """A framework file is malformed or references an unknown check."""


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    group: str
    checks: tuple[str, ...] = ()   # resolved check ids (sets expanded, de-duplicated)
    refs: tuple[str, ...] = ()     # as written in the file ("@set" kept)
    coverage: str | None = None    # full | partial | None (manual)
    note: str = ""


@dataclass(frozen=True)
class Group:
    id: str
    title: str
    controls: tuple[Control, ...]


@dataclass(frozen=True)
class Framework:
    id: str
    name: str
    short_name: str
    version: str
    mapping_version: int
    publisher: str
    notice: str
    groups: tuple[Group, ...]
    controls: tuple[Control, ...] = field(default=())

    def meta(self) -> dict:
        auto = sum(1 for c in self.controls if c.checks)
        return {"id": self.id, "name": self.name, "short_name": self.short_name, "version": self.version,
                "mapping_version": self.mapping_version, "publisher": self.publisher, "notice": self.notice,
                "controls": len(self.controls), "automated_controls": auto}


def _read(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise MappingError(f"{path.name}: {e}") from None


@cache
def check_sets() -> dict[str, dict]:
    doc = _read(DIR / CHECKSETS)
    sets = doc.get("sets")
    if not isinstance(sets, dict):
        raise MappingError(f"{CHECKSETS}: 'sets' must be an object")
    return sets


def expand(refs: list[str] | tuple[str, ...], where: str = "") -> tuple[str, ...]:
    """Resolve "@set" references; keep order, drop duplicates."""
    sets = check_sets()
    out: dict[str, None] = {}
    for r in refs:
        if r.startswith("@"):
            s = sets.get(r[1:])
            if s is None:
                raise MappingError(f"{where}: unknown check set {r}")
            for c in s.get("checks") or []:
                out[c] = None
        else:
            out[r] = None
    return tuple(out)


def _load(path: Path) -> Framework:
    doc = _read(path)
    fid = doc.get("id")
    if not fid or fid != path.stem:
        raise MappingError(f"{path.name}: 'id' must equal the file name ({path.stem})")
    groups: list[Group] = []
    all_controls: list[Control] = []
    seen: set[str] = set()
    for g in doc.get("groups") or []:
        controls = []
        for c in g.get("controls") or []:
            cid, title = str(c.get("id") or ""), str(c.get("title") or "")
            if not cid or not title or len(title) > 120:
                raise MappingError(f"{path.name}: every control needs an id and a short title (<= 120 chars)")
            if cid in seen:
                raise MappingError(f"{path.name}: duplicate control {cid}")
            seen.add(cid)
            refs = tuple(c.get("checks") or ())
            coverage = c.get("coverage")
            if refs and coverage not in COVERAGE:
                raise MappingError(f"{path.name} {cid}: coverage must be one of {COVERAGE}")
            if not refs and coverage:
                raise MappingError(f"{path.name} {cid}: coverage without checks")
            ctl = Control(id=cid, title=title, group=str(g.get("id")), refs=refs,
                          checks=expand(refs, f"{path.name} {cid}"), coverage=coverage if refs else None,
                          note=str(c.get("note") or ""))
            controls.append(ctl)
            all_controls.append(ctl)
        groups.append(Group(id=str(g.get("id")), title=str(g.get("title")), controls=tuple(controls)))
    return Framework(id=fid, name=doc["name"], short_name=doc.get("short_name") or doc["name"],
                     version=str(doc.get("version") or ""), mapping_version=int(doc.get("mapping_version") or 1),
                     publisher=str(doc.get("publisher") or ""), notice=str(doc.get("notice") or ""),
                     groups=tuple(groups), controls=tuple(all_controls))


@cache
def frameworks() -> dict[str, Framework]:
    """All framework files, in display order (validated against the check registry)."""
    from . import checks

    found = {p.stem: _load(p) for p in sorted(DIR.glob("*.json")) if p.name != CHECKSETS}
    known = checks.registry()
    for fw in found.values():
        for c in fw.controls:
            unknown = [x for x in c.checks if x not in known]
            if unknown:
                raise MappingError(f"{fw.id} {c.id}: unknown check(s) {', '.join(unknown)}")
    order = [k for k in ORDER if k in found] + sorted(k for k in found if k not in ORDER)
    return {k: found[k] for k in order}


def get(framework_id: str) -> Framework | None:
    return frameworks().get(framework_id)
