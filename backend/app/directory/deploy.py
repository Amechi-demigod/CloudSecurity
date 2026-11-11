"""Deploy agent: turn Discovery's "No agent" machines into enrolled devices
(docs/DIRECTORY_DISCOVERY.md#deploying-the-agent).

The platform never writes to a directory or an MDM. For a selection of
directory machines it

* picks the best **route** per machine from where it was found and its OS
  (`plan_machine`, pure): Group Policy for on-prem AD Windows computers,
  Intune for Windows / macOS devices Intune manages, Configuration Manager /
  Jamf / another RMM (only when the admin chooses it: directories do not say
  which tool manages a machine), or a manual install (download or one-liner)
  for the rest; machines that cannot or should not run the agent are excluded
  with the reason;
* records the batch as an `AgentDeployment` with its machines, issues
  enrollment tokens / pre-configured installers for it (capped to the batch,
  expiring with it) and
* reports progress: which machines have since enrolled, through the existing
  directory matching (directory/matching.py; recomputed after every sync and
  every 30 minutes).
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Device, EnrollmentToken, utcnow
from ..services import devices as device_svc
from .models import AgentDeployment, AgentDeploymentItem, DirectoryComputer

ROUTES = ("gpo", "intune", "rmm", "manual")
ROUTE_LABEL = {"gpo": "Group Policy (Active Directory)", "intune": "Microsoft Intune",
               "rmm": "Configuration Manager, Jamf or another RMM", "manual": "Download or one-line install"}
EXCLUDED_LABEL = {
    "has_agent": "Already has an active agent",
    "mobile": "Phones, tablets and ChromeOS cannot run the agent (they are managed by their MDM)",
    "no_agent_expected": "Personal or registered-only device: no agent is expected on it",
    "disabled": "Disabled in every directory it is in",
    "linux": "Linux servers are not pushed from a directory: install the .deb / .rpm from Devices > Enrollment (docs/DEVICE_MANAGEMENT.md)",
    "unknown_os": "Operating system unknown or not supported by the agent",
    "gone": "No longer in any directory",
}
# Installer package per platform (services/installers.py).
PACKAGE = {"windows": "windows-msi", "macos": "macos-pkg"}
MAX_SELECTION = 5000
# Prefer the platform an MDM reports over what a directory guesses from a name.
_PLATFORM_ORDER = ("intune", "entra", "ad", "endpoint", "chromeos", "mobile")


@dataclass(frozen=True)
class Record:
    """One directory record of a physical machine (only what planning needs)."""

    kind: str  # ad | entra | intune | endpoint | chromeos | mobile
    platform: str  # windows | macos | linux | ios | android | chromeos | other | ""
    agent_expected: bool = True
    enabled: bool = True


@dataclass(frozen=True)
class Plan:
    route: str | None  # None = excluded
    reason: str = ""  # exclusion reason (EXCLUDED_LABEL key)
    platform: str = ""
    allowed: tuple[str, ...] = ()


def machine_platform(records: Iterable[Record]) -> str:
    recs = sorted(records, key=lambda r: _PLATFORM_ORDER.index(r.kind) if r.kind in _PLATFORM_ORDER else 99)
    return next((r.platform for r in recs if r.platform), "")


def plan_machine(records: list[Record], *, has_agent: bool) -> Plan:
    """Best route for one physical machine (pure; unit-tested).

    Intune wins over Group Policy for a machine in both (it also reaches
    machines off the corporate network); the admin can switch any machine to
    another allowed route."""
    platform = machine_platform(records)
    if has_agent:
        return Plan(None, "has_agent", platform)
    if not records:
        return Plan(None, "gone", platform)
    if platform in ("ios", "android", "chromeos") or all(r.kind in ("chromeos", "mobile") for r in records):
        return Plan(None, "mobile", platform)
    if not any(r.enabled for r in records):
        return Plan(None, "disabled", platform)
    if not any(r.agent_expected for r in records if r.enabled):
        return Plan(None, "no_agent_expected", platform)
    if platform == "linux":
        return Plan(None, "linux", platform)
    if platform not in PACKAGE:
        return Plan(None, "unknown_os", platform)
    kinds = {r.kind for r in records if r.enabled}
    allowed: list[str] = []
    if "intune" in kinds:
        allowed.append("intune")
    if "ad" in kinds and platform == "windows":
        allowed.append("gpo")
    allowed += ["rmm", "manual"]
    return Plan(allowed[0] if allowed[0] != "rmm" else "manual", "", platform, tuple(allowed))


def batch_cap(n: int) -> int:
    """Enrollment cap for a batch of n machines: a small margin for re-imaged or
    renamed machines (re-installs on an enrolled machine use no enrollment)."""
    return min(100000, n + max(2, math.ceil(n * 0.1)))


# ----------------------------------------------------------------------------- planning against the database
@dataclass
class Machine:
    id: str  # representative record id
    name: str
    os: str
    domain: str
    ou: str
    kinds: list[str]
    plan: Plan
    sources: list[str] = field(default_factory=list)


def _active_devices(db: Session, ids: set[str]) -> dict[str, Device]:
    out: dict[str, Device] = {}
    ids_l = sorted(i for i in ids if i)
    for i in range(0, len(ids_l), 500):
        for d in db.scalars(select(Device).where(Device.id.in_(ids_l[i:i + 500]), Device.status == "active")):
            out[d.id] = d
    return out


def _members(db: Session, machine_ids: list[str]) -> dict[str, list[DirectoryComputer]]:
    machine = func.coalesce(DirectoryComputer.machine_id, DirectoryComputer.id)
    out: dict[str, list[DirectoryComputer]] = defaultdict(list)
    for i in range(0, len(machine_ids), 500):
        for c in db.scalars(select(DirectoryComputer).where(machine.in_(machine_ids[i:i + 500]),
                                                            DirectoryComputer.missing_since.is_(None))
                            .order_by(DirectoryComputer.id)):
            out[c.machine_id or c.id].append(c)
    return out


def resolve_machines(db: Session, computer_ids: list[str]) -> tuple[list[str], list[str]]:
    """Representative machine ids for these directory records (deduplicated, in
    order) and the ids that do not exist in this organisation."""
    ids = list(dict.fromkeys(computer_ids))
    found: dict[str, str] = {}
    for i in range(0, len(ids), 500):
        for cid, mid in db.execute(select(DirectoryComputer.id, DirectoryComputer.machine_id)
                                   .where(DirectoryComputer.id.in_(ids[i:i + 500]))):
            found[cid] = mid or cid
    return list(dict.fromkeys(found[i] for i in ids if i in found)), [i for i in ids if i not in found]


def plan(db: Session, machine_ids: list[str]) -> list[Machine]:
    members = _members(db, machine_ids)
    active = _active_devices(db, {c.device_id for cs in members.values() for c in cs if c.device_id})
    out = []
    for mid in machine_ids:
        recs = members.get(mid, [])
        rep = next((c for c in recs if c.id == mid), recs[0] if recs else None)
        records = [Record(c.device_kind, c.platform, c.agent_expected, c.enabled) for c in recs]
        p = plan_machine(records, has_agent=any(c.device_id in active for c in recs if c.device_id))
        if rep is None:
            gone = db.get(DirectoryComputer, mid)
            out.append(Machine(mid, gone.name if gone else "", gone.operating_system if gone else "", "", "", [], p))
            continue
        os_name = rep.operating_system or next((c.operating_system for c in recs if c.operating_system), "")
        ad = next((c for c in recs if c.device_kind == "ad"), None)
        out.append(Machine(mid, rep.name, os_name, (ad or rep).domain, (ad or rep).ou,
                           sorted({c.device_kind for c in recs}, key=lambda k: _PLATFORM_ORDER.index(k)
                                  if k in _PLATFORM_ORDER else 99), p,
                           sorted({c.source_id for c in recs})))
    return out


def plan_out(machines: list[Machine]) -> dict[str, Any]:
    """Machines grouped by suggested route (+ OUs for Group Policy) and the excluded ones by reason."""
    groups: dict[str, list[dict]] = {r: [] for r in ROUTES}
    excluded: dict[str, list[dict]] = defaultdict(list)
    for m in machines:
        row = {"computer_id": m.id, "name": m.name, "os": m.os, "platform": m.plan.platform, "domain": m.domain,
               "ou": m.ou, "kinds": m.kinds, "source_ids": m.sources, "route": m.plan.route,
               "allowed_routes": list(m.plan.allowed), "reason": m.plan.reason}
        if m.plan.route:
            groups[m.plan.route].append(row)
        else:
            excluded[m.plan.reason].append(row)
    return {"routes": [{"route": r, "label": ROUTE_LABEL[r], "count": len(groups[r]), "items": groups[r],
                        **route_facts(r, groups[r])} for r in ROUTES if groups[r]],
            "excluded": [{"reason": k, "label": EXCLUDED_LABEL[k], "count": len(v), "items": v}
                         for k, v in excluded.items()],
            "total": len(machines), "deployable": sum(len(v) for v in groups.values())}


def route_facts(route: str, items: list[dict]) -> dict[str, Any]:
    """Facts the per-route instructions need: platforms, and the OUs for Group Policy."""
    out: dict[str, Any] = {"platforms": dict(Counter(i["platform"] for i in items))}
    if route == "gpo":
        ous = Counter((i["domain"], i["ou"]) for i in items)
        out["ous"] = [{"domain": d, "ou": o, "count": n} for (d, o), n in sorted(ous.items(), key=lambda x: (-x[1], x[0]))]
    return out


# ----------------------------------------------------------------------------- progress
def state(dep: AgentDeployment, now: datetime | None = None) -> str:
    now = now or utcnow()
    if dep.revoked_at is not None:
        return "revoked"
    if dep.expires_at <= now:
        return "expired"
    return "active"


def progress(db: Session, dep: AgentDeployment, items: list[AgentDeploymentItem] | None = None,
             now: datetime | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Per selected machine: enrolled (its directory machine is matched to an
    active agent device), pending, or gone (no longer in any directory)."""
    now = now or utcnow()
    items = items if items is not None else list(db.scalars(
        select(AgentDeploymentItem).where(AgentDeploymentItem.deployment_id == dep.id)
        .order_by(AgentDeploymentItem.name, AgentDeploymentItem.id)))
    # The machine a record belongs to can change (re-grouping): follow the record.
    ids = [i.computer_id for i in items]
    current: dict[str, str] = {}
    for k in range(0, len(ids), 500):
        for cid, mid in db.execute(select(DirectoryComputer.id, DirectoryComputer.machine_id)
                                   .where(DirectoryComputer.id.in_(ids[k:k + 500]))):
            current[cid] = mid or cid
    members = _members(db, sorted(set(current.values())))
    active = _active_devices(db, {c.device_id for cs in members.values() for c in cs if c.device_id})
    tokens = set(dep.token_ids or [])
    rows = []
    counts = Counter()
    for it in items:
        recs = members.get(current.get(it.computer_id, ""), [])
        dev = next((active[c.device_id] for c in recs if c.device_id in active), None)
        status = "enrolled" if dev else ("pending" if recs else "gone")
        counts[status] += 1
        rows.append({"computer_id": it.computer_id, "name": it.name, "os": it.os, "platform": it.platform,
                     "route": it.route, "domain": it.domain, "ou": it.ou, "kinds": list(it.kinds or []),
                     "status": status, "device_id": dev.id if dev else None,
                     "device_hostname": dev.hostname if dev else None,
                     "enrolled_at": dev.enrolled_at if dev else None,
                     "via_deployment": bool(dev and dev.enrollment_token_id in tokens)})
    total = len(items)
    via_tokens = db.scalar(select(func.count()).select_from(Device).where(
        Device.enrollment_token_id.in_(tokens), Device.status == "active")) if tokens else 0
    summary = {"total": total, "enrolled": counts["enrolled"], "pending": counts["pending"], "gone": counts["gone"],
               "pct": round(counts["enrolled"] * 100.0 / total, 1) if total else None,
               "enrolled_with_tokens": via_tokens or 0, "age_days": max(0, (now - dep.created_at).days)}
    return rows, summary


def tokens_out(db: Session, dep: AgentDeployment, now: datetime | None = None) -> list[dict[str, Any]]:
    ids = list(dep.token_ids or [])
    if not ids:
        return []
    rows = db.scalars(select(EnrollmentToken).where(EnrollmentToken.id.in_(ids))
                      .order_by(EnrollmentToken.created_at))
    return [{"id": t.id, "name": t.name, "token_prefix": t.token_prefix, "package_platform": t.package_platform,
             "max_uses": t.max_uses, "use_count": t.use_count, "expires_at": t.expires_at,
             "state": device_svc.token_state(t, now)} for t in rows]
