"""Apply matches and (re)evaluate discovery issues (docs/DIRECTORY_DISCOVERY.md#discovery-issues).

Runs after every sync that stored objects and periodically from the scheduler
(device check-ins change "disabled but active" and the signed-in users). Reads
only the columns it needs and writes only rows that changed, so it stays cheap
for directories with 100k+ objects.

Computer issues are evaluated per physical machine: the AD computer, Entra
device and Intune record of one laptop are one machine (matching.cluster_computers),
reported once and counted once in coverage.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.orm import Session

from ..asset_lifecycle.models import ItAsset
from ..models import Device, utcnow
from . import matching
from .models import FINDING_TYPES, DirectoryComputer, DirectoryFinding, DirectorySource, DirectoryUser

log = logging.getLogger(__name__)

# An agent device that checked in this recently counts as "active".
ACTIVE_WINDOW = timedelta(days=7)
CHUNK = 500
# Where a device record comes from, for issue details.
KIND_LABEL = {"ad": "Active Directory", "entra": "Entra ID", "intune": "Intune", "endpoint": "Google endpoints",
              "chromeos": "Google ChromeOS", "mobile": "Google mobile"}
# Operating systems Intune manages that the agent also runs on.
INTUNE_OS = frozenset({"windows", "macos"})


def _chunks(seq: list, n: int = CHUNK):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def _device_rows(db: Session) -> list[Any]:
    return db.execute(select(Device.id, Device.hostname, Device.status, Device.last_seen_at, Device.ad_domain,
                             Device.ad_computer_sid, Device.entra_device_id, Device.directory_join,
                             Device.serial_number, Device.agent_features, Device.inventory, Device.os_family)).all()


def _join(d: Any) -> dict[str, Any]:
    return d.directory_join or {}


# ----------------------------------------------------------------------------- matching
def apply_matches(db: Session, now: datetime | None = None, devices: list[Any] | None = None) -> int:
    """Group current (not missing) computers into machines, match them to active
    devices and store the result on the computers. Returns the number of
    computers changed."""
    now = now or utcnow()
    devices = devices if devices is not None else _device_rows(db)
    dkeys = [matching.DeviceKey(id=d.id, hostname=d.hostname or "", ad_domain=d.ad_domain or "",
                                ad_computer_sid=d.ad_computer_sid or "",
                                ad_object_guid=_join(d).get("ad_object_guid", ""),
                                dns_hostname=_join(d).get("dns_hostname", ""),
                                serial=d.serial_number or "",
                                entra_device_id=d.entra_device_id or _join(d).get("entra_device_id", ""))
             for d in devices if d.status == "active"]
    rows = db.execute(select(DirectoryComputer.id, DirectoryComputer.external_id, DirectoryComputer.domain,
                             DirectoryComputer.short_name, DirectoryComputer.dns_hostname,
                             DirectoryComputer.object_sid, DirectoryComputer.serial_number,
                             DirectoryComputer.device_kind, DirectoryComputer.cloud_device_id,
                             DirectoryComputer.device_id, DirectoryComputer.it_asset_id,
                             DirectoryComputer.match_status, DirectoryComputer.match_method,
                             DirectoryComputer.match_confidence, DirectoryComputer.match_candidates,
                             DirectoryComputer.machine_id)
                      .where(DirectoryComputer.missing_since.is_(None))).all()
    hybrid = {i for i, attrs in db.execute(select(DirectoryComputer.id, DirectoryComputer.attributes).where(
        DirectoryComputer.device_kind == "entra", DirectoryComputer.missing_since.is_(None)))
        if (attrs or {}).get("join") == "hybrid"}
    ckeys = [matching.ComputerKey(id=r.id, external_id=r.external_id, domain=r.domain, short_name=r.short_name,
                                  dns_hostname=r.dns_hostname, object_sid=r.object_sid or "", serial=r.serial_number,
                                  kind=r.device_kind, cloud_device_id=r.cloud_device_id or "", hybrid=r.id in hybrid)
             for r in rows]
    clusters = matching.cluster_computers(ckeys, dkeys)
    matches = matching.match_computers(ckeys, dkeys, clusters)
    asset_by_device = dict(db.execute(select(ItAsset.device_id, ItAsset.id).where(ItAsset.device_id.is_not(None))).all())
    own_assets = {r.it_asset_id for r in rows if r.it_asset_id}
    unlinked_own = set()
    for chunk in _chunks(list(own_assets)):
        unlinked_own.update(db.scalars(select(ItAsset.id).where(ItAsset.id.in_(chunk), ItAsset.device_id.is_(None))))
    # An asset added from Discovery (no agent yet) belongs to the whole machine.
    machine_asset: dict[str, str] = {}
    for r in sorted(rows, key=lambda r: r.id):
        if r.it_asset_id in unlinked_own:
            machine_asset.setdefault(clusters[r.id], r.it_asset_id)
    changes: dict[str, dict[str, Any]] = {}
    for r in rows:
        m = matches[r.id]
        machine = clusters[r.id]
        asset = asset_by_device.get(m.device_id) if m.device_id else None
        if asset is None:
            asset = machine_asset.get(machine)
        new = {"match_status": m.status, "device_id": m.device_id, "match_method": m.method,
               "match_confidence": m.confidence, "match_candidates": m.candidates, "it_asset_id": asset,
               "machine_id": machine}
        old = {"match_status": r.match_status, "device_id": r.device_id, "match_method": r.match_method,
               "match_confidence": r.match_confidence, "match_candidates": list(r.match_candidates or []),
               "it_asset_id": r.it_asset_id, "machine_id": r.machine_id}
        if new != old:
            changes[r.id] = new
    for chunk in _chunks(list(changes)):
        for c in db.scalars(select(DirectoryComputer).where(DirectoryComputer.id.in_(chunk))):
            new = changes[c.id]
            if new["device_id"] != c.device_id:
                c.matched_at = now if new["device_id"] else None
            for k, v in new.items():
                setattr(c, k, v)
        db.flush()
    return len(changes)


# ----------------------------------------------------------------------------- findings
@dataclass
class _F:
    type: str
    kind: str
    source_id: str | None
    computer_id: str | None = None
    user_id: str | None = None
    device_id: str | None = None
    name: str = ""
    domain: str = ""
    ou: str = ""
    os: str = ""
    last_logon_at: datetime | None = None
    enabled: bool | None = None
    detail: str = ""

    @property
    def key(self) -> str:
        if self.kind == "user" and self.computer_id:
            return f"{self.type}:{self.user_id}:c{self.computer_id}"
        obj = self.computer_id or self.user_id or self.device_id
        return f"{self.type}:{obj}" + (f":{self.device_id}" if self.kind == "user" and self.device_id else "")

    def values(self) -> dict[str, Any]:
        return {"type": self.type, "kind": self.kind, "source_id": self.source_id, "computer_id": self.computer_id,
                "user_id": self.user_id, "device_id": self.device_id, "name": self.name[:256],
                "domain": self.domain[:255], "ou": self.ou, "os": self.os[:256], "last_logon_at": self.last_logon_at,
                "enabled": self.enabled, "detail": self.detail[:500]}


def _fmt(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d") if dt else "never"


def _labels(kinds: list[str]) -> str:
    order = matching.DEVICE_KINDS
    ranked = sorted(set(kinds), key=lambda k: order.index(k) if k in order else len(order))
    return ", ".join(KIND_LABEL.get(k, k) for k in ranked)


@dataclass
class _Sources:
    """What the evaluation needs to know about the organisation's sources."""

    stale_days: dict[str, int]
    types: dict[str, str]
    # Sources whose users' last sign-in is known (Entra ID needs P1/P2 + AuditLog.Read.All).
    sign_in_known: set[str]
    # Tenant ids of Entra sources whose Intune part completed / devices part completed.
    intune_tenants: set[str]
    entra_tenants: set[str]
    synced: bool

    @classmethod
    def load(cls, db: Session) -> _Sources | None:
        sources = list(db.scalars(select(DirectorySource)))
        if not sources:
            return None
        def ok(s: DirectorySource, part: str) -> bool:
            return ((s.scope_status or {}).get(part) or {}).get("status") == "ok"
        return cls(
            stale_days={s.id: int((s.config or {}).get("stale_days") or 90) for s in sources},
            types={s.id: s.type for s in sources},
            sign_in_known={s.id for s in sources if s.type != "entra" or ok(s, "sign_in")},
            intune_tenants={(s.config or {}).get("tenant_id", "") for s in sources
                            if s.type == "entra" and s.enabled and ok(s, "intune")} - {""},
            entra_tenants={(s.config or {}).get("tenant_id", "") for s in sources
                           if s.type == "entra" and s.enabled and ok(s, "devices")} - {""},
            synced=any(s.last_success_at for s in sources),
        )


def compute_findings(db: Session, now: datetime, devices: list[Any]) -> list[_F]:
    src = _Sources.load(db)
    if src is None:
        return []
    dev = {d.id: d for d in devices}
    active_dev = {d.id for d in devices if d.status == "active"}
    recent_dev = {d.id for d in devices if d.status == "active" and d.last_seen_at and now - d.last_seen_at <= ACTIVE_WINDOW}
    out: list[_F] = []
    matched_devices: set[str] = set()
    ambiguous_devices: set[str] = set()
    intune_devices: set[str] = set()
    covered_domains = {(s.config or {}).get("domain", "").lower() for s in db.scalars(
        select(DirectorySource).where(DirectorySource.type == "ad"))}
    rows = db.execute(select(DirectoryComputer.id, DirectoryComputer.source_id, DirectoryComputer.machine_id,
                             DirectoryComputer.device_kind, DirectoryComputer.name, DirectoryComputer.domain,
                             DirectoryComputer.ou, DirectoryComputer.operating_system, DirectoryComputer.enabled,
                             DirectoryComputer.last_logon_at, DirectoryComputer.when_created,
                             DirectoryComputer.agent_expected, DirectoryComputer.compliance,
                             DirectoryComputer.encrypted, DirectoryComputer.device_id, DirectoryComputer.match_status,
                             DirectoryComputer.match_candidates)
                      .where(DirectoryComputer.missing_since.is_(None))
                      .order_by(DirectoryComputer.source_id, DirectoryComputer.id)).all()
    machines: dict[str, list[Any]] = defaultdict(list)
    for r in rows:
        if r.device_kind == "ad":
            covered_domains.add(r.domain)
        if r.device_id:
            matched_devices.add(r.device_id)
            if r.device_kind == "intune":
                intune_devices.add(r.device_id)
        if r.match_status == "ambiguous":
            ambiguous_devices.update(r.match_candidates or [])
        machines[r.machine_id or r.id].append(r)
    covered_domains.discard("")

    def cutoff(r: Any) -> datetime:
        return now - timedelta(days=src.stale_days.get(r.source_id, 90))

    def recent(r: Any) -> bool:
        return r.last_logon_at is not None and r.last_logon_at >= cutoff(r)

    def stale(r: Any) -> bool:
        return not recent(r) and (r.last_logon_at is not None or r.when_created is None
                                  or r.when_created < cutoff(r))

    for machine_id, members in machines.items():
        rep = next((m for m in members if m.id == machine_id), members[0])
        ad_only = all(m.device_kind == "ad" for m in members)
        enabled = [m for m in members if m.enabled]
        active = [m for m in enabled if recent(m)]
        last = max((m.last_logon_at for m in members if m.last_logon_at), default=None)
        base = {"kind": "computer", "source_id": rep.source_id, "computer_id": rep.id, "name": rep.name,
                "domain": rep.domain, "ou": rep.ou,
                "os": rep.operating_system or next((m.operating_system for m in members if m.operating_system), ""),
                "last_logon_at": last, "enabled": bool(enabled)}
        device_id = rep.device_id
        if any(m.agent_expected for m in active) and (device_id is None or device_id not in active_dev):
            if ad_only:
                detail = "Signs in to the domain but has no agent"
            else:
                detail = f"Active in {_labels([m.device_kind for m in active])} but has no agent"
            if rep.match_status == "ambiguous":
                detail += f": {len(rep.match_candidates or [])} agent devices could be this computer (check names)"
            out.append(_F("not_managed", **base, detail=detail))
        if enabled and not active and all(stale(m) for m in enabled):
            days = src.stale_days.get(rep.source_id, 90)
            if ad_only:
                detail = f"No domain logon for {days}+ days (last {_fmt(last)})"
            else:
                detail = f"No activity in {_labels([m.device_kind for m in enabled])} for {days}+ days (last {_fmt(last)})"
            out.append(_F("stale_computer", **base, detail=detail))
        disabled = [m for m in members if not m.enabled]
        if disabled and device_id and device_id in recent_dev:
            d = dev[device_id]
            where = "the directory" if ad_only else _labels([m.device_kind for m in disabled])
            out.append(_F("disabled_but_active", **{**base, "enabled": False, "device_id": device_id},
                          detail=f"Disabled in {where}, but its agent checked in {_fmt(d.last_seen_at)}"))
        noncompliant = [m for m in members if m.device_kind == "intune" and (m.compliance or "").lower() == "noncompliant"]
        if noncompliant:
            m = noncompliant[0]
            extra = " · not encrypted" if m.encrypted is False else ""
            out.append(_F("non_compliant", **{**base, "computer_id": m.id, "source_id": m.source_id, "name": m.name,
                                               "os": m.operating_system or base["os"], "device_id": device_id},
                          detail=f"Intune reports it non-compliant (last check-in {_fmt(m.last_logon_at)}){extra}"))
    if src.synced:
        has_ad = bool(covered_domains) or "ad" in src.types.values()
        for d in devices:
            if d.id not in active_dev:
                continue
            j = _join(d)
            tenant = (j.get("entra_tenant_id") or "").lower()
            entra_id = (d.entra_device_id or j.get("entra_device_id") or "").lower()
            common = {"kind": "device", "source_id": None, "device_id": d.id, "name": d.hostname or "",
                      "domain": (d.ad_domain or "").lower(), "os": d.os_family or "", "last_logon_at": d.last_seen_at}
            # Intune manages this OS in the device's (synced) tenant, but has no record of it.
            if (d.os_family in INTUNE_OS and tenant and tenant in src.intune_tenants and d.id not in intune_devices
                    and d.id not in ambiguous_devices):
                out.append(_F("not_in_intune", **common,
                              detail=f"Joined to Entra tenant {tenant}, where Intune is in use, but Intune has no "
                                     "record of it"))
            if d.id in matched_devices:
                continue
            reports_join = "directory_collector" in (d.agent_features or "").split(",")
            dom = (d.ad_domain or "").lower()
            if dom and dom in covered_domains:
                why = ("several directory computers could be this device" if d.id in ambiguous_devices
                       else "joined to a synced domain, but no directory computer matches it")
                out.append(_F("unknown_to_directory", **common, detail=f"Agent device {why}"))
            elif entra_id and tenant and tenant in src.entra_tenants:
                why = ("several directory records could be this device" if d.id in ambiguous_devices
                       else f"joined to Entra tenant {tenant}, but no Entra device matches it")
                out.append(_F("unknown_to_directory", **common, detail=f"Agent device {why}"))
            elif not dom and not entra_id and reports_join and has_ad:
                out.append(_F("not_domain_joined", **common, detail="The agent reports no Active Directory domain"))
            elif not dom and d.id in ambiguous_devices:
                out.append(_F("unknown_to_directory", **common,
                              detail="Several directory computers could be this device (agent older than 1.3.0 "
                                     "does not report its domain)"))
    out.extend(_user_findings(db, now, devices, recent_dev, src))
    out.extend(_privileged_findings(db, now, src, active_dev))
    return out


def netbios_map(devices: list[Any]) -> dict[str, str]:
    m: dict[str, str] = {}
    for d in devices:
        j = d.directory_join or {}
        if j.get("ad_netbios") and j.get("ad_domain"):
            m[j["ad_netbios"].lower()] = j["ad_domain"].lower()
    return m


_USER_COLS = (DirectoryUser.id, DirectoryUser.source_id, DirectoryUser.sam_key, DirectoryUser.user_principal_name,
              DirectoryUser.mail, DirectoryUser.domain, DirectoryUser.enabled, DirectoryUser.last_logon_at,
              DirectoryUser.display_name, DirectoryUser.department, DirectoryUser.title, DirectoryUser.ou,
              DirectoryUser.sam_account_name, DirectoryUser.object_sid)


def _user_index(db: Session, names: set[str], emails: set[str]) -> tuple[matching.UserIndex, dict[str, Any]]:
    rows: dict[str, Any] = {}
    for chunk in _chunks(sorted(names)):
        for r in db.execute(select(*_USER_COLS).where(DirectoryUser.sam_key.in_(chunk),
                                                      DirectoryUser.missing_since.is_(None))):
            rows[r.id] = r
    for chunk in _chunks(sorted(emails)):
        for r in db.execute(select(*_USER_COLS).where(
                (DirectoryUser.user_principal_name.in_(chunk)) | (DirectoryUser.mail.in_(chunk)),
                DirectoryUser.missing_since.is_(None))):
            rows[r.id] = r
    # The same person in AD and Entra ID (synced): bring in every record with the SID.
    sids = sorted({r.object_sid for r in rows.values() if r.object_sid})
    for chunk in _chunks(sids):
        for r in db.execute(select(*_USER_COLS).where(DirectoryUser.object_sid.in_(chunk),
                                                      DirectoryUser.missing_since.is_(None))):
            rows[r.id] = r
    idx = matching.UserIndex(matching.UserKey(id=r.id, sam=r.sam_key, upn=r.user_principal_name, mail=r.mail,
                                              domain=r.domain, person=r.object_sid or "") for r in rows.values())
    return idx, rows


def _logins(inv: dict | None) -> list[str]:
    users = (inv or {}).get("logged_in_users") or []
    return [u for u in users if isinstance(u, str) and u.strip()][:16] if isinstance(users, list) else []


def _user_findings(db: Session, now: datetime, devices: list[Any], recent_dev: set[str], src: _Sources) -> list[_F]:
    signed = [(d, raw) for d in devices if d.id in recent_dev for raw in _logins(d.inventory)]
    if not signed:
        return []
    names = {matching.parse_login(raw)[1] for _, raw in signed}
    emails = {n for n in names if "@" in n}
    idx, rows = _user_index(db, {n for n in names if "@" not in n}, emails)
    by_person: dict[str, list[Any]] = defaultdict(list)
    for r in rows.values():
        if r.object_sid:
            by_person[r.object_sid].append(r)
    nb = netbios_map(devices)
    out: list[_F] = []
    for d, raw in signed:
        j = d.directory_join or {}
        u = idx.resolve(raw, device_domain=d.ad_domain or "", device_netbios=j.get("ad_netbios", ""),
                        device_hostname=d.hostname or "", netbios_map=nb)
        if u is None:
            continue
        r = rows[u.id]
        # One person, several directories (AD + Entra ID): disabled in any of them
        # counts; last logon is the latest one known.
        people = by_person.get(r.object_sid, [r]) if r.object_sid else [r]
        disabled = next((p for p in people if not p.enabled), None)
        r = disabled or r
        base = {"kind": "user", "source_id": r.source_id, "user_id": r.id, "device_id": d.id,
                "name": r.sam_account_name or r.user_principal_name, "domain": r.domain, "ou": r.ou,
                "last_logon_at": r.last_logon_at, "enabled": r.enabled}
        if disabled is not None:
            out.append(_F("disabled_user_signed_in", **base,
                          detail=f"Disabled in the directory, but signed in on {d.hostname}"))
            continue
        known = [p for p in people if p.source_id in src.sign_in_known]
        if not known:
            continue  # last sign-in unknown (Entra ID without P1/P2): never "stale"
        last = max((p.last_logon_at for p in known if p.last_logon_at), default=None)
        days = max(src.stale_days.get(p.source_id, 90) for p in known)
        if last is None or last < now - timedelta(days=days):
            what = "domain logon" if all(src.types.get(p.source_id) == "ad" for p in known) else "sign-in"
            out.append(_F("stale_user_signed_in", **{**base, "last_logon_at": last},
                          detail=f"Signed in on {d.hostname}, but no {what} for {days}+ days (last {_fmt(last)})"))
    return out


ELIGIBLE_PREFIX = "Eligible: "  # graph.ELIGIBLE_PREFIX (PIM eligible, not active)


def _holds(roles: list[str]) -> str:
    """'holds Global Administrator; eligible (PIM) for Security Administrator'."""
    active = [r for r in roles if not r.startswith(ELIGIBLE_PREFIX)]
    eligible = [r.removeprefix(ELIGIBLE_PREFIX).replace(" (PIM, via group)", " (via group)").removesuffix(" (PIM)")
                for r in roles if r.startswith(ELIGIBLE_PREFIX)]
    parts = ([f"holds {', '.join(active)}"] if active else []) + (
        [f"is eligible (PIM) for {', '.join(eligible)}"] if eligible else [])
    return "; ".join(parts) or "holds a privileged role"


def _privileged_findings(db: Session, now: datetime, src: _Sources, active_dev: set[str]) -> list[_F]:
    """Privileged role holders: disabled but still assigned, stale, primary device without an agent."""
    users = db.execute(select(DirectoryUser.id, DirectoryUser.source_id, DirectoryUser.user_principal_name,
                              DirectoryUser.mail, DirectoryUser.sam_account_name, DirectoryUser.domain,
                              DirectoryUser.ou, DirectoryUser.enabled, DirectoryUser.last_logon_at,
                              DirectoryUser.when_created, DirectoryUser.privileged_roles)
                       .where(DirectoryUser.privileged.is_(True), DirectoryUser.missing_since.is_(None))).all()
    if not users:
        return []
    out: list[_F] = []
    emails = {e for u in users for e in (u.user_principal_name, u.mail) if e}
    devices: dict[str, list[Any]] = defaultdict(list)
    for chunk in _chunks(sorted(emails)):
        for c in db.execute(select(DirectoryComputer.id, DirectoryComputer.machine_id, DirectoryComputer.name,
                                   DirectoryComputer.primary_user, DirectoryComputer.device_id,
                                   DirectoryComputer.agent_expected, DirectoryComputer.enabled,
                                   DirectoryComputer.operating_system)
                            .where(DirectoryComputer.primary_user.in_(chunk), DirectoryComputer.missing_since.is_(None))):
            devices[c.primary_user].append(c)
    for u in users:
        holds = _holds(u.privileged_roles or [])
        holds_cap = holds[0].upper() + holds[1:]
        base = {"kind": "user", "source_id": u.source_id, "user_id": u.id,
                "name": u.user_principal_name or u.sam_account_name, "domain": u.domain, "ou": u.ou,
                "last_logon_at": u.last_logon_at, "enabled": u.enabled}
        if not u.enabled:
            out.append(_F("privileged_disabled", **base, detail=f"Disabled, but {holds}"))
            continue
        days = src.stale_days.get(u.source_id, 90)
        cutoff = now - timedelta(days=days)
        if u.source_id in src.sign_in_known and (
                (u.last_logon_at is not None and u.last_logon_at < cutoff)
                or (u.last_logon_at is None and (u.when_created is None or u.when_created < cutoff))):
            out.append(_F("privileged_stale", **base,
                          detail=f"{holds_cap}, but no sign-in for {days}+ days (last {_fmt(u.last_logon_at)})"))
        seen: set[str] = set()
        for c in devices.get(u.user_principal_name, []) + devices.get(u.mail, []):
            machine = c.machine_id or c.id
            if machine in seen or not c.enabled or not c.agent_expected:
                continue
            seen.add(machine)
            if c.device_id and c.device_id in active_dev:
                continue
            out.append(_F("privileged_no_agent", **{**base, "computer_id": machine},
                          detail=f"{holds_cap}; their primary device {c.name} "
                                 f"({c.operating_system or 'unknown OS'}) has no agent"))
    return out


def store_findings(db: Session, findings: list[_F], now: datetime) -> dict[str, int]:
    """Diff against the stored findings: insert new, update changed, delete
    resolved (first_seen_at survives). Returns counts per type."""
    new = {f.key: f for f in findings}
    existing = {r.key: r for r in db.execute(select(
        DirectoryFinding.id, DirectoryFinding.key, DirectoryFinding.type, DirectoryFinding.kind,
        DirectoryFinding.source_id, DirectoryFinding.computer_id, DirectoryFinding.user_id, DirectoryFinding.device_id,
        DirectoryFinding.name, DirectoryFinding.domain, DirectoryFinding.ou, DirectoryFinding.os,
        DirectoryFinding.last_logon_at, DirectoryFinding.enabled, DirectoryFinding.detail)).all()}
    gone = [r.id for k, r in existing.items() if k not in new]
    for chunk in _chunks(gone):
        db.execute(delete(DirectoryFinding).where(DirectoryFinding.id.in_(chunk))
                   .execution_options(synchronize_session=False))
    changed = []
    for k, f in new.items():
        r = existing.get(k)
        if r is None:
            db.add(DirectoryFinding(key=k, first_seen_at=now, last_evaluated_at=now, **f.values()))
        elif any(getattr(r, c) != v for c, v in f.values().items()):
            changed.append(r.id)
    vals = {existing[k].id: new[k].values() for k in new if k in existing}
    for chunk in _chunks(changed):
        for row in db.scalars(select(DirectoryFinding).where(DirectoryFinding.id.in_(chunk))):
            for c, v in vals[row.id].items():
                setattr(row, c, v)
            row.last_evaluated_at = now
    db.flush()
    counts = dict.fromkeys(FINDING_TYPES, 0)
    for f in findings:
        counts[f.type] += 1
    return counts


def reconcile(db: Session, now: datetime | None = None, *, notify: bool = False) -> dict[str, int]:
    """Match, evaluate and store findings for the session's organisation; with
    `notify`, raise "not managed changed" notifications. Commits."""
    from ..notifications import directory_source

    now = now or utcnow()
    devices = _device_rows(db)
    apply_matches(db, now, devices)
    findings = compute_findings(db, now, devices)
    counts = store_findings(db, findings, now)
    if notify:
        per_source: dict[str, int] = defaultdict(int)
        for f in findings:
            if f.type == "not_managed" and f.source_id:
                per_source[f.source_id] += 1
        for src in db.scalars(select(DirectorySource)):
            n = per_source.get(src.id, 0)
            if src.last_success_at is None or src.notified_not_managed == n:
                continue
            previous = src.notified_not_managed
            src.notified_not_managed = n
            if previous is not None or n > 0:
                directory_source.not_managed_changed(db, src, previous, n)
    db.commit()
    return counts


# ----------------------------------------------------------------------------- read helpers
def coverage(db: Session) -> dict[str, Any]:
    """Managed share of the physical machines the agent is expected on: enabled,
    present directory records grouped by machine, each machine counted once."""
    machine = func.coalesce(DirectoryComputer.machine_id, DirectoryComputer.id)
    where = (DirectoryComputer.enabled.is_(True), DirectoryComputer.missing_since.is_(None),
             DirectoryComputer.agent_expected.is_(True))
    total = db.scalar(select(func.count(func.distinct(machine))).where(*where)) or 0
    managed = db.scalar(select(func.count(func.distinct(machine)))
                        .join(Device, Device.id == DirectoryComputer.device_id)
                        .where(*where, Device.status == "active")) or 0
    # Split by device class (workstation / server / domain controller, from the
    # directory attributes); a machine whose records disagree counts in each class.
    totals = dict(db.execute(select(DirectoryComputer.device_class, func.count(func.distinct(machine)))
                             .where(*where).group_by(DirectoryComputer.device_class)).all())
    managed_by = dict(db.execute(select(DirectoryComputer.device_class, func.count(func.distinct(machine)))
                                 .join(Device, Device.id == DirectoryComputer.device_id)
                                 .where(*where, Device.status == "active").group_by(DirectoryComputer.device_class))
                      .all())
    by_class = {c or "unknown": {"directory_computers": n, "managed": managed_by.get(c, 0),
                                 "pct": round(managed_by.get(c, 0) * 100.0 / n, 1) if n else None}
                for c, n in totals.items()}
    return {"directory_computers": total, "managed": managed,
            "pct": round(managed * 100.0 / total, 1) if total else None, "by_class": by_class}


def in_source(source_id: str):
    """Findings of a source: its own, and those of machines one of its records belongs to."""
    machines = select(func.coalesce(DirectoryComputer.machine_id, DirectoryComputer.id)).where(
        DirectoryComputer.source_id == source_id)
    return or_(DirectoryFinding.source_id == source_id,
               and_(DirectoryFinding.kind == "computer", DirectoryFinding.computer_id.in_(machines)))


def finding_counts(db: Session, source_id: str | None = None) -> dict[str, int]:
    stmt = select(DirectoryFinding.type, func.count()).group_by(DirectoryFinding.type)
    if source_id:
        stmt = stmt.where(in_source(source_id))
    counts = dict.fromkeys(FINDING_TYPES, 0)
    counts.update({t: n for t, n in db.execute(stmt).all()})
    return counts


def owner_enrichment(db: Session, assets: list[Any], devices: dict[str, Device]) -> dict[str, dict[str, Any]]:
    """Directory identity of IT asset owners, for display only. The owner key
    stays the username / email (the agent-always-wins owner rule is unchanged)."""
    names: set[str] = set()
    emails: set[str] = set()
    for a in assets:
        if a.assignee_email:
            emails.add(a.assignee_email.lower())
        elif a.assignee_name:
            names.add(matching.parse_login(a.assignee_name)[1])
    if not names and not emails:
        return {}
    if not db.scalar(select(func.count()).select_from(DirectoryUser)):
        return {}
    idx, rows = _user_index(db, {n for n in names if "@" not in n}, emails | {n for n in names if "@" in n})
    if not rows:
        return {}
    out: dict[str, dict[str, Any]] = {}
    for a in assets:
        if a.assignee_email:
            u = idx.by_email(a.assignee_email)
        elif a.assignee_name:
            d = devices.get(a.device_id or "")
            j = (d.directory_join or {}) if d is not None else {}
            u = idx.resolve(a.assignee_name, device_domain=(d.ad_domain or "") if d is not None else "",
                            device_netbios=j.get("ad_netbios", ""))
        else:
            u = None
        if u is None:
            continue
        r = rows[u.id]
        out[a.id] = {"user_id": r.id, "display_name": r.display_name, "mail": r.mail or r.user_principal_name,
                     "department": r.department, "title": r.title, "enabled": r.enabled}
    return out
