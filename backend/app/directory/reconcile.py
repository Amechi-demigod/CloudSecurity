"""Apply matches and (re)evaluate discovery issues (docs/DIRECTORY_DISCOVERY.md#discovery-issues).

Runs after every sync that stored objects and periodically from the scheduler
(device check-ins change "disabled but active" and the signed-in users). Reads
only the columns it needs and writes only rows that changed, so it stays cheap
for directories with 100k+ objects.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..asset_lifecycle.models import ItAsset
from ..models import Device, utcnow
from . import matching
from .models import FINDING_TYPES, DirectoryComputer, DirectoryFinding, DirectorySource, DirectoryUser

log = logging.getLogger(__name__)

# An agent device that checked in this recently counts as "active".
ACTIVE_WINDOW = timedelta(days=7)
CHUNK = 500


def _chunks(seq: list, n: int = CHUNK):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def _device_rows(db: Session) -> list[Any]:
    return db.execute(select(Device.id, Device.hostname, Device.status, Device.last_seen_at, Device.ad_domain,
                             Device.ad_computer_sid, Device.directory_join, Device.serial_number,
                             Device.agent_features, Device.inventory, Device.os_family)).all()


# ----------------------------------------------------------------------------- matching
def apply_matches(db: Session, now: datetime | None = None, devices: list[Any] | None = None) -> int:
    """Run the matcher over current (not missing) computers and active devices and
    store the result on the computers. Returns the number of computers changed."""
    now = now or utcnow()
    devices = devices if devices is not None else _device_rows(db)
    dkeys = [matching.DeviceKey(id=d.id, hostname=d.hostname or "", ad_domain=d.ad_domain or "",
                                ad_computer_sid=d.ad_computer_sid or "",
                                ad_object_guid=(d.directory_join or {}).get("ad_object_guid", ""),
                                dns_hostname=(d.directory_join or {}).get("dns_hostname", ""),
                                serial=d.serial_number or "")
             for d in devices if d.status == "active"]
    rows = db.execute(select(DirectoryComputer.id, DirectoryComputer.external_id, DirectoryComputer.domain,
                             DirectoryComputer.short_name, DirectoryComputer.dns_hostname,
                             DirectoryComputer.object_sid, DirectoryComputer.serial_number,
                             DirectoryComputer.device_id, DirectoryComputer.it_asset_id,
                             DirectoryComputer.match_status, DirectoryComputer.match_method,
                             DirectoryComputer.match_confidence, DirectoryComputer.match_candidates)
                      .where(DirectoryComputer.missing_since.is_(None))).all()
    matches = matching.match_computers(
        [matching.ComputerKey(id=r.id, external_id=r.external_id, domain=r.domain, short_name=r.short_name,
                              dns_hostname=r.dns_hostname, object_sid=r.object_sid or "", serial=r.serial_number)
         for r in rows], dkeys)
    asset_by_device = dict(db.execute(select(ItAsset.device_id, ItAsset.id).where(ItAsset.device_id.is_not(None))).all())
    own_assets = {r.it_asset_id for r in rows if r.it_asset_id}
    unlinked_own = set()
    for chunk in _chunks(list(own_assets)):
        unlinked_own.update(db.scalars(select(ItAsset.id).where(ItAsset.id.in_(chunk), ItAsset.device_id.is_(None))))
    changes: dict[str, dict[str, Any]] = {}
    for r in rows:
        m = matches[r.id]
        asset = asset_by_device.get(m.device_id) if m.device_id else None
        if asset is None and r.it_asset_id in unlinked_own:
            asset = r.it_asset_id  # added from Discovery, no agent yet
        new = {"match_status": m.status, "device_id": m.device_id, "match_method": m.method,
               "match_confidence": m.confidence, "match_candidates": m.candidates, "it_asset_id": asset}
        old = {"match_status": r.match_status, "device_id": r.device_id, "match_method": r.match_method,
               "match_confidence": r.match_confidence, "match_candidates": list(r.match_candidates or []),
               "it_asset_id": r.it_asset_id}
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
        obj = self.computer_id or self.user_id or self.device_id
        return f"{self.type}:{obj}" + (f":{self.device_id}" if self.kind == "user" and self.device_id else "")

    def values(self) -> dict[str, Any]:
        return {"type": self.type, "kind": self.kind, "source_id": self.source_id, "computer_id": self.computer_id,
                "user_id": self.user_id, "device_id": self.device_id, "name": self.name[:256],
                "domain": self.domain[:255], "ou": self.ou, "os": self.os[:256], "last_logon_at": self.last_logon_at,
                "enabled": self.enabled, "detail": self.detail[:500]}


def _fmt(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d") if dt else "never"


def compute_findings(db: Session, now: datetime, devices: list[Any]) -> list[_F]:
    sources = {s.id: s for s in db.scalars(select(DirectorySource))}
    if not sources:
        return []
    stale_days = {sid: int((s.config or {}).get("stale_days") or 90) for sid, s in sources.items()}
    dev = {d.id: d for d in devices}
    active_dev = {d.id for d in devices if d.status == "active"}
    recent_dev = {d.id for d in devices if d.status == "active" and d.last_seen_at and now - d.last_seen_at <= ACTIVE_WINDOW}
    out: list[_F] = []
    matched_devices: set[str] = set()
    ambiguous_devices: set[str] = set()
    covered_domains = {(s.config or {}).get("domain", "").lower() for s in sources.values()}
    seen_ext: set[tuple[str, str]] = set()
    rows = db.execute(select(DirectoryComputer.id, DirectoryComputer.source_id, DirectoryComputer.external_id,
                             DirectoryComputer.name, DirectoryComputer.domain, DirectoryComputer.ou,
                             DirectoryComputer.operating_system, DirectoryComputer.enabled,
                             DirectoryComputer.last_logon_at, DirectoryComputer.when_created,
                             DirectoryComputer.device_id, DirectoryComputer.match_status,
                             DirectoryComputer.match_candidates)
                      .where(DirectoryComputer.missing_since.is_(None))
                      .order_by(DirectoryComputer.source_id, DirectoryComputer.id)).all()
    for r in rows:
        covered_domains.add(r.domain)
        if r.device_id:
            matched_devices.add(r.device_id)
        if r.match_status == "ambiguous":
            ambiguous_devices.update(r.match_candidates or [])
        # The same object synced by two sources is reported once.
        if (r.external_id, "c") in seen_ext:
            continue
        seen_ext.add((r.external_id, "c"))
        cutoff = now - timedelta(days=stale_days.get(r.source_id, 90))
        base = {"kind": "computer", "source_id": r.source_id, "computer_id": r.id, "name": r.name,
                "domain": r.domain, "ou": r.ou, "os": r.operating_system, "last_logon_at": r.last_logon_at,
                "enabled": r.enabled}
        recent = r.last_logon_at is not None and r.last_logon_at >= cutoff
        if r.enabled and recent and (r.device_id is None or r.device_id not in active_dev):
            detail = "Signs in to the domain but has no agent"
            if r.match_status == "ambiguous":
                detail += f": {len(r.match_candidates or [])} agent devices could be this computer (check names)"
            out.append(_F("not_managed", **base, detail=detail))
        if r.enabled and not recent and (r.last_logon_at is not None or r.when_created is None
                                         or r.when_created < cutoff):
            out.append(_F("stale_computer", **base,
                          detail=f"No domain logon for {stale_days.get(r.source_id, 90)}+ days "
                                 f"(last {_fmt(r.last_logon_at)})"))
        if not r.enabled and r.device_id and r.device_id in recent_dev:
            d = dev[r.device_id]
            out.append(_F("disabled_but_active", **{**base, "device_id": r.device_id},
                          detail=f"Disabled in the directory, but its agent checked in {_fmt(d.last_seen_at)}"))
    synced = any(s.last_success_at for s in sources.values())
    if synced:
        for d in devices:
            if d.id not in active_dev or d.id in matched_devices:
                continue
            reports_join = "directory_collector" in (d.agent_features or "").split(",")
            dom = (d.ad_domain or "").lower()
            common = {"kind": "device", "source_id": None, "device_id": d.id, "name": d.hostname or "",
                      "domain": dom, "os": d.os_family or "", "last_logon_at": d.last_seen_at}
            if dom and dom in covered_domains:
                why = ("several directory computers could be this device" if d.id in ambiguous_devices
                       else "joined to a synced domain, but no directory computer matches it")
                out.append(_F("unknown_to_directory", **common, detail=f"Agent device {why}"))
            elif not dom and reports_join:
                out.append(_F("not_domain_joined", **common, detail="The agent reports no Active Directory domain"))
            elif not dom and d.id in ambiguous_devices:
                out.append(_F("unknown_to_directory", **common,
                              detail="Several directory computers could be this device (agent older than 1.3.0 "
                                     "does not report its domain)"))
    out.extend(_user_findings(db, now, devices, recent_dev, stale_days))
    return out


def netbios_map(devices: list[Any]) -> dict[str, str]:
    m: dict[str, str] = {}
    for d in devices:
        j = d.directory_join or {}
        if j.get("ad_netbios") and j.get("ad_domain"):
            m[j["ad_netbios"].lower()] = j["ad_domain"].lower()
    return m


def _user_index(db: Session, names: set[str], emails: set[str]) -> tuple[matching.UserIndex, dict[str, Any]]:
    rows: dict[str, Any] = {}
    cols = (DirectoryUser.id, DirectoryUser.source_id, DirectoryUser.sam_key, DirectoryUser.user_principal_name,
            DirectoryUser.mail, DirectoryUser.domain, DirectoryUser.enabled, DirectoryUser.last_logon_at,
            DirectoryUser.display_name, DirectoryUser.department, DirectoryUser.title, DirectoryUser.ou,
            DirectoryUser.sam_account_name)
    for chunk in _chunks(sorted(names)):
        for r in db.execute(select(*cols).where(DirectoryUser.sam_key.in_(chunk),
                                                DirectoryUser.missing_since.is_(None))):
            rows[r.id] = r
    for chunk in _chunks(sorted(emails)):
        for r in db.execute(select(*cols).where(
                (DirectoryUser.user_principal_name.in_(chunk)) | (DirectoryUser.mail.in_(chunk)),
                DirectoryUser.missing_since.is_(None))):
            rows[r.id] = r
    idx = matching.UserIndex(matching.UserKey(id=r.id, sam=r.sam_key, upn=r.user_principal_name, mail=r.mail,
                                              domain=r.domain) for r in rows.values())
    return idx, rows


def _logins(inv: dict | None) -> list[str]:
    users = (inv or {}).get("logged_in_users") or []
    return [u for u in users if isinstance(u, str) and u.strip()][:16] if isinstance(users, list) else []


def _user_findings(db: Session, now: datetime, devices: list[Any], recent_dev: set[str],
                   stale_days: dict[str, int]) -> list[_F]:
    signed = [(d, raw) for d in devices if d.id in recent_dev for raw in _logins(d.inventory)]
    if not signed:
        return []
    names = {matching.parse_login(raw)[1] for _, raw in signed}
    emails = {n for n in names if "@" in n}
    idx, rows = _user_index(db, {n for n in names if "@" not in n}, emails)
    nb = netbios_map(devices)
    out: list[_F] = []
    for d, raw in signed:
        j = d.directory_join or {}
        u = idx.resolve(raw, device_domain=d.ad_domain or "", device_netbios=j.get("ad_netbios", ""),
                        device_hostname=d.hostname or "", netbios_map=nb)
        if u is None:
            continue
        r = rows[u.id]
        base = {"kind": "user", "source_id": r.source_id, "user_id": r.id, "device_id": d.id,
                "name": r.sam_account_name or r.user_principal_name, "domain": r.domain, "ou": r.ou,
                "last_logon_at": r.last_logon_at, "enabled": r.enabled}
        if not r.enabled:
            out.append(_F("disabled_user_signed_in", **base,
                          detail=f"Disabled in the directory, but signed in on {d.hostname}"))
        else:
            days = stale_days.get(r.source_id, 90)
            if r.last_logon_at is None or r.last_logon_at < now - timedelta(days=days):
                out.append(_F("stale_user_signed_in", **base,
                              detail=f"Signed in on {d.hostname}, but no domain logon for {days}+ days "
                                     f"(last {_fmt(r.last_logon_at)})"))
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
    """Managed share of enabled, present directory computers (distinct objects)."""
    total = db.scalar(select(func.count(func.distinct(DirectoryComputer.external_id))).where(
        DirectoryComputer.enabled.is_(True), DirectoryComputer.missing_since.is_(None))) or 0
    managed = db.scalar(select(func.count(func.distinct(DirectoryComputer.external_id)))
                        .join(Device, Device.id == DirectoryComputer.device_id)
                        .where(DirectoryComputer.enabled.is_(True), DirectoryComputer.missing_since.is_(None),
                               Device.status == "active")) or 0
    return {"directory_computers": total, "managed": managed,
            "pct": round(managed * 100.0 / total, 1) if total else None}


def finding_counts(db: Session, source_id: str | None = None) -> dict[str, int]:
    stmt = select(DirectoryFinding.type, func.count()).group_by(DirectoryFinding.type)
    if source_id:
        stmt = stmt.where(DirectoryFinding.source_id == source_id)
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
