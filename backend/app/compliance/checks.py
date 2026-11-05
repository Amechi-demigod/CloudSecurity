"""Automated checks that provide compliance evidence, and their evaluation.

A check id names one of the platform's existing checks:

* ``cloud:<rule id>``: a cloud posture rule (app/engine/posture*.py). Fails
  while the rule has an open finding; no data when the scope has no resource
  of the rule's type.
* ``endpoint:<check>``: an endpoint agent posture check (disk encryption,
  firewall, ...; app/services/devices.py). Fails on devices that report the
  matching issue; no data when no active device reports the check.
* ``vuln:<kind>``: open known-exploited (CISA KEV) vulnerabilities, and
  critical / high vulnerabilities open longer than the dashboard SLA.
* ``directory:<issue type>``: a directory discovery issue
  (app/directory/reconcile.py); no data without a synced directory that can
  report it.
* ``inventory:<kind>``: cloud scans and directory syncs are current.

Evaluation answers, per check, pass / fail / no_data / out_of_scope (the
report's filter excludes that kind of check: a cloud account filter leaves
endpoint and directory checks out, a device group filter leaves cloud and
directory checks out), how many objects were evaluated and failed, and up to
`ITEMS` failing objects with links into the console.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import cache
from typing import Any
from urllib.parse import quote

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..directory.models import FINDING_TYPES, DirectoryFinding, DirectorySource
from ..engine import posture
from ..models import Asset, Device, Finding, ScanRun, Vulnerability, utcnow
from ..services import dashboards
from ..services import devices as device_svc

ITEMS = 25  # failing objects listed per check (the console links to the full list)
CLOUD_SCAN_MAX_AGE = timedelta(days=7)
DIRECTORY_SYNC_MAX_AGE = timedelta(days=3)

# endpoint check -> (posture check reported by the agent or None, device issue code, title)
ENDPOINT: dict[str, tuple[str | None, str, str]] = {
    "disk_encryption": ("disk_encryption", "disk_encryption_off", "Disk encryption on (BitLocker / FileVault)"),
    "firewall": ("firewall", "firewall_off", "Host firewall on"),
    "antivirus": ("antivirus", "antivirus_off", "Antivirus with real-time protection on"),
    "av_signatures": (None, "av_signatures_outdated", "Antivirus signatures up to date"),
    "os_updates": (None, "os_updates_pending", "OS updates installed within the grace period"),
    "screen_lock": ("screen_lock", "screen_lock_off", "Screen lock / password on wake"),
    "sip": ("sip", "sip_disabled", "System Integrity Protection on (macOS)"),
    "gatekeeper": ("gatekeeper", "gatekeeper_off", "Gatekeeper on (macOS)"),
    "secure_boot": ("secure_boot", "secure_boot_off", "Secure Boot on"),
    "checkin": (None, "inactive", "Devices checking in (none silent for over a week)"),
}
VULN = {"kev": "No open known-exploited (CISA KEV) vulnerabilities",
        "critical_sla": "Critical vulnerabilities fixed within the SLA",
        "high_sla": "High vulnerabilities fixed within the SLA"}
DIRECTORY_TITLES = {
    "not_managed": "Directory machines have an agent", "stale_computer": "No stale computer accounts",
    "disabled_but_active": "No disabled computers still in use",
    "unknown_to_directory": "Agent devices known to the directory",
    "not_domain_joined": "Agent devices joined to a domain / Entra ID",
    "non_compliant": "Devices compliant in Intune", "not_in_intune": "Devices enrolled in Intune",
    "disabled_user_signed_in": "No disabled users signed in on devices",
    "stale_user_signed_in": "No stale users signed in on devices",
    "privileged_disabled": "No disabled accounts holding admin roles",
    "privileged_stale": "No stale privileged admins",
    "privileged_no_agent": "Privileged admins' devices have an agent",
}
# Directory source types that can report each issue type (else: no data).
DIRECTORY_SOURCES: dict[str, tuple[str, ...]] = {
    "not_domain_joined": ("ad",), "non_compliant": ("entra",), "not_in_intune": ("entra",),
    "privileged_disabled": ("entra", "google"), "privileged_stale": ("entra", "google"),
    "privileged_no_agent": ("entra", "google"),
}
INVENTORY = {"cloud_scan": "Cloud accounts scanned within 7 days",
             "directory_sync": "Directories synced within 3 days"}
KINDS = ("cloud", "endpoint", "vuln", "directory", "inventory")


@dataclass(frozen=True)
class CheckDef:
    id: str
    kind: str
    title: str
    rule: posture.PostureRule | None = None


@cache
def registry() -> dict[str, CheckDef]:
    out: dict[str, CheckDef] = {}
    for r in posture.RULES:
        out[f"cloud:{r.id}"] = CheckDef(f"cloud:{r.id}", "cloud", r.title, r)
    for k, (_, _, title) in ENDPOINT.items():
        out[f"endpoint:{k}"] = CheckDef(f"endpoint:{k}", "endpoint", title)
    for k, title in VULN.items():
        out[f"vuln:{k}"] = CheckDef(f"vuln:{k}", "vuln", title)
    for t in FINDING_TYPES:
        out[f"directory:{t}"] = CheckDef(f"directory:{t}", "directory", DIRECTORY_TITLES[t])
    for k, title in INVENTORY.items():
        out[f"inventory:{k}"] = CheckDef(f"inventory:{k}", "inventory", title)
    return out


@dataclass(frozen=True)
class Scope:
    """What a report covers: the whole organisation, one cloud account, or one device group."""

    account: str | None = None
    device_group: str | None = None

    @property
    def key(self) -> str:
        if self.account:
            return f"account:{self.account}"
        if self.device_group:
            return f"group:{self.device_group}"
        return ""

    def includes(self, check_id: str) -> bool:
        kind = check_id.split(":", 1)[0]
        if self.account:
            return kind in ("cloud", "vuln") or check_id == "inventory:cloud_scan"
        if self.device_group:
            return kind in ("endpoint", "vuln")
        return True

    def label(self) -> str:
        if self.account:
            return f"cloud account {self.account}"
        if self.device_group:
            return f"device group {self.device_group}"
        return "whole organisation"


@dataclass
class Result:
    id: str
    kind: str
    title: str
    status: str  # pass | fail | no_data | out_of_scope
    failing: int = 0
    total: int | None = None
    detail: str = ""
    link: str | None = None
    items: list[dict[str, Any]] = field(default_factory=list)

    def out(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "title": self.title, "status": self.status,
                "failing": self.failing, "total": self.total, "detail": self.detail, "link": self.link,
                "items": self.items}


def _account_assets(account: str):
    return select(Asset.id).where(Asset.subscription_id == account)


# ----------------------------------------------------------------------------- cloud
def _cloud(db: Session, ids: list[str], scope: Scope) -> dict[str, Result]:
    reg = registry()
    type_stmt = select(Asset.type, func.count()).group_by(Asset.type)
    find_stmt = (select(Finding.rule_id, func.count(func.distinct(Finding.asset_id)))
                 .where(Finding.status == "open").group_by(Finding.rule_id))
    if scope.account:
        type_stmt = type_stmt.where(Asset.subscription_id == scope.account)
        find_stmt = find_stmt.where(Finding.asset_id.in_(_account_assets(scope.account)))
    types = dict(db.execute(type_stmt).all())
    failing = dict(db.execute(find_stmt).all())
    out: dict[str, Result] = {}
    for cid in ids:
        rule = reg[cid].rule
        assert rule is not None
        total = int(types.get(rule.resource_type, 0))
        n = int(failing.get(rule.id, 0))
        link = f"/findings?rule={quote(rule.id)}" + (f"&subscription={quote(scope.account)}" if scope.account else "")
        if n:
            status = "fail"
        elif total:
            status = "pass"
        else:
            status = "no_data"
        r = Result(cid, "cloud", rule.title, status, failing=n, total=max(total, n), link=link,
                   detail="" if total or n else f"no {rule.resource_type.replace('_', ' ')} in scope")
        if n:
            stmt = (select(Finding.id, Finding.asset_id, Asset.name, Finding.severity, Finding.first_seen)
                    .join(Asset, (Asset.id == Finding.asset_id) & (Asset.organization_id == Finding.organization_id))
                    .where(Finding.rule_id == rule.id, Finding.status == "open"))
            if scope.account:
                stmt = stmt.where(Asset.subscription_id == scope.account)
            for fid, _aid, name, sev, first in db.execute(stmt.order_by(Asset.name, Finding.id).limit(ITEMS)):
                r.items.append({"label": name, "detail": sev, "since": first, "link": f"/findings?finding={fid}"})
        out[cid] = r
    return out


# ----------------------------------------------------------------------------- endpoints
def _endpoint(db: Session, ids: list[str], scope: Scope, now: datetime) -> dict[str, Result]:
    stmt = select(Device).where(Device.status == "active")
    if scope.device_group:
        stmt = stmt.where(Device.device_group == scope.device_group)
    devices = list(db.scalars(stmt.order_by(Device.hostname)))
    issues = {d.id: {i["code"]: i for i in device_svc.device_issues(d, now)} for d in devices}
    out: dict[str, Result] = {}
    for cid in ids:
        key = cid.split(":", 1)[1]
        check, code, title = ENDPOINT[key]
        applicable = []
        for d in devices:
            p = d.posture or {}
            if check is not None:
                ok = device_svc._check(p, check)[0] in ("pass", "fail")
            elif key == "av_signatures":
                age = device_svc._check(p, "antivirus")[1].get("signature_age_days")
                ok = isinstance(age, int | float)
            elif key == "os_updates":
                ok = d.last_checkin_at is not None
            else:
                ok = True
            if ok:
                applicable.append(d)
        bad = [d for d in applicable if code in issues[d.id]]
        status = "fail" if bad else "pass" if applicable else "no_data"
        link = f"/devices?issue={code}"
        r = Result(cid, "endpoint", title, status, failing=len(bad), total=len(applicable), link=link,
                   detail="" if applicable else "no active device reports this check")
        for d in bad[:ITEMS]:
            r.items.append({"label": d.hostname, "detail": issues[d.id][code].get("detail") or "",
                            "link": f"/devices/{d.id}"})
        out[cid] = r
    return out


# ----------------------------------------------------------------------------- vulnerabilities
def _vuln(db: Session, ids: list[str], scope: Scope, now: datetime) -> dict[str, Result]:
    base = select(Vulnerability)
    if scope.account:
        base = base.where(Vulnerability.asset_id.in_(_account_assets(scope.account)))
    elif scope.device_group:
        base = base.where(Vulnerability.device_id.in_(
            select(Device.id).where(Device.device_group == scope.device_group, Device.status == "active")))
    any_rows = db.scalar(select(func.count()).select_from(base.subquery())) or 0
    dev_stmt = select(func.count()).select_from(Device).where(Device.status == "active")
    if scope.device_group:
        dev_stmt = dev_stmt.where(Device.device_group == scope.device_group)
    devices = 0 if scope.account else (db.scalar(dev_stmt) or 0)
    open_ = base.where(Vulnerability.status == "open")
    total_open = db.scalar(select(func.count()).select_from(open_.subquery())) or 0
    sla = dashboards.sla_days()
    out: dict[str, Result] = {}
    for cid in ids:
        key = cid.split(":", 1)[1]
        if key == "kev":
            stmt, link = open_.where(Vulnerability.kev.is_(True)), "/vulnerabilities?kev=1"
        else:
            sev = "critical" if key == "critical_sla" else "high"
            stmt = open_.where(Vulnerability.severity == sev,
                               Vulnerability.first_seen < now - timedelta(days=sla[sev]))
            link = f"/vulnerabilities?severity={sev}"
        n = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        status = "fail" if n else "pass" if (any_rows or devices) else "no_data"
        detail = ""
        if key != "kev":
            detail = f"SLA {sla['critical' if key == 'critical_sla' else 'high']:g} days"
        if status == "no_data":
            detail = "no vulnerability data in scope"
        r = Result(cid, "vuln", VULN[key], status, failing=n, total=total_open, link=link, detail=detail)
        if n:
            rows = list(db.scalars(stmt.order_by(Vulnerability.risk_score.desc(), Vulnerability.id).limit(ITEMS)))
            dev_ids = [v.device_id for v in rows if v.device_id]
            names = dict(db.execute(select(Device.id, Device.hostname).where(Device.id.in_(dev_ids))).all()) \
                if dev_ids else {}
            for v in rows:
                where = names.get(v.device_id or "", "") if v.device_id else (v.asset.name if v.asset else "")
                r.items.append({"label": f"{v.cve_id} {v.package} {v.version}".strip(), "detail": where,
                                "since": v.first_seen,
                                "link": f"/devices/{v.device_id}" if v.device_id else "/vulnerabilities"})
        out[cid] = r
    return out


# ----------------------------------------------------------------------------- directory
def _synced_source_types(db: Session) -> set[str]:
    return set(db.scalars(select(DirectorySource.type).where(DirectorySource.enabled.is_(True),
                                                            DirectorySource.last_success_at.is_not(None))))


def _directory(db: Session, ids: list[str]) -> dict[str, Result]:
    types = _synced_source_types(db)
    counts = Counter(dict(db.execute(select(DirectoryFinding.type, func.count()).group_by(DirectoryFinding.type))
                          .all()))
    out: dict[str, Result] = {}
    for cid in ids:
        t = cid.split(":", 1)[1]
        able = types & set(DIRECTORY_SOURCES.get(t, ("ad", "entra", "google")))
        n = int(counts.get(t, 0))
        status = "fail" if n else "pass" if able else "no_data"
        r = Result(cid, "directory", DIRECTORY_TITLES[t], status, failing=n, link=f"/it-assets/discovery?type={t}",
                   detail="" if able or n else "no synced directory reports this")
        if n:
            for f in db.scalars(select(DirectoryFinding).where(DirectoryFinding.type == t)
                                .order_by(DirectoryFinding.name, DirectoryFinding.id).limit(ITEMS)):
                r.items.append({"label": f.name, "detail": f.detail, "since": f.first_seen,
                                "link": f"/it-assets/discovery?type={t}"})
        out[cid] = r
    return out


# ----------------------------------------------------------------------------- inventory
def _inventory(db: Session, ids: list[str], scope: Scope, now: datetime) -> dict[str, Result]:
    out: dict[str, Result] = {}
    for cid in ids:
        key = cid.split(":", 1)[1]
        if key == "cloud_scan":
            if scope.account:
                last = db.scalar(select(func.max(Asset.last_seen)).where(Asset.subscription_id == scope.account))
                ran = last is not None
            else:
                ran = (db.scalar(select(func.count()).select_from(ScanRun)) or 0) > 0
                last = db.scalar(select(func.max(ScanRun.finished_at)).where(ScanRun.status == "succeeded"))
            if not ran:
                status, detail = "no_data", "no cloud scan yet"
            elif last is None or now - last > CLOUD_SCAN_MAX_AGE:
                status = "fail"
                detail = f"last successful scan {last:%Y-%m-%d}" if last else "no successful scan"
            else:
                status, detail = "pass", f"last successful scan {last:%Y-%m-%d %H:%M} UTC"
            out[cid] = Result(cid, "inventory", INVENTORY[key], status, failing=int(status == "fail"), total=1,
                              detail=detail, link="/connectors")
        else:
            sources = list(db.scalars(select(DirectorySource).where(DirectorySource.enabled.is_(True))))
            stale = [s for s in sources if s.last_success_at is None or now - s.last_success_at > DIRECTORY_SYNC_MAX_AGE]
            status = "no_data" if not sources else "fail" if stale else "pass"
            r = Result(cid, "inventory", INVENTORY[key], status, failing=len(stale), total=len(sources),
                       detail="no directory connected" if not sources else "", link="/connectors#directories")
            for s in stale[:ITEMS]:
                r.items.append({"label": s.name, "detail": f"last successful sync {s.last_success_at:%Y-%m-%d}"
                                if s.last_success_at else "never synced successfully",
                                "link": "/connectors#directories"})
            out[cid] = r
    return out


def evaluate(db: Session, ids: list[str] | set[str], scope: Scope = Scope(),
             now: datetime | None = None) -> dict[str, Result]:
    """Evaluate the given checks once each for the session's organisation."""
    now = now or utcnow()
    reg = registry()
    by_kind: dict[str, list[str]] = {}
    out: dict[str, Result] = {}
    for cid in sorted(set(ids)):
        if scope.includes(cid):
            by_kind.setdefault(reg[cid].kind, []).append(cid)
        else:
            out[cid] = Result(cid, reg[cid].kind, reg[cid].title, "out_of_scope",
                              detail=f"not assessed in a report for one {scope.label()}")
    for kind, kind_ids in by_kind.items():
        if kind == "cloud":
            out.update(_cloud(db, kind_ids, scope))
        elif kind == "endpoint":
            out.update(_endpoint(db, kind_ids, scope, now))
        elif kind == "vuln":
            out.update(_vuln(db, kind_ids, scope, now))
        elif kind == "directory":
            out.update(_directory(db, kind_ids))
        else:
            out.update(_inventory(db, kind_ids, scope, now))
    return out
