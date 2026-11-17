"""Attack surface & pre-ASV: targets and ownership proof, scan lifecycle, findings, disputes and the report data.
All functions work in the session's organisation (callers commit) unless stated otherwise."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import secrets
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import config, modules, tenancy
from .. import db as dbmod
from ..auth import audit
from ..locks import advisory_lock
from ..models import (
    Asset,
    ExternalDispute,
    ExternalFinding,
    ExternalHost,
    ExternalReport,
    ExternalScan,
    ExternalSettings,
    ExternalTarget,
    Organization,
    User,
    Vulnerability,
    new_id,
    utcnow,
)
from ..notifications import external_source
from ..services import vuln_sla
from . import catalog, cve, dnsclient, engine, guard, rules
from .net import Net

log = logging.getLogger(__name__)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
PROOF_PATH = "/.well-known/sentrigis-verification.txt"
MAX_CIDR_ADDRESSES = 256  # a /24
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
ENGINE_RUN = engine.run  # tests replace it
CVE_LOOKUP = cve.lookup  # tests replace it


class ExternalError(Exception):
    """A request the module refuses; `status` is the HTTP status to answer with."""

    def __init__(self, message: str, status: int = 422):
        super().__init__(message)
        self.status = status


# ----------------------------------------------------------------------------- settings
def get_settings(db: Session) -> ExternalSettings:
    oid = tenancy.require_org(db)
    row = db.get(ExternalSettings, oid)
    if row is None:
        row = ExternalSettings(organization_id=oid)
        db.add(row)
        db.flush()
    return row


def set_scope(db: Session, text: str, confirm: bool, actor: User, ip: str | None) -> ExternalSettings:
    row = get_settings(db)
    text = text.strip()
    if confirm and len(text) < 10:
        raise ExternalError("describe the in-scope internet-facing systems before confirming")
    changed = text != (row.scope_text or "")
    row.scope_text = text
    if confirm:
        row.scope_confirmed_by, row.scope_confirmed_at = actor.email, utcnow()
    elif changed:
        row.scope_confirmed_by = row.scope_confirmed_at = None  # an edited declaration must be confirmed again
    row.updated_at = utcnow()
    audit(db, "external_scope_confirmed" if confirm else "external_scope_updated", actor=actor,
          target="external:scope", ip=ip, length=len(text))
    return row


def set_schedule(db: Session, enabled: bool | None, interval_hours: float | None, actor: User, ip: str | None
                 ) -> ExternalSettings:
    row = get_settings(db)
    if enabled is not None:
        row.schedule_enabled = enabled
    if interval_hours is not None:
        if not 24 <= interval_hours <= 24 * 90:
            raise ExternalError("the interval must be between 24 hours and 90 days")
        row.interval_hours = float(interval_hours)
    row.updated_at = utcnow()
    audit(db, "external_schedule_updated", actor=actor, target="external:schedule", ip=ip,
          enabled=row.schedule_enabled, interval_hours=row.interval_hours)
    return row


# ----------------------------------------------------------------------------- targets
def parse_target(raw: str) -> tuple[str, str]:
    """(kind, normalised value) of a domain, public IPv4 address or CIDR of at most /24."""
    v = (raw or "").strip().lower().rstrip(".")
    if not v or len(v) > 255:
        raise ExternalError("enter a domain, an IPv4 address or a CIDR range")
    if "/" in v:
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ExternalError("not a valid CIDR range") from None
        if not isinstance(net, ipaddress.IPv4Network):
            raise ExternalError("only IPv4 is supported")
        if net.num_addresses > MAX_CIDR_ADDRESSES:
            raise ExternalError("ranges larger than a /24 (256 addresses) are not allowed: add smaller ranges")
        try:
            guard.check_ip(str(net.network_address))
            guard.check_ip(str(net.broadcast_address))
        except guard.BlockedAddress as e:
            raise ExternalError(f"{e}") from None
        if any(net.overlaps(b) for b in guard.BLOCKED_V4):
            raise ExternalError("the range overlaps a private, reserved or otherwise non-public address block")
        return ("ip", str(net.network_address)) if net.prefixlen == 32 else ("cidr", str(net))
    if guard.is_ip_literal(v):
        try:
            return "ip", guard.check_ip(v)
        except guard.BlockedAddress as e:
            raise ExternalError(str(e)) from None
    if ":" in v:
        raise ExternalError("only IPv4 is supported")
    if not DOMAIN_RE.match(v):
        raise ExternalError("not a valid domain name")
    return "domain", v


def list_targets(db: Session) -> list[ExternalTarget]:
    return list(db.scalars(select(ExternalTarget).order_by(ExternalTarget.created_at)))


def _verified_domains(db: Session) -> list[str]:
    return [t.value for t in list_targets(db) if t.kind == "domain" and t.verified_at]


def parent_verified(db: Session, name: str) -> str | None:
    for d in _verified_domains(db):
        if name == d or name.endswith("." + d):
            return d
    return None


def add_target(db: Session, raw: str, actor: User, ip: str | None) -> ExternalTarget:
    kind, value = parse_target(raw)
    if db.scalar(select(ExternalTarget).where(ExternalTarget.value == value)) is not None:
        raise ExternalError("this target is already added", 409)
    if (db.scalar(select(func.count()).select_from(ExternalTarget)) or 0) >= config.settings.external_max_targets:
        raise ExternalError(f"an organisation can have at most {config.settings.external_max_targets} targets", 409)
    t = ExternalTarget(kind=kind, value=value, token=secrets.token_hex(16), created_by=actor.email)
    db.add(t)
    if kind == "domain":
        parent = parent_verified(db, value)
        if parent:
            t.verified_method, t.verified_at, t.verified_detail = "parent", utcnow(), f"subdomain of verified {parent}"
    db.flush()
    audit(db, "external_target_added", actor=actor, target=f"external_target:{value}", ip=ip, kind=kind)
    return t


def remove_target(db: Session, t: ExternalTarget, actor: User, ip: str | None) -> None:
    audit(db, "external_target_removed", actor=actor, target=f"external_target:{t.value}", ip=ip)
    db.delete(t)


async def _http_proof(domain: str, token: str) -> bool:
    r = await Net(connect_timeout=5, read_timeout=6).http(domain, 443, tls=True, path=PROOF_PATH, max_body=512)
    return bool(r and r["status"] == 200 and token.encode() in r["body"])


def check_domain_proof(domain: str, token: str) -> tuple[str | None, str]:
    """(method, detail) when the ownership proof is found (DNS TXT first, then the well-known file), else
    (None, why not). DNS and HTTP go through the address guard."""
    want = f"sentrigis-verification={token}"
    for name in (domain, f"_sentrigis.{domain}"):
        try:
            if any(v.strip().strip('"') == want for v in dnsclient.query(name, "TXT")):
                return "dns", f"TXT record on {name}"
        except Exception:
            log.debug("TXT lookup failed for %s", name, exc_info=True)
    try:
        if asyncio.run(_http_proof(domain, token)):
            return "http", f"https://{domain}{PROOF_PATH}"
    except Exception:
        log.debug("HTTP proof failed for %s", domain, exc_info=True)
    return None, ("no TXT record sentrigis-verification=<token> on the domain or _sentrigis.<domain>, and no "
                  f"{PROOF_PATH} file containing the token, was found")


def verify_target(db: Session, t: ExternalTarget, actor: User, ip: str | None) -> dict[str, Any]:
    if t.kind != "domain":
        return {"verified": False, "error": "IP addresses and ranges are not verified here: they are scanned when a "
                "verified domain resolves to them, when they are public IPs of your cloud inventory, or after a "
                "platform owner approves them"}
    method, detail = check_domain_proof(t.value, t.token)
    t.last_check_at = utcnow()
    if method is None:
        t.last_check_error = detail[:255]
        audit(db, "external_target_verify_failed", actor=actor, target=f"external_target:{t.value}", ip=ip)
        return {"verified": False, "error": detail}
    t.verified_method, t.verified_at, t.verified_detail, t.last_check_error = method, utcnow(), detail, None
    for other in list_targets(db):  # subdomain targets are covered by this domain
        if other.kind == "domain" and not other.verified_at and other.value.endswith("." + t.value):
            other.verified_method, other.verified_at = "parent", utcnow()
            other.verified_detail = f"subdomain of verified {t.value}"
    audit(db, "external_target_verified", actor=actor, target=f"external_target:{t.value}", ip=ip, method=method)
    return {"verified": True, "method": method, "detail": detail}


def request_approval(db: Session, t: ExternalTarget, attestation: str, actor: User, ip: str | None) -> None:
    if t.kind == "domain":
        raise ExternalError("domains are verified with a DNS record or a file, not approved")
    attestation = attestation.strip()
    if len(attestation) < 20:
        raise ExternalError("state, in at least a sentence, that you own or are authorised to scan these addresses")
    if t.approval_status == "approved":
        raise ExternalError("already approved", 409)
    t.attested_by, t.attested_at, t.attestation = actor.email, utcnow(), attestation[:1000]
    t.approval_status, t.approval_note = "requested", None
    audit(db, "external_target_approval_requested", actor=actor, target=f"external_target:{t.value}", ip=ip)


def decide_approval(db: Session, t: ExternalTarget, approve: bool, note: str, admin: User, ip: str | None) -> None:
    """Platform owner (unscoped session). The audit entry goes to the customer's organisation."""
    if t.approval_status != "requested":
        raise ExternalError("there is no pending approval request for this target", 409)
    if not note.strip():
        raise ExternalError("a note is required")
    t.approval_status = "approved" if approve else "rejected"
    t.approval_note, t.approved_by, t.approved_at = note.strip()[:1000], admin.email, utcnow()
    if approve:
        t.verified_method, t.verified_at, t.verified_detail = "platform", utcnow(), "approved by a platform owner"
    audit(db, "external_target_approved" if approve else "external_target_rejected", actor=admin,
          target=f"external_target:{t.value}", ip=ip, organization_id=t.organization_id, note=note.strip()[:500],
          attested_by=t.attested_by)


def set_default_passwords(db: Session, t: ExternalTarget, enabled: bool, consent: bool, actor: User, ip: str | None
                          ) -> None:
    if enabled and not consent:
        raise ExternalError("explicit consent is required to enable default-password checks")
    t.default_password_checks = enabled
    t.consent_by, t.consent_at = (actor.email, utcnow()) if enabled else (None, None)
    audit(db, "external_default_passwords_enabled" if enabled else "external_default_passwords_disabled",
          actor=actor, target=f"external_target:{t.value}", ip=ip, consent=bool(enabled and consent))


def set_window(db: Session, t: ExternalTarget, start: int | None, end: int | None, actor: User, ip: str | None
               ) -> None:
    for h in (start, end):
        if h is not None and not 0 <= h <= 23:
            raise ExternalError("hours must be between 0 and 23 (UTC)")
    if (start is None) != (end is None):
        raise ExternalError("give both the start and the end hour, or neither")
    t.window_start_hour, t.window_end_hour = start, end
    audit(db, "external_target_window_updated", actor=actor, target=f"external_target:{t.value}", ip=ip,
          start=start, end=end)


def in_window(t: ExternalTarget, now: datetime) -> bool:
    s, e = t.window_start_hour, t.window_end_hour
    if s is None or e is None or s == e:
        return True
    h = now.hour
    return s <= h < e if s < e else (h >= s or h < e)


# ----------------------------------------------------------------------------- cloud inventory
def cloud_ip_map(db: Session) -> dict[str, str]:
    """Public IPv4 -> asset id of the organisation's cloud inventory (only when it has the cloud module)."""
    if not modules.has_module(db, modules.CLOUD):
        return {}
    out: dict[str, str] = {}
    for aid, props in db.execute(select(Asset.id, Asset.properties).where(Asset.removed_at.is_(None))):
        props = props or {}
        vals = list(props.get("public_ips") or []) + list(props.get("external_ips") or [])
        if props.get("public_ip"):
            p = props["public_ip"]
            vals.append(p.get("ip") if isinstance(p, dict) else p)
        for v in vals:
            if isinstance(v, str) and guard.is_ip_literal(v):
                out.setdefault(v, aid)
    return out


# ----------------------------------------------------------------------------- scans
class Busy(ExternalError):
    pass


def build_plan(db: Session, now: datetime, only_host: str | None = None) -> tuple[engine.Plan, list[dict]]:
    plan = engine.Plan(cloud_ips=set(cloud_ip_map(db)), max_hosts=config.settings.external_max_hosts_per_scan,
                       only_host=only_host)
    skipped: list[dict] = []
    for t in list_targets(db):
        if not in_window(t, now):
            skipped.append({"value": t.value, "reason": "outside the target's scan window"})
            continue
        if t.kind == "domain":
            if not t.verified_at:
                skipped.append({"value": t.value, "reason": "domain ownership is not verified"})
                continue
            if t.verified_method in ("dns", "http"):
                method, detail = check_domain_proof(t.value, t.token)
                t.last_check_at = now
                if method is None:
                    t.last_check_error = detail[:255]
                    skipped.append({"value": t.value, "reason": "the ownership proof is no longer found"})
                    continue
                t.last_check_error = None
            plan.domains.append(engine.DomainIn(t.id, t.value, t.default_password_checks))
        else:
            plan.ip_targets.append(engine.IpTargetIn(t.id, t.value, t.approval_status == "approved",
                                                     t.default_password_checks))
    return plan, skipped


def running_scans(db: Session) -> list[ExternalScan]:
    return list(db.scalars(select(ExternalScan).where(ExternalScan.status == "running")))


def recover_orphans(db: Session, now: datetime) -> int:
    """Scans left 'running' by a process that died (older than the maximum duration plus a grace period)."""
    limit = now - timedelta(seconds=config.settings.external_max_scan_seconds + 600)
    n = 0
    for s in db.scalars(select(ExternalScan).where(ExternalScan.status == "running", ExternalScan.started_at < limit)):
        s.status, s.finished_at, s.message = "failed", now, "The scan stopped unexpectedly."
        n += 1
    return n


def create_scan(db: Session, trigger: str, actor: User | None, ip: str | None = None, only_host: str | None = None,
                now: datetime | None = None) -> ExternalScan:
    """Create the scan record (status running) after checking limits; start it with `launch`. Raises Busy when a
    concurrency limit is reached and ExternalError when nothing can be scanned."""
    now = now or utcnow()
    s = config.settings
    org = tenancy.require_org(db)
    plan, skipped = build_plan(db, now, only_host)
    if not plan.domains and not plan.ip_targets:
        why = "; ".join(f"{x['value']}: {x['reason']}" for x in skipped[:5]) or "no targets yet"
        raise ExternalError(f"nothing can be scanned ({why})", 409)
    with advisory_lock("external_scan_start"):
        recover_orphans(db, now)
        mine = running_scans(db)
        if len(mine) >= s.external_max_scans_per_org:
            raise Busy("a scan of this organisation is already running", 409)
        with tenancy.unscoped(db):
            total = db.scalar(select(func.count()).select_from(ExternalScan).where(ExternalScan.status == "running"))
        if (total or 0) >= s.external_max_concurrent_scans:
            raise Busy("the scanner is busy with other scans; try again in a few minutes", 429)
        scan = ExternalScan(trigger=trigger, started_at=now, started_by=actor.email if actor else None,
                            scanner_ip=s.external_scanner_egress_ip or None, skipped=skipped,
                            targets=[t.value for t in list_targets(db)])
        db.add(scan)
        db.flush()
        audit(db, "external_scan_started", actor=actor, target=f"external_scan:{scan.id}", ip=ip, trigger=trigger,
              only_host=only_host, organization_id=org)
        db.commit()
    return scan


def _launch_thread(org_id: str, scan_id: str, only_host: str | None) -> None:
    def main() -> None:
        try:
            run_scan(org_id, scan_id, only_host)
        except Exception:
            log.exception("external scan %s crashed", scan_id)

    threading.Thread(target=main, name=f"external-scan-{scan_id[:6]}", daemon=True).start()


LAUNCHER = _launch_thread  # tests replace it to run scans inline


def launch(db: Session, scan: ExternalScan, only_host: str | None = None) -> None:
    LAUNCHER(tenancy.require_org(db), scan.id, only_host)


def run_scan(org_id: str, scan_id: str, only_host: str | None = None) -> None:
    with dbmod.get_session(org_id) as db:
        scan = db.get(ExternalScan, scan_id)
        if scan is None:
            return
        now = utcnow()
        try:
            plan, skipped = build_plan(db, now, only_host)
            db.commit()
            out = asyncio.run(ENGINE_RUN(plan))
            out.skipped = skipped + out.skipped
            persist(db, scan, out, only_host=only_host)
        except Exception as e:
            db.rollback()
            log.exception("external scan %s failed", scan_id)
            scan = db.get(ExternalScan, scan_id)
            scan.status, scan.finished_at = "failed", utcnow()
            scan.message = f"The scan failed: {type(e).__name__}"
        db.commit()


# ----------------------------------------------------------------------------- results
class _Safe(dict):
    def __missing__(self, key):  # unknown placeholders stay visible instead of failing
        return "{" + key + "}"


def _fmt(s: str, ctx: dict) -> str:
    return s.format_map(_Safe(ctx))


def _finding_fields(hit) -> dict[str, Any]:
    x = hit.extra
    ctx = {"host": hit.host, "port": hit.port or "", "url": hit.url or "", "path": x.get("path", hit.key or ""),
           "product": x.get("product", ""), "version": x.get("version", ""), "kind": x.get("kind", ""),
           "service": x.get("service", "")}
    if hit.check_id == "cve":
        label = cve.LABELS.get(x["product"], x["product"])
        cvss = float(x["cvss"])
        fixed = x.get("fixed_version")
        return {
            "title": f"{x['cve_id']}: {label} {x['version']}"[:255], "severity": catalog.severity_for(cvss),
            "cvss": cvss, "vector": x.get("vector"), "cwe": x.get("cwe"), "cve_id": x["cve_id"],
            "auto_fail": x.get("cwe") in rules.AUTO_FAIL_CWES, "dos_only": bool(x.get("dos_only")),
            "special_note": None,
            "detail": {
                "description": (x.get("description") or "") + "\n\nThe version comes from the service banner. "
                "Distribution packages often backport fixes without changing the version: if this is the case, "
                "dispute the finding as a false positive and describe the package version.",
                "impact": "An attacker may exploit this flaw against the exposed service; the impact depends on the "
                          "vulnerability (see the CVE record).",
                "steps": [f"Read the banner of {hit.host}:{hit.port}: {label} {x['version']}.",
                          f"Compare it with the affected range of {x['cve_id']} in the NVD."],
                "fix": {"General": f"Upgrade {label} to " + (f"{fixed} or later." if fixed else "the latest supported "
                        "release, or apply the vendor's security update.")},
                "references": [f"https://nvd.nist.gov/vuln/detail/{x['cve_id']}"],
                "compliance": catalog.TEMPLATES["cve"]["compliance"]}}
    tpl = catalog.template(hit.check_id)
    title = tpl["title"]
    path = ctx["path"]
    if hit.check_id == "file-exposed":
        title = f"{ctx['kind'] or 'Sensitive file'} downloadable: {path}"
    elif hit.check_id == "admin-panel":
        title = f"Administration interface exposed: {path}"
    elif hit.check_id == "api-docs":
        title = f"API documentation exposed: {path.split('?')[0]}"
    elif hit.check_id == "dir-listing":
        title = f"Directory listing enabled: {path}"
    elif hit.check_id == "default-credentials":
        title = f"Vendor default credentials accepted ({ctx['service']})"
    elif hit.check_id == "eol-software":
        title = f"End-of-life software: {cve.LABELS.get(ctx['product'], ctx['product'])} {ctx['version']}"
    elif hit.check_id.startswith("tls-") and hit.port:
        title = f"{title} on port {hit.port}"
    detail = {"description": _fmt(tpl["description"], ctx) + (f" {x['reason']}" if x.get("reason") else ""),
              "impact": tpl["impact"], "steps": [_fmt(s, ctx) for s in tpl["steps"]], "fix": tpl["fix"],
              "references": tpl["references"], "compliance": tpl["compliance"]}
    return {"title": title[:255], "severity": tpl["severity"], "cvss": tpl["cvss"], "vector": tpl["vector"],
            "cwe": tpl["cwe"], "cve_id": None, "auto_fail": tpl["auto_fail"], "dos_only": tpl["dos_only"],
            "special_note": tpl["special_note"], "detail": detail}


def _key(hit) -> str:
    return f"{hit.check_id}|{hit.host}|{hit.port or 0}|{hit.key or hit.extra.get('cve_id', '')}"[:400]


def _software_hits(db: Session, h: engine.HostOut, now: datetime, allow_fetch: bool) -> list:
    from .checks import Hit

    hits = []
    seen: set[tuple[str, str]] = set()
    for sw in h.software:
        pv = (sw["product"], sw["version"])
        port = sw.get("port")
        if pv in seen:
            continue
        seen.add(pv)
        why = cve.eol(*pv)
        if why:
            hits.append(Hit("eol-software", h.host, h.ip, port, evidence={"product": pv[0], "version": pv[1],
                                                                          "source": sw.get("source")},
                            extra={"product": pv[0], "version": pv[1], "reason": why}, key=pv[0]))
        try:
            found = CVE_LOOKUP(db, pv[0], pv[1], now, allow_fetch=allow_fetch)
        except Exception:
            log.exception("CVE lookup for %s %s failed", *pv)
            found = []
        for c in found:
            hits.append(Hit("cve", h.host, h.ip, port, evidence={"product": pv[0], "version": pv[1], "cve": c["cve_id"],
                                                                 "source": sw.get("source")},
                            extra={**c, "product": pv[0], "version": pv[1]}, key=c["cve_id"]))
    return hits


def _next_seq(db: Session) -> int:
    st = get_settings(db)
    n = st.next_finding_seq or 1
    st.next_finding_seq = n + 1
    return n


def persist(db: Session, scan: ExternalScan, out: engine.ScanOut, *, only_host: str | None = None,
            allow_fetch: bool = True) -> None:
    """Store hosts and findings of a finished scan, resolve findings no longer seen, evaluate the result."""
    now = utcnow()
    asset_by_ip = cloud_ip_map(db)
    existing_hosts = {h.host: h for h in db.scalars(select(ExternalHost))}
    new_hosts = open_ports = 0
    seen_hosts: set[str] = set()
    alive: set[str] = set()
    hits = []
    for h in out.hosts:
        seen_hosts.add(h.host)
        row = existing_hosts.get(h.host)
        if row is None:
            row = ExternalHost(host=h.host, first_seen=now)
            db.add(row)
            new_hosts += 1
        row.ip, row.target_id, row.dns, row.ports = h.ip, h.target_id, h.dns, h.ports
        row.tls, row.software, row.active = h.tls, h.software, True
        row.last_seen, row.last_scan_id = now, scan.id
        row.asset_id = asset_by_ip.get(h.ip or "") or None
        open_ports += len(h.ports)
        if h.ports:
            alive.add(h.host)
        hits.extend(h.hits)
        hits.extend(_software_hits(db, h, now, allow_fetch))
    if not only_host and not out.truncated:
        scanned_targets = {h.target_id for h in out.hosts}
        for name, row in existing_hosts.items():
            if name not in seen_hosts and row.target_id in scanned_targets:
                row.active = False
    # --- findings
    by_key: dict[str, Any] = {}
    for hit in hits:
        by_key.setdefault(_key(hit), hit)
    existing = {f.key: f for f in db.scalars(select(ExternalFinding))}
    new_findings: list[ExternalFinding] = []
    for key, hit in by_key.items():
        fields = _finding_fields(hit)
        f = existing.get(key)
        reopened = False
        if f is None:
            f = ExternalFinding(seq=_next_seq(db), key=key, check_id=hit.check_id, first_seen=now, status="open")
            db.add(f)
            new_findings.append(f)
        elif f.status == "resolved":
            f.status, f.resolved_at, reopened = "open", None, True
            new_findings.append(f)
        for k, v in fields.items():
            setattr(f, k, v)
        f.host, f.ip, f.port, f.url, f.evidence = hit.host, hit.ip, hit.port, hit.url, hit.evidence
        f.last_seen, f.last_scan_id = now, scan.id
        if reopened:
            f.status_note = "Re-opened: seen again by the scan."
    resolved = 0
    if not out.truncated:
        for key, f in existing.items():
            if key not in by_key and f.status != "resolved" and f.host in alive and (not only_host or f.host == only_host):
                f.status, f.resolved_at, f.last_scan_id = "resolved", now, scan.id
                f.status_note = "Resolved: no longer seen by the latest scan."
                resolved += 1
    db.flush()
    for f in new_findings:
        if f.severity in ("critical", "high"):
            external_source.finding_created(db, f)
    sync_vulnerabilities(db, out, by_key, now)
    # --- result
    open_findings = list(db.scalars(select(ExternalFinding).where(ExternalFinding.status != "resolved")))
    exempt = exempt_ids(db)
    failing = sum(1 for f in open_findings if rules.counts(f, f.id in exempt))
    scan.hosts, scan.open_ports, scan.new_hosts = len(out.hosts), open_ports, new_hosts
    scan.findings_open = len(open_findings)
    scan.skipped = out.skipped[:200]
    scan.result = rules.overall(failing)
    scan.finished_at = utcnow()
    scan.status = "partial" if (out.truncated or out.errors) else "succeeded"
    scan.message = "; ".join(out.errors[:5])[:1000] or (f"{resolved} finding(s) resolved." if resolved else "")


def sync_vulnerabilities(db: Session, out: engine.ScanOut, by_key: dict[str, Any], now: datetime) -> None:
    """CVE findings of hosts that are linked to a cloud asset are also listed in Vulnerabilities (source
    "external"), when the organisation has that module. Hosts without a linked asset are not shown there
    (a Vulnerability needs an asset, device or network device): follow-up."""
    if not modules.has_module(db, modules.VULNERABILITIES):
        return
    linked = {h.host: db.scalar(select(ExternalHost.asset_id).where(ExternalHost.host == h.host)) for h in out.hosts}
    wanted: dict[str, tuple[str, dict, Any]] = {}
    for hit in by_key.values():
        aid = linked.get(hit.host)
        if hit.check_id == "cve" and aid:
            wanted[f"ext:{hit.port}:{hit.extra['cve_id']}"] = (aid, hit.extra, hit)
    from ..engine.risk import priority_for, vuln_risk_score

    existing = {}
    for v in db.scalars(select(Vulnerability).where(Vulnerability.source == "external")):
        existing[(v.asset_id, v.match_key)] = v
    seen = set()
    for mk, (aid, x, hit) in wanted.items():
        v = existing.get((aid, mk))
        if v is None:
            v = Vulnerability(id=new_id(), asset_id=aid, source="external", match_key=mk, first_seen=now,
                              cve_id=x["cve_id"][:32])
            db.add(v)
        v.package, v.version = cve.LABELS.get(x["product"], x["product"])[:128], x["version"][:64]
        v.fixed_version = (x.get("fixed_version") or None) and x["fixed_version"][:64]
        v.title, v.cvss, v.severity = (x.get("description") or x["cve_id"])[:255], float(x["cvss"]), x["severity"]
        v.status, v.resolved_at, v.last_seen = "open", None, now
        v.internet_exposed, v.in_use = True, True  # reached from the internet by the external scan
        v.exploit_available = bool(v.exploit_available)
        asset = db.get(Asset, (tenancy.require_org(db), aid))
        v.sensitive_data_access = bool(asset.sensitive_data) if asset else False
        v.risk_score = vuln_risk_score(v.cvss, True, True, v.exploit_available, v.sensitive_data_access)
        v.priority = priority_for(v.risk_score)
        v.evidence = {"external": True, "host": hit.host, "port": hit.port, "url": hit.url}
        seen.add((aid, mk))
    for k, v in existing.items():
        if k not in seen and v.status == "open" and v.asset_id in linked.values():
            v.status, v.resolved_at = "resolved", now


# ----------------------------------------------------------------------------- findings and disputes
def exempt_ids(db: Session) -> set[str]:
    return set(db.scalars(select(ExternalDispute.finding_id).where(ExternalDispute.status == "accepted")))


def finding_ref(f: ExternalFinding) -> str:
    return f"EXT-{f.seq:04d}"


def fix_due(f: ExternalFinding, now: datetime | None = None) -> dict | None:
    if f.status == "resolved" or f.severity == "info":
        return None
    return vuln_sla.fix_due(f.first_seen, f.severity, now=now or utcnow())


def accept_risk(db: Session, f: ExternalFinding, reason: str, actor: User, ip: str | None) -> None:
    if not reason.strip():
        raise ExternalError("a reason is required")
    f.status, f.status_note, f.status_by = "accepted", reason.strip()[:1000], actor.email
    audit(db, "external_finding_risk_accepted", actor=actor, target=f"external_finding:{finding_ref(f)}", ip=ip,
          reason=reason.strip()[:500])


def reopen(db: Session, f: ExternalFinding, actor: User, ip: str | None) -> None:
    f.status, f.status_note, f.status_by = "open", None, actor.email
    f.resolved_at = None
    audit(db, "external_finding_reopened", actor=actor, target=f"external_finding:{finding_ref(f)}", ip=ip)


def submit_dispute(db: Session, f: ExternalFinding, kind: str, reason: str, actor: User, ip: str | None
                   ) -> ExternalDispute:
    if kind not in ("false_positive", "compensating_control"):
        raise ExternalError("kind must be false_positive or compensating_control")
    if len(reason.strip()) < 10:
        raise ExternalError("explain the dispute (at least a sentence)")
    if f.status == "resolved":
        raise ExternalError("a resolved finding cannot be disputed", 409)
    if db.scalar(select(ExternalDispute).where(ExternalDispute.finding_id == f.id, ExternalDispute.status == "pending")):
        raise ExternalError("this finding already has a dispute under review", 409)
    d = ExternalDispute(finding_id=f.id, kind=kind, reason=reason.strip()[:4000], submitted_by=actor.email)
    db.add(d)
    f.status = "disputed"
    db.flush()
    audit(db, "external_dispute_submitted", actor=actor, target=f"external_finding:{finding_ref(f)}", ip=ip,
          kind=kind, dispute_id=d.id)
    return d


def decide_dispute(db: Session, d: ExternalDispute, accept: bool, note: str, admin: User, ip: str | None) -> None:
    """Platform owner (unscoped session)."""
    if d.status != "pending":
        raise ExternalError("this dispute was already reviewed", 409)
    if not note.strip():
        raise ExternalError("a note is required")
    d.status = "accepted" if accept else "rejected"
    d.reviewed_by, d.reviewed_at, d.review_note = admin.email, utcnow(), note.strip()[:1000]
    f = db.get(ExternalFinding, d.finding_id)
    if f is not None and not accept and f.status == "disputed":
        f.status = "open"
    audit(db, "external_dispute_accepted" if accept else "external_dispute_rejected", actor=admin,
          target=f"external_finding:{finding_ref(f)}" if f else None, ip=ip, organization_id=d.organization_id,
          dispute_id=d.id, note=note.strip()[:500])


# ----------------------------------------------------------------------------- serializers
def finding_out(f: ExternalFinding, *, full: bool = False, disputes: list[ExternalDispute] | None = None,
                now: datetime | None = None) -> dict[str, Any]:
    due = fix_due(f, now)
    out = {"id": f.id, "ref": finding_ref(f), "check_id": f.check_id, "title": f.title, "severity": f.severity,
           "cvss": f.cvss, "vector": f.vector, "cwe": f.cwe, "cve_id": f.cve_id, "host": f.host, "ip": f.ip,
           "port": f.port, "url": f.url, "status": f.status, "first_seen": f.first_seen, "last_seen": f.last_seen,
           "resolved_at": f.resolved_at, "auto_fail": f.auto_fail or f.check_id in rules.AUTO_FAIL_CHECKS,
           "dos_only": f.dos_only, "fails": rules.fail_reason(f) is not None, "special_note": f.special_note,
           "fix_due": due["due_at"] if due else None, "overdue_days": due["overdue_days"] if due else None,
           "days_left": due["days_left"] if due else None}
    if full:
        out.update({"detail": f.detail, "evidence": f.evidence, "status_note": f.status_note, "status_by": f.status_by,
                    "fail_reason": rules.fail_reason(f),
                    "sla_basis": due["basis"] if due else None,
                    "disputes": [dispute_out(d) for d in disputes or []]})
    return out


def dispute_out(d: ExternalDispute, f: ExternalFinding | None = None) -> dict[str, Any]:
    out = {"id": d.id, "finding_id": d.finding_id, "kind": d.kind, "reason": d.reason, "submitted_by": d.submitted_by,
           "submitted_at": d.submitted_at, "status": d.status, "reviewed_by": d.reviewed_by,
           "reviewed_at": d.reviewed_at, "review_note": d.review_note}
    if f is not None:
        out.update({"ref": finding_ref(f), "title": f.title, "host": f.host, "severity": f.severity, "cvss": f.cvss,
                    "organization_id": d.organization_id})
    return out


def target_out(t: ExternalTarget) -> dict[str, Any]:
    host = t.value
    return {"id": t.id, "kind": t.kind, "value": t.value, "verified": bool(t.verified_at),
            "verified_method": t.verified_method, "verified_at": t.verified_at, "verified_detail": t.verified_detail,
            "last_check_at": t.last_check_at, "last_check_error": t.last_check_error,
            "approval_status": t.approval_status, "approval_note": t.approval_note, "attested_by": t.attested_by,
            "attestation": t.attestation, "default_password_checks": t.default_password_checks,
            "consent_by": t.consent_by, "consent_at": t.consent_at, "window_start_hour": t.window_start_hour,
            "window_end_hour": t.window_end_hour, "created_at": t.created_at,
            "proof": ({"txt_name": f"_sentrigis.{host}", "txt_value": f"sentrigis-verification={t.token}",
                       "txt_name_alt": host, "file_url": f"https://{host}{PROOF_PATH}", "file_content": t.token}
                      if t.kind == "domain" and not t.verified_at else None)}


def scan_out(s: ExternalScan) -> dict[str, Any]:
    return {"id": s.id, "trigger": s.trigger, "status": s.status, "started_at": s.started_at,
            "finished_at": s.finished_at, "started_by": s.started_by, "scanner_ip": s.scanner_ip, "hosts": s.hosts,
            "open_ports": s.open_ports, "new_hosts": s.new_hosts, "findings_open": s.findings_open,
            "result": s.result, "targets": s.targets, "skipped": s.skipped, "message": s.message}


def host_out(h: ExternalHost, counts: dict[str, int]) -> dict[str, Any]:
    tls_summary = None
    if h.tls:
        worst = None
        for t in h.tls.values():
            protos = [k for k, v in (t.get("protocols") or {}).items() if v]
            if any(p in protos for p in ("SSLv3", "TLS1.0", "TLS1.1")):
                worst = "legacy protocols"
            elif worst is None and t.get("trusted") is False:
                worst = "certificate not trusted"
            elif worst is None and (t.get("days_left") is not None and t["days_left"] < 30):
                worst = "certificate expiring"
        tls_summary = worst or "ok"
    return {"id": h.id, "host": h.host, "ip": h.ip, "ports": h.ports, "software": h.software, "tls": h.tls,
            "tls_summary": tls_summary, "dns": h.dns, "asset_id": h.asset_id, "active": h.active,
            "first_seen": h.first_seen, "last_seen": h.last_seen, "findings": counts.get(h.host, 0)}


def overview(db: Session, now: datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    st = get_settings(db)
    scans = list(db.scalars(select(ExternalScan).where(ExternalScan.trigger != "retest")
                            .order_by(ExternalScan.started_at.desc()).limit(1)))
    last = scans[0] if scans else None
    hosts = list(db.scalars(select(ExternalHost).where(ExternalHost.active.is_(True))))
    findings = list(db.scalars(select(ExternalFinding).where(ExternalFinding.status != "resolved")))
    exempt = exempt_ids(db)
    failing = sum(1 for f in findings if rules.counts(f, f.id in exempt))
    last_done = db.scalar(select(ExternalScan).where(ExternalScan.status.in_(("succeeded", "partial")))
                          .order_by(ExternalScan.started_at.desc()).limit(1))
    interval = timedelta(hours=st.interval_hours)
    next_due = (last.started_at + interval) if (last and st.schedule_enabled) else None
    return {
        "hosts": len(hosts), "open_ports": sum(len(h.ports or []) for h in hosts),
        "new_since_last_scan": last_done.new_hosts if last_done else 0,
        "open_findings": len(findings), "failing_findings": failing,
        "by_severity": {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER},
        "result": rules.overall(failing) if last_done else None, "result_label": rules.label(
            rules.overall(failing) if last_done else None),
        "last_scan": scan_out(last) if last else None, "running": bool(running_scans(db)),
        "scanner_egress_ip": config.settings.external_scanner_egress_ip or None,
        "schedule": {"enabled": st.schedule_enabled, "interval_hours": st.interval_hours, "next_scan_at": next_due},
        "scope": {"text": st.scope_text, "confirmed_by": st.scope_confirmed_by, "confirmed_at": st.scope_confirmed_at},
        "limits": {"max_targets": config.settings.external_max_targets, "max_cidr_addresses": MAX_CIDR_ADDRESSES},
        "disclaimer": DISCLAIMER,
    }


DISCLAIMER = ("Pre-ASV scan. This is not an ASV scan report and not an Attestation of Scan Compliance: only a PCI SSC "
              "Approved Scanning Vendor can issue those.")


# ----------------------------------------------------------------------------- report data
SPECIAL_NOTES = {
    "remote_access": "Remote access software or services",
    "browsable_directory": "Browsable directories",
    "embedded_links": "Embedded links or scripts from other domains",
    "default_credentials": "Default credentials accepted",
}


def report_data(db: Session, now: datetime | None = None) -> dict[str, Any]:
    """Everything of the pre-ASV report (Parts 1 to 3c), from the current state of the organisation."""
    now = now or utcnow()
    org = db.get(Organization, tenancy.require_org(db))
    st = get_settings(db)
    scan = db.scalar(select(ExternalScan).where(ExternalScan.status.in_(("succeeded", "partial")),
                                                ExternalScan.trigger != "retest")
                     .order_by(ExternalScan.started_at.desc()).limit(1))
    findings = list(db.scalars(select(ExternalFinding).where(ExternalFinding.status != "resolved")))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.cvss, f.host))
    disputes = defaultdict(list)
    for d in db.scalars(select(ExternalDispute)):
        disputes[d.finding_id].append(d)
    hosts = list(db.scalars(select(ExternalHost).where(ExternalHost.active.is_(True)).order_by(ExternalHost.host)))
    host_ip = {h.host: h.ip for h in hosts}
    vulns, components, notes = [], {}, defaultdict(list)
    for h in hosts:
        components[h.host] = {"host": h.host, "ip": h.ip, "ports": [p["port"] for p in h.ports or []],
                              "failing": 0, "findings": 0}
    for f in findings:
        accepted = next((d for d in disputes[f.id] if d.status == "accepted"), None)
        fails = rules.counts(f, accepted is not None)
        reason = rules.fail_reason(f)
        row = {"ref": finding_ref(f), "title": f.title, "host": f.host, "ip": f.ip or host_ip.get(f.host), "port": f.port,
               "severity": f.severity, "cvss": f.cvss, "vector": f.vector, "cwe": f.cwe, "cve_id": f.cve_id,
               "status": f.status, "result": "Fail" if fails else "Pass",
               "reason": reason if fails else (None if reason is None else "Exempted: accepted dispute"),
               "exception": ({"kind": accepted.kind, "reason": accepted.reason, "reviewed_by": accepted.reviewed_by,
                              "note": accepted.review_note} if accepted else None),
               "fix": (f.detail or {}).get("fix", {}).get("General", "")}
        vulns.append(row)
        c = components.setdefault(f.host, {"host": f.host, "ip": f.ip, "ports": [], "failing": 0, "findings": 0})
        c["findings"] += 1
        c["failing"] += 1 if fails else 0
        if f.special_note:
            notes[f.special_note].append({"host": f.host, "port": f.port, "item": f.title,
                                          "detail": f"{f.url or ''}".strip()})
    for c in components.values():
        c["result"] = "Fail" if c["failing"] else "Pass"
    failing = sum(c["failing"] for c in components.values())
    result = rules.overall(failing)
    return {
        "title": "Pre-ASV external vulnerability scan",
        "disclaimer": DISCLAIMER, "generated_at": now.isoformat(),
        "customer": {"name": org.name if org else "", "contact": org.contact_email if org else None},
        "scan": ({"id": scan.id, "started_at": scan.started_at.isoformat(),
                  "finished_at": scan.finished_at.isoformat() if scan.finished_at else None, "trigger": scan.trigger,
                  "status": scan.status, "scanner_ip": scan.scanner_ip, "hosts": scan.hosts,
                  "targets": scan.targets, "skipped": scan.skipped} if scan else None),
        "scanner_ip": (scan.scanner_ip if scan else None) or config.settings.external_scanner_egress_ip or None,
        "result": result if scan else None, "result_label": rules.label(result if scan else None),
        "rules": rules.RULE_TABLE,
        "components": sorted(components.values(), key=lambda c: (c["result"] != "Fail", c["host"])),
        "vulnerabilities": vulns,
        "special_notes": [{"key": k, "label": SPECIAL_NOTES.get(k, k), "items": v} for k, v in notes.items()],
        "exceptions": [v for v in vulns if v["exception"]],
        "scope": {"text": st.scope_text, "confirmed_by": st.scope_confirmed_by,
                  "confirmed_at": st.scope_confirmed_at.isoformat() if st.scope_confirmed_at else None},
    }


def generate_report(db: Session, actor: User, ip: str | None) -> ExternalReport:
    st = get_settings(db)
    if not st.scope_confirmed_at:
        raise ExternalError("confirm the scope declaration (the list of in-scope internet-facing systems) first", 409)
    data = report_data(db)
    if data["scan"] is None:
        raise ExternalError("run a scan first", 409)
    r = ExternalReport(scan_id=data["scan"]["id"], generated_by=actor.email, result=data["result"], data=data)
    db.add(r)
    db.flush()
    audit(db, "external_report_generated", actor=actor, target=f"external_report:{r.id}", ip=ip, result=r.result)
    return r
