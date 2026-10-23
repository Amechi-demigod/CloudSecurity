"""Match one device (NVD by CPE) or one asset (OSV) and reconcile its
Vulnerability rows: create new ones, update / re-open existing ones, and
resolve the ones whose software was upgraded or removed.

A vulnerability is only resolved when the product it was found in is either
gone from the inventory or was checked successfully in this pass; when the
feed for that product is unavailable (offline) the existing rows are kept.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..engine.risk import cvss_severity, priority_for, vuln_risk_score
from ..models import Asset, AssetPackage, Device, DeviceSoftware, Vulnerability, new_id, utcnow
from . import feeds
from .cpe import Installed, cve_matches
from .feeds import FeedError, cpe_key
from .mapping import map_software
from .state import ASSET, DEVICE, get_state
from .versions import macos_version, windows_os

log = logging.getLogger(__name__)

NVD = "nvd"
OSV = "osv"
SEVERITIES = ("critical", "high", "medium", "low")
DEFAULT_CVSS = 5.0  # used (and flagged in evidence) when a feed publishes no score yet


@dataclass
class Finding:
    match_key: str
    cve_id: str
    package: str
    version: str
    fixed_version: str | None
    title: str
    cvss: float
    severity: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class MatchOutcome:
    target_type: str
    target_id: str
    target_name: str
    new: list[Vulnerability] = field(default_factory=list)
    resolved: int = 0
    open: int = 0
    checked: list[dict] = field(default_factory=list)
    not_checked: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _arch(raw: str) -> str:
    a = (raw or "").lower()
    if a in ("amd64", "x86_64", "x64", "64-bit"):
        return "x64"
    if a in ("arm64", "aarch64"):
        return "arm64"
    if a in ("386", "x86", "i386", "32-bit"):
        return "x86"
    return ""


def _severity(sev: str, cvss: float) -> str:
    sev = (sev or "").lower()
    return sev if sev in SEVERITIES else (cvss_severity(cvss) if cvss > 0 else "medium")


def device_os(device: Device) -> tuple[str, str, str] | None:
    """(NVD cpe, version, label) of the device's operating system."""
    if device.os_family == "windows":
        r = windows_os(device.os_name, device.os_version, device.os_build)
        if r is None:
            return None
        product, version = r
        words = product.split("_")[1:]  # windows_11_23h2 -> 11 23H2 ; windows_server_2022 -> Server 2022
        label = "Windows " + " ".join(w.capitalize() if w == "server" else w.upper() for w in words)
        return f"o:microsoft:{product}", version, label
    if device.os_family == "macos":
        v = macos_version(device.os_version)
        return ("o:apple:macos", v, "macOS") if v else None
    return None


def _platform(device: Device, os_cpe: str | None, os_version: str, apps: list[Installed]) -> list[Installed]:
    fam, arch = device.os_family, _arch(device.architecture)
    plat = list(apps)
    if os_cpe:
        plat.append(Installed(cpe_key(os_cpe), os_version, os_family=fam, arch=arch))
    if fam == "windows":
        for p in ("windows", "windows_10", "windows_11"):
            plat.append(Installed(f"o:microsoft:{p}", "", os_family=fam, arch=arch))
    elif fam == "macos":
        for p in ("macos", "mac_os_x", "mac_os"):
            plat.append(Installed(f"o:apple:{p}", os_version if p == "macos" else "", os_family=fam, arch=arch))
    return plat


# ----------------------------------------------------------------------------- devices
def match_device(db: Session, device: Device, now: datetime | None = None, *, allow_fetch: bool = True
                 ) -> MatchOutcome:
    now = now or utcnow()
    out = MatchOutcome(DEVICE, device.id, device.hostname)
    fam, arch = device.os_family, _arch(device.architecture)
    # (match_key, label, cpes, Installed-version, update, display name, raw version, sw_edition)
    targets: list[tuple[str, str, tuple[str, ...], str, str, str, str, str]] = []
    os_info = device_os(device)
    if os_info is not None:
        os_cpe, os_ver, os_label = os_info
        targets.append(("os", os_label, (os_cpe,), os_ver, "", device.os_name or os_label, os_ver, ""))
    else:
        out.not_checked.append({"name": device.os_name or fam, "version": device.os_build or device.os_version,
                                "reason": "operating system build not recognised"})
    software = list(db.scalars(select(DeviceSoftware).where(DeviceSoftware.device_id == device.id)))
    for sw in software:
        m, reason = map_software(sw.name, sw.version, sw.publisher, sw.identifier, fam)
        if m is None:
            out.not_checked.append({"name": sw.name, "version": sw.version, "publisher": sw.publisher,
                                    "reason": reason})
            continue
        targets.append((m.rule.id, m.rule.label, m.rule.cpes, m.version, m.update, sw.name, sw.version,
                        m.sw_edition))

    apps = [Installed(cpe_key(c), v, u, fam, arch, e) for (_k, _l, cpes, v, u, _n, _r, e) in targets for c in cpes]
    platform = _platform(device, None, "", apps)

    findings: dict[tuple[str, str], Finding] = {}
    checked_keys: set[str] = set()
    installed_keys = {t[0] for t in targets}
    for key, label, cpes, version, update, name, raw_version, edition in targets:
        ok = True
        for cpe in cpes:
            data, err = feeds.nvd_product(db, cpe, now, allow_fetch=allow_fetch)
            db.commit()  # keep the cache / status even if a later step fails
            if data is None:
                ok = False
                out.errors.append(f"{cpe}: {err}")
                continue
            inst = Installed(cpe_key(cpe), version, update, fam, arch, edition)
            for cve_id, c in data.items():
                res = cve_matches(c.get("cfg") or [], inst, platform)
                if res is None:
                    continue
                fk = (key, cve_id)
                prev = findings.get(fk)
                if prev is not None:
                    continue
                cvss = float(c.get("cvss") or 0.0)
                evidence = {"criteria": res.criteria, "cpe": cpe, "software": name, "published": c.get("pub"),
                            "vector": c.get("vec") or None,
                            "range": {k: v for k, v in {
                                "start_including": res.version_start_including,
                                "start_excluding": res.version_start_excluding,
                                "end_including": res.version_end_including,
                                "end_excluding": res.version_end_excluding}.items() if v},
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}
                if cvss <= 0:
                    evidence["score_missing"] = True
                findings[fk] = Finding(match_key=key, cve_id=cve_id[:32], package=label[:128],
                                       version=(raw_version or version)[:64],
                                       fixed_version=(res.fixed_version or None) and res.fixed_version[:64],
                                       title=(c.get("desc") or "")[:255], cvss=cvss if cvss > 0 else DEFAULT_CVSS,
                                       severity=_severity(c.get("sev") or "", cvss), evidence=evidence)
        entry = {"name": name, "version": raw_version, "product": label, "cpe": ",".join(cpes), "rule": key}
        if ok:
            checked_keys.add(key)
            out.checked.append(entry)
        else:
            out.not_checked.append({**entry, "reason": "vulnerability data unavailable (feed offline)"})
    _reconcile(db, out, NVD, Vulnerability.device_id == device.id, findings, checked_keys, installed_keys, now,
               lambda: Vulnerability(id=new_id(), device_id=device.id, source=NVD, first_seen=now),
               context=None)
    st = get_state(db, DEVICE, device.id)
    if st is not None:
        st.matched_at = now
        st.requested_at = None
        st.checked = out.checked[:2000]
        st.not_checked = out.not_checked[:2000]
        st.os_info = {"cpe": os_info[0], "version": os_info[1], "label": os_info[2]} if os_info else {}
        st.error = "; ".join(out.errors)[:2000] or None
    return out


# ----------------------------------------------------------------------------- assets (OSV)
DEB_LIKE = ("Debian", "Ubuntu", "Alpine")


def _osv_name(p: AssetPackage) -> str:
    eco = p.ecosystem.split(":", 1)[0]
    if eco in DEB_LIKE and p.source_name:
        return p.source_name
    return p.name


def _fixed(rec: dict, eco: str, name: str) -> str | None:
    fixed = None
    for a in rec.get("affected") or []:
        pkg = a.get("package") or {}
        if pkg.get("ecosystem") != eco or pkg.get("name") != name:
            continue
        for rng in a.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    fixed = ev["fixed"]
    return fixed


def _cve_ids(rec: dict) -> list[str]:
    ids = [i for i in (rec.get("upstream") or []) + (rec.get("aliases") or []) if str(i).startswith("CVE-")]
    if rec.get("id", "").startswith("CVE-"):
        ids.insert(0, rec["id"])
    seen: list[str] = []
    for i in ids:
        if i not in seen:
            seen.append(i)
    return seen or [rec.get("id", "?")]


def osv_queries(db: Session, packages: list[AssetPackage], now: datetime, allow_fetch: bool
                ) -> tuple[dict[tuple[str, str, str], list[dict] | None], list[str]]:
    """{(ecosystem, name, version): [{id, modified}] or None (unavailable)}, errors."""
    from datetime import timedelta

    from ..config import settings

    keys = sorted({(p.ecosystem, _osv_name(p), p.version) for p in packages if p.ecosystem and p.version})
    results: dict[tuple[str, str, str], list[dict] | None] = {}
    todo: list[tuple[str, str, str]] = []
    stale: dict[tuple[str, str, str], list[dict]] = {}
    for k in keys:
        row = feeds.cache_get(db, "osvq:" + "|".join(k))
        if row is not None and row.expires_at > now:
            results[k] = row.data.get("vulns") or []
        else:
            if row is not None:
                stale[k] = row.data.get("vulns") or []
            todo.append(k)
    errors: list[str] = []
    if todo and allow_fetch:
        try:
            res = feeds.osv_querybatch([{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in todo])
            ttl = timedelta(hours=settings.vuln_osv_cache_hours)
            for k, vulns in zip(todo, res, strict=False):
                slim = [{"id": v.get("id"), "modified": v.get("modified")} for v in vulns if v.get("id")]
                feeds.cache_put(db, "osvq:" + "|".join(k), {"vulns": slim}, ttl, now)
                results[k] = slim
            feeds.record_status(db, "osv", ok=True, now=now)
        except FeedError as e:
            errors.append(str(e))
            feeds.record_status(db, "osv", ok=False, error=str(e), now=now)
        db.commit()
    for k in todo:
        if k not in results:
            results[k] = stale.get(k)
    return results, errors


def match_asset(db: Session, asset: Asset, now: datetime | None = None, *, allow_fetch: bool = True
                ) -> MatchOutcome:
    now = now or utcnow()
    out = MatchOutcome(ASSET, asset.id, asset.name)
    packages = list(db.scalars(select(AssetPackage).where(AssetPackage.asset_id == asset.id)))
    results, errors = osv_queries(db, packages, now, allow_fetch)
    out.errors.extend(errors)
    binaries: dict[tuple[str, str, str], list[str]] = {}
    for p in packages:
        if not p.ecosystem or not p.version:
            out.not_checked.append({"name": p.name, "version": p.version,
                                    "reason": "ecosystem not supported by OSV" if not p.ecosystem else "no version"})
            continue
        binaries.setdefault((p.ecosystem, _osv_name(p), p.version), []).append(p.name)
    findings: dict[tuple[str, str], Finding] = {}
    checked_keys: set[str] = set()
    installed_keys: set[str] = set()
    for (eco, name, version), bins in sorted(binaries.items()):
        key = f"{eco}|{name}"
        installed_keys.add(key)
        vulns = results.get((eco, name, version))
        if vulns is None:
            out.not_checked.append({"name": name, "version": version, "ecosystem": eco,
                                    "reason": "vulnerability data unavailable (feed offline)"})
            continue
        complete = True
        for v in vulns:
            try:
                if allow_fetch:
                    rec = feeds.osv_vuln(db, v["id"], v.get("modified"), now)
                else:
                    row = feeds.cache_get(db, f"osv:{v['id']}")
                    rec = row.data if row is not None else None
            except FeedError as e:
                out.errors.append(f"{v['id']}: {e}")
                complete = False
                continue
            if not rec:
                complete = False
                continue
            cvss, vector, scored = feeds.osv_score(rec)
            for cve in _cve_ids(rec):
                fk = (key, cve)
                f = findings.get(fk)
                if f is not None:
                    if rec["id"] not in f.evidence["osv_ids"]:
                        f.evidence["osv_ids"].append(rec["id"])
                    if scored and (f.evidence.get("score_missing") or cvss > f.cvss):
                        f.cvss, f.severity = cvss, cvss_severity(cvss)
                        f.evidence.pop("score_missing", None)
                    continue
                evidence = {"osv_ids": [rec["id"]], "ecosystem": eco, "binaries": sorted(set(bins))[:50],
                            "vector": vector, "url": f"https://osv.dev/vulnerability/{rec['id']}"}
                if not scored:
                    evidence["score_missing"] = True
                findings[fk] = Finding(match_key=key, cve_id=cve[:32], package=name[:128], version=version[:64],
                                       fixed_version=(_fixed(rec, eco, name) or None) and _fixed(rec, eco, name)[:64],
                                       title=(rec.get("summary") or rec.get("details") or "")[:255],
                                       cvss=cvss, severity=cvss_severity(cvss) if cvss > 0 else "medium",
                                       evidence=evidence)
        db.commit()
        if complete:
            checked_keys.add(key)
        out.checked.append({"name": name, "version": version, "ecosystem": eco, "binaries": sorted(set(bins))[:20],
                            "complete": complete})
    _reconcile(db, out, OSV, Vulnerability.asset_id == asset.id, findings, checked_keys, installed_keys, now,
               lambda: Vulnerability(id=new_id(), asset_id=asset.id, source=OSV, first_seen=now, in_use=False),
               context=asset)
    st = get_state(db, ASSET, asset.id)
    if st is not None:
        st.matched_at = now
        st.requested_at = None
        st.checked = out.checked[:5000]
        st.not_checked = out.not_checked[:2000]
        st.error = "; ".join(out.errors)[:2000] or None
    return out


# ----------------------------------------------------------------------------- reconcile
def score(v: Vulnerability, context: Asset | None) -> None:
    """Risk score: assets use their runtime context. Endpoint software has no
    runtime evidence of dormancy (users launch desktop apps), so device
    vulnerabilities are scored as in use, without internet exposure."""
    if context is not None:
        v.internet_exposed = bool(context.internet_exposed)
        v.sensitive_data_access = bool(context.sensitive_data)
        v.risk_score = vuln_risk_score(v.cvss, v.in_use, v.internet_exposed, v.exploit_available,
                                       v.sensitive_data_access)
    else:
        v.internet_exposed = False
        v.sensitive_data_access = False
        v.risk_score = vuln_risk_score(v.cvss, True, False, v.exploit_available, False)
    v.priority = priority_for(v.risk_score)


def _reconcile(db: Session, out: MatchOutcome, source: str, owner_clause, findings: dict[tuple[str, str], Finding],
               checked_keys: set[str], installed_keys: set[str], now: datetime, factory, context: Asset | None
               ) -> None:
    kev = feeds.kev_catalog(db)
    epss_row = feeds.cache_get(db, "epss")
    epss = (epss_row.data.get("scores") or {}) if epss_row is not None else {}
    existing = {(v.match_key, v.cve_id): v for v in db.scalars(
        select(Vulnerability).where(owner_clause, Vulnerability.source == source))}
    for fk, f in findings.items():
        v = existing.get(fk)
        is_new = v is None
        if v is None:
            v = factory()
            v.match_key = f.match_key
            v.cve_id = f.cve_id
            db.add(v)
        elif v.status != "open":
            v.status, v.resolved_at = "open", None
            is_new = True  # re-appeared (downgrade / reinstall)
        v.package, v.version, v.fixed_version = f.package, f.version, f.fixed_version
        v.title, v.cvss, v.severity = f.title, f.cvss, f.severity
        k = kev.get(f.cve_id)
        v.kev = k is not None
        v.exploit_available = v.kev
        v.epss = epss.get(f.cve_id)
        ev = dict(f.evidence)
        if k is not None:
            ev["kev"] = k
        v.evidence = ev
        v.last_seen = now
        score(v, context)
        if is_new:
            out.new.append(v)
    for fk, v in existing.items():
        if fk in findings or v.status != "open":
            continue
        # Resolve only when the product is gone, or was checked successfully now.
        if v.match_key in checked_keys or v.match_key not in installed_keys:
            v.status, v.resolved_at = "resolved", now
            out.resolved += 1
    db.flush()
    out.open = len(findings)


def resolve_all(db: Session, owner_clause, now: datetime, reason: str) -> int:
    n = 0
    for v in db.scalars(select(Vulnerability).where(owner_clause, Vulnerability.status == "open",
                                                    Vulnerability.source.in_((NVD, OSV)))):
        v.status, v.resolved_at = "resolved", now
        v.evidence = {**(v.evidence or {}), "resolved_reason": reason}
        n += 1
    return n

