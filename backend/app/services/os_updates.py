"""Missing OS updates (docs/PATCHING.md): the per-device Windows Update report.

Step 1 of patching is read-only: agents 1.4.0+ on Windows search the Windows
Update Agent against the machine's own configured source (WSUS, Windows Update
for Business or Microsoft Update) on a schedule and on demand
(`scan_os_updates`), and upload what is missing. Nothing is installed.

The latest successful report replaces the previous one; a failed search keeps
the last known list and only records the error. Issues are derived on read,
like the other device issues (app/services/devices.py), so age-based ones are
always current:

  os_critical_updates_missing  a missing update rated Critical by Microsoft
                               (MSRC) released more than N days ago (14)
  os_security_updates_missing  any missing security / critical update released
                               more than N days ago (30)
  os_reboot_pending            a restart has been pending for N days (7)
  windows_update_disabled      the Windows Update service is disabled
  os_update_scan_stale         no update search succeeded for N days (7)
"""
from __future__ import annotations

import csv
import io
from datetime import UTC, date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, undefer

from .. import config
from ..models import Device, DeviceCommand, DeviceOsUpdates, Vulnerability, utcnow
from ..schemas_os_updates import SECURITY_CLASSIFICATIONS, OsUpdateReportIn

FEATURE = "windows_updates"
COMMAND_TYPE = "scan_os_updates"
MIN_AGENT_VERSION = "1.4.0"
ISSUE_CODES = ("os_critical_updates_missing", "os_security_updates_missing", "os_reboot_pending",
               "windows_update_disabled", "os_update_scan_stale")
CATALOG_URL = "https://www.catalog.update.microsoft.com/Search.aspx?q="


def _naive(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is not None:
        return dt.astimezone(UTC).replace(tzinfo=None)
    return dt


def z(dt: datetime | None) -> str | None:
    """Naive-UTC datetime -> ISO 8601 with Z (plain dict responses)."""
    return dt.isoformat() + "Z" if dt is not None else None


def support(device: Device) -> tuple[bool, str | None, bool]:
    """(supported, reason when not, agent update required)."""
    if device.os_family != "windows":
        return False, "OS update reports are Windows only in this version.", False
    if FEATURE not in (device.agent_features or "").split(","):
        return False, (f"Agent update required: OS update reports need agent {MIN_AGENT_VERSION} or later "
                       f"(this device runs {device.agent_version or 'an unknown version'})."), True
    return True, None, False


def is_security(u: dict[str, Any]) -> bool:
    return u.get("classification") in SECURITY_CLASSIFICATIONS or bool(u.get("msrc_severity"))


def is_critical(u: dict[str, Any]) -> bool:
    return u.get("msrc_severity") == "Critical"


def _oldest(updates: list[dict[str, Any]], pred) -> date | None:
    dates = [date.fromisoformat(u["release_date"]) for u in updates if pred(u) and u.get("release_date")]
    return min(dates) if dates else None


def store_report(db: Session, device: Device, body: OsUpdateReportIn) -> DeviceOsUpdates:
    """Replace the device's report (a failed search keeps the previous update list)."""
    now = utcnow()
    st = db.get(DeviceOsUpdates, device.id, options=[undefer(DeviceOsUpdates.updates)])
    if st is None:
        st = DeviceOsUpdates(device_id=device.id, created_at=now, updates=[])
        db.add(st)
    st.reported_at = now
    st.scanned_at = _naive(body.scanned_at)
    st.scan_status, st.scan_error, st.scan_trigger = body.status, body.error, body.trigger
    st.scan_duration_seconds = body.duration_seconds
    st.source, st.source_detail = body.source, body.source_detail
    st.service_state, st.service_start_type = body.service_state, body.service_start_type
    st.last_install_success_at = _naive(body.last_install_success_at)
    successes = [t for t in (_naive(body.last_search_success_at), st.last_success_at,
                             st.scanned_at if body.status == "ok" else None) if t is not None]
    st.last_success_at = max(successes) if successes else None
    st.reboot_pending = body.reboot_pending
    if body.reboot_pending:
        st.reboot_pending_since = st.reboot_pending_since or now
    else:
        st.reboot_pending_since = None
    if body.status == "ok":
        st.listed_at = st.scanned_at
        updates = [u.model_dump(mode="json") for u in body.updates]
        updates.sort(key=lambda u: (not is_critical(u), not is_security(u), u.get("release_date") or "9999",
                                    u["title"].lower()))
        st.updates = updates
        st.missing_count = len(updates)
        st.security_count = sum(1 for u in updates if is_security(u))
        st.critical_count = sum(1 for u in updates if is_critical(u))
        st.oldest_security_release = _oldest(updates, is_security)
        st.oldest_critical_release = _oldest(updates, is_critical)
    db.flush()
    return st


def _age_days(d: date | None, now: datetime) -> int | None:
    return None if d is None else max(0, (now.date() - d).days)


def issues(device: Device, now: datetime) -> list[tuple[str, str]]:
    """(code, detail) of the OS-update issues of a device (see the module docstring)."""
    st = device.os_updates
    if st is None or device.os_family != "windows":
        return []
    s = config.settings
    out: list[tuple[str, str]] = []
    age = _age_days(st.oldest_critical_release, now)
    if age is not None and age > s.device_os_updates_critical_days:
        out.append(("os_critical_updates_missing",
                    f"{st.critical_count} critical update(s) missing, the oldest released {age} days ago"))
    age = _age_days(st.oldest_security_release, now)
    if age is not None and age > s.device_os_updates_security_days:
        out.append(("os_security_updates_missing",
                    f"{st.security_count} security update(s) missing, the oldest released {age} days ago"))
    if st.reboot_pending and st.reboot_pending_since is not None:
        days = (now - st.reboot_pending_since).total_seconds() / 86400
        if days >= s.device_os_updates_reboot_days:
            out.append(("os_reboot_pending", f"restart pending for {int(days)} days"))
    if st.service_start_type == "disabled":
        out.append(("windows_update_disabled", "the Windows Update service (wuauserv) start type is Disabled"))
    ref = st.last_success_at or st.created_at
    days = (now - ref).total_seconds() / 86400
    if days >= s.device_os_updates_scan_stale_days:
        detail = (f"last successful search {int(days)} days ago" if st.last_success_at
                  else f"no successful search since the first report {int(days)} days ago")
        if st.scan_status == "failed" and st.scan_error:
            detail += f" ({st.scan_error[:200]})"
        out.append(("os_update_scan_stale", detail))
    return out


def summary(device: Device, now: datetime | None = None) -> dict[str, Any] | None:
    """Compact per-device figures for the Devices list (None: no report)."""
    st = device.os_updates
    if st is None:
        return None
    now = now or utcnow()
    return {"listed": st.listed_at is not None, "missing": st.missing_count, "security": st.security_count,
            "critical": st.critical_count, "oldest_security_days": _age_days(st.oldest_security_release, now),
            "reboot_pending": st.reboot_pending, "scan_status": st.scan_status, "scanned_at": z(st.scanned_at),
            "source": st.source}


def matches_filter(device: Device, value: str) -> bool:
    """Devices list filter ?updates=security|any|none|unknown."""
    st = device.os_updates
    if value == "unknown":
        return st is None
    if st is None:
        return False
    return {"security": st.security_count > 0, "any": st.missing_count > 0,
            "none": st.listed_at is not None and st.missing_count == 0}[value]


def fleet(devices: list[Device], now: datetime) -> dict[str, Any]:
    """Endpoints dashboard tile: active devices missing security updates and the oldest one's age."""
    reporting = with_security = with_critical = with_any = 0
    oldest: int | None = None
    for d in devices:
        st = d.os_updates
        if st is None or st.listed_at is None or d.os_family != "windows":
            continue
        reporting += 1
        with_any += st.missing_count > 0
        with_critical += st.critical_count > 0
        if st.security_count > 0:
            with_security += 1
            age = _age_days(st.oldest_security_release, now)
            if age is not None and (oldest is None or age > oldest):
                oldest = age
    return {"reporting": reporting, "devices_missing_security": with_security,
            "devices_missing_critical": with_critical, "devices_missing_any": with_any,
            "oldest_security_days": oldest}


def pending_scan(db: Session, device_id: str) -> DeviceCommand | None:
    return db.scalar(select(DeviceCommand).where(DeviceCommand.device_id == device_id,
                                                 DeviceCommand.type == COMMAND_TYPE,
                                                 DeviceCommand.status.in_(("pending", "delivered")))
                     .order_by(DeviceCommand.created_at.desc()).limit(1))


def _known_cves(db: Session, cves: set[str]) -> set[str]:
    """CVE ids that already appear in this organisation's vulnerability views."""
    if not cves:
        return set()
    found: set[str] = set()
    ids = sorted(cves)
    for i in range(0, len(ids), 500):
        found.update(db.scalars(select(Vulnerability.cve_id).where(Vulnerability.cve_id.in_(ids[i:i + 500]))
                                .distinct()))
    return found


def device_view(db: Session, device: Device) -> dict[str, Any]:
    """Everything the device's "OS updates" tab shows."""
    s = config.settings
    now = utcnow()
    supported, reason, update_required = support(device)
    st = db.get(DeviceOsUpdates, device.id, options=[undefer(DeviceOsUpdates.updates)])
    cmd = pending_scan(db, device.id)
    out: dict[str, Any] = {
        "supported": supported, "unsupported_reason": reason, "agent_update_required": update_required,
        "min_agent_version": MIN_AGENT_VERSION,
        "thresholds": {"critical_days": s.device_os_updates_critical_days,
                       "security_days": s.device_os_updates_security_days,
                       "reboot_days": s.device_os_updates_reboot_days,
                       "scan_stale_days": s.device_os_updates_scan_stale_days},
        "pending_scan": None if cmd is None else {"command_id": cmd.id, "status": cmd.status,
                                                  "requested_at": z(cmd.created_at),
                                                  "requested_by": cmd.requested_by_email},
        "issues": [{"code": c, "detail": d} for c, d in issues(device, now)],
        "report": None,
    }
    if st is None:
        return out
    updates = list(st.updates or [])
    known = _known_cves(db, {c for u in updates for c in u.get("cve_ids") or []})
    out["report"] = {
        "reported_at": z(st.reported_at), "scanned_at": z(st.scanned_at), "scan_status": st.scan_status,
        "scan_error": st.scan_error, "scan_trigger": st.scan_trigger, "scan_duration_seconds": st.scan_duration_seconds,
        "last_success_at": z(st.last_success_at), "last_install_success_at": z(st.last_install_success_at),
        "listed_at": z(st.listed_at),
        "source": st.source, "source_detail": st.source_detail, "service_state": st.service_state,
        "service_start_type": st.service_start_type, "reboot_pending": st.reboot_pending,
        "reboot_pending_since": z(st.reboot_pending_since), "missing_count": st.missing_count,
        "security_count": st.security_count, "critical_count": st.critical_count,
        "oldest_security_days": _age_days(st.oldest_security_release, now),
        "updates": [{**u, "age_days": _age_days(date.fromisoformat(u["release_date"]), now)
                     if u.get("release_date") else None,
                     "security": is_security(u), "known_cves": [c for c in u.get("cve_ids") or [] if c in known]}
                    for u in updates],
    }
    return out


CSV_COLUMNS = ["hostname", "device_id", "device_group", "os_version", "source", "scanned_at", "scan_status",
               "reboot_pending", "kb_ids", "title", "classification", "msrc_severity", "release_date", "age_days",
               "cve_ids", "reboot_behavior", "size_bytes", "catalog_url"]


def export_csv(db: Session, *, security_only: bool, device_id: str | None, safe_cell) -> tuple[str, int]:
    """One row per (device, missing update), for active devices with a report."""
    now = utcnow()
    stmt = (select(Device, DeviceOsUpdates).join(DeviceOsUpdates, DeviceOsUpdates.device_id == Device.id)
            .where(Device.status == "active").options(undefer(DeviceOsUpdates.updates)).order_by(Device.hostname))
    if device_id:
        stmt = stmt.where(Device.id == device_id)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLUMNS)
    n = 0
    for d, st in db.execute(stmt):
        for u in st.updates or []:
            if security_only and not is_security(u):
                continue
            rd = u.get("release_date") or ""
            kbs = u.get("kb_ids") or []
            row = [d.hostname, d.id, d.device_group or "", d.os_version, st.source,
                   z(st.scanned_at) or "", st.scan_status,
                   "yes" if st.reboot_pending else "no", " ".join(kbs), u.get("title", ""),
                   u.get("classification", ""), u.get("msrc_severity", ""), rd,
                   _age_days(date.fromisoformat(rd), now) if rd else "", " ".join(u.get("cve_ids") or []),
                   u.get("reboot_behavior", ""), u.get("size_bytes") if u.get("size_bytes") is not None else "",
                   CATALOG_URL + kbs[0] if kbs else ""]
            w.writerow([safe_cell(v) if isinstance(v, str) else v for v in row])
            n += 1
    return buf.getvalue(), n
