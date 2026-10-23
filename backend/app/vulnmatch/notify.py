"""Notifications for newly matched vulnerabilities, aggregated per CVE.

A fleet-wide Chrome CVE must not send one message per laptop: everything
found in one worker pass is grouped by CVE into a single "vulnerability /
created" event ("CVE-2024-1234 in Google Chrome on 37 devices"). A CVE that
was notified within the last NOTIFY_WINDOW is not notified again (later
check-ins of the same fleet), and the notification rules' own throttle (by
group key) applies on top.

Only critical vulnerabilities (VULN_NOTIFY_MIN_SEVERITY) and CISA KEV-listed
ones are notified.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import quote

from sqlalchemy.orm import Session

from .. import config
from ..notifications.builtin import VULNERABILITY
from ..notifications.events import SEV_RANK, Event, emit
from . import feeds

NOTIFY_WINDOW = timedelta(hours=24)
MAX_NAMES = 20


@dataclass
class Item:
    cve_id: str
    severity: str
    kev: bool
    cvss: float
    package: str
    title: str
    fixed_version: str | None
    target_type: str  # device | asset
    target_id: str
    target_name: str


def qualifies(severity: str, kev: bool) -> bool:
    return kev or SEV_RANK.get(severity, 0) >= SEV_RANK.get(config.settings.vuln_notify_min_severity, 4)


def notify(db: Session, items: list[Item], now: datetime, *, reason: str = "found") -> int:
    """Emit one event per CVE for the qualifying items. Returns events emitted."""
    by_cve: dict[str, list[Item]] = defaultdict(list)
    for it in items:
        if qualifies(it.severity, it.kev):
            by_cve[it.cve_id].append(it)
    n = 0
    for cve, group in sorted(by_cve.items()):
        ck = f"notified:{cve}"
        row = feeds.cache_get(db, ck)
        if row is not None and row.expires_at > now and not (reason == "kev" and not row.data.get("kev")):
            continue
        kev = any(i.kev for i in group)
        sev = max((i.severity for i in group), key=lambda s: SEV_RANK.get(s, 0))
        if kev and SEV_RANK.get(sev, 0) < SEV_RANK["high"]:
            sev = "high"  # actively exploited: never below high
        devices = sorted({i.target_name for i in group if i.target_type == "device"})
        assets = sorted({(i.target_id, i.target_name) for i in group if i.target_type == "asset"})
        packages = sorted({i.package for i in group})
        where = []
        if devices:
            where.append(f"{len(devices)} device{'s' if len(devices) != 1 else ''}")
        if assets:
            where.append(f"{len(assets)} asset{'s' if len(assets) != 1 else ''}")
        lead = "Now known exploited: " if reason == "kev" else ("Known exploited: " if kev else "")
        title = f"{lead}{cve} in {', '.join(packages[:3])} on {' and '.join(where)}"
        fixed = sorted({i.fixed_version for i in group if i.fixed_version})
        summary = (group[0].title or "") + (f" Fixed in {fixed[0]}." if fixed else "")
        names = devices[:MAX_NAMES] + [a[1] for a in assets][:MAX_NAMES]
        ev = Event(
            source=VULNERABILITY, event_type="created", severity=sev, title=title, summary=summary,
            entity_id=cve, group_key=f"{VULNERABILITY}:{cve}:aggregate",
            asset_id=assets[0][0] if len(assets) == 1 and not devices else None, rule_id=cve,
            link_path=f"/vulnerabilities?cve={quote(cve, safe='')}",
            attributes={"cvss": max(i.cvss for i in group), "kev": kev, "exploit_available": kev,
                        "packages": packages[:10], "fixed_version": fixed[0] if fixed else None,
                        "device_count": len(devices), "asset_count": len(assets), "targets": names,
                        "asset_type": "device" if devices and not assets else None},
        )
        if emit(db, ev) is not None:
            feeds.cache_put(db, ck, {"kev": kev, "count": len(group)}, NOTIFY_WINDOW, now)
            n += 1
    return n
