"""End-of-life runtimes and database engines as Vulnerability rows (source "eol").

The posture rules already raise findings for them (AZ-APP-009 / AZ-FN-009, AZ-PG-007,
AZ-MYSQL-007, AZ-REDIS-005). Recording them as vulnerabilities as well puts them on
the Vulnerabilities page next to CVEs and lets the risk score use the asset's runtime
context. One row per asset and stack (`match_key = "eol:<stack>"`, `cve_id =
"EOL-<STACK>-<version>"`); a row resolves when the asset no longer runs that version.
The EOL table is bundled (engine/eol.py, endoflife.date): no network call.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..engine import eol
from ..engine.risk import cvss_severity
from ..models import Asset, Vulnerability, new_id
from ..notifications import builtin as notify

SOURCE = "eol"
# No CVE exists for "unsupported": scored like a high-severity issue that will not be fixed.
EOL_CVSS = 7.5
EOL_SLUG = {"node": "nodejs", "redis": "azure-cache-for-redis"}
DB_ENGINES = {"postgresql_server": ("postgresql", "version"), "mysql_server": ("mysql", "version"),
              "redis_cache": ("redis", "redis_version")}


def eol_items(a: Asset) -> list[dict]:
    """[{stack, version, label, eol_date}] for the asset's end-of-life runtimes / engines."""
    p = a.properties or {}
    pairs: list[tuple[str, str]] = []
    if a.type in ("web_app", "function_app"):
        pairs = eol.app_runtimes(p.get("runtime_config") or {})
    elif a.type in DB_ENGINES:
        stack, key = DB_ENGINES[a.type]
        if p.get(key):
            pairs = [(stack, str(p[key]))]
    out = []
    for stack, version in pairs:
        ev = eol.eol_check(stack, version)
        if ev:
            out.append({"stack": stack, "version": version, "label": ev["runtime"], "eol_date": ev["eol_date"]})
    return out


def sync_eol_vulnerabilities(db: Session, assets: list[Asset], now: datetime) -> dict:
    opened = resolved = 0
    for a in assets:
        if a is None:
            continue
        items = {f"eol:{i['stack']}": i for i in eol_items(a)}
        existing = {v.match_key: v for v in db.scalars(select(Vulnerability).where(
            Vulnerability.asset_id == a.id, Vulnerability.source == SOURCE))}
        for key, i in items.items():
            v = existing.get(key)
            is_new = v is None or v.status != "open"
            if v is None:
                v = Vulnerability(id=new_id(), asset_id=a.id, source=SOURCE, match_key=key, first_seen=now)
                db.add(v)
            v.status, v.resolved_at = "open", None
            v.cve_id = f"EOL-{i['stack'].upper()}-{i['version']}"[:32]
            v.package, v.version, v.fixed_version = eol.STACK_LABEL.get(i["stack"], i["stack"]), i["version"], None
            v.title = f"{i['label']} is end-of-life since {i['eol_date']}"
            v.cvss, v.severity = EOL_CVSS, cvss_severity(EOL_CVSS)
            v.exploit_available, v.kev, v.epss = False, None, None
            v.in_use = True  # the app / server runs on it
            v.last_seen = now
            v.evidence = {"eol_date": i["eol_date"], "runtime": i["label"], "source": "endoflife.date",
                          "url": f"https://endoflife.date/{EOL_SLUG.get(i['stack'], i['stack'])}"}
            if is_new:
                db.flush()
                notify.vulnerability_found(db, v)
                opened += 1
        for key, v in existing.items():
            if key not in items and v.status == "open":
                v.status, v.resolved_at = "resolved", now
                resolved += 1
    db.flush()
    return {"eol_opened": opened, "eol_resolved": resolved}
