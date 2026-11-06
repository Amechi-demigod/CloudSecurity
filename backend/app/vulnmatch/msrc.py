"""Microsoft Security Update Guide (MSRC CVRF API v3.0): which Windows update fixes a CVE.

https://api.msrc.microsoft.com/cvrf/v3.0/ is free and needs no key. `updates` lists the
monthly security-update documents, `cvrf/<id>` (e.g. `2024-May`) is one document with, per
CVE, the remediations per product: the KB article, the fixed build (`FixedBuild`, e.g.
`10.0.22631.3593`), whether a restart is needed, the superseded KB, and Microsoft's
mitigations / workarounds.

The documents are large, so only what the console needs is kept, for Windows products:

    cves[CVE-2024-30040] = {"t": title, "m": "2024-May", "rel": "2024-05-14", "expl": "Exploited:Yes;...",
                            "fix": [{"p": "Windows 11 Version 23H2 for x64-based Systems", "kb": "5037771",
                                     "b": "10.0.22631.3593", "rs": true, "sup": "5036893"}],
                            "mit": ["..."], "wk": ["..."]}

It goes through the same machinery as the other feeds (feeds._request: one httpx client with
proxy support, retries; the cache table; `vuln_feed_status` row "msrc"). A failed refresh keeps
the last good copy and never raises into a check-in: nothing here runs inside a request, only
in the vulnerability worker, and the console reads the cache. Without data, Windows fixes
degrade to "Install the latest cumulative update" (services/vuln_fixes.py).
"""
from __future__ import annotations

import html
import logging
import re
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from .. import config
from ..models import utcnow
from . import feeds

log = logging.getLogger(__name__)

CACHE_KEY = "msrc"
RETENTION = timedelta(days=60)
MAX_TEXT = 1500
MAX_NOTES = 4
# Remediation types in the CVRF schema.
R_WORKAROUND, R_MITIGATION, R_VENDOR_FIX = 0, 1, 2

_KB = re.compile(r"^(?:KB)?(\d{6,8})$", re.IGNORECASE)
_TAGS = re.compile(r"<[^>]+>")
_BR = re.compile(r"<\s*(?:br|/p|/li|/div)\s*/?>", re.IGNORECASE)
# Microsoft writes these sentences into every record that has nothing to offer: not guidance.
_BOILERPLATE = re.compile(r"has not identified any (?:mitigating factors|workarounds)", re.IGNORECASE)
_BUILD = re.compile(r"^(?:10\.0\.)?(\d{4,6})(?:\.(\d+))?$")


def clean_text(s: Any) -> str:
    """Plain text from an MSRC note (HTML fragments, entities, runs of white space)."""
    if not isinstance(s, str):
        return ""
    s = _BR.sub("\n", s)
    s = html.unescape(_TAGS.sub("", s))
    s = re.sub(r"[ \t\r\f\v]+", " ", s)
    s = re.sub(r"\n\s*\n+", "\n", s).strip()
    return s[:MAX_TEXT]


def parse_build(build: str) -> tuple[int, int] | None:
    """`10.0.22631.3593` -> (22631, 3593); `22631.3593` too; None when not a build."""
    m = _BUILD.match((build or "").strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2) or 0)


def _val(x: Any) -> str:
    """CVRF wraps most strings as {"Value": "..."}."""
    if isinstance(x, dict):
        return str(x.get("Value") or "")
    return str(x or "")


def _product_names(tree: dict) -> dict[str, str]:
    out: dict[str, str] = {}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if "ProductID" in node and ("Value" in node or "Name" in node):
                out[str(node["ProductID"])] = str(node.get("Value") or node.get("Name") or "")
            for v in node.values():
                if isinstance(v, (dict, list)):
                    walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(tree or {})
    return out


def _is_windows_os(name: str) -> bool:
    return name.startswith("Windows ")


def parse_document(doc: dict) -> dict[str, dict]:
    """Compact {cve_id: record} of the Windows operating-system CVEs in one monthly document."""
    names = _product_names(doc.get("ProductTree") or {})
    tracking = doc.get("DocumentTracking") or {}
    alias = _val((tracking.get("Identification") or {}).get("Alias")) or _val(
        (tracking.get("Identification") or {}).get("ID"))
    released = str(tracking.get("InitialReleaseDate") or "")[:10]
    out: dict[str, dict] = {}
    for v in doc.get("Vulnerability") or []:
        cve = str(v.get("CVE") or "")
        if not cve.startswith("CVE-"):
            continue
        fixes: list[dict] = []
        mit: list[str] = []
        wk: list[str] = []
        for r in v.get("Remediations") or []:
            rtype = r.get("Type")
            pids = [str(p) for p in r.get("ProductID") or []]
            if rtype == R_VENDOR_FIX:
                m = _KB.match(_val(r.get("Description")).strip())
                build = str(r.get("FixedBuild") or "")
                for pid in pids:
                    pname = names.get(pid, "")
                    if not _is_windows_os(pname) or (not m and not build):
                        continue
                    f: dict[str, Any] = {"p": pname}
                    if m:
                        f["kb"] = m.group(1)
                    if build:
                        f["b"] = build
                    rs = _val(r.get("RestartRequired")).strip().lower()
                    if rs in ("yes", "no"):
                        f["rs"] = rs == "yes"
                    sup = str(r.get("Supercedence") or "").strip()
                    if sup:
                        f["sup"] = sup[:120]
                    if f not in fixes:
                        fixes.append(f)
            elif rtype in (R_MITIGATION, R_WORKAROUND):
                text = clean_text(_val(r.get("Description")))
                target = mit if rtype == R_MITIGATION else wk
                if text and not _BOILERPLATE.search(text) and text not in target and len(target) < MAX_NOTES:
                    target.append(text)
        if not fixes:
            continue
        expl = ""
        for t in v.get("Threats") or []:
            if t.get("Type") == 1 and _val(t.get("Description")):
                expl = _val(t.get("Description"))[:300]
                break
        rec: dict[str, Any] = {"t": _val(v.get("Title"))[:255], "m": alias, "rel": released, "fix": fixes}
        if expl:
            rec["expl"] = expl
        if mit:
            rec["mit"] = mit
        if wk:
            rec["wk"] = wk
        out[cve] = rec
    return out


def _updates_index(base: str) -> list[dict]:
    data = feeds._request("msrc", "GET", f"{base}/updates", min_interval=1.0)
    items = data.get("value") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise feeds.FeedError("api.msrc.microsoft.com returned an unexpected updates index")
    rows = [i for i in items if isinstance(i, dict) and i.get("ID")]
    rows.sort(key=lambda i: str(i.get("InitialReleaseDate") or ""), reverse=True)
    return rows


def refresh(db: Session, now: datetime | None = None) -> tuple[bool, str | None]:
    """Refresh the cached MSRC data (changed / new monthly documents only). Returns
    (ok, error); never raises. The caller commits."""
    now = now or utcnow()
    s = config.settings
    row = feeds.cache_get(db, CACHE_KEY)
    data = row.data if row is not None else {}
    months: dict[str, str] = dict(data.get("months") or {})
    cves: dict[str, dict] = dict(data.get("cves") or {})
    try:
        index = _updates_index(s.msrc_api_url)[:s.msrc_months]
        keep = {str(i["ID"]) for i in index}
        for alias in list(months):
            if alias not in keep:
                months.pop(alias)
                cves = {c: r for c, r in cves.items() if r.get("m") != alias}
        err: str | None = None
        for item in reversed(index):  # oldest first, so a newer month wins for a revised CVE
            alias = str(item["ID"])
            stamp = str(item.get("CurrentReleaseDate") or item.get("InitialReleaseDate") or "")
            if months.get(alias) == stamp:
                continue
            try:
                doc = feeds._request("msrc", "GET", f"{s.msrc_api_url}/cvrf/{alias}", min_interval=1.0)
            except feeds.FeedError as e:
                err = err or f"{alias}: {e}"
                if str(e).startswith("cannot reach"):
                    break  # offline: do not retry every remaining month
                continue  # one bad document does not stop the others
            parsed = parse_document(doc if isinstance(doc, dict) else {})
            cves = {c: r for c, r in cves.items() if r.get("m") != alias}
            for c, r in parsed.items():
                r["m"] = alias
                cves[c] = r
            months[alias] = stamp
        feeds.cache_put(db, CACHE_KEY, {"months": months, "cves": cves, "synced_at": now.isoformat()},
                        RETENTION, now)
        if err:
            feeds.record_status(db, "msrc", ok=False, error=err, now=now)
            return False, err
        feeds.record_status(db, "msrc", ok=True, items=len(cves), now=now)
        return True, None
    except feeds.FeedError as e:
        log.warning("MSRC refresh failed: %s", e)
        feeds.record_status(db, "msrc", ok=False, error=str(e), now=now)
        return False, str(e)
    except Exception as e:  # a malformed document must not stop anything else
        log.exception("MSRC refresh failed")
        feeds.record_status(db, "msrc", ok=False, error=f"{e.__class__.__name__}: {e}", now=now)
        return False, str(e)


def load(db: Session) -> dict[str, dict]:
    """{cve_id: record} from the cache ({} when never fetched / feed unavailable)."""
    row = feeds.cache_get(db, CACHE_KEY)
    return dict((row.data.get("cves") or {}) if row is not None else {})


def lookup(db: Session, cve_id: str) -> dict | None:
    return load(db).get(cve_id)
