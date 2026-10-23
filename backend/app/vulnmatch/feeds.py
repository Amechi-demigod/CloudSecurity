"""Vulnerability feeds: NVD CVE API 2.0, OSV.dev, CISA KEV, FIRST EPSS.

All HTTP goes through one httpx client factory with `trust_env=True`, so
HTTPS_PROXY / HTTP_PROXY / NO_PROXY / SSL_CERT_FILE from cnapp.env apply. Tests
swap the transport with `set_transport()` (no network in tests).

Responses are cached in `vuln_feed_cache` with an expiry: a failed refresh
keeps using the last good copy (offline operation), records the error in
`vuln_feed_status` and never raises into a check-in.

NVD terms: https://nvd.nist.gov/developers/terms-of-use - requests are spaced
(6 s without an API key, 0.7 s with one), retried with back-off on 403/429/5xx,
and NVD data is refreshed incrementally (lastModStartDate) instead of being
re-downloaded. The NVD_API_KEY is sent as the `apiKey` header and never logged.
"""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

import httpx
from sqlalchemy.orm import Session

from .. import config
from ..models import VulnFeedCache, VulnFeedStatus, utcnow
from .cpe import compact_configurations, product_key, split_cpe
from .versions import cvss3_base_score

log = logging.getLogger(__name__)

USER_AGENT = "cnapp-vulnerability-matcher (+https://github.com/Amechi-demigod/CloudSecurity)"
NVD_PAGE = 2000
NVD_MAX_WINDOW = timedelta(days=110)  # NVD allows lastMod ranges of up to 120 days
# Full re-download of a product this often (incremental updates cannot see a
# CVE whose configuration stopped mentioning the product).
NVD_FULL_REFRESH = timedelta(days=30)
OSV_BATCH = 1000
EPSS_BATCH = 100
DESC_MAX = 400

_transport: httpx.BaseTransport | None = None
_sleep: Callable[[float], None] = time.sleep
_rate_lock = threading.Lock()
_last_request: dict[str, float] = {}


class FeedError(Exception):
    """A feed could not be reached / parsed. The message never contains secrets."""


def set_transport(transport: httpx.BaseTransport | None, sleep: Callable[[float], None] | None = None) -> None:
    """Tests: route all feed HTTP through `transport` (e.g. httpx.MockTransport)."""
    global _transport, _sleep
    _transport = transport
    _sleep = sleep or (time.sleep if transport is None else (lambda _s: None))
    _last_request.clear()


def _client() -> httpx.Client:
    kw: dict[str, Any] = {"timeout": httpx.Timeout(60.0, connect=15.0), "follow_redirects": True,
                          "headers": {"User-Agent": USER_AGENT, "Accept": "application/json"}}
    if _transport is not None:
        kw["transport"] = _transport
    else:
        kw["trust_env"] = True  # HTTPS_PROXY / NO_PROXY / SSL_CERT_FILE
    return httpx.Client(**kw)


def _space(feed: str, min_interval: float) -> None:
    with _rate_lock:
        last = _last_request.get(feed)
        now = time.monotonic()
        if last is not None and now - last < min_interval:
            _sleep(min_interval - (now - last))
        _last_request[feed] = time.monotonic()


def _request(feed: str, method: str, url: str, *, params: dict | None = None, json: Any = None,
             headers: dict | None = None, min_interval: float = 0.0, retries: int = 3) -> Any:
    delay = max(min_interval, 2.0)
    for attempt in range(retries + 1):
        _space(feed, min_interval)
        try:
            with _client() as c:
                r = c.request(method, url, params=params, json=json, headers=headers)
        except httpx.HTTPError as e:
            err = f"cannot reach {httpx.URL(url).host}: {e.__class__.__name__}"
            if attempt >= retries:
                raise FeedError(err) from None
            _sleep(delay * (2 ** attempt))
            continue
        if r.status_code == 200:
            try:
                return r.json()
            except ValueError:
                raise FeedError(f"{httpx.URL(url).host} did not return JSON") from None
        if r.status_code in (403, 429) or r.status_code >= 500:
            if attempt >= retries:
                raise FeedError(f"{httpx.URL(url).host} returned HTTP {r.status_code}")
            retry_after = r.headers.get("Retry-After", "")
            _sleep(float(retry_after) if retry_after.isdigit() else delay * (2 ** attempt))
            continue
        raise FeedError(f"{httpx.URL(url).host} returned HTTP {r.status_code}")
    raise FeedError("unreachable")  # pragma: no cover


# ----------------------------------------------------------------------------- cache + status
def cache_get(db: Session, key: str) -> VulnFeedCache | None:
    return db.get(VulnFeedCache, key)


def cache_put(db: Session, key: str, data: dict, ttl: timedelta, now: datetime | None = None) -> VulnFeedCache:
    now = now or utcnow()
    row = db.get(VulnFeedCache, key)
    if row is None:
        row = VulnFeedCache(key=key)
        db.add(row)
    row.data = data
    row.fetched_at = now
    row.expires_at = now + ttl
    return row


def record_status(db: Session, feed: str, *, ok: bool, error: str | None = None, items: int | None = None,
                  now: datetime | None = None) -> None:
    now = now or utcnow()
    row = db.get(VulnFeedStatus, feed)
    if row is None:
        row = VulnFeedStatus(feed=feed)
        db.add(row)
    row.last_attempt_at = now
    if ok:
        row.last_success_at = now
        row.last_error = None
        if items is not None:
            row.items = items
    else:
        row.last_error = (error or "unknown error")[:1000]


# ----------------------------------------------------------------------------- NVD
def _nvd_headers() -> dict[str, str]:
    key = config.settings.nvd_api_key
    return {"apiKey": key} if key else {}


def _nvd_interval() -> float:
    return 0.7 if config.settings.nvd_api_key else 6.0


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def pick_cvss(metrics: dict) -> tuple[float, str, str]:
    """(score, severity, vector): NVD primary v3.1, then v3.0, v4.0, v2."""
    for name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        items = metrics.get(name) or []
        if not items:
            continue
        items = sorted(items, key=lambda m: 0 if m.get("type") == "Primary" else 1)
        d = items[0].get("cvssData") or {}
        score = float(d.get("baseScore") or 0.0)
        sev = (d.get("baseSeverity") or items[0].get("baseSeverity") or "").lower()
        return score, sev, d.get("vectorString") or ""
    return 0.0, "", ""


def compact_cve(cve: dict, key: str) -> dict | None:
    """The fields matching needs from one NVD CVE record, for product `key`."""
    if (cve.get("vulnStatus") or "").lower() == "rejected":
        return None
    cfg = compact_configurations(cve.get("configurations") or [], key)
    if not cfg:
        return None
    score, sev, vector = pick_cvss(cve.get("metrics") or {})
    desc = next((d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
    return {"cvss": score, "sev": sev, "vec": vector, "pub": cve.get("published"), "desc": desc[:DESC_MAX],
            "cfg": cfg}


def nvd_cpe_prefix(cpe: str) -> str:
    """`a:google:chrome` -> `cpe:2.3:a:google:chrome` (escapes kept as written)."""
    return f"cpe:2.3:{cpe}"


def cpe_key(cpe: str) -> str:
    part, vendor, product = (split_cpe(cpe) + ["", "", ""])[:3]
    return product_key(part, vendor, product)


def fetch_nvd_product(cpe: str, since: datetime | None = None, now: datetime | None = None) -> dict[str, Any]:
    """All CVEs whose configurations mention `cpe` (`part:vendor:product`),
    optionally only those modified since `since`. Returns {cve_id: compact|None}."""
    s = config.settings
    key = cpe_key(cpe)
    params: dict[str, Any] = {"virtualMatchString": nvd_cpe_prefix(cpe), "resultsPerPage": NVD_PAGE}
    if since is not None:
        params["lastModStartDate"] = _iso(since)
        params["lastModEndDate"] = _iso(now or utcnow())
    out: dict[str, Any] = {}
    start = 0
    while True:
        params["startIndex"] = start
        data = _request("nvd", "GET", s.nvd_api_url, params=params, headers=_nvd_headers(),
                        min_interval=_nvd_interval())
        vulns = data.get("vulnerabilities") or []
        for item in vulns:
            cve = item.get("cve") or {}
            if cve.get("id"):
                out[cve["id"]] = compact_cve(cve, key)
        total = int(data.get("totalResults") or 0)
        start += int(data.get("resultsPerPage") or len(vulns) or NVD_PAGE)
        if not vulns or start >= total:
            return out


def nvd_product(db: Session, cpe: str, now: datetime | None = None, *, allow_fetch: bool = True
                ) -> tuple[dict[str, Any] | None, str | None]:
    """Cached CVE data of one CPE product: ({cve_id: compact}, error).

    Fresh cache -> as is. Stale or missing -> incremental (or full) refresh;
    on failure the stale copy is returned with the error, or (None, error)."""
    now = now or utcnow()
    ttl = timedelta(hours=config.settings.vuln_nvd_cache_hours)
    ck = f"nvd:{cpe_key(cpe)}"
    row = cache_get(db, ck)
    if row is not None and row.expires_at > now:
        return row.data.get("cves") or {}, None
    if not allow_fetch:
        return (row.data.get("cves") or {}, "NVD refresh deferred") if row is not None else (None, "not fetched yet")
    try:
        watermark = None
        full_at = row.data.get("full_at") if row is not None else None
        if row is not None and row.data.get("synced_at") and full_at:
            watermark = datetime.fromisoformat(row.data["synced_at"])
            if now - watermark > NVD_MAX_WINDOW or now - datetime.fromisoformat(full_at) > NVD_FULL_REFRESH:
                watermark = None
        changes = fetch_nvd_product(cpe, since=watermark - timedelta(minutes=5) if watermark else None, now=now)
        cves = dict(row.data.get("cves") or {}) if (row is not None and watermark is not None) else {}
        for cid, c in changes.items():
            if c is None:
                cves.pop(cid, None)
            else:
                cves[cid] = c
        cache_put(db, ck, {"cpe": cpe, "cves": cves, "synced_at": now.isoformat(),
                           "full_at": full_at if watermark is not None else now.isoformat()}, ttl, now)
        record_status(db, "nvd", ok=True, now=now, items=None)
        return cves, None
    except FeedError as e:
        log.warning("NVD refresh of %s failed: %s", cpe, e)
        record_status(db, "nvd", ok=False, error=f"{cpe}: {e}", now=now)
        if row is not None:
            return row.data.get("cves") or {}, str(e)
        return None, str(e)


# ----------------------------------------------------------------------------- OSV
def osv_querybatch(queries: list[dict]) -> list[list[dict]]:
    """Vuln {id, modified} lists, one per query (follows next_page_token)."""
    url = f"{config.settings.osv_api_url}/v1/querybatch"
    results: list[list[dict]] = []
    for i in range(0, len(queries), OSV_BATCH):
        chunk = [dict(q) for q in queries[i:i + OSV_BATCH]]
        acc: list[list[dict]] = [[] for _ in chunk]
        pending = list(range(len(chunk)))
        for _ in range(20):  # pagination rounds
            body = {"queries": [chunk[j] for j in pending]}
            data = _request("osv", "POST", url, json=body)
            res = data.get("results") or []
            nxt = []
            for idx, r in zip(pending, res, strict=False):
                acc[idx].extend(r.get("vulns") or [])
                if r.get("next_page_token"):
                    chunk[idx]["page_token"] = r["next_page_token"]
                    nxt.append(idx)
            if not nxt:
                break
            pending = nxt
        results.extend(acc)
    return results


def osv_vuln(db: Session, vuln_id: str, modified: str | None, now: datetime | None = None) -> dict | None:
    """Full OSV record (cached by id; refetched when `modified` changed)."""
    now = now or utcnow()
    ck = f"osv:{vuln_id}"
    row = cache_get(db, ck)
    if row is not None and (modified is None or row.data.get("modified") == modified) and row.expires_at > now:
        return row.data
    try:
        data = _request("osv", "GET", f"{config.settings.osv_api_url}/v1/vulns/{vuln_id}")
    except FeedError:
        if row is not None:
            return row.data
        raise
    slim = {k: data.get(k) for k in ("id", "modified", "summary", "aliases", "upstream", "severity",
                                     "affected", "database_specific", "published")}
    slim["details"] = (data.get("details") or "")[:DESC_MAX]
    for a in slim.get("affected") or []:
        a.pop("versions", None)  # long explicit version lists are not needed
    cache_put(db, ck, slim, timedelta(hours=config.settings.vuln_osv_cache_hours * 7), now)
    return slim


SEVERITY_LABEL_CVSS = {"critical": 9.0, "high": 7.5, "important": 7.5, "medium": 5.0, "moderate": 5.0,
                       "low": 2.5, "negligible": 1.0}


def osv_score(rec: dict) -> tuple[float, str | None, bool]:
    """(cvss, vector, scored) from an OSV record. Falls back to the distro's
    severity label; `scored` is False when neither exists (default 5.0)."""
    for sev in rec.get("severity") or []:
        if sev.get("type") in ("CVSS_V3", "CVSS_V31", "CVSS_V30"):
            score = cvss3_base_score(sev.get("score") or "")
            if score is not None:
                return score, sev.get("score"), True
    labels: list[str] = []
    for sev in rec.get("severity") or []:
        if sev.get("type") in ("Ubuntu", "Debian") and sev.get("score"):
            labels.append(str(sev["score"]))
    ds = rec.get("database_specific") or {}
    if isinstance(ds.get("severity"), str):
        labels.append(ds["severity"])
    summary = rec.get("summary") or ""
    if ":" in summary[:12]:
        labels.append(summary.split(":", 1)[0])  # Red Hat / Rocky / Alma: "Moderate: openssl update"
    for a in rec.get("affected") or []:
        es = a.get("ecosystem_specific") or {}
        if isinstance(es.get("severity"), str):
            labels.append(es["severity"])
    for lab in labels:
        v = SEVERITY_LABEL_CVSS.get(lab.strip().lower())
        if v is not None:
            return v, None, True
    return 5.0, None, False


# ----------------------------------------------------------------------------- KEV / EPSS
def fetch_kev() -> dict[str, dict]:
    data = _request("kev", "GET", config.settings.kev_url)
    out = {}
    for v in data.get("vulnerabilities") or []:
        cid = v.get("cveID")
        if cid:
            out[cid] = {"added": v.get("dateAdded"), "due": v.get("dueDate"),
                        "ransomware": v.get("knownRansomwareCampaignUse"), "name": v.get("vulnerabilityName"),
                        "action": (v.get("requiredAction") or "")[:300]}
    if not out:
        raise FeedError("KEV catalog was empty")
    return out


def kev_catalog(db: Session) -> dict[str, dict]:
    row = cache_get(db, "kev")
    return (row.data.get("cves") or {}) if row is not None else {}


def fetch_epss(cves: list[str]) -> dict[str, float]:
    out: dict[str, float] = {}
    for i in range(0, len(cves), EPSS_BATCH):
        chunk = cves[i:i + EPSS_BATCH]
        data = _request("epss", "GET", config.settings.epss_api_url, params={"cve": ",".join(chunk)})
        for d in data.get("data") or []:
            try:
                out[d["cve"]] = float(d["epss"])
            except (KeyError, TypeError, ValueError):
                continue
    return out
