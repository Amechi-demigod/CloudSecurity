"""Certificate transparency through the crt.sh JSON endpoint (configurable, can be disabled). One query per domain,
cached in the process, capped in size and time. Only certificates for names equal to or below the verified domain
are kept."""
from __future__ import annotations

import re
import threading
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse

from .. import service as ext_service
from .hits import Hit

NAME_RE = ext_service.DOMAIN_RE
MAX_ROWS = 5000  # rows read from the response before filtering
_cache: dict[str, tuple[float, list[dict]]] = {}
_lock = threading.Lock()


class CtError(Exception):
    pass


def clear_cache() -> None:
    with _lock:
        _cache.clear()


def fetch(domain: str, url: str, timeout: float) -> list[dict]:
    """The raw JSON rows for `%.domain` (the only network call of the reputation module besides DNS)."""
    import httpx

    if urlparse(url).scheme != "https":
        raise CtError("the certificate transparency URL must be https")
    try:
        r = httpx.get(url, params={"q": f"%.{domain}", "output": "json"}, timeout=timeout,
                      headers={"User-Agent": "Sentrigis-Reputation/1.0"}, follow_redirects=False)
        r.raise_for_status()
        rows = r.json()
    except Exception as e:
        raise CtError(f"certificate transparency source failed ({type(e).__name__})") from None
    if not isinstance(rows, list):
        raise CtError("unexpected certificate transparency response")
    return rows[:MAX_ROWS]


FETCH = fetch  # tests replace it


def cached_rows(domain: str, url: str, timeout: float, ttl: float, clock=time.monotonic) -> list[dict]:
    now = clock()
    with _lock:
        hit = _cache.get(domain)
        if hit and ttl > 0 and now - hit[0] < ttl:
            return hit[1]
    rows = FETCH(domain, url, timeout)
    with _lock:
        _cache[domain] = (now, rows)
        if len(_cache) > 200:
            _cache.pop(next(iter(_cache)))
    return rows


def issuer_of(issuer_name: str) -> str:
    m = re.search(r"(?:^|,\s*)O=([^,]+)", issuer_name or "") or re.search(r"(?:^|,\s*)CN=([^,]+)", issuer_name or "")
    return (m.group(1).strip().strip('"') if m else (issuer_name or "unknown").strip())[:100] or "unknown"


def _when(v) -> datetime | None:
    try:
        return datetime.fromisoformat(str(v).replace("Z", "").split("+")[0].replace(" ", "T")[:19])
    except ValueError:
        return None


def parse(domain: str, rows: list[dict], now: datetime, days: int, cap: int) -> list[dict]:
    """Certificates issued (not_before) in the last `days` days, newest first, at most `cap`:
    [{issuer, names, wildcard, not_before, not_after, logged_at}]. Duplicates (precert + cert) are merged."""
    since = now - timedelta(days=days)
    out: dict[tuple, dict] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        nb = _when(row.get("not_before"))
        if nb is None or nb < since or nb > now + timedelta(days=1):
            continue
        names, wildcard = set(), False
        for n in str(row.get("name_value", "")).replace(",", "\n").split("\n"):
            n = n.strip().lower().rstrip(".")
            star = n.startswith("*.")
            n = n.removeprefix("*.")
            if (n == domain or n.endswith("." + domain)) and NAME_RE.match(n):
                names.add(("*." if star else "") + n)
                wildcard = wildcard or star
        if not names:
            continue
        issuer = issuer_of(str(row.get("issuer_name", "")))
        na = _when(row.get("not_after"))
        key = (issuer, tuple(sorted(names)), nb.isoformat())
        out.setdefault(key, {"issuer": issuer, "names": sorted(names)[:20], "name_count": len(names),
                             "wildcard": wildcard, "not_before": nb.isoformat(),
                             "not_after": na.isoformat() if na else None,
                             "logged_at": (_when(row.get("entry_timestamp")) or nb).isoformat()})
    return sorted(out.values(), key=lambda c: (c["not_before"], c["issuer"]), reverse=True)[:cap]


def hits_for(domain: str, certs: list[dict], new_issuers: list[str]) -> list[Hit]:
    hits: list[Hit] = []
    for iss in sorted(new_issuers):
        ex = [c for c in certs if c["issuer"] == iss][:5]
        hits.append(Hit(
            "rep.ct_new_issuer", "certificate", domain, "low", f"Certificate from a new issuer: {iss}",
            f"A certificate for {domain} or one of its subdomains was issued by {iss}, which has not issued a "
            "certificate for this domain before. This is often a new service or a team using a different "
            "provider, but it can also be a certificate requested by someone who should not have one.",
            "Check that the certificate was requested by your organisation. If not, contact the issuer to revoke it "
            "and look for a compromised DNS or hosting account. Consider a CAA record to limit who may issue.",
            subject=iss, evidence={"issuer": iss, "certificates": ex}))
    wild = [c for c in certs if c["wildcard"]]
    if wild:
        hits.append(Hit(
            "rep.ct_wildcard", "certificate", domain, "info",
            f"{len(wild)} wildcard certificate{'s' if len(wild) != 1 else ''} issued recently",
            "Wildcard certificates cover every subdomain, so a stolen private key has a wide impact. They are "
            "legitimate and common; this is for awareness.",
            "Make sure wildcard keys are stored securely and used on as few servers as possible.",
            evidence={"certificates": wild[:5]}))
    return hits
