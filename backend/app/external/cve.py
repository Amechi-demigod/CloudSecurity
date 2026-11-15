"""Known CVEs and end-of-life detection for software versions seen in banners, using the platform's existing NVD
cache and matcher (app/vulnmatch). Versions from banners can be backported by distributions: such findings say so
and can be disputed."""
from __future__ import annotations

import re
from datetime import datetime

from sqlalchemy.orm import Session

from ..vulnmatch import feeds
from ..vulnmatch.cpe import Installed, cve_matches
from ..vulnmatch.matcher import DEFAULT_CVSS, _severity
from .rules import AUTO_FAIL_CWES

CPES = {"apache": "a:apache:http_server", "nginx": "a:nginx:nginx", "iis": "a:microsoft:internet_information_services",
        "openssh": "a:openbsd:openssh", "proftpd": "a:proftpd:proftpd", "vsftpd": "a:vsftpd_project:vsftpd",
        "php": "a:php:php", "exim": "a:exim:exim", "lighttpd": "a:lighttpd:lighttpd", "openssl": "a:openssl:openssl"}
LABELS = {"apache": "Apache HTTP Server", "nginx": "nginx", "iis": "Microsoft IIS", "openssh": "OpenSSH",
          "proftpd": "ProFTPD", "vsftpd": "vsftpd", "php": "PHP", "exim": "Exim", "lighttpd": "lighttpd",
          "openssl": "OpenSSL"}
MAX_PER_PRODUCT = 15


def _ver(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3]) or (0,)


def eol(product: str, version: str) -> str | None:
    """Why this version is unsupported, or None (only products where end of life is unambiguous)."""
    v = _ver(version)
    if product == "php" and v < (8, 1):
        return "PHP releases before 8.1 no longer receive security fixes"
    if product == "apache" and v < (2, 4):
        return "Apache HTTP Server 2.2 and earlier are end of life"
    if product == "iis" and v < (8, 5):
        return "IIS " + version + " ships with Windows Server 2012 or earlier, which is out of support"
    if product == "openssl" and v < (1, 1, 1):
        return "OpenSSL releases before 1.1.1 are end of life"
    if product == "openssh" and v < (7, 4):
        return "this OpenSSH release is far out of date and unsupported"
    return None


def is_dos_only(vector: str | None) -> bool:
    if not vector:
        return False
    parts = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    return parts.get("C") == "N" and parts.get("I") == "N" and parts.get("A") in ("L", "H")


def lookup(db: Session, product: str, version: str, now: datetime, *, allow_fetch: bool = True) -> list[dict]:
    """CVEs affecting `product version` from the NVD cache: [{cve_id, cvss, severity, vector, cwe, description,
    fixed_version, published, dos_only}] (highest CVSS first, capped)."""
    cpe = CPES.get(product)
    if not cpe:
        return []
    data, _err = feeds.nvd_product(db, cpe, now, allow_fetch=allow_fetch)
    db.commit()
    if not data:
        return []
    inst = Installed(feeds.cpe_key(cpe), version)
    out = []
    for cve_id, c in data.items():
        if c is None:
            continue
        res = cve_matches(c.get("cfg") or [], inst, [])
        if res is None:
            continue
        cvss = float(c.get("cvss") or 0.0) or DEFAULT_CVSS
        cwes = list(c.get("cwe") or [])
        pick = next((x for x in cwes if x in AUTO_FAIL_CWES), cwes[0] if cwes else None)
        out.append({"cve_id": cve_id, "cvss": cvss, "severity": _severity(c.get("sev") or "", cvss),
                    "vector": c.get("vec") or None, "cwe": pick,
                    "description": (c.get("desc") or "")[:600], "fixed_version": res.fixed_version,
                    "published": c.get("pub"), "dos_only": is_dos_only(c.get("vec"))})
    out.sort(key=lambda x: -x["cvss"])
    return out[:MAX_PER_PRODUCT]
