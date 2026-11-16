"""Pre-ASV pass / fail rules (modelled on the PCI ASV Program Guide; NOT an ASV decision).

| Rule | Result |
|---|---|
| Open finding with CVSS base score >= 4.0 | fail |
| SSLv3, TLS 1.0 or TLS 1.1 offered (tls-sslv3 / tls-tls10 / tls-tls11) | automatic fail, whatever the score |
| SQL injection or cross-site scripting indicated (CWE-89 / CWE-79 on a matched CVE; no payloads are sent) | automatic fail |
| Vendor default credentials accepted (opt-in check) | automatic fail |
| End-of-life / unsupported software detected from banners (eol-software) | automatic fail |
| Expired, self-signed, untrusted or mismatched certificate | fail through its CVSS score (>= 4.0) |
| Denial-of-service-only vulnerability (confidentiality and integrity impact none) | never fails |
| Accepted dispute (false positive / compensating control) | does not fail; listed in Part 3a exceptions |
| Resolved finding | not counted |
| "Accepted risk" status | still counts: a customer cannot waive an ASV failure by accepting the risk |

A component (host) passes when none of its counted findings fails. The overall result is "Likely pass" only when
every component passes. Unsure points are marked in docs/ATTACK_SURFACE.md."""
from __future__ import annotations

from typing import Any

FAIL_CVSS = 4.0
AUTO_FAIL_CHECKS = frozenset({"tls-sslv3", "tls-tls10", "tls-tls11", "default-credentials", "eol-software"})
AUTO_FAIL_CWES = frozenset({"CWE-89", "CWE-79"})

RULE_TABLE: list[dict[str, str]] = [
    {"rule": "CVSS base score 4.0 or higher", "result": "Fail"},
    {"rule": "SSLv3, TLS 1.0 or TLS 1.1 offered", "result": "Automatic fail"},
    {"rule": "SQL injection or cross-site scripting indicated (CWE-89 / CWE-79)", "result": "Automatic fail"},
    {"rule": "Vendor default credentials accepted", "result": "Automatic fail"},
    {"rule": "End-of-life or unsupported software detected", "result": "Automatic fail"},
    {"rule": "Denial-of-service-only vulnerability", "result": "Does not fail"},
    {"rule": "Accepted dispute (false positive / compensating control)", "result": "Does not fail (exception)"},
]

# Marker fields of the finding model used here (works with ORM rows and dicts).


def _get(f: Any, name: str, default=None):
    return f.get(name, default) if isinstance(f, dict) else getattr(f, name, default)


def fail_reason(f: Any) -> str | None:
    """Why the finding fails a pre-ASV scan, or None. Ignores status and disputes (see `counts`)."""
    check_id, cwe = _get(f, "check_id", ""), _get(f, "cwe")
    if _get(f, "auto_fail", False) or check_id in AUTO_FAIL_CHECKS or (cwe in AUTO_FAIL_CWES):
        return "automatic fail"
    if _get(f, "dos_only", False):
        return None
    if float(_get(f, "cvss", 0) or 0) >= FAIL_CVSS:
        return f"CVSS {float(_get(f, 'cvss', 0)):g} is 4.0 or higher"
    return None


def counts(f: Any, exempt: bool = False) -> bool:
    """True when the finding fails the scan: open (not resolved), not exempted by an accepted dispute."""
    if _get(f, "status") == "resolved" or exempt:
        return False
    return fail_reason(f) is not None


def overall(failing: int) -> str:
    return "fail" if failing else "pass"


def label(result: str | None) -> str:
    return {"pass": "Likely pass", "fail": "Likely fail"}.get(result or "", "Not scanned yet")
