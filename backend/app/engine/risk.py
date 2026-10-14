"""Risk scoring.

Vulnerability risk combines the CVSS base score with *runtime context* so that
vulnerabilities in packages that are actually loaded and reachable outrank
dormant ones:

    base     = cvss / 10                                   (0..1)
    runtime  = 1.0 if the package is loaded at runtime else 0.2
    context  = 0.4 + 0.25*internet_exposed + 0.20*exploit_available
                   + 0.15*sensitive_data_access             (0.4..1.0)
    risk     = 100 * base * runtime * context               (0..100)

Properties guaranteed by the formula (and covered by tests):
* A dormant vuln can never exceed 20, regardless of CVSS.
* An in-use, internet-exposed vuln with CVSS >= 5 scores >= 32.5, so it always
  ranks above any dormant one.
"""
from __future__ import annotations

import math
from collections.abc import Iterable

DORMANT_FACTOR = 0.2


def vuln_risk_score(
    cvss: float,
    in_use: bool,
    internet_exposed: bool,
    exploit_available: bool,
    sensitive_data_access: bool,
) -> float:
    cvss = max(0.0, min(10.0, float(cvss)))
    base = cvss / 10.0
    runtime = 1.0 if in_use else DORMANT_FACTOR
    context = 0.4 + 0.25 * internet_exposed + 0.20 * exploit_available + 0.15 * sensitive_data_access
    return round(100.0 * base * runtime * context, 1)


def priority_for(score: float) -> str:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def cvss_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def noise_reduction(in_use_flags: Iterable[bool]) -> dict:
    """% of vulnerabilities deprioritized because the package isn't loaded at runtime."""
    flags = list(in_use_flags)
    total = len(flags)
    dormant = sum(1 for f in flags if not f)
    pct = round(100.0 * dormant / total, 1) if total else 0.0
    return {"total": total, "in_use": total - dormant, "dormant": dormant, "percent": pct}


# Weights used for the overall environment risk score.
FINDING_W = {"critical": 8.0, "high": 4.0, "medium": 1.5, "low": 0.5, "info": 0.0}
ALERT_W = {"critical": 12.0, "high": 6.0, "medium": 2.0, "low": 0.5, "info": 0.0}


def overall_risk_score(
    finding_severities: Iterable[str],
    vuln_scores: Iterable[float],
    alert_severities: Iterable[str],
    attack_path_count: int = 0,
    asset_count: int = 1,
) -> float:
    """0 (no risk) .. 100 (extreme). Saturating so it never overflows.

    Normalised by environment size so a big estate isn't automatically 100.
    """
    w = sum(FINDING_W.get(s, 0) for s in finding_severities)
    w += sum(s / 20.0 for s in vuln_scores if s >= 70)  # only critical-priority vulns
    w += sum(ALERT_W.get(s, 0) for s in alert_severities)
    w += 5.0 * attack_path_count
    scale = max(50.0, asset_count * 5.0)
    return round(100.0 * (1.0 - math.exp(-w / scale)), 1)
