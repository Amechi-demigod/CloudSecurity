"""Fix-due dates (SLA) of vulnerabilities, shared by the CVE page and the device fix list.

    known exploited (CISA KEV)  the KEV due date when the catalog states one, else 14 days
    critical 7 days, high 14, medium 30, low 90 (days after the vulnerability was first seen)

This is a display helper for "Fix due": the dashboard / compliance SLA (DASHBOARD_SLA_*_DAYS) is a
separate, configurable measure and is not changed by it.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any

SLA_DAYS = {"critical": 7, "high": 14, "medium": 30, "low": 90}
KEV_DEFAULT_DAYS = 14


def sla_days(severity: str, kev: bool = False) -> int:
    return KEV_DEFAULT_DAYS if kev else SLA_DAYS.get(severity, SLA_DAYS["low"])


def _kev_due(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        return datetime.combine(date.fromisoformat(str(raw)[:10]), datetime.min.time())
    except ValueError:
        return None


def fix_due(first_seen: datetime, severity: str, *, kev: bool = False, kev_due: str | None = None,
            now: datetime) -> dict[str, Any]:
    """{"due_at": naive-UTC datetime, "basis": str, "overdue_days": int | None, "days_left": int | None}."""
    due = _kev_due(kev_due) if kev else None
    if due is not None:
        basis = "CISA KEV due date"
    elif kev:
        due, basis = first_seen + timedelta(days=KEV_DEFAULT_DAYS), f"{KEV_DEFAULT_DAYS} days (known exploited)"
    else:
        days = sla_days(severity)
        due, basis = first_seen + timedelta(days=days), f"{days} days ({severity})"
    delta = (now - due).total_seconds() / 86400
    if delta > 0:
        return {"due_at": due, "basis": basis, "overdue_days": max(1, int(delta)), "days_left": None}
    return {"due_at": due, "basis": basis, "overdue_days": None, "days_left": max(0, int(-delta))}
