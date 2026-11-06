"""Everything the finding detail page and the single-finding PDF add on top of a stored finding:
remediation guidance (with the asset's own names substituted), the fix-by SLA, days open and the
"why this matters here" context (internet exposure, sensitive data, attack-path membership)."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from ..engine import guidance
from ..models import Asset, Finding, get_asset, utcnow
from . import analytics

#: days to fix, counted from the first time the finding was seen
SLA_DAYS = {"critical": 7, "high": 14, "medium": 30, "low": 90}
SECRET_KEY_HINTS = ("secret", "password", "passwd", "token", "key", "credential")


def sla_days(severity: str) -> int | None:
    return SLA_DAYS.get(severity)


def sla_state(f: Finding, now: datetime | None = None) -> dict[str, Any]:
    """`sla_due` (None for severities without an SLA), `days_open`, and `overdue_days` (open findings past due)."""
    now = now or utcnow()
    end = f.resolved_at if f.status == "resolved" and f.resolved_at else now
    days_open = max(0, (end - f.first_seen).days)
    days = sla_days(f.severity)
    due = f.first_seen + timedelta(days=days) if days else None
    overdue = None
    if due is not None and f.status == "open" and now > due:
        overdue = (now - due).days
    return {"sla_days": days, "sla_due": due, "days_open": days_open, "overdue_days": overdue}


def mask_evidence(value: Any, key: str = "") -> Any:
    """Evidence is shown to people and printed: never emit anything that looks like a secret."""
    if any(h in key.lower() for h in SECRET_KEY_HINTS):
        return "********" if value not in (None, "", [], {}) else value
    if isinstance(value, dict):
        return {k: mask_evidence(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_evidence(v, key) for v in value]
    return value


def context(db: Session, asset: Asset | None) -> dict[str, Any]:
    paths = []
    if asset is not None:
        for p in analytics.attack_paths(db, limit=100):
            if any(s.asset_id == asset.id for s in p.steps):
                paths.append({"id": p.id, "title": p.title, "severity": p.severity, "score": p.score})
    return {"internet_exposed": bool(asset and asset.internet_exposed),
            "sensitive_data": bool(asset and asset.sensitive_data), "attack_paths": paths}


def detail(db: Session, f: Finding) -> dict[str, Any]:
    asset = get_asset(db, f.asset_id)
    g = guidance.render(f.rule_id, name=asset.name if asset else None,
                        resource_group=asset.resource_group if asset else None,
                        region=asset.region if asset else None,
                        account=asset.subscription_id if asset else None)
    out: dict[str, Any] = {
        "guidance": g,
        "risk_score": g["risk_score"] if g else None,
        "context": context(db, asset),
        "asset": ({"name": asset.name, "type": asset.type, "provider": asset.provider,
                   "subscription_id": asset.subscription_id, "subscription_name": asset.subscription_name,
                   "resource_group": asset.resource_group, "region": asset.region, "tags": asset.tags or {},
                   "source": asset.source} if asset else None),
        "evidence": mask_evidence(f.evidence or {}),
    }
    out.update(sla_state(f))
    return out
