"""Rule matching, quiet hours and digest scheduling (pure functions, easy to test)."""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import UTC, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .events import SEV_RANK, STATUS_CHANGED


@dataclass
class EventContext:
    """What a rule can match on, from the event plus its asset (if any)."""

    source: str
    event_type: str
    severity: str
    asset_id: str | None = None
    asset_type: str | None = None
    subscription_id: str | None = None
    tags: dict[str, Any] = field(default_factory=dict)
    rule_id: str | None = None
    mitre_technique_id: str | None = None


def build_context(ev, asset=None) -> EventContext:
    attrs = ev.attributes or {}
    return EventContext(
        source=ev.source, event_type=ev.event_type, severity=ev.severity, asset_id=ev.asset_id,
        asset_type=getattr(asset, "type", None) or attrs.get("asset_type"),
        subscription_id=getattr(asset, "subscription_id", None) or attrs.get("subscription_id"),
        tags=dict((getattr(asset, "tags", None) or attrs.get("tags") or {})),
        rule_id=ev.rule_id, mitre_technique_id=ev.mitre_technique_id,
    )


def _ci_in(value: str | None, options: list[str]) -> bool:
    if value is None:
        return False
    v = value.lower()
    return any(v == o.lower() for o in options)


def _technique_matches(technique: str | None, wanted: list[str]) -> bool:
    if not technique:
        return False
    t = technique.upper()
    return any(t == w.upper() or t.startswith(w.upper() + ".") for w in wanted)


def _rule_id_matches(rule_id: str | None, patterns: list[str]) -> bool:
    if not rule_id:
        return False
    return any(fnmatch.fnmatchcase(rule_id.lower(), p.lower()) for p in patterns)


def matches(rule, ctx: EventContext) -> bool:
    """Does notification rule `rule` select this event?"""
    if not rule.enabled:
        return False
    if rule.sources and ctx.source not in rule.sources:
        return False
    if ctx.event_type == STATUS_CHANGED:
        if not rule.include_status_changes:
            return False
    elif rule.event_types and ctx.event_type not in rule.event_types:
        return False
    if SEV_RANK.get(ctx.severity, 0) < SEV_RANK.get(rule.min_severity or "info", 0):
        return False
    if rule.subscription_ids and not _ci_in(ctx.subscription_id, rule.subscription_ids):
        return False
    if rule.asset_ids and not _ci_in(ctx.asset_id, rule.asset_ids):
        return False
    if rule.asset_types and ctx.asset_type not in rule.asset_types:
        return False
    for k, v in (rule.tags or {}).items():
        if k not in ctx.tags:
            return False
        if v not in ("*", None, "") and str(ctx.tags[k]).lower() != str(v).lower():
            return False
    if rule.rule_ids and not _rule_id_matches(ctx.rule_id, rule.rule_ids):
        return False
    if rule.mitre_techniques and not _technique_matches(ctx.mitre_technique_id, rule.mitre_techniques):
        return False
    return True


# --- time windows -------------------------------------------------------------------

def zone(name: str | None) -> ZoneInfo:
    try:
        return ZoneInfo(name or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def parse_hhmm(v: str) -> time:
    h, m = v.split(":")
    return time(int(h), int(m))


def quiet_until(rule, now: datetime, severity: str) -> datetime | None:
    """If `now` (naive UTC) is inside the rule's quiet hours, the naive-UTC time
    the window ends; else None. Severities at/above the bypass level are never held."""
    if not (rule.quiet_start and rule.quiet_end):
        return None
    if rule.quiet_bypass_severity and SEV_RANK.get(severity, 0) >= SEV_RANK.get(rule.quiet_bypass_severity, 99):
        return None
    tz = zone(rule.timezone)
    local = now.replace(tzinfo=UTC).astimezone(tz)
    start, end = parse_hhmm(rule.quiet_start), parse_hhmm(rule.quiet_end)
    if start == end:
        return None
    t = local.time()
    if start < end:
        inside = start <= t < end
        end_day = local.date()
    else:  # wraps midnight, e.g. 22:00-07:00
        inside = t >= start or t < end
        end_day = local.date() + timedelta(days=1) if t >= start else local.date()
    if not inside:
        return None
    end_local = datetime.combine(end_day, end, tzinfo=tz)
    return end_local.astimezone(UTC).replace(tzinfo=None)


def digest_due(rule, now: datetime) -> bool:
    """Daily digest: due once per local day, at or after `digest_hour` (rule time zone)."""
    tz = zone(rule.timezone)
    local = now.replace(tzinfo=UTC).astimezone(tz)
    if local.hour < (rule.digest_hour or 0):
        return False
    if rule.last_digest_at is None:
        return True
    last_local = rule.last_digest_at.replace(tzinfo=UTC).astimezone(tz)
    return last_local.date() < local.date()
