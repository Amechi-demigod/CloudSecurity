"""Channel-neutral messages, stored on each delivery and rendered per channel at send time."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .. import config
from . import settings as nsettings
from .events import get_source

SOURCE_LABELS_FALLBACK = {"test": "Test"}


def iso(dt: datetime | None) -> str | None:
    return dt.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z") if dt else None


def deep_link(path: str | None) -> str | None:
    base = nsettings.get().public_base_url
    if not path or not base:
        return None
    if not base.startswith(("https://", "http://")):
        return None
    return base + (path if path.startswith("/") else "/" + path)


def source_label(name: str) -> str:
    src = get_source(name)
    return src.label if src else SOURCE_LABELS_FALLBACK.get(name, name.replace("_", " ").title())


def event_message(ev, asset=None, *, suppressed: int = 0, rule_name: str = "") -> dict[str, Any]:
    attrs = ev.attributes or {}
    facts: list[list[str]] = [["Severity", ev.severity.capitalize()], ["Source", source_label(ev.source)]]
    asset_name = getattr(asset, "name", None) or attrs.get("asset_name")
    if asset_name:
        facts.append(["Resource", f"{asset_name} ({getattr(asset, 'type', None) or attrs.get('asset_type') or '?'})"])
    sub = getattr(asset, "subscription_name", None) or getattr(asset, "subscription_id", None) \
        or attrs.get("subscription_id")
    if sub:
        facts.append(["Subscription", str(sub)])
    if ev.rule_id:
        facts.append(["Rule", ev.rule_id])
    if ev.mitre_technique_id:
        name = attrs.get("mitre_technique_name")
        facts.append(["MITRE ATT&CK", f"{ev.mitre_technique_id} {name}" if name else ev.mitre_technique_id])
    if ev.event_type not in ("created",):
        facts.append(["Event", ev.event_type.replace("_", " ")])
    facts.append(["Time", iso(ev.created_at) or ""])
    if suppressed:
        facts.append(["Suppressed", f"{suppressed} similar notification(s) since the last one"])
    return {
        "kind": "event",
        "title": ev.title,
        "summary": ev.summary or "",
        "severity": ev.severity,
        "source": ev.source,
        "source_label": source_label(ev.source),
        "event_type": ev.event_type,
        "facts": facts,
        "link": deep_link(ev.link_path),
        "rule_name": rule_name,
        "suppressed": suppressed,
        "event": {
            "id": ev.id, "source": ev.source, "type": ev.event_type, "severity": ev.severity, "title": ev.title,
            "summary": ev.summary or "", "entity_id": ev.entity_id, "asset_id": ev.asset_id,
            "asset_name": asset_name, "subscription_id": getattr(asset, "subscription_id", None)
            or attrs.get("subscription_id"), "rule_id": ev.rule_id, "mitre_technique_id": ev.mitre_technique_id,
            "occurred_at": iso(ev.created_at), "link": deep_link(ev.link_path), "attributes": attrs,
        },
    }


def digest_message(rule_name: str, items: list[dict[str, Any]], total: int, now: datetime) -> dict[str, Any]:
    by_sev: dict[str, int] = {}
    for it in items:
        by_sev[it["severity"]] = by_sev.get(it["severity"], 0) + 1
    worst = max(items, key=lambda i: ["info", "low", "medium", "high", "critical"].index(i["severity"]))["severity"] \
        if items else "info"
    return {
        "kind": "digest",
        "title": f"Daily digest: {total} notification(s) for \"{rule_name}\"",
        "summary": ", ".join(f"{n} {s}" for s, n in sorted(by_sev.items())),
        "severity": worst,
        "source": "digest",
        "source_label": "Digest",
        "event_type": "digest",
        "facts": [["Rule", rule_name], ["Notifications", str(total)], ["Generated", iso(now) or ""]],
        "link": deep_link("/"),
        "items": [{**it, "link": deep_link(it.get("link_path"))} for it in items],
        "total": total,
        "rule_name": rule_name,
    }


def test_message(channel_name: str, actor: str | None, now: datetime) -> dict[str, Any]:
    return {
        "kind": "test",
        "title": f"Test notification from {config.settings.brand_name}",
        "summary": f"If you can read this, the channel \"{channel_name}\" is configured correctly."
        + (f" Sent by {actor}." if actor else ""),
        "severity": "info",
        "source": "test",
        "source_label": "Test",
        "event_type": "test",
        "facts": [["Channel", channel_name], ["Time", iso(now) or ""]],
        "link": deep_link("/notifications"),
        "event": {"id": None, "source": "test", "type": "test", "severity": "info",
                  "title": "Test notification", "occurred_at": iso(now)},
    }
