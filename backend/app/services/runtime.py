"""Runtime event ingestion + detection -> alerts."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..engine.detection import evaluate_event
from ..models import Alert, AlertEvent, RuntimeEvent, utcnow

# Repeated hits of the same rule on the same asset within this window are
# grouped into one alert (event_count increments) instead of creating noise.
CORRELATION_WINDOW = timedelta(minutes=30)


def summarize(e: dict[str, Any]) -> str:
    p = e.get("process") or {}
    n = e.get("network") or {}
    f = e.get("file") or {}
    t = e.get("event_type")
    if t == "process_exec":
        return f"exec {p.get('name', '?')}: {(p.get('cmdline') or '')[:200]}"
    if t == "network_connection":
        return (f"{p.get('name', '?')} {n.get('direction', 'outbound')} {n.get('protocol', 'tcp')} "
                f"-> {n.get('dst_ip', '?')}:{n.get('dst_port', '?')}")
    if t == "file_access":
        return f"{p.get('name', '?')} {f.get('operation', 'read')} {f.get('path', '?')}"
    if t == "library_loaded":
        lib = e.get("library") or {}
        ver = f" {lib['version']}" if lib.get("version") else ""
        return f"loaded {lib.get('package') or '?'}{ver} ({lib.get('path', '?')})"[:500]
    if t == "privilege_escalation":
        pr = e.get("privilege") or {}
        return f"{p.get('name', '?')} uid {pr.get('from_uid', '?')} -> {pr.get('to_uid', 0)} ({pr.get('method', '?')})"
    return t or "event"


# Sensor clocks can drift; never let an event claim to be from the future
# (it would pin alerts to the top of every list forever).
MAX_CLOCK_SKEW = timedelta(minutes=5)


def ingest_event(db: Session, event: dict[str, Any], source: str = "sensor",
                 event_id: str | None = None) -> tuple[RuntimeEvent, list[Alert]]:
    ts = event.get("timestamp")
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if isinstance(ts, datetime) and ts.tzinfo is not None:
        ts = ts.astimezone(UTC).replace(tzinfo=None)  # store naive UTC
    now = utcnow()
    ts = ts or now
    if ts > now + MAX_CLOCK_SKEW:
        ts = now
    data = {k: v for k, v in event.items() if k not in {"timestamp"} and v is not None}
    ev = RuntimeEvent(
        **({"id": event_id} if event_id else {}),
        timestamp=ts,
        asset_id=event.get("asset_id"),
        event_type=event["event_type"],
        summary=summarize(event),
        data=data,
        sensor_id=event.get("sensor_id"),
        source=source,
    )
    db.add(ev)
    db.flush()

    alerts: list[Alert] = []
    for rule, reason in evaluate_event(event):
        existing = db.scalar(
            select(Alert).where(
                Alert.rule_id == rule.id,
                Alert.asset_id == ev.asset_id,
                Alert.status != "resolved",
                Alert.last_seen >= ts - CORRELATION_WINDOW,
            ).order_by(Alert.last_seen.desc())
        )
        if existing is not None:
            existing.event_count += 1
            existing.last_seen = max(existing.last_seen, ts)
            alert = existing
        else:
            alert = Alert(
                rule_id=rule.id, title=rule.title, description=f"{rule.description} Trigger: {reason}",
                severity=rule.severity, asset_id=ev.asset_id, mitre_tactic=rule.mitre_tactic,
                mitre_technique_id=rule.mitre_technique_id, mitre_technique_name=rule.mitre_technique_name,
                first_seen=ts, last_seen=ts,
            )
            db.add(alert)
            db.flush()
        db.add(AlertEvent(alert_id=alert.id, event_id=ev.id))
        alerts.append(alert)
    db.flush()
    return ev, alerts
