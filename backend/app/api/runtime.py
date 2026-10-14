"""Runtime events (sensor ingest + feed) and CDR alerts."""
from __future__ import annotations

import hmac
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..db import get_db
from ..models import Alert, AlertEvent, Asset, RuntimeEvent
from ..schemas import (AlertDetail, AlertOut, AlertUpdate, AssetOut, IngestResult, RuntimeEventIn, RuntimeEventOut,
                       TimelineEntry)
from ..services.runtime import ingest_event

router = APIRouter(prefix="/api", tags=["runtime"])
TIMELINE_CONTEXT = timedelta(minutes=10)


def _check_token(authorization: str | None) -> None:
    token = config.settings.runtime_ingest_token
    if not token:
        return
    supplied = (authorization or "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(supplied, token):
        raise HTTPException(401, "invalid or missing sensor token")


@router.post("/runtime/events", response_model=IngestResult, status_code=202)
def ingest_runtime_events(
    events: RuntimeEventIn | list[RuntimeEventIn],
    db: Session = Depends(get_db),
    authorization: str | None = Header(None),
):
    """Ingest one event or a batch from a runtime sensor (eBPF agent, Falco bridge, ...).

    If RUNTIME_INGEST_TOKEN is set, send `Authorization: Bearer <token>`.
    """
    _check_token(authorization)
    batch = events if isinstance(events, list) else [events]
    if len(batch) > 1000:
        raise HTTPException(413, "max 1000 events per request")
    alert_ids: list[str] = []
    for e in batch:
        _, alerts = ingest_event(db, e.model_dump(exclude_none=True), source="sensor")
        alert_ids += [a.id for a in alerts]
    db.commit()
    return IngestResult(accepted=len(batch), alerts_triggered=len(alert_ids), alert_ids=sorted(set(alert_ids)))


@router.get("/runtime/schema")
def runtime_event_schema():
    """JSON schema of the sensor event payload."""
    return RuntimeEventIn.model_json_schema()


@router.get("/runtime/events", response_model=list[RuntimeEventOut])
def list_events(
    db: Session = Depends(get_db),
    asset_id: str | None = None,
    event_type: str | None = None,
    since: datetime | None = None,
    limit: int = Query(100, le=1000),
):
    stmt = select(RuntimeEvent)
    if asset_id:
        stmt = stmt.where(RuntimeEvent.asset_id == asset_id)
    if event_type:
        stmt = stmt.where(RuntimeEvent.event_type == event_type)
    if since:
        stmt = stmt.where(RuntimeEvent.timestamp > since.replace(tzinfo=None))
    return list(db.scalars(stmt.order_by(RuntimeEvent.timestamp.desc()).limit(limit)))


def _alert_out(a: Alert, names: dict[str, tuple[str, str]]) -> AlertOut:
    o = AlertOut.model_validate(a)
    if a.asset_id in names:
        o.asset_name, o.asset_type = names[a.asset_id]
    return o


@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(
    db: Session = Depends(get_db),
    status: str | None = Query(None, description="open|acknowledged|resolved (default: not resolved)"),
    severity: str | None = None,
    rule_id: str | None = None,
    asset_id: str | None = None,
    limit: int = Query(200, le=2000),
):
    stmt = select(Alert)
    if status == "all":
        pass
    elif status:
        stmt = stmt.where(Alert.status == status)
    else:
        stmt = stmt.where(Alert.status != "resolved")
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
    if asset_id:
        stmt = stmt.where(Alert.asset_id == asset_id)
    alerts = list(db.scalars(stmt.order_by(Alert.last_seen.desc()).limit(limit)))
    ids = {a.asset_id for a in alerts if a.asset_id}
    names = {i: (n, t) for i, n, t in db.execute(select(Asset.id, Asset.name, Asset.type).where(Asset.id.in_(ids)))}
    return [_alert_out(a, names) for a in alerts]


@router.get("/alerts/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: str, db: Session = Depends(get_db)):
    """Alert with an event timeline: triggering events + surrounding events on the same asset."""
    a = db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(404, "alert not found")
    linked_ids = {eid for (eid,) in db.execute(select(AlertEvent.event_id).where(AlertEvent.alert_id == a.id))}
    events = {e.id: e for e in db.scalars(select(RuntimeEvent).where(RuntimeEvent.id.in_(linked_ids)))}
    if a.asset_id:
        ctx = select(RuntimeEvent).where(
            RuntimeEvent.asset_id == a.asset_id,
            RuntimeEvent.timestamp >= a.first_seen - TIMELINE_CONTEXT,
            RuntimeEvent.timestamp <= a.last_seen + TIMELINE_CONTEXT,
        ).limit(200)
        for e in db.scalars(ctx):
            events.setdefault(e.id, e)
    timeline = []
    for e in sorted(events.values(), key=lambda e: e.timestamp):
        t = TimelineEntry.model_validate(e)
        t.triggered = e.id in linked_ids
        timeline.append(t)
    asset = db.get(Asset, a.asset_id) if a.asset_id else None
    base = AlertOut.model_validate(a).model_dump()
    if asset is not None:
        base.update(asset_name=asset.name, asset_type=asset.type)
    return AlertDetail(**base, asset=AssetOut.model_validate(asset) if asset else None, timeline=timeline)


@router.patch("/alerts/{alert_id}", response_model=AlertOut)
def update_alert(alert_id: str, body: AlertUpdate, db: Session = Depends(get_db)):
    a = db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(404, "alert not found")
    a.status = body.status
    db.commit()
    return AlertOut.model_validate(a)
