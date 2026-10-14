"""Runtime events (sensor ingest + feed) and CDR alerts."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from pydantic import Discriminator, Tag, TypeAdapter, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..auth import audit, client_ip, require_analyst
from ..db import get_db
from ..models import Alert, AlertEvent, Asset, RuntimeEvent, User
from ..schemas import (
    AlertDetail,
    AlertOut,
    AlertUpdate,
    AssetOut,
    IngestResult,
    RuntimeEventIn,
    RuntimeEventOut,
    SensorEventV1,
    TimelineEntry,
)
from ..security import require_ingest_token
from ..services.runtime import ingest_event
from ..services.sensor import AssetResolver, apply_library_loaded, expire_stale_in_use, normalize_v1

router = APIRouter(prefix="/api", tags=["runtime"])
# Sensor ingest: authenticated by the INGEST_API_TOKEN bearer token, not user sessions.
ingest_router = APIRouter(prefix="/api", tags=["runtime"])
TIMELINE_CONTEXT = timedelta(minutes=10)


def _event_kind(v: Any) -> str:
    return "v1" if isinstance(v, dict) and "schema_version" in v else "legacy"


AnyEvent = Annotated[
    Annotated[RuntimeEventIn, Tag("legacy")] | Annotated[SensorEventV1, Tag("v1")],
    Discriminator(_event_kind),
]
_EVENTS = TypeAdapter(list[AnyEvent])


def _unpack(payload: Any) -> list[Any]:
    """Accept a single event, a JSON array, or a sensor envelope {"events": [...]}."""
    if isinstance(payload, dict) and isinstance(payload.get("events"), list):
        return payload["events"]
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return payload
    raise RequestValidationError([{"type": "model_type", "loc": ("body",), "input": None,
                                   "msg": "expected an event object, an array of events or {\"events\": [...]}"}])


@ingest_router.post("/runtime/events", response_model=IngestResult, status_code=202,
             dependencies=[Depends(require_ingest_token)])
def ingest_runtime_events(payload: Any = Body(...), db: Session = Depends(get_db)):
    """Ingest runtime-sensor events.

    Body: one event, a JSON array of events, or `{"events": [...]}` (sensor envelope).
    Each event is either the native sensor schema v1.0 (has `schema_version`, see
    sensor/EVENT_SCHEMA.md) or the legacy `RuntimeEventIn` shape. Requires
    `Authorization: Bearer <INGEST_API_TOKEN>`.
    """
    raw = _unpack(payload)
    limit = config.settings.max_events_per_request
    if len(raw) > limit:
        raise HTTPException(413, f"max {limit} events per request")
    try:
        events = _EVENTS.validate_python(raw)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors(include_url=False, include_context=False)) from None

    resolver = AssetResolver(db)
    alert_ids: set[str] = set()
    duplicates = in_use_updates = 0
    seen: set[str] = set()
    for e in events:
        if isinstance(e, RuntimeEventIn):
            _, alerts = ingest_event(db, e.model_dump(exclude_none=True), source="sensor")
            alert_ids.update(a.id for a in alerts)
            continue
        event_id = e.event_id.replace("-", "").lower()[:32] if e.event_id else None
        if event_id and (event_id in seen or db.get(RuntimeEvent, event_id) is not None):
            duplicates += 1
            continue
        if event_id:
            seen.add(event_id)
        asset_id = resolver.resolve(e)
        normalized = normalize_v1(e, asset_id)
        if e.event_type == "library_loaded":
            flipped = apply_library_loaded(db, asset_id, normalized.get("library") or {})
            in_use_updates += flipped
            if not flipped:
                # Hourly heartbeats for already-known / irrelevant libraries are not
                # stored, so they don't flood the runtime event feed.
                continue
        _, alerts = ingest_event(db, normalized, source="sensor", event_id=event_id)
        alert_ids.update(a.id for a in alerts)
    expire_stale_in_use(db)
    db.commit()
    return IngestResult(accepted=len(events), alerts_triggered=len(alert_ids), alert_ids=sorted(alert_ids),
                        duplicates=duplicates, in_use_updates=in_use_updates)


@router.get("/runtime/schema")
def runtime_event_schema():
    """JSON schemas of the accepted sensor event payloads (native v1.0 and legacy)."""
    return {"v1": SensorEventV1.model_json_schema(), "legacy": RuntimeEventIn.model_json_schema()}


@router.get("/runtime/events", response_model=list[RuntimeEventOut])
def list_events(
    db: Session = Depends(get_db),
    asset_id: str | None = None,
    event_type: str | None = None,
    source: str | None = Query(None, description="simulated | sensor"),
    since: datetime | None = None,
    limit: int = Query(100, ge=1, le=1000),
):
    stmt = select(RuntimeEvent)
    if source:
        stmt = stmt.where(RuntimeEvent.source == source)
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
def update_alert(alert_id: str, body: AlertUpdate, request: Request, user: User = Depends(require_analyst),
                 db: Session = Depends(get_db)):
    a = db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(404, "alert not found")
    if a.status != body.status:
        audit(db, "alert_updated", actor=user, target=a.id, ip=client_ip(request),
              rule_id=a.rule_id, status=[a.status, body.status])
    a.status = body.status
    db.commit()
    return AlertOut.model_validate(a)
