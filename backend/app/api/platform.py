"""Dashboard, attack paths, connectors and scans."""
from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config, tenancy
from ..auth import audit, client_ip, require_admin, require_analyst
from ..connectors import CLOUD_CONNECTORS, build_registry
from ..connectors.org_config import org_settings
from ..db import get_db
from ..engine.attack_paths import INTERNET_NODE
from ..models import Asset, ScanRun, User
from ..schemas import ScanRequest, ScanRunOut, ScanScheduleOut, ScanScheduleUpdate
from ..services import analytics, scan_schedule
from ..services.scans import start_scan

router = APIRouter(prefix="/api", tags=["platform"])
# Unauthenticated: liveness probe only.
public_router = APIRouter(prefix="/api", tags=["platform"])


@public_router.get("/health")
def health(request: Request):
    sim = getattr(request.app.state, "simulator", None)
    s = config.settings
    reg = build_registry(s)
    return {"status": "ok", "simulation_mode": s.simulation_mode, "simulator_running": bool(sim and sim.running),
            "simulator_leader": bool(sim and sim.is_leader),
            # azure_configured / aws_configured / gcp_configured
            **{f"{n}_configured": bool(n in reg and reg[n].is_configured()) for n in CLOUD_CONNECTORS}}


@router.get("/dashboard")
def get_dashboard(db: Session = Depends(get_db)):
    return analytics.dashboard(db)


@router.get("/compliance")
def get_compliance(db: Session = Depends(get_db)):
    return analytics.compliance_summary(db)


@router.get("/attack-paths")
def list_attack_paths(db: Session = Depends(get_db), limit: int = Query(20, le=100),
                      confirmed_only: bool = Query(False, description="Only paths with an exploitable weakness")):
    """Attack paths, confirmed first. Exposure paths (no weakness yet) have `confirmed=false`."""
    return [asdict(p) for p in analytics.attack_paths(db, limit=limit, include_unconfirmed=not confirmed_only)]


@router.get("/attack-paths/graph")
def attack_path_graph(db: Session = Depends(get_db), limit: int = Query(10, le=50),
                      confirmed_only: bool = Query(False, description="Only paths with an exploitable weakness")):
    """Union of the top-N attack paths as a node/edge graph for visualization."""
    paths = analytics.attack_paths(db, limit=limit, include_unconfirmed=not confirmed_only)
    node_ids: set[str] = set()
    edges: dict[tuple, dict] = {}
    for p in paths:
        for e in p.edges:
            node_ids.update((e["source"], e["target"]))
            edges.setdefault((e["source"], e["target"], e["type"]), {**e, "paths": []})["paths"].append(p.id)
    node_ids.discard(INTERNET_NODE)
    assets = {a.id: a for a in db.scalars(select(Asset).where(Asset.id.in_(node_ids)))}
    nodes = [{"id": INTERNET_NODE, "name": "Internet", "type": "internet"}] if paths else []
    nodes += [{"id": a.id, "name": a.name, "type": a.type, "internet_exposed": a.internet_exposed,
               "sensitive_data": a.sensitive_data} for a in assets.values()]
    return {"nodes": nodes, "edges": list(edges.values()), "paths": [asdict(p) for p in paths]}


@router.get("/connectors")
def list_connectors(db: Session = Depends(get_db)):
    """Connectors with configuration state, scan scope and their latest scan."""
    out = []
    for c in build_registry(org_settings(db)).values():
        last = db.scalar(select(ScanRun).where(ScanRun.connector == c.name).order_by(ScanRun.started_at.desc()).limit(1))
        accounts = sorted({(sid, name) for sid, name in db.execute(
            select(Asset.subscription_id, Asset.subscription_name).where(Asset.source == c.name).distinct()) if sid})
        out.append({**c.info(),
                    "last_scan": ScanRunOut.model_validate(last).model_dump(mode="json") if last else None,
                    "discovered_scopes": [{"id": sid, "name": name or sid} for sid, name in accounts]})
    return out


@router.post("/scans", response_model=ScanRunOut, status_code=202)
def run_scan(body: ScanRequest, request: Request, user: User = Depends(require_analyst),
             db: Session = Depends(get_db)):
    """Start a read-only connector scan in the background (e.g. `{"connector": "azure"}`)."""
    registry = build_registry(org_settings(db))
    conn = registry.get(body.connector)
    if conn is None:
        raise HTTPException(404, f"unknown connector '{body.connector}'")
    if not conn.is_configured():
        raise HTTPException(400, f"connector '{body.connector}' is not configured; {conn.setup_hint}".rstrip("; "))
    run = start_scan(conn, tenancy.require_org(db), background=True)
    audit(db, "scan_started", actor=user, target=body.connector, ip=client_ip(request), scan_id=run.id)
    db.commit()
    return run


@router.get("/scan-schedule", response_model=ScanScheduleOut)
def get_scan_schedule(db: Session = Depends(get_db)):
    """Scheduled-scan settings and, per connector, the last scan and the next scheduled one."""
    return scan_schedule.status(db)


@router.put("/scan-schedule", response_model=ScanScheduleOut)
def update_scan_schedule(body: ScanScheduleUpdate, request: Request, user: User = Depends(require_admin),
                         db: Session = Depends(get_db)):
    """Override the schedule (admin). Only the fields sent are changed; null resets a
    field to its environment default (SCAN_SCHEDULE_ENABLED / SCAN_INTERVAL_HOURS)."""
    fields = set(body.model_fields_set)
    if not fields:
        raise HTTPException(422, "nothing to change: send enabled and/or interval_hours")
    try:
        before, after = scan_schedule.update(db, actor=user.email, enabled=body.enabled,
                                             interval_hours=body.interval_hours, fields=fields)
    except ValueError as e:
        raise HTTPException(422, str(e)) from e
    audit(db, "scan_schedule_updated", actor=user, target="scan-schedule", ip=client_ip(request),
          before=before, after=after)
    db.commit()
    return scan_schedule.status(db)


@router.get("/scans", response_model=list[ScanRunOut])
def list_scans(db: Session = Depends(get_db), limit: int = Query(20, ge=1, le=200)):
    return list(db.scalars(select(ScanRun).order_by(ScanRun.started_at.desc()).limit(limit)))


@router.get("/scans/{scan_id}", response_model=ScanRunOut)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    run = db.get(ScanRun, scan_id)
    if run is None:
        raise HTTPException(404, "scan not found")
    return run
