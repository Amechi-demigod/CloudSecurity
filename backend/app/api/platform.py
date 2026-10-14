"""Dashboard, attack paths, connectors and scans."""
from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..connectors import build_registry
from ..db import get_db
from ..engine.attack_paths import INTERNET_NODE
from ..models import Asset, ScanRun
from ..schemas import ScanRequest, ScanRunOut
from ..services import analytics
from ..services.scans import start_scan

router = APIRouter(prefix="/api", tags=["platform"])


@router.get("/health")
def health(request: Request):
    sim = getattr(request.app.state, "simulator", None)
    s = config.settings
    return {"status": "ok", "simulation_mode": s.simulation_mode, "simulator_running": bool(sim and sim.running),
            "azure_configured": build_registry(s)["azure"].is_configured()}


@router.get("/dashboard")
def get_dashboard(db: Session = Depends(get_db)):
    return analytics.dashboard(db)


@router.get("/compliance")
def get_compliance(db: Session = Depends(get_db)):
    return analytics.compliance_summary(db)


@router.get("/attack-paths")
def list_attack_paths(db: Session = Depends(get_db), limit: int = Query(20, le=100)):
    return [asdict(p) for p in analytics.attack_paths(db, limit=limit)]


@router.get("/attack-paths/graph")
def attack_path_graph(db: Session = Depends(get_db), limit: int = Query(10, le=50)):
    """Union of the top-N attack paths as a node/edge graph for visualization."""
    paths = analytics.attack_paths(db, limit=limit)
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
def list_connectors():
    return [c.info() for c in build_registry(config.settings).values()]


@router.post("/scans", response_model=ScanRunOut, status_code=202)
def run_scan(body: ScanRequest):
    """Start a read-only connector scan in the background (e.g. `{"connector": "azure"}`)."""
    registry = build_registry(config.settings)
    conn = registry.get(body.connector)
    if conn is None:
        raise HTTPException(404, f"unknown connector '{body.connector}'")
    if not conn.is_configured():
        raise HTTPException(400, f"connector '{body.connector}' is not configured; see README "
                                 "(AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_IDS)")
    return start_scan(conn, background=True)


@router.get("/scans", response_model=list[ScanRunOut])
def list_scans(db: Session = Depends(get_db), limit: int = Query(20, ge=1, le=200)):
    return list(db.scalars(select(ScanRun).order_by(ScanRun.started_at.desc()).limit(limit)))


@router.get("/scans/{scan_id}", response_model=ScanRunOut)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    run = db.get(ScanRun, scan_id)
    if run is None:
        raise HTTPException(404, "scan not found")
    return run
