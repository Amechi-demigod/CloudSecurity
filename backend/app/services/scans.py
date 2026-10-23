"""Run connectors (e.g. the Azure scanner) and record ScanRun history."""
from __future__ import annotations

import logging
import threading

from sqlalchemy import func, select

from .. import db as dbmod
from ..connectors.base import Connector
from ..locks import advisory_lock
from ..models import Finding, ScanRun, utcnow
from ..notifications import builtin as notify
from .ingest import ingest_collection

log = logging.getLogger(__name__)


MANUAL = "manual"
SCHEDULED = "scheduled"


def start_scan(connector: Connector, background: bool = True, trigger: str = MANUAL) -> ScanRun:
    with dbmod.get_session() as db:
        run = ScanRun(connector=connector.name, status="running", trigger=trigger)
        db.add(run)
        db.commit()
        run_id = run.id
    if background:
        threading.Thread(target=execute_scan, args=(connector, run_id), daemon=True).start()
    else:
        execute_scan(connector, run_id)
    with dbmod.get_session() as db:
        return db.get(ScanRun, run_id)


def execute_scan(connector: Connector, run_id: str) -> None:
    # One scan per connector at a time, across all replicas / workers.
    with advisory_lock(f"scan-{connector.name}"), dbmod.get_session() as db:
        run = db.get(ScanRun, run_id)
        try:
            result = connector.collect()
            stats = ingest_collection(db, result, source=connector.name)
            run.assets_found = stats["assets"]
            run.findings_open = db.scalar(
                select(func.count()).select_from(Finding).where(Finding.source == connector.name,
                                                                Finding.status == "open")) or 0
            run.errors = result.errors[:200]
            run.status = "succeeded" if not result.errors or result.assets else "failed"
            run.message = (f"{stats['assets']} assets, {stats['findings_opened']} findings opened, "
                           f"{stats['findings_resolved']} resolved")
        except Exception as exc:
            log.exception("scan %s failed", run_id)
            db.rollback()
            run = db.get(ScanRun, run_id)
            run.status = "failed"
            run.message = f"{type(exc).__name__}: {exc}"
        run.finished_at = utcnow()
        notify.scan_finished(db, run)
        db.commit()
