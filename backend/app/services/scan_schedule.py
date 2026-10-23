"""Scheduled cloud posture scans.

A leader-elected background job (one per deployment, whatever the number of
gunicorn workers / replicas) scans every configured cloud connector every
`interval_hours` (default 6, SCAN_INTERVAL_HOURS), one ScanRun per connector,
recorded with trigger="scheduled".

Timing is derived from the database, never from process memory, so restarts
neither cause scan storms nor missed scans:

* a connector is due when its newest *scheduled* run started at least one
  interval ago (or it has never had one);
* after a (re)start the first scheduled scan waits SCAN_STARTUP_DELAY_SECONDS,
  then every overdue connector is scanned once;
* manual scans ("Run scan", POST /api/scans) are recorded with
  trigger="manual" and neither reset nor delay the schedule;
* runs never overlap: if a scan of that connector (manual or scheduled) is
  still running when the next one is due, the slot is skipped, logged and
  recorded as a "skipped" run, and the next attempt is one interval later;
* a run left "running" by a process that died (its scan lock is free) is
  marked failed after ORPHAN_GRACE, which raises the usual failure notification.

Failures are recorded on the ScanRun and raise a "Cloud scans" (source "scan",
event "failed") notification, routed through the normal notification rules.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from .. import db as dbmod
from ..connectors import build_registry
from ..connectors.base import Connector
from ..locks import LeaderLock, advisory_lock
from ..models import ScanRun, ScanScheduleSettings, utcnow
from ..notifications import builtin as notify
from .scans import SCHEDULED, start_scan

log = logging.getLogger(__name__)

# A "running" row whose scan lock is free and that is older than this was left
# behind by a process that stopped mid-scan.
ORPHAN_GRACE = timedelta(minutes=10)
SIMULATED = "simulated"


# ----------------------------------------------------------------------------- settings
@dataclass
class Schedule:
    enabled: bool
    interval_hours: float
    enabled_overridden: bool  # set in the console (else the environment default)
    interval_overridden: bool
    updated_at: datetime | None = None
    updated_by: str | None = None

    @property
    def interval(self) -> timedelta:
        return timedelta(hours=self.interval_hours)


def get_row(db: Session) -> ScanScheduleSettings | None:
    return db.get(ScanScheduleSettings, 1)


def effective(db: Session) -> Schedule:
    s = config.settings
    row = get_row(db)
    enabled = row.enabled if row is not None and row.enabled is not None else s.scan_schedule_enabled
    interval = row.interval_hours if row is not None and row.interval_hours is not None else s.scan_interval_hours
    return Schedule(enabled=bool(enabled), interval_hours=float(interval),
                    enabled_overridden=row is not None and row.enabled is not None,
                    interval_overridden=row is not None and row.interval_hours is not None,
                    updated_at=row.updated_at if row is not None else None,
                    updated_by=row.updated_by if row is not None else None)


def update(db: Session, *, actor: str, enabled: bool | None, interval_hours: float | None,
           fields: set[str]) -> tuple[dict, dict]:
    """Apply console overrides (None = back to the environment default) for the
    given fields. Returns (before, after) for the audit log. Caller commits."""
    row = get_row(db)
    if row is None:
        row = ScanScheduleSettings(id=1)
        db.add(row)
    before = {"enabled": row.enabled, "interval_hours": row.interval_hours}
    if "enabled" in fields:
        row.enabled = enabled
    if "interval_hours" in fields:
        if interval_hours is not None and not (
                config.MIN_INTERVAL_HOURS <= interval_hours <= config.MAX_INTERVAL_HOURS):
            raise ValueError(f"interval_hours must be between {config.MIN_INTERVAL_HOURS:g} and "
                             f"{config.MAX_INTERVAL_HOURS:g}")
        row.interval_hours = interval_hours
    row.updated_at = utcnow()
    row.updated_by = actor
    return before, {"enabled": row.enabled, "interval_hours": row.interval_hours}


# ----------------------------------------------------------------------------- connectors
def schedule_reason(conn: Connector) -> str | None:
    """Why `conn` is not scanned on schedule, or None if it is."""
    if conn.name == SIMULATED and not config.settings.simulation_mode:
        return "simulated connector (SIMULATION_MODE is off)"
    if not conn.is_configured():
        return "not configured"
    return None


def schedulable(registry: dict[str, Connector]) -> list[Connector]:
    return [c for c in registry.values() if schedule_reason(c) is None]


# ----------------------------------------------------------------------------- run history
def last_scheduled_run(db: Session, connector: str) -> ScanRun | None:
    return db.scalars(select(ScanRun).where(ScanRun.connector == connector, ScanRun.trigger == SCHEDULED)
                      .order_by(ScanRun.started_at.desc()).limit(1)).first()


def last_run(db: Session, connector: str) -> ScanRun | None:
    """Newest run that actually scanned (manual or scheduled; skipped slots excluded)."""
    return db.scalars(select(ScanRun).where(ScanRun.connector == connector, ScanRun.status != "skipped")
                      .order_by(ScanRun.started_at.desc()).limit(1)).first()


def running_runs(db: Session, connector: str) -> list[ScanRun]:
    return list(db.scalars(select(ScanRun).where(ScanRun.connector == connector, ScanRun.status == "running")))


def next_due(last_scheduled: ScanRun | None, interval: timedelta) -> datetime | None:
    """When the connector is next due (None: never scanned on schedule, due now)."""
    return last_scheduled.started_at + interval if last_scheduled is not None else None


def scan_lock_free(connector: str) -> bool:
    with advisory_lock(f"scan-{connector}", blocking=False) as got:
        return got


def recover_orphans(db: Session, connector: str, now: datetime) -> int:
    """Mark runs left "running" by a dead process as failed. Caller commits."""
    stale = [r for r in running_runs(db, connector) if now - r.started_at >= ORPHAN_GRACE]
    if not stale or not scan_lock_free(connector):
        return 0
    for run in stale:
        run.status = "failed"
        run.finished_at = now
        run.message = "Interrupted: the backend stopped while this scan was running."
        log.warning("scan %s of %s was interrupted (backend stopped); marked failed", run.id, connector)
        notify.scan_finished(db, run)
    return len(stale)


# ----------------------------------------------------------------------------- scheduler
Launcher = Callable[[Connector], object]


def _launch(conn: Connector) -> object:
    return start_scan(conn, background=True, trigger=SCHEDULED)


@dataclass
class TickResult:
    leader: bool
    started: list[str]
    skipped: list[str]  # due, but a scan of that connector was still running
    waiting: bool = False  # still inside the startup delay


class ScanScheduler:
    """Leader-elected scheduler thread. `tick()` holds all the logic and takes
    an explicit `now`, so tests drive it with a fake clock."""

    LOCK_NAME = "scan-scheduler"

    def __init__(self, tick_seconds: float = 60.0, startup_delay_seconds: float | None = None,
                 clock: Callable[[], datetime] = utcnow,
                 registry_factory: Callable[[], dict[str, Connector]] | None = None,
                 launcher: Launcher = _launch):
        self.tick_seconds = tick_seconds
        self.clock = clock
        delay = config.settings.scan_startup_delay_seconds if startup_delay_seconds is None else startup_delay_seconds
        self.not_before = clock() + timedelta(seconds=delay)
        self._registry_factory = registry_factory or (lambda: build_registry(config.settings))
        self._launch = launcher
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._leader = LeaderLock(self.LOCK_NAME)

    @property
    def is_leader(self) -> bool:
        return self._leader.acquired

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="scan-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
        if not (self._thread and self._thread.is_alive()):
            self._leader.release()

    def tick(self, now: datetime | None = None) -> TickResult:
        leader = self._leader.held() if self._leader.acquired else self._leader.try_acquire()
        if not leader:
            return TickResult(False, [], [])
        now = now or self.clock()
        if now < self.not_before:
            return TickResult(True, [], [], waiting=True)
        started: list[str] = []
        skipped: list[str] = []
        with dbmod.get_session() as db:
            sched = effective(db)
            if not sched.enabled:
                return TickResult(True, [], [])
            for conn in schedulable(self._registry_factory()):
                try:
                    recover_orphans(db, conn.name, now)
                    db.commit()
                    due = next_due(last_scheduled_run(db, conn.name), sched.interval)
                    if due is not None and now < due:
                        continue
                    if running_runs(db, conn.name):
                        log.warning("scheduled %s scan skipped: the previous scan is still running", conn.name)
                        db.add(ScanRun(connector=conn.name, trigger=SCHEDULED, status="skipped", started_at=now,
                                       finished_at=now, message="Skipped: the previous scan was still running."))
                        db.commit()
                        skipped.append(conn.name)
                        continue
                    log.info("starting scheduled %s scan (every %g h)", conn.name, sched.interval_hours)
                    self._launch(conn)
                    started.append(conn.name)
                except Exception:
                    db.rollback()
                    log.exception("scheduled %s scan could not be started", conn.name)
        return TickResult(True, started, skipped)

    def _run(self) -> None:
        while not self._stop.wait(self.tick_seconds):
            try:
                self.tick()
            except Exception:
                log.exception("scan scheduler tick failed")


# ----------------------------------------------------------------------------- status (API)
def status(db: Session, now: datetime | None = None) -> dict:
    now = now or utcnow()
    sched = effective(db)
    s = config.settings
    connectors = []
    for conn in build_registry(s).values():
        reason = schedule_reason(conn)
        last_sched = last_scheduled_run(db, conn.name)
        due = next_due(last_sched, sched.interval) if sched.enabled and reason is None else None
        connectors.append({
            "name": conn.name, "provider": conn.provider, "configured": conn.is_configured(),
            "scheduled": sched.enabled and reason is None, "not_scheduled_reason": reason,
            "last_run": last_run(db, conn.name), "last_scheduled_run": last_sched,
            # None while scheduled means "due now" (overdue or never scanned on schedule).
            "next_run_at": max(due, now) if due is not None else None,
            "running": bool(running_runs(db, conn.name)),
        })
    return {
        "enabled": sched.enabled, "interval_hours": sched.interval_hours,
        "enabled_overridden": sched.enabled_overridden, "interval_overridden": sched.interval_overridden,
        "default_enabled": s.scan_schedule_enabled, "default_interval_hours": s.scan_interval_hours,
        "min_interval_hours": config.MIN_INTERVAL_HOURS, "max_interval_hours": config.MAX_INTERVAL_HOURS,
        "updated_at": sched.updated_at, "updated_by": sched.updated_by, "connectors": connectors,
    }
