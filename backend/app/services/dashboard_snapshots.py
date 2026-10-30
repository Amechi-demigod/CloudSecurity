"""Daily dashboard snapshots (leader-elected background job).

Once per UTC day, for every active organisation, the job stores the
point-in-time dashboard metrics (`dashboards.current_metrics`) for all cloud
accounts together and for each cloud account (`DashboardSnapshot`, one row per
organisation, day and account scope). The dashboards compare today's numbers
with the snapshot taken `range` days earlier; with no snapshot for that day the
change is unknown (null) and not shown. Trends therefore fill in from the day
this job first runs.

Like the scan scheduler, one process holds the "dashboard-snapshots" leader
lock (PostgreSQL advisory lock / SQLite flock); the others stay idle. Writing is
idempotent (unique organisation + day + account): a restart, a second replica
or the dashboard's own lazy write on the first read of the day never produce a
second row.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from .. import tenancy
from ..locks import LeaderLock
from ..models import utcnow
from . import dashboards

log = logging.getLogger(__name__)


@dataclass
class SnapshotTick:
    leader: bool
    written: dict[str, int] = field(default_factory=dict)  # organisation id -> rows written


class DashboardSnapshotWorker:
    """`tick()` holds the logic and takes an explicit `now` so tests can drive it."""

    LOCK_NAME = "dashboard-snapshots"

    def __init__(self, tick_seconds: float = 900.0, clock: Callable[[], datetime] = utcnow):
        self.tick_seconds = tick_seconds
        self.clock = clock
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
        self._thread = threading.Thread(target=self._run, name="dashboard-snapshots", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
        if not (self._thread and self._thread.is_alive()):
            self._leader.release()

    def tick(self, now: datetime | None = None) -> SnapshotTick:
        leader = self._leader.held() if self._leader.acquired else self._leader.try_acquire()
        if not leader:
            return SnapshotTick(False)
        day = (now or self.clock()).date()
        result = SnapshotTick(True)
        for org_id, db in tenancy.for_each_active_org():
            try:
                n = dashboards.snapshot_all(db, day)
                if n:
                    result.written[org_id] = n
                    log.info("dashboard snapshots for %s on %s: %d written", org_id, day, n)
            except Exception:
                db.rollback()
                log.exception("dashboard snapshot of organisation %s failed", org_id)
        return result

    def _run(self) -> None:
        # First tick right away (after start-up), then every tick_seconds.
        while True:
            try:
                self.tick()
            except Exception:
                log.exception("dashboard snapshot tick failed")
            if self._stop.wait(self.tick_seconds):
                return
