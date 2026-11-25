"""Leader-elected background job for the time-driven device tracking alerts (not seen for N days, agent stopped).
`tick()` holds the logic and takes an explicit `now`, so tests drive it without a thread."""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import datetime

from .. import tenancy
from ..locks import LeaderLock
from ..models import utcnow
from . import alerts

log = logging.getLogger(__name__)


class TrackingAlertWorker:
    LOCK_NAME = "device-tracking-alerts"

    def __init__(self, tick_seconds: float = 900.0, startup_delay_seconds: float = 120.0,
                 clock: Callable[[], datetime] = utcnow):
        self.tick_seconds, self.startup_delay, self.clock = tick_seconds, startup_delay_seconds, clock
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._leader = LeaderLock(self.LOCK_NAME)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="device-tracking-alerts", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
        if not (self._thread and self._thread.is_alive()):
            self._leader.release()

    def tick(self, now: datetime | None = None) -> dict[str, dict[str, int]]:
        """Organisation id -> alerts raised. Empty when this process is not the leader."""
        leader = self._leader.held() if self._leader.acquired else self._leader.try_acquire()
        if not leader:
            return {}
        now = now or self.clock()
        result: dict[str, dict[str, int]] = {}
        for org_id, db in tenancy.for_each_active_org():
            try:
                counts = alerts.check_absences(db, now)
                alerts.prune_events(db, now)
                db.commit()
                if any(counts.values()):
                    result[org_id] = counts
            except Exception:
                db.rollback()
                log.exception("device tracking alert check of organisation %s failed", org_id)
        return result

    def _run(self) -> None:
        if self._stop.wait(self.startup_delay):
            return
        while True:
            try:
                self.tick()
            except Exception:
                log.exception("device tracking alert tick failed")
            if self._stop.wait(self.tick_seconds):
                return
