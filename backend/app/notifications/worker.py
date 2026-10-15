"""Background notification dispatcher (leader-elected, like the runtime simulator).

Every replica / gunicorn worker starts one; only the process holding the
"notification-dispatcher" leader lock (PostgreSQL advisory lock, or a SQLite
file lock) processes events and sends. The others re-check each interval and
take over if the leader goes away. Runs in its own thread, so slow webhooks
never block API requests or the detection pipeline.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta

from .. import db as dbmod
from ..locks import LeaderLock
from ..models import utcnow
from . import dispatcher

log = logging.getLogger(__name__)

CLEANUP_EVERY = timedelta(hours=1)


class NotificationWorker:
    LOCK_NAME = "notification-dispatcher"

    def __init__(self, interval: float = 5.0):
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._leader = LeaderLock(self.LOCK_NAME)
        self.is_leader = False
        self.last_tick_at: datetime | None = None
        self._last_cleanup: datetime | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="notification-dispatcher", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
        if not (self._thread and self._thread.is_alive()):
            self._leader.release()
            self.is_leader = False

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _check_leadership(self) -> bool:
        was = self.is_leader
        self.is_leader = self._leader.held() if self._leader.acquired else self._leader.try_acquire()
        if self.is_leader and not was:
            log.info("notification dispatcher: this instance is now the leader")
        return self.is_leader

    def tick(self, now: datetime | None = None) -> dict | None:
        """One iteration. Returns stats, or None when this instance is not the leader."""
        if not self._check_leadership():
            return None
        now = now or utcnow()
        stats: dict = {}
        steps = [
            ("polled", lambda db: dispatcher.poll_sources(db, now)),
            ("events", lambda db: dispatcher.process_events(db, now)),
            ("digests", lambda db: dispatcher.flush_digests(db, now)),
            ("sent", lambda db: dispatcher.send_due(db, now)),
        ]
        if self._last_cleanup is None or now - self._last_cleanup >= CLEANUP_EVERY:
            steps.append(("cleanup", lambda db: dispatcher.cleanup(db, now)))
            self._last_cleanup = now
        for name, fn in steps:
            try:
                with dbmod.get_session() as db:
                    stats[name] = fn(db)
            except Exception:  # one failing step must not stop the others
                log.exception("notification dispatcher step %s failed", name)
        self.last_tick_at = now
        return stats

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.tick()
            except Exception:
                log.exception("notification dispatcher tick failed")


_worker: NotificationWorker | None = None


def get_worker() -> NotificationWorker | None:
    return _worker


def set_worker(w: NotificationWorker | None) -> None:
    global _worker
    _worker = w
