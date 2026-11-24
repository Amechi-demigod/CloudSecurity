"""Weekly (configurable) scans of every organisation that has the `external` module: a leader-elected background
thread like the cloud scan scheduler. Due = the newest non-retest scan started at least `interval_hours` ago (or none
yet). Limits (global / per organisation concurrency, scan windows) are applied by `service.create_scan`."""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta

from sqlalchemy import select

from .. import modules, tenancy
from ..locks import LeaderLock
from ..models import ExternalScan, ExternalTarget, ReputationRun, utcnow
from . import service
from .reputation import service as rep_service

log = logging.getLogger(__name__)


class ExternalScheduler:
    LOCK_NAME = "external-scheduler"

    def __init__(self, tick_seconds: float = 300.0, startup_delay_seconds: float = 300.0, clock=utcnow, launcher=None,
                 reputation_launcher=None):
        self.tick_seconds = tick_seconds
        self.clock = clock
        self.not_before = clock() + timedelta(seconds=startup_delay_seconds)
        self._launcher = launcher
        self._rep_launcher = reputation_launcher
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._leader = LeaderLock(self.LOCK_NAME)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="external-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
        if not (self._thread and self._thread.is_alive()):
            self._leader.release()

    def tick(self, now: datetime | None = None) -> list[str]:
        """Start the due scans; returns the organisation ids started."""
        leader = self._leader.held() if self._leader.acquired else self._leader.try_acquire()
        now = now or self.clock()
        if not leader or now < self.not_before:
            return []
        started: list[str] = []
        for org_id, db in tenancy.for_each_active_org():
            try:
                if not modules.has_module(db, modules.EXTERNAL):
                    continue
                st = service.get_settings(db)
                if not st.schedule_enabled or not db.scalar(select(ExternalTarget.id).limit(1)):
                    db.commit()
                    continue
                last = db.scalar(select(ExternalScan).where(ExternalScan.trigger.notin_(service.PARTIAL_TRIGGERS))
                                 .order_by(ExternalScan.started_at.desc()).limit(1))
                if last is not None and now - last.started_at < timedelta(hours=st.interval_hours):
                    db.commit()
                    continue
                scan = service.create_scan(db, "scheduled", None, now=now)
                (self._launcher or service.launch)(db, scan)
                started.append(org_id)
            except service.ExternalError as e:  # busy, nothing scannable right now, ...
                db.rollback()
                log.info("scheduled external scan of %s not started: %s", org_id, e)
            except Exception:
                db.rollback()
                log.exception("scheduled external scan of organisation %s failed", org_id)
        return started

    def tick_reputation(self, now: datetime | None = None) -> list[str]:
        """Start the due reputation runs (same leader, same weekly schedule setting as the scans); returns org ids."""
        leader = self._leader.held() if self._leader.acquired else self._leader.try_acquire()
        now = now or self.clock()
        if not leader or now < self.not_before:
            return []
        started: list[str] = []
        for org_id, db in tenancy.for_each_active_org():
            try:
                if not modules.has_module(db, modules.EXTERNAL):
                    continue
                st = service.get_settings(db)
                if not st.schedule_enabled or not rep_service.verified_domains(db):
                    db.commit()
                    continue
                last = db.scalar(select(ReputationRun.started_at).order_by(ReputationRun.started_at.desc()).limit(1))
                if last is not None and now - last < timedelta(hours=st.interval_hours):
                    db.commit()
                    continue
                run = rep_service.create_run(db, "scheduled", None, now=now)
                (self._rep_launcher or rep_service.launch)(db, run)
                started.append(org_id)
            except service.ExternalError as e:
                db.rollback()
                log.info("scheduled reputation run of %s not started: %s", org_id, e)
            except Exception:
                db.rollback()
                log.exception("scheduled reputation run of organisation %s failed", org_id)
        return started

    def _run(self) -> None:
        while not self._stop.wait(self.tick_seconds):
            try:
                self.tick()
            except Exception:
                log.exception("external scheduler tick failed")
            try:
                self.tick_reputation()
            except Exception:
                log.exception("reputation scheduler tick failed")

