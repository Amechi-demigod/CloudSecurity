"""Leader-elected directory sync scheduler (docs/DIRECTORY_DISCOVERY.md#scheduling).

Every tick (60 s), for every active organisation and enabled source:

* a queued run whose collector has not fetched the command within
  PICKUP_TIMEOUT (offline, or the command expired / was cancelled) is failed and
  re-queued on the next healthy collector of the source (failover; each
  collector is tried once per slot);
* a running run that sent no batch for STALL_TIMEOUT, or whose upload token
  expired, is failed (the agent went away mid-sync) and failed over likewise;
* a source is due when its newest scheduled run was queued `interval_hours`
  ago (or never). Timing comes from the database, so restarts neither cause
  sync storms nor skip syncs.

Organisations with directory sources are also re-evaluated (matches and
findings) every RECONCILE_INTERVAL, and objects missing for
DIRECTORY_MISSING_PURGE_DAYS are deleted.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import tenancy
from ..auth import audit
from ..locks import LeaderLock
from ..models import DeviceCommand, utcnow
from . import reconcile
from . import service as svc
from .models import DirectorySource, DirectorySyncRun

log = logging.getLogger(__name__)

RECONCILE_INTERVAL = timedelta(minutes=30)


class DirectoryScheduler:
    LOCK_NAME = "directory-scheduler"

    def __init__(self, tick_seconds: float = 60.0, clock: Callable[[], datetime] = utcnow):
        self.tick_seconds = tick_seconds
        self.clock = clock
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._leader = LeaderLock(self.LOCK_NAME)
        self._reconciled: dict[str, datetime] = {}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="directory-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=15)
        if not (self._thread and self._thread.is_alive()):
            self._leader.release()

    def _run(self) -> None:
        while not self._stop.wait(self.tick_seconds):
            try:
                self.tick()
            except Exception:
                log.exception("directory scheduler tick failed")

    def tick(self, now: datetime | None = None) -> dict[str, list[str]]:
        leader = self._leader.held() if self._leader.acquired else self._leader.try_acquire()
        out: dict[str, list[str]] = {"queued": [], "failed": [], "failed_over": []}
        if not leader:
            return out
        now = now or self.clock()
        for org_id, db in tenancy.for_each_active_org():
            try:
                self.tick_org(db, org_id, now, out)
            except Exception:
                db.rollback()
                log.exception("directory syncs of organisation %s failed", org_id)
        return out

    def tick_org(self, db: Session, org_id: str, now: datetime, out: dict[str, list[str]]) -> None:
        sources = list(db.scalars(select(DirectorySource)))
        if not sources:
            return
        for src in sources:
            try:
                self._supervise(db, src, now, out)
                db.commit()
                if src.enabled:
                    self._maybe_queue(db, src, now, out)
                    db.commit()
            except Exception:
                db.rollback()
                log.exception("directory source %s: scheduling failed", src.id)
        last = self._reconciled.get(org_id)
        if last is None or now - last >= RECONCILE_INTERVAL:
            n = svc.purge_missing(db, now)
            if n:
                log.info("purged %d directory objects missing for too long (organisation %s)", n, org_id)
            db.commit()
            reconcile.reconcile(db, now)
            self._reconciled[org_id] = now

    def _supervise(self, db: Session, src: DirectorySource, now: datetime, out: dict[str, list[str]]) -> None:
        run = svc.active_run(db, src.id)
        if run is None:
            return
        reason = None
        if run.status == "queued":
            cmd = db.get(DeviceCommand, run.command_id) if run.command_id else None
            if cmd is None or cmd.status in ("expired", "cancelled"):
                reason = "the collector did not pick up the sync (command expired or cancelled)"
            elif now - run.queued_at >= svc.PICKUP_TIMEOUT:
                minutes = int(svc.PICKUP_TIMEOUT.total_seconds() // 60)
                reason = f"the collector did not pick up the sync within {minutes} minutes (offline?)"
                if cmd.status == "pending":
                    cmd.status, cmd.completed_at, cmd.output = "cancelled", now, "directory sync failed over"
        else:
            last = run.last_batch_at or run.started_at or run.queued_at
            if run.token_expires_at is not None and run.token_expires_at < now:
                reason = "the sync did not finish before its upload token expired"
            elif now - last >= svc.STALL_TIMEOUT:
                reason = f"no data from the collector for {int(svc.STALL_TIMEOUT.total_seconds() // 60)} minutes"
        if reason is None:
            return
        svc.fail_run(db, run, reason, now=now)
        out["failed"].append(run.id)
        if run.trigger == "test" or not src.enabled:
            return
        try:
            nxt = svc.queue_run(db, src, trigger=run.trigger, actor=svc.SYSTEM, attempt=run.attempt + 1,
                                tried=list(run.tried_device_ids or []), now=now)
        except svc.DirectoryError:
            return  # no other healthy collector: the failure stands (and was notified)
        audit(db, "directory_sync_failed_over", actor_email=svc.SYSTEM, target=f"directory-source:{src.id}",
              from_run=run.id, run_id=nxt.id, device_id=nxt.device_id, attempt=nxt.attempt)
        out["failed_over"].append(nxt.id)

    def _maybe_queue(self, db: Session, src: DirectorySource, now: datetime, out: dict[str, list[str]]) -> None:
        if svc.active_run(db, src.id) is not None:
            return
        last = svc.last_scheduled_run(db, src.id)
        if last is not None and now < last.queued_at + svc.interval(src):
            return
        try:
            run = svc.queue_run(db, src, trigger="scheduled", actor=svc.SYSTEM, now=now)
        except svc.DirectoryError as e:
            # Record the missed slot (so the schedule moves on and the failure is notified).
            run = DirectorySyncRun(source_id=src.id, trigger="scheduled", status="queued", queued_at=now,
                                   scopes=list((src.config or {}).get("scopes") or []), tried_device_ids=[])
            db.add(run)
            db.flush()
            svc.fail_run(db, run, e.detail, now=now)
            out["failed"].append(run.id)
            return
        audit(db, "directory_sync_started", actor_email=svc.SYSTEM, target=f"directory-source:{src.id}",
              run_id=run.id, trigger="scheduled", device_id=run.device_id)
        out["queued"].append(run.id)
