"""Seeding + background runtime-event simulator (simulated data mode)."""
from __future__ import annotations

import logging
import random
import threading
from datetime import timedelta

from sqlalchemy import func, select

from .. import db as dbmod
from ..connectors.simulated import SimulatedConnector, benign_events, generate_history, pick_scenario, workload_dicts
from ..locks import LeaderLock
from ..models import Asset, utcnow
from .ingest import ingest_collection
from .runtime import ingest_event

log = logging.getLogger(__name__)


def seed_if_empty(seed: int = 42, history: bool = True) -> bool:
    """Populate the DB with the simulated environment if it has no assets yet.

    Callers starting several replicas at once should hold the "startup" lock
    (see app.main) so only one of them seeds."""
    with dbmod.get_session() as db:
        if db.scalar(select(func.count()).select_from(Asset)):
            return False
        result = SimulatedConnector(seed).collect()
        ingest_collection(db, result, source="simulated")
        if history:
            rng = random.Random(seed)
            workloads = workload_dicts(list(db.scalars(select(Asset))))
            for e in generate_history(rng, workloads, utcnow()):
                ingest_event(db, e, source="simulated")
            db.commit()
        log.info("Seeded simulated environment: %d assets", len(result.assets))
        return True


def simulate_tick(rng: random.Random, attack_probability: float = 0.25) -> int:
    """Emit one batch of live events. Returns number of events ingested."""
    with dbmod.get_session() as db:
        workloads = workload_dicts(list(db.scalars(select(Asset).where(Asset.type.in_(["vm", "pod", "function_app"])))))
        if not workloads:
            return 0
        now = utcnow()
        events = []
        for _ in range(rng.randint(2, 5)):
            events += benign_events(rng, rng.choice(workloads), now - timedelta(seconds=rng.randint(0, 5)))
        if rng.random() < attack_probability:
            exposed = [w for w in workloads if w["internet_exposed"]] or workloads
            asset = rng.choice(exposed)
            events += pick_scenario(rng, asset)(rng, asset, now)
        for e in events:
            ingest_event(db, e, source="simulated")
        db.commit()
        return len(events)


class RuntimeSimulator:
    """Background thread emitting simulated runtime events every N seconds.

    Safe to start in every replica / gunicorn worker: only the process holding
    the "runtime-simulator" leader lock (PostgreSQL advisory lock or SQLite
    file lock) emits events. The others keep trying each interval and take
    over if the leader goes away.
    """

    LOCK_NAME = "runtime-simulator"

    def __init__(self, interval: float = 15.0, seed: int | None = None, attack_probability: float = 0.05):
        self.interval = interval
        self.attack_probability = attack_probability
        self.rng = random.Random(seed)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._leader = LeaderLock(self.LOCK_NAME)
        self.is_leader = False

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="runtime-simulator", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
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
            log.info("runtime simulator: this instance is now the leader")
        return self.is_leader

    def tick(self) -> int:
        """One iteration: emit events if this instance is the leader."""
        if not self._check_leadership():
            return 0
        return simulate_tick(self.rng, self.attack_probability)

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.tick()
            except Exception:  # never let the simulator die
                log.exception("simulator tick failed")
