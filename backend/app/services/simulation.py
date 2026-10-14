"""Seeding + background runtime-event simulator (simulated data mode)."""
from __future__ import annotations

import logging
import random
import threading
from datetime import timedelta

from sqlalchemy import func, select

from .. import db as dbmod
from ..connectors.simulated import (SimulatedConnector, benign_events, generate_history, pick_scenario,
                                    workload_dicts)
from ..models import Asset, utcnow
from .ingest import ingest_collection
from .runtime import ingest_event

log = logging.getLogger(__name__)


def seed_if_empty(seed: int = 42, history: bool = True) -> bool:
    """Populate the DB with the simulated environment if it has no assets yet."""
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
    """Background thread emitting simulated runtime events every N seconds."""

    def __init__(self, interval: float = 15.0, seed: int | None = None, attack_probability: float = 0.05):
        self.interval = interval
        self.attack_probability = attack_probability
        self.rng = random.Random(seed)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

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

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                simulate_tick(self.rng, self.attack_probability)
            except Exception:  # never let the simulator die
                log.exception("simulator tick failed")
