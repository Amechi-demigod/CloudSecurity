"""FastAPI application entrypoint.

Run locally:  uvicorn app.main:app --reload   (from the backend/ directory)
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import config, db
from .api import inventory, platform, runtime, vulns
from .services.simulation import RuntimeSimulator, seed_if_empty

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("cnapp")


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = config.settings
    db.init_engine(s.database_url)
    app.state.simulator = None
    if s.simulation_mode:
        seed_if_empty(s.seed)
        if s.simulator_enabled:
            app.state.simulator = RuntimeSimulator(interval=s.simulator_interval_seconds)
            app.state.simulator.start()
            log.info("Runtime simulator started (every %.0fs)", s.simulator_interval_seconds)
    yield
    if app.state.simulator:
        app.state.simulator.stop()


def create_app() -> FastAPI:
    app = FastAPI(
        title="CloudSecurity CNAPP",
        version="0.1.0",
        description="Runtime-first cloud security platform MVP: inventory, CSPM, runtime-aware "
        "vulnerability prioritization, CDR and attack paths.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.settings.cors_origins,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["*"],
    )
    for r in (platform.router, inventory.router, vulns.router, runtime.router):
        app.include_router(r)
    return app


app = create_app()
