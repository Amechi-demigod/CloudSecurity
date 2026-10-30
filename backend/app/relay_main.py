"""Remote-session relay process (on-prem `relay` service).

    uvicorn app.relay_main:app --host 0.0.0.0 --port 8001 --workers 1

ONE worker on purpose: the agent and the viewer of a session must reach the
same process, which pairs their WebSockets in memory (app/remote_hub.py). The
REST API keeps running in the gunicorn backend (REMOTE_RELAY_MODE=api); nginx
sends only /api/remote/* and /api/agent/remote/* here. State is shared through
the database (remote_sessions); migrations are run by the backend.

Restarting this process (cnapp-ctl update / rollback) ends the live sessions
with end reason "relay_restart".
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.concurrency import run_in_threadpool

from . import config, db, logging_setup, remote_hub, tenancy
from .api import remote_relay
from .services import remote_sessions as rsvc

log = logging.getLogger("cnapp.remote")
SWEEP_SECONDS = 15.0


def sweep_all() -> int:
    n = 0
    for org_id, s in tenancy.for_each_active_org():
        try:
            n += rsvc.sweep(s)
            s.commit()
        except Exception:
            s.rollback()
            log.exception("remote session sweep of organisation %s failed", org_id)
    return n


async def _sweeper(stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            await run_in_threadpool(sweep_all)
        except Exception:
            log.exception("remote session sweep failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=SWEEP_SECONDS)
        except TimeoutError:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_engine(config.settings.database_url)
    stop = asyncio.Event()
    task = asyncio.create_task(_sweeper(stop), name="remote-session-sweep")
    yield
    stop.set()
    await remote_hub.hub.shutdown("relay_restart")
    # Sessions this process no longer holds (crash before shutdown): the sweep of
    # the next relay start ends them through the stale heartbeat.
    await run_in_threadpool(sweep_all)
    task.cancel()


def create_app() -> FastAPI:
    s = config.settings
    logging_setup.configure(s.effective_log_format, s.log_level)
    problems = s.production_problems() if s.is_production else s.auth_config_problems()
    if s.remote_relay_mode != "relay":
        problems = [*problems, "the relay process needs REMOTE_RELAY_MODE=relay"]
    if problems:
        for p in problems:
            log.critical("refusing to start: %s", p)
        raise RuntimeError("invalid configuration: " + "; ".join(problems))
    app = FastAPI(title="Remote session relay", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "component": "remote-relay", "sessions": len(remote_hub.hub.pairs)}

    app.include_router(remote_relay.router)
    return app


app = create_app() if config.settings.remote_relay_mode == "relay" else None
