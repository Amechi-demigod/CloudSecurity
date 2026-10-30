"""Remote-session relay process (on-prem `relay` service).

    python -m app.relay_main      agents on :8001, viewers on :8002

ONE process on purpose: the agent and the viewer of a session must reach the
same process, which pairs their WebSockets in memory (app/remote_hub.py). The
REST API keeps running in the gunicorn backend (REMOTE_RELAY_MODE=api); nginx
sends only /api/agent/remote/* (to :8001) and /api/remote/* (to :8002) here.
State is shared through the database (remote_sessions); migrations are run by
the backend.

The two ends get separate listeners so that uvicorn refuses an oversized
WebSocket frame before buffering it: agents send tiles (up to
REMOTE_SESSION_AGENT_MAX_MESSAGE_BYTES), viewers only small JSON
(REMOTE_SESSION_VIEWER_MAX_MESSAGE_BYTES). The relay re-checks both sizes too.

Restarting this process (cnapp-ctl update / rollback) ends the live sessions
with end reason "relay_restart".
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from starlette.concurrency import run_in_threadpool

from . import config, db, logging_setup, remote_hub, tenancy
from .api import remote_relay
from .services import remote_sessions as rsvc

log = logging.getLogger("cnapp.remote")
SWEEP_SECONDS = 15.0
AGENT_PORT, VIEWER_PORT = 8001, 8002


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


def _check_config() -> None:
    s = config.settings
    logging_setup.configure(s.effective_log_format, s.log_level)
    problems = s.production_problems() if s.is_production else s.auth_config_problems()
    if s.remote_relay_mode != "relay":
        problems = [*problems, "the relay process needs REMOTE_RELAY_MODE=relay"]
    if problems:
        for p in problems:
            log.critical("refusing to start: %s", p)
        raise RuntimeError("invalid configuration: " + "; ".join(problems))


def create_app(router=None, *, with_lifespan: bool = True) -> FastAPI:
    """One listener's app: `router` is remote_relay.agent_router, viewer_router
    or (default) both. The lifespan (database, sweeper, ending live sessions
    on shutdown) runs once per process: on the agent listener under main()."""
    _check_config()
    app = FastAPI(title="Remote session relay", lifespan=lifespan if with_lifespan else None,
                  docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "component": "remote-relay", "sessions": len(remote_hub.hub.pairs)}

    app.include_router(router or remote_relay.router)
    return app


class _Server(uvicorn.Server):
    # main() handles SIGTERM / SIGINT for both listeners.
    def capture_signals(self):
        return contextlib.nullcontext()


def _servers() -> tuple[_Server, _Server]:
    s = config.settings
    common = {"host": "0.0.0.0", "proxy_headers": False, "ws_ping_interval": 20.0,  # noqa: S104 (container)
              "timeout_graceful_shutdown": 20, "log_config": None}
    agent = uvicorn.Config(create_app(remote_relay.agent_router), port=AGENT_PORT,
                           ws_max_size=s.remote_session_agent_max_message_bytes + 65536, **common)
    # Twice the relay's own limit: a JSON message just over it still reaches the
    # relay (which ends the session as a protocol error); anything bigger is
    # refused by uvicorn before it is buffered.
    viewer = uvicorn.Config(create_app(remote_relay.viewer_router, with_lifespan=False), port=VIEWER_PORT,
                            ws_max_size=2 * s.remote_session_viewer_max_message_bytes, **common)
    return _Server(agent), _Server(viewer)


async def _run() -> None:
    agent, viewer = _servers()
    loop = asyncio.get_running_loop()
    stopping = asyncio.Event()

    def stop() -> None:
        if not stopping.is_set():
            stopping.set()
            # End the live sessions as "relay_restart" first (the agent listener's
            # lifespan does it again for anything left), then stop accepting.
            loop.create_task(_stop(agent, viewer))

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop)
    agent_task = asyncio.create_task(agent.serve(), name="relay-agent-listener")
    # The agent listener's lifespan initialises the database: viewers only after it.
    while not agent.started and not agent_task.done():
        await asyncio.sleep(0.05)
    viewer_task = asyncio.create_task(viewer.serve(), name="relay-viewer-listener") if agent.started else None
    try:
        await agent_task
    finally:
        viewer.should_exit = True
        if viewer_task is not None:
            await viewer_task


async def _stop(agent: _Server, viewer: _Server) -> None:
    try:
        await remote_hub.hub.shutdown("relay_restart")
    finally:
        agent.should_exit = viewer.should_exit = True


def main() -> None:
    asyncio.run(_run())


if __name__ == "__main__":
    main()
