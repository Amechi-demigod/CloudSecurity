"""FastAPI application entrypoint.

Run locally:  uvicorn app.main:app --reload   (from the backend/ directory)
Production:   gunicorn -c gunicorn.conf.py app.main:app   (see the Dockerfile)
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse, RedirectResponse

from . import auth, config, db, locks, logging_setup, tenancy
from .api import agent as agent_api
from .api import agent_update_auto as agent_update_auto_api
from .api import agent_updates as agent_updates_api
from .api import approvals as approvals_api
from .api import auth as auth_api
from .api import device_scripts as device_scripts_api
from .api import devices, inventory, platform, runtime, vulns
from .api import exposure as exposure_api
from .api import mfa_sso as mfa_sso_api
from .api import organization as organization_api
from .asset_lifecycle import api as it_assets_api
from .notifications import api as notifications_api
from .notifications import settings as notification_settings
from .notifications.worker import NotificationWorker, set_worker
from .security import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from .services.agent_update_auto import AgentUpdateWorker
from .services.scan_schedule import ScanScheduler
from .services.simulation import RuntimeSimulator, seed_if_empty
from .vulnmatch import worker as vuln_worker

log = logging.getLogger("cnapp")


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = config.settings
    db.init_engine(s.database_url)
    # Several replicas / workers may start together: one at a time creates the
    # first admin and seeds the simulated environment.
    with locks.advisory_lock("startup"):
        with db.get_session(tenancy.DEFAULT_ORG_ID) as session:
            auth.bootstrap_admin(session)
        if s.simulation_mode:
            seed_if_empty(s.seed)
    app.state.simulator = None
    if s.simulation_mode:
        if s.simulator_enabled:
            app.state.simulator = RuntimeSimulator(
                interval=s.simulator_interval_seconds, attack_probability=s.simulator_attack_probability
            )
            app.state.simulator.start()
            log.info("Runtime simulator started (every %.0fs)", s.simulator_interval_seconds)
    ns = notification_settings.get()
    for p in ns.problems():
        log.warning("notifications: %s", p)
    app.state.notifier = None
    if ns.worker_enabled:
        # Leader election: only one replica / worker sends.
        app.state.notifier = NotificationWorker(interval=ns.poll_seconds)
        set_worker(app.state.notifier)
        app.state.notifier.start()
    # Automatic agent rollout + GitHub Releases auto-import (leader-elected).
    app.state.agent_updates = None
    if s.agent_update_worker_enabled:
        app.state.agent_updates = AgentUpdateWorker()
        app.state.agent_updates.start()
    # Scheduled cloud posture scans (leader-elected; enabled / interval are read
    # from the database on every tick, so console changes apply without a restart).
    app.state.scan_scheduler = None
    if s.scan_scheduler_worker_enabled:
        app.state.scan_scheduler = ScanScheduler()
        app.state.scan_scheduler.start()
    # Vulnerability (CVE) matching: feeds, debounced re-matching, KEV / EPSS
    # (leader-elected; never runs inside a request).
    app.state.vuln_worker = None
    if s.vuln_worker_enabled and s.vuln_matching_enabled:
        app.state.vuln_worker = vuln_worker.VulnWorker()
        vuln_worker.set_worker(app.state.vuln_worker)
        app.state.vuln_worker.start()
    yield
    if app.state.vuln_worker:
        app.state.vuln_worker.stop()
        vuln_worker.set_worker(None)
    if app.state.scan_scheduler:
        app.state.scan_scheduler.stop()
    if app.state.simulator:
        app.state.simulator.stop()
    if app.state.notifier:
        app.state.notifier.stop()
        set_worker(None)
    if app.state.agent_updates:
        app.state.agent_updates.stop()


def create_app() -> FastAPI:
    s = config.settings
    logging_setup.configure(s.effective_log_format, s.log_level)
    problems = s.production_problems() if s.is_production else s.auth_config_problems()
    if problems:
        for p in problems:
            log.critical("refusing to start: %s", p)
        kind = "insecure production" if s.is_production else "invalid"
        raise RuntimeError(f"{kind} configuration: " + "; ".join(problems))
    if "*" in s.cors_origins:
        log.warning("CORS_ORIGINS contains '*': any website can read this API from a browser")
    auth.login_limiter.reset()
    agent_api.device_limiter.reset()
    agent_api.enroll_limiter.reset()
    app = FastAPI(
        debug=s.debug and not s.is_production,
        title="CloudSecurity CNAPP",
        version="0.1.0",
        description="Runtime-first cloud security platform MVP: inventory, CSPM, runtime-aware "
        "vulnerability prioritization, CDR and attack paths.",
        lifespan=lifespan,
        # Served below under /api/ so they work through the frontend's /api proxy,
        # and require a login unless API_DOCS_PUBLIC=true.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    origins = config.settings.cors_origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials="*" not in origins,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type", auth.CSRF_HEADER],
    )
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=s.max_request_bytes,
                       path_limits={"/api/agent/": max(s.agent_max_request_bytes, s.max_request_bytes),
                                    "/api/updates/releases": max(s.agent_update_max_bundle_bytes, s.max_request_bytes),
                                    # IT assets: CSV import and wipe / destruction certificate uploads
                                    it_assets_api.UPLOAD_PREFIXES[0]: max(s.asset_import_max_bytes,
                                                                          s.max_request_bytes),
                                    it_assets_api.UPLOAD_PREFIXES[1]: max(s.asset_certificate_max_bytes,
                                                                          s.max_request_bytes),
                                    "/api/scripts/bundles": max(s.device_script_max_bundle_bytes, s.max_request_bytes),
                                    # sensor package inventory (a few thousand packages per host)
                                    "/api/runtime/packages": max(8 * 1024 * 1024, s.max_request_bytes)})
    app.add_middleware(SecurityHeadersMiddleware, hsts_max_age=s.hsts_max_age if s.is_production else 0)

    # Public: health probe, login, sensor ingest (own bearer-token auth) and the
    # endpoint-agent API (per-device credentials, never user sessions).
    app.include_router(platform.public_router)
    app.include_router(runtime.ingest_router)
    app.include_router(agent_api.router)
    app.include_router(agent_updates_api.device_router)  # /api/agent/updates/*: device credentials
    app.include_router(device_scripts_api.device_router)  # /api/agent/scripts/*: device credentials
    app.include_router(auth_api.router)  # /login is public; the others depend on the session
    app.include_router(mfa_sso_api.router)  # /login/mfa*, /providers and /sso/* are public
    # Everything else requires a logged-in user (viewer or higher). Write
    # endpoints additionally require analyst/admin via their own dependencies.
    session_required = [Depends(auth.require_viewer)]
    for r in (platform.router, inventory.router, vulns.router, runtime.router, devices.router):
        app.include_router(r, dependencies=session_required)
    app.include_router(exposure_api.router, dependencies=session_required)  # /api/exposure: any signed-in user
    app.include_router(auth_api.admin_router)
    app.include_router(agent_update_auto_api.router)  # /api/updates/automation, /api/updates/update-now
    app.include_router(notifications_api.router)  # analyst read-only, admin writes
    app.include_router(mfa_sso_api.admin_router)
    app.include_router(it_assets_api.router)  # /api/it-assets/*: viewer reads, analyst/admin writes
    app.include_router(agent_updates_api.router)  # /api/updates/*: viewer reads, admin writes (all audited)
    app.include_router(approvals_api.router)  # /api/approvals/*: admin only (two-person rule)
    app.include_router(device_scripts_api.router)  # /api/scripts/*: viewer reads, admin imports / runs
    app.include_router(organization_api.router)  # /api/organization/*: the session's organisation
    if s.api_docs_enabled:
        _add_docs(app)
    return app


def _add_docs(app: FastAPI) -> None:
    deps = [] if config.settings.api_docs_public else [Depends(auth.require_viewer)]

    @app.get("/api/openapi.json", include_in_schema=False, dependencies=deps)
    def openapi_json():
        return JSONResponse(app.openapi())

    @app.get("/api/docs", include_in_schema=False, dependencies=deps)
    def swagger_ui():
        return get_swagger_ui_html(openapi_url="/api/openapi.json", title=f"{app.title} - API docs")

    @app.get("/docs", include_in_schema=False)
    def docs_redirect():
        return RedirectResponse("/api/docs")


app = create_app()
