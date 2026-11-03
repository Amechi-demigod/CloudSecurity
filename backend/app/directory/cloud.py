"""Server-side collection of cloud directories (docs/DIRECTORY_DISCOVERY.md#server-side-collection).

Entra ID + Intune (directory/graph.py) and Google Workspace (directory/google.py)
are read by the platform itself over their HTTPS APIs; no collector agent is
involved. They reuse everything else of directory discovery: sources, sync
runs, the scheduler, upsert by (source, external id), missing-marking,
matching, findings, notifications, audit, RBAC and tenancy.

Flow of one sync:

1. `service.queue_run` records a queued run (no command, no collector).
2. `kick` hands it to a small in-process worker pool. Whichever process claims
   the run first (an atomic queued -> running UPDATE) executes it, so several
   API workers and the scheduler never run it twice. The leader-elected
   scheduler re-kicks queued runs nobody picked up (e.g. after a restart) and
   fails running ones that stopped making progress.
3. `execute` runs the provider's parts in order (users, roles, devices,
   Intune, ...). Each part pages through its API and streams every page into
   the same upsert path as agent batches (one page in memory, committed per
   page, which is also the run's heartbeat). A part the tenant is not licensed
   or permitted for is skipped with a clear status; the others continue.
4. Only parts that completed (and a run under the safety cap) mark the objects
   they did not return as missing. Matches and findings are re-evaluated.

"Test & save" (`test_source`) runs the provider's permission / licence checks
synchronously and records them on a test run.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..models import utcnow
from . import service as svc
from .cloud_http import CloudApiError, CloudHttp
from .models import CLOUD_TYPES, DirectoryComputer, DirectorySource, DirectorySyncRun, DirectoryUser

log = logging.getLogger(__name__)

WORKERS = 2
# Tests: run kicked syncs synchronously in the calling thread.
INLINE = False

_pool: ThreadPoolExecutor | None = None
_pending: set[str] = set()
_lock = threading.Lock()


# ----------------------------------------------------------------------------- parts
class PartSkipped(Exception):
    """A part cannot run for this tenant: status is missing_permission,
    unlicensed or not_enabled; the rest of the sync continues."""

    def __init__(self, status: str, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


class CapReached(Exception):
    """The run's max_objects safety cap was reached."""


class Cancelled(Exception):
    """The run was ended elsewhere (source disabled / deleted)."""


class FatalError(Exception):
    """The whole sync cannot run (credential, configuration)."""


@dataclass
class Part:
    name: str
    label: str
    run: Callable[[SyncContext], dict[str, Any] | None]
    # (model, device kinds) the part fully lists when it completes: objects of
    # the source it did not return are marked missing. None: marks nothing.
    lists: tuple[Any, tuple[str, ...] | None] | None = None


@dataclass
class SyncContext:
    db: Session
    src: DirectorySource
    run: DirectorySyncRun
    http: CloudHttp
    status: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def config(self) -> dict[str, Any]:
        return self.src.config or {}

    def _room(self, n: int) -> int:
        return max(0, self.run.max_objects - (self.run.computers_seen + self.run.users_seen)) if n else 0

    def _check_running(self) -> None:
        """Before writing a page: the run may have been ended meanwhile (source disabled / deleted)."""
        status = self.db.scalar(select(DirectorySyncRun.status).where(DirectorySyncRun.id == self.run.id))
        if status != "running":
            raise Cancelled(f"the run was {status or 'deleted'}")

    def _page_done(self) -> None:
        self.run.next_seq += 1
        self.run.last_batch_at = utcnow()
        self.db.commit()

    def _store(self, model, items: list[dict[str, Any]]) -> int:
        self._check_running()
        room = self._room(len(items))
        capped = len(items) > room
        items = items[:room]
        n = svc.upsert_records(self.db, model, self.src, self.run, items, utcnow()) if items else 0
        if model is DirectoryUser:
            self.run.users_seen += n
        else:
            self.run.computers_seen += n
        self.run.truncated = self.run.truncated or capped
        self._page_done()
        if capped:
            raise CapReached()
        return n

    def store_users(self, items: list[dict[str, Any]]) -> int:
        return self._store(DirectoryUser, items)

    def store_computers(self, items: list[dict[str, Any]]) -> int:
        return self._store(DirectoryComputer, items)

    def update_computers(self, values: dict[str, dict[str, Any]], kinds: tuple[str, ...]) -> int:
        """Set columns on computers of this source already stored by this run
        (e.g. the primary user, listed separately). Keyed by external id."""
        self._check_running()
        n = 0
        keys = list(values)
        for i in range(0, len(keys), 500):
            for row in self.db.scalars(select(DirectoryComputer).where(
                    DirectoryComputer.source_id == self.src.id, DirectoryComputer.external_id.in_(keys[i:i + 500]),
                    DirectoryComputer.device_kind.in_(kinds))):
                for col, v in values[row.external_id].items():
                    setattr(row, col, v)
                n += 1
        self._page_done()
        return n

    def set_privileged(self, roles: dict[str, Iterable[str]], *, complete: bool) -> int:
        """Privileged role names per user external id. `complete`: users of the
        source not in `roles` lose their privileged flag (the role listing was
        complete); otherwise flags are only added. Returns privileged users."""
        self._check_running()
        want = {k: sorted(set(v)) for k, v in roles.items() if v}
        rows: dict[str, DirectoryUser] = {}
        keys = list(want)
        for i in range(0, len(keys), 500):
            rows.update({u.external_id: u for u in self.db.scalars(select(DirectoryUser).where(
                DirectoryUser.source_id == self.src.id, DirectoryUser.external_id.in_(keys[i:i + 500])))})
        if complete:
            rows.update({u.external_id: u for u in self.db.scalars(select(DirectoryUser).where(
                DirectoryUser.source_id == self.src.id, DirectoryUser.privileged.is_(True)))})
        n = 0
        for ext, u in rows.items():
            new = want.get(ext) or ([] if complete else list(u.privileged_roles or []))
            if list(u.privileged_roles or []) != new or u.privileged != bool(new):
                u.privileged_roles, u.privileged = new, bool(new)
            n += bool(new)
        self._page_done()
        return n


# ----------------------------------------------------------------------------- providers
class Provider:
    """One cloud directory type (graph.EntraProvider, google.GoogleProvider)."""

    type: str = ""
    label: str = ""

    def __init__(self, db: Session, src: DirectorySource, http: CloudHttp):
        self.db, self.src, self.http = db, src, http

    def validate(self) -> None:
        """Configuration / credential checks when the source is saved (DirectoryError)."""

    def connect(self) -> None:
        """Obtain credentials / tokens (FatalError when impossible)."""

    def parts(self, scopes: list[str]) -> list[Part]:
        raise NotImplementedError

    def checks(self) -> list[dict[str, Any]]:
        """Permission / licence checks for Test & save."""
        raise NotImplementedError


def provider_class(type_: str) -> type[Provider]:
    if type_ == "entra":
        from .graph import EntraProvider

        return EntraProvider
    if type_ == "google":
        from .google import GoogleProvider

        return GoogleProvider
    raise ValueError(f"not a cloud directory type: {type_}")


def validate_source(db: Session, src: DirectorySource) -> None:
    with CloudHttp() as http:
        provider_class(src.type)(db, src, http).validate()


def check(status: str, id_: str, label: str, detail: str = "", *, required: bool = True) -> dict[str, Any]:
    return {"id": id_, "label": label, "status": status, "detail": detail[:500], "required": required}


# ----------------------------------------------------------------------------- execution
def kick(org_id: str, run_id: str) -> None:
    """Execute a queued cloud run in the background (inline in tests)."""
    if INLINE:
        execute(org_id, run_id)
        return
    global _pool
    with _lock:
        if run_id in _pending:
            return
        _pending.add(run_id)
        if _pool is None:
            _pool = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="directory-cloud")
    _pool.submit(_execute_logged, org_id, run_id)


def is_pending(run_id: str) -> bool:
    with _lock:
        return run_id in _pending


def _execute_logged(org_id: str, run_id: str) -> None:
    try:
        execute(org_id, run_id)
    except Exception:
        log.exception("directory sync run %s failed unexpectedly", run_id)
    finally:
        with _lock:
            _pending.discard(run_id)


def execute(org_id: str, run_id: str) -> None:
    """Claim a queued run (atomically: one process wins) and run it."""
    from .. import db as dbmod
    from . import reconcile

    with dbmod.get_session(org_id) as db:
        now = utcnow()
        claimed = db.execute(update(DirectorySyncRun)
                             .where(DirectorySyncRun.id == run_id, DirectorySyncRun.status == "queued")
                             .values(status="running", started_at=now, last_batch_at=now)
                             .execution_options(synchronize_session=False)).rowcount
        db.commit()
        if not claimed:
            return
        run = db.get(DirectorySyncRun, run_id)
        src = db.get(DirectorySource, run.source_id) if run is not None else None
        if run is None:
            return
        if src is None or not src.enabled or src.type not in CLOUD_TYPES:
            svc.fail_run(db, run, "the directory source was disabled or deleted")
            db.commit()
            return
        src.last_sync_status = "running"
        db.commit()
        sync(db, src, run)
        try:
            reconcile.reconcile(db, notify=True)
        except Exception:
            db.rollback()
            log.exception("re-evaluating directory matches after run %s failed", run_id)


def sync(db: Session, src: DirectorySource, run: DirectorySyncRun) -> None:
    """Run every part of a claimed run and end it (commits)."""
    statuses: dict[str, dict[str, Any]] = {}
    completed: list[Part] = []
    fatal: str | None = None
    cancelled = False
    started = utcnow()
    with CloudHttp() as http:
        provider = provider_class(src.type)(db, src, http)
        ctx = SyncContext(db, src, run, http, statuses)
        try:
            provider.connect()
            for part in provider.parts(list(run.scopes or [])):
                try:
                    extra = part.run(ctx) or {}
                    statuses[part.name] = {"status": "ok", **extra}
                    completed.append(part)
                except PartSkipped as e:
                    statuses[part.name] = {"status": e.status, "detail": e.detail[:500]}
                    db.rollback()
                except CloudApiError as e:
                    statuses[part.name] = {"status": "error", "detail": str(e)[:500]}
                    db.rollback()
                except CapReached:
                    statuses[part.name] = {"status": "truncated",
                                           "detail": f"stopped at the {run.max_objects} objects safety cap"}
                    break
        except FatalError as e:
            fatal = str(e)
            db.rollback()
        except Cancelled:
            cancelled = True
            db.rollback()
        requests, throttled = http.requests, http.throttled
    if cancelled:
        return  # whoever ended the run recorded it
    db.refresh(run)
    if run.status != "running":
        return
    now = utcnow()
    run.finished_at = now
    run.agent_duration_ms = int((now - started).total_seconds() * 1000)
    run.scope_status = statuses
    run.server = f"{requests} API requests" + (f", throttled {throttled}x" if throttled else "")
    problems = [f"{name}: {s.get('detail') or s['status']}" for name, s in statuses.items()
                if s["status"] not in ("ok", "truncated")]
    if fatal or (not completed and not run.truncated):
        run.status = "failed"
        run.error = (fatal or "; ".join(problems) or "nothing was collected")[:2000]
    else:
        run.status = "succeeded"
        run.error = ("partial: " + "; ".join(problems))[:2000] if problems else None
    complete = run.status == "succeeded" and not run.truncated
    if complete:
        for part in completed:
            if part.lists is not None:
                model, kinds = part.lists
                svc.mark_missing(db, src, run, model, now, kinds)
    svc.record_run_end(db, src, run, now, complete=complete, actor=svc.SYSTEM)
    db.commit()


def test_source(db: Session, src: DirectorySource, actor: str) -> DirectorySyncRun:
    """Synchronous permission / licence checks ("Test & save"), recorded as a test
    run (caller commits). Nothing is stored but the check results."""
    now = utcnow()
    run = DirectorySyncRun(source_id=src.id, trigger="test", status="running", requested_by=actor,
                           tried_device_ids=[], scopes=list((src.config or {}).get("scopes") or []),
                           max_objects=0, queued_at=now, started_at=now)
    db.add(run)
    db.flush()
    with CloudHttp() as http:
        try:
            checks = provider_class(src.type)(db, src, http).checks()
        except FatalError as e:
            checks = [check("error", "credential", "Credentials", str(e))]
    run.checks = checks
    run.finished_at = utcnow()
    failed = [c for c in checks if c["required"] and c["status"] != "ok"]
    run.status = "failed" if failed else "succeeded"
    run.error = "; ".join(f"{c['label']}: {c['detail'] or c['status']}" for c in failed)[:2000] or None
    svc.record_run_end(db, src, run, run.finished_at, complete=False, actor=actor)
    return run


def rekick(org_id: str, run_id: str) -> None:
    """Scheduler: a queued cloud run this process is not already holding (e.g.
    queued before a restart, or by another process) is handed to the pool
    again; the atomic claim makes a duplicate harmless."""
    if not is_pending(run_id):
        kick(org_id, run_id)
