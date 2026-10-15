"""Cross-process locks and leader election, so several replicas (Container Apps)
or gunicorn workers can share one database safely.

* PostgreSQL: session-level advisory locks (`pg_advisory_lock`), held on a
  dedicated connection. They are released automatically if the process dies
  or its connection drops, so a new leader takes over.
* SQLite file database: an `flock` on a lock file next to the database (all
  processes sharing a SQLite file are on the same host).
* In-memory SQLite (tests): a per-process threading lock.
"""
from __future__ import annotations

import hashlib
import logging
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from . import db as dbmod

log = logging.getLogger(__name__)

try:  # pragma: no cover - platform dependent
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

_thread_locks: dict[str, threading.Lock] = {}
_thread_locks_guard = threading.Lock()


def lock_key(name: str) -> int:
    """Stable signed 64-bit advisory-lock key for `name`."""
    return int.from_bytes(hashlib.sha256(f"cnapp:{name}".encode()).digest()[:8], "big", signed=True)


def _thread_lock(name: str) -> threading.Lock:
    with _thread_locks_guard:
        return _thread_locks.setdefault(name, threading.Lock())


def _sqlite_lock_path(name: str) -> str | None:
    eng = dbmod.engine
    path = eng.url.database if eng is not None else None
    if not path or path == ":memory:" or fcntl is None:
        return None
    return f"{path}.{name}.lock"


class LeaderLock:
    """A named lock that is held until released (e.g. for the lifetime of a
    background job). `try_acquire()` never blocks; `held()` re-checks that the
    lock is still owned (PostgreSQL connection still alive)."""

    def __init__(self, name: str):
        self.name = name
        self._conn: Any = None  # PostgreSQL connection holding the advisory lock
        self._pid: int | None = None  # its server backend pid
        self._fd: int | None = None  # SQLite lock file
        self._tlock: threading.Lock | None = None

    @property
    def acquired(self) -> bool:
        return self._conn is not None or self._fd is not None or self._tlock is not None

    def try_acquire(self, blocking: bool = False) -> bool:
        if self.acquired:
            return self.held()
        eng = dbmod.engine
        assert eng is not None, "init_engine() not called"
        if eng.dialect.name == "postgresql":
            conn = eng.connect()
            try:
                fn = "pg_advisory_lock" if blocking else "pg_try_advisory_lock"
                from sqlalchemy import text

                got = conn.execute(text(f"SELECT {fn}(:k)"), {"k": lock_key(self.name)}).scalar()
                conn.commit()
                got = True if blocking else bool(got)
            except Exception:
                conn.invalidate()
                conn.close()
                raise
            if not got:
                conn.close()
                return False
            self._conn = conn
            self._pid = conn.execute(text("SELECT pg_backend_pid()")).scalar()
            conn.commit()
            return True
        path = _sqlite_lock_path(self.name)
        if path is not None:
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                return False
            self._fd = fd
            return True
        lock = _thread_lock(self.name)
        if not lock.acquire(blocking=blocking):
            return False
        self._tlock = lock
        return True

    def held(self) -> bool:
        """True if we still own the lock (drops ownership if the DB connection died)."""
        if self._conn is not None:
            try:
                from sqlalchemy import text

                # A reconnect (new backend pid) means the session that held the lock is gone.
                pid = self._conn.execute(text("SELECT pg_backend_pid()")).scalar()
                self._conn.commit()
                if pid != self._pid:
                    raise ConnectionError("advisory-lock connection was replaced")
                return True
            except Exception:
                log.warning("lost the %r leader lock (database connection dropped)", self.name)
                self._discard_conn()
                return False
        return self._fd is not None or self._tlock is not None

    def _discard_conn(self) -> None:
        try:
            self._conn.invalidate()  # never return a lock-holding connection to the pool
            self._conn.close()
        except Exception:  # pragma: no cover - best effort
            log.debug("closing a dead lock connection failed", exc_info=True)
        self._conn = None
        self._pid = None

    def release(self) -> None:
        if self._conn is not None:
            try:
                from sqlalchemy import text

                self._conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": lock_key(self.name)})
                self._conn.commit()
                self._conn.close()
                self._conn = self._pid = None
            except Exception:
                self._discard_conn()
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None
        if self._tlock is not None:
            self._tlock.release()
            self._tlock = None


@contextmanager
def advisory_lock(name: str, blocking: bool = True) -> Iterator[bool]:
    """Hold the named cross-process lock for the duration of the block.

    Yields True if acquired; with blocking=False, yields False (and the body
    should skip its work) when another process holds it.
    """
    lock = LeaderLock(name)
    got = lock.try_acquire(blocking=blocking)
    try:
        yield got
    finally:
        if got:
            lock.release()
