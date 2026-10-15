"""Database portability: URL handling, Alembic migrations, locks and leader election.

Runs against SQLite by default and against PostgreSQL when TEST_DATABASE_URL
points to one (CI runs both).
"""
from __future__ import annotations

import threading

import pytest
from sqlalchemy import inspect, text

from app import db, locks
from app.services.simulation import RuntimeSimulator
from tests.conftest import IS_POSTGRES, TEST_DATABASE_URL, fresh_db, reset_database


@pytest.mark.parametrize("url,expected", [
    ("postgres://u:p@h:5432/d?sslmode=require", "postgresql+psycopg://u:p@h:5432/d?sslmode=require"),
    ("postgresql://u:p@h/d", "postgresql+psycopg://u:p@h/d"),
    ("postgresql+psycopg://u:p@h/d", "postgresql+psycopg://u:p@h/d"),
    ("sqlite:///./cnapp.db", "sqlite:///./cnapp.db"),
])
def test_normalize_url(url, expected):
    assert db.normalize_url(url) == expected


def _schema_diff(eng):
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    with eng.connect() as conn:
        mc = MigrationContext.configure(conn, opts={"compare_type": True})
        return compare_metadata(mc, db.Base.metadata)


def test_migrations_match_models(tmp_path):
    """`alembic upgrade head` on an empty database yields exactly the ORM schema."""
    if IS_POSTGRES:
        reset_database()
        eng = db.create_db_engine(TEST_DATABASE_URL)
    else:
        eng = db.create_db_engine(f"sqlite:///{tmp_path / 'migrated.db'}")
    try:
        db.run_migrations(eng)
        insp = inspect(eng)
        assert insp.has_table("alembic_version") and insp.has_table("users") and insp.has_table("assets")
        assert _schema_diff(eng) == []
        with eng.connect() as conn:
            assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0002_device_management"
        db.run_migrations(eng)  # idempotent
    finally:
        eng.dispose()


@pytest.mark.skipif(not IS_POSTGRES, reason="PostgreSQL only (SQLite uses create_all)")
def test_pre_alembic_postgres_database_is_stamped():
    reset_database()
    eng = db.create_db_engine(TEST_DATABASE_URL)
    try:
        # How Phase 1/2 created schemas (before the device-management tables existed).
        phase2 = [t for t in db.Base.metadata.sorted_tables if not t.name.startswith(("device", "enrollment"))]
        db.Base.metadata.create_all(eng, tables=phase2)
        db.run_migrations(eng)
        with eng.connect() as conn:
            assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0002_device_management"
    finally:
        eng.dispose()


def test_init_engine_without_migrate_leaves_db_untouched():
    reset_database()
    eng = db.init_engine(TEST_DATABASE_URL, migrate=False)
    assert not inspect(eng).has_table("assets")
    fresh_db()


def test_leader_lock_is_exclusive(session):
    a, b = locks.LeaderLock("t-exclusive"), locks.LeaderLock("t-exclusive")
    result = {}

    def contender():  # a different thread, as another replica would be
        result["b"] = b.try_acquire()

    assert a.try_acquire() and a.held()
    t = threading.Thread(target=contender)
    t.start()
    t.join()
    assert result["b"] is False
    a.release()
    t = threading.Thread(target=contender)
    t.start()
    t.join()
    assert result["b"] is True and b.held()
    b.release()
    assert not b.acquired


def test_advisory_lock_non_blocking(session):
    with locks.advisory_lock("t-ctx") as got:
        assert got
        seen = {}
        t = threading.Thread(target=lambda: seen.setdefault("inner", locks.advisory_lock("t-ctx", blocking=False)
                                                            .__enter__()))
        t.start()
        t.join()
        assert seen["inner"] is False
    with locks.advisory_lock("t-ctx", blocking=False) as again:
        assert again


def test_sqlite_file_lock(tmp_path, session):
    if IS_POSTGRES:
        pytest.skip("SQLite file locking")
    db.init_engine(f"sqlite:///{tmp_path / 'locks.db'}")
    try:
        a, b = locks.LeaderLock("t-file"), locks.LeaderLock("t-file")
        assert a.try_acquire() and a._fd is not None
        assert b.try_acquire() is False  # flock conflicts across file descriptions
        a.release()
        assert b.try_acquire()
        b.release()
    finally:
        fresh_db()


def test_only_one_simulator_emits_events(client):
    """Two replicas each start a simulator; only the leader emits events and the
    other takes over once the leader stops."""
    from app.models import RuntimeEvent

    def count():
        with db.get_session() as s:
            return s.query(RuntimeEvent).count()

    sims = [RuntimeSimulator(interval=3600, seed=i, attack_probability=0) for i in (1, 2)]
    outcomes = {}

    def tick(i):
        outcomes[i] = sims[i].tick()

    try:
        before = count()
        for i in (0, 1):  # each "replica" ticks from its own thread
            t = threading.Thread(target=tick, args=(i,))
            t.start()
            t.join()
        assert sorted(bool(v) for v in outcomes.values()) == [False, True]
        leader = 0 if outcomes[0] else 1
        assert sims[leader].is_leader and not sims[1 - leader].is_leader
        assert count() > before
        sims[leader].stop()  # leader shuts down: lock released
        t = threading.Thread(target=tick, args=(1 - leader,))
        t.start()
        t.join()
        assert outcomes[1 - leader] > 0 and sims[1 - leader].is_leader
    finally:
        for s in sims:
            s._stop.set()
            s._leader.release()


@pytest.mark.skipif(not IS_POSTGRES, reason="PostgreSQL only")
def test_leader_lock_lost_when_connection_dies(session):
    for drop in ("invalidate", "close_dbapi"):
        lock = locks.LeaderLock("t-lost")
        assert lock.try_acquire()
        if drop == "invalidate":  # SQLAlchemy would transparently reconnect
            lock._conn.invalidate()
        else:  # the server / network dropped the connection
            lock._conn.connection.dbapi_connection.close()
        assert lock.held() is False and not lock.acquired
        other = locks.LeaderLock("t-lost")
        assert other.try_acquire()  # the server released the advisory lock
        other.release()
