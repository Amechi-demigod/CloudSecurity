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


def _head() -> str:
    from alembic.script import ScriptDirectory

    return ScriptDirectory.from_config(db.alembic_config()).get_current_head()


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
            assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == _head()
        db.run_migrations(eng)  # idempotent
    finally:
        eng.dispose()


MIGRATION_CHAIN = ["0001_baseline", "0002_device_management", "0003_notifications", "0004_mfa_sso",
                   "0005_agent_installers", "0006_agent_updates", "0007_it_asset_lifecycle",
                   "0008_agent_update_automation", "0009_device_approvals_scripts", "0010_scheduled_scans"]


def test_migration_history_is_linear():
    """The feature branches each started at 0001_baseline; once integrated they
    must form one linear chain with exactly one head."""
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(db.alembic_config())
    assert script.get_heads() == [MIGRATION_CHAIN[-1]]
    chain = [r.revision for r in script.walk_revisions("base", "heads")][::-1]
    assert chain == MIGRATION_CHAIN


def test_upgrade_from_baseline_and_downgrade(tmp_path):
    """A database at 0001_baseline (deployed Phase 3) upgrades to head, and the
    downgrade path back to the baseline works too."""
    if IS_POSTGRES:
        reset_database()
        eng = db.create_db_engine(TEST_DATABASE_URL)
    else:
        eng = db.create_db_engine(f"sqlite:///{tmp_path / 'baseline.db'}")
    try:
        db.run_migrations(eng, "0001_baseline")
        insp = inspect(eng)
        assert insp.has_table("users") and not insp.has_table("devices")
        assert not insp.has_table("notification_rules") and not insp.has_table("user_mfa")
        db.run_migrations(eng)
        with eng.connect() as conn:
            assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == _head()
        assert _schema_diff(eng) == []

        from alembic import command

        command.downgrade(db.alembic_config(eng), "0001_baseline")
        insp = inspect(eng)
        assert not insp.has_table("devices") and not insp.has_table("notification_rules")
        assert not insp.has_table("user_mfa") and insp.has_table("users")
        db.run_migrations(eng)
        assert _schema_diff(eng) == []
    finally:
        eng.dispose()


def test_sqlite_create_all_startup_path(tmp_path):
    """SQLite deployments use create_all() (+ additive columns) at startup rather
    than Alembic: every feature's tables are created."""
    if IS_POSTGRES:
        pytest.skip("SQLite startup path")
    try:
        eng = db.init_engine(f"sqlite:///{tmp_path / 'startup.db'}")
        names = set(inspect(eng).get_table_names())
        assert {t.name for t in db.Base.metadata.sorted_tables} <= names
        assert {"devices", "notification_rules", "user_mfa", "user_identities"} <= names
    finally:
        fresh_db()


@pytest.mark.skipif(not IS_POSTGRES, reason="PostgreSQL only (SQLite uses create_all)")
def test_pre_alembic_postgres_database_is_stamped():
    reset_database()
    eng = db.create_db_engine(TEST_DATABASE_URL)
    try:
        # How Phase 1/2 created schemas: only the baseline tables existed then (the
        # MFA tables are created too, to exercise 0004_mfa_sso's has_table guards).
        later = ("notification_", "device", "enrollment_tokens", "agent_", "it_asset", "scan_schedule")
        baseline = [t for t in db.Base.metadata.sorted_tables if not t.name.startswith(later)]
        db.Base.metadata.create_all(eng, tables=baseline)
        db.run_migrations(eng)  # stamped at the baseline, then upgraded
        with eng.connect() as conn:
            assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == _head()
        assert inspect(eng).has_table("notification_deliveries") and inspect(eng).has_table("devices")
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
