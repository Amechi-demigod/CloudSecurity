"""Database portability: URL handling, Alembic migrations, locks and leader election.

Runs against SQLite by default and against PostgreSQL when TEST_DATABASE_URL
points to one (CI runs both).
"""
from __future__ import annotations

import threading

import pytest
from sqlalchemy import inspect, select, text

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
                   "0008_agent_update_automation", "0009_device_approvals_scripts", "0010_scheduled_scans",
                   "0011_vulnerability_matching", "0013_organizations"]


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


def test_sqlite_existing_vulnerabilities_table_is_relaxed(tmp_path):
    """An SQLite database from before CVE matching has vulnerabilities.asset_id
    NOT NULL; startup rebuilds the table (keeping rows) so endpoint-device
    vulnerabilities (no asset) can be stored."""
    if IS_POSTGRES:
        pytest.skip("SQLite startup path")
    path = tmp_path / "old.db"
    old = db.create_db_engine(f"sqlite:///{path}")
    try:
        db.run_migrations(old, "0010_scheduled_scans")
        with old.begin() as conn:
            conn.execute(text("INSERT INTO assets (id, name, type, provider, tags, internet_exposed, sensitive_data, "
                              "properties, source, first_seen, last_seen) VALUES ('a1', 'vm1', 'vm', 'azure', '{}', "
                              "0, 0, '{}', 'simulated', '2026-01-01', '2026-01-01')"))
            conn.execute(text("INSERT INTO vulnerabilities (id, asset_id, cve_id, package, version, title, cvss, "
                              "severity, exploit_available, in_use, internet_exposed, sensitive_data_access, "
                              "risk_score, priority, status, source, first_seen) VALUES ('v1', 'a1', 'CVE-1', "
                              "'openssl', '1', '', 9.8, 'critical', 0, 0, 0, 0, 10, 'low', 'open', 'simulated', "
                              "'2026-01-01')"))
        cols = {c["name"]: c for c in inspect(old).get_columns("vulnerabilities")}
        assert cols["asset_id"]["nullable"] is False and "device_id" not in cols
    finally:
        old.dispose()
    try:
        eng = db.init_engine(f"sqlite:///{path}")
        cols = {c["name"]: c for c in inspect(eng).get_columns("vulnerabilities")}
        assert cols["asset_id"]["nullable"] is True and "device_id" in cols and "kev" in cols
        idx = {i["name"] for i in inspect(eng).get_indexes("vulnerabilities")}
        assert {"ix_vulnerabilities_asset_id", "ix_vulnerabilities_device_id"} <= idx
        with eng.begin() as conn:
            assert conn.execute(text("SELECT cve_id, asset_id FROM vulnerabilities")).all() == [("CVE-1", "a1")]
        db.init_engine(f"sqlite:///{path}")  # idempotent
    finally:
        fresh_db()


@pytest.mark.skipif(not IS_POSTGRES, reason="PostgreSQL only (SQLite uses create_all)")
def test_pre_alembic_postgres_database_is_stamped():
    reset_database()
    eng = db.create_db_engine(TEST_DATABASE_URL)
    try:
        # How Phase 1/2 created schemas: only the baseline tables existed then (the
        # MFA tables are created too, to exercise 0004_mfa_sso's has_table guards).
        later = ("notification_", "device", "enrollment_tokens", "agent_", "it_asset", "scan_schedule", "vuln_",
                 "asset_packages")
        baseline = [t for t in db.Base.metadata.sorted_tables
                    if not t.name.startswith(later) and t.name != "vulnerabilities"]
        db.Base.metadata.create_all(eng, tables=baseline)
        # vulnerabilities as it was then: without the CVE-matching columns (device_id -> devices)
        from sqlalchemy import MetaData, Table

        md = MetaData()
        db.Base.metadata.tables["assets"].to_metadata(md)
        new_cols = {"device_id", "kev", "epss", "match_key", "last_seen", "resolved_at", "evidence"}
        old_vulns = Table("vulnerabilities", md, *[c._copy() for c in db.Base.metadata.tables["vulnerabilities"].columns
                                                   if c.name not in new_cols])
        md.create_all(eng, tables=[old_vulns])
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
        with db.get_session("default") as s:
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


# --- multi-tenancy upgrade (0013_organizations) ---------------------------------------------

def _fill(conn, table: str, **values):
    """Insert one row at the 0011 schema, filling NOT NULL columns we do not care about."""
    import datetime as dt

    from sqlalchemy import JSON, Boolean, Date, DateTime, Float, Integer, LargeBinary, MetaData, Numeric, Table

    t = Table(table, MetaData(), autoload_with=conn)
    row = dict(values)
    for c in t.columns:
        if c.name in row or c.nullable or c.autoincrement is True:
            continue
        ty = c.type
        row[c.name] = (dt.datetime(2026, 1, 1) if isinstance(ty, DateTime) else dt.date(2026, 1, 1)
                       if isinstance(ty, Date) else False if isinstance(ty, Boolean) else 0
                       if isinstance(ty, Integer | Float | Numeric) else {} if isinstance(ty, JSON) else b""
                       if isinstance(ty, LargeBinary) else "x")
    conn.execute(t.insert().values(**row))


OLD_ROWS = [
    ("users", {"id": "u1", "email": "admin@example.com", "role": "admin", "password_hash": "h"}),
    ("users", {"id": "u2", "email": "viewer@example.com", "role": "viewer", "password_hash": "h"}),
    ("user_sessions", {"id": "s1", "user_id": "u1"}),
    ("assets", {"id": "/subscriptions/1/vm1", "name": "vm1", "type": "vm"}),
    ("assets", {"id": "/subscriptions/1/nsg1", "name": "nsg1", "type": "nsg"}),
    ("relationships", {"source_id": "/subscriptions/1/nsg1", "target_id": "/subscriptions/1/vm1", "type": "protects"}),
    ("findings", {"id": "f1", "rule_id": "R1", "asset_id": "/subscriptions/1/vm1", "severity": "high"}),
    ("vulnerabilities", {"id": "v1", "asset_id": "/subscriptions/1/vm1", "cve_id": "CVE-1", "cvss": 9.0}),
    ("asset_packages", {"asset_id": "/subscriptions/1/vm1", "name": "openssl"}),
    ("devices", {"id": "d1", "hostname": "laptop-1", "os_family": "windows"}),
    ("device_credentials", {"id": "c1", "device_id": "d1", "secret_hash": "sh"}),
    ("vulnerabilities", {"id": "v2", "device_id": "d1", "cve_id": "CVE-2", "cvss": 5.0}),
    ("enrollment_tokens", {"id": "e1", "name": "t", "token_hash": "th"}),
    ("runtime_events", {"id": "ev1", "event_type": "process_exec"}),
    ("alerts", {"id": "al1", "rule_id": "D1", "severity": "high"}),
    ("alert_events", {"alert_id": "al1", "event_id": "ev1"}),
    ("scan_runs", {"id": "sr1", "connector": "azure"}),
    ("scan_schedule_settings", {"id": 1, "interval_hours": 3.0}),
    ("agent_update_settings", {"id": 1, "mode": "manual"}),
    ("agent_update_rings", {"id": "r1", "name": "Pilot"}),
    ("it_asset_settings", {"id": 1, "data": {"default_currency": "NGN"}}),
    ("it_assets", {"id": "i1", "asset_tag": "WK-0001", "device_id": "d1"}),
    ("notification_source_state", {"source": "attack_path", "state": {"seen": ["p1"]}}),
    ("notification_channels", {"id": "n1", "name": "Teams", "type": "teams"}),
    ("audit_log", {"action": "login_success", "actor_email": "admin@example.com"}),
    ("vuln_match_state", {"target_type": "device", "target_id": "d1"}),
]


def _check_migrated(eng):
    """Every pre-existing row belongs to the default organisation; roles became memberships."""
    with eng.connect() as conn:
        for table in sorted({t for t, _ in OLD_ROWS} - {"users"}):
            orgs = conn.execute(text(f"SELECT organization_id FROM {table}")).scalars().all()  # noqa: S608
            assert orgs and set(orgs) == {"default"}, table
        assert conn.execute(text("SELECT id, slug, is_default, status FROM organizations")).all() == [
            ("default", "default", True, "active")]
        assert sorted(conn.execute(text("SELECT user_id, role, organization_id FROM organization_memberships"))
                      .all()) == [("u1", "admin", "default"), ("u2", "viewer", "default")]
        assert conn.execute(text("SELECT count(*) FROM users WHERE is_platform_admin")).scalar() == 0
        assert conn.execute(text("SELECT interval_hours FROM scan_schedule_settings")).scalar() == 3.0
        cols = {c["name"] for c in inspect(eng).get_columns("users")}
        assert "role" not in cols and "is_platform_admin" in cols
    # The application reads the migrated data through the organisation-scoped ORM.
    from sqlalchemy.orm import Session

    from app import tenancy
    from app.models import Asset, Finding, Relationship, ScanScheduleSettings, get_asset

    with Session(eng) as s:
        tenancy.set_org(s, "default")
        assert get_asset(s, "/subscriptions/1/vm1").name == "vm1"
        assert s.scalar(select(Finding)).asset.name == "vm1"
        assert s.scalar(select(Relationship)).target_id == "/subscriptions/1/vm1"
        assert s.get(ScanScheduleSettings, "default").interval_hours == 3.0
        tenancy.set_org(s, "other")
        assert s.scalars(select(Asset)).all() == [] and get_asset(s, "/subscriptions/1/vm1") is None


def _db_at_0011_with_data(tmp_path, name: str):
    if IS_POSTGRES:
        reset_database()
        url = TEST_DATABASE_URL
    else:
        url = f"sqlite:///{tmp_path / name}"
    eng = db.create_db_engine(url)
    db.run_migrations(eng, "0011_vulnerability_matching")
    with eng.begin() as conn:
        for table, values in OLD_ROWS:
            _fill(conn, table, **values)
    return eng, url


def test_upgrade_from_0011_with_data_migrates_into_default_org(tmp_path):
    """Alembic path (PostgreSQL in production): existing data lands in the
    default organisation with no manual step; downgrade restores the old shape."""
    eng, _ = _db_at_0011_with_data(tmp_path, "upgrade.db")
    try:
        db.run_migrations(eng)
        assert _schema_diff(eng) == []
        _check_migrated(eng)

        from alembic import command

        command.downgrade(db.alembic_config(eng), "0011_vulnerability_matching")
        with eng.connect() as conn:
            assert conn.execute(text("SELECT role FROM users WHERE id = 'u1'")).scalar() == "admin"
            assert conn.execute(text("SELECT count(*) FROM findings")).scalar() == 1
            assert conn.execute(text("SELECT id FROM scan_schedule_settings")).scalar() == 1
        db.run_migrations(eng)
        assert _schema_diff(eng) == []
        _check_migrated(eng)
    finally:
        eng.dispose()


def test_sqlite_startup_upgrade_with_data(tmp_path):
    """SQLite installations upgrade at startup (create_all path, no Alembic):
    same result as the migration."""
    if IS_POSTGRES:
        pytest.skip("SQLite startup path")
    eng, url = _db_at_0011_with_data(tmp_path, "startup-upgrade.db")
    eng.dispose()
    try:
        eng = db.init_engine(url)
        _check_migrated(eng)
        db.init_engine(url)  # idempotent
        _check_migrated(db.engine)
    finally:
        fresh_db()
