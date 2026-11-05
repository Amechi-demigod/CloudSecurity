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
                   "0011_vulnerability_matching", "0013_organizations", "0014_host_isolation",
                   "0015_command_result_data", "0016_dashboard_snapshots", "0017_onboarding_dismissed",
                   "0018_remote_sessions", "0019_offboarding_username", "0020_directory_discovery",
                   "0021_directory_cloud_sources", "0022_windows_updates", "0023_endpoint_actions",
                   "0024_agent_deployments", "0025_compliance_reports", "0026_device_classification",
                   "0027_directory_collectors"]


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
        # How Phase 1/2 created schemas: only the baseline tables existed then
        # (the baseline migration's schema, without Alembic's version table). The
        # MFA tables are created too, to exercise 0004_mfa_sso's has_table guards.
        db.run_migrations(eng, "0001_baseline")
        with eng.begin() as conn:
            conn.execute(text("DROP TABLE alembic_version"))
        mfa_tables = [db.Base.metadata.tables[t] for t in ("user_mfa", "mfa_recovery_codes", "mfa_challenges",
                                                            "user_identities", "oidc_auth_requests")]
        db.Base.metadata.create_all(eng, tables=mfa_tables)
        db.run_migrations(eng)  # stamped at the baseline, then upgraded
        with eng.connect() as conn:
            assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == _head()
        assert inspect(eng).has_table("notification_deliveries") and inspect(eng).has_table("devices")
        assert _schema_diff(eng) == []
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


def test_dashboard_snapshots_migration(tmp_path):
    """0016 adds dashboard_snapshots (unique per organisation, day and account)
    on top of 0015; downgrading removes it again."""
    if IS_POSTGRES:
        reset_database()
        eng = db.create_db_engine(TEST_DATABASE_URL)
    else:
        eng = db.create_db_engine(f"sqlite:///{tmp_path / 'snapshots.db'}")
    try:
        db.run_migrations(eng, "0015_command_result_data")
        assert not inspect(eng).has_table("dashboard_snapshots")
        db.run_migrations(eng, "0016_dashboard_snapshots")
        insp = inspect(eng)
        assert insp.has_table("dashboard_snapshots")
        cols = {c["name"] for c in insp.get_columns("dashboard_snapshots")}
        assert cols == {"id", "organization_id", "day", "account", "metrics", "created_at"}
        uniques = [set(u["column_names"]) for u in insp.get_unique_constraints("dashboard_snapshots")]
        assert {"organization_id", "day", "account"} in uniques
        db.run_migrations(eng)  # later revisions on top match the ORM
        assert _schema_diff(eng) == []

        from alembic import command

        command.downgrade(db.alembic_config(eng), "0015_command_result_data")
        assert not inspect(eng).has_table("dashboard_snapshots")
    finally:
        eng.dispose()


def test_onboarding_dismissed_migration(tmp_path):
    """0017 adds the organisation's checklist dismissal columns on top of 0016
    (existing organisations stay not dismissed); downgrading removes them."""
    if IS_POSTGRES:
        reset_database()
        eng = db.create_db_engine(TEST_DATABASE_URL)
    else:
        eng = db.create_db_engine(f"sqlite:///{tmp_path / 'onboarding.db'}")
    try:
        db.run_migrations(eng, "0016_dashboard_snapshots")
        assert "onboarding_dismissed_at" not in {c["name"] for c in inspect(eng).get_columns("organizations")}
        db.run_migrations(eng, "0017_onboarding_dismissed")
        cols = {c["name"]: c for c in inspect(eng).get_columns("organizations")}
        assert cols["onboarding_dismissed_at"]["nullable"] and cols["onboarding_dismissed_by"]["nullable"]
        with eng.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM organizations WHERE onboarding_dismissed_at IS NOT NULL")
                                ).scalar() == 0
        db.run_migrations(eng)  # later revisions on top match the ORM
        assert _schema_diff(eng) == []

        from alembic import command

        command.downgrade(db.alembic_config(eng), "0016_dashboard_snapshots")
        assert "onboarding_dismissed_at" not in {c["name"] for c in inspect(eng).get_columns("organizations")}
    finally:
        eng.dispose()


def test_remote_sessions_migration(tmp_path):
    """0018 adds remote_sessions (one open session per device through the
    nullable unique open_device_id) on top of 0017; downgrading removes it."""
    if IS_POSTGRES:
        reset_database()
        eng = db.create_db_engine(TEST_DATABASE_URL)
    else:
        eng = db.create_db_engine(f"sqlite:///{tmp_path / 'remote.db'}")
    try:
        db.run_migrations(eng, "0017_onboarding_dismissed")
        assert not inspect(eng).has_table("remote_sessions")
        db.run_migrations(eng, "0018_remote_sessions")
        insp = inspect(eng)
        assert insp.has_table("remote_sessions")
        cols = {c["name"] for c in insp.get_columns("remote_sessions")}
        assert {"token_hash", "open_device_id", "mode", "state", "bytes_to_viewer"} <= cols
        assert not {"token", "frames", "keystrokes"} & cols  # metadata only
        uniques = [set(u["column_names"]) for u in insp.get_unique_constraints("remote_sessions")]
        assert {"open_device_id"} in uniques
        db.run_migrations(eng)  # later revisions on top match the ORM
        assert _schema_diff(eng) == []

        from alembic import command

        command.downgrade(db.alembic_config(eng), "0017_onboarding_dismissed")
        assert not inspect(eng).has_table("remote_sessions")
    finally:
        eng.dispose()


def test_offboarding_username_migration(tmp_path):
    """0019 adds it_asset_offboardings.person_username (existing offboardings get
    an empty username) on top of 0018; downgrading removes it."""
    if IS_POSTGRES:
        reset_database()
        eng = db.create_db_engine(TEST_DATABASE_URL)
    else:
        eng = db.create_db_engine(f"sqlite:///{tmp_path / 'offboarding.db'}")
    try:
        db.run_migrations(eng, "0018_remote_sessions")
        assert "person_username" not in {c["name"] for c in inspect(eng).get_columns("it_asset_offboardings")}
        with eng.begin() as conn:
            org = conn.execute(text("SELECT id FROM organizations LIMIT 1")).scalar()
            conn.execute(text(
                "INSERT INTO it_asset_offboardings (id, organization_id, person_email, person_name, department, "
                "leave_date, retrieval_due, status, notes, created_at) VALUES ('ob1', :org, 'a@example.com', '', '', "
                "'2026-01-01', '2026-01-08', 'open', '', '2026-01-01 00:00:00')"), {"org": org})
        db.run_migrations(eng, "0019_offboarding_username")
        cols = {c["name"]: c for c in inspect(eng).get_columns("it_asset_offboardings")}
        assert not cols["person_username"]["nullable"]
        with eng.connect() as conn:
            assert conn.execute(text("SELECT person_username FROM it_asset_offboardings")).scalar() == ""
        db.run_migrations(eng)
        assert _schema_diff(eng) == []

        from alembic import command

        command.downgrade(db.alembic_config(eng), "0018_remote_sessions")
        assert "person_username" not in {c["name"] for c in inspect(eng).get_columns("it_asset_offboardings")}
    finally:
        eng.dispose()


def test_directory_discovery_migration(tmp_path):
    """0020 adds the directory discovery tables and the (nullable) domain-join
    columns of devices on top of 0019; downgrading removes them again."""
    if IS_POSTGRES:
        reset_database()
        eng = db.create_db_engine(TEST_DATABASE_URL)
    else:
        eng = db.create_db_engine(f"sqlite:///{tmp_path / 'directory.db'}")
    tables = ("directory_sources", "directory_sync_runs", "directory_computers", "directory_users",
              "directory_findings")
    try:
        db.run_migrations(eng, "0019_offboarding_username")
        assert not any(inspect(eng).has_table(t) for t in tables)
        db.run_migrations(eng)
        assert all(inspect(eng).has_table(t) for t in tables)
        cols = {c["name"]: c for c in inspect(eng).get_columns("devices")}
        assert all(cols[c]["nullable"] for c in ("directory_join", "ad_domain", "ad_computer_sid", "entra_device_id"))
        assert _schema_diff(eng) == []

        from alembic import command

        command.downgrade(db.alembic_config(eng), "0019_offboarding_username")
        assert not any(inspect(eng).has_table(t) for t in tables)
        assert "ad_domain" not in {c["name"] for c in inspect(eng).get_columns("devices")}
    finally:
        eng.dispose()


def test_directory_cloud_sources_migration(tmp_path):
    """0021 adds the cloud-directory columns on top of 0020 with defaults for
    existing AD rows (device kind "ad", agent expected, not privileged)."""
    if IS_POSTGRES:
        reset_database()
        eng = db.create_db_engine(TEST_DATABASE_URL)
    else:
        eng = db.create_db_engine(f"sqlite:///{tmp_path / 'directory_cloud.db'}")
    try:
        db.run_migrations(eng, "0020_directory_discovery")
        with eng.begin() as conn:  # the default organisation comes from migration 0013
            conn.execute(text(
                "INSERT INTO directory_sources (id, organization_id, type, name, enabled, config, collector_device_ids,"
                " computers_count, users_count, created_at, updated_at) VALUES ('s1', 'default', 'ad', 'AD', true, '{}',"
                " '[]', 0, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"))
            conn.execute(text(
                "INSERT INTO directory_computers (id, organization_id, source_id, external_id, distinguished_name,"
                " domain, ou, enabled, first_seen_at, last_seen_at, attributes, name, short_name, dns_hostname,"
                " sam_account_name, serial_number, operating_system, os_version, match_status, match_candidates)"
                " VALUES ('c1', 'default', 's1', 'g', '', '', '', true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '{}', 'PC1',"
                " 'pc1', '', '', '', '', '', 'unmatched', '[]')"))
        db.run_migrations(eng)
        assert _schema_diff(eng) == []
        with eng.connect() as conn:
            row = conn.execute(text("SELECT device_kind, agent_expected, primary_user, machine_id FROM "
                                    "directory_computers")).one()
            assert (row[0], bool(row[1]), row[2], row[3]) == ("ad", True, "", None)
            assert conn.execute(text("SELECT scope_status FROM directory_sources")).scalar() in ("{}", {})

        from alembic import command

        command.downgrade(db.alembic_config(eng), "0020_directory_discovery")
        assert "device_kind" not in {c["name"] for c in inspect(eng).get_columns("directory_computers")}
        assert "privileged" not in {c["name"] for c in inspect(eng).get_columns("directory_users")}
    finally:
        eng.dispose()


def test_windows_updates_migration(tmp_path):
    """0022 adds the per-device missing-updates table on top of 0021; downgrading removes it."""
    if IS_POSTGRES:
        reset_database()
        eng = db.create_db_engine(TEST_DATABASE_URL)
    else:
        eng = db.create_db_engine(f"sqlite:///{tmp_path / 'os-updates.db'}")
    try:
        db.run_migrations(eng, "0021_directory_cloud_sources")
        assert not inspect(eng).has_table("device_os_updates")
        db.run_migrations(eng)
        assert inspect(eng).has_table("device_os_updates")
        assert _schema_diff(eng) == []

        from alembic import command

        command.downgrade(db.alembic_config(eng), "0021_directory_cloud_sources")
        assert not inspect(eng).has_table("device_os_updates")
    finally:
        eng.dispose()


def test_endpoint_actions_migration(tmp_path):
    """0023 adds the Windows services inventory on top of 0022; downgrading removes it."""
    if IS_POSTGRES:
        reset_database()
        eng = db.create_db_engine(TEST_DATABASE_URL)
    else:
        eng = db.create_db_engine(f"sqlite:///{tmp_path / 'endpoint-actions.db'}")
    try:
        db.run_migrations(eng, "0022_windows_updates")
        assert not inspect(eng).has_table("device_services")
        db.run_migrations(eng)
        assert inspect(eng).has_table("device_services")
        assert _schema_diff(eng) == []

        from alembic import command

        command.downgrade(db.alembic_config(eng), "0022_windows_updates")
        assert not inspect(eng).has_table("device_services")
    finally:
        eng.dispose()


def _insert_row(conn, table: str, values: dict) -> None:
    """Insert a row giving every NOT NULL column without a server default a value."""
    from datetime import datetime

    import sqlalchemy as sa

    row = dict(values)
    for c in inspect(conn).get_columns(table):
        if c["name"] in row or c["nullable"] or c.get("default") is not None:
            continue
        t = c["type"]
        row[c["name"]] = (False if isinstance(t, sa.Boolean) else 0 if isinstance(t, sa.Integer | sa.Numeric)
                          else datetime(2026, 1, 1) if isinstance(t, sa.DateTime)
                          else "{}" if isinstance(t, sa.JSON) else "")
    cols = ", ".join(row)
    conn.execute(text(f"INSERT INTO {table} ({cols}) VALUES ({', '.join(':' + k for k in row)})"), row)  # noqa: S608


def test_device_classification_migration(tmp_path):
    """0026 classifies existing devices from OS name and model ("inferred"),
    classifies directory computers (SERVER_TRUST_ACCOUNT = domain controller)
    and marks agent / directory asset types as automatic; downgrade removes it."""
    if IS_POSTGRES:
        reset_database()
        eng = db.create_db_engine(TEST_DATABASE_URL)
    else:
        eng = db.create_db_engine(f"sqlite:///{tmp_path / 'device_class.db'}")
    try:
        db.run_migrations(eng, "0025_compliance_reports")
        with eng.begin() as conn:
            base = {"organization_id": "default", "os_version": "", "os_build": "", "architecture": "",
                    "serial_number": "", "machine_id": "", "agent_version": "1.3.0", "status": "active"}
            for i, (fam, os_name, make, model) in enumerate([
                    ("windows", "Microsoft Windows 11 Pro", "LENOVO", "20XW"),
                    ("windows", "Microsoft Windows Server 2022 Standard", "VMware, Inc.", "VMware7,1"),
                    ("macos", "macOS 15", "Apple Inc.", "MacBookPro18,3"),
                    ("linux", "Ubuntu 24.04", "Amazon EC2", "m5.metal")]):
                _insert_row(conn, "devices", {**base, "id": f"d{i}", "hostname": f"h{i}", "os_family": fam,
                                              "os_name": os_name, "manufacturer": make, "model": model})
            _insert_row(conn, "directory_sources", {"id": "s1", "organization_id": "default", "type": "ad",
                                                    "name": "AD", "config": "{}", "collector_device_ids": "[]"})
            for cid, os_name, uac in (("c1", "Windows Server 2022", 532480), ("c2", "Windows Server 2019", 4096),
                                      ("c3", "Windows 11 Enterprise", 4096)):
                _insert_row(conn, "directory_computers", {
                    "id": cid, "organization_id": "default", "source_id": "s1", "external_id": cid,
                    "operating_system": os_name, "user_account_control": uac, "platform": "windows",
                    "device_kind": "ad", "match_candidates": "[]"})
            for aid, src, typ, dev in (("a1", "agent", "computer", "d1"), ("a2", "manual", "laptop", None),
                                       ("a3", "agent", "monitor", None)):
                _insert_row(conn, "it_assets", {"id": aid, "organization_id": "default", "asset_tag": aid,
                                                "source": src, "asset_type": typ, "device_id": dev,
                                                "custom_fields": "{}"})
        db.run_migrations(eng)
        assert _schema_diff(eng) == []
        with eng.connect() as conn:
            rows = {r[0]: (r[1], r[2], r[3]) for r in conn.execute(text(
                "SELECT id, device_class, class_source, is_virtual FROM devices"))}
            assert rows["d0"][:2] == ("workstation", "inferred") and rows["d0"][2] is None
            assert rows["d1"][0] == "server" and bool(rows["d1"][2]) is True
            assert rows["d2"][0] == "workstation"
            assert rows["d3"][0] == "server" and rows["d3"][2] is None  # bare-metal EC2
            assert dict(conn.execute(text("SELECT id, device_class FROM directory_computers")).all()) == {
                "c1": "domain_controller", "c2": "server", "c3": "workstation"}
            assets = {r[0]: (r[1], r[2]) for r in conn.execute(text(
                "SELECT id, asset_type, asset_type_source FROM it_assets"))}
            assert assets == {"a1": ("server", "auto"), "a2": ("laptop", "manual"), "a3": ("monitor", "manual")}

        from alembic import command

        command.downgrade(db.alembic_config(eng), "0025_compliance_reports")
        assert "device_class" not in {c["name"] for c in inspect(eng).get_columns("devices")}
        assert "asset_type_source" not in {c["name"] for c in inspect(eng).get_columns("it_assets")}
    finally:
        eng.dispose()


def test_directory_collectors_migration(tmp_path):
    """0027 adds dedicated collectors; existing AD sources keep their endpoint-agent
    collectors (legacy: collector_ids = []) and existing tokens are agent tokens."""
    if IS_POSTGRES:
        reset_database()
        eng = db.create_db_engine(TEST_DATABASE_URL)
    else:
        eng = db.create_db_engine(f"sqlite:///{tmp_path / 'collectors.db'}")
    try:
        db.run_migrations(eng, "0026_device_classification")
        with eng.begin() as conn:
            conn.execute(text(
                "INSERT INTO directory_sources (id, organization_id, type, name, enabled, config, collector_device_ids,"
                " computers_count, users_count, created_at, updated_at, scope_status) VALUES ('s1', 'default', 'ad',"
                " 'AD', true, '{}', '[\"d1\"]', 0, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '{}')"))
            conn.execute(text(
                "INSERT INTO enrollment_tokens (id, organization_id, name, token_hash, token_prefix, use_count,"
                " created_at, expires_at) VALUES ('t1', 'default', 'x', 'h', 'cne_', 0, CURRENT_TIMESTAMP,"
                " CURRENT_TIMESTAMP)"))
        db.run_migrations(eng)
        assert _schema_diff(eng) == []
        with eng.connect() as conn:
            assert conn.execute(text("SELECT collector_ids FROM directory_sources")).scalar() in ("[]", [])
            assert conn.execute(text("SELECT kind FROM enrollment_tokens")).scalar() == "agent"
        from alembic import command

        command.downgrade(db.alembic_config(eng), "0026_device_classification")
        assert not inspect(eng).has_table("directory_collectors")
        assert "kind" not in {c["name"] for c in inspect(eng).get_columns("enrollment_tokens")}
    finally:
        eng.dispose()
