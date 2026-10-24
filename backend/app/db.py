"""Database engine / session handling (SQLAlchemy 2.x; SQLite or PostgreSQL).

* SQLite (the local default) keeps the zero-setup behaviour: tables are created
  with `create_all()` and new nullable columns are added on startup.
* PostgreSQL (production, e.g. Azure Database for PostgreSQL Flexible Server)
  is managed by Alembic migrations in `backend/migrations/`, applied on startup
  (`DB_AUTO_MIGRATE=true`, the default) or explicitly with
  `python -m app.cli migrate` / `alembic upgrade head`.

Schema changes on startup run under a cross-process lock (a PostgreSQL advisory
lock, or a file lock for SQLite) so several replicas / gunicorn workers can
start at the same time.
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

log = logging.getLogger(__name__)

BACKEND_DIR = Path(__file__).resolve().parents[1]


class Base(DeclarativeBase):
    pass


engine: Engine | None = None
SessionLocal: sessionmaker[Session] | None = None


def normalize_url(url: str) -> str:
    """Map postgres:// / postgresql:// URLs to the psycopg 3 driver."""
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


def is_sqlite(url_or_engine: str | Engine) -> bool:
    name = url_or_engine.dialect.name if isinstance(url_or_engine, Engine) else make_url(
        normalize_url(url_or_engine)).get_backend_name()
    return name == "sqlite"


def create_db_engine(url: str) -> Engine:
    from . import config

    url = normalize_url(url)
    kwargs: dict = {}
    if is_sqlite(url):
        kwargs["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            # Share a single in-memory DB across threads (tests).
            from sqlalchemy.pool import StaticPool

            kwargs["poolclass"] = StaticPool
    else:
        s = config.settings
        kwargs.update(pool_pre_ping=True, pool_size=s.db_pool_size, max_overflow=s.db_max_overflow,
                      # Azure Postgres closes idle connections; recycle well before that.
                      pool_recycle=1800)
    eng = create_engine(url, **kwargs)

    if is_sqlite(url):

        @event.listens_for(eng, "connect")
        def _sqlite_pragmas(dbapi_conn, _):  # pragma: no cover - trivial
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    return eng


def init_engine(url: str, migrate: bool | None = None) -> Engine:
    """(Re)create the global engine + session factory and bring the schema up to date."""
    global engine, SessionLocal
    from . import config, locks

    if engine is not None:
        engine.dispose()
    engine = create_db_engine(url)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    from . import models  # noqa: F401  (register tables)

    if migrate is None:
        migrate = config.settings.db_auto_migrate
    if migrate:
        with locks.advisory_lock("schema-migration"):
            if is_sqlite(engine):
                Base.metadata.create_all(engine)
                _upgrade_sqlite_tenancy(engine)
                _relax_not_null(engine)
                _add_missing_columns(engine)
            else:
                run_migrations(engine)
            with get_session(unscoped=True) as session:
                from . import tenancy

                tenancy.ensure_default_org(session)
                session.commit()
    return engine


def alembic_config(eng: Engine | None = None):
    from alembic.config import Config

    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    if eng is not None:
        cfg.attributes["engine"] = eng
    return cfg


def run_migrations(eng: Engine, revision: str = "head") -> None:
    """`alembic upgrade head`. A database that predates Alembic (tables created by
    `create_all()`, no `alembic_version`) is stamped at the baseline first."""
    from alembic import command
    from sqlalchemy import inspect

    cfg = alembic_config(eng)
    insp = inspect(eng)
    if insp.has_table("assets") and not insp.has_table("alembic_version"):
        log.warning("Existing schema without Alembic history: stamping baseline revision")
        command.stamp(cfg, "0001_baseline")
    command.upgrade(cfg, revision)


def _add_missing_columns(eng: Engine) -> None:
    """Minimal additive migration (SQLite only): create_all() never alters existing
    tables, so add nullable columns introduced after a database was first created."""
    from sqlalchemy import inspect, text

    insp = inspect(eng)
    with eng.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            existing = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name not in existing and col.nullable:
                    ddl = col.type.compile(dialect=eng.dialect)
                    # identifiers come from our own ORM metadata, never from user input
                    conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}" {ddl}'))


# (table, column) pairs that became nullable after release; SQLite cannot
# ALTER a NOT NULL constraint away, so such tables are rebuilt once.
RELAXED_COLUMNS = (("vulnerabilities", "asset_id"),)


def _relax_not_null(eng: Engine) -> None:
    """SQLite only: rebuild a table whose column is NOT NULL in the database but
    nullable in the ORM (e.g. vulnerabilities.asset_id since endpoint devices
    have vulnerabilities too). Data, including columns added since, is kept."""
    from sqlalchemy import inspect, text

    insp = inspect(eng)
    for table_name, column in RELAXED_COLUMNS:
        if not insp.has_table(table_name):
            continue
        cols = {c["name"]: c for c in insp.get_columns(table_name)}
        if column not in cols or cols[column]["nullable"]:
            continue
        table = Base.metadata.tables[table_name]
        common = [c.name for c in table.columns if c.name in cols]
        collist = ", ".join(f'"{c}"' for c in common)
        old = f"_old_{table_name}"
        log.warning("Rebuilding SQLite table %s to make %s nullable", table_name, column)
        with eng.begin() as conn:
            for idx in insp.get_indexes(table_name):
                conn.execute(text(f'DROP INDEX IF EXISTS "{idx["name"]}"'))
            conn.execute(text(f'ALTER TABLE "{table_name}" RENAME TO "{old}"'))
            table.create(conn)
            # identifiers come from our own ORM metadata, never from user input
            conn.execute(text(f'INSERT INTO "{table_name}" ({collist}) SELECT {collist} FROM "{old}"'))  # noqa: S608
            conn.execute(text(f'DROP TABLE "{old}"'))


# New NOT NULL columns of tables rebuilt by _upgrade_sqlite_tenancy, with the
# value existing rows get (SQL literals).
_SQLITE_NEW_COLUMN_VALUES = {"organization_id": "'default'", "is_platform_admin": "0"}


def _upgrade_sqlite_tenancy(eng: Engine) -> None:
    """SQLite only: bring a database created before multi-tenancy to the current
    schema (what the 0013_organizations migration does on PostgreSQL). Every
    existing row goes to the default organisation and user roles become
    memberships of it. Tables whose columns differ from the ORM in a way an ALTER
    cannot fix (a new NOT NULL column, a dropped column, a new primary key) are
    rebuilt with their data. Idempotent: nothing to do on an up-to-date database."""
    from sqlalchemy import inspect, text

    from .tenancy import DEFAULT_ORG_ID

    insp = inspect(eng)
    existing = set(insp.get_table_names())
    if "users" not in existing:
        return
    rebuild = []
    for table in Base.metadata.sorted_tables:
        if table.name not in existing:
            continue
        db_cols = {c["name"] for c in insp.get_columns(table.name)}
        orm_cols = {c.name for c in table.columns}
        new_required = [c for c in table.columns if c.name not in db_cols and c.name in _SQLITE_NEW_COLUMN_VALUES]
        if new_required or (db_cols - orm_cols):
            rebuild.append((table, db_cols))
    if not rebuild:
        return
    log.warning("Upgrading SQLite database to organisations: rebuilding %d tables (existing data goes to the "
                "default organisation)", len(rebuild))
    with eng.connect() as conn:
        conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
        conn.exec_driver_sql("PRAGMA legacy_alter_table=ON")  # keep other tables' FKs pointing at the new table
        conn.commit()  # pragmas only apply outside a transaction; end the autobegun one
        try:
            with conn.begin():
                users_cols = {c["name"] for c in insp.get_columns("users")}
                if "role" in users_cols:
                    # Roles move to memberships of the default organisation.
                    conn.execute(text(
                        "INSERT INTO organization_memberships (organization_id, user_id, role, created_at) "
                        "SELECT :org, id, role, created_at FROM users WHERE id NOT IN "
                        "(SELECT user_id FROM organization_memberships)"), {"org": DEFAULT_ORG_ID})
                for table, db_cols in rebuild:
                    common = [c.name for c in table.columns if c.name in db_cols]
                    added = [c.name for c in table.columns
                             if c.name not in db_cols and c.name in _SQLITE_NEW_COLUMN_VALUES]
                    old = f"_old_{table.name}"
                    for idx in insp.get_indexes(table.name):
                        conn.execute(text(f'DROP INDEX IF EXISTS "{idx["name"]}"'))
                    conn.execute(text(f'ALTER TABLE "{table.name}" RENAME TO "{old}"'))
                    table.create(conn)
                    # identifiers and literals come from our own ORM metadata, never from user input
                    cols = ", ".join(f'"{c}"' for c in common + added)
                    values = ", ".join([f'"{c}"' for c in common] + [_SQLITE_NEW_COLUMN_VALUES[c] for c in added])
                    conn.execute(text(f'INSERT INTO "{table.name}" ({cols}) SELECT {values} FROM "{old}"'))  # noqa: S608
                    conn.execute(text(f'DROP TABLE "{old}"'))
            problems = conn.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
            if problems:
                log.warning("SQLite foreign key check after the organisation upgrade: %d problem(s), e.g. %s",
                            len(problems), problems[:5])
        finally:
            conn.rollback()
            conn.exec_driver_sql("PRAGMA legacy_alter_table=OFF")
            conn.exec_driver_sql("PRAGMA foreign_keys=ON")
            conn.commit()


def get_session(org_id: str | None = None, *, unscoped: bool = False) -> Session:
    """A new session. Pass the organisation to work in, or `unscoped=True` for
    deliberate cross-organisation (platform / system) access. A session with
    neither refuses to touch tenant tables (app/tenancy.py)."""
    from . import tenancy

    assert SessionLocal is not None, "init_engine() not called"
    session = SessionLocal()
    if unscoped:
        tenancy.set_unscoped(session)
    elif org_id is not None:
        tenancy.set_org(session, org_id)
    return session


def get_db() -> Iterator[Session]:
    """FastAPI dependency. The authentication dependency (user session, device
    credential, ingest token) scopes it to the caller's organisation."""
    db = get_session()
    try:
        yield db
    finally:
        db.close()
