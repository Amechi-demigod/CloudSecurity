"""Database engine / session handling (SQLAlchemy 2.x + SQLite)."""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


engine: Engine | None = None
SessionLocal: sessionmaker[Session] | None = None


def init_engine(url: str) -> Engine:
    """(Re)create the global engine + session factory and create tables."""
    global engine, SessionLocal
    kwargs: dict = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            # Share a single in-memory DB across threads (tests).
            from sqlalchemy.pool import StaticPool

            kwargs["poolclass"] = StaticPool
    engine = create_engine(url, **kwargs)

    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _):  # pragma: no cover - trivial
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    from . import models  # noqa: F401  (register tables)

    Base.metadata.create_all(engine)
    return engine


def get_session() -> Session:
    assert SessionLocal is not None, "init_engine() not called"
    return SessionLocal()


def get_db() -> Iterator[Session]:
    """FastAPI dependency."""
    db = get_session()
    try:
        yield db
    finally:
        db.close()
