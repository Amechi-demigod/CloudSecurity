"""Alembic environment.

The engine is either handed over by the application (`app.db.run_migrations`
sets `config.attributes["engine"]`) or built from DATABASE_URL when the
`alembic` CLI is used directly.
"""
from __future__ import annotations

from logging.config import fileConfig

from alembic import context

from app import config as app_config
from app import models  # noqa: F401  (register tables on Base.metadata)
from app.db import Base, create_db_engine

config = context.config
target_metadata = Base.metadata

if config.config_file_name is not None and "engine" not in config.attributes:
    fileConfig(config.config_file_name, disable_existing_loggers=False)


def run_migrations_offline() -> None:
    from app.db import normalize_url

    context.configure(url=normalize_url(app_config.settings.database_url), target_metadata=target_metadata,
                      literal_binds=True, dialect_opts={"paramstyle": "named"}, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = config.attributes.get("engine")
    owned = engine is None
    if owned:
        engine = create_db_engine(app_config.settings.database_url)
    try:
        with engine.connect() as connection:
            sqlite = connection.dialect.name == "sqlite"
            if sqlite:
                # Batch migrations rebuild SQLite tables (copy, DROP, rename); with
                # foreign keys enforced, dropping a referenced table would cascade
                # deletes into its children. Only settable outside a transaction.
                connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
                connection.commit()  # end the autobegun (empty) transaction
            try:
                context.configure(connection=connection, target_metadata=target_metadata,
                                  render_as_batch=sqlite, compare_type=True)
                with context.begin_transaction():
                    context.run_migrations()
            finally:
                if sqlite:
                    connection.rollback()  # nothing pending: alembic committed
                    connection.exec_driver_sql("PRAGMA foreign_keys=ON")
                    connection.commit()
    finally:
        if owned:
            engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
