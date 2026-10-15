import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Tests never touch a real DB file, never start the background simulator,
# and never see real Azure credentials.
#
# By default every test gets a fresh in-memory SQLite database. Set
# TEST_DATABASE_URL (e.g. postgresql://postgres:postgres@localhost:5432/cnapp_test)
# to run the whole suite against PostgreSQL instead: each test then starts from
# an empty `public` schema and the Alembic migrations are applied.
# WARNING: that database is wiped repeatedly.
TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL") or "sqlite://"
os.environ.update({
    "APP_ENV": "development",
    "DATABASE_URL": TEST_DATABASE_URL,
    "SIMULATION_MODE": "true",
    "SIMULATOR_ENABLED": "false",
    "INGEST_API_TOKEN": "test-ingest-token",
    "RUNTIME_INGEST_TOKEN": "",
    "INGEST_ALLOW_UNAUTHENTICATED": "false",
    "ADMIN_EMAIL": "Admin@Example.com",
    "ADMIN_PASSWORD": "correct-horse-battery",
    "COOKIE_SECURE": "true",
    "API_DOCS_PUBLIC": "false",
    # Notification tests drive the dispatcher explicitly (no background thread).
    "NOTIFICATIONS_WORKER_ENABLED": "false",
})
for k in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_IDS", "AZURE_AUTH_MODE",
          "AZURE_MANAGED_IDENTITY_CLIENT_ID", "AZURE_USE_DEFAULT_CREDENTIAL", "SESSION_SECRET", "DEBUG",
          "TRUST_PROXY_HEADERS", "TRUSTED_PROXY_CIDRS", "API_DOCS_ENABLED", "LOG_FORMAT", "CORS_ORIGINS",
          "NOTIFICATIONS_ENCRYPTION_KEY", "PUBLIC_BASE_URL", "NOTIFICATIONS_ALLOW_INSECURE_DEV"):
    os.environ.pop(k, None)

from app import config, db  # noqa: E402

IS_POSTGRES = not db.is_sqlite(TEST_DATABASE_URL)

AUTH = {"Authorization": "Bearer test-ingest-token"}
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "correct-horse-battery"
# https so the Secure session cookie is sent back, as in a real browser.
BASE_URL = "https://testserver"


def login(c, email: str = ADMIN_EMAIL, password: str = ADMIN_PASSWORD):
    """Log `c` in and make it send the CSRF header on every request."""
    r = c.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return r


def make_user(c, role: str, email: str | None = None, password: str = "a-long-test-password"):
    """Create a user through the admin API (`c` must be logged in as admin)."""
    email = email or f"{role}@example.com"
    r = c.post("/api/users", json={"email": email, "name": role.title(), "role": role, "password": password})
    assert r.status_code == 201, r.text
    return r.json()


def reset_database() -> None:
    """Start from an empty database (only needed for PostgreSQL; a new in-memory
    SQLite engine is empty anyway)."""
    if not IS_POSTGRES:
        return
    from sqlalchemy import text

    if db.engine is not None:
        db.engine.dispose()
    eng = db.create_db_engine(TEST_DATABASE_URL)
    try:
        with eng.begin() as conn:
            conn.execute(text("DROP SCHEMA public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
    finally:
        eng.dispose()


def fresh_db():
    """Reset the test database and (re)initialize the global engine on it."""
    reset_database()
    return db.init_engine(TEST_DATABASE_URL)


@pytest.fixture()
def session():
    """Fresh, empty database session."""
    config.reload_settings()
    fresh_db()
    s = db.get_session()
    yield s
    s.close()


@pytest.fixture()
def anon_client():
    """Unauthenticated API client against a freshly seeded simulated environment."""
    from fastapi.testclient import TestClient

    config.reload_settings()
    reset_database()
    from app.main import create_app

    with TestClient(create_app(), base_url=BASE_URL) as c:
        yield c


@pytest.fixture()
def client(anon_client):
    """API client logged in as the bootstrap admin."""
    login(anon_client)
    return anon_client


@pytest.fixture()
def empty_client(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("SIMULATION_MODE", "false")
    config.reload_settings()
    reset_database()
    from app.main import create_app

    with TestClient(create_app(), base_url=BASE_URL) as c:
        login(c)
        yield c
    monkeypatch.setenv("SIMULATION_MODE", "true")
    config.reload_settings()
