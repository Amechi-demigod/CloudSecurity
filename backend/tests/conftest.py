import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Tests never touch a real DB file, never start the background simulator,
# and never see real Azure credentials.
os.environ.update({
    "DATABASE_URL": "sqlite://",
    "SIMULATION_MODE": "true",
    "SIMULATOR_ENABLED": "false",
    "INGEST_API_TOKEN": "test-ingest-token",
    "RUNTIME_INGEST_TOKEN": "",
    "INGEST_ALLOW_UNAUTHENTICATED": "false",
    "ADMIN_EMAIL": "Admin@Example.com",
    "ADMIN_PASSWORD": "correct-horse-battery",
    "COOKIE_SECURE": "true",
    "API_DOCS_PUBLIC": "false",
})
for k in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_IDS"):
    os.environ.pop(k, None)

from app import config, db  # noqa: E402

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


@pytest.fixture()
def session():
    """Fresh, empty in-memory database session."""
    config.reload_settings()
    db.init_engine("sqlite://")
    s = db.get_session()
    yield s
    s.close()


@pytest.fixture()
def anon_client():
    """Unauthenticated API client against a freshly seeded simulated environment."""
    from fastapi.testclient import TestClient

    config.reload_settings()
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
    from app.main import create_app

    with TestClient(create_app(), base_url=BASE_URL) as c:
        login(c)
        yield c
    monkeypatch.setenv("SIMULATION_MODE", "true")
    config.reload_settings()
