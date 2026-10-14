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
})
for k in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_IDS"):
    os.environ.pop(k, None)

from app import config, db  # noqa: E402

AUTH = {"Authorization": "Bearer test-ingest-token"}


@pytest.fixture()
def session():
    """Fresh, empty in-memory database session."""
    config.reload_settings()
    db.init_engine("sqlite://")
    s = db.get_session()
    yield s
    s.close()


@pytest.fixture()
def client():
    """API client against a freshly seeded simulated environment."""
    from fastapi.testclient import TestClient

    config.reload_settings()
    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c


@pytest.fixture()
def empty_client(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("SIMULATION_MODE", "false")
    config.reload_settings()
    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c
    monkeypatch.setenv("SIMULATION_MODE", "true")
    config.reload_settings()
