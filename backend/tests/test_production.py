"""Production hardening: config guardrails, security headers, docs, proxy IPs, logging."""
from __future__ import annotations

import json
import logging

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app import auth, config
from app.config import Settings
from app.logging_setup import JsonFormatter
from tests.conftest import BASE_URL, login, reset_database

SECRET = "s" * 40


@pytest.fixture()
def prod_env(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("SESSION_SECRET", SECRET)
    monkeypatch.setenv("ALLOW_SQLITE_IN_PRODUCTION", "true")  # the suite may run on SQLite
    config.reload_settings()
    yield monkeypatch
    monkeypatch.undo()
    config.reload_settings()


@pytest.fixture()
def prod_client(prod_env):
    reset_database()
    from app.main import create_app

    with TestClient(create_app(), base_url=BASE_URL) as c:
        yield c


def test_development_has_no_production_problems():
    assert Settings().production_problems() == []


def test_production_defaults(prod_env):
    s = config.settings
    assert s.is_production and s.production_problems() == []
    assert s.cors_origins == [] and s.api_docs_enabled is False and s.effective_log_format == "json"


@pytest.mark.parametrize("env,expected", [
    ({"SESSION_SECRET": ""}, "SESSION_SECRET"),
    ({"SESSION_SECRET": "short"}, "SESSION_SECRET"),
    ({"COOKIE_SECURE": "false"}, "COOKIE_SECURE"),
    ({"DEBUG": "true"}, "DEBUG"),
    ({"CORS_ORIGINS": "*"}, "CORS_ORIGINS"),
    ({"CORS_ORIGINS": "http://cnapp.example.com"}, "https://"),
    ({"INGEST_ALLOW_UNAUTHENTICATED": "true"}, "INGEST_ALLOW_UNAUTHENTICATED"),
    ({"API_DOCS_PUBLIC": "true"}, "API_DOCS_PUBLIC"),
    ({"ALLOW_SQLITE_IN_PRODUCTION": "false", "DATABASE_URL": "sqlite:///x.db"}, "PostgreSQL"),
])
def test_insecure_production_config_refuses_to_start(prod_env, env, expected):
    for k, v in env.items():
        prod_env.setenv(k, v)
    config.reload_settings()
    assert any(expected in p for p in config.settings.production_problems())
    from app.main import create_app

    with pytest.raises(RuntimeError, match="insecure production configuration"):
        create_app()


def test_production_app_headers_and_no_docs(prod_client):
    r = prod_client.get("/api/health")
    assert r.status_code == 200
    assert r.headers["strict-transport-security"].startswith("max-age=31536000")
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["cache-control"] == "no-store"
    login(prod_client)
    for path in ("/api/docs", "/api/openapi.json", "/docs", "/openapi.json", "/redoc"):
        assert prod_client.get(path, follow_redirects=False).status_code == 404, path
    assert prod_client.get("/api/auth/me").status_code == 200


def test_production_cors_is_strict(prod_env):
    prod_env.setenv("CORS_ORIGINS", "https://cnapp.example.com")
    config.reload_settings()
    reset_database()
    from app.main import create_app

    with TestClient(create_app(), base_url=BASE_URL) as c:
        ok = c.options("/api/health", headers={"Origin": "https://cnapp.example.com",
                                              "Access-Control-Request-Method": "GET"})
        assert ok.headers.get("access-control-allow-origin") == "https://cnapp.example.com"
        bad = c.get("/api/health", headers={"Origin": "https://evil.example"})
        assert "access-control-allow-origin" not in bad.headers


def test_development_sends_no_hsts(anon_client):
    r = anon_client.get("/api/health")
    assert "strict-transport-security" not in r.headers and r.headers["x-frame-options"] == "DENY"


def test_session_secret_keys_the_stored_token_id(prod_client):
    token = "example-token"
    assert auth._token_id(token) != __import__("hashlib").sha256(token.encode()).hexdigest()
    login(prod_client)  # sessions work end to end with the keyed digest
    assert prod_client.get("/api/auth/me").json()["user"]["email"] == "admin@example.com"


# --- client IP behind proxies ------------------------------------------------------

def _request(peer: str, xff: str | None) -> Request:
    headers = [(b"x-forwarded-for", xff.encode())] if xff is not None else []
    return Request({"type": "http", "method": "GET", "path": "/", "headers": headers, "client": (peer, 1234)})


@pytest.mark.parametrize("trust,cidrs,peer,xff,expected", [
    # default: never trust the header
    ("false", "", "10.0.0.5", "203.0.113.9", "10.0.0.5"),
    # legacy single proxy: right-most entry
    ("true", "", "172.18.0.3", "1.2.3.4, 203.0.113.9", "203.0.113.9"),
    # Container Apps: ingress + nginx on private addresses; spoofed left-most value ignored
    ("true", "10.0.0.0/8,100.64.0.0/10", "10.0.1.7", "6.6.6.6, 203.0.113.9, 100.100.0.4", "203.0.113.9"),
    # peer is not a trusted proxy: header ignored entirely
    ("true", "10.0.0.0/8", "198.51.100.1", "203.0.113.9", "198.51.100.1"),
    # every hop internal: left-most
    ("true", "10.0.0.0/8", "10.0.1.7", "10.0.2.2, 10.0.1.9", "10.0.2.2"),
    # garbage hops are not trusted proxies
    ("true", "10.0.0.0/8", "10.0.1.7", "203.0.113.9, not-an-ip", "not-an-ip"),
    # no header
    ("true", "10.0.0.0/8", "10.0.1.7", None, "10.0.1.7"),
])
def test_client_ip(monkeypatch, trust, cidrs, peer, xff, expected):
    monkeypatch.setenv("TRUST_PROXY_HEADERS", trust)
    monkeypatch.setenv("TRUSTED_PROXY_CIDRS", cidrs)
    config.reload_settings()
    try:
        assert auth.client_ip(_request(peer, xff)) == expected
    finally:
        monkeypatch.undo()
        config.reload_settings()


# --- structured logging ------------------------------------------------------------

def test_json_log_formatter():
    rec = logging.LogRecord("cnapp.test", logging.WARNING, __file__, 1, "hello %s", ("world",), None)
    rec.request_id = "abc"
    out = json.loads(JsonFormatter().format(rec))
    assert out["message"] == "hello world" and out["level"] == "WARNING" and out["logger"] == "cnapp.test"
    assert out["request_id"] == "abc" and "timestamp" in out
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        rec = logging.LogRecord("x", logging.ERROR, __file__, 1, "failed", (), sys.exc_info())
    assert "ValueError: boom" in json.loads(JsonFormatter().format(rec))["exception"]


def test_gunicorn_config_loads(monkeypatch):
    import runpy
    from pathlib import Path

    monkeypatch.setenv("WEB_CONCURRENCY", "3")
    cfg = runpy.run_path(str(Path(__file__).resolve().parents[1] / "gunicorn.conf.py"))
    assert cfg["workers"] == 3 and cfg["worker_class"] == "uvicorn_worker.UvicornWorker"
    assert cfg["forwarded_allow_ips"] == "127.0.0.1" and cfg["control_socket_disable"] is True
    assert cfg["logconfig_dict"]["version"] == 1
