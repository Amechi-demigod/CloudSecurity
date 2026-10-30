"""Connection test behind "Test & save" on Connectors & scans
(app/connectors/access_check.py, PUT /api/organization/connectors/{provider}
with "test" / "start_first_scan"). Every cloud SDK is faked or moto-backed:
no real cloud API call is ever made."""
from __future__ import annotations

import logging
import time
from types import SimpleNamespace as NS
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select

from app import config, db
from app.config import Settings
from app.connectors import access_check, org_config
from app.connectors.aws import AwsConnector
from app.connectors.azure import AzureConnector
from app.connectors.gcp import GcpConnector
from app.models import AuditLog, ConnectorConfig, ScanRun
from app.notifications import crypto
from tests.test_gcp_connector import FakeSession, Resp

SUB = "33333333-3333-3333-3333-333333333333"
SECRET = "super-secret-value-123"
AZURE_BODY = {"config": {"tenant_id": "22222222-2222-2222-2222-222222222222", "client_id": "app-id",
                         "subscription_ids": [SUB]}, "secrets": {"client_secret": SECRET}}


def azure_settings() -> Settings:
    return org_config.probe_settings("azure", {"tenant_id": "t", "client_id": "c", "subscription_ids": [SUB]},
                                     {"client_secret": SECRET})


# ----------------------------------------------------------------------------- per provider
def test_azure_check_lists_one_resource_group_per_subscription():
    groups = MagicMock()
    groups.list.return_value = iter([NS(name="rg-1")])
    factory = MagicMock(return_value=NS(resource_groups=groups))
    conn = AzureConnector(azure_settings(), client_factory=factory)
    assert conn.check_access() == [{"id": SUB, "name": SUB}]
    factory.assert_called_once_with("resource", SUB)


def test_azure_check_explains_auth_and_permission_failures(monkeypatch):
    from azure.core.exceptions import ClientAuthenticationError, HttpResponseError

    def fail_with(exc):
        groups = MagicMock()
        groups.list.side_effect = exc
        monkeypatch.setattr(AzureConnector, "_client_factory",
                            lambda self: (lambda kind, sub: NS(resource_groups=groups)))
        return access_check.run("azure", azure_settings(), {"client_secret": SECRET})

    r = fail_with(ClientAuthenticationError(f"AADSTS7000215: Invalid client secret provided {SECRET}"))
    assert not r.ok and "rejected the credentials" in r.message and SECRET not in r.message
    denied = HttpResponseError("AuthorizationFailed")
    denied.status_code = 403
    r = fail_with(denied)
    assert not r.ok and f"cannot read subscription {SUB}" in r.message and "Reader" in r.message


def test_aws_check_with_moto():
    moto = pytest.importorskip("moto")
    import boto3

    with moto.mock_aws():
        s = org_config.probe_settings("aws", {"access_key_id": "AKIAIOSFODNN7EXAMPLE"},
                                      {"secret_access_key": "fake-secret"})
        conn = AwsConnector(s, session_factory=lambda: boto3.Session(
            aws_access_key_id="testing", aws_secret_access_key="testing", region_name="us-east-1"))
        boto3.client("iam", region_name="us-east-1", aws_access_key_id="testing",
                     aws_secret_access_key="testing").create_account_alias(AccountAlias="acme-prod")
        assert conn.check_access() == [{"id": "123456789012", "name": "acme-prod"}]


def test_aws_check_explains_a_rejected_key(monkeypatch):
    from botocore.exceptions import ClientError

    import app.connectors.aws as aws_mod

    sts = MagicMock()
    sts.get_caller_identity.side_effect = ClientError(
        {"Error": {"Code": "InvalidClientTokenId", "Message": "The security token included in the request is invalid."}},
        "GetCallerIdentity")
    monkeypatch.setattr(aws_mod, "build_base_session", lambda settings: NS(client=lambda service, **kw: sts))
    s = org_config.probe_settings("aws", {"access_key_id": "AKIAIOSFODNN7EXAMPLE"}, {"secret_access_key": "x" * 40})
    r = access_check.run("aws", s, {"secret_access_key": "x" * 40})
    assert not r.ok and "AWS rejected the access key" in r.message


def test_gcp_check_reads_projects_and_explains_403():
    key = '{"type": "service_account", "client_email": "cnapp-scanner@p.iam.gserviceaccount.com", "private_key": "PK"}'
    s = org_config.probe_settings("gcp", {"project_ids": ["acme-prod"]}, {"credentials_json": key})
    ok = FakeSession({("GET", "/v3/projects/acme-prod"): {"projectId": "acme-prod", "displayName": "Acme prod"}})
    conn = GcpConnector(s, session_factory=lambda: ok, sleep=lambda x: None)
    assert conn.check_access() == [{"id": "acme-prod", "name": "Acme prod"}]
    assert [c[0] for c in ok.calls] == ["GET"]
    denied = FakeSession({("GET", "/v3/projects/acme-prod"): Resp(403, {"error": {
        "code": 403, "message": "The caller does not have permission", "status": "PERMISSION_DENIED"}})})
    conn = GcpConnector(s, session_factory=lambda: denied, sleep=lambda x: None)
    with pytest.raises(Exception) as e:
        conn.check_access()
    msg = access_check.explain("gcp", e.value.scope, e.value.cause)
    assert "cannot read acme-prod" in msg and "roles/iam.securityReviewer" in msg


def test_run_times_out_and_never_logs_secrets(monkeypatch, caplog):
    monkeypatch.setattr(AzureConnector, "check_access", lambda self: time.sleep(2))
    caplog.set_level(logging.DEBUG)
    r = access_check.run("azure", azure_settings(), {"client_secret": SECRET}, timeout=0.2)
    assert not r.ok and "No answer from Azure within 1 seconds" in r.message
    assert SECRET not in caplog.text


def test_incomplete_values_are_not_tested():
    s = org_config.probe_settings("azure", {"subscription_ids": [SUB]}, {})
    r = access_check.run("azure", s)
    assert not r.ok and "required" in r.message


def test_probe_settings_never_use_ambient_identity(monkeypatch):
    monkeypatch.setenv("AZURE_MANAGED_IDENTITY_CLIENT_ID", "mi-client")
    monkeypatch.setenv("AWS_USE_DEFAULT_CREDENTIALS", "true")
    config.reload_settings()
    try:
        s = org_config.probe_settings("azure", {"subscription_ids": [SUB]}, {})
        assert s.azure_managed_identity_client_id is None and not s.aws_use_default_credentials
        assert not s.simulation_mode
    finally:
        monkeypatch.delenv("AZURE_MANAGED_IDENTITY_CLIENT_ID")
        monkeypatch.delenv("AWS_USE_DEFAULT_CREDENTIALS")
        config.reload_settings()


# ----------------------------------------------------------------------------- API
@pytest.fixture()
def encryption(monkeypatch):
    monkeypatch.setenv("NOTIFICATIONS_ENCRYPTION_KEY", crypto.generate_key())
    config.reload_settings()
    yield
    monkeypatch.delenv("NOTIFICATIONS_ENCRYPTION_KEY")
    config.reload_settings()


@pytest.fixture()
def started(monkeypatch):
    """Record first scans instead of running them (no thread, no cloud call)."""
    from app.api import organization

    calls = []

    def fake_start(conn, org_id, background=True, trigger="manual"):
        with db.get_session(org_id) as s:
            run = ScanRun(connector=conn.name, status="running", trigger=trigger)
            s.add(run)
            s.commit()
            calls.append((conn.name, trigger))
            return NS(id=run.id)

    monkeypatch.setattr(organization, "start_scan", fake_start)
    return calls


def test_test_and_save_stores_nothing_when_the_test_fails(client, encryption, monkeypatch, started):
    seen = {}

    def fake_run(provider, settings, secrets):
        seen.update(provider=provider, secret=settings.azure_client_secret, subs=settings.azure_subscription_ids)
        return access_check.AccessCheck(False, "Azure rejected the credentials.")

    monkeypatch.setattr(access_check, "run", fake_run)
    r = client.put("/api/organization/connectors/azure", json={**AZURE_BODY, "test": True, "start_first_scan": True})
    assert r.status_code == 422 and r.json()["detail"] == "Azure rejected the credentials."
    assert seen == {"provider": "azure", "secret": SECRET, "subs": [SUB]}
    with db.get_session("default") as s:
        assert s.scalars(select(ConnectorConfig)).all() == []
        audit = s.scalars(select(AuditLog).where(AuditLog.action == "connector_config_tested")).one()
        assert audit.detail["ok"] is False and SECRET not in str(audit.detail)
    assert started == []


def test_test_and_save_then_first_scan_once(client, encryption, monkeypatch, started):
    monkeypatch.setattr(access_check, "run", lambda p, s, sec: access_check.AccessCheck(
        True, f"Connected to Azure: read access to {SUB}.", [{"id": SUB, "name": SUB}]))
    r = client.put("/api/organization/connectors/azure", json={**AZURE_BODY, "test": True, "start_first_scan": True})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["stored"] and body["test_message"].startswith("Connected to Azure") and body["first_scan_id"]
    assert SECRET not in r.text
    assert started == [("azure", "first_scan")]
    # Editing later (secret kept: not sent) tests with the stored secret and starts no second scan.
    seen = {}

    def fake_run(provider, settings, secrets):
        seen["secret"] = settings.azure_client_secret
        return access_check.AccessCheck(True, "ok", [])

    monkeypatch.setattr(access_check, "run", fake_run)
    r = client.put("/api/organization/connectors/azure", json={
        "config": AZURE_BODY["config"], "test": True, "start_first_scan": True})
    assert r.status_code == 200 and r.json()["first_scan_id"] is None
    assert seen["secret"] == SECRET and started == [("azure", "first_scan")]
    scans = client.get("/api/scans").json()
    first = next(x for x in scans if x["id"] == body["first_scan_id"])
    assert first["trigger"] == "first_scan" and first["triggered_by"] == "admin@example.com"


def test_plain_save_still_skips_the_test(client, encryption, monkeypatch, started):
    monkeypatch.setattr(access_check, "run", lambda *a: pytest.fail("no test requested"))
    r = client.put("/api/organization/connectors/azure", json=AZURE_BODY)
    assert r.status_code == 200 and r.json()["test_message"] is None and started == []


def test_only_admins_save(client, encryption):
    from fastapi.testclient import TestClient

    from tests.conftest import BASE_URL, login, make_user

    make_user(client, "analyst")
    analyst = TestClient(client.app, base_url=BASE_URL)
    login(analyst, "analyst@example.com", "a-long-test-password")
    assert analyst.put("/api/organization/connectors/azure", json={**AZURE_BODY, "test": True}).status_code == 403
