"""AWS / GCP: config validation, rule catalog, API surface (health, connectors, filters)."""
from __future__ import annotations

import pytest

from app import config
from app.config import Settings
from app.connectors.base import AssetRecord, CollectionResult
from app.engine import posture
from app.engine.posture import evaluate_asset


# --------------------------------------------------------------------------- config validation
@pytest.mark.parametrize("env,problem", [
    ({"AWS_ACCESS_KEY_ID": "AKIAABCDEFGHIJKLMNOP"}, "must be set together"),
    ({"AWS_SECRET_ACCESS_KEY": "x"}, "must be set together"),
    ({"AWS_ACCESS_KEY_ID": "not-a-key", "AWS_SECRET_ACCESS_KEY": "x"}, "does not look like an access key"),
    ({"AWS_ROLE_ARNS": "arn:aws:iam::123:role/x"}, "AWS_ROLE_ARNS"),
    ({"AWS_ROLE_ARNS": "arn:aws:iam::123456789012:user/x"}, "AWS_ROLE_ARNS"),
    ({"AWS_EXTERNAL_ID": "a"}, "AWS_EXTERNAL_ID"),
    ({"AWS_EXTERNAL_ID": "has space"}, "AWS_EXTERNAL_ID"),
    ({"AWS_REGIONS": "eu-west-1,Frankfurt"}, "AWS_REGIONS: 'Frankfurt'"),
    ({"AWS_HOME_REGION": "global"}, "AWS_HOME_REGION"),
    ({"AWS_AUTH_MODE": "magic"}, "AWS_AUTH_MODE"),
    ({"GCP_PROJECT_IDS": "Acme_Prod"}, "GCP_PROJECT_IDS: 'Acme_Prod'"),
    ({"GCP_ORGANIZATION_ID": "acme.com"}, "GCP_ORGANIZATION_ID"),
    ({"GCP_CREDENTIALS_FILE": "secrets/key.json"}, "absolute path"),
])
def test_invalid_cloud_settings_are_reported(monkeypatch, env, problem):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    probs = Settings().cloud_config_problems()
    assert any(problem in p for p in probs), probs
    # fatal at startup in every environment (like the SSO checks)
    assert any(problem in p for p in Settings().auth_config_problems())
    secret = env.get("AWS_SECRET_ACCESS_KEY")
    assert not secret or secret == "x" or all(secret not in p for p in probs)


def test_valid_cloud_settings(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAABCDEFGHIJKLMNOP")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "not-a-real-secret-for-tests-0000")
    monkeypatch.setenv("AWS_ROLE_ARNS", "arn:aws:iam::111111111111:role/cnapp-readonly, "
                                        "arn:aws-us-gov:iam::222222222222:role/path/cnapp-readonly")
    monkeypatch.setenv("AWS_EXTERNAL_ID", "cnapp-3f9c2a7e1b")
    monkeypatch.setenv("AWS_REGIONS", "eu-west-1,us-east-1,us-gov-west-1,ap-southeast-2")
    monkeypatch.setenv("GCP_PROJECT_IDS", "acme-prod,acme-dev-123")
    monkeypatch.setenv("GCP_ORGANIZATION_ID", "organizations/1234567890")
    monkeypatch.setenv("GCP_CREDENTIALS_FILE", "/run/secrets/gcp/credentials.json")
    s = Settings()
    assert s.cloud_config_problems() == []
    assert s.aws_role_arns[1].startswith("arn:aws-us-gov:") and s.gcp_organization_id == "1234567890"
    assert "not-a-real-secret" not in repr(s) and "cnapp-3f9c2a7e1b" not in repr(s)


def test_defaults_are_valid_and_unconfigured():
    s = Settings()
    assert s.cloud_config_problems() == []
    assert s.aws_home_region == "us-east-1" and s.aws_regions == [] and s.gcp_project_ids == []


# --------------------------------------------------------------------------- rule catalog
def test_rule_counts_and_frameworks():
    aws = [r for r in posture.RULES if r.id.startswith("AWS-")]
    gcp = [r for r in posture.RULES if r.id.startswith("GCP-")]
    assert 18 <= len(aws) <= 26 and 18 <= len(gcp) <= 26
    assert all(any(c.startswith(("CIS AWS", "CIS EKS", "AWS FSBP")) for c in r.compliance) for r in aws)
    assert all(any(c.startswith(("CIS GCP", "CIS GKE")) for c in r.compliance) for r in gcp)
    assert sum(any(c.startswith("CIS AWS") for c in r.compliance) for r in aws) >= 15
    assert sum(any(c.startswith("CIS GCP") for c in r.compliance) for r in gcp) >= 12


AWS_TYPES = {"aws_account", "iam_user", "iam_role", "s3_bucket", "ec2_instance", "security_group", "rds_instance",
             "eks_cluster", "kms_key", "cloudtrail_trail", "lambda_function"}
GCP_TYPES = {"gcp_project", "gcp_service_account", "gcp_firewall_rule", "gce_instance", "gcs_bucket", "gke_cluster",
             "cloud_sql_instance", "gcp_kms_key", "cloud_run_service", "cloud_function"}


@pytest.mark.parametrize("type_", sorted(AWS_TYPES | GCP_TYPES))
def test_unknown_properties_never_produce_findings(type_):
    """A failed / denied API read leaves properties missing: no false positives."""
    assert evaluate_asset({"id": "x", "name": "x", "type": type_, "properties": {}}) == []


def test_kms_without_rotation_period_fails_but_other_purposes_pass():
    a = lambda **p: {"id": "k", "name": "k", "type": "gcp_kms_key", "properties": p}  # noqa: E731
    assert [r.id for r, _ in evaluate_asset(a(purpose="ENCRYPT_DECRYPT"))] == ["GCP-KMS-001"]
    assert evaluate_asset(a(purpose="ENCRYPT_DECRYPT", rotation_period_days=90)) == []
    assert evaluate_asset(a(purpose="ASYMMETRIC_SIGN")) == []
    assert evaluate_asset(a()) == []


@pytest.mark.parametrize("type_,props,expected", [
    ("aws_account", {"password_policy": None}, {"AWS-IAM-003"}),
    ("aws_account", {"password_policy": {"minimum_length": 14}}, set()),
    ("iam_user", {"console_access": False, "mfa_active": False}, set()),
    ("iam_user", {"access_keys": [{"slot": 1, "age_days": 90}]}, set()),
    ("iam_user", {"access_keys": [{"slot": 1, "age_days": 91}]}, {"AWS-IAM-005"}),
    ("ec2_instance", {"public_ip": None, "security_rules": [
        {"name": "r", "direction": "Inbound", "access": "Allow", "source_prefixes": ["0.0.0.0/0"],
         "port_ranges": ["22"]}]}, set()),
    ("ec2_instance", {"public_ip": "1.2.3.4", "security_rules": [
        {"name": "r", "direction": "Inbound", "access": "Allow", "source_prefixes": ["::/0"],
         "port_ranges": ["3389"]}]}, {"AWS-EC2-001"}),
    ("eks_cluster", {"endpoint_public_access": True, "public_access_cidrs": ["203.0.113.0/24"]}, set()),
    ("eks_cluster", {"endpoint_public_access": False}, set()),
    ("rds_instance", {"backup_retention_days": 7}, set()),
    ("rds_instance", {"backup_retention_days": 3}, {"AWS-RDS-003"}),
    ("security_group", {"is_default": True, "security_rules": []}, set()),
    ("gke_cluster", {"private_endpoint": False, "master_authorized_networks": True, "authorized_cidrs": ["10.0.0.0/8"]}, set()),
    ("gke_cluster", {"private_endpoint": False, "master_authorized_networks": True,
                     "authorized_cidrs": ["0.0.0.0/0"]}, {"GCP-GKE-002"}),
    ("gcp_project", {"owners": ["user:a", "user:b", "user:c"]}, set()),
    ("cloud_run_service", {"public_invoker": ["roles/run.invoker:allUsers"], "ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY"},
     set()),
    ("gce_instance", {"default_service_account": True, "full_api_access": False}, set()),
])
def test_rule_edges(type_, props, expected):
    got = {r.id for r, _ in evaluate_asset({"id": "x", "name": "x", "type": type_, "properties": props})}
    assert got == expected


# --------------------------------------------------------------------------- API
def test_health_reports_every_cloud(anon_client):
    h = anon_client.get("/api/health").json()
    assert h["azure_configured"] is False and h["aws_configured"] is False and h["gcp_configured"] is False


def test_health_reports_configured_clouds(anon_client, monkeypatch, tmp_path):
    key = tmp_path / "k.json"
    key.write_text("{}")
    monkeypatch.setattr(config.settings, "aws_use_default_credentials", True)
    monkeypatch.setattr(config.settings, "gcp_project_ids", ["acme-prod"])
    monkeypatch.setattr(config.settings, "gcp_credentials_file", str(key))
    h = anon_client.get("/api/health").json()
    assert h["aws_configured"] is True and h["gcp_configured"] is True


def test_connectors_list_cloud_cards(client):
    conns = {c["name"]: c for c in client.get("/api/connectors").json()}
    assert {"simulated", "azure", "aws", "gcp"} <= set(conns)
    for name in ("aws", "gcp"):
        c = conns[name]
        assert c["configured"] is False and c["provider"] == name and c["last_scan"] is None
        assert c["scope"] == [] and c["discovered_scopes"] == [] and "docs/CONNECT_" in c["setup_hint"]
    assert conns["aws"]["regions"] == ["all enabled"]


@pytest.mark.parametrize("name,hint", [("aws", "AWS_ACCESS_KEY_ID"), ("gcp", "cnapp-ctl gcp-key install")])
def test_scan_requires_configuration(client, name, hint):
    r = client.post("/api/scans", json={"connector": name})
    assert r.status_code == 400 and hint in r.json()["detail"]


class FakeAws:
    name = "aws"
    provider = "aws"
    description = "fake"
    setup_hint = ""

    def is_configured(self):
        return True

    def scope(self):
        return ["111111111111"]

    def info(self):
        return {"name": self.name, "provider": self.provider, "description": "", "configured": True,
                "scope": self.scope(), "setup_hint": ""}

    def collect(self):
        acct = "111111111111"
        return CollectionResult(assets=[
            AssetRecord(id=f"aws:account:{acct}", name="prod", type="aws_account", provider="aws",
                        subscription_id=acct, subscription_name="prod", properties={"root_mfa_enabled": False}),
            AssetRecord(id=f"arn:aws:s3:::open-{acct}", name="open", type="s3_bucket", provider="aws",
                        subscription_id=acct, subscription_name="prod", internet_exposed=True,
                        properties={"is_public": True}),
        ], errors=["111111111111/eu-west-1/eks: ClientError: throttled"])


def test_scan_flows_into_inventory_findings_and_filters(empty_client, monkeypatch):
    from app.api import platform

    real = platform.build_registry

    def registry(s):
        return {**real(s), "aws": FakeAws()}

    monkeypatch.setattr(platform, "build_registry", registry)
    r = empty_client.post("/api/scans", json={"connector": "aws"})
    assert r.status_code == 202, r.text
    import time

    for _ in range(100):
        runs = empty_client.get("/api/scans").json()
        if runs and runs[0]["status"] != "running":
            break
        time.sleep(0.05)
    run = runs[0]
    assert run["connector"] == "aws" and run["status"] == "succeeded" and run["errors"]
    conns = {c["name"]: c for c in empty_client.get("/api/connectors").json()}
    assert conns["aws"]["last_scan"]["id"] == run["id"]
    assert conns["aws"]["discovered_scopes"] == [{"id": "111111111111", "name": "prod"}]
    facets = empty_client.get("/api/assets/facets").json()
    assert "aws" in facets["providers"] and "aws" in facets["sources"]
    assert {"id": "111111111111", "name": "prod", "provider": "aws"} in facets["subscriptions"]
    assert len(empty_client.get("/api/assets", params={"provider": "aws"}).json()) == 2
    assert empty_client.get("/api/assets", params={"provider": "gcp"}).json() == []
    fs = empty_client.get("/api/findings", params={"provider": "aws"}).json()
    assert {f["rule_id"] for f in fs} >= {"AWS-IAM-001", "AWS-S3-001"}
    assert empty_client.get("/api/findings", params={"provider": "gcp"}).json() == []
    assert len(empty_client.get("/api/findings", params={"subscription_id": "111111111111"}).json()) == len(fs)
    assert len(empty_client.get("/api/findings", params={"source": "aws"}).json()) == len(fs)
    comp = {c["framework"] for c in empty_client.get("/api/compliance").json()}
    assert {"CIS AWS", "CIS GCP", "CIS Azure"} <= comp


def test_scheduler_picks_up_configured_aws_and_gcp(tmp_path):
    """Scheduled scans (app/services/scan_schedule.py) cover AWS / GCP once configured."""
    from app.connectors import build_registry, configured_cloud_connectors
    from app.services import scan_schedule

    s = Settings()
    names = {c.name for c in scan_schedule.schedulable(build_registry(s))}
    assert not names & {"aws", "gcp"}
    assert "not configured" in (scan_schedule.schedule_reason(build_registry(s)["aws"]) or "")
    key = tmp_path / "k.json"
    key.write_text("{}")
    s.aws_use_default_credentials = True
    s.gcp_project_ids, s.gcp_credentials_file = ["acme-prod"], str(key)
    names = {c.name for c in scan_schedule.schedulable(build_registry(s))}
    assert {"aws", "gcp"} <= names
    assert {c.name for c in configured_cloud_connectors(s)} == {"aws", "gcp"}
