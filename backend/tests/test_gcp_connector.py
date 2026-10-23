"""GCP connector tests: a fake HTTP session answers the REST calls (no network, no Google auth)."""
from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from app.config import Settings
from app.connectors.gcp import GcpApiError, GcpConnector, ReadOnlyGcpClient, ReadOnlyViolation, check_method
from app.engine.attack_paths import compute_attack_paths
from app.engine.posture import evaluate_asset
from app.models import Finding, ScanRun
from app.services.ingest import asset_to_dict, ingest_collection

P = "acme-prod"
NUM = "123456789012"
DEFAULT_SA = f"{NUM}-compute@developer.gserviceaccount.com"
APP_SA = f"app@{P}.iam.gserviceaccount.com"
NOW = datetime(2026, 10, 1, tzinfo=UTC)


class Resp:
    def __init__(self, status: int, body: dict | None = None, headers: dict | None = None):
        self.status_code = status
        self._body = body or {}
        self.headers = headers or {}
        self.text = json.dumps(self._body)
        self.content = self.text.encode()

    def json(self):
        return self._body


def routes() -> dict:
    """(METHOD, path) -> response body (or Resp / list of Resp for sequences)."""
    fw = lambda name, ports, src="0.0.0.0/0", **kw: {  # noqa: E731
        "name": name, "network": f"https://www.googleapis.com/compute/v1/projects/{P}/global/networks/default",
        "direction": "INGRESS", "priority": 1000, "sourceRanges": [src],
        "allowed": [{"IPProtocol": "tcp", "ports": ports}], **kw}
    return {
        ("GET", f"/v3/projects/{P}"): {"name": f"projects/{NUM}", "projectId": P, "displayName": "Acme Prod",
                                      "state": "ACTIVE", "parent": "organizations/42"},
        ("POST", f"/v3/projects/{P}:getIamPolicy"): {"bindings": [
            {"role": "roles/owner", "members": ["user:a@acme.com", "user:b@acme.com", "user:c@acme.com",
                                                "user:d@acme.com"]},
            {"role": "roles/editor", "members": [f"serviceAccount:{DEFAULT_SA}"]},
            {"role": "roles/iam.serviceAccountUser", "members": ["group:devs@acme.com"]},
            {"role": "roles/viewer", "members": ["allAuthenticatedUsers"]},
            {"role": "roles/storage.objectViewer", "members": [f"serviceAccount:{APP_SA}"]},
        ]},
        ("GET", f"/v1/projects/{P}/serviceAccounts"): {"accounts": [
            {"email": DEFAULT_SA, "displayName": "Compute Engine default service account"},
            {"email": APP_SA, "displayName": "app"}]},
        ("GET", f"/v1/projects/{P}/serviceAccounts/{DEFAULT_SA}/keys"): {"keys": []},
        ("GET", f"/v1/projects/{P}/serviceAccounts/{APP_SA}/keys"): {"keys": [
            {"name": f"projects/{P}/serviceAccounts/{APP_SA}/keys/abcdef0123456789", "keyType": "USER_MANAGED",
             "validAfterTime": "2026-01-01T00:00:00Z"}]},
        ("GET", f"/compute/v1/projects/{P}/global/firewalls"): [
            Resp(200, {"items": [fw("allow-ssh", ["22"]), fw("allow-web", ["443"], targetTags=["web"])],
                       "nextPageToken": "p2"}),
            Resp(200, {"items": [fw("allow-all-internal", ["0-65535"], src="10.0.0.0/8"),
                                 fw("allow-everything", [], targetTags=["legacy"]),
                                 fw("allow-rdp-off", ["3389"], disabled=True)]})],
        ("GET", f"/compute/v1/projects/{P}/aggregated/instances"): {"items": {
            "zones/europe-west1-b": {"instances": [{
                "name": "web-1", "zone": f"https://www.googleapis.com/compute/v1/projects/{P}/zones/europe-west1-b",
                "status": "RUNNING", "machineType": ".../machineTypes/e2-small", "tags": {"items": ["web"]},
                "networkInterfaces": [{"network": ".../global/networks/default",
                                       "accessConfigs": [{"natIP": "34.1.2.3"}]}],
                "serviceAccounts": [{"email": DEFAULT_SA,
                                     "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}]},
                {"name": "batch-1", "zone": ".../zones/europe-west1-c", "status": "RUNNING",
                 "networkInterfaces": [{"network": ".../global/networks/default"}],
                 "serviceAccounts": [{"email": APP_SA, "scopes": []}]}]},
            "zones/us-east1-b": {"warning": {"code": "NO_RESULTS_ON_PAGE"}}}},
        ("GET", "/storage/v1/b"): {"items": [
            {"name": "acme-pii", "location": "EU", "labels": {"data-classification": "pii"},
             "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": False}}},
            {"name": "acme-site", "location": "US", "labels": {},
             "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}, "publicAccessPrevention": "inherited"},
             "retentionPolicy": {"retentionPeriod": "86400"}}]},
        ("GET", "/storage/v1/b/acme-pii/iam"): {"bindings": [
            {"role": "roles/storage.objectViewer", "members": [f"serviceAccount:{APP_SA}"]}]},
        ("GET", "/storage/v1/b/acme-site/iam"): {"bindings": [
            {"role": "roles/storage.objectViewer", "members": ["allUsers"]}]},
        ("GET", f"/v1/projects/{P}/locations/-/clusters"): {"clusters": [
            {"name": "gke-1", "location": "europe-west1", "currentMasterVersion": "1.30.1",
             "legacyAbac": {"enabled": True}, "nodeConfig": {"serviceAccount": "default"},
             "network": "default"},
            {"name": "gke-private", "location": "europe-west1",
             "privateClusterConfig": {"enablePrivateNodes": True, "enablePrivateEndpoint": True},
             "workloadIdentityConfig": {"workloadPool": f"{P}.svc.id.goog"}}]},
        ("GET", f"/v1/projects/{P}/instances"): {"items": [
            {"name": "orders-db", "region": "europe-west1", "databaseVersion": "POSTGRES_15",
             "settings": {"ipConfiguration": {"ipv4Enabled": True, "authorizedNetworks": [{"value": "0.0.0.0/0"}],
                                              "sslMode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"},
                          "backupConfiguration": {"enabled": False}}},
            {"name": "private-db", "region": "europe-west1",
             "settings": {"ipConfiguration": {"ipv4Enabled": False, "sslMode": "ENCRYPTED_ONLY"},
                          "backupConfiguration": {"enabled": True}}}]},
        ("GET", f"/v1/projects/{P}/locations"): {"locations": [{"locationId": "europe-west1"}]},
        ("GET", f"/v1/projects/{P}/locations/europe-west1/keyRings"): {"keyRings": [
            {"name": f"projects/{P}/locations/europe-west1/keyRings/app"}]},
        ("GET", f"/v1/projects/{P}/locations/europe-west1/keyRings/app/cryptoKeys"): {"cryptoKeys": [
            {"name": f"projects/{P}/locations/europe-west1/keyRings/app/cryptoKeys/data", "purpose": "ENCRYPT_DECRYPT"},
            {"name": f"projects/{P}/locations/europe-west1/keyRings/app/cryptoKeys/rotated",
             "purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "7776000s"}]},
        ("GET", f"/v2/projects/{P}/locations/-/services"): {"services": [
            {"name": f"projects/{P}/locations/europe-west1/services/api", "uri": "https://api-x.a.run.app",
             "ingress": "INGRESS_TRAFFIC_ALL", "template": {"serviceAccount": APP_SA}}]},
        ("GET", f"/v2/projects/{P}/locations/europe-west1/services/api:getIamPolicy"): {"bindings": [
            {"role": "roles/run.invoker", "members": ["allUsers"]}]},
        ("GET", f"/v2/projects/{P}/locations/-/functions"): {"functions": [
            {"name": f"projects/{P}/locations/europe-west1/functions/hook", "environment": "GEN_2",
             "url": "https://hook-x.run.app",
             "serviceConfig": {"serviceAccountEmail": APP_SA, "ingressSettings": "ALLOW_INTERNAL_ONLY"}}]},
        ("GET", f"/v2/projects/{P}/locations/europe-west1/functions/hook:getIamPolicy"): {"bindings": [
            {"role": "roles/cloudfunctions.invoker", "members": ["allUsers"]}]},
    }


class FakeSession:
    def __init__(self, table: dict):
        self.table = {k: (list(v) if isinstance(v, list) else v) for k, v in table.items()}
        self.calls: list[tuple[str, str, dict]] = []

    def request(self, method, url, params=None, json=None, timeout=None):
        from urllib.parse import urlsplit

        path = urlsplit(url).path
        self.calls.append((method, url, dict(params or {})))
        v = self.table.get((method, path))
        if v is None:
            return Resp(404, {"error": {"code": 404, "message": f"no route {method} {path}", "status": "NOT_FOUND"}})
        if isinstance(v, list):
            return v.pop(0) if len(v) > 1 else v[0]
        return v if isinstance(v, Resp) else Resp(200, v)


def settings(**kw) -> Settings:
    s = Settings()
    s.gcp_project_ids, s.gcp_organization_id = [P], None
    s.gcp_credentials_file, s.gcp_use_default_credentials = None, False
    for k, v in kw.items():
        setattr(s, k, v)
    return s


def scan(table: dict | None = None, **kw):
    fake = FakeSession(table if table is not None else routes())
    conn = GcpConnector(settings(**kw), session_factory=lambda: fake, sleep=lambda s: None, now=lambda: NOW)
    return conn, conn.collect(), fake


@pytest.fixture(scope="module")
def result():
    return scan()[1]


def by_name(res, name):
    return next(a for a in res.assets if a.name == name)


def failing(a):
    return {r.id for r, _ in evaluate_asset(asset_to_dict(a))}


def test_inventory_mapping(result):
    assert result.errors == []
    types = {a.type for a in result.assets}
    assert {"gcp_project", "gcp_service_account", "gcp_firewall_rule", "gce_instance", "gcs_bucket", "gke_cluster",
            "cloud_sql_instance", "gcp_kms_key", "cloud_run_service", "cloud_function"} <= types
    for a in result.assets:
        assert a.provider == "gcp" and a.subscription_id == P and a.subscription_name == "Acme Prod"
    web = by_name(result, "web-1")
    assert web.internet_exposed and web.region == "europe-west1" and web.properties["external_ips"] == ["34.1.2.3"]
    assert "allow-ssh" in web.properties["exposure"]
    assert web.properties["default_service_account"] and web.properties["full_api_access"]
    # tag-targeted rule applies to web-1 (tag web) but not the legacy-only rule
    assert any(r.startswith("allow-web") for r in web.properties["internet_ingress"])
    assert not any(r.startswith("allow-everything") for r in web.properties["internet_ingress"])
    batch = by_name(result, "batch-1")
    assert not batch.internet_exposed and batch.properties["external_ips"] == []
    pii, site = by_name(result, "acme-pii"), by_name(result, "acme-site")
    assert pii.sensitive_data and not pii.internet_exposed and pii.properties["uniform_access"] is False
    assert site.internet_exposed and site.properties["public_members"] == ["roles/storage.objectViewer:allUsers"]
    assert site.properties["retention_seconds"] == 86400
    db = by_name(result, "orders-db")
    assert db.internet_exposed and db.sensitive_data and db.properties["ssl_required"] is False
    assert by_name(result, "private-db").properties["ssl_required"] is True
    gke = by_name(result, "gke-1")
    assert gke.internet_exposed and gke.properties["legacy_abac"] and not gke.properties["workload_identity"]
    assert not by_name(result, "gke-private").internet_exposed
    proj = by_name(result, P)
    assert proj.properties["project_number"] == NUM
    assert proj.properties["public_bindings"] == ["roles/viewer:allAuthenticatedUsers"]
    sa = by_name(result, DEFAULT_SA)
    assert sa.properties["admin_roles"] == ["roles/editor"] and sa.properties["scope"] == "project"
    app = by_name(result, APP_SA)
    assert app.properties["user_managed_keys"][0]["age_days"] == 273 and not app.properties["admin"]
    assert by_name(result, "api").internet_exposed
    assert not by_name(result, "hook").internet_exposed  # allUsers invoker but internal-only ingress


def test_relationships(result):
    ids = {a.name: a.id for a in result.assets}
    rels = {(r.source_id, r.type, r.target_id) for r in result.relationships}
    assert (ids["allow-ssh"], "protects", ids["web-1"]) in rels
    assert (ids["web-1"], "uses_identity", ids[DEFAULT_SA]) in rels
    assert (ids["gke-1"], "uses_identity", ids[DEFAULT_SA]) in rels  # "default" node SA resolved
    assert (ids[DEFAULT_SA], "has_access", ids["acme-pii"]) in rels  # Editor -> every bucket
    assert (ids[DEFAULT_SA], "has_access", ids["orders-db"]) in rels
    assert (ids[APP_SA], "has_access", ids["acme-pii"]) in rels  # bucket-level binding
    assert (ids["api"], "uses_identity", ids[APP_SA]) in rels
    assert len(rels) == len(result.relationships)  # de-duplicated


def test_rules_fire_on_scanned_shapes(result):
    assert {"GCP-GCE-001", "GCP-GCE-002"} <= failing(by_name(result, "web-1"))
    assert failing(by_name(result, "batch-1")) == set()
    assert failing(by_name(result, "allow-ssh")) == {"GCP-FW-001"}
    assert failing(by_name(result, "allow-everything")) == {"GCP-FW-001", "GCP-FW-002", "GCP-FW-003"}
    assert failing(by_name(result, "allow-rdp-off")) == set()  # disabled rule
    assert failing(by_name(result, "allow-all-internal")) == set()
    assert failing(by_name(result, "acme-site")) == {"GCP-GCS-001"}
    assert failing(by_name(result, "acme-pii")) == {"GCP-GCS-002"}
    assert failing(by_name(result, "gke-1")) == {"GCP-GKE-001", "GCP-GKE-002", "GCP-GKE-003", "GCP-GKE-004"}
    assert failing(by_name(result, "gke-private")) == set()
    assert failing(by_name(result, "orders-db")) == {"GCP-SQL-001", "GCP-SQL-002", "GCP-SQL-003", "GCP-SQL-004"}
    assert failing(by_name(result, "private-db")) == set()
    assert failing(by_name(result, "data")) == {"GCP-KMS-001"}
    assert failing(by_name(result, "rotated")) == set()
    assert failing(by_name(result, P)) == {"GCP-IAM-003", "GCP-IAM-004", "GCP-IAM-005"}
    assert failing(by_name(result, DEFAULT_SA)) == {"GCP-IAM-001"}
    assert failing(by_name(result, APP_SA)) == {"GCP-IAM-002"}
    assert failing(by_name(result, "api")) == {"GCP-RUN-001"}
    assert failing(by_name(result, "hook")) == set()


def test_attack_path_internet_vm_editor_sa_to_sensitive_bucket(result):
    assets = {a.id: asset_to_dict(a) | {"sensitive_data": a.sensitive_data, "internet_exposed": a.internet_exposed}
              for a in result.assets}
    rels = [{"source_id": r.source_id, "target_id": r.target_id, "type": r.type} for r in result.relationships]
    findings = {}
    for a in result.assets:
        findings[a.id] = [{"severity": r.severity, "title": r.title} for r, _ in evaluate_asset(asset_to_dict(a))]
    paths = compute_attack_paths(assets, rels, {}, findings)
    web = by_name(result, "web-1").id
    pii = by_name(result, "acme-pii").id
    p = next(p for p in paths if p.entry_id == web and p.target_id == pii)
    assert [s.type for s in p.steps] == ["gce_instance", "gcp_service_account", "gcs_bucket"]
    assert any("roles/editor" in r for r in p.steps[1].reasons)
    # the publicly open database is a one-hop path on its own
    assert any(p.entry_id == p.target_id == by_name(result, "orders-db").id for p in paths)


def test_only_guarded_read_requests_are_sent():
    _, _, fake = scan()
    assert fake.calls
    for method, url, _ in fake.calls:
        assert url.startswith("https://") and ".googleapis.com/" in url
        assert method == "GET" or url.endswith(":getIamPolicy"), (method, url)


def test_pagination_follows_next_page_token():
    _, res, fake = scan()
    fw_calls = [c for c in fake.calls if c[1].endswith("/global/firewalls")]
    assert len(fw_calls) == 2 and fw_calls[1][2]["pageToken"] == "p2"
    assert {"allow-ssh", "allow-everything"} <= {a.name for a in res.assets}


@pytest.mark.parametrize("method_id,verb,url", [
    ("compute.instances.delete", "DELETE", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances/i"),
    ("compute.instances.setMetadata", "POST", "https://compute.googleapis.com/compute/v1/x/setMetadata"),
    ("compute.firewalls.insert", "POST", "https://compute.googleapis.com/compute/v1/projects/p/global/firewalls"),
    ("cloudresourcemanager.projects.setIamPolicy", "POST", "https://cloudresourcemanager.googleapis.com/v3/p:setIamPolicy"),
    ("iam.projects.serviceAccounts.keys.create", "POST", "https://iam.googleapis.com/v1/projects/p/serviceAccounts/s/keys"),
    ("iam.projects.serviceAccounts.generateAccessToken", "POST", "https://iamcredentials.googleapis.com/v1/x"),
    ("storage.objects.get", "GET", "https://storage.googleapis.com/storage/v1/b/bkt/o/secret.csv"),
    ("storage.objects.list", "GET", "https://storage.googleapis.com/storage/v1/b/bkt/o"),
    ("secretmanager.projects.secrets.versions.access", "GET", "https://secretmanager.googleapis.com/v1/x:access"),
    ("secretmanager.projects.secrets.list", "GET", "https://secretmanager.googleapis.com/v1/projects/p/secrets"),
    ("compute.instances.getSerialPortOutput", "GET", "https://compute.googleapis.com/compute/v1/x/serialPort"),
    ("compute.instances.list", "POST", "https://compute.googleapis.com/compute/v1/projects/p/zones/z/instances"),
    ("compute.instances.list", "GET", "https://evil.example.com/compute/v1/projects/p/zones/z/instances"),
    ("compute.instances.list", "GET", "http://compute.googleapis.com/compute/v1/projects/p/zones/z/instances"),
])
def test_read_only_guard_blocks(method_id, verb, url):
    with pytest.raises(ReadOnlyViolation):
        check_method(method_id, verb, url)
    fake = FakeSession({})
    with pytest.raises(ReadOnlyViolation):
        ReadOnlyGcpClient(fake).call(method_id, url, http_method=verb)
    assert fake.calls == []  # nothing was sent


@pytest.mark.parametrize("method_id,verb", [
    ("compute.instances.aggregatedList", "GET"), ("compute.firewalls.list", "GET"),
    ("cloudresourcemanager.projects.get", "GET"), ("cloudresourcemanager.projects.getIamPolicy", "POST"),
    ("cloudresourcemanager.projects.search", "POST"), ("storage.buckets.getIamPolicy", "GET"),
])
def test_read_only_guard_allows_reads(method_id, verb):
    check_method(method_id, verb, "https://x.googleapis.com/v1/y")


def test_connector_code_only_uses_guarded_client():
    """No direct session/HTTP use in the connector besides the guarded client."""
    import inspect

    from app.connectors import gcp

    src = inspect.getsource(gcp.GcpConnector)
    assert ".request(" not in src and "requests." not in src and "session." not in src


def test_retries_throttling_then_succeeds():
    sleeps = []
    table = {("GET", "/v1/x"): [Resp(429, {}, {"Retry-After": "3"}), Resp(503), Resp(200, {"ok": True})]}
    client = ReadOnlyGcpClient(FakeSession(table), sleep=sleeps.append)
    assert client.call("svc.things.get", "https://svc.googleapis.com/v1/x") == {"ok": True}
    assert sleeps == [3.0, 2.0]


def test_persistent_errors_raise_after_max_attempts():
    table = {("GET", "/v1/x"): [Resp(503)]}
    fake = FakeSession(table)
    with pytest.raises(GcpApiError) as ei:
        ReadOnlyGcpClient(fake, sleep=lambda s: None, max_attempts=3).call("svc.things.get",
                                                                         "https://svc.googleapis.com/v1/x")
    assert ei.value.status == 503 and len(fake.calls) == 3


def test_partial_failures_are_recorded_and_disabled_apis_skipped():
    t = routes()
    t[("GET", f"/v1/projects/{P}/locations/-/clusters")] = Resp(403, {"error": {
        "code": 403, "message": "Kubernetes Engine API has not been used in project 123 before or it is disabled.",
        "status": "PERMISSION_DENIED", "details": [{"reason": "SERVICE_DISABLED"}]}})
    t[("GET", f"/v1/projects/{P}/instances")] = Resp(500, {"error": {"code": 500, "message": "backend error"}})
    t[("GET", "/storage/v1/b/acme-site/iam")] = Resp(403, {"error": {"code": 403, "message": "denied",
                                                                     "status": "PERMISSION_DENIED"}})
    _, res, _ = scan(t)
    types = {a.type for a in res.assets}
    assert "gke_cluster" not in types and "cloud_sql_instance" not in types
    assert {"gce_instance", "gcs_bucket", "cloud_run_service"} <= types
    assert any(e.startswith(f"{P}/cloud sql:") and "500" in e for e in res.errors)
    assert any("bucket iam acme-site" in e for e in res.errors)
    assert not any("gke" in e for e in res.errors)  # API disabled -> skipped, not an error
    assert by_name(res, P).properties["apis_not_enabled"] == ["gke"]
    # unknown bucket IAM: not reported as public
    assert not by_name(res, "acme-site").internet_exposed


def test_failing_project_does_not_stop_others():
    t = routes()
    t[("GET", "/v3/projects/broken-proj")] = Resp(403, {"error": {"code": 403, "message": "no access"}})
    _, res, _ = scan(t, gcp_project_ids=[P, "broken-proj"])
    assert any(e.startswith("broken-proj/project:") for e in res.errors)
    assert any(e.startswith("broken-proj/") for e in res.errors[1:])
    assert by_name(res, "web-1")


def test_organization_discovery_walks_folders():
    t = routes()
    t[("GET", "/v3/projects")] = [Resp(200, {"projects": [{"projectId": P, "name": f"projects/{NUM}", "state": "ACTIVE"}]}),
                                  Resp(200, {"projects": [{"projectId": "deleted-one", "state": "DELETE_REQUESTED"}]})]
    t[("GET", "/v3/folders")] = [Resp(200, {"folders": [{"name": "folders/7", "state": "ACTIVE"}]}),
                                 Resp(200, {})]
    conn, res, fake = scan(t, gcp_project_ids=[], gcp_organization_id="42")
    parents = [c[2].get("parent") for c in fake.calls if c[1].endswith(("/v3/projects", "/v3/folders"))]
    assert parents == ["organizations/42", "organizations/42", "folders/7", "folders/7"]
    assert {a.subscription_id for a in res.assets} == {P}
    assert conn.scope() == ["organizations/42"]


def test_credentials_error_is_reported_not_raised():
    def boom():
        raise RuntimeError("could not load credentials")
    res = GcpConnector(settings(), session_factory=boom).collect()
    assert res.assets == [] and res.errors == ["credentials: RuntimeError: could not load credentials"]


def test_is_configured(tmp_path):
    key = tmp_path / "sa.json"
    assert not GcpConnector(settings()).is_configured()  # no credentials
    assert not GcpConnector(settings(gcp_credentials_file=str(key))).is_configured()  # file missing
    info = GcpConnector(settings(gcp_credentials_file=str(key))).info()
    assert "does not exist" in info["problem"] and info["configured"] is False
    key.write_text("{}")
    key.chmod(0o600)
    assert GcpConnector(settings(gcp_credentials_file=str(key))).is_configured()
    assert not GcpConnector(settings(gcp_credentials_file=str(key), gcp_project_ids=[])).is_configured()
    assert GcpConnector(settings(gcp_use_default_credentials=True)).is_configured()
    assert GcpConnector(settings(gcp_use_default_credentials=True, gcp_project_ids=[],
                                 gcp_organization_id="42")).is_configured()


def test_build_session_loads_key_file_without_network(tmp_path):
    """A service account key file becomes an authorized session; no token is fetched until a request."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from app.connectors.gcp import SCOPES, build_session

    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    key = tmp_path / "sa.json"
    key.write_text(json.dumps({"type": "service_account", "project_id": P, "private_key_id": "k1",
                               "private_key": pem, "client_email": f"cnapp@{P}.iam.gserviceaccount.com",
                               "client_id": "1", "token_uri": "https://oauth2.googleapis.com/token"}))
    sess = build_session(settings(gcp_credentials_file=str(key)))
    assert sess.credentials.service_account_email == f"cnapp@{P}.iam.gserviceaccount.com"
    assert list(sess.credentials.scopes) == SCOPES
    assert not sess.credentials.valid  # no token requested yet


def test_scan_through_ingest_and_scan_service(session, monkeypatch):
    """Same entry point as the manual "Run scan" button: execute_scan -> ingest (source=gcp)."""
    from app.services import scans

    conn = GcpConnector(settings(), session_factory=lambda: FakeSession(routes()), sleep=lambda s: None,
                        now=lambda: NOW)
    run = scans.start_scan(conn, background=False)
    assert run.status == "succeeded" and run.connector == "gcp" and run.assets_found > 10
    fs = session.query(Finding).filter(Finding.source == "gcp").all()
    assert {"GCP-GCS-001", "GCP-SQL-001", "GCP-IAM-001"} <= {f.rule_id for f in fs}
    assert session.get(ScanRun, run.id).errors == []


def test_rescan_resolves_fixed_findings(session):
    conn, res, _ = scan()
    ingest_collection(session, res, source="gcp")
    t = routes()
    t[("GET", "/storage/v1/b/acme-site/iam")] = {"bindings": []}
    ingest_collection(session, scan(t)[1], source="gcp")
    f = session.query(Finding).filter(Finding.rule_id == "GCP-GCS-001").one()
    assert f.status == "resolved"
