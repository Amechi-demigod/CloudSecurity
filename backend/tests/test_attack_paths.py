from app.engine.attack_paths import compute_attack_paths


def a(id_, type_, exposed=False, sensitive=False, **props):
    return {"id": id_, "name": id_, "type": type_, "internet_exposed": exposed, "sensitive_data": sensitive,
            "properties": props}


ASSETS = {x["id"]: x for x in [
    a("vm", "vm", exposed=True, exposure="public IP"),
    a("mi", "identity", roles=["Contributor"], scope="subscription"),
    a("st", "storage_account", sensitive=True, data_classification="PII"),
    a("internal-vm", "vm"),
]}
RELS = [
    {"source_id": "vm", "target_id": "mi", "type": "uses_identity"},
    {"source_id": "mi", "target_id": "st", "type": "has_access"},
    {"source_id": "internal-vm", "target_id": "mi", "type": "uses_identity"},
]
LOG4J = {"cve_id": "CVE-2021-44228", "package": "log4j-core", "cvss": 10.0, "in_use": True,
         "exploit_available": True, "risk_score": 100.0}


def test_finds_internet_to_sensitive_data_path():
    paths = compute_attack_paths(ASSETS, RELS, {"vm": [LOG4J]}, {})
    assert len(paths) == 1
    p = paths[0]
    assert [s.asset_id for s in p.steps] == ["vm", "mi", "st"]
    assert p.edges[0] == {"source": "internet", "target": "vm", "type": "exposes"}
    assert p.severity in ("critical", "high")
    assert any("CVE-2021-44228" in r for r in p.steps[0].reasons)
    assert any("PII" in r for r in p.steps[-1].reasons)


def test_dormant_vulnerability_does_not_create_path():
    dormant = {**LOG4J, "in_use": False}
    assert compute_attack_paths(ASSETS, RELS, {"vm": [dormant]}, {}) == []


def test_no_weakness_no_path():
    assert compute_attack_paths(ASSETS, RELS, {}, {}) == []


def test_internal_assets_are_not_entry_points():
    paths = compute_attack_paths(ASSETS, RELS, {"internal-vm": [LOG4J]}, {})
    assert paths == []


def test_publicly_exposed_data_store_is_a_one_hop_path():
    assets = {"pub": a("pub", "storage_account", exposed=True, sensitive=True)}
    findings = {"pub": [{"severity": "high", "title": "Storage account allows public blob access"}]}
    paths = compute_attack_paths(assets, [], {}, findings)
    assert len(paths) == 1 and paths[0].steps[0].asset_id == "pub"


def test_paths_sorted_by_score_and_limited():
    assets = dict(ASSETS)
    assets["vm2"] = a("vm2", "vm", exposed=True)
    rels = RELS + [{"source_id": "vm2", "target_id": "mi", "type": "uses_identity"}]
    weak = {**LOG4J, "cve_id": "CVE-X", "cvss": 7.0, "exploit_available": False, "risk_score": 40.0}
    paths = compute_attack_paths(assets, rels, {"vm": [LOG4J], "vm2": [weak]}, {})
    assert [p.entry_id for p in paths] == ["vm", "vm2"]
    assert paths[0].score > paths[1].score
    assert len(compute_attack_paths(assets, rels, {"vm": [LOG4J], "vm2": [weak]}, {}, limit=1)) == 1
