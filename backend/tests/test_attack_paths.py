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
    assert p.confirmed and p.note is None and p.steps[0].weak and not p.steps[1].weak
    assert [s.asset_id for s in p.steps] == ["vm", "mi", "st"]
    assert p.edges[0] == {"source": "internet", "target": "vm", "type": "exposes"}
    assert p.severity in ("critical", "high")
    assert any("CVE-2021-44228" in r for r in p.steps[0].reasons)
    assert any("PII" in r for r in p.steps[-1].reasons)


def confirmed(paths):
    return [p for p in paths if p.confirmed]


def test_dormant_vulnerability_does_not_confirm_a_path():
    dormant = {**LOG4J, "in_use": False}
    paths = compute_attack_paths(ASSETS, RELS, {"vm": [dormant]}, {})
    assert confirmed(paths) == []
    assert compute_attack_paths(ASSETS, RELS, {"vm": [dormant]}, {}, include_unconfirmed=False) == []


def test_no_weakness_gives_an_unconfirmed_exposure_path():
    paths = compute_attack_paths(ASSETS, RELS, {}, {})
    assert len(paths) == 1
    p = paths[0]
    assert p.confirmed is False and p.note == "No exploitable weakness found yet" and p.weaknesses == []
    assert p.severity in ("medium", "low")
    assert not any(s.weak for s in p.steps)
    assert compute_attack_paths(ASSETS, RELS, {}, {}, include_unconfirmed=False) == []


def test_internal_assets_are_not_entry_points():
    paths = compute_attack_paths(ASSETS, RELS, {"internal-vm": [LOG4J]}, {})
    assert confirmed(paths) == []
    assert all(p.entry_id != "internal-vm" for p in paths)


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
    paths = compute_attack_paths(assets, rels, {"vm": [LOG4J], "vm2": [weak]}, {}, include_unconfirmed=False)
    assert [p.entry_id for p in paths] == ["vm", "vm2"]
    assert paths[0].score > paths[1].score
    assert len(compute_attack_paths(assets, rels, {"vm": [LOG4J], "vm2": [weak]}, {}, limit=1)) == 1


# --------------------------------------------------------------------------- network attribution
def nsg(id_, *rules, type_="nsg"):
    return a(id_, type_, security_rules=[
        {"name": n, "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
         "source_prefixes": [src], "port_ranges": [port]} for n, port, src in rules])


SSH_FINDING = {"severity": "high", "title": "NSG allows SSH (22) from the internet"}


def nsg_graph(*controls, edge_props=None, vm_type="vm"):
    assets = {x["id"]: x for x in [a("web", vm_type, exposed=True, exposure="public IP 52.1.2.3"),
                                   a("mi", "identity", roles=["Key Vault Secrets User"], scope="resource"),
                                   a("kv", "key_vault", sensitive=True, data_classification="secrets & keys"),
                                   *controls]}
    rels = [{"source_id": "web", "target_id": "mi", "type": "uses_identity"},
            {"source_id": "mi", "target_id": "kv", "type": "has_access"}]
    for c in controls:
        rels.append({"source_id": c["id"], "target_id": "web", "type": "protects",
                     "properties": (edge_props or {}).get(c["id"], {})})
    return assets, rels


def test_nsg_finding_is_attributed_to_the_protected_entry_vm():
    assets, rels = nsg_graph(nsg("web-nsg", ("ssh", "22", "*")))
    paths = compute_attack_paths(assets, rels, {}, {"web-nsg": [SSH_FINDING]})
    assert len(paths) == 1 and paths[0].confirmed
    p = paths[0]
    assert "Exposed via NSG web-nsg: SSH (22) open to Internet" in p.steps[0].reasons
    assert p.steps[0].weak and p.weaknesses == ["Exposed via NSG web-nsg: SSH (22) open to Internet"]
    unconfirmed = compute_attack_paths(assets, rels, {}, {})[0]
    assert unconfirmed.score < p.score


def test_nsg_without_open_finding_is_not_a_weakness():
    # rules open but the finding was suppressed / resolved -> nothing to attribute
    assets, rels = nsg_graph(nsg("web-nsg", ("ssh", "22", "*")))
    assert compute_attack_paths(assets, rels, {}, {"web-nsg": [{"severity": "medium", "title": "x"}]})[0].confirmed \
        is False


def test_nsg_attribution_needs_an_internet_exposed_entry():
    assets, rels = nsg_graph(nsg("web-nsg", ("ssh", "22", "*")))
    assets["web"]["internet_exposed"] = False
    assert compute_attack_paths(assets, rels, {}, {"web-nsg": [SSH_FINDING]}) == []


def test_all_ports_open_is_reported_once():
    assets, rels = nsg_graph(nsg("web-nsg", ("any", "*", "0.0.0.0/0")))
    p = compute_attack_paths(assets, rels, {}, {"web-nsg": [{"severity": "critical", "title": "all ports"}]})[0]
    assert "Exposed via NSG web-nsg: all ports open to Internet" in p.steps[0].reasons


def test_nic_and_subnet_nsgs_must_both_allow():
    nic = nsg("nic-nsg", ("ssh", "22", "*"), ("rdp", "3389", "*"))
    subnet = nsg("subnet-nsg", ("rdp", "3389", "Internet"))
    props = {"nic-nsg": {"levels": ["nic"]}, "subnet-nsg": {"levels": ["subnet"]}}
    assets, rels = nsg_graph(nic, subnet, edge_props=props)
    f = {"nic-nsg": [SSH_FINDING], "subnet-nsg": [{"severity": "high", "title": "RDP open"}]}
    p = compute_attack_paths(assets, rels, {}, f)[0]
    assert p.confirmed
    reasons = [r for r in p.steps[0].reasons if r.startswith("Exposed via")]
    assert reasons == ["Exposed via NSG nic-nsg: RDP (3389) open to Internet",
                       "Exposed via NSG subnet-nsg: RDP (3389) open to Internet"]
    # subnet NSG blocks everything from the internet -> NIC NSG's SSH rule is not reachable
    closed = nsg("subnet-nsg", ("vnet", "*", "VirtualNetwork"))
    assets, rels = nsg_graph(nic, closed, edge_props=props)
    assert compute_attack_paths(assets, rels, {}, {"nic-nsg": [SSH_FINDING]})[0].confirmed is False


def test_same_level_controls_are_combined_aws_security_groups():
    sg1 = nsg("sg-web", ("ssh", "22", "0.0.0.0/0"), type_="security_group")
    sg2 = nsg("sg-internal", ("app", "8080", "10.0.0.0/8"), type_="security_group")
    assets, rels = nsg_graph(sg1, sg2, vm_type="ec2_instance")
    p = compute_attack_paths(assets, rels, {}, {"sg-web": [{"severity": "high", "title": "admin ports"}]})[0]
    assert p.confirmed
    assert "Exposed via security group sg-web: SSH (22) open to Internet" in p.steps[0].reasons


def test_gcp_firewall_rule_to_instance():
    fw = nsg("allow-rdp", ("rdp", "3389", "0.0.0.0/0"), type_="gcp_firewall_rule")
    assets, rels = nsg_graph(fw, vm_type="gce_instance")
    p = compute_attack_paths(assets, rels, {}, {"allow-rdp": [{"severity": "high", "title": "RDP open"}]})[0]
    assert "Exposed via firewall rule allow-rdp: RDP (3389) open to Internet" in p.steps[0].reasons


def test_control_without_rules_falls_back_to_finding_title():
    assets, rels = nsg_graph(a("web-nsg", "nsg"))
    p = compute_attack_paths(assets, rels, {}, {"web-nsg": [SSH_FINDING]})[0]
    assert "Exposed via NSG web-nsg: NSG allows SSH (22) from the internet" in p.steps[0].reasons


def test_vmss_identity_chain_to_key_vault():
    assets = {x["id"]: x for x in [
        a("vmss", "vmss", exposed=True, exposure="public load balancer lb-web (20.1.1.1)"),
        a("uai", "identity", roles=["Key Vault Secrets User"], scope="resource_group"),
        a("kv", "key_vault", sensitive=True, data_classification="secrets & keys"),
        nsg("vmss-nsg", ("ssh", "22", "*")),
    ]}
    rels = [{"source_id": "vmss", "target_id": "uai", "type": "uses_identity"},
            {"source_id": "uai", "target_id": "kv", "type": "has_access"},
            {"source_id": "vmss-nsg", "target_id": "vmss", "type": "protects", "properties": {"levels": ["nic"]}}]
    p = compute_attack_paths(assets, rels, {}, {"vmss-nsg": [SSH_FINDING]})[0]
    assert [s.asset_id for s in p.steps] == ["vmss", "uai", "kv"] and p.confirmed
    assert any("resource group scope" in r for r in p.steps[1].reasons)
    # a CVE on the scale set works like on any workload
    q = compute_attack_paths(assets, rels, {"vmss": [LOG4J]}, {})[0]
    assert q.confirmed and any("CVE-2021-44228" in r for r in q.steps[0].reasons)


def test_scoring_caps_and_ordering():
    # many juicy hops but no weakness: still capped at medium, ranked after any confirmed path
    assets = {x["id"]: x for x in [
        a("big", "vm", exposed=True),
        a("mi", "identity", roles=["Owner"], scope="subscription"),
        a("kv", "key_vault", sensitive=True), a("st", "storage_account", sensitive=True),
        a("small", "vm", exposed=True), a("mi2", "identity"), a("st2", "storage_account", sensitive=True),
    ]}
    rels = [{"source_id": "big", "target_id": "mi", "type": "uses_identity"},
            {"source_id": "mi", "target_id": "kv", "type": "has_access"},
            {"source_id": "mi", "target_id": "st", "type": "has_access"},
            {"source_id": "small", "target_id": "mi2", "type": "uses_identity"},
            {"source_id": "mi2", "target_id": "st2", "type": "has_access"}]
    weak = {**LOG4J, "cvss": 7.0, "exploit_available": False, "risk_score": 20.0}
    paths = compute_attack_paths(assets, rels, {"small": [weak]}, {})
    assert [p.confirmed for p in paths] == [True, False, False]
    assert all(p.severity in ("medium", "low") and p.score <= 54 for p in paths if not p.confirmed)
    assert paths[0].entry_id == "small"


def test_confirmed_variant_beats_unconfirmed_for_same_entry_and_target():
    assets, rels = nsg_graph(nsg("web-nsg", ("ssh", "22", "*")))
    # second, unconfirmed route to the same key vault
    assets["mi2"] = a("mi2", "identity")
    rels += [{"source_id": "web", "target_id": "mi2", "type": "uses_identity"},
             {"source_id": "mi2", "target_id": "kv", "type": "has_access"}]
    paths = compute_attack_paths(assets, rels, {}, {"web-nsg": [SSH_FINDING]})
    assert len(paths) == 1 and paths[0].confirmed
