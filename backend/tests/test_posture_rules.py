import pytest

from app.engine import posture
from app.engine.posture import PostureRule, evaluate_asset, open_to_internet


def asset(type_, **props):
    return {"id": "x", "name": "x", "type": type_, "properties": props}


def failing_ids(a):
    return {r.id for r, _ in evaluate_asset(a)}


def test_rule_catalog_is_well_formed():
    ids = [r.id for r in posture.RULES]
    assert len(ids) == len(set(ids)), "duplicate rule ids"
    for r in posture.RULES:
        assert r.severity in posture.SEVERITIES
        assert r.title and r.remediation and r.resource_type
        assert r.compliance, f"{r.id} has no compliance mapping"


@pytest.mark.parametrize("props,expected", [
    ({"allow_blob_public_access": True, "https_only": True, "min_tls_version": "TLS1_2"}, {"AZ-STG-001"}),
    ({"allow_blob_public_access": False, "https_only": False, "min_tls_version": "TLS1_2"}, {"AZ-STG-002"}),
    ({"allow_blob_public_access": False, "https_only": True, "min_tls_version": "TLS1_0"}, {"AZ-STG-003"}),
    ({"allow_blob_public_access": False, "https_only": True, "min_tls_version": "TLS1_2"}, set()),
])
def test_storage_rules(props, expected):
    assert failing_ids(asset("storage_account", **props)) == expected


def nsg(*rules):
    return asset("nsg", security_rules=list(rules))


def r(port, source="*", access="Allow", direction="Inbound", name="r"):
    return {"name": name, "direction": direction, "access": access, "source_prefixes": [source], "port_ranges": [port]}


def test_nsg_ssh_rdp_any():
    assert failing_ids(nsg(r("22"))) == {"AZ-NSG-001"}
    assert failing_ids(nsg(r("3389", source="0.0.0.0/0"))) == {"AZ-NSG-002"}
    assert failing_ids(nsg(r("*", source="Internet"))) == {"AZ-NSG-001", "AZ-NSG-002", "AZ-NSG-003"}
    assert failing_ids(nsg(r("20-25"))) == {"AZ-NSG-001"}


def test_nsg_non_matching_rules_pass():
    assert failing_ids(nsg(r("22", source="10.0.0.0/8"))) == set()
    assert failing_ids(nsg(r("22", access="Deny"))) == set()
    assert failing_ids(nsg(r("22", direction="Outbound"))) == set()
    assert failing_ids(nsg(r("443"))) == set()


def test_open_to_internet_handles_legacy_single_fields():
    a = asset("nsg", security_rules=[{"name": "legacy", "direction": "Inbound", "access": "Allow",
                                       "source": "*", "port_range": "3389"}])
    assert open_to_internet(a, 3389) == ["legacy"]


def test_vm_rules():
    assert failing_ids(asset("vm", public_ips=["1.2.3.4"], disk_encryption=False)) == {"AZ-VM-001", "AZ-VM-002"}
    assert failing_ids(asset("vm", public_ips=[], disk_encryption=True)) == set()


def test_sql_rules():
    a = asset("sql_server", public_network_access=True, auditing_enabled=False,
              firewall_rules=[{"name": "all", "start_ip": "0.0.0.0", "end_ip": "255.255.255.255"}])
    assert failing_ids(a) == {"AZ-SQL-001", "AZ-SQL-002", "AZ-SQL-003"}
    ok = asset("sql_server", public_network_access=False, auditing_enabled=True,
               firewall_rules=[{"name": "azure", "start_ip": "0.0.0.0", "end_ip": "0.0.0.0"}])
    assert failing_ids(ok) == set()
    # Unknown auditing state (e.g. API error) must not raise a finding.
    assert "AZ-SQL-002" not in failing_ids(asset("sql_server", auditing_enabled=None))


def test_keyvault_aks_identity_subscription_rules():
    assert failing_ids(asset("key_vault", soft_delete=False, purge_protection=False)) == {"AZ-KV-001", "AZ-KV-002"}
    assert failing_ids(asset("aks_cluster", rbac_enabled=False, private_cluster=False, authorized_ip_ranges=[])) \
        == {"AZ-AKS-001", "AZ-AKS-002"}
    assert failing_ids(asset("aks_cluster", rbac_enabled=True, private_cluster=False,
                             authorized_ip_ranges=["1.2.3.0/24"])) == set()
    assert failing_ids(asset("identity", roles=["Contributor"], scope="subscription")) == {"AZ-ID-001"}
    assert failing_ids(asset("identity", roles=["Contributor"], scope="resource")) == set()
    assert failing_ids(asset("subscription", owner_count=5, contributor_count=8)) == {"AZ-SUB-001", "AZ-SUB-002"}
    assert failing_ids(asset("subscription", owner_count=2, contributor_count=3)) == set()


def test_rule_only_applies_to_its_resource_type():
    assert failing_ids(asset("vm", allow_blob_public_access=True)) == set()


def test_broken_check_never_raises():
    def boom(_):
        raise RuntimeError("bad rule")

    rule = PostureRule(id="T", title="t", severity="low", resource_type="vm", check=boom, description="",
                       remediation="")
    assert rule.evaluate(asset("vm")) is None


def test_compliance_controls_mapping():
    m = posture.compliance_controls()
    assert "AZ-NSG-001" in m["CIS Azure 6.2"]
    assert "AZ-SQL-003" in m["CIS Azure 4.1.2"]
