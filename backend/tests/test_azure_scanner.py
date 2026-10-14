"""Azure connector tests with mocked azure-mgmt clients (no network, no SDK auth)."""
from types import SimpleNamespace as NS
from unittest.mock import MagicMock

import pytest

from app.config import Settings
from app.connectors.azure import AzureConnector, ReadOnlyClient, ReadOnlyViolation
from app.engine.posture import evaluate_asset
from app.models import Finding, Relationship
from app.services.ingest import asset_to_dict, ingest_collection

SUB = "11111111-2222-3333-4444-555555555555"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-app/providers"
OWNER = "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIB = "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42dd-a8b5-a5a87f9b0f2b"
BLOB_OWNER = "/providers/Microsoft.Authorization/roleDefinitions/b7e6dc6d-f1e8-4753-8033-0f276bb0955b"

VM_ID = f"{RG}/Microsoft.Compute/virtualMachines/web-01"
PIP_ID = f"{RG}/Microsoft.Network/publicIPAddresses/web-01-pip"
NSG_ID = f"{RG}/Microsoft.Network/networkSecurityGroups/web-nsg"
ST_ID = f"{RG}/Microsoft.Storage/storageAccounts/stpublic01"
SQL_ID = f"{RG}/Microsoft.Sql/servers/sql-app"
KV_ID = f"{RG}/Microsoft.KeyVault/vaults/kv-app"
AKS_ID = f"{RG}/Microsoft.ContainerService/managedClusters/aks-app"
FN_ID = f"{RG}/Microsoft.Web/sites/fn-app"
UAI_ID = f"{RG}/Microsoft.ManagedIdentity/userAssignedIdentities/id-app"


def ops(**methods):
    """Operations-group double: each kwarg becomes a MagicMock returning the value."""
    o = MagicMock(spec=list(methods) + ["begin_delete", "begin_create_or_update", "delete", "update"])
    for name, value in methods.items():
        getattr(o, name).return_value = value
    return o


def build_clients():
    rule = lambda name, port, src="*": NS(name=name, direction="Inbound", access="Allow", protocol="Tcp",  # noqa
                                         source_address_prefix=src, source_address_prefixes=[],
                                         destination_port_range=port, destination_port_ranges=[], priority=100)
    network = NS(
        public_ip_addresses=ops(list_all=[NS(id=PIP_ID, ip_address="52.1.2.3")]),
        network_security_groups=ops(list_all=[NS(id=NSG_ID, name="web-nsg", location="eastus", tags={},
                                                 security_rules=[rule("ssh", "22"), rule("rdp", "3389", "10.0.0.0/8")])]),
        network_interfaces=ops(list_all=[NS(
            virtual_machine=NS(id=VM_ID), network_security_group=NS(id=NSG_ID),
            ip_configurations=[NS(public_ip_address=NS(id=PIP_ID))])]),
    )
    compute = NS(virtual_machines=ops(list_all=[NS(
        id=VM_ID, name="web-01", location="eastus", tags={"env": "prod"},
        hardware_profile=NS(vm_size="Standard_B2s"),
        storage_profile=NS(os_disk=NS(os_type="Linux", encryption_settings=None,
                                      managed_disk=NS(disk_encryption_set=None))),
        security_profile=None,
        identity=NS(principal_id="vm-principal", user_assigned_identities={UAI_ID: {}}),
    )]))
    storage = NS(storage_accounts=ops(list=[NS(
        id=ST_ID, name="stpublic01", location="eastus", tags={"data-classification": "PII"},
        allow_blob_public_access=True, enable_https_traffic_only=False, minimum_tls_version="TLS1_0",
        public_network_access="Enabled", network_rule_set=NS(default_action="Allow"), kind="StorageV2")]))
    sql = NS(
        servers=ops(list=[NS(id=SQL_ID, name="sql-app", location="eastus", tags={}, public_network_access="Enabled")]),
        firewall_rules=ops(list_by_server=[NS(name="AllowAll", start_ip_address="0.0.0.0",
                                              end_ip_address="255.255.255.255")]),
        server_blob_auditing_policies=ops(get=NS(state="Disabled")),
        databases=ops(list_by_server=[NS(id=f"{SQL_ID}/databases/master", name="master", location="eastus", tags={}),
                                      NS(id=f"{SQL_ID}/databases/orders", name="orders", location="eastus", tags={},
                                         sku=NS(name="S0"))]),
    )
    keyvault = NS(vaults=ops(list_by_subscription=[NS(
        id=KV_ID, name="kv-app", location="eastus", tags={},
        properties=NS(enable_soft_delete=False, enable_purge_protection=None, public_network_access="Enabled"))]))
    containerservice = NS(managed_clusters=ops(list=[NS(
        id=AKS_ID, name="aks-app", location="eastus", tags={}, kubernetes_version="1.29.2", enable_rbac=False,
        api_server_access_profile=None, aad_profile=None, agent_pool_profiles=[NS(count=3)])]))
    resource_ops = ops(get_by_id=None, list=[
        NS(id=FN_ID, name="fn-app", type="Microsoft.Web/sites", kind="functionapp,linux", location="eastus", tags={}),
        NS(id=UAI_ID, name="id-app", type="Microsoft.ManagedIdentity/userAssignedIdentities", kind=None,
           location="eastus", tags={}),
        NS(id=f"{RG}/Microsoft.Insights/components/ai", name="ai", type="Microsoft.Insights/components",
           kind="web", location="eastus", tags={}),
    ])
    resource_ops.get_by_id.side_effect = lambda rid, api_version: (
        NS(properties={"httpsOnly": False}) if "sites" in rid else NS(properties={"principalId": "uai-principal"}))
    resource = NS(resources=resource_ops)
    sub_scope = f"/subscriptions/{SUB}"
    authorization = NS(role_assignments=ops(list_for_subscription=[
        *[NS(role_definition_id=sub_scope + OWNER, scope=sub_scope, principal_id=f"user{i}") for i in range(5)],
        NS(role_definition_id=sub_scope + CONTRIB, scope=sub_scope, principal_id="uai-principal"),
        NS(role_definition_id=sub_scope + BLOB_OWNER, scope=ST_ID, principal_id="vm-principal"),
    ]))
    return {"network": network, "compute": compute, "storage": storage, "sql": sql, "keyvault": keyvault,
            "containerservice": containerservice, "resource": resource, "authorization": authorization}


@pytest.fixture()
def clients():
    return build_clients()


def make_connector(clients, **overrides):
    s = Settings()
    s.azure_subscription_ids = [SUB]
    for k, v in overrides.items():
        setattr(s, k, v)
    return AzureConnector(s, client_factory=lambda kind, sub: ReadOnlyClient(clients[kind], kind))


def by_name(result):
    return {a.name: a for a in result.assets}


def test_inventory_and_normalization(clients):
    res = make_connector(clients).collect()
    assert res.errors == []
    a = by_name(res)
    assert {"web-01", "web-nsg", "stpublic01", "sql-app", "orders", "kv-app", "aks-app", "fn-app", "id-app",
            "web-01 (system identity)", SUB} <= set(a)
    assert "master" not in a and "ai" not in a
    vm = a["web-01"]
    assert vm.internet_exposed and vm.properties["public_ips"] == ["52.1.2.3"]
    assert vm.properties["disk_encryption"] is False
    assert vm.resource_group == "rg-app" and vm.id == VM_ID.lower()
    st = a["stpublic01"]
    assert st.internet_exposed and st.sensitive_data and st.properties["data_classification"] == "PII"
    assert a[SUB].properties == {"owner_count": 5, "contributor_count": 1}
    assert a["id-app"].properties["roles"] == ["Contributor"] and a["id-app"].properties["scope"] == "subscription"
    assert a["fn-app"].properties["https_only"] is False


def test_relationships(clients):
    res = make_connector(clients).collect()
    edges = {(r.source_id.rsplit("/", 1)[-1], r.target_id.rsplit("/", 1)[-1], r.type) for r in res.relationships}
    assert ("web-nsg", "web-01", "protects") in edges
    assert ("web-01", "id-app", "uses_identity") in edges
    assert ("web-01", "system", "uses_identity") in edges
    assert ("system", "stpublic01", "has_access") in edges  # Blob Data Owner on the account
    assert ("id-app", "stpublic01", "has_access") in edges  # Contributor at subscription scope
    assert ("sql-app", "orders", "contains") in edges


def test_posture_checks_on_real_shapes(clients):
    res = make_connector(clients).collect()
    failing = {r.id for a in res.assets for r, _ in evaluate_asset(asset_to_dict(a))}
    expected = {"AZ-NSG-001", "AZ-VM-001", "AZ-VM-002", "AZ-STG-001", "AZ-STG-002", "AZ-STG-003", "AZ-SQL-001",
                "AZ-SQL-002", "AZ-SQL-003", "AZ-KV-001", "AZ-KV-002", "AZ-AKS-001", "AZ-AKS-002", "AZ-FN-001",
                "AZ-ID-001", "AZ-SUB-001"}
    assert expected <= failing
    assert "AZ-NSG-002" not in failing  # RDP only from 10.0.0.0/8


def test_only_read_operations_are_called(clients):
    make_connector(clients).collect()
    for client in clients.values():
        for group in vars(client).values():
            for name, call in group._mock_children.items():
                if call.called:
                    assert name.startswith(("list", "get")), name


def test_read_only_guard_blocks_mutations(clients):
    guarded = ReadOnlyClient(clients["storage"], "storage")
    with pytest.raises(ReadOnlyViolation):
        guarded.storage_accounts.begin_delete("rg", "x")
    with pytest.raises(ReadOnlyViolation):
        guarded.storage_accounts.update
    assert guarded.storage_accounts.list() is not None


def test_service_failures_are_isolated(clients):
    clients["sql"].servers.list.side_effect = RuntimeError("AuthorizationFailed")
    res = make_connector(clients).collect()
    assert any("sql" in e and "AuthorizationFailed" in e for e in res.errors)
    assert "web-01" in by_name(res) and "sql-app" not in by_name(res)


def test_not_configured_without_credentials():
    s = Settings()
    s.azure_subscription_ids = [SUB]
    s.azure_tenant_id = s.azure_client_id = s.azure_client_secret = None
    s.azure_use_default_credential = False
    assert AzureConnector(s).is_configured() is False
    s.azure_tenant_id, s.azure_client_id, s.azure_client_secret = "t", "c", "secret"
    assert AzureConnector(s).is_configured() is True
    s.azure_subscription_ids = []
    assert AzureConnector(s).is_configured() is False


def test_ingest_merges_and_resolves_on_rescan(session, clients):
    conn = make_connector(clients)
    stats = ingest_collection(session, conn.collect(), source="azure")
    assert stats["findings_opened"] >= 15
    stg = session.query(Finding).filter_by(rule_id="AZ-STG-001").one()
    assert stg.status == "open" and stg.source == "azure"
    assert session.query(Relationship).count() > 0

    # Customer fixes the storage account -> next scan resolves the finding.
    acct = clients["storage"].storage_accounts.list.return_value[0]
    acct.allow_blob_public_access = False
    stats = ingest_collection(session, conn.collect(), source="azure")
    assert stats["findings_resolved"] >= 1
    session.refresh(stg)
    assert stg.status == "resolved" and stg.resolved_at is not None


@pytest.mark.parametrize("kind,group,read_op,write_op", [
    ("resource", "resources", "list", "begin_delete_by_id"),
    ("compute", "virtual_machines", "list_all", "begin_delete"),
    ("network", "network_security_groups", "list_all", "begin_create_or_update"),
    ("storage", "storage_accounts", "list", "update"),
    ("sql", "servers", "list", "begin_delete"),
    ("keyvault", "vaults", "list_by_subscription", "delete"),
    ("containerservice", "managed_clusters", "list", "begin_delete"),
    ("authorization", "role_assignments", "list_for_subscription", "create"),
])
def test_real_sdk_clients_are_wrapped_read_only(kind, group, read_op, write_op):
    """Construct the real azure-mgmt clients (no network I/O) and check the guard."""
    pytest.importorskip("azure.mgmt.storage")
    from app.connectors.azure import AzureClientFactory

    client = AzureClientFactory(MagicMock())(kind, SUB)
    assert callable(getattr(getattr(client, group), read_op))
    with pytest.raises(ReadOnlyViolation):
        getattr(getattr(client, group), write_op)


@pytest.mark.parametrize("kind,group,secret_op", [
    ("storage", "storage_accounts", "list_keys"),
    ("storage", "storage_accounts", "list_account_sas"),
    ("containerservice", "managed_clusters", "list_cluster_admin_credentials"),
    ("containerservice", "managed_clusters", "list_cluster_user_credentials"),
])
def test_secret_returning_list_calls_are_blocked(kind, group, secret_op):
    """list_keys & co. are POSTs that return secrets; a posture scan must never call them."""
    pytest.importorskip("azure.mgmt.storage")
    from app.connectors.azure import AzureClientFactory

    client = AzureClientFactory(MagicMock())(kind, SUB)
    with pytest.raises(ReadOnlyViolation):
        getattr(getattr(client, group), secret_op)


def test_raw_request_escape_hatch_blocked():
    pytest.importorskip("azure.mgmt.storage")
    from app.connectors.azure import AzureClientFactory

    client = AzureClientFactory(MagicMock())("storage", SUB)
    with pytest.raises(ReadOnlyViolation):
        client.send_request
    with pytest.raises(AttributeError):
        client._pipeline
