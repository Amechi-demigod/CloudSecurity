"""Azure connector -> attack-path graph mapping (fake SDK clients, no Azure calls).

Covers what the attack-path engine needs from a real subscription: NIC- and
subnet-level NSG linkage, load balancer / application gateway exposure, VM
scale sets and their user-assigned identities, AKS kubelet and function app
identities, RBAC at resource-group scope (with fan-out cap) and Key Vault
access policies.
"""
from types import SimpleNamespace as NS

import pytest
from azure.mgmt.network.models import SecurityRuleAccess, SecurityRuleDirection

from app.config import Settings
from app.connectors.azure import (
    MAX_ACCESS_EDGES_PER_GRANT,
    AzureConnector,
    ReadOnlyClient,
    _scope_kind,
    data_targets,
)
from app.engine.posture import evaluate_asset
from app.services import analytics
from app.services.ingest import asset_to_dict, ingest_collection
from tests.azure_fakes import ops, with_defaults

SUB = "99999999-2222-3333-4444-555555555555"
SUB_ID = f"/subscriptions/{SUB}"
RG = f"{SUB_ID}/resourceGroups/rg-app"
P = f"{RG}/providers"
RG_DATA = f"{SUB_ID}/resourceGroups/rg-data"
PD = f"{RG_DATA}/providers"
ROLE = f"{SUB_ID}/providers/Microsoft.Authorization/roleDefinitions/"
CONTRIB = ROLE + "b24988ac-6180-42dd-a8b5-a5a87f9b0f2b"
CUSTOM_KV = ROLE + "00000000-aaaa-bbbb-cccc-000000000001"  # resolved through role_definitions.list

SUBNET = f"{P}/Microsoft.Network/virtualNetworks/vnet/subnets/snet-app"
SUBNET_NSG = f"{P}/Microsoft.Network/networkSecurityGroups/subnet-nsg"
VMSS_NSG = f"{P}/Microsoft.Network/networkSecurityGroups/vmss-nsg"
VMSS = f"{P}/Microsoft.Compute/virtualMachineScaleSets/app-vmss"
VMSS_UAI = f"{P}/Microsoft.ManagedIdentity/userAssignedIdentities/app-vmss-identity"
LB = f"{P}/Microsoft.Network/loadBalancers/lb-web"
LB_FE = f"{LB}/frontendIPConfigurations/fe"
LB_POOL = f"{LB}/backendAddressPools/web"
LB_PIP = f"{P}/Microsoft.Network/publicIPAddresses/lb-pip"
API_VM = f"{P}/Microsoft.Compute/virtualMachines/api-01"
API_NIC = f"{P}/Microsoft.Network/networkInterfaces/api-01-nic"
GW = f"{P}/Microsoft.Network/applicationGateways/agw"
GW_PIP = f"{P}/Microsoft.Network/publicIPAddresses/agw-pip"
GW_POOL = f"{GW}/backendAddressPools/app"
KV_RBAC = f"{PD}/Microsoft.KeyVault/vaults/kv-secrets"
KV_LEGACY = f"{P}/Microsoft.KeyVault/vaults/kv-legacy"
AKS = f"{P}/Microsoft.ContainerService/managedClusters/aks-app"
KUBELET = f"{SUB_ID}/resourceGroups/MC_rg-app/providers/Microsoft.ManagedIdentity/userAssignedIdentities/aks-agentpool"
FN = f"{P}/Microsoft.Web/sites/fn-orders"
N_STORAGE = MAX_ACCESS_EDGES_PER_GRANT + 10


def nsg_rule(name, port, src="*"):
    # real SDK enums: str() of these is "SecurityRuleDirection.INBOUND", the connector must use .value
    return NS(name=name, direction=SecurityRuleDirection.INBOUND, access=SecurityRuleAccess.ALLOW, protocol="Tcp",
              source_address_prefix=src, source_address_prefixes=[], destination_port_range=port,
              destination_port_ranges=[], priority=100)


def build_clients(subnet_rules=None):
    subnet_rules = [nsg_rule("ssh", "22", "Internet"), nsg_rule("https", "443", "Internet")] \
        if subnet_rules is None else subnet_rules
    network = NS(
        public_ip_addresses=ops(list_all=[NS(id=LB_PIP, ip_address="20.1.1.1"), NS(id=GW_PIP, ip_address="20.2.2.2")]),
        network_security_groups=ops(list_all=[
            NS(id=SUBNET_NSG, name="subnet-nsg", location="eastus", tags={}, security_rules=subnet_rules),
            NS(id=VMSS_NSG, name="vmss-nsg", location="eastus", tags={},
               security_rules=[nsg_rule("ssh", "22"), nsg_rule("https", "443")]),
        ]),
        virtual_networks=ops(list_all=[NS(subnets=[NS(id=SUBNET, network_security_group=NS(id=SUBNET_NSG))])]),
        network_interfaces=ops(list_all=[NS(
            id=API_NIC, virtual_machine=NS(id=API_VM), network_security_group=None,
            ip_configurations=[NS(public_ip_address=None, subnet=NS(id=SUBNET))])]),
        load_balancers=ops(list_all=[NS(
            id=LB, name="lb-web",
            frontend_ip_configurations=[NS(id=LB_FE, public_ip_address=NS(id=LB_PIP))],
            load_balancing_rules=[NS(frontend_ip_configuration=NS(id=LB_FE), backend_address_pool=NS(id=LB_POOL),
                                     backend_address_pools=None, frontend_port=443)],
            backend_address_pools=[NS(id=LB_POOL, backend_ip_configurations=[
                NS(id=f"{VMSS}/virtualMachines/0/networkInterfaces/nic/ipConfigurations/ipc")])],
            inbound_nat_rules=[], inbound_nat_pools=[])]),
        application_gateways=ops(list_all=[NS(
            id=GW, name="agw", frontend_ip_configurations=[NS(public_ip_address=NS(id=GW_PIP))],
            backend_address_pools=[NS(id=GW_POOL, backend_ip_configurations=[
                NS(id=f"{API_NIC}/ipConfigurations/ipconfig1")])])]),
    )
    compute = NS(
        virtual_machines=ops(list_all=[NS(
            id=API_VM, name="api-01", location="eastus", tags={}, hardware_profile=NS(vm_size="B2s"),
            storage_profile=NS(os_disk=NS(os_type="Linux", encryption_settings=None, managed_disk=None)),
            security_profile=NS(encryption_at_host=True), identity=NS(principal_id="api-principal",
                                                                     user_assigned_identities=None))]),
        virtual_machine_scale_sets=ops(list_all=[NS(
            id=VMSS, name="app-vmss", location="eastus", tags={}, sku=NS(name="Standard_D2s_v5", capacity=3),
            orchestration_mode="Uniform",
            identity=NS(principal_id=None, user_assigned_identities={VMSS_UAI: NS(principal_id="vmss-principal")}),
            virtual_machine_profile=NS(
                storage_profile=NS(os_disk=NS(os_type="Linux", managed_disk=NS(disk_encryption_set=None))),
                security_profile=None,
                network_profile=NS(network_interface_configurations=[NS(
                    network_security_group=NS(id=VMSS_NSG),
                    ip_configurations=[NS(subnet=NS(id=SUBNET), public_ip_address_configuration=NS(name="pip"),
                                          load_balancer_backend_address_pools=[NS(id=LB_POOL)],
                                          application_gateway_backend_address_pools=[],
                                          load_balancer_inbound_nat_pools=[])])])))]),
    )
    storage_accounts = [NS(id=f"{PD}/Microsoft.Storage/storageAccounts/st{i:03d}", name=f"st{i:03d}",
                           location="eastus", tags={"data_classification": "confidential"} if i == N_STORAGE - 1 else {},
                           allow_blob_public_access=False, enable_https_traffic_only=True,
                           minimum_tls_version="TLS1_2", public_network_access="Disabled",
                           network_rule_set=NS(default_action="Deny"), kind="StorageV2")
                        for i in range(N_STORAGE)]
    storage = NS(storage_accounts=ops(list=storage_accounts))
    sql = NS(servers=ops(list=[]))
    keyvault = NS(vaults=ops(list_by_subscription=[
        NS(id=KV_RBAC, name="kv-secrets", location="eastus", tags={},
           properties=NS(enable_soft_delete=True, enable_purge_protection=True, enable_rbac_authorization=True,
                         access_policies=[NS(object_id="api-principal", permissions=NS(secrets=["get"]))])),
        NS(id=KV_LEGACY, name="kv-legacy", location="eastus", tags={},
           properties=NS(enable_soft_delete=True, enable_purge_protection=True, enable_rbac_authorization=False,
                         access_policies=[
                             NS(object_id="api-principal", permissions=NS(secrets=["Get", "List"], keys=[],
                                                                          certificates=None)),
                             NS(object_id="fn-principal", permissions=NS(secrets=["list"]))])),  # names only
    ]))
    containerservice = NS(managed_clusters=ops(list=[NS(
        id=AKS, name="aks-app", location="eastus", tags={}, kubernetes_version="1.30", enable_rbac=True,
        api_server_access_profile=NS(enable_private_cluster=True, authorized_ip_ranges=[]), aad_profile=NS(),
        agent_pool_profiles=[NS(count=2)], identity=NS(principal_id="aks-cp-principal", user_assigned_identities={}),
        identity_profile={"kubeletidentity": NS(resource_id=KUBELET, object_id="kubelet-principal")})]))
    resource_ops = ops(get_by_id=None, list=[
        NS(id=FN, name="fn-orders", type="Microsoft.Web/sites", kind="functionapp", location="eastus", tags={},
           identity=NS(principal_id="fn-principal", user_assigned_identities=None)),
        NS(id=VMSS_UAI, name="app-vmss-identity", type="Microsoft.ManagedIdentity/userAssignedIdentities",
           kind=None, location="eastus", tags={}),
        NS(id=KUBELET, name="aks-agentpool", type="Microsoft.ManagedIdentity/userAssignedIdentities",
           kind=None, location="eastus", tags={}),
    ])
    # principalId lookups fail: the connector falls back to the workload identity blocks
    resource_ops.get_by_id.side_effect = RuntimeError("AuthorizationFailed")
    authorization = NS(
        role_definitions=ops(list=[NS(name="00000000-aaaa-bbbb-cccc-000000000001", role_name="Key Vault Secrets User")]),
        role_assignments=ops(list_for_subscription=[
            NS(role_definition_id=CUSTOM_KV, scope=RG_DATA, principal_id="vmss-principal"),
            NS(role_definition_id=CONTRIB, scope=RG_DATA, principal_id="kubelet-principal"),
        ]))
    return with_defaults({"network": network, "compute": compute, "storage": storage, "sql": sql,
                          "keyvault": keyvault, "containerservice": containerservice,
                          "resource": NS(resources=resource_ops), "authorization": authorization})


def collect(clients=None):
    s = Settings()
    s.azure_subscription_ids = [SUB]
    clients = clients or build_clients()
    return AzureConnector(s, client_factory=lambda kind, sub: ReadOnlyClient(clients[kind], kind)).collect()


def short(x):
    return x.rsplit("/", 1)[-1] if "/identities/system" not in x else x.split("/")[-3] + "(system)"


@pytest.fixture()
def result():
    return collect()


def edges(res, type_=None):
    return {(short(r.source_id), short(r.target_id), r.type): r.properties for r in res.relationships
            if type_ is None or r.type == type_}


def test_nic_and_subnet_nsgs_link_to_vms_and_scale_sets(result):
    prot = edges(result, "protects")
    assert prot[("vmss-nsg", "app-vmss", "protects")] == {"levels": ["nic"]}
    assert prot[("subnet-nsg", "app-vmss", "protects")] == {"levels": ["subnet"]}
    assert prot[("subnet-nsg", "api-01", "protects")] == {"levels": ["subnet"]}


def test_sdk_enums_are_normalized(result):
    nsg = next(a for a in result.assets if a.name == "vmss-nsg")
    assert nsg.properties["security_rules"][0]["direction"] == "Inbound"
    assert {r.id for r, _ in evaluate_asset(asset_to_dict(nsg))} == {"AZ-NSG-001"}


def test_scale_set_inventory_and_exposure(result):
    ss = next(a for a in result.assets if a.name == "app-vmss")
    assert ss.type == "vmss" and ss.internet_exposed
    assert ss.properties["capacity"] == 3 and ss.properties["per_instance_public_ip"] is True
    assert "public IP per instance" in ss.properties["exposure"]
    assert "public load balancer lb-web (20.1.1.1) port 443" in ss.properties["exposure"]
    assert {r.id for r, _ in evaluate_asset(asset_to_dict(ss))} == {"AZ-VMSS-001", "AZ-VMSS-002"}


def test_vm_behind_public_app_gateway_is_exposed(result):
    vm = next(a for a in result.assets if a.name == "api-01")
    assert vm.internet_exposed and vm.properties["public_ips"] == []
    assert vm.properties["exposure"] == "public application gateway agw (20.2.2.2)"


def test_internal_load_balancer_does_not_expose():
    clients = build_clients()
    lb = clients["network"].load_balancers.list_all.return_value[0]
    lb.frontend_ip_configurations[0].public_ip_address = None
    clients["network"].application_gateways.list_all.return_value = []
    vmss = clients["compute"].virtual_machine_scale_sets.list_all.return_value[0]
    vmss.virtual_machine_profile.network_profile.network_interface_configurations[0] \
        .ip_configurations[0].public_ip_address_configuration = None
    res = collect(clients)
    assert not any(a.internet_exposed for a in res.assets if a.name in {"app-vmss", "api-01"})


def test_workload_identities(result):
    uses = edges(result, "uses_identity")
    assert ("app-vmss", "app-vmss-identity", "uses_identity") in uses
    assert ("aks-app", "aks-agentpool", "uses_identity") in uses and \
        uses[("aks-app", "aks-agentpool", "uses_identity")] == {"via": "kubelet"}
    assert ("aks-app", "aks-app(system)", "uses_identity") in uses
    assert ("fn-orders", "fn-orders(system)", "uses_identity") in uses
    assert ("api-01", "api-01(system)", "uses_identity") in uses
    uai = next(a for a in result.assets if a.name == "app-vmss-identity")
    assert uai.properties["principal_id"] == "vmss-principal"  # learned from the scale set


def test_resource_group_scope_roles_reach_data_stores(result):
    acc = edges(result, "has_access")
    # custom role id resolved to "Key Vault Secrets User" via role_definitions.list; RG scope covers the vault
    assert acc[("app-vmss-identity", "kv-secrets", "has_access")] == {"role": "Key Vault Secrets User",
                                                                     "scope": "resource_group"}
    # ... but not vaults / storage outside rg-data, and not storage (role is Key Vault only)
    assert ("app-vmss-identity", "kv-legacy", "has_access") not in acc
    assert not any(s == "app-vmss-identity" and t.startswith("st") for s, t, _ in acc)
    uai = next(a for a in result.assets if a.name == "app-vmss-identity")
    assert uai.properties["roles"] == ["Key Vault Secrets User"] and uai.properties["scope"] == "resource_group"


def test_fan_out_is_capped_sensitive_first(result):
    kubelet_edges = [t for s, t, _ in edges(result, "has_access") if s == "aks-agentpool"]
    assert len(kubelet_edges) == MAX_ACCESS_EDGES_PER_GRANT  # Contributor on rg-data: 60 accounts + 1 vault
    assert f"st{N_STORAGE - 1:03d}" in kubelet_edges and "kv-secrets" in kubelet_edges  # sensitive kept
    kubelet = next(a for a in result.assets if a.name == "aks-agentpool")
    assert kubelet.properties["data_access_truncated"] == N_STORAGE + 1 - MAX_ACCESS_EDGES_PER_GRANT


def test_key_vault_access_policies(result):
    acc = edges(result, "has_access")
    assert acc[("api-01(system)", "kv-legacy", "has_access")] == {"role": "Key Vault access policy",
                                                                 "permissions": "secrets: get, list"}
    assert ("api-01(system)", "kv-secrets", "has_access") not in acc  # RBAC vault ignores policies
    assert ("fn-orders(system)", "kv-legacy", "has_access") not in acc  # list only: no secret values


def test_no_errors_and_no_duplicate_edges(result):
    assert result.errors == []
    keys = [(r.source_id, r.target_id, r.type) for r in result.relationships]
    assert len(keys) == len(set(keys))


@pytest.mark.parametrize("role,targets", [
    ("Owner", {"storage_account", "sql_server", "key_vault", "postgresql_server", "mysql_server",
               "cosmos_account", "redis_cache", "sql_managed_instance"}),
    ("DocumentDB Account Contributor", {"cosmos_account"}),
    ("Cosmos DB Operator", set()),
    ("Redis Cache Contributor", {"redis_cache"}),
    ("SQL Managed Instance Contributor", {"sql_managed_instance"}),
    ("Storage Blob Data Reader", {"storage_account"}),
    ("Storage Account Contributor", {"storage_account"}),
    ("Key Vault Secrets User", {"key_vault"}),
    ("Key Vault Reader", set()),
    ("SQL DB Contributor", {"sql_server"}),
    ("Reader", set()),
    ("custom:abc", set()),
])
def test_data_targets(role, targets):
    assert data_targets(role) == targets


def test_scope_kind():
    sub = SUB_ID.lower()
    assert _scope_kind(sub, sub) == "subscription"
    assert _scope_kind("/providers/microsoft.management/managementgroups/root", sub) == "subscription"
    assert _scope_kind(RG_DATA.lower(), sub) == "resource_group"
    assert _scope_kind(KV_RBAC.lower(), sub) == "resource"


def test_end_to_end_confirmed_path_through_nsg_and_scale_set_identity(session):
    ingest_collection(session, collect(), source="azure")
    paths = analytics.attack_paths(session, limit=50)
    vmss_kv = next(p for p in paths if p.title == "Internet -> app-vmss -> app-vmss-identity -> kv-secrets")
    assert vmss_kv.confirmed and vmss_kv.severity in ("high", "critical", "medium")
    assert "Exposed via NSG vmss-nsg: SSH (22) open to Internet" in vmss_kv.steps[0].reasons
    assert "Exposed via NSG subnet-nsg: SSH (22) open to Internet" in vmss_kv.steps[0].reasons
    # api-01 has no public IP and sits only behind the app gateway (HTTP(S) to the backends):
    # the subnet NSG's SSH rule is not reachable from the internet -> exposure path only
    api = next(p for p in paths if p.entry_id.endswith("/api-01") and p.target_id.endswith("/kv-legacy"))
    assert not api.confirmed and "public application gateway agw" in api.steps[0].reasons[0]


def test_end_to_end_lb_nat_rule_forwarding_ssh_confirms(session):
    clients = build_clients()
    lb = clients["network"].load_balancers.list_all.return_value[0]
    lb.inbound_nat_rules = [NS(frontend_ip_configuration=NS(id=LB_FE), frontend_port=50022, backend_port=22,
                               backend_ip_configuration=NS(id=f"{API_NIC}/ipConfigurations/ipconfig1"))]
    res = collect(clients)
    vm = next(a for a in res.assets if a.name == "api-01")
    assert vm.properties["forwarded_ports"] == [22]
    assert "public load balancer lb-web (20.1.1.1) NAT port 50022" in vm.properties["exposure"]
    ingest_collection(session, res, source="azure")
    api = next(p for p in analytics.attack_paths(session, limit=50)
               if p.entry_id.endswith("/api-01") and p.target_id.endswith("/kv-legacy"))
    assert api.confirmed and "Exposed via NSG subnet-nsg: SSH (22) open to Internet" in api.steps[0].reasons


def test_end_to_end_exposure_path_when_subnet_blocks(session):
    clients = build_clients(subnet_rules=[nsg_rule("https", "443", "Internet")])
    ingest_collection(session, collect(clients), source="azure")
    paths = analytics.attack_paths(session, limit=50)
    vmss_kv = next(p for p in paths if p.title == "Internet -> app-vmss -> app-vmss-identity -> kv-secrets")
    assert vmss_kv.confirmed is False and vmss_kv.note == "No exploitable weakness found yet"
    assert vmss_kv.severity in ("medium", "low")
    assert all(p.confirmed for p in analytics.attack_paths(session, limit=50, include_unconfirmed=False))
