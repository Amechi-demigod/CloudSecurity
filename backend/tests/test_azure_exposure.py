"""Azure exposure coverage with fake SDK clients (no Azure calls): NSG evaluation on NICs, Azure Firewall
DNAT, route tables, private endpoints, App Service, managed databases, the Exposure API and attack paths."""
from types import SimpleNamespace as NS

import pytest

from app.config import Settings
from app.connectors.azure import AzureConnector, ReadOnlyClient, ReadOnlyViolation, eval_access_restrictions
from app.engine import eol
from app.engine.posture import evaluate_asset
from app.services import analytics
from app.services.ingest import asset_to_dict, ingest_collection
from tests.azure_fakes import ops, with_defaults

SUB = "77777777-2222-3333-4444-555555555555"
S = f"/subscriptions/{SUB}"
P = f"{S}/resourceGroups/rg-prod/providers"
NET = f"{P}/Microsoft.Network"
VNET = f"{NET}/virtualNetworks/vnet-spoke"
SNET_APP = f"{VNET}/subnets/snet-app"
SNET_MI = f"{VNET}/subnets/snet-mi"
SNET_PE = f"{VNET}/subnets/snet-pe"
NSG_APP = f"{NET}/networkSecurityGroups/nsg-app"
NSG_MI = f"{NET}/networkSecurityGroups/nsg-mi"
RT = f"{NET}/routeTables/rt-spoke"
FW = f"{NET}/azureFirewalls/fw-hub"
FW_PIP = f"{NET}/publicIPAddresses/fw-pip"
POLICY = f"{NET}/firewallPolicies/fwp-hub"
VM = f"{P}/Microsoft.Compute/virtualMachines/app-vm"
VM_NIC = f"{NET}/networkInterfaces/app-vm-nic"
VMSS = f"{P}/Microsoft.Compute/virtualMachineScaleSets/api-vmss"
ILB = f"{NET}/loadBalancers/ilb-api"
ILB_FE = f"{ILB}/frontendIPConfigurations/fe"
ILB_POOL = f"{ILB}/backendAddressPools/api"
COSMOS = f"{P}/Microsoft.DocumentDB/databaseAccounts/cosmos-orders"
PG = f"{P}/Microsoft.DBforPostgreSQL/flexibleServers/pg-orders"
MYSQL = f"{P}/Microsoft.DBforMySQL/flexibleServers/mysql-legacy"
REDIS = f"{P}/Microsoft.Cache/redis/redis-cache"
MI = f"{P}/Microsoft.Sql/managedInstances/sqlmi-core"
KV = f"{P}/Microsoft.KeyVault/vaults/kv-app"
ST_PRIV = f"{P}/Microsoft.Storage/storageAccounts/stprivate"
ST_PUB = f"{P}/Microsoft.Storage/storageAccounts/stpublicpe"
WEB = f"{P}/Microsoft.Web/sites/web-shop"
FN = f"{P}/Microsoft.Web/sites/fn-internal"
PLAN = f"{P}/Microsoft.Web/serverfarms/plan-prod"
PE_ST = f"{NET}/privateEndpoints/pe-stprivate"
PE_STPUB = f"{NET}/privateEndpoints/pe-stpublic"
PE_FN = f"{NET}/privateEndpoints/pe-fn"
ROLE = f"{S}/providers/Microsoft.Authorization/roleDefinitions/"
KV_SECRETS_USER = ROLE + "4633458b-17de-408a-b874-0445c86b69e6"


def nsg_rule(name, port, src="*", access="Allow", prio=100):
    return NS(name=name, direction="Inbound", access=access, protocol="Tcp", priority=prio,
              source_address_prefix=src, source_address_prefixes=[], destination_port_range=port,
              destination_port_ranges=[], destination_address_prefix="*", destination_address_prefixes=[],
              source_application_security_groups=None, destination_application_security_groups=None)


def restriction(name, ip, action="Allow", prio=100, tag="Default"):
    return NS(name=name, ip_address=ip, action=action, priority=prio, tag=tag, vnet_subnet_resource_id=None,
              headers=None)


def site_config(**kw):
    base = dict(min_tls_version="1.2", ftps_state="Disabled", http20_enabled=True, remote_debugging_enabled=False,
                ip_security_restrictions=[], ip_security_restrictions_default_action=None,
                scm_ip_security_restrictions=[], scm_ip_security_restrictions_default_action=None,
                scm_ip_security_restrictions_use_main=False, linux_fx_version="NODE|22-lts", public_network_access=None)
    base.update(kw)
    return NS(**base)


def build_clients():
    network = NS(
        public_ip_addresses=ops(list_all=[NS(id=FW_PIP, ip_address="20.9.9.9", sku=NS(name="Standard"))]),
        network_security_groups=ops(list_all=[
            NS(id=NSG_APP, name="nsg-app", location="westeurope", tags={}, security_rules=[
                nsg_rule("deny-ssh-internet", "22", "Internet", "Deny", 100), nsg_rule("allow-ssh", "22", "*", prio=200)]),
            NS(id=NSG_MI, name="nsg-mi", location="westeurope", tags={}, security_rules=[
                nsg_rule("public-endpoint", "3342", "Internet", prio=300)]),
        ]),
        route_tables=ops(list_all=[NS(id=RT, name="rt-spoke", routes=[
            NS(address_prefix="0.0.0.0/0", next_hop_type="VirtualAppliance", next_hop_ip_address="10.0.0.4")])]),
        virtual_networks=ops(list_all=[NS(id=VNET, name="vnet-spoke", location="westeurope", tags={},
                                          address_space=NS(address_prefixes=["10.1.0.0/16"]), subnets=[
            NS(id=SNET_APP, name="snet-app", network_security_group=NS(id=NSG_APP), route_table=NS(id=RT),
               address_prefix="10.1.0.0/24", delegations=[]),
            NS(id=SNET_MI, name="snet-mi", network_security_group=NS(id=NSG_MI), route_table=None,
               address_prefix="10.1.1.0/24", delegations=[NS(service_name="Microsoft.Sql/managedInstances")]),
            NS(id=SNET_PE, name="snet-pe", network_security_group=None, route_table=None,
               address_prefix="10.1.2.0/24", delegations=[]),
        ])]),
        network_interfaces=ops(list_all=[
            NS(id=VM_NIC, name="app-vm-nic", virtual_machine=NS(id=VM), private_endpoint=None,
               network_security_group=None, ip_configurations=[NS(
                   id=f"{VM_NIC}/ipConfigurations/ipconfig1", private_ip_address="10.1.0.4", subnet=NS(id=SNET_APP),
                   public_ip_address=None, application_security_groups=None)]),
        ]),
        load_balancers=ops(list_all=[NS(
            id=ILB, name="ilb-api", frontend_ip_configurations=[NS(id=ILB_FE, public_ip_address=None,
                                                                   private_ip_address="10.1.0.100")],
            load_balancing_rules=[NS(frontend_ip_configuration=NS(id=ILB_FE), backend_address_pool=NS(id=ILB_POOL),
                                     backend_address_pools=None, frontend_port=443, backend_port=8443)],
            backend_address_pools=[NS(id=ILB_POOL, backend_ip_configurations=[])],
            inbound_nat_rules=[], inbound_nat_pools=[])]),
        private_endpoints=ops(list_by_subscription=[
            NS(id=PE_ST, name="pe-stprivate", location="westeurope", tags={}, subnet=NS(id=SNET_PE),
               private_link_service_connections=[NS(private_link_service_id=ST_PRIV, group_ids=["blob"],
                                                    private_link_service_connection_state=NS(status="Approved"))],
               manual_private_link_service_connections=[], custom_dns_configs=[NS(ip_addresses=["10.1.2.4"])]),
            NS(id=PE_STPUB, name="pe-stpublic", location="westeurope", tags={}, subnet=NS(id=SNET_PE),
               private_link_service_connections=[NS(private_link_service_id=ST_PUB, group_ids=["blob"],
                                                    private_link_service_connection_state=NS(status="Approved"))],
               manual_private_link_service_connections=[], custom_dns_configs=[NS(ip_addresses=["10.1.2.5"])]),
            NS(id=PE_FN, name="pe-fn", location="westeurope", tags={}, subnet=NS(id=SNET_PE),
               private_link_service_connections=[NS(private_link_service_id=FN, group_ids=["sites"],
                                                    private_link_service_connection_state=NS(status="Approved"))],
               manual_private_link_service_connections=[], custom_dns_configs=[NS(ip_addresses=["10.1.2.6"])]),
        ]),
        firewall_policies=ops(list_all=[NS(id=POLICY, name="fwp-hub", location="westeurope", tags={},
                                           threat_intel_mode="Off", intrusion_detection=None, sku=NS(tier="Standard"),
                                           base_policy=None)]),
        firewall_policy_rule_collection_groups=ops(list=[NS(name="DefaultDnatRuleCollectionGroup", rule_collections=[
            NS(name="dnat", priority=100, rule_collection_type="FirewallPolicyNatRuleCollection",
               action=NS(type="DNAT"), rules=[
                   NS(name="ssh-to-app", rule_type="NatRule", source_addresses=["*"], source_ip_groups=[],
                      destination_addresses=["20.9.9.9"], destination_ports=["2222"], ip_protocols=["TCP"],
                      translated_address="10.1.0.4", translated_port="22", translated_fqdn=None),
                   NS(name="api", rule_type="NatRule", source_addresses=["*"], source_ip_groups=[],
                      destination_addresses=["20.9.9.9"], destination_ports=["443"], ip_protocols=["TCP"],
                      translated_address="10.1.0.100", translated_port="443", translated_fqdn=None),
                   NS(name="office-blob", rule_type="NatRule", source_addresses=["52.10.20.0/24"],
                      source_ip_groups=[], destination_addresses=["20.9.9.9"], destination_ports=["8443"],
                      ip_protocols=["TCP"], translated_address="10.1.2.4", translated_port="443",
                      translated_fqdn=None)]),
            NS(name="net", priority=200, rule_collection_type="FirewallPolicyFilterRuleCollection",
               action=NS(type="Allow"), rules=[
                   NS(name="any-any", rule_type="NetworkRule", source_addresses=["*"], source_ip_groups=[],
                      destination_addresses=["10.0.0.0/8"], destination_ports=["*"], ip_protocols=["Any"])]),
        ])]),
        azure_firewalls=ops(list_all=[NS(
            id=FW, name="fw-hub", location="westeurope", tags={}, sku=NS(tier="Standard"), threat_intel_mode="Alert",
            ip_configurations=[NS(public_ip_address=NS(id=FW_PIP), private_ip_address="10.0.0.4")],
            hub_ip_addresses=None, nat_rule_collections=[], network_rule_collections=[],
            application_rule_collections=[], firewall_policy=NS(id=POLICY), virtual_hub=None)]),
    )
    compute = NS(
        virtual_machines=ops(list_all=[NS(
            id=VM, name="app-vm", location="westeurope", tags={}, hardware_profile=NS(vm_size="D2s"),
            storage_profile=NS(os_disk=NS(os_type="Linux", encryption_settings=None, managed_disk=None)),
            security_profile=NS(encryption_at_host=True),
            identity=NS(principal_id="app-vm-principal", user_assigned_identities=None))]),
        virtual_machine_scale_sets=ops(list_all=[NS(
            id=VMSS, name="api-vmss", location="westeurope", tags={}, sku=NS(name="D2s", capacity=2),
            orchestration_mode="Uniform", identity=None,
            virtual_machine_profile=NS(
                storage_profile=NS(os_disk=NS(os_type="Linux", managed_disk=None)), security_profile=None,
                network_profile=NS(network_interface_configurations=[NS(
                    network_security_group=None,
                    ip_configurations=[NS(subnet=NS(id=SNET_APP), public_ip_address_configuration=None,
                                          load_balancer_backend_address_pools=[NS(id=ILB_POOL)],
                                          application_gateway_backend_address_pools=[],
                                          load_balancer_inbound_nat_pools=[], application_security_groups=None)])])))]),
    )
    storage = NS(storage_accounts=ops(list=[
        NS(id=ST_PRIV, name="stprivate", location="westeurope", tags={"data_classification": "confidential"},
           allow_blob_public_access=True, enable_https_traffic_only=True, minimum_tls_version="TLS1_2",
           public_network_access="Disabled", network_rule_set=NS(default_action="Allow", ip_rules=[]), kind="StorageV2"),
        NS(id=ST_PUB, name="stpublicpe", location="westeurope", tags={"data_classification": "confidential"},
           allow_blob_public_access=False, enable_https_traffic_only=True, minimum_tls_version="TLS1_2",
           public_network_access="Enabled", network_rule_set=NS(default_action="Allow", ip_rules=[]), kind="StorageV2"),
    ]))
    sql = NS(servers=ops(list=[]), managed_instances=ops(list=[NS(
        id=MI, name="sqlmi-core", location="westeurope", tags={}, subnet_id=SNET_MI, public_data_endpoint_enabled=True,
        minimal_tls_version="1.0", fully_qualified_domain_name="sqlmi-core.public.abc.database.windows.net",
        administrators=NS(sid="mi-admin", azure_ad_only_authentication=False), proxy_override="Proxy",
        identity=None)]))
    keyvault = NS(vaults=ops(list_by_subscription=[NS(
        id=KV, name="kv-app", location="westeurope", tags={},
        properties=NS(enable_soft_delete=True, enable_purge_protection=True, enable_rbac_authorization=True,
                      public_network_access="Enabled", network_acls=NS(default_action="Deny", ip_rules=[]),
                      access_policies=[]))]))
    web = NS(
        app_service_plans=ops(list=[NS(id=PLAN, name="plan-prod", location="westeurope", tags={},
                                       sku=NS(name="P1v3", tier="PremiumV3"), reserved=True, number_of_sites=2,
                                       zone_redundant=False)]),
        web_apps=ops(
            list=[NS(id=WEB, name="web-shop", kind="app,linux", location="westeurope", tags={}, state="Running",
                     default_host_name="web-shop.azurewebsites.net", https_only=False, public_network_access="",
                     client_cert_enabled=False, client_cert_mode="Required", server_farm_id=PLAN,
                     virtual_network_subnet_id=None, identity=NS(type="SystemAssigned", principal_id="web-principal",
                                                                 user_assigned_identities=None)),
                  NS(id=FN, name="fn-internal", kind="functionapp,linux", location="westeurope", tags={},
                     state="Running", default_host_name="fn-internal.azurewebsites.net", https_only=True,
                     public_network_access="Disabled", client_cert_enabled=False, server_farm_id=PLAN,
                     virtual_network_subnet_id=SNET_APP, identity=None)],
            get_configuration=None, get_auth_settings_v2_without_secrets=NS(platform=NS(enabled=False)),
            list_slots=[NS(name="web-shop/staging")]))
    web.web_apps.get_configuration.side_effect = lambda rg, name: (
        site_config(linux_fx_version="PHP|7.4", ftps_state="AllAllowed", remote_debugging_enabled=True,
                    http20_enabled=False, min_tls_version="1.0") if name == "web-shop"
        else site_config(linux_fx_version="PYTHON|3.12"))
    postgresql = NS(
        servers=ops(list_by_subscription=[NS(
            id=PG, name="pg-orders", location="westeurope", tags={}, version="11", full_version=None,
            network=NS(public_network_access="Disabled", delegated_subnet_resource_id=SNET_APP),
            backup=NS(geo_redundant_backup="Disabled", backup_retention_days=7),
            auth_config=NS(active_directory_auth="Enabled"), fully_qualified_domain_name=None, identity=None)]),
        firewall_rules=ops(list_by_server=[]),
        configurations=ops(get=None),
        administrators_microsoft_entra=ops(list_by_server=[NS(object_id="app-vm-principal", principal_name="app-vm")]))
    postgresql.configurations.get.side_effect = lambda rg, name, param: NS(
        value={"require_secure_transport": "on", "ssl_min_protocol_version": "TLSv1.2"}[param])
    mysql = NS(
        servers=ops(list=[NS(
            id=MYSQL, name="mysql-legacy", location="westeurope", tags={}, version="5.7", full_version="5.7.44",
            network=NS(public_network_access="Enabled", delegated_subnet_resource_id=None),
            backup=NS(geo_redundant_backup="Enabled", backup_retention_days=7), fully_qualified_domain_name=None,
            identity=None)]),
        firewall_rules=ops(list_by_server=[NS(name="AllowAll", start_ip_address="0.0.0.0",
                                              end_ip_address="255.255.255.255")]),
        configurations=ops(get=None),
        azure_ad_administrators=ops(list_by_server=[]))
    mysql.configurations.get.side_effect = lambda rg, name, param: NS(
        value={"require_secure_transport": "OFF", "tls_version": "TLSv1,TLSv1.1,TLSv1.2"}[param])
    cosmosdb = NS(
        database_accounts=ops(list=[NS(
            id=COSMOS, name="cosmos-orders", location="westeurope", tags={"data_classification": "PII"},
            kind="GlobalDocumentDB", public_network_access="Enabled", ip_rules=[],
            is_virtual_network_filter_enabled=False, virtual_network_rules=[], disable_local_auth=False,
            minimal_tls_version="Tls12", backup_policy=NS(type="Periodic", periodic_mode_properties=NS(
                backup_storage_redundancy="Local")),
            api_properties=None, document_endpoint="https://cosmos-orders.documents.azure.com:443/")]),
        sql_resources=ops(list_sql_role_assignments=[NS(
            principal_id="app-vm-principal",
            role_definition_id=f"{COSMOS}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002")]))
    redis = NS(
        redis=ops(list_by_subscription=[NS(
            id=REDIS, name="redis-cache", location="westeurope", tags={}, enable_non_ssl_port=True,
            minimum_tls_version="1.2", public_network_access="Enabled", subnet_id=None, redis_version="4.0.14",
            disable_access_key_authentication=False, redis_configuration=NS(aad_enabled="false"),
            sku=NS(name="Standard"), host_name="redis-cache.redis.cache.windows.net", identity=None)]),
        firewall_rules=ops(list=[]))
    authorization = NS(role_definitions=ops(list=[]), role_assignments=ops(list_for_subscription=[
        NS(role_definition_id=KV_SECRETS_USER, scope=KV, principal_id="web-principal")]))
    return with_defaults({"network": network, "compute": compute, "storage": storage, "sql": sql,
                          "keyvault": keyvault, "web": web, "postgresql": postgresql, "mysql": mysql,
                          "cosmosdb": cosmosdb, "redis": redis, "authorization": authorization})


def collect(clients=None):
    s = Settings()
    s.azure_subscription_ids = [SUB]
    clients = clients or build_clients()
    return AzureConnector(s, client_factory=lambda kind, sub: ReadOnlyClient(clients[kind], kind)).collect()


@pytest.fixture(scope="module")
def result():
    return collect()


def by_name(res):
    return {a.name: a for a in res.assets}


def edges(res, type_):
    return {(r.source_id.rsplit("/", 1)[-1], r.target_id.rsplit("/", 1)[-1]): r.properties
            for r in res.relationships if r.type == type_}


def failing(asset):
    return {r.id for r, _ in evaluate_asset(asset_to_dict(asset))}


def test_no_errors(result):
    assert result.errors == []


# ----------------------------------------------------------------------------- Azure Firewall
def test_firewall_inventory_and_dnat_mapping(result):
    a = by_name(result)
    fw = a["fw-hub"]
    assert fw.type == "azure_firewall" and fw.internet_exposed
    assert fw.properties["public_ips"] == ["20.9.9.9"] and fw.properties["policy"] == "fwp-hub"
    assert fw.properties["threat_intel_mode"] == "Off"  # the policy's mode wins over the classic setting
    rules = {r["name"]: r for r in fw.properties["dnat_rules"]}
    assert rules["ssh-to-app"]["targets"] == ["app-vm"]
    assert rules["api"]["targets"] == ["api-vmss"]  # via the internal load balancer 10.1.0.100
    assert rules["office-blob"]["targets"] == ["stprivate"]  # via the private endpoint 10.1.2.4
    assert {"2222", "443"} <= set(fw.properties["effective_ports"])
    assert a["fwp-hub"].type == "firewall_policy"
    conn = edges(result, "connects_to")
    assert conn[("fw-hub", "app-vm")]["ports"] == [22] and conn[("fw-hub", "app-vm")]["via"] == "DNAT"
    assert conn[("fw-hub", "api-vmss")]["ports"] == [8443]  # ILB rule 443 -> backend 8443
    assert ("fwp-hub", "fw-hub") in edges(result, "applies_to")
    assert {"AZ-FW-001", "AZ-FW-003", "AZ-FW-005"} <= failing(fw)
    assert "AZ-FW-004" not in failing(fw)  # uses a policy


def test_dnat_backends_are_exposed_via_the_firewall(result):
    a = by_name(result)
    vm = a["app-vm"]
    assert vm.internet_exposed and vm.properties["exposed_only_via"] == [FW.lower()]
    assert vm.properties["effective_ports"] == ["22"]
    assert "Azure Firewall fw-hub DNAT 20.9.9.9:2222 -> 10.1.0.4:22" in vm.properties["exposure"]
    assert vm.properties["egress"] == "0.0.0.0/0 via Azure Firewall fw-hub (10.0.0.4)"  # forced tunnelling
    ss = a["api-vmss"]
    assert ss.internet_exposed and ss.properties["effective_ports"] == ["8443"]
    assert "via internal load balancer ilb-api" in ss.properties["exposure"]
    # restricted DNAT source (a public /24): the private store is reachable from that range only
    st = a["stprivate"]
    assert not st.internet_exposed and st.properties["exposure_level"] == "restricted"
    assert st.properties["partial_exposure"][0]["source"] == "52.10.20.0/24"


# ----------------------------------------------------------------------------- private endpoints
def test_private_endpoints_and_public_access(result):
    a = by_name(result)
    pe = a["pe-stprivate"]
    assert pe.type == "private_endpoint" and pe.properties["vnet"] == VNET.lower()
    assert pe.properties["targets"][0]["id"] == ST_PRIV.lower()
    assert ("pe-stprivate", "stprivate") in edges(result, "connects_to")
    assert ("vnet-spoke", "pe-stprivate") in edges(result, "contains")
    priv = a["stprivate"]
    assert priv.properties["public_endpoint"] == "disabled" and priv.properties["private_endpoints"] == ["pe-stprivate"]
    assert not priv.internet_exposed and "AZ-STG-004" not in failing(priv)
    pub = a["stpublicpe"]
    assert pub.properties["public_endpoint"] == "open" and pub.properties["private_endpoints"] == ["pe-stpublic"]
    assert "AZ-STG-004" in failing(pub)  # public access still enabled despite private endpoint
    fn = a["fn-internal"]
    assert fn.type == "function_app" and not fn.internet_exposed and fn.properties["public_endpoint"] == "disabled"
    kv = a["kv-app"]
    assert kv.properties["public_endpoint"] == "closed" and "AZ-KV-004" not in failing(kv)


# ----------------------------------------------------------------------------- App Service
def test_app_service_inventory_and_rules(result):
    a = by_name(result)
    web = a["web-shop"]
    assert web.type == "web_app" and web.internet_exposed
    p = web.properties
    assert p["public_endpoint"] == "open" and p["scm_access"] == "open" and p["auth_enabled"] is False
    assert p["plan"] == "plan-prod" and p["slots"] == ["web-shop/staging"] and p["managed_identity"] is True
    assert p["runtimes"] == ["php 7.4"] and p["eol_runtimes"] == ["PHP 7.4"]
    assert set(p["effective_ports"]) == {"80", "443"}  # not HTTPS-only
    hits = {r.id: ev for r, ev in evaluate_asset(asset_to_dict(web))}
    assert {"AZ-APP-001", "AZ-APP-002", "AZ-APP-003", "AZ-APP-004", "AZ-APP-006", "AZ-APP-007", "AZ-APP-008",
            "AZ-APP-009", "AZ-APP-010"} <= set(hits)
    assert "AZ-APP-005" not in hits  # has a managed identity
    assert hits["AZ-APP-009"]["_title"] == "Runtime PHP 7.4 is end-of-life since 2022-11-28"
    assert ("plan-prod", "web-shop") in edges(result, "contains")
    assert ("web-shop(system)", "kv-app") in {(s.replace(" (system identity)", "(system)"), t) for s, t in
                                               [(next(x.name for x in result.assets if x.id == r.source_id),
                                                 r.target_id.rsplit("/", 1)[-1]) for r in result.relationships
                                                if r.type == "has_access"]}


@pytest.mark.parametrize("rules,default,expected", [
    ([], None, "open"),
    ([restriction("Allow all", "Any", prio=2147483647)], None, "open"),
    ([restriction("office", "52.10.20.0/24")], None, "restricted"),  # implicit deny-all once rules exist
    ([restriction("office", "52.10.20.0/24")], "Allow", "open"),
    ([restriction("vnet-only", "10.0.0.0/8")], None, "closed"),
    ([restriction("deny-all", "Any", action="Deny", prio=100), restriction("office", "52.10.20.0/24", prio=200)],
     None, "closed"),  # first match wins
    ([restriction("afd", "AzureFrontDoor.Backend", tag="ServiceTag")], None, "restricted"),
    ([restriction("internet", "0.0.0.0/0")], "Deny", "open"),
])
def test_access_restriction_evaluation(rules, default, expected):
    assert eval_access_restrictions(rules, default)[0] == expected


@pytest.mark.parametrize("cfg,expected", [
    ({"linux_fx_version": "PHP|8.0"}, ["PHP 8.0"]),
    ({"linux_fx_version": "NODE|16-lts"}, ["Node.js 16"]),
    ({"linux_fx_version": "PYTHON|3.7"}, ["Python 3.7"]),
    ({"linux_fx_version": "DOTNETCORE|3.1"}, [".NET 3.1"]),
    ({"net_framework_version": "v6.0"}, [".NET 6.0"]),
    ({"net_framework_version": "v4.0"}, []),  # .NET Framework 4.x: supported with Windows
    ({"linux_fx_version": "JAVA|17-java17"}, []),
    ({"linux_fx_version": "TOMCAT|9.0-java11"}, []),
    ({"windows_fx_version": "DOCKER|nginx:latest"}, []),
    ({"php_version": "7.3", "python_version": "3.12"}, ["PHP 7.3"]),
    ({"node_version": "~14"}, ["Node.js ~14"]),
])
def test_eol_runtime_detection(cfg, expected):
    from datetime import date

    assert [h["runtime"] for h in eol.eol_runtimes(cfg, today=date(2026, 10, 23))] == expected


def test_eol_table_dates():
    from datetime import date

    assert eol.eol_check("python", "3.10", today=date(2026, 10, 30)) is None
    assert eol.eol_check("python", "3.10", today=date(2026, 11, 1))["eol_date"] == "2026-10-31"
    assert eol.eol_check("postgresql", "11")["eol_date"] == "2023-11-09"
    assert eol.eol_check("mysql", "8.0.36", today=date(2026, 5, 1))["eol_date"] == "2026-04-30"
    assert eol.eol_check("redis", "6.0") is None


def test_auth_settings_read_is_secret_free_and_guarded():
    clients = build_clients()
    guarded = ReadOnlyClient(clients["web"], "web")
    assert guarded.web_apps.get_auth_settings_v2_without_secrets is not None
    for blocked in ("get_auth_settings", "get_auth_settings_v2", "list_application_settings",
                    "list_publishing_profile_xml_with_secrets", "list_host_keys", "get_functions_admin_token"):
        with pytest.raises(ReadOnlyViolation):
            getattr(guarded.web_apps, blocked)


# ----------------------------------------------------------------------------- databases
def test_database_mapping_and_rules(result):
    a = by_name(result)
    cosmos = a["cosmos-orders"]
    assert cosmos.type == "cosmos_account" and cosmos.sensitive_data and cosmos.internet_exposed
    assert cosmos.properties["data_classification"] == "PII" and cosmos.properties["public_endpoint"] == "open"
    assert {"AZ-COSMOS-001", "AZ-COSMOS-002", "AZ-COSMOS-004"} <= failing(cosmos)
    assert "AZ-COSMOS-003" not in failing(cosmos)

    pg = a["pg-orders"]
    assert pg.type == "postgresql_server" and not pg.internet_exposed
    assert pg.properties["public_endpoint"] == "disabled" and pg.properties["delegated_subnet"] == SNET_APP.lower()
    assert pg.properties["require_secure_transport"] is True and pg.properties["min_tls_version"] == "TLSv1.2"
    hits = {r.id: ev for r, ev in evaluate_asset(asset_to_dict(pg))}
    assert set(hits) == {"AZ-PG-005", "AZ-PG-007"}
    assert hits["AZ-PG-007"]["_title"] == "PostgreSQL server engine PostgreSQL 11 is end-of-life since 2023-11-09"

    my = a["mysql-legacy"]
    assert my.type == "mysql_server" and my.internet_exposed and my.properties["public_endpoint"] == "open"
    assert my.properties["min_tls_version"] == "TLSv1"
    assert {"AZ-MYSQL-001", "AZ-MYSQL-003", "AZ-MYSQL-004", "AZ-MYSQL-006", "AZ-MYSQL-007"} <= failing(my)

    redis = a["redis-cache"]
    assert redis.type == "redis_cache" and redis.internet_exposed
    assert redis.properties["effective_ports"] == ["6379-6380"]  # TLS 6380 + non-TLS 6379
    assert {"AZ-REDIS-001", "AZ-REDIS-003", "AZ-REDIS-004", "AZ-REDIS-005"} <= failing(redis)

    mi = a["sqlmi-core"]
    assert mi.type == "sql_managed_instance" and mi.internet_exposed and mi.properties["public_endpoint"] == "open"
    assert {"AZ-SQLMI-001", "AZ-SQLMI-002", "AZ-SQLMI-003"} <= failing(mi)


def test_database_has_access_edges(result):
    names = {x.id: x.name for x in result.assets}
    acc = {(names[r.source_id], names[r.target_id]): r.properties for r in result.relationships
           if r.type == "has_access"}
    assert acc[("app-vm (system identity)", "cosmos-orders")]["role"] == "Cosmos DB Built-in Data Contributor"
    assert acc[("app-vm (system identity)", "pg-orders")]["role"] == "Entra administrator"


def test_mi_closed_when_nsg_does_not_admit_3342():
    clients = build_clients()
    clients["network"].network_security_groups.list_all.return_value[1].security_rules = [
        nsg_rule("office", "3342", "52.10.20.0/24")]
    mi = by_name(collect(clients))["sqlmi-core"]
    assert not mi.internet_exposed and mi.properties["public_endpoint"] == "restricted"


def test_missing_permission_is_recorded_not_fatal():
    clients = build_clients()
    clients["cosmosdb"].database_accounts.list.side_effect = RuntimeError("AuthorizationFailed")
    clients["redis"].redis.list_by_subscription.side_effect = RuntimeError(
        "MissingSubscriptionRegistration: The subscription is not registered to use namespace 'Microsoft.Cache'")
    res = collect(clients)
    assert any("cosmosdb" in e and "AuthorizationFailed" in e for e in res.errors)
    assert any("redis" in e and "MissingSubscriptionRegistration" in e for e in res.errors)
    assert "pg-orders" in by_name(res) and "cosmos-orders" not in by_name(res)


def test_only_read_operations_are_called():
    clients = build_clients()
    collect(clients)
    for client in clients.values():
        for group in vars(client).values():
            for name, call in group._mock_children.items():
                if call.called:
                    assert name.startswith(("list", "get")), name


def test_real_sdk_models_enum_normalization():
    """New SDK models return str enums whose str() is 'EnumName.MEMBER': the connector uses their values."""
    from azure.mgmt.network.models import AzureFirewallThreatIntelMode, SecurityRuleAccess, SecurityRuleDirection
    from azure.mgmt.redis.models import PublicNetworkAccess as RedisPna
    from azure.mgmt.web.models import FtpsState

    clients = build_clients()
    rule = clients["network"].network_security_groups.list_all.return_value[0].security_rules[0]
    rule.direction, rule.access = SecurityRuleDirection.INBOUND, SecurityRuleAccess.DENY
    clients["network"].azure_firewalls.list_all.return_value[0].threat_intel_mode = AzureFirewallThreatIntelMode.ALERT
    clients["network"].firewall_policies.list_all.return_value[0].threat_intel_mode = AzureFirewallThreatIntelMode.OFF
    clients["redis"].redis.list_by_subscription.return_value[0].public_network_access = RedisPna.ENABLED
    web_cfg = clients["web"].web_apps.get_configuration.side_effect
    clients["web"].web_apps.get_configuration.side_effect = lambda rg, n: NS(
        **{**vars(web_cfg(rg, n)), "ftps_state": FtpsState.ALL_ALLOWED})
    a = by_name(collect(clients))
    assert a["nsg-app"].properties["security_rules"][0]["access"] == "Deny"
    assert a["fw-hub"].properties["threat_intel_mode"] == "Off"
    assert a["redis-cache"].properties["public_network_access"] == "Enabled"
    assert a["web-shop"].properties["ftps_state"] == "AllAllowed"


# ----------------------------------------------------------------------------- end to end
def test_attack_paths_end_to_end(session):
    ingest_collection(session, collect(), source="azure")
    paths = analytics.attack_paths(session, limit=100)
    titles = {p.title: p for p in paths}
    # firewall DNAT -> VM -> identity -> Cosmos DB / PostgreSQL
    fw_cosmos = titles["Internet -> fw-hub -> app-vm -> app-vm (system identity) -> cosmos-orders"]
    assert fw_cosmos.confirmed
    assert any("Azure Firewall DNAT forwards a management port" in w for w in fw_cosmos.weaknesses)
    assert any("Azure Firewall fw-hub DNAT" in r for r in fw_cosmos.steps[1].reasons)
    assert {e["type"] for e in fw_cosmos.edges} >= {"exposes", "connects_to", "uses_identity", "has_access"}
    assert "Internet -> fw-hub -> app-vm -> app-vm (system identity) -> pg-orders" in titles
    # the VM is reached through the firewall: not a separate entry point
    assert not any(p.entry_id == VM.lower() for p in paths)
    # public App Service with an end-of-life runtime -> identity -> key vault
    web_kv = titles["Internet -> web-shop -> web-shop (system identity) -> kv-app"]
    assert web_kv.confirmed
    assert "Vulnerable: Runtime PHP 7.4 is end-of-life since 2022-11-28" in web_kv.steps[0].reasons
    # private-only stores and the private function app are never entry points
    assert not any(p.entry_id in (ST_PRIV.lower(), FN.lower(), PG.lower()) for p in paths)
    # internet-exposed data stores are entries on their own
    assert any(p.entry_id == COSMOS.lower() and p.target_id == COSMOS.lower() and p.confirmed for p in paths)


def test_exposure_api(empty_client):
    from app import db

    client = empty_client
    session = db.get_session()
    try:
        ingest_collection(session, collect(), source="azure")
    finally:
        session.close()
    r = client.get("/api/exposure")
    assert r.status_code == 200
    body = r.json()
    items = {i["name"]: i for i in body["items"]}
    assert {"fw-hub", "app-vm", "api-vmss", "web-shop", "cosmos-orders", "mysql-legacy", "redis-cache",
            "sqlmi-core", "stpublicpe", "stprivate"} <= set(items)
    assert "pg-orders" not in items and "fn-internal" not in items and "kv-app" not in items
    vm = items["app-vm"]
    assert vm["level"] == "open" and not vm["attack_path_entry"] and vm["exposed_only_via"] == ["fw-hub"]
    assert vm["methods"][0]["kind"] == "firewall_dnat" and vm["methods"][0]["label"] == "Azure Firewall DNAT"
    assert vm["effective_ports"] == ["22"]
    assert any(p["confirmed"] for p in vm["attack_paths"])
    st = items["stpublicpe"]
    assert st["private_endpoints"] == ["pe-stpublic"] and st["level"] == "open" and not st["attack_path_entry"]
    assert any(f["rule_id"] == "AZ-STG-004" for f in st["findings"]["top"])
    assert items["stprivate"]["level"] == "restricted"
    web = items["web-shop"]
    assert web["attack_path_entry"] and any(f["rule_id"] == "AZ-APP-009" for f in web["findings"]["top"])
    # filters
    ssh = {i["name"] for i in client.get("/api/exposure", params={"port": 22}).json()["items"]}
    assert ssh == {"app-vm"}
    dbs = client.get("/api/exposure", params={"type": "redis_cache"}).json()["items"]
    assert [i["name"] for i in dbs] == ["redis-cache"]
    assert client.get("/api/exposure", params={"provider": "aws"}).json()["items"] == []
    assert {i["name"] for i in client.get("/api/exposure", params={"level": "restricted"}).json()["items"]} == {"stprivate"}
    assert client.get("/api/exposure", params={"subscription": SUB}).json()["summary"]["total"] == len(items)
    facets = body["facets"]
    assert "azure" in facets["providers"] and "22" in facets["ports"] and "web_app" in facets["types"]
    summary = client.get("/api/exposure/summary").json()
    assert summary["open"] == body["summary"]["open"] and summary["risky_ports_open"] >= 3


def test_exposure_api_requires_sign_in(anon_client):
    assert anon_client.get("/api/exposure").status_code == 401


def test_exposure_api_on_simulated_and_other_cloud_shapes(client):
    """Assets without exposure methods (simulated data, AWS / GCP) are described from their exposure text."""
    body = client.get("/api/exposure").json()
    assert body["items"], "the simulated environment has internet-exposed assets"
    for i in body["items"]:
        assert i["methods"] and i["level"] in ("open", "restricted")
    assert body["summary"]["by_provider"]


def test_classic_firewall_rules_and_app_gateway_fqdn_backend():
    clients = build_clients()
    net = clients["network"]
    fw = net.azure_firewalls.list_all.return_value[0]
    fw.firewall_policy = None
    fw.nat_rule_collections = [NS(name="classic-dnat", priority=100, action=NS(type="Dnat"), rules=[
        NS(name="rdp", source_addresses=["*"], source_ip_groups=[], destination_addresses=["20.9.9.9"],
           destination_ports=["3389"], protocols=["TCP"], translated_address="10.1.0.4", translated_port="3389",
           translated_fqdn=None)])]
    net.firewall_policies.list_all.return_value = []
    gw_pip = f"{NET}/publicIPAddresses/agw-pip"
    net.public_ip_addresses.list_all.return_value.append(NS(id=gw_pip, ip_address="20.8.8.8", sku=None))
    net.application_gateways = ops(list_all=[NS(
        id=f"{NET}/applicationGateways/agw", name="agw",
        frontend_ip_configurations=[NS(public_ip_address=NS(id=gw_pip))],
        backend_http_settings_collection=[NS(port=443)],
        backend_address_pools=[NS(id=f"{NET}/applicationGateways/agw/backendAddressPools/fn",
                                  backend_ip_configurations=[],
                                  backend_addresses=[NS(fqdn="fn-internal.azurewebsites.net", ip_address=None)])])])
    res = collect(clients)
    a = by_name(res)
    fwa = a["fw-hub"]
    assert fwa.properties["policy"] is None and fwa.properties["classic_rule_count"] == 1
    assert {"AZ-FW-001", "AZ-FW-004"} <= failing(fwa) and "AZ-FW-003" not in failing(fwa)
    assert a["app-vm"].properties["effective_ports"] == ["3389"]
    # a private function app published through a public application gateway is internet-exposed
    fn = a["fn-internal"]
    assert fn.internet_exposed and fn.properties["public_endpoint"] == "disabled"
    assert "public application gateway agw (20.8.8.8)" in fn.properties["exposure"]


def test_single_servers_are_flagged_retired():
    clients = build_clients()
    clients["resource"].resources = ops(list=[NS(
        id=f"{P}/Microsoft.DBforPostgreSQL/servers/pg-single", name="pg-single",
        type="Microsoft.DBforPostgreSQL/servers", kind=None, location="westeurope", tags={})], get_by_id=NS(
        properties={"version": "11", "sslEnforcement": "Disabled", "minimalTlsVersion": "TLS1_0",
                    "publicNetworkAccess": "Enabled"}))
    pg = by_name(collect(clients))["pg-single"]
    assert pg.properties["deployment"] == "single"
    assert {"AZ-PG-003", "AZ-PG-004", "AZ-PG-007", "AZ-PG-008"} <= failing(pg)


def test_vm_public_ip_blocked_by_nsg_is_not_exposed():
    clients = build_clients()
    net = clients["network"]
    pip = f"{NET}/publicIPAddresses/vm-pip"
    net.public_ip_addresses.list_all.return_value.append(NS(id=pip, ip_address="20.7.7.7", sku=NS(name="Standard")))
    net.network_interfaces.list_all.return_value[0].ip_configurations[0].public_ip_address = NS(id=pip)
    net.azure_firewalls.list_all.return_value = []
    # nsg-app: deny SSH from Internet (100) before allow SSH from * (200); defaults deny the rest
    vm = by_name(collect(clients))["app-vm"]
    assert not vm.internet_exposed and vm.properties["public_ips"] == ["20.7.7.7"]
    assert vm.properties["exposure_level"] == "none"
    assert "public IP 20.7.7.7: no port reachable from the Internet" in vm.properties["exposure_blocked"]
    assert vm.properties["network_controls"] == ["NSG nsg-app (subnet)"]
    # removing the deny opens SSH through the subnet NSG
    net.network_security_groups.list_all.return_value[0].security_rules.pop(0)
    vm = by_name(collect(clients))["app-vm"]
    assert vm.internet_exposed and vm.properties["effective_ports"] == ["22"]
    # no NSG at all: a Standard public IP is closed by default, a Basic one is open
    net.virtual_networks.list_all.return_value[0].subnets[0].network_security_group = None
    assert not by_name(collect(clients))["app-vm"].internet_exposed
    net.public_ip_addresses.list_all.return_value[-1].sku = NS(name="Basic")
    assert by_name(collect(clients))["app-vm"].properties["effective_ports"] == ["*"]


def test_eol_runtimes_and_engines_become_vulnerabilities(empty_client):
    from app import db
    from app.models import Vulnerability

    clients = build_clients()
    session = db.get_session()
    try:
        stats = ingest_collection(session, collect(clients), source="azure")
        assert stats["eol_opened"] == 4
        rows = {v.cve_id: v for v in session.query(Vulnerability).filter_by(source="eol")}
        assert set(rows) == {"EOL-PHP-7.4", "EOL-POSTGRESQL-11", "EOL-MYSQL-5.7.44", "EOL-REDIS-4.0.14"}
        php = rows["EOL-PHP-7.4"]
        assert php.title == "PHP 7.4 is end-of-life since 2022-11-28" and php.in_use and php.status == "open"
        assert php.internet_exposed and php.priority in ("critical", "high")
        assert php.evidence["url"] == "https://endoflife.date/php"
    finally:
        session.close()
    listed = empty_client.get("/api/vulnerabilities", params={"source": "eol"}).json()
    assert {v["cve_id"] for v in listed} == set(rows)
    # the app is upgraded: the next scan resolves its row
    web_cfg = clients["web"].web_apps.get_configuration.side_effect
    clients["web"].web_apps.get_configuration.side_effect = lambda rg, n: NS(
        **{**vars(web_cfg(rg, n)), "linux_fx_version": "PHP|8.3"})
    session = db.get_session()
    try:
        stats = ingest_collection(session, collect(clients), source="azure")
        assert stats["eol_resolved"] == 1 and stats["eol_opened"] == 0
        assert session.query(Vulnerability).filter_by(cve_id="EOL-PHP-7.4").one().status == "resolved"
    finally:
        session.close()
