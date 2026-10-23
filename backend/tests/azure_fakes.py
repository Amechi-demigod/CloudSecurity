"""Fake azure-mgmt clients for connector tests (no network, no SDK auth, no real Azure calls)."""
from types import SimpleNamespace as NS
from unittest.mock import MagicMock


def ops(**methods):
    """Operations-group double: each kwarg becomes a MagicMock returning the value."""
    o = MagicMock(spec=list(methods) + ["begin_delete", "begin_create_or_update", "delete", "update"])
    for name, value in methods.items():
        getattr(o, name).return_value = value
    return o


# Operation groups the connector reads; a test that does not care about one gets an empty listing.
EMPTY_GROUPS = {
    "network": {"public_ip_addresses": {"list_all": []}, "network_security_groups": {"list_all": []},
                "virtual_networks": {"list_all": []}, "network_interfaces": {"list_all": []},
                "load_balancers": {"list_all": []}, "application_gateways": {"list_all": []},
                "route_tables": {"list_all": []}, "private_endpoints": {"list_by_subscription": []},
                "firewall_policies": {"list_all": []}, "azure_firewalls": {"list_all": []},
                "firewall_policy_rule_collection_groups": {"list": []}},
    "compute": {"virtual_machines": {"list_all": []}, "virtual_machine_scale_sets": {"list_all": []}},
    "storage": {"storage_accounts": {"list": []}},
    "sql": {"servers": {"list": []}, "managed_instances": {"list": []}},
    "keyvault": {"vaults": {"list_by_subscription": []}},
    "containerservice": {"managed_clusters": {"list": []}},
    "resource": {"resources": {"list": [], "get_by_id": None}},
    "authorization": {"role_definitions": {"list": []}, "role_assignments": {"list_for_subscription": []}},
    "web": {"app_service_plans": {"list": []}, "web_apps": {"list": []}},
    "postgresql": {"servers": {"list_by_subscription": []}},
    "mysql": {"servers": {"list": []}},
    "cosmosdb": {"database_accounts": {"list": []}},
    "redis": {"redis": {"list_by_subscription": []}},
}


def with_defaults(clients: dict) -> dict:
    """Fill every client kind / operation group the test did not define with empty listings."""
    for kind, groups in EMPTY_GROUPS.items():
        client = clients.setdefault(kind, NS())
        for group, methods in groups.items():
            if not hasattr(client, group):
                setattr(client, group, ops(**methods))
    return clients
