"""Real Azure posture connector (opt-in, READ-ONLY).

Uses azure-identity + azure-mgmt-* SDKs to inventory resources across one or
more subscriptions and normalizes them into `AssetRecord`s whose properties the
posture rules engine understands.

Safety: every management client is wrapped in `ReadOnlyClient`, which only lets
`list*` / `get*` operations through and raises on anything else (create,
update, delete, begin_*...). The service principal should additionally only
hold the built-in **Reader** role (see README).
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from typing import Any

from ..config import Settings
from .base import AssetRecord, CollectionResult, Connector, RelationshipRecord

log = logging.getLogger(__name__)

# Well-known built-in role definition GUIDs -> names.
BUILTIN_ROLES = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42dd-a8b5-a5a87f9b0f2b": "Contributor",
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "b7e6dc6d-f1e8-4753-8033-0f276bb0955b": "Storage Blob Data Owner",
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe": "Storage Blob Data Contributor",
    "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1": "Storage Blob Data Reader",
    "00482a5a-887f-4fb3-b363-3b7fe8e74483": "Key Vault Administrator",
    "4633458b-17de-408a-b874-0445c86b69e6": "Key Vault Secrets User",
}
DATA_ROLES = {"Owner", "Contributor", "Storage Blob Data Owner", "Storage Blob Data Contributor",
              "Storage Blob Data Reader", "Key Vault Administrator", "Key Vault Secrets User"}
SENSITIVE_TAG_KEYS = {"data_classification", "data-classification", "dataclassification", "classification",
                      "sensitivity", "data"}
NON_SENSITIVE_VALUES = {"public", "none", "non-sensitive", "nonsensitive", "general"}

READ_PREFIXES = ("list", "get")
# Some list*/get* operations are POSTs that return secrets (storage keys, SAS
# tokens, AKS kubeconfigs, publishing profiles...). A posture scanner never
# needs them, so they are blocked even though their names look read-only.
SECRET_MARKERS = ("key", "credential", "secret", "sas", "connection_string", "publishing", "token", "password")


class ReadOnlyViolation(PermissionError):
    pass


class _ReadOnlyOperations:
    """Proxy around an SDK operations group allowing only list*/get* calls."""

    def __init__(self, ops: Any, path: str):
        self._ops = ops
        self._path = path

    def __getattr__(self, name: str) -> Any:
        if not name.startswith(READ_PREFIXES):
            raise ReadOnlyViolation(f"Blocked non read-only Azure call: {self._path}.{name}")
        if any(m in name.lower() for m in SECRET_MARKERS):
            raise ReadOnlyViolation(f"Blocked secret-returning Azure call: {self._path}.{name}")
        return getattr(self._ops, name)


class ReadOnlyClient:
    """Proxy around an azure-mgmt client: attribute access returns guarded operation groups."""

    def __init__(self, client: Any, name: str = "client"):
        self._client = client
        self._name = name

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            # never expose the raw pipeline / send_request escape hatches
            raise AttributeError(f"private Azure client attribute not exposed: {self._name}.{name}")
        if name in {"send_request", "close"}:
            raise ReadOnlyViolation(f"Blocked raw Azure client call: {self._name}.{name}")
        return _ReadOnlyOperations(getattr(self._client, name), f"{self._name}.{name}")


class AzureClientFactory:
    """Builds read-only-wrapped SDK clients per subscription. Swap out in tests."""

    def __init__(self, credential: Any):
        self.credential = credential

    def _make(self, kind: str, sub: str) -> Any:
        if kind == "resource":
            try:
                from azure.mgmt.resource.resources import ResourceManagementClient  # azure-mgmt-resource >= 24
            except ImportError:  # pragma: no cover - older SDK layout
                from azure.mgmt.resource import ResourceManagementClient
            c = ResourceManagementClient(self.credential, sub)
        elif kind == "compute":
            from azure.mgmt.compute import ComputeManagementClient
            c = ComputeManagementClient(self.credential, sub)
        elif kind == "network":
            from azure.mgmt.network import NetworkManagementClient
            c = NetworkManagementClient(self.credential, sub)
        elif kind == "storage":
            from azure.mgmt.storage import StorageManagementClient
            c = StorageManagementClient(self.credential, sub)
        elif kind == "sql":
            from azure.mgmt.sql import SqlManagementClient
            c = SqlManagementClient(self.credential, sub)
        elif kind == "keyvault":
            from azure.mgmt.keyvault import KeyVaultManagementClient
            c = KeyVaultManagementClient(self.credential, sub)
        elif kind == "containerservice":
            from azure.mgmt.containerservice import ContainerServiceClient
            c = ContainerServiceClient(self.credential, sub)
        elif kind == "authorization":
            from azure.mgmt.authorization import AuthorizationManagementClient
            c = AuthorizationManagementClient(self.credential, sub)
        else:
            raise ValueError(kind)
        return ReadOnlyClient(c, kind)

    def __call__(self, kind: str, sub: str) -> Any:
        return self._make(kind, sub)


def build_credential(settings: Settings) -> Any:
    """ClientSecretCredential if a secret is configured, else DefaultAzureCredential (opt-in)."""
    if settings.azure_tenant_id and settings.azure_client_id and settings.azure_client_secret:
        from azure.identity import ClientSecretCredential

        return ClientSecretCredential(settings.azure_tenant_id, settings.azure_client_id, settings.azure_client_secret)
    from azure.identity import DefaultAzureCredential

    return DefaultAzureCredential(exclude_interactive_browser_credential=True)


# ----------------------------------------------------------------------------- helpers
def _g(obj: Any, *path: str, default: Any = None) -> Any:
    """Safe nested getattr (also tolerates dicts)."""
    cur = obj
    for p in path:
        if cur is None:
            return default
        cur = cur.get(p) if isinstance(cur, dict) else getattr(cur, p, None)
    return default if cur is None else cur


def _rg(resource_id: str) -> str | None:
    parts = resource_id.split("/")
    low = [p.lower() for p in parts]
    if "resourcegroups" in low:
        i = low.index("resourcegroups")
        return parts[i + 1] if i + 1 < len(parts) else None
    return None


def _norm_id(rid: str | None) -> str:
    return (rid or "").lower()


def _sensitive_from_tags(tags: dict | None) -> tuple[bool, str | None]:
    for k, v in (tags or {}).items():
        if k.lower() in SENSITIVE_TAG_KEYS and str(v).lower() not in NON_SENSITIVE_VALUES:
            return True, str(v)
    return False, None


def _enabled(v: Any) -> bool:
    return str(v).lower() in {"enabled", "true"}


def _list(it: Iterable | None) -> list:
    return list(it) if it is not None else []


class AzureConnector(Connector):
    name = "azure"
    provider = "azure"
    description = "Read-only Azure posture scan via azure-mgmt SDKs (Reader role)."

    def __init__(self, settings: Settings, client_factory: Callable[[str, str], Any] | None = None):
        self.settings = settings
        self._factory = client_factory

    def is_configured(self) -> bool:
        s = self.settings
        has_secret = bool(s.azure_tenant_id and s.azure_client_id and s.azure_client_secret)
        return bool(s.azure_subscription_ids) and (has_secret or s.azure_use_default_credential
                                                    or self._factory is not None)

    def _client_factory(self) -> Callable[[str, str], Any]:
        if self._factory is None:
            self._factory = AzureClientFactory(build_credential(self.settings))
        return self._factory

    # ------------------------------------------------------------------ main entry
    def collect(self) -> CollectionResult:
        res = CollectionResult()
        factory = self._client_factory()
        for sub in self.settings.azure_subscription_ids:
            try:
                self._collect_subscription(factory, sub, res)
            except Exception as exc:  # keep scanning other subscriptions
                log.exception("Azure scan failed for subscription %s", sub)
                res.errors.append(f"{sub}: {type(exc).__name__}: {exc}")
        return res

    def _step(self, res: CollectionResult, label: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except ReadOnlyViolation:
            raise
        except Exception as exc:
            log.warning("Azure %s failed: %s", label, exc)
            res.errors.append(f"{label}: {type(exc).__name__}: {exc}")

    def _collect_subscription(self, factory, sub: str, res: CollectionResult) -> None:
        sub_asset_id = f"/subscriptions/{sub}".lower()
        sub_name = sub
        base = dict(provider="azure", subscription_id=sub, subscription_name=sub_name)
        assets: dict[str, AssetRecord] = {}
        rels: list[RelationshipRecord] = []
        principal_to_identity: dict[str, str] = {}

        def add(a: AssetRecord) -> AssetRecord:
            assets[a.id] = a
            return a

        sub_asset = add(AssetRecord(id=sub_asset_id, name=sub_name, type="subscription", region="global",
                                    resource_group=None, **base, properties={}))

        # ----------------------------------------------------------- network (needed by VMs)
        pip_by_id: dict[str, str] = {}
        nic_info: dict[str, dict] = {}  # vm id -> {"public_ips": [...], "nsgs": [...]}

        def network():
            net = factory("network", sub)
            for pip in _list(net.public_ip_addresses.list_all()):
                pip_by_id[_norm_id(pip.id)] = _g(pip, "ip_address", default="(dynamic)")
            for nsg in _list(net.network_security_groups.list_all()):
                rules = []
                for r in _list(_g(nsg, "security_rules", default=[])):
                    sources = _list(_g(r, "source_address_prefixes", default=[])) or [_g(r, "source_address_prefix", default="")]
                    ports = _list(_g(r, "destination_port_ranges", default=[])) or [_g(r, "destination_port_range", default="")]
                    rules.append({"name": r.name, "direction": str(_g(r, "direction", default="")),
                                  "access": str(_g(r, "access", default="")), "protocol": str(_g(r, "protocol", default="*")),
                                  "source_prefixes": sources, "port_ranges": ports,
                                  "priority": _g(r, "priority")})
                nid = _norm_id(nsg.id)
                add(AssetRecord(id=nid, name=nsg.name, type="nsg", region=nsg.location, resource_group=_rg(nsg.id),
                                tags=dict(nsg.tags or {}), **base, properties={"security_rules": rules}))
            for nic in _list(net.network_interfaces.list_all()):
                vm_id = _norm_id(_g(nic, "virtual_machine", "id"))
                if not vm_id:
                    continue
                info = nic_info.setdefault(vm_id, {"public_ips": [], "nsgs": []})
                for ipc in _list(_g(nic, "ip_configurations", default=[])):
                    pid = _norm_id(_g(ipc, "public_ip_address", "id"))
                    if pid:
                        info["public_ips"].append(pip_by_id.get(pid, pid.rsplit("/", 1)[-1]))
                nsg_id = _norm_id(_g(nic, "network_security_group", "id"))
                if nsg_id:
                    info["nsgs"].append(nsg_id)

        self._step(res, f"{sub}/network", network)

        # ----------------------------------------------------------- compute
        def compute():
            cm = factory("compute", sub)
            for vm in _list(cm.virtual_machines.list_all()):
                vid = _norm_id(vm.id)
                info = nic_info.get(vid, {"public_ips": [], "nsgs": []})
                os_disk = _g(vm, "storage_profile", "os_disk")
                encrypted = bool(_g(os_disk, "encryption_settings", "enabled")) \
                    or bool(_g(os_disk, "managed_disk", "disk_encryption_set", "id")) \
                    or bool(_g(vm, "security_profile", "encryption_at_host"))
                pips = info["public_ips"]
                add(AssetRecord(
                    id=vid, name=vm.name, type="vm", region=vm.location, resource_group=_rg(vm.id),
                    tags=dict(vm.tags or {}), internet_exposed=bool(pips), **base,
                    properties={"size": _g(vm, "hardware_profile", "vm_size"),
                                "os": str(_g(vm, "storage_profile", "os_disk", "os_type", default="")),
                                "public_ips": pips, "disk_encryption": encrypted,
                                "exposure": f"public IP {', '.join(pips)}" if pips else None}))
                for nsg_id in info["nsgs"]:
                    rels.append(RelationshipRecord(nsg_id, vid, "protects"))
                ident = _g(vm, "identity")
                if ident is not None:
                    pid = _g(ident, "principal_id")
                    if pid:  # system-assigned identity -> synthetic identity asset
                        iid = f"{vid}/identities/system"
                        add(AssetRecord(id=iid, name=f"{vm.name} (system identity)", type="identity",
                                        region=vm.location, resource_group=_rg(vm.id), **base,
                                        properties={"principal_id": pid, "principal_type": "SystemAssigned",
                                                    "roles": [], "scope": "resource"}))
                        principal_to_identity[pid] = iid
                        rels.append(RelationshipRecord(vid, iid, "uses_identity"))
                    for uai_id in (_g(ident, "user_assigned_identities", default={}) or {}).keys():
                        rels.append(RelationshipRecord(vid, _norm_id(uai_id), "uses_identity"))

        self._step(res, f"{sub}/compute", compute)

        # ----------------------------------------------------------- storage
        def storage():
            st = factory("storage", sub)
            for acc in _list(st.storage_accounts.list()):
                sens, cls = _sensitive_from_tags(acc.tags)
                public_blob = bool(_g(acc, "allow_blob_public_access", default=False))
                pna = _g(acc, "public_network_access", default="Enabled")
                default_action = str(_g(acc, "network_rule_set", "default_action", default="Allow"))
                exposed = public_blob and _enabled(pna) and default_action.lower() == "allow"
                add(AssetRecord(
                    id=_norm_id(acc.id), name=acc.name, type="storage_account", region=acc.location,
                    resource_group=_rg(acc.id), tags=dict(acc.tags or {}), internet_exposed=exposed,
                    sensitive_data=sens, **base,
                    properties={"allow_blob_public_access": public_blob,
                                "https_only": _g(acc, "enable_https_traffic_only"),
                                "min_tls_version": str(_g(acc, "minimum_tls_version", default="TLS1_0")),
                                "public_network_access": str(pna), "network_default_action": default_action,
                                "kind": str(_g(acc, "kind", default="")), "data_classification": cls,
                                "exposure": "anonymous blob access allowed" if exposed else None}))

        self._step(res, f"{sub}/storage", storage)

        # ----------------------------------------------------------- SQL
        def sql():
            sq = factory("sql", sub)
            for srv in _list(sq.servers.list()):
                rg = _rg(srv.id)
                fw = []
                try:
                    fw = [{"name": r.name, "start_ip": r.start_ip_address, "end_ip": r.end_ip_address}
                          for r in _list(sq.firewall_rules.list_by_server(rg, srv.name))]
                except Exception as exc:
                    res.errors.append(f"{sub}/sql firewall {srv.name}: {exc}")
                auditing = None
                try:
                    pol = sq.server_blob_auditing_policies.get(rg, srv.name)
                    auditing = _enabled(_g(pol, "state", default="Disabled"))
                except Exception as exc:
                    res.errors.append(f"{sub}/sql auditing {srv.name}: {exc}")
                public = _enabled(_g(srv, "public_network_access", default="Enabled"))
                allow_all = any(r["start_ip"] == "0.0.0.0" and r["end_ip"] == "255.255.255.255" for r in fw)
                _, cls = _sensitive_from_tags(srv.tags)
                sid = _norm_id(srv.id)
                add(AssetRecord(
                    id=sid, name=srv.name, type="sql_server", region=srv.location, resource_group=rg,
                    tags=dict(srv.tags or {}), internet_exposed=public and allow_all,
                    sensitive_data=True,  # databases are treated as sensitive by default
                    **base, properties={"public_network_access": public, "auditing_enabled": auditing,
                                        "firewall_rules": fw, "data_classification": cls or "database",
                                        "exposure": "firewall allows 0.0.0.0-255.255.255.255" if allow_all else None}))
                try:
                    for d in _list(sq.databases.list_by_server(rg, srv.name)):
                        if d.name == "master":
                            continue
                        did = _norm_id(d.id)
                        add(AssetRecord(id=did, name=d.name, type="sql_database", region=d.location,
                                        resource_group=rg, tags=dict(d.tags or {}), sensitive_data=True, **base,
                                        properties={"sku": _g(d, "sku", "name"), "data_classification": cls or "database"}))
                        rels.append(RelationshipRecord(sid, did, "contains"))
                except Exception as exc:
                    res.errors.append(f"{sub}/sql databases {srv.name}: {exc}")

        self._step(res, f"{sub}/sql", sql)

        # ----------------------------------------------------------- Key Vault
        def keyvault():
            kv = factory("keyvault", sub)
            for v in _list(kv.vaults.list_by_subscription()):
                props = _g(v, "properties")
                soft = _g(props, "enable_soft_delete")
                add(AssetRecord(
                    id=_norm_id(v.id), name=v.name, type="key_vault", region=v.location, resource_group=_rg(v.id),
                    tags=dict(v.tags or {}), sensitive_data=True, **base,
                    properties={"soft_delete": True if soft is None else bool(soft),  # default on since 2020
                                "purge_protection": bool(_g(props, "enable_purge_protection", default=False)),
                                "public_network_access": str(_g(props, "public_network_access", default="Enabled")),
                                "data_classification": "secrets & keys"}))

        self._step(res, f"{sub}/keyvault", keyvault)

        # ----------------------------------------------------------- AKS
        def aks():
            cs = factory("containerservice", sub)
            for mc in _list(cs.managed_clusters.list()):
                api = _g(mc, "api_server_access_profile")
                private = bool(_g(api, "enable_private_cluster", default=False))
                ranges = _list(_g(api, "authorized_ip_ranges", default=[]))
                add(AssetRecord(
                    id=_norm_id(mc.id), name=mc.name, type="aks_cluster", region=mc.location, resource_group=_rg(mc.id),
                    tags=dict(mc.tags or {}), internet_exposed=not private and not ranges, **base,
                    properties={"kubernetes_version": _g(mc, "kubernetes_version"),
                                "rbac_enabled": bool(_g(mc, "enable_rbac", default=False)),
                                "private_cluster": private, "authorized_ip_ranges": ranges,
                                "aad_enabled": _g(mc, "aad_profile") is not None,
                                "node_count": sum(int(_g(p, "count", default=0) or 0)
                                                  for p in _list(_g(mc, "agent_pool_profiles", default=[]))),
                                "exposure": "public API server" if not private and not ranges else None}))

        self._step(res, f"{sub}/aks", aks)

        # ----------------------------------------------------------- generic: functions + managed identities
        def generic():
            rm = factory("resource", sub)
            for r in _list(rm.resources.list()):
                rtype = str(r.type or "").lower()
                kind = str(_g(r, "kind", default="")).lower()
                rid = _norm_id(r.id)
                if rtype == "microsoft.web/sites" and "functionapp" in kind:
                    https_only = None
                    try:
                        full = rm.resources.get_by_id(r.id, api_version="2023-01-01")
                        https_only = _g(full, "properties", "httpsOnly")
                    except ReadOnlyViolation:
                        raise
                    except Exception as exc:  # noqa: BLE001 - optional enrichment
                        log.debug("function app detail for %s unavailable: %s", r.id, exc)
                    add(AssetRecord(id=rid, name=r.name, type="function_app", region=r.location,
                                    resource_group=_rg(r.id), tags=dict(r.tags or {}), internet_exposed=True, **base,
                                    properties={"kind": kind, "https_only": https_only,
                                                "exposure": f"https://{r.name}.azurewebsites.net"}))
                elif rtype == "microsoft.managedidentity/userassignedidentities":
                    principal = None
                    try:
                        full = rm.resources.get_by_id(r.id, api_version="2023-01-31")
                        principal = _g(full, "properties", "principalId")
                    except ReadOnlyViolation:
                        raise
                    except Exception as exc:  # noqa: BLE001 - optional enrichment
                        log.debug("identity detail for %s unavailable: %s", r.id, exc)
                    add(AssetRecord(id=rid, name=r.name, type="identity", region=r.location,
                                    resource_group=_rg(r.id), tags=dict(r.tags or {}), **base,
                                    properties={"principal_id": principal, "principal_type": "UserAssigned",
                                                "roles": [], "scope": "resource"}))
                    if principal:
                        principal_to_identity[principal] = rid

        self._step(res, f"{sub}/resources", generic)

        # ----------------------------------------------------------- RBAC
        def rbac():
            az = factory("authorization", sub)
            owners = contributors = 0
            for ra in _list(az.role_assignments.list_for_subscription()):
                rd = _g(ra, "role_definition_id") or _g(ra, "properties", "role_definition_id") or ""
                role = BUILTIN_ROLES.get(rd.rsplit("/", 1)[-1].lower(), f"custom:{rd.rsplit('/', 1)[-1]}")
                scope = _norm_id(_g(ra, "scope") or _g(ra, "properties", "scope") or "")
                principal = _g(ra, "principal_id") or _g(ra, "properties", "principal_id")
                at_sub = scope == sub_asset_id
                if at_sub and role == "Owner":
                    owners += 1
                elif at_sub and role == "Contributor":
                    contributors += 1
                iid = principal_to_identity.get(principal)
                if not iid or iid not in assets:
                    continue
                ident = assets[iid]
                ident.properties["roles"] = sorted(set(ident.properties.get("roles", [])) | {role})
                if at_sub:
                    ident.properties["scope"] = "subscription"
                if role not in DATA_ROLES:
                    continue
                for a in list(assets.values()):
                    if a.type in {"storage_account", "sql_server", "key_vault"} and (
                            a.id == scope or a.id.startswith(scope + "/")):
                        rels.append(RelationshipRecord(iid, a.id, "has_access", {"role": role}))
            sub_asset.properties.update({"owner_count": owners, "contributor_count": contributors})

        self._step(res, f"{sub}/rbac", rbac)

        res.assets.extend(assets.values())
        # drop edges to unknown nodes (e.g. NSG on another subscription)
        res.relationships.extend(r for r in rels if r.source_id in assets and r.target_id in assets)
