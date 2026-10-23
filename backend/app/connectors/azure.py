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
import re
from collections.abc import Callable, Iterable
from enum import Enum
from typing import Any

from ..config import Settings
from .base import AssetRecord, CollectionResult, Connector, RelationshipRecord
from .base import sensitive_from_tags as _sensitive_from_tags

log = logging.getLogger(__name__)

# Well-known built-in role definition GUIDs -> names. Fallback only: the scan resolves
# role names (built-in and custom) with `role_definitions.list` when it can.
BUILTIN_ROLES = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42dd-a8b5-a5a87f9b0f2b": "Contributor",
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
    "b7e6dc6d-f1e8-4753-8033-0f276bb0955b": "Storage Blob Data Owner",
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe": "Storage Blob Data Contributor",
    "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1": "Storage Blob Data Reader",
    "17d1049b-9a84-46fb-8f53-869881c3d3ab": "Storage Account Contributor",
    "00482a5a-887f-4fb3-b363-3b7fe8e74483": "Key Vault Administrator",
    "4633458b-17de-408a-b874-0445c86b69e6": "Key Vault Secrets User",
    "b86a8fe4-44ce-4948-aee5-eccb2c155cd7": "Key Vault Secrets Officer",
    "14b46e9e-c2b7-41e4-8b14-b9d0b8af6a66": "Key Vault Crypto Officer",
    "12338af0-0e69-4776-bea7-57ae8d297424": "Key Vault Crypto User",
    "21090545-7ca7-4776-b22c-e363652d74d2": "Key Vault Reader",
    "f25e0fa2-a7c8-4377-a976-54943a77a395": "Key Vault Contributor",
    "9b7fa17d-e63e-47b0-bb0a-15c516ac86ec": "SQL DB Contributor",
    "6d8ee4ec-f05a-4a1d-8b00-a9b17e38b437": "SQL Server Contributor",
    "056cd41c-7e88-42e1-933e-88ba6a50c9c3": "SQL Security Manager",
}
DATA_STORE_TYPES = {"storage_account", "sql_server", "key_vault"}
# Roles that give (or let the holder give itself) access to data, and the store types they apply to.
# Owner / Contributor can read storage keys, change SQL firewall/admins and vault access policies.
BROAD_DATA_ROLES = {"Owner", "Contributor"}
NON_DATA_ROLES = {"Key Vault Reader", "Storage Blob Delegator"}
# Key Vault access-policy permissions that expose secret / key / certificate material.
KV_DATA_PERMISSIONS = {"get", "all", "decrypt", "unwrapkey", "sign", "export"}
# Fan-out cap: an identity granted a data role at resource-group / subscription scope gets
# has_access edges to at most this many stores per assignment (sensitive stores first); the
# rest is counted in the identity's `data_access_truncated` property.
MAX_ACCESS_EDGES_PER_GRANT = 50
SCOPE_RANK = {"resource": 0, "resource_group": 1, "subscription": 2}


def data_targets(role: str) -> set[str]:
    """Data store types a role grants data-plane (or self-grantable) access to; empty if none."""
    if role in BROAD_DATA_ROLES:
        return set(DATA_STORE_TYPES)
    if role in NON_DATA_ROLES:
        return set()
    r = role.lower()
    if r.startswith("storage ") and (" data " in f"{r} " or r == "storage account contributor"):
        return {"storage_account"}
    if r == "reader and data access":
        return {"storage_account"}
    if r.startswith("key vault "):
        return {"key_vault"}
    if r.startswith("sql "):
        return {"sql_server"}
    return set()  # custom roles are not interpreted (their actions are not fetched)


def _scope_kind(scope: str, sub_id: str) -> str:
    """resource | resource_group | subscription (management-group / root scopes count as subscription)."""
    if scope in ("", "/", sub_id) or scope.startswith("/providers/microsoft.management/managementgroups/"):
        return "subscription"
    if re.fullmatch(re.escape(sub_id) + r"/resourcegroups/[^/]+", scope):
        return "resource_group"
    return "resource"


def _in_scope(asset_id: str, scope: str, kind: str) -> bool:
    return kind == "subscription" or asset_id == scope or asset_id.startswith(scope + "/")


def _vmss_from_id(rid: str) -> str | None:
    """Scale set id from any id below it (instance NIC IP configurations...)."""
    m = re.match(r"(.*?/providers/microsoft\.compute/virtualmachinescalesets/[^/]+)", rid.lower())
    return m.group(1) if m else None


def _ports(values: Iterable[Any]) -> set[int]:
    """Backend ports as ints; 0 (HA ports) expands to the risky ports the attack-path engine checks."""
    out: set[int] = set()
    for v in values:
        if isinstance(v, int) and v > 0:
            out.add(v)
        elif v == 0:
            from ..engine.attack_paths import EXPOSURE_PORTS  # local: keeps the connector import-light

            out |= {p for p, _ in EXPOSURE_PORTS if p is not None}
    return out


def _dedupe(rels: Iterable[RelationshipRecord]) -> list[RelationshipRecord]:
    """One edge per (source, target, type); differing `role`s are folded into `roles`, levels are merged."""
    out: dict[tuple[str, str, str], RelationshipRecord] = {}
    for r in rels:
        key = (r.source_id, r.target_id, r.type)
        if key not in out:
            out[key] = RelationshipRecord(r.source_id, r.target_id, r.type, dict(r.properties or {}))
            continue
        props = out[key].properties
        for k, v in (r.properties or {}).items():
            if k == "role" and props.get("role") not in (None, v):
                props["roles"] = sorted(set(props.get("roles") or [props["role"]]) | {v})
            elif k == "levels":
                props["levels"] = sorted(set(props.get("levels") or []) | set(v))
            else:
                props.setdefault(k, v)
    return list(out.values())


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


AUTH_MODES = ("auto", "client_secret", "managed_identity", "default")


def resolve_auth_mode(settings: Settings) -> str | None:
    """Which credential the scanner will use, or None if none is configured.

    auto: client secret (local / outside Azure) if all three AZURE_TENANT_ID,
    AZURE_CLIENT_ID and AZURE_CLIENT_SECRET are set; else managed identity if
    AZURE_MANAGED_IDENTITY_CLIENT_ID is set (Container Apps); else
    DefaultAzureCredential if AZURE_USE_DEFAULT_CREDENTIAL=true.
    """
    s = settings
    mode = s.azure_auth_mode if s.azure_auth_mode in AUTH_MODES else "auto"
    has_secret = bool(s.azure_tenant_id and s.azure_client_id and s.azure_client_secret)
    if mode == "client_secret":
        return mode if has_secret else None
    if mode in ("managed_identity", "default"):
        return mode
    if has_secret:
        return "client_secret"
    if s.azure_managed_identity_client_id:
        return "managed_identity"
    if s.azure_use_default_credential:
        return "default"
    return None


def build_credential(settings: Settings) -> Any:
    """Credential for the configured auth mode (see `resolve_auth_mode`).

    Deployed on Azure (Container Apps), the scanner authenticates with the
    app's managed identity: no secret exists anywhere. Grant that identity the
    built-in Reader role on each subscription to scan.
    """
    mode = resolve_auth_mode(settings)
    if mode == "client_secret":
        from azure.identity import ClientSecretCredential

        return ClientSecretCredential(settings.azure_tenant_id, settings.azure_client_id, settings.azure_client_secret)
    if mode == "managed_identity":
        from azure.identity import ManagedIdentityCredential

        if settings.azure_managed_identity_client_id:
            return ManagedIdentityCredential(client_id=settings.azure_managed_identity_client_id)
        return ManagedIdentityCredential()  # system-assigned
    if mode == "default":
        from azure.identity import DefaultAzureCredential

        return DefaultAzureCredential(exclude_interactive_browser_credential=True,
                                      managed_identity_client_id=settings.azure_managed_identity_client_id)
    raise RuntimeError("Azure connector is not configured: set AZURE_SUBSCRIPTION_IDS and a credential "
                       "(managed identity, client secret or AZURE_USE_DEFAULT_CREDENTIAL)")


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


def _s(v: Any, default: str = "") -> str:
    """String value of an SDK field. Newer azure-mgmt models return `str` enums whose
    `str()` is "EnumName.MEMBER", so use the enum's value."""
    if v is None:
        return default
    return str(v.value) if isinstance(v, Enum) else str(v)


def _enabled(v: Any) -> bool:
    return _s(v).lower() in {"enabled", "true"}


def _list(it: Iterable | None) -> list:
    return list(it) if it is not None else []


class AzureConnector(Connector):
    name = "azure"
    provider = "azure"
    description = "Read-only Azure posture scan via azure-mgmt SDKs (Reader role)."
    setup_hint = ("set AZURE_SUBSCRIPTION_IDS and a credential: the managed identity "
                  "(AZURE_MANAGED_IDENTITY_CLIENT_ID) when deployed on Azure, or "
                  "AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET locally")

    def __init__(self, settings: Settings, client_factory: Callable[[str, str], Any] | None = None):
        self.settings = settings
        self._factory = client_factory

    def is_configured(self) -> bool:
        s = self.settings
        return bool(s.azure_subscription_ids) and (resolve_auth_mode(s) is not None or self._factory is not None)

    def scope(self) -> list[str]:
        return list(self.settings.azure_subscription_ids)

    def info(self) -> dict:
        return {**super().info(), "auth_mode": resolve_auth_mode(self.settings)}

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

        def identities(owner_id: str, owner_name: str, ident: Any, location: str | None) -> None:
            """uses_identity edges from a workload to its system- and user-assigned identities."""
            if ident is None:
                return
            pid = _g(ident, "principal_id")
            if pid:  # system-assigned identity -> synthetic identity asset
                iid = f"{owner_id}/identities/system"
                add(AssetRecord(id=iid, name=f"{owner_name} (system identity)", type="identity",
                                region=location, resource_group=_rg(owner_id), **base,
                                properties={"principal_id": pid, "principal_type": "SystemAssigned",
                                            "roles": [], "scope": "resource"}))
                principal_to_identity[pid] = iid
                rels.append(RelationshipRecord(owner_id, iid, "uses_identity"))
            for uai_id, val in (_g(ident, "user_assigned_identities", default={}) or {}).items():
                uid = _norm_id(uai_id)
                rels.append(RelationshipRecord(owner_id, uid, "uses_identity"))
                upid = _g(val, "principal_id")
                if upid:  # lets RBAC resolve the identity even if its own lookup fails
                    principal_to_identity.setdefault(upid, uid)

        # ----------------------------------------------------------- network (needed by VMs / scale sets)
        pip_by_id: dict[str, str] = {}
        subnet_nsg: dict[str, str] = {}  # subnet id -> NSG id
        nic_vm: dict[str, str] = {}  # NIC id -> VM id
        # vm id -> {"public_ips": [...], "nsgs": {nsg id: {"nic", "subnet"}}}
        nic_info: dict[str, dict] = {}
        # LB / App Gateway backend or NAT pool id -> (exposure text, backend ports forwarded from the internet)
        public_pools: dict[str, tuple[str, set[int]]] = {}
        net_exposure: dict[str, list[str]] = {}  # VM / scale set id -> exposure texts (LB / App Gateway)
        net_ports: dict[str, set[int]] = {}  # VM / scale set id -> backend ports forwarded by public LBs

        def owner_of_ipconfig(ipc_id: str | None) -> str | None:
            """VM (via its NIC) or scale set behind a NIC IP configuration id."""
            rid = _norm_id(ipc_id)
            vmss = _vmss_from_id(rid)
            if vmss:
                return vmss
            return nic_vm.get(rid.split("/ipconfigurations/")[0])

        def expose(target: str | None, text: str, ports: Iterable[int] = ()) -> None:
            if not target:
                return
            if text not in net_exposure.setdefault(target, []):
                net_exposure[target].append(text)
            net_ports.setdefault(target, set()).update(p for p in ports if isinstance(p, int))

        def network():
            net = factory("network", sub)
            for pip in _list(net.public_ip_addresses.list_all()):
                pip_by_id[_norm_id(pip.id)] = _g(pip, "ip_address", default="(dynamic)")
            for nsg in _list(net.network_security_groups.list_all()):
                rules = []
                for r in _list(_g(nsg, "security_rules", default=[])):
                    sources = _list(_g(r, "source_address_prefixes", default=[])) or [_g(r, "source_address_prefix", default="")]
                    ports = _list(_g(r, "destination_port_ranges", default=[])) or [_g(r, "destination_port_range", default="")]
                    rules.append({"name": r.name, "direction": _s(_g(r, "direction", default="")),
                                  "access": _s(_g(r, "access", default="")), "protocol": _s(_g(r, "protocol", default="*")),
                                  "source_prefixes": sources, "port_ranges": ports,
                                  "priority": _g(r, "priority")})
                nid = _norm_id(nsg.id)
                add(AssetRecord(id=nid, name=nsg.name, type="nsg", region=nsg.location, resource_group=_rg(nsg.id),
                                tags=dict(nsg.tags or {}), **base, properties={"security_rules": rules}))

            def subnets():
                for vnet in _list(net.virtual_networks.list_all()):
                    for sn in _list(_g(vnet, "subnets", default=[])):
                        nsg_id = _norm_id(_g(sn, "network_security_group", "id"))
                        if nsg_id:
                            subnet_nsg[_norm_id(sn.id)] = nsg_id

            self._step(res, f"{sub}/network/subnets", subnets)

            for nic in _list(net.network_interfaces.list_all()):
                vm_id = _norm_id(_g(nic, "virtual_machine", "id"))
                if not vm_id:
                    continue
                nic_vm[_norm_id(_g(nic, "id"))] = vm_id
                info = nic_info.setdefault(vm_id, {"public_ips": [], "nsgs": {}})
                for ipc in _list(_g(nic, "ip_configurations", default=[])):
                    pid = _norm_id(_g(ipc, "public_ip_address", "id"))
                    if pid:
                        info["public_ips"].append(pip_by_id.get(pid, pid.rsplit("/", 1)[-1]))
                    sn_nsg = subnet_nsg.get(_norm_id(_g(ipc, "subnet", "id")))
                    if sn_nsg:
                        info["nsgs"].setdefault(sn_nsg, set()).add("subnet")
                nsg_id = _norm_id(_g(nic, "network_security_group", "id"))
                if nsg_id:
                    info["nsgs"].setdefault(nsg_id, set()).add("nic")

            def load_balancers():
                for lb in _list(net.load_balancers.list_all()):
                    fes = {_norm_id(fe.id): pip_by_id.get(_norm_id(_g(fe, "public_ip_address", "id")), "public IP")
                           for fe in _list(_g(lb, "frontend_ip_configurations", default=[]))
                           if _g(fe, "public_ip_address", "id")}
                    if not fes:
                        continue  # internal load balancer
                    ips = ", ".join(sorted(set(fes.values())))
                    pool_ports: dict[str, tuple[set, set]] = {}  # pool -> (frontend ports, backend ports)
                    for rule in _list(_g(lb, "load_balancing_rules", default=[])):
                        if _norm_id(_g(rule, "frontend_ip_configuration", "id")) not in fes:
                            continue
                        pools = [_g(rule, "backend_address_pool", "id")]
                        pools += [_g(p, "id") for p in _list(_g(rule, "backend_address_pools", default=[]))]
                        for pool in filter(None, pools):
                            fe_ports, be_ports = pool_ports.setdefault(_norm_id(pool), (set(), set()))
                            fe_ports.add(_g(rule, "frontend_port"))
                            # backend port 0 = HA ports (all ports)
                            be_ports.add(_g(rule, "backend_port", default=_g(rule, "frontend_port")))
                    for pool_id, (fe_ports, be_ports) in pool_ports.items():
                        plist = ", ".join(str(p) for p in sorted(p for p in fe_ports if p))
                        public_pools[pool_id] = (f"public load balancer {lb.name} ({ips})"
                                                 + (f" port {plist}" if plist else ""), _ports(be_ports))
                    for pool in _list(_g(lb, "backend_address_pools", default=[])):
                        hit = public_pools.get(_norm_id(pool.id))
                        if hit:
                            for ipc in _list(_g(pool, "backend_ip_configurations", default=[])):
                                expose(owner_of_ipconfig(_g(ipc, "id")), *hit)
                    for nat in _list(_g(lb, "inbound_nat_rules", default=[])):
                        if _norm_id(_g(nat, "frontend_ip_configuration", "id")) in fes:
                            expose(owner_of_ipconfig(_g(nat, "backend_ip_configuration", "id")),
                                   f"public load balancer {lb.name} ({ips}) NAT port {_g(nat, 'frontend_port')}",
                                   _ports({_g(nat, "backend_port")}))
                    for np_ in _list(_g(lb, "inbound_nat_pools", default=[])):  # classic VMSS NAT pools
                        if _norm_id(_g(np_, "frontend_ip_configuration", "id")) in fes:
                            public_pools[_norm_id(np_.id)] = (
                                f"public load balancer {lb.name} ({ips}) NAT ports "
                                f"{_g(np_, 'frontend_port_range_start')}-{_g(np_, 'frontend_port_range_end')}",
                                _ports({_g(np_, "backend_port")}))

            self._step(res, f"{sub}/network/load-balancers", load_balancers)

            def app_gateways():
                for gw in _list(net.application_gateways.list_all()):
                    ips = sorted({pip_by_id.get(_norm_id(_g(fe, "public_ip_address", "id")), "public IP")
                                  for fe in _list(_g(gw, "frontend_ip_configurations", default=[]))
                                  if _g(fe, "public_ip_address", "id")})
                    if not ips:
                        continue
                    # HTTP(S) only reaches the backends: no admin / database port is forwarded
                    text = f"public application gateway {gw.name} ({', '.join(ips)})"
                    for pool in _list(_g(gw, "backend_address_pools", default=[])):
                        public_pools[_norm_id(pool.id)] = (text, set())
                        for ipc in _list(_g(pool, "backend_ip_configurations", default=[])):
                            expose(owner_of_ipconfig(_g(ipc, "id")), text)

            self._step(res, f"{sub}/network/app-gateways", app_gateways)

        self._step(res, f"{sub}/network", network)

        def protects(nsgs: dict[str, set], target: str) -> None:
            for nsg_id, levels in nsgs.items():
                rels.append(RelationshipRecord(nsg_id, target, "protects", {"levels": sorted(levels)}))

        # ----------------------------------------------------------- compute
        def compute():
            cm = factory("compute", sub)
            for vm in _list(cm.virtual_machines.list_all()):
                vid = _norm_id(vm.id)
                info = nic_info.get(vid, {"public_ips": [], "nsgs": {}})
                os_disk = _g(vm, "storage_profile", "os_disk")
                encrypted = bool(_g(os_disk, "encryption_settings", "enabled")) \
                    or bool(_g(os_disk, "managed_disk", "disk_encryption_set", "id")) \
                    or bool(_g(vm, "security_profile", "encryption_at_host"))
                pips = info["public_ips"]
                exposures = ([f"public IP {', '.join(pips)}"] if pips else []) + net_exposure.get(vid, [])
                add(AssetRecord(
                    id=vid, name=vm.name, type="vm", region=vm.location, resource_group=_rg(vm.id),
                    tags=dict(vm.tags or {}), internet_exposed=bool(exposures), **base,
                    properties={"size": _g(vm, "hardware_profile", "vm_size"),
                                "os": _s(_g(vm, "storage_profile", "os_disk", "os_type", default="")),
                                "public_ips": pips, "disk_encryption": encrypted,
                                "forwarded_ports": sorted(net_ports.get(vid, ())),
                                "exposure": "; ".join(exposures) or None}))
                protects(info["nsgs"], vid)
                identities(vid, vm.name, _g(vm, "identity"), vm.location)

        self._step(res, f"{sub}/compute", compute)

        def scale_sets():
            cm = factory("compute", sub)
            for ss in _list(cm.virtual_machine_scale_sets.list_all()):
                sid = _norm_id(ss.id)
                prof = _g(ss, "virtual_machine_profile")
                nsgs: dict[str, set] = {}
                exposures: list[str] = []
                forwarded: set[int] = set(net_ports.get(sid, ()))
                per_instance_pip = False
                for nc in _list(_g(prof, "network_profile", "network_interface_configurations", default=[])):
                    nsg_id = _norm_id(_g(nc, "network_security_group", "id"))
                    if nsg_id:
                        nsgs.setdefault(nsg_id, set()).add("nic")
                    for ipc in _list(_g(nc, "ip_configurations", default=[])):
                        sn_nsg = subnet_nsg.get(_norm_id(_g(ipc, "subnet", "id")))
                        if sn_nsg:
                            nsgs.setdefault(sn_nsg, set()).add("subnet")
                        if _g(ipc, "public_ip_address_configuration") is not None:
                            per_instance_pip = True
                        for attr in ("load_balancer_backend_address_pools", "application_gateway_backend_address_pools",
                                     "load_balancer_inbound_nat_pools"):
                            for pool in _list(_g(ipc, attr, default=[])):
                                hit = public_pools.get(_norm_id(_g(pool, "id")))
                                if hit:
                                    forwarded |= hit[1]
                                    if hit[0] not in exposures:
                                        exposures.append(hit[0])
                exposures = (["public IP per instance"] if per_instance_pip else []) + exposures
                exposures += [e for e in net_exposure.get(sid, []) if e not in exposures]
                os_disk = _g(prof, "storage_profile", "os_disk")
                encrypted = bool(_g(os_disk, "managed_disk", "disk_encryption_set", "id")) \
                    or bool(_g(prof, "security_profile", "encryption_at_host"))
                add(AssetRecord(
                    id=sid, name=ss.name, type="vmss", region=ss.location, resource_group=_rg(ss.id),
                    tags=dict(ss.tags or {}), internet_exposed=bool(exposures), **base,
                    properties={"size": _g(ss, "sku", "name"), "capacity": _g(ss, "sku", "capacity"),
                                "os": _s(_g(os_disk, "os_type", default="")),
                                "orchestration_mode": _s(_g(ss, "orchestration_mode", default="")) or None,
                                "per_instance_public_ip": per_instance_pip, "disk_encryption": encrypted,
                                "public_ips": [], "forwarded_ports": sorted(forwarded),
                                "exposure": "; ".join(exposures) or None}))
                protects(nsgs, sid)
                identities(sid, ss.name, _g(ss, "identity"), ss.location)

        self._step(res, f"{sub}/compute/scale-sets", scale_sets)

        # ----------------------------------------------------------- storage
        def storage():
            st = factory("storage", sub)
            for acc in _list(st.storage_accounts.list()):
                sens, cls = _sensitive_from_tags(acc.tags)
                public_blob = bool(_g(acc, "allow_blob_public_access", default=False))
                pna = _g(acc, "public_network_access", default="Enabled")
                default_action = _s(_g(acc, "network_rule_set", "default_action", default="Allow"))
                exposed = public_blob and _enabled(pna) and default_action.lower() == "allow"
                add(AssetRecord(
                    id=_norm_id(acc.id), name=acc.name, type="storage_account", region=acc.location,
                    resource_group=_rg(acc.id), tags=dict(acc.tags or {}), internet_exposed=exposed,
                    sensitive_data=sens, **base,
                    properties={"allow_blob_public_access": public_blob,
                                "https_only": _g(acc, "enable_https_traffic_only"),
                                "min_tls_version": _s(_g(acc, "minimum_tls_version", default="TLS1_0")),
                                "public_network_access": _s(pna), "network_default_action": default_action,
                                "kind": _s(_g(acc, "kind", default="")), "data_classification": cls,
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
        kv_policies: list[tuple[str, str, str]] = []  # (vault id, principal object id, permission summary)

        def keyvault():
            kv = factory("keyvault", sub)
            for v in _list(kv.vaults.list_by_subscription()):
                props = _g(v, "properties")
                soft = _g(props, "enable_soft_delete")
                rbac_mode = bool(_g(props, "enable_rbac_authorization", default=False))
                vid = _norm_id(v.id)
                add(AssetRecord(
                    id=vid, name=v.name, type="key_vault", region=v.location, resource_group=_rg(v.id),
                    tags=dict(v.tags or {}), sensitive_data=True, **base,
                    properties={"soft_delete": True if soft is None else bool(soft),  # default on since 2020
                                "purge_protection": bool(_g(props, "enable_purge_protection", default=False)),
                                "public_network_access": _s(_g(props, "public_network_access", default="Enabled")),
                                "rbac_authorization": rbac_mode,
                                "data_classification": "secrets & keys"}))
                if rbac_mode:
                    continue  # access policies are ignored by RBAC-mode vaults
                for ap in _list(_g(props, "access_policies", default=[])):
                    oid = _g(ap, "object_id")
                    granted = []
                    for kind in ("secrets", "keys", "certificates"):
                        perms = sorted({_s(p).lower() for p in _list(_g(ap, "permissions", kind, default=[]))})
                        if set(perms) & KV_DATA_PERMISSIONS:
                            granted.append(f"{kind}: {', '.join(perms)}")
                    if oid and granted:
                        kv_policies.append((vid, oid, "; ".join(granted)))

        self._step(res, f"{sub}/keyvault", keyvault)

        # ----------------------------------------------------------- AKS
        def aks():
            cs = factory("containerservice", sub)
            for mc in _list(cs.managed_clusters.list()):
                api = _g(mc, "api_server_access_profile")
                private = bool(_g(api, "enable_private_cluster", default=False))
                ranges = _list(_g(api, "authorized_ip_ranges", default=[]))
                cid = _norm_id(mc.id)
                add(AssetRecord(
                    id=cid, name=mc.name, type="aks_cluster", region=mc.location, resource_group=_rg(mc.id),
                    tags=dict(mc.tags or {}), internet_exposed=not private and not ranges, **base,
                    properties={"kubernetes_version": _g(mc, "kubernetes_version"),
                                "rbac_enabled": bool(_g(mc, "enable_rbac", default=False)),
                                "private_cluster": private, "authorized_ip_ranges": ranges,
                                "aad_enabled": _g(mc, "aad_profile") is not None,
                                "node_count": sum(int(_g(p, "count", default=0) or 0)
                                                  for p in _list(_g(mc, "agent_pool_profiles", default=[]))),
                                "exposure": "public API server" if not private and not ranges else None}))
                identities(cid, mc.name, _g(mc, "identity"), mc.location)
                # The kubelet identity is what code on the nodes (pods) can obtain tokens for.
                kubelet = (_g(mc, "identity_profile", default={}) or {}).get("kubeletidentity")
                kid = _norm_id(_g(kubelet, "resource_id"))
                if kid:
                    rels.append(RelationshipRecord(cid, kid, "uses_identity", {"via": "kubelet"}))
                    if _g(kubelet, "object_id"):
                        principal_to_identity.setdefault(_g(kubelet, "object_id"), kid)

        self._step(res, f"{sub}/aks", aks)

        # ----------------------------------------------------------- generic: functions + managed identities
        def generic():
            rm = factory("resource", sub)
            for r in _list(rm.resources.list()):
                rtype = str(r.type or "").lower()
                kind = _s(_g(r, "kind", default="")).lower()
                rid = _norm_id(r.id)
                if rtype == "microsoft.web/sites" and "functionapp" in kind:
                    https_only = None
                    ident = _g(r, "identity")
                    try:
                        full = rm.resources.get_by_id(r.id, api_version="2023-01-01")
                        https_only = _g(full, "properties", "httpsOnly")
                        ident = ident or _g(full, "identity")
                    except ReadOnlyViolation:
                        raise
                    except Exception as exc:  # noqa: BLE001 - optional enrichment
                        log.debug("function app detail for %s unavailable: %s", r.id, exc)
                    add(AssetRecord(id=rid, name=r.name, type="function_app", region=r.location,
                                    resource_group=_rg(r.id), tags=dict(r.tags or {}), internet_exposed=True, **base,
                                    properties={"kind": kind, "https_only": https_only,
                                                "exposure": f"https://{r.name}.azurewebsites.net"}))
                    identities(rid, r.name, ident, r.location)
                elif rtype == "microsoft.managedidentity/userassignedidentities":
                    principal = None
                    try:
                        full = rm.resources.get_by_id(r.id, api_version="2023-01-31")
                        principal = _g(full, "properties", "principalId")
                    except ReadOnlyViolation:
                        raise
                    except Exception as exc:  # noqa: BLE001 - optional enrichment
                        log.debug("identity detail for %s unavailable: %s", r.id, exc)
                    if not principal:  # learned from a workload's identity block
                        principal = next((p for p, i in principal_to_identity.items() if i == rid), None)
                    add(AssetRecord(id=rid, name=r.name, type="identity", region=r.location,
                                    resource_group=_rg(r.id), tags=dict(r.tags or {}), **base,
                                    properties={"principal_id": principal, "principal_type": "UserAssigned",
                                                "roles": [], "scope": "resource"}))
                    if principal:
                        principal_to_identity[principal] = rid

        self._step(res, f"{sub}/resources", generic)

        # ----------------------------------------------------------- RBAC
        def grant(iid: str, store_ids: list[str], props: dict) -> None:
            """has_access edges, sensitive stores first, capped per grant (see MAX_ACCESS_EDGES_PER_GRANT)."""
            ordered = sorted(store_ids, key=lambda i: (not assets[i].sensitive_data, i))
            for target in ordered[:MAX_ACCESS_EDGES_PER_GRANT]:
                rels.append(RelationshipRecord(iid, target, "has_access", dict(props)))
            dropped = len(ordered) - MAX_ACCESS_EDGES_PER_GRANT
            if dropped > 0:
                ident = assets[iid]
                ident.properties["data_access_truncated"] = ident.properties.get("data_access_truncated", 0) + dropped

        def rbac():
            az = factory("authorization", sub)
            role_names = dict(BUILTIN_ROLES)
            try:  # resolves every built-in and custom role name; the static map is the fallback
                for rd in _list(az.role_definitions.list(sub_asset_id)):
                    if _g(rd, "name") and _g(rd, "role_name"):
                        role_names[str(rd.name).lower()] = str(rd.role_name)
            except ReadOnlyViolation:
                raise
            except Exception as exc:  # noqa: BLE001 - optional enrichment
                log.debug("role definitions for %s unavailable: %s", sub, exc)
            owners = contributors = 0
            for ra in _list(az.role_assignments.list_for_subscription()):
                rd = _g(ra, "role_definition_id") or _g(ra, "properties", "role_definition_id") or ""
                guid = rd.rsplit("/", 1)[-1].lower()
                role = role_names.get(guid, f"custom:{guid}")
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
                kind = _scope_kind(scope, sub_asset_id)
                ident.properties["roles"] = sorted(set(ident.properties.get("roles", [])) | {role})
                if SCOPE_RANK[kind] > SCOPE_RANK.get(ident.properties.get("scope", "resource"), 0):
                    ident.properties["scope"] = kind
                targets = data_targets(role)
                if not targets:
                    continue
                stores = [a.id for a in assets.values() if a.type in targets and _in_scope(a.id, scope, kind)]
                grant(iid, stores, {"role": role, "scope": kind})
            sub_asset.properties.update({"owner_count": owners, "contributor_count": contributors})

        self._step(res, f"{sub}/rbac", rbac)

        def access_policies():
            for vault_id, oid, summary in kv_policies:
                iid = principal_to_identity.get(oid)
                if iid in assets:
                    rels.append(RelationshipRecord(iid, vault_id, "has_access",
                                                   {"role": "Key Vault access policy", "permissions": summary}))

        self._step(res, f"{sub}/keyvault/access-policies", access_policies)

        res.assets.extend(assets.values())
        # drop edges to unknown nodes (e.g. NSG on another subscription) and merge duplicates
        res.relationships.extend(_dedupe(r for r in rels if r.source_id in assets and r.target_id in assets))
