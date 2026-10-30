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
from ..engine import nsg as nsgeval
from .base import AssetRecord, CollectionResult, Connector, RelationshipRecord, ScopeAccessError
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
    "4939a1f6-9ae0-4e48-a1e0-f2cbe897382d": "SQL Managed Instance Contributor",
    "5bd9cd88-fe45-4216-938b-f97437e15450": "DocumentDB Account Contributor",
    "fbdf93bf-df7d-467e-a4d2-9458aa1360c8": "Cosmos DB Account Reader Role",
    "230815da-be43-4aae-9cb4-875f7bd000aa": "Cosmos DB Operator",
    "e0f68234-74aa-48ed-b826-c38b57376e17": "Redis Cache Contributor",
    "de139f84-1756-47ae-9be6-808fbbe84772": "Website Contributor",
}
DATA_STORE_TYPES = {"storage_account", "sql_server", "key_vault", "postgresql_server", "mysql_server",
                    "cosmos_account", "redis_cache", "sql_managed_instance"}
# Cosmos DB built-in data-plane (SQL API) role definitions
COSMOS_DATA_ROLES = {"00000000-0000-0000-0000-000000000001": "Cosmos DB Built-in Data Reader",
                     "00000000-0000-0000-0000-000000000002": "Cosmos DB Built-in Data Contributor"}
# Roles that give (or let the holder give itself) access to data, and the store types they apply to.
# Owner / Contributor can read storage keys, change SQL firewall/admins and vault access policies.
BROAD_DATA_ROLES = {"Owner", "Contributor"}
NON_DATA_ROLES = {"Key Vault Reader", "Storage Blob Delegator", "Cosmos DB Operator"}
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
    if r == "sql managed instance contributor":
        return {"sql_managed_instance"}
    if r.startswith("sql "):
        return {"sql_server"}
    # can read account keys (read-only keys for the reader role) = data access
    if r in {"documentdb account contributor", "cosmos db account reader role"}:
        return {"cosmos_account"}
    if r == "redis cache contributor":  # can list access keys
        return {"redis_cache"}
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
SECRET_MARKERS = ("key", "credential", "secret", "sas", "connection_string", "publishing", "token", "password",
                  "application_settings", "app_setting", "auth_settings")
# Explicitly secret-free variants of otherwise blocked reads (Easy Auth state without client secrets).
SAFE_READS = {"get_auth_settings_v2_without_secrets"}


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
        if name in SAFE_READS:
            return getattr(self._ops, name)
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
        elif kind == "web":
            from azure.mgmt.web import WebSiteManagementClient
            c = WebSiteManagementClient(self.credential, sub)
        elif kind == "postgresql":
            from azure.mgmt.postgresqlflexibleservers import PostgreSQLManagementClient
            c = PostgreSQLManagementClient(self.credential, sub)
        elif kind == "mysql":
            from azure.mgmt.mysqlflexibleservers import MySQLManagementClient
            c = MySQLManagementClient(self.credential, sub)
        elif kind == "cosmosdb":
            from azure.mgmt.cosmosdb import CosmosDBManagementClient
            c = CosmosDBManagementClient(self.credential, sub)
        elif kind == "redis":
            from azure.mgmt.redis import RedisManagementClient
            c = RedisManagementClient(self.credential, sub)
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


def _list_any(ops: Any, *names: str, args: tuple = ()) -> list:
    """First list operation the SDK version provides (operation names differ between SDK majors)."""
    for n in names:
        try:
            fn = getattr(ops, n)
        except AttributeError:
            continue
        return _list(fn(*args))
    raise AttributeError(f"none of {names} available")


def _ids(items: Iterable | None) -> list[str]:
    return [i for i in (_norm_id(_g(x, "id")) for x in _list(items)) if i]


def _tail(rid: str | None) -> str:
    return (rid or "").rstrip("/").rsplit("/", 1)[-1]


def _bool(v: Any) -> bool | None:
    """True / False from bools, 'Enabled' / 'Disabled', 'on' / 'off', 'true' / 'false'; None if unknown."""
    if v is None or v == "":
        return None
    if isinstance(v, bool):
        return v
    s = _s(v).strip().lower()
    if s in {"enabled", "true", "on", "1", "yes"}:
        return True
    if s in {"disabled", "false", "off", "0", "no"}:
        return False
    return None


def _ip_range_kind(start: str | None, end: str | None) -> str | None:
    """Classify a start-end firewall rule: 'internet' (all), 'azure' (0.0.0.0 = Azure services),
    'partial' (public range) or None (private)."""
    if start == "0.0.0.0" and end == "255.255.255.255":
        return "internet"
    if start == "0.0.0.0" and end in ("0.0.0.0", None):
        return "azure"
    return nsgeval.classify_source(start or "")


def firewall_state(public: bool, rules: list[dict]) -> tuple[str, list[dict]]:
    """Public-endpoint state of a PaaS firewall: (open | restricted | closed | disabled, partial sources)."""
    if not public:
        return "disabled", []
    partial = []
    for r in rules:
        kind = _ip_range_kind(r.get("start_ip"), r.get("end_ip"))
        if kind == "internet":
            return "open", []
        if kind == "azure":
            partial.append({"source": "Azure services (0.0.0.0)", "rule": r.get("name")})
        elif kind == "partial":
            src = r["start_ip"] if r.get("end_ip") in (None, r.get("start_ip")) else f"{r['start_ip']}-{r['end_ip']}"
            partial.append({"source": src, "rule": r.get("name")})
    return ("restricted" if partial else "closed"), partial


def eval_access_restrictions(rules: Iterable | None, default_action: Any) -> tuple[str, list[dict]]:
    """App Service access restrictions (main or SCM site): open | restricted | closed, plus partial sources.

    Rules are processed by priority, first match wins; VNet (service endpoint) rules never match
    internet traffic; an AzureFrontDoor.Backend service tag lets internet traffic in through Front
    Door (reported as restricted). Without rules the site is open; with rules the implicit default is
    Deny unless `ipSecurityRestrictionsDefaultAction` says Allow.
    """
    rules = sorted(_list(rules), key=lambda r: _g(r, "priority", default=2147483647))
    partial: list[dict] = []
    for r in rules:
        allow = _s(_g(r, "action", default="Allow")).lower() == "allow"
        if _g(r, "vnet_subnet_resource_id"):
            continue
        ip = str(_g(r, "ip_address", default="") or "")
        name = _g(r, "name", default=ip)
        if _s(_g(r, "tag", default="Default")).lower() == "servicetag":
            if allow and ip.lower().startswith("azurefrontdoor"):
                fdid = (_g(r, "headers", default={}) or {}).get("x-azure-fdid")
                partial.append({"source": ip + (" (own Front Door only)" if fdid else " (any Front Door)"),
                                "rule": name})
            continue
        kind = nsgeval.classify_source(ip)
        if kind == "internet":
            return ("open" if allow else ("restricted" if partial else "closed")), partial
        if kind == "partial" and allow:
            partial.append({"source": ip, "rule": name})
    da = _s(default_action).lower() or ("deny" if rules else "allow")
    if da == "allow":
        return "open", partial
    return ("restricted" if partial else "closed"), partial


def paas_method(kind: str, detail: str, ports: list[str], state: str, partial: list[dict] | None = None) -> dict:
    """Exposure method of a PaaS public endpoint in the shape the Exposure view reads."""
    level = {"open": "open", "restricted": "restricted"}.get(state, "blocked")
    return {"kind": kind, "detail": detail, "ports": ports if level == "open" else [], "level": level,
            "partial": [{**p, "ports": ports} for p in (partial or [])] if level == "restricted" else [],
            "state": state}


def apply_exposure(asset: AssetRecord, methods: list[dict], set_exposed: bool = True) -> None:
    """Store exposure methods, effective ports and level on an asset (and its internet_exposed flag)."""
    p = asset.properties
    seen: set[tuple] = set()
    methods = [m for m in methods if (k := (m["kind"], m["detail"], tuple(m.get("ports") or []))) not in seen
               and not seen.add(k)]
    p["exposure_methods"] = methods
    open_m = [m for m in methods if m["level"] == "open"]
    ports: nsgeval.PortRanges = []
    for m in open_m:
        ports = nsgeval._norm(ports + nsgeval.parse_ports(m.get("ports") or []))
    p["effective_ports"] = nsgeval.format_ports(ports) if ports else []
    p["partial_exposure"] = [{**x, "via": m["detail"]} for m in methods for x in m.get("partial") or []]
    p["exposure_level"] = "open" if open_m else "restricted" if p["partial_exposure"] else "none"
    blocked = [m["detail"] for m in methods if m["level"] == "blocked" and m.get("note")]
    p["exposure_blocked"] = "; ".join(f"{d}: no port reachable from the Internet" for d in blocked) or None
    via = [m.get("via") for m in open_m]
    p["exposed_only_via"] = sorted(set(via)) if via and all(via) else []
    if set_exposed:
        asset.internet_exposed = bool(open_m)
        p["exposure"] = "; ".join(dict.fromkeys(m["detail"] for m in open_m)) or None


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

    def check_access(self, max_scopes: int = 10) -> list[dict[str, str]]:
        """Connection test: list one resource group per subscription (Reader is enough)."""
        factory = self._client_factory()
        reached = []
        for sub in self.settings.azure_subscription_ids[:max_scopes]:
            try:
                next(iter(factory("resource", sub).resource_groups.list()), None)
            except ReadOnlyViolation:
                raise
            except Exception as exc:
                raise ScopeAccessError(sub, exc) from exc
            reached.append({"id": sub, "name": sub})
        return reached

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

        def step(label: str, fn: Callable[[], None]) -> None:
            self._step(res, f"{sub}/{label}", fn)

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

        # ----------------------------------------------------------- network state (shared by later steps)
        pips: dict[str, dict] = {}  # public IP id -> {"ip", "sku"}
        nsg_rules: dict[str, list[dict]] = {}  # NSG id -> normalized rules
        subnets: dict[str, dict] = {}  # subnet id -> {"nsg", "route_table", "vnet", "name"}
        default_routes: dict[str, dict] = {}  # route table id -> 0.0.0.0/0 route
        vm_nics: dict[str, list[dict]] = {}  # VM id -> per IP configuration context
        nic_vm: dict[str, str] = {}  # NIC id -> VM id
        ip_owner: dict[str, list[tuple[str, str, dict | None]]] = {}  # private IP -> (owner, label, port map)
        pe_nic_ips: dict[str, list[str]] = {}  # private endpoint id -> private IPs of its NIC
        pe_targets: dict[str, list[str]] = {}  # target resource id -> private endpoint names
        # LB / App Gateway backend or NAT pool id -> (kind, exposure text, backend ports; None = all ports)
        public_pools: dict[str, tuple[str, str, set[int] | None]] = {}
        net_methods: dict[str, list[dict]] = {}  # VM / scale set id -> raw exposure methods (LB / App Gateway)
        net_ports: dict[str, set[int]] = {}  # VM / scale set id -> backend ports forwarded by public LBs
        pool_members: dict[str, set[str]] = {}  # LB pool id -> VM / scale set ids
        ilb_frontends: dict[str, list[tuple[str, int, int | None, str]]] = {}  # private IP -> (pool, fport, bport, lb)
        appgw_addr_backends: list[tuple[str, set[int], str]] = []  # (text, ports, backend IP or FQDN)
        firewalls: dict[str, dict] = {}  # firewall id -> normalized firewall
        fw_private_ips: dict[str, str] = {}  # firewall private IP -> firewall name
        methods_by_asset: dict[str, list[dict]] = {}  # asset id -> finalized exposure methods
        host_to_site: dict[str, str] = {}  # *.azurewebsites.net host -> site id
        data_grants: list[tuple[str, str, dict]] = []  # (store id, principal object id, edge properties)

        def owner_of_ipconfig(ipc_id: str | None) -> str | None:
            """VM (via its NIC) or scale set behind a NIC IP configuration id."""
            rid = _norm_id(ipc_id)
            vmss = _vmss_from_id(rid)
            if vmss:
                return vmss
            return nic_vm.get(rid.split("/ipconfigurations/")[0])

        def raw_method(target: str | None, kind: str, text: str, ports: set[int] | None, ipc: str | None = None,
                       nsg_applies: bool = True) -> None:
            if not target:
                return
            net_methods.setdefault(target, []).append({"kind": kind, "detail": text, "ports": ports,
                                                       "ipconfig": _norm_id(ipc), "nsg_applies": nsg_applies})
            if kind in ("load_balancer", "lb_nat"):
                net_ports.setdefault(target, set()).update(_ports(ports if ports is not None else {0}))

        def nsg_exposure(nsg_id: str | None, asgs: list[str], ips: list[str]) -> nsgeval.Exposure | None:
            if not nsg_id or nsg_id not in nsg_rules:
                return None  # no NSG (or one outside the scanned subscriptions): nothing filters
            return nsgeval.evaluate_rules(nsg_rules[nsg_id], azure_defaults=True, target_asgs=asgs, target_ips=ips)

        def effective(ctx: dict) -> nsgeval.Exposure | None:
            if "eff" not in ctx:  # inbound: subnet NSG first, then NIC NSG; both must allow
                ctx["eff"] = nsgeval.combine_levels(nsg_exposure(ctx.get("subnet_nsg"), ctx["asgs"], ctx["ips"]),
                                                    nsg_exposure(ctx.get("nic_nsg"), ctx["asgs"], ctx["ips"]))
            return ctx["eff"]

        def finalize_method(raw: dict, ctx: dict | None, closed_without_nsg: bool = False) -> dict:
            wanted = nsgeval.FULL if raw["ports"] is None else nsgeval.parse_ports(sorted(raw["ports"]))
            partial: list[dict] = []
            eff = effective(ctx) if ctx is not None and raw.get("nsg_applies", True) else None
            if ctx is not None and raw.get("nsg_applies", True) and eff is not None:
                open_ = nsgeval.intersect(eff.open_ports(), wanted)
                for lo, hi, rule, cidr in eff.partial:
                    hit = nsgeval.intersect([(lo, hi)], wanted)
                    if hit and not nsgeval.intersect(hit, open_) == hit:
                        partial.append({"source": cidr, "rule": rule, "ports": nsgeval.format_ports(hit)})
            else:
                open_ = [] if closed_without_nsg else wanted
            level = "open" if open_ else "restricted" if partial else "blocked"
            out = {"kind": raw["kind"], "detail": raw["detail"], "ports": nsgeval.format_ports(open_) if open_ else [],
                   "level": level, "partial": partial}
            if level == "blocked":
                out["note"] = ("Standard public IP without NSG: closed by default" if closed_without_nsg and eff is None
                               else "NSG rules deny it")
            if raw.get("via"):
                out["via"] = raw["via"]
            return out

        def ctx_for(raw: dict, ctxs: list[dict]) -> dict | None:
            ipc = raw.get("ipconfig") or ""
            for c in ctxs:
                if ipc and c.get("ipconfig") == ipc:
                    return c
            for c in ctxs:
                if ipc and c.get("nic") and ipc.startswith(c["nic"] + "/"):
                    return c
            return ctxs[0] if ctxs else None

        def nsg_levels(ctxs: list[dict]) -> dict[str, set]:
            out: dict[str, set] = {}
            for c in ctxs:
                if c.get("subnet_nsg"):
                    out.setdefault(c["subnet_nsg"], set()).add("subnet")
                if c.get("nic_nsg"):
                    out.setdefault(c["nic_nsg"], set()).add("nic")
            return out

        def controls_text(levels: dict[str, set]) -> list[str]:
            names = {a.id: a.name for a in assets.values() if a.type == "nsg"}
            return [f"NSG {names.get(n, _tail(n))} ({', '.join(sorted(lv)).replace('nic', 'NIC')})"
                    for n, lv in sorted(levels.items())]

        # ----------------------------------------------------------- network
        def network():
            net = factory("network", sub)
            for pip in _list(net.public_ip_addresses.list_all()):
                pips[_norm_id(pip.id)] = {"ip": _g(pip, "ip_address", default="(dynamic)"),
                                          "sku": _s(_g(pip, "sku", "name", default="")) or None}
            for nsg in _list(net.network_security_groups.list_all()):
                rules = []
                for r in _list(_g(nsg, "security_rules", default=[])):
                    sources = _list(_g(r, "source_address_prefixes", default=[])) or [_g(r, "source_address_prefix", default="")]
                    ports = _list(_g(r, "destination_port_ranges", default=[])) or [_g(r, "destination_port_range", default="")]
                    dests = _list(_g(r, "destination_address_prefixes", default=[])) or \
                        [d for d in [_g(r, "destination_address_prefix")] if d]
                    rule = {"name": r.name, "direction": _s(_g(r, "direction", default="")),
                            "access": _s(_g(r, "access", default="")), "protocol": _s(_g(r, "protocol", default="*")),
                            "source_prefixes": [s for s in sources if s not in (None, "")], "port_ranges": ports,
                            "priority": _g(r, "priority")}
                    src_asgs = _ids(_g(r, "source_application_security_groups"))
                    dst_asgs = _ids(_g(r, "destination_application_security_groups"))
                    if src_asgs:
                        rule["source_asgs"] = src_asgs
                    if dst_asgs:
                        rule["destination_asgs"] = dst_asgs
                    if dests and dests != ["*"]:
                        rule["destination_prefixes"] = dests
                    rules.append(rule)
                nid = _norm_id(nsg.id)
                nsg_rules[nid] = rules
                add(AssetRecord(id=nid, name=nsg.name, type="nsg", region=nsg.location, resource_group=_rg(nsg.id),
                                tags=dict(nsg.tags or {}), **base, properties={"security_rules": rules}))

            def route_tables():
                for rt in _list(net.route_tables.list_all()):
                    for route in _list(_g(rt, "routes", default=[])):
                        if _g(route, "address_prefix") in ("0.0.0.0/0", "Internet"):
                            default_routes[_norm_id(rt.id)] = {
                                "table": rt.name, "next_hop_type": _s(_g(route, "next_hop_type", default="")),
                                "next_hop_ip": _g(route, "next_hop_ip_address")}

            step("network/route-tables", route_tables)

            def vnets():
                for vnet in _list(net.virtual_networks.list_all()):
                    vid = _norm_id(_g(vnet, "id"))
                    sn_props = []
                    for sn in _list(_g(vnet, "subnets", default=[])):
                        sid = _norm_id(sn.id)
                        info = {"name": _g(sn, "name") or _tail(sid), "vnet": vid,
                                "nsg": _norm_id(_g(sn, "network_security_group", "id")) or None,
                                "route_table": _norm_id(_g(sn, "route_table", "id")) or None,
                                "prefix": _g(sn, "address_prefix") or ", ".join(_list(_g(sn, "address_prefixes")))}
                        subnets[sid] = info
                        dr = default_routes.get(info["route_table"] or "")
                        sn_props.append({**{k: v for k, v in info.items() if k != "vnet"},
                                         "default_route": (f"0.0.0.0/0 -> {dr['next_hop_type']}"
                                                           + (f" {dr['next_hop_ip']}" if dr.get("next_hop_ip") else ""))
                                         if dr else None,
                                         "delegations": [_s(_g(d, "service_name")) for d in
                                                         _list(_g(sn, "delegations", default=[]))]})
                    if vid and _g(vnet, "name"):
                        add(AssetRecord(id=vid, name=vnet.name, type="vnet", region=_g(vnet, "location"),
                                        resource_group=_rg(vid), tags=dict(_g(vnet, "tags", default={}) or {}), **base,
                                        properties={"address_space": _list(_g(vnet, "address_space", "address_prefixes")),
                                                    "subnets": sn_props}))

            step("network/subnets", vnets)

            for nic in _list(net.network_interfaces.list_all()):
                nid = _norm_id(_g(nic, "id"))
                vm_id = _norm_id(_g(nic, "virtual_machine", "id"))
                pe_id = _norm_id(_g(nic, "private_endpoint", "id"))
                nic_nsg = _norm_id(_g(nic, "network_security_group", "id")) or None
                for ipc in _list(_g(nic, "ip_configurations", default=[])):
                    ip = _g(ipc, "private_ip_address")
                    subnet = _norm_id(_g(ipc, "subnet", "id"))
                    pid = _norm_id(_g(ipc, "public_ip_address", "id"))
                    if pe_id and ip:
                        pe_nic_ips.setdefault(pe_id, []).append(ip)
                    if not vm_id:
                        continue
                    nic_vm[nid] = vm_id
                    vm_nics.setdefault(vm_id, []).append({
                        "nic": nid, "ipconfig": _norm_id(_g(ipc, "id")), "subnet": subnet,
                        "subnet_nsg": subnets.get(subnet, {}).get("nsg"), "nic_nsg": nic_nsg,
                        "asgs": _ids(_g(ipc, "application_security_groups")), "ips": [ip] if ip else [],
                        "public_ip": (pips.get(pid) or {"ip": pid.rsplit("/", 1)[-1], "sku": None}) if pid else None})
                    if ip:
                        ip_owner.setdefault(ip, []).append((vm_id, f"NIC {_g(nic, 'name') or _tail(nid)}", None))
                if vm_id and vm_id not in vm_nics:  # NIC without IP configurations in the listing
                    vm_nics[vm_id] = [{"nic": nid, "ipconfig": None, "subnet": None, "subnet_nsg": None,
                                       "nic_nsg": nic_nsg, "asgs": [], "ips": [], "public_ip": None}]

            def load_balancers():
                for lb in _list(net.load_balancers.list_all()):
                    fes = {_norm_id(fe.id): pips.get(_norm_id(_g(fe, "public_ip_address", "id")), {}).get("ip", "public IP")
                           for fe in _list(_g(lb, "frontend_ip_configurations", default=[]))
                           if _g(fe, "public_ip_address", "id")}
                    private_fes = {_norm_id(fe.id): _g(fe, "private_ip_address")
                                   for fe in _list(_g(lb, "frontend_ip_configurations", default=[]))
                                   if not _g(fe, "public_ip_address", "id") and _g(fe, "private_ip_address")}
                    for pool in _list(_g(lb, "backend_address_pools", default=[])):
                        for ipc in _list(_g(pool, "backend_ip_configurations", default=[])):
                            owner = owner_of_ipconfig(_g(ipc, "id"))
                            if owner:
                                pool_members.setdefault(_norm_id(pool.id), set()).add(owner)
                    rules = _list(_g(lb, "load_balancing_rules", default=[]))
                    for rule in rules:  # internal frontends: what an Azure Firewall DNAT can target
                        fe = _norm_id(_g(rule, "frontend_ip_configuration", "id"))
                        if fe in private_fes:
                            pools = [_g(rule, "backend_address_pool", "id")]
                            pools += [_g(p, "id") for p in _list(_g(rule, "backend_address_pools", default=[]))]
                            for pool in filter(None, pools):
                                ilb_frontends.setdefault(private_fes[fe], []).append(
                                    (_norm_id(pool), _g(rule, "frontend_port"),
                                     _g(rule, "backend_port", default=_g(rule, "frontend_port")), lb.name))
                    if not fes:
                        continue  # internal load balancer
                    ips = ", ".join(sorted(set(fes.values())))
                    pool_ports: dict[str, tuple[set, set]] = {}  # pool -> (frontend ports, backend ports)
                    for rule in rules:
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
                        ports = None if 0 in be_ports else {p for p in be_ports if isinstance(p, int)}
                        public_pools[pool_id] = ("load_balancer", f"public load balancer {lb.name} ({ips})"
                                                 + (f" port {plist}" if plist else ""), ports)
                    for pool in _list(_g(lb, "backend_address_pools", default=[])):
                        hit = public_pools.get(_norm_id(pool.id))
                        if hit:
                            for ipc in _list(_g(pool, "backend_ip_configurations", default=[])):
                                raw_method(owner_of_ipconfig(_g(ipc, "id")), *hit, ipc=_g(ipc, "id"))
                    for nat in _list(_g(lb, "inbound_nat_rules", default=[])):
                        if _norm_id(_g(nat, "frontend_ip_configuration", "id")) in fes:
                            bport = _g(nat, "backend_port")
                            ipc_id = _g(nat, "backend_ip_configuration", "id")
                            raw_method(owner_of_ipconfig(ipc_id), "lb_nat",
                                       f"public load balancer {lb.name} ({ips}) NAT port {_g(nat, 'frontend_port')}",
                                       None if bport == 0 else {bport}, ipc=ipc_id)
                    for np_ in _list(_g(lb, "inbound_nat_pools", default=[])):  # classic VMSS NAT pools
                        if _norm_id(_g(np_, "frontend_ip_configuration", "id")) in fes:
                            bport = _g(np_, "backend_port")
                            public_pools[_norm_id(np_.id)] = (
                                "lb_nat", f"public load balancer {lb.name} ({ips}) NAT ports "
                                f"{_g(np_, 'frontend_port_range_start')}-{_g(np_, 'frontend_port_range_end')}",
                                None if bport == 0 else {bport})

            step("network/load-balancers", load_balancers)

            def app_gateways():
                for gw in _list(net.application_gateways.list_all()):
                    ips = sorted({pips.get(_norm_id(_g(fe, "public_ip_address", "id")), {}).get("ip", "public IP")
                                  for fe in _list(_g(gw, "frontend_ip_configurations", default=[]))
                                  if _g(fe, "public_ip_address", "id")})
                    if not ips:
                        continue
                    # HTTP(S) only reaches the backends: no admin / database port is forwarded. The gateway's
                    # own subnet is the source, so the backends' NSG Internet rules do not apply.
                    ports = {p for p in (_g(s, "port") for s in _list(_g(gw, "backend_http_settings_collection",
                                                                          default=[]))) if isinstance(p, int)}
                    ports = ports or {80, 443}
                    text = f"public application gateway {gw.name} ({', '.join(ips)})"
                    for pool in _list(_g(gw, "backend_address_pools", default=[])):
                        public_pools[_norm_id(pool.id)] = ("app_gateway", text, ports)
                        for ipc in _list(_g(pool, "backend_ip_configurations", default=[])):
                            raw_method(owner_of_ipconfig(_g(ipc, "id")), "app_gateway", text, ports,
                                       ipc=_g(ipc, "id"), nsg_applies=False)
                        for addr in _list(_g(pool, "backend_addresses", default=[])):
                            target = _g(addr, "ip_address") or _g(addr, "fqdn")
                            if target:
                                appgw_addr_backends.append((text, ports, str(target).lower()))

            step("network/app-gateways", app_gateways)

            def private_endpoints():
                for pe in _list_any(net.private_endpoints, "list_by_subscription", "list_all"):
                    peid = _norm_id(pe.id)
                    subnet = _norm_id(_g(pe, "subnet", "id"))
                    vnet = subnet.split("/subnets/")[0] if subnet else None
                    targets = []
                    for c in _list(_g(pe, "private_link_service_connections", default=[])) + \
                            _list(_g(pe, "manual_private_link_service_connections", default=[])):
                        tid = _norm_id(_g(c, "private_link_service_id"))
                        if tid:
                            targets.append({"id": tid, "group_ids": _list(_g(c, "group_ids")),
                                            "status": _s(_g(c, "private_link_service_connection_state", "status",
                                                            default="")) or None})
                    ips = [ip for cfg in _list(_g(pe, "custom_dns_configs", default=[]))
                           for ip in _list(_g(cfg, "ip_addresses", default=[]))]
                    ips += [_g(ipc, "private_ip_address") for ipc in _list(_g(pe, "ip_configurations", default=[]))
                            if _g(ipc, "private_ip_address")]
                    ips = list(dict.fromkeys(ips + pe_nic_ips.get(peid, [])))
                    add(AssetRecord(id=peid, name=pe.name, type="private_endpoint", region=_g(pe, "location"),
                                    resource_group=_rg(peid), tags=dict(_g(pe, "tags", default={}) or {}), **base,
                                    properties={"subnet": subnet or None, "vnet": vnet,
                                                "subnet_name": subnets.get(subnet, {}).get("name"),
                                                "targets": targets, "private_ips": ips}))
                    if vnet:
                        rels.append(RelationshipRecord(vnet, peid, "contains"))
                    for t in targets:
                        if t["status"] and t["status"].lower() not in ("approved", ""):
                            continue  # pending / rejected connections give no private access
                        rels.append(RelationshipRecord(peid, t["id"], "connects_to",
                                                       {"via": "private endpoint", "group_ids": t["group_ids"]}))
                        pe_targets.setdefault(t["id"], []).append(pe.name)
                        for ip in ips:
                            ip_owner.setdefault(ip, []).append((t["id"], f"private endpoint {pe.name}", None))

            step("network/private-endpoints", private_endpoints)

            def azure_firewalls():
                policies: dict[str, dict] = {}

                def fw_rule(r: Any, collection: str, priority: Any, action: str | None = None) -> dict:
                    sources = [str(x) for x in _list(_g(r, "source_addresses", default=[]))]
                    groups = [_tail(x) for x in _list(_g(r, "source_ip_groups", default=[]))]
                    kinds = {nsgeval.classify_source(x) for x in sources}
                    kind = "internet" if "internet" in kinds else "partial" if "partial" in kinds else "none"
                    protos = [_s(p) for p in _list(_g(r, "protocols", default=None) or _g(r, "ip_protocols", default=[]))]
                    out = {"collection": collection, "priority": priority, "name": _g(r, "name"),
                           "sources": sources + [f"ipgroup:{g}" for g in groups], "source_kind": kind,
                           "destination": ", ".join(str(x) for x in _list(_g(r, "destination_addresses", default=[]))),
                           "ports": [str(x) for x in _list(_g(r, "destination_ports", default=[]))], "protocols": protos}
                    if action is not None:
                        out["action"] = action
                    else:
                        out.update({"translated_address": _g(r, "translated_address"),
                                    "translated_port": _g(r, "translated_port"),
                                    "translated_fqdn": _g(r, "translated_fqdn")})
                    return out

                def policy_rules():
                    for pol in _list(net.firewall_policies.list_all()):
                        pid = _norm_id(pol.id)
                        info = {"name": pol.name, "threat_intel_mode": _s(_g(pol, "threat_intel_mode", default="")) or None,
                                "idps_mode": _s(_g(pol, "intrusion_detection", "mode", default="")) or None,
                                "sku_tier": _s(_g(pol, "sku", "tier", default="")) or None,
                                "base_policy": _norm_id(_g(pol, "base_policy", "id")) or None,
                                "dnat": [], "network": [], "application": 0}
                        for grp in _list(net.firewall_policy_rule_collection_groups.list(_rg(pol.id), pol.name)):
                            for col in _list(_g(grp, "rule_collections", default=[])):
                                ctype = _s(_g(col, "rule_collection_type", default="")).lower()
                                action = _s(_g(col, "action", "type", default=""))
                                for r in _list(_g(col, "rules", default=[])):
                                    rtype = _s(_g(r, "rule_type", default="")).lower()
                                    if rtype == "natrule" or "nat" in ctype:
                                        info["dnat"].append(fw_rule(r, f"{grp.name}/{col.name}", _g(col, "priority")))
                                    elif rtype == "networkrule":
                                        info["network"].append(fw_rule(r, f"{grp.name}/{col.name}", _g(col, "priority"),
                                                                       action or "Allow"))
                                    else:
                                        info["application"] += 1
                        policies[pid] = info
                        add(AssetRecord(id=pid, name=pol.name, type="firewall_policy", region=_g(pol, "location"),
                                        resource_group=_rg(pid), tags=dict(_g(pol, "tags", default={}) or {}), **base,
                                        properties={k: v for k, v in info.items() if k not in ("dnat", "network")}
                                        | {"dnat_rule_count": len(info["dnat"]),
                                           "network_rule_count": len(info["network"])}))

                step("network/firewall-policies", policy_rules)

                def inherited(pid: str | None, depth: int = 0) -> tuple[list, list, dict]:
                    pol = policies.get(pid or "")
                    if not pol or depth > 5:
                        return [], [], {}
                    bd, bn, _ = inherited(pol["base_policy"], depth + 1)
                    return bd + pol["dnat"], bn + pol["network"], pol

                for fw in _list(net.azure_firewalls.list_all()):
                    fid = _norm_id(fw.id)
                    public, private = [], []
                    for ipc in _list(_g(fw, "ip_configurations", default=[])):
                        pid = _norm_id(_g(ipc, "public_ip_address", "id"))
                        if pid:
                            public.append(pips.get(pid, {}).get("ip") or _tail(pid))
                        if _g(ipc, "private_ip_address"):
                            private.append(_g(ipc, "private_ip_address"))
                    hub = _g(fw, "hub_ip_addresses")
                    public += [_g(x, "address") for x in _list(_g(hub, "public_i_ps", "addresses", default=[]))
                               if _g(x, "address")]
                    if _g(hub, "private_ip_address"):
                        private.append(_g(hub, "private_ip_address"))
                    dnat = [fw_rule(r, col.name, _g(col, "priority"))
                            for col in _list(_g(fw, "nat_rule_collections", default=[]))
                            for r in _list(_g(col, "rules", default=[]))]
                    network = [fw_rule(r, col.name, _g(col, "priority"), _s(_g(col, "action", "type", default="Allow")))
                               for col in _list(_g(fw, "network_rule_collections", default=[]))
                               for r in _list(_g(col, "rules", default=[]))]
                    classic = len(dnat) + len(network) + sum(len(_list(_g(c, "rules", default=[]))) for c in
                                                             _list(_g(fw, "application_rule_collections", default=[])))
                    policy_id = _norm_id(_g(fw, "firewall_policy", "id")) or None
                    pdnat, pnet, pol = inherited(policy_id)
                    for ip in private:
                        fw_private_ips[ip] = fw.name
                    firewalls[fid] = {"name": fw.name, "public_ips": public, "dnat": dnat + pdnat}
                    ti = (pol.get("threat_intel_mode") if pol else None) or _s(_g(fw, "threat_intel_mode", default="")) or None
                    add(AssetRecord(
                        id=fid, name=fw.name, type="azure_firewall", region=_g(fw, "location"), resource_group=_rg(fid),
                        tags=dict(_g(fw, "tags", default={}) or {}), **base,
                        properties={"public_ips": public, "private_ips": private,
                                    "sku_tier": _s(_g(fw, "sku", "tier", default="")) or None,
                                    "policy_id": policy_id, "policy": pol.get("name") if pol else None,
                                    "virtual_hub": _norm_id(_g(fw, "virtual_hub", "id")) or None,
                                    "threat_intel_mode": ti, "idps_mode": pol.get("idps_mode") if pol else None,
                                    "classic_rule_count": classic, "dnat_rules": dnat + pdnat,
                                    "network_rules": network + pnet}))
                    if policy_id:
                        rels.append(RelationshipRecord(policy_id, fid, "applies_to"))

            step("network/azure-firewalls", azure_firewalls)

        step("network", network)

        def protects(nsgs: dict[str, set], target: str) -> None:
            for nsg_id, levels in nsgs.items():
                rels.append(RelationshipRecord(nsg_id, target, "protects", {"levels": sorted(levels)}))

        def egress(ctxs: list[dict]) -> str | None:
            for c in ctxs:
                dr = default_routes.get((subnets.get(c.get("subnet") or "", {}) or {}).get("route_table") or "")
                if dr and dr["next_hop_type"].lower() == "virtualappliance":
                    fw = fw_private_ips.get(dr.get("next_hop_ip") or "")
                    return (f"0.0.0.0/0 via Azure Firewall {fw} ({dr['next_hop_ip']})" if fw
                            else f"0.0.0.0/0 via virtual appliance {dr.get('next_hop_ip')}")
                if dr:
                    return f"0.0.0.0/0 via {dr['next_hop_type']}"
            return None

        # ----------------------------------------------------------- compute
        def compute():
            cm = factory("compute", sub)
            for vm in _list(cm.virtual_machines.list_all()):
                vid = _norm_id(vm.id)
                ctxs = vm_nics.get(vid, [])
                raws = [({"kind": "public_ip", "detail": f"public IP {c['public_ip']['ip']}", "ports": None,
                          "ipconfig": c["ipconfig"]}, str(c["public_ip"].get("sku") or "").lower() == "standard")
                        for c in ctxs if c.get("public_ip")]
                raws += [(r, False) for r in net_methods.get(vid, [])]
                methods_by_asset[vid] = [finalize_method(r, ctx_for(r, ctxs), closed) for r, closed in raws]
                os_disk = _g(vm, "storage_profile", "os_disk")
                encrypted = bool(_g(os_disk, "encryption_settings", "enabled")) \
                    or bool(_g(os_disk, "managed_disk", "disk_encryption_set", "id")) \
                    or bool(_g(vm, "security_profile", "encryption_at_host"))
                levels = nsg_levels(ctxs)
                add(AssetRecord(
                    id=vid, name=vm.name, type="vm", region=vm.location, resource_group=_rg(vm.id),
                    tags=dict(vm.tags or {}), **base,
                    properties={"size": _g(vm, "hardware_profile", "vm_size"),
                                "os": _s(_g(vm, "storage_profile", "os_disk", "os_type", default="")),
                                "public_ips": [c["public_ip"]["ip"] for c in ctxs if c.get("public_ip")],
                                "private_ips": [ip for c in ctxs for ip in c["ips"]],
                                "asgs": sorted({a for c in ctxs for a in c["asgs"]}),
                                "disk_encryption": encrypted,
                                "forwarded_ports": sorted(net_ports.get(vid, ())),
                                "network_controls": controls_text(levels), "egress": egress(ctxs)}))
                protects(levels, vid)
                identities(vid, vm.name, _g(vm, "identity"), vm.location)

        step("compute", compute)

        def scale_sets():
            cm = factory("compute", sub)
            for ss in _list(cm.virtual_machine_scale_sets.list_all()):
                sid = _norm_id(ss.id)
                prof = _g(ss, "virtual_machine_profile")
                ctxs: list[dict] = []
                raws: list[tuple[dict, bool]] = []
                forwarded: set[int] = set(net_ports.get(sid, ()))
                per_instance_pip = False
                for nc in _list(_g(prof, "network_profile", "network_interface_configurations", default=[])):
                    nic_nsg = _norm_id(_g(nc, "network_security_group", "id")) or None
                    for ipc in _list(_g(nc, "ip_configurations", default=[])):
                        subnet = _norm_id(_g(ipc, "subnet", "id"))
                        ctx = {"nic": None, "ipconfig": None, "subnet": subnet,
                               "subnet_nsg": subnets.get(subnet, {}).get("nsg"), "nic_nsg": nic_nsg,
                               "asgs": _ids(_g(ipc, "application_security_groups")), "ips": [], "public_ip": None}
                        ctxs.append(ctx)
                        pipc = _g(ipc, "public_ip_address_configuration")
                        if pipc is not None:
                            per_instance_pip = True
                            standard = _s(_g(pipc, "sku", "name", default="")).lower() == "standard"
                            raws.append(({"kind": "public_ip", "detail": "public IP per instance", "ports": None,
                                          "ctx": ctx}, standard))
                        for attr in ("load_balancer_backend_address_pools", "application_gateway_backend_address_pools",
                                     "load_balancer_inbound_nat_pools"):
                            for pool in _list(_g(ipc, attr, default=[])):
                                pool_id = _norm_id(_g(pool, "id"))
                                pool_members.setdefault(pool_id, set()).add(sid)
                                hit = public_pools.get(pool_id)
                                if hit:
                                    kind, text, ports = hit
                                    if kind != "app_gateway":
                                        forwarded |= _ports(ports if ports is not None else {0})
                                    raws.append(({"kind": kind, "detail": text, "ports": ports, "ctx": ctx,
                                                  "nsg_applies": kind != "app_gateway"}, False))
                raws += [(r, False) for r in net_methods.get(sid, [])]
                methods_by_asset[sid] = [finalize_method(r, r.get("ctx") or (ctxs[0] if ctxs else None), closed)
                                         for r, closed in raws]
                os_disk = _g(prof, "storage_profile", "os_disk")
                encrypted = bool(_g(os_disk, "managed_disk", "disk_encryption_set", "id")) \
                    or bool(_g(prof, "security_profile", "encryption_at_host"))
                levels = nsg_levels(ctxs)
                add(AssetRecord(
                    id=sid, name=ss.name, type="vmss", region=ss.location, resource_group=_rg(ss.id),
                    tags=dict(ss.tags or {}), **base,
                    properties={"size": _g(ss, "sku", "name"), "capacity": _g(ss, "sku", "capacity"),
                                "os": _s(_g(os_disk, "os_type", default="")),
                                "orchestration_mode": _s(_g(ss, "orchestration_mode", default="")) or None,
                                "per_instance_public_ip": per_instance_pip, "disk_encryption": encrypted,
                                "public_ips": [], "asgs": sorted({a for c in ctxs for a in c["asgs"]}),
                                "forwarded_ports": sorted(forwarded),
                                "network_controls": controls_text(levels), "egress": egress(ctxs)}))
                protects(levels, sid)
                identities(sid, ss.name, _g(ss, "identity"), ss.location)

        step("compute/scale-sets", scale_sets)

        def paas_common(rid: str, state: str, partial: list[dict], detail: str, ports: list[str],
                        kind: str = "public_endpoint", controls: list[str] | None = None) -> dict:
            pes = sorted(pe_targets.get(rid, []))
            methods_by_asset[rid] = [paas_method(kind, detail, ports, state, partial)]
            return {"public_endpoint": state, "private_endpoints": pes,
                    "network_controls": (controls or []) + [f"private endpoint {p}" for p in pes]}

        # ----------------------------------------------------------- storage
        def storage():
            st = factory("storage", sub)
            for acc in _list(st.storage_accounts.list()):
                sens, cls = _sensitive_from_tags(acc.tags)
                public_blob = bool(_g(acc, "allow_blob_public_access", default=False))
                pna = _g(acc, "public_network_access", default="Enabled")
                default_action = _s(_g(acc, "network_rule_set", "default_action", default="Allow"))
                ip_rules = [str(_g(r, "ip_address_or_range")) for r in
                            _list(_g(acc, "network_rule_set", "ip_rules", default=[])) if _g(r, "ip_address_or_range")]
                exposed = public_blob and _enabled(pna) and default_action.lower() == "allow"
                rid = _norm_id(acc.id)
                state = "disabled" if not _enabled(pna) else "open" if default_action.lower() == "allow" \
                    else "restricted" if ip_rules else "closed"
                common = paas_common(rid, state, [{"source": ip, "rule": "storage firewall"} for ip in ip_rules],
                                     f"public endpoint https://{acc.name}.blob.core.windows.net", ["443"],
                                     controls=[f"storage firewall: default {default_action}"])
                add(AssetRecord(
                    id=rid, name=acc.name, type="storage_account", region=acc.location,
                    resource_group=_rg(acc.id), tags=dict(acc.tags or {}), internet_exposed=exposed,
                    sensitive_data=sens, **base,
                    properties={"allow_blob_public_access": public_blob,
                                "https_only": _g(acc, "enable_https_traffic_only"),
                                "min_tls_version": _s(_g(acc, "minimum_tls_version", default="TLS1_0")),
                                "public_network_access": _s(pna), "network_default_action": default_action,
                                "ip_rules": ip_rules, **common,
                                "kind": _s(_g(acc, "kind", default="")), "data_classification": cls,
                                "exposure": "anonymous blob access allowed" if exposed else None}))

        step("storage", storage)

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
                state, partial = firewall_state(public, fw)
                admin = _g(srv, "administrators")
                if _g(admin, "sid"):
                    data_grants.append((sid, str(_g(admin, "sid")), {"role": "Entra administrator"}))
                add(AssetRecord(
                    id=sid, name=srv.name, type="sql_server", region=srv.location, resource_group=rg,
                    tags=dict(srv.tags or {}), internet_exposed=public and allow_all,
                    sensitive_data=True,  # databases are treated as sensitive by default
                    **base, properties={"public_network_access": public, "auditing_enabled": auditing,
                                        "firewall_rules": fw, "data_classification": cls or "database",
                                        "min_tls_version": _s(_g(srv, "minimal_tls_version", default="")) or None,
                                        "entra_only": _bool(_g(admin, "azure_ad_only_authentication")),
                                        **paas_common(sid, state, partial,
                                                      f"public endpoint {srv.name}.database.windows.net:1433",
                                                      ["1433"], controls=[f"SQL firewall ({len(fw)} rules)"]),
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

        step("sql", sql)

        def sql_managed_instances():
            sq = factory("sql", sub)
            for mi in _list(sq.managed_instances.list()):
                mid = _norm_id(mi.id)
                subnet = _norm_id(_g(mi, "subnet_id"))
                nsg_id = subnets.get(subnet, {}).get("nsg")
                public = bool(_g(mi, "public_data_endpoint_enabled", default=False))
                partial: list[dict] = []
                if not public:
                    state = "disabled"
                else:  # the public endpoint (TCP 3342) is filtered by the subnet NSG
                    exp = nsg_exposure(nsg_id, [], [])
                    if exp is None or nsgeval.contains(exp.open_ports(), 3342):
                        state = "open"
                    else:
                        partial = [{"source": p["source"], "rule": p["rule"]} for p in exp.partial_summary()
                                   if nsgeval.contains(nsgeval.parse_ports(p["ports"]), 3342)]
                        state = "restricted" if partial else "closed"
                admin = _g(mi, "administrators")
                if _g(admin, "sid"):
                    data_grants.append((mid, str(_g(admin, "sid")), {"role": "Entra administrator"}))
                _, cls = _sensitive_from_tags(mi.tags)
                host = _g(mi, "fully_qualified_domain_name") or mi.name
                add(AssetRecord(
                    id=mid, name=mi.name, type="sql_managed_instance", region=mi.location, resource_group=_rg(mid),
                    tags=dict(mi.tags or {}), internet_exposed=state == "open", sensitive_data=True, **base,
                    properties={"public_data_endpoint": public, "subnet": subnet or None,
                                "min_tls_version": _s(_g(mi, "minimal_tls_version", default="")) or None,
                                "entra_only": _bool(_g(admin, "azure_ad_only_authentication")),
                                "proxy_override": _s(_g(mi, "proxy_override", default="")) or None,
                                "data_classification": cls or "database",
                                **paas_common(mid, state, partial, f"public data endpoint {host}:3342", ["3342"],
                                              controls=[f"subnet NSG {_tail(nsg_id)}"] if nsg_id else []),
                                "exposure": f"public data endpoint {host}:3342 open to the Internet"
                                if state == "open" else None}))
                identities(mid, mi.name, _g(mi, "identity"), mi.location)

        step("sql/managed-instances", sql_managed_instances)

        # ----------------------------------------------------------- Key Vault
        kv_policies: list[tuple[str, str, str]] = []  # (vault id, principal object id, permission summary)

        def keyvault():
            kv = factory("keyvault", sub)
            for v in _list(kv.vaults.list_by_subscription()):
                props = _g(v, "properties")
                soft = _g(props, "enable_soft_delete")
                rbac_mode = bool(_g(props, "enable_rbac_authorization", default=False))
                vid = _norm_id(v.id)
                pna = _s(_g(props, "public_network_access", default="Enabled"))
                default_action = _s(_g(props, "network_acls", "default_action", default="Allow"))
                ip_rules = [str(_g(r, "value")) for r in _list(_g(props, "network_acls", "ip_rules", default=[]))
                            if _g(r, "value")]
                state = "disabled" if pna.lower() == "disabled" else "open" if default_action.lower() == "allow" \
                    else "restricted" if ip_rules else "closed"
                add(AssetRecord(
                    id=vid, name=v.name, type="key_vault", region=v.location, resource_group=_rg(v.id),
                    tags=dict(v.tags or {}), sensitive_data=True, **base,
                    properties={"soft_delete": True if soft is None else bool(soft),  # default on since 2020
                                "purge_protection": bool(_g(props, "enable_purge_protection", default=False)),
                                "public_network_access": pna, "network_default_action": default_action,
                                "rbac_authorization": rbac_mode,
                                **paas_common(vid, state, [{"source": ip, "rule": "vault firewall"} for ip in ip_rules],
                                              f"public endpoint https://{v.name}.vault.azure.net", ["443"],
                                              controls=[f"vault firewall: default {default_action}"]),
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

        step("keyvault", keyvault)

        # ----------------------------------------------------------- App Service (web + function apps)
        def web():
            w = factory("web", sub)
            plans: dict[str, str] = {}

            def app_plans():
                for plan in _list(w.app_service_plans.list()):
                    pid = _norm_id(plan.id)
                    plans[pid] = plan.name
                    add(AssetRecord(
                        id=pid, name=plan.name, type="app_service_plan", region=plan.location, resource_group=_rg(pid),
                        tags=dict(_g(plan, "tags", default={}) or {}), **base,
                        properties={"sku": _g(plan, "sku", "name"), "tier": _g(plan, "sku", "tier"),
                                    "os": "linux" if _g(plan, "reserved") else "windows",
                                    "number_of_sites": _g(plan, "number_of_sites"),
                                    "zone_redundant": _g(plan, "zone_redundant")}))

            step("web/plans", app_plans)
            detail_errors: dict[str, int] = {}

            def detail(label: str, fn: Callable[..., Any], *args: Any) -> Any:
                try:
                    return fn(*args)
                except ReadOnlyViolation:
                    raise
                except Exception as exc:  # noqa: BLE001 - optional detail; one error per kind
                    if label not in detail_errors:
                        res.errors.append(f"{sub}/web {label}: {type(exc).__name__}: {exc}")
                    detail_errors[label] = detail_errors.get(label, 0) + 1
                    return None

            for site in _list(w.web_apps.list()):
                sid = _norm_id(site.id)
                rg = _rg(site.id)
                kind = _s(_g(site, "kind", default="")).lower()
                rtype = "function_app" if "functionapp" in kind else "web_app"
                cfg = detail("configuration", lambda r, n: w.web_apps.get_configuration(r, n), rg, site.name) \
                    or _g(site, "site_config")
                auth = detail("authentication", lambda r, n: w.web_apps.get_auth_settings_v2_without_secrets(r, n),
                              rg, site.name)
                slots = detail("slots", lambda r, n: [s.name for s in _list(w.web_apps.list_slots(r, n))], rg, site.name)
                pna = _s(_g(site, "public_network_access", default="")) or _s(_g(cfg, "public_network_access",
                                                                                   default=""))
                pes = pe_targets.get(sid, [])
                if pna.lower() == "disabled" or (not pna and pes):  # a private endpoint disabled public access
                    state, partial = "disabled", []
                else:
                    state, partial = eval_access_restrictions(_g(cfg, "ip_security_restrictions"),
                                                              _g(cfg, "ip_security_restrictions_default_action"))
                if state == "disabled":
                    scm = "disabled"
                elif _g(cfg, "scm_ip_security_restrictions_use_main"):
                    scm = state
                else:
                    scm, _ = eval_access_restrictions(_g(cfg, "scm_ip_security_restrictions"),
                                                      _g(cfg, "scm_ip_security_restrictions_default_action"))
                host = _g(site, "default_host_name") or f"{site.name}.azurewebsites.net"
                host_to_site[str(host).lower()] = sid
                https_only = _g(site, "https_only")
                ident = _g(site, "identity")
                id_type = _s(_g(ident, "type", default="")).lower()
                auth_on = _bool(_g(auth, "platform", "enabled")) if auth is not None else None
                runtime = {k: _g(cfg, k) for k in ("linux_fx_version", "windows_fx_version", "net_framework_version",
                                                    "php_version", "python_version", "node_version", "java_version",
                                                    "power_shell_version") if _g(cfg, k)}
                from ..engine.eol import app_runtimes, eol_runtimes  # local: keeps the import graph shallow

                restrictions = [{"name": _g(r, "name"), "priority": _g(r, "priority"),
                                 "action": _s(_g(r, "action", default="")), "source": _g(r, "ip_address")
                                 or _tail(_g(r, "vnet_subnet_resource_id")), "tag": _s(_g(r, "tag", default=""))}
                                for r in _list(_g(cfg, "ip_security_restrictions"))]
                common = paas_common(sid, state, partial, f"https://{host}",
                                     ["443"] if https_only else ["80", "443"], kind="app_service",
                                     controls=[f"access restrictions ({len(restrictions)} rules)"] if restrictions else [])
                plan_id = _norm_id(_g(site, "server_farm_id"))
                add(AssetRecord(
                    id=sid, name=site.name, type=rtype, region=site.location, resource_group=rg,
                    tags=dict(site.tags or {}), internet_exposed=state == "open", **base,
                    properties={"kind": kind, "state": _g(site, "state"), "default_host_name": host,
                                "https_only": https_only, "public_network_access": pna or "Enabled",
                                "access_restrictions": restrictions,
                                "access_default_action": _s(_g(cfg, "ip_security_restrictions_default_action",
                                                               default="")) or None,
                                "scm_access": scm, "client_cert_enabled": _g(site, "client_cert_enabled"),
                                "client_cert_mode": _s(_g(site, "client_cert_mode", default="")) or None,
                                "auth_enabled": auth_on,
                                "min_tls_version": _s(_g(cfg, "min_tls_version", default="")) or None,
                                "ftps_state": _s(_g(cfg, "ftps_state", default="")) or None,
                                "http20_enabled": _g(cfg, "http20_enabled"),
                                "remote_debugging": _g(cfg, "remote_debugging_enabled"),
                                "managed_identity": bool(id_type and id_type != "none") if ident is not None
                                or cfg is not None else None,
                                "runtime_config": runtime,
                                "runtimes": [f"{s} {v}" for s, v in app_runtimes(runtime)],
                                "eol_runtimes": [h["runtime"] for h in eol_runtimes(runtime)],
                                "plan": plans.get(plan_id) or _tail(plan_id) or None, "slots": slots,
                                "vnet_integration_subnet": _norm_id(_g(site, "virtual_network_subnet_id")) or None,
                                **common,
                                "exposure": f"https://{host}" + ("" if not partial else " (restricted)")
                                if state == "open" else None}))
                if plan_id:
                    rels.append(RelationshipRecord(plan_id, sid, "contains"))
                identities(sid, site.name, ident, site.location)

        step("web", web)

        # ----------------------------------------------------------- managed databases
        def flexible(kind: str, rtype: str, label: str, port: str, host_suffix: str, tls_param: str,
                     admins_ops: tuple[str, ...]):
            def run():
                cl = factory(kind, sub)
                errors: set[str] = set()

                def opt(what: str, fn: Callable[..., Any], *args: Any) -> Any:
                    try:
                        return fn(*args)
                    except ReadOnlyViolation:
                        raise
                    except Exception as exc:  # noqa: BLE001 - optional detail; one error per kind
                        if what not in errors:
                            errors.add(what)
                            res.errors.append(f"{sub}/{kind} {what}: {type(exc).__name__}: {exc}")
                        return None

                for srv in _list_any(cl.servers, "list_by_subscription", "list"):
                    rg, name, sid = _rg(srv.id), srv.name, _norm_id(srv.id)
                    fw = opt("firewall rules", lambda r_, n_: [
                        {"name": r.name, "start_ip": _g(r, "start_ip_address"), "end_ip": _g(r, "end_ip_address")}
                        for r in _list(cl.firewall_rules.list_by_server(r_, n_))], rg, name) or []

                    def conf(r_: str, n_: str, param: str) -> str | None:
                        c = opt("server parameters", lambda: cl.configurations.get(r_, n_, param))
                        return None if c is None else _g(c, "value")

                    secure = _bool(conf(rg, name, "require_secure_transport"))
                    tls = conf(rg, name, tls_param)
                    admins = None
                    for op in admins_ops:
                        if hasattr_safe(cl, op):
                            admins = opt("Entra administrators",
                                         lambda o, r_, n_: _list(getattr(cl, o).list_by_server(r_, n_)), op, rg, name)
                            break
                    for adm in admins or []:
                        oid = _g(adm, "object_id") or _g(adm, "sid")
                        if oid:
                            data_grants.append((sid, str(oid), {"role": "Entra administrator"}))
                    delegated = _norm_id(_g(srv, "network", "delegated_subnet_resource_id"))
                    pna = _s(_g(srv, "network", "public_network_access", default="")) or ("Disabled" if delegated
                                                                                           else "Enabled")
                    public = _enabled(pna) and not delegated
                    state, partial = firewall_state(public, fw)
                    auth_cfg = _g(srv, "auth_config")
                    entra = _bool(_g(auth_cfg, "active_directory_auth")) if auth_cfg is not None else \
                        (bool(admins) if admins is not None else None)
                    _, cls = _sensitive_from_tags(srv.tags)
                    host = _g(srv, "fully_qualified_domain_name") or f"{name}{host_suffix}"
                    version = _s(_g(srv, "full_version", default="")) or _s(_g(srv, "version", default="")) or None
                    add(AssetRecord(
                        id=sid, name=name, type=rtype, region=srv.location, resource_group=rg,
                        tags=dict(srv.tags or {}), internet_exposed=state == "open", sensitive_data=True, **base,
                        properties={"deployment": "flexible", "version": version,
                                    "public_network_access": pna, "delegated_subnet": delegated or None,
                                    "firewall_rules": fw, "require_secure_transport": secure,
                                    "min_tls_version": str(tls).split(",")[0].strip() if tls else None,
                                    "geo_redundant_backup": _bool(_g(srv, "backup", "geo_redundant_backup")),
                                    "backup_retention_days": _g(srv, "backup", "backup_retention_days"),
                                    "entra_auth": entra, "data_classification": cls or "database",
                                    **paas_common(sid, state, partial, f"public endpoint {host}:{port}", [port],
                                                  controls=([f"{label} firewall ({len(fw)} rules)"] if public else
                                                            ["VNet integration (private access)"] if delegated else [])),
                                    "exposure": f"{label} firewall allows 0.0.0.0-255.255.255.255"
                                    if state == "open" else None}))
                    identities(sid, name, _g(srv, "identity"), srv.location)
            return run

        def hasattr_safe(obj: Any, name: str) -> bool:
            try:
                getattr(obj, name)
                return True
            except AttributeError:
                return False

        step("postgresql", flexible("postgresql", "postgresql_server", "PostgreSQL", "5432",
                                    ".postgres.database.azure.com", "ssl_min_protocol_version",
                                    ("administrators_microsoft_entra", "administrators")))
        step("mysql", flexible("mysql", "mysql_server", "MySQL", "3306", ".mysql.database.azure.com", "tls_version",
                               ("azure_ad_administrators",)))

        def cosmos():
            cdb = factory("cosmosdb", sub)
            role_errors = False
            for acc in _list(cdb.database_accounts.list()):
                aid, rg = _norm_id(acc.id), _rg(acc.id)
                pna = _s(_g(acc, "public_network_access", default="")) or "Enabled"
                ip_rules = [str(_g(r, "ip_address_or_range")) for r in _list(_g(acc, "ip_rules", default=[]))
                            if _g(r, "ip_address_or_range")]
                vnet_filter = bool(_g(acc, "is_virtual_network_filter_enabled", default=False))
                if not _enabled(pna):
                    state, partial = "disabled", []
                elif not ip_rules and not vnet_filter:
                    state, partial = "open", []  # no firewall: all networks
                else:
                    partial = []
                    state = "closed"
                    for ip in ip_rules:
                        if ip == "0.0.0.0":  # "Accept connections from within public Azure datacenters"
                            partial.append({"source": "Azure datacenters (0.0.0.0)", "rule": "ip rule"})
                            continue
                        k = nsgeval.classify_source(ip)
                        if k == "internet":
                            state = "open"
                            break
                        if k == "partial":
                            partial.append({"source": ip, "rule": "ip rule"})
                    if state != "open":
                        state = "restricted" if partial else "closed"
                kind = _s(_g(acc, "kind", default="")) or None
                ports = ["443"] + (["10255"] if (kind or "").lower() == "mongodb" else [])
                sens, cls = _sensitive_from_tags(acc.tags)
                endpoint = _g(acc, "document_endpoint") or f"https://{acc.name}.documents.azure.com:443/"
                add(AssetRecord(
                    id=aid, name=acc.name, type="cosmos_account", region=acc.location, resource_group=rg,
                    tags=dict(acc.tags or {}), internet_exposed=state == "open", sensitive_data=True, **base,
                    properties={"kind": kind, "public_network_access": pna, "ip_rules": ip_rules,
                                "virtual_network_filter": vnet_filter,
                                "virtual_network_rules": len(_list(_g(acc, "virtual_network_rules", default=[]))),
                                "local_auth_disabled": _bool(_g(acc, "disable_local_auth")),
                                "min_tls_version": _s(_g(acc, "minimal_tls_version", default="")) or None,
                                "backup_type": _s(_g(acc, "backup_policy", "type", default="")) or None,
                                "backup_redundancy": _s(_g(acc, "backup_policy", "periodic_mode_properties",
                                                           "backup_storage_redundancy", default="")) or None,
                                "server_version": _s(_g(acc, "api_properties", "server_version", default="")) or None,
                                "data_classification": cls or "database",
                                **paas_common(aid, state, partial, f"public endpoint {endpoint}", ports,
                                              controls=[f"Cosmos DB firewall ({len(ip_rules)} IP rules"
                                                        + (", VNet filter)" if vnet_filter else ")")]
                                              if ip_rules or vnet_filter else []),
                                "exposure": f"public endpoint {endpoint} (all networks)" if state == "open" else None}))
                if (kind or "globaldocumentdb").lower() != "globaldocumentdb":
                    continue  # data-plane RBAC role assignments exist for the NoSQL API
                try:
                    for ra in _list(cdb.sql_resources.list_sql_role_assignments(rg, acc.name)):
                        guid = _tail(_g(ra, "role_definition_id")).lower()
                        role = COSMOS_DATA_ROLES.get(guid, "Cosmos DB custom data role")
                        if _g(ra, "principal_id"):
                            data_grants.append((aid, str(_g(ra, "principal_id")), {"role": role}))
                except ReadOnlyViolation:
                    raise
                except Exception as exc:  # noqa: BLE001 - optional detail
                    if not role_errors:
                        role_errors = True
                        res.errors.append(f"{sub}/cosmosdb role assignments: {type(exc).__name__}: {exc}")

        step("cosmosdb", cosmos)

        def redis():
            rc = factory("redis", sub)
            for c in _list(rc.redis.list_by_subscription()):
                cid, rg = _norm_id(c.id), _rg(c.id)
                fw = []
                try:
                    fw = [{"name": r.name, "start_ip": _g(r, "start_ip"), "end_ip": _g(r, "end_ip")}
                          for r in _list(rc.firewall_rules.list(rg, c.name))]
                except ReadOnlyViolation:
                    raise
                except Exception as exc:  # noqa: BLE001
                    res.errors.append(f"{sub}/redis firewall {c.name}: {type(exc).__name__}: {exc}")
                pna = _s(_g(c, "public_network_access", default="")) or "Enabled"
                injected = _norm_id(_g(c, "subnet_id"))
                public = _enabled(pna) and not injected
                if public and not fw:
                    state, partial = "open", []  # no firewall rules: every address
                else:
                    state, partial = firewall_state(public, fw)
                non_ssl = bool(_g(c, "enable_non_ssl_port", default=False))
                aad = str(_g(c, "redis_configuration", "aad_enabled", default="")).lower() == "true"
                if aad:
                    try:
                        for pa in _list(rc.access_policy_assignment.list(rg, c.name)):
                            if _g(pa, "object_id"):
                                data_grants.append((cid, str(_g(pa, "object_id")),
                                                    {"role": f"Redis {_g(pa, 'access_policy_name') or 'access policy'}"}))
                    except ReadOnlyViolation:
                        raise
                    except Exception as exc:  # noqa: BLE001
                        res.errors.append(f"{sub}/redis access policies {c.name}: {type(exc).__name__}: {exc}")
                sens, cls = _sensitive_from_tags(c.tags)
                host = _g(c, "host_name") or f"{c.name}.redis.cache.windows.net"
                ports = ["6380"] + (["6379"] if non_ssl else [])
                add(AssetRecord(
                    id=cid, name=c.name, type="redis_cache", region=c.location, resource_group=rg,
                    tags=dict(c.tags or {}), internet_exposed=state == "open", sensitive_data=True, **base,
                    properties={"redis_version": _s(_g(c, "redis_version", default="")) or None,
                                "sku": _g(c, "sku", "name"), "non_ssl_port": non_ssl,
                                "min_tls_version": _s(_g(c, "minimum_tls_version", default="")) or None,
                                "public_network_access": pna, "vnet_injected_subnet": injected or None,
                                "firewall_rules": fw, "entra_auth": aad,
                                "access_key_auth_disabled": _bool(_g(c, "disable_access_key_authentication")),
                                "data_classification": cls or "cache",
                                **paas_common(cid, state, partial, f"public endpoint {host}", ports,
                                              controls=[f"Redis firewall ({len(fw)} rules)"] if fw else []),
                                "exposure": f"public endpoint {host} (no firewall rules)" if state == "open" else None}))
                identities(cid, c.name, _g(c, "identity"), c.location)

        step("redis", redis)

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
                methods_by_asset[cid] = [paas_method(
                    "public_endpoint", "public Kubernetes API server", ["443"],
                    "disabled" if private else "restricted" if ranges else "open",
                    [{"source": r, "rule": "authorized IP range"} for r in ranges])]
                identities(cid, mc.name, _g(mc, "identity"), mc.location)
                # The kubelet identity is what code on the nodes (pods) can obtain tokens for.
                kubelet = (_g(mc, "identity_profile", default={}) or {}).get("kubeletidentity")
                kid = _norm_id(_g(kubelet, "resource_id"))
                if kid:
                    rels.append(RelationshipRecord(cid, kid, "uses_identity", {"via": "kubelet"}))
                    if _g(kubelet, "object_id"):
                        principal_to_identity.setdefault(_g(kubelet, "object_id"), kid)

        step("aks", aks)

        # ----------------------------------------------------------- generic: managed identities, retired
        # Single Servers, and function apps when the App Service API could not be read
        def generic():
            rm = factory("resource", sub)
            for r in _list(rm.resources.list()):
                rtype = str(r.type or "").lower()
                kind = _s(_g(r, "kind", default="")).lower()
                rid = _norm_id(r.id)
                if rtype == "microsoft.web/sites" and "functionapp" in kind and rid not in assets:
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
                elif rtype in ("microsoft.dbforpostgresql/servers", "microsoft.dbformysql/servers"):
                    props: dict = {}
                    try:
                        props = _g(rm.resources.get_by_id(r.id, api_version="2017-12-01"), "properties",
                                   default={}) or {}
                    except ReadOnlyViolation:
                        raise
                    except Exception as exc:  # noqa: BLE001 - optional enrichment
                        log.debug("single server detail for %s unavailable: %s", r.id, exc)
                    pg = "postgresql" in rtype
                    _, cls = _sensitive_from_tags(r.tags)
                    add(AssetRecord(
                        id=rid, name=r.name, type="postgresql_server" if pg else "mysql_server", region=r.location,
                        resource_group=_rg(r.id), tags=dict(r.tags or {}), sensitive_data=True, **base,
                        properties={"deployment": "single", "version": props.get("version"),
                                    "public_network_access": props.get("publicNetworkAccess"),
                                    "require_secure_transport": _bool(props.get("sslEnforcement")),
                                    "min_tls_version": props.get("minimalTlsVersion"),
                                    "data_classification": cls or "database"}))
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

        step("resources", generic)

        # ----------------------------------------------------------- exposure: firewall DNAT, App Gateway
        # backends addressed by IP / FQDN, then the final exposure of every workload
        def finalize_exposure():
            for ip, entries in ilb_frontends.items():  # internal LB frontends -> their backends
                for pool, fport, bport, lb_name in entries:
                    for owner in pool_members.get(pool, ()):
                        ip_owner.setdefault(ip, []).append(
                            (owner, f"internal load balancer {lb_name}", {fport: bport}))
            for text, ports, target in appgw_addr_backends:
                owners = [o for o, _, _ in ip_owner.get(target, [])] or \
                    ([host_to_site[target]] if target in host_to_site else [])
                for owner in owners:
                    methods_by_asset.setdefault(owner, []).append(
                        {"kind": "app_gateway", "detail": text, "level": "open", "partial": [],
                         "ports": nsgeval.format_ports(nsgeval.parse_ports(sorted(ports)))})
            for fid, fw in firewalls.items():
                fw_methods = []
                for rule in fw["dnat"]:
                    if rule["source_kind"] not in ("internet", "partial"):
                        continue
                    level = "open" if rule["source_kind"] == "internet" else "restricted"
                    front = f"{rule['destination'] or ', '.join(fw['public_ips'])}:{','.join(rule['ports'])}"
                    partial = [{"source": s, "rule": rule["name"], "ports": rule["ports"]}
                               for s in rule["sources"] if nsgeval.classify_source(s) == "partial"]
                    fw_methods.append({"kind": "firewall_dnat_frontend", "level": level,
                                       "detail": f"Azure Firewall DNAT {front} -> "
                                                 f"{rule.get('translated_address') or rule.get('translated_fqdn')}:"
                                                 f"{rule.get('translated_port')}",
                                       "ports": rule["ports"] if level == "open" else [],
                                       "partial": partial if level == "restricted" else []})
                    tport = rule.get("translated_port")
                    tport = int(tport) if str(tport).isdigit() else None
                    targets = []
                    for owner, label, portmap in ip_owner.get(str(rule.get("translated_address") or ""), []):
                        port = portmap.get(tport) if portmap is not None else tport
                        if portmap is not None and port is None:
                            continue  # the internal LB does not forward that port
                        via_text = f" via {label}" if portmap is not None or "private endpoint" in label else ""
                        methods_by_asset.setdefault(owner, []).append({
                            "kind": "firewall_dnat", "level": level, "via": fid,
                            "detail": f"Azure Firewall {fw['name']} DNAT {front} -> "
                                      f"{rule['translated_address']}:{tport}{via_text}",
                            "ports": [str(port)] if level == "open" and port is not None else [],
                            "partial": partial if level == "restricted" else []})
                        rels.append(RelationshipRecord(fid, owner, "connects_to",
                                                       {"via": "DNAT", "ports": [port] if port is not None else [],
                                                        "public": front, "rule": rule["name"]}))
                        targets.append(owner)
                    rule["targets"] = [assets[t].name if t in assets else _tail(t) for t in dict.fromkeys(targets)]
                if fid in assets:
                    apply_exposure(assets[fid], fw_methods)
            paas = {"storage_account", "key_vault", "sql_server", "sql_managed_instance", "web_app", "function_app",
                    "postgresql_server", "mysql_server", "cosmos_account", "redis_cache", "aks_cluster"}
            for aid, methods in methods_by_asset.items():
                a = assets.get(aid)
                if a is None:
                    continue
                if a.type not in paas:
                    apply_exposure(a, methods)
                    continue
                # PaaS keep their own internet_exposed rule; a DNAT / App Gateway in front of them adds to it
                was_exposed, own_text = a.internet_exposed, a.properties.get("exposure")
                apply_exposure(a, methods, set_exposed=False)
                extra = [m for m in methods if m["level"] == "open" and m["kind"] in ("firewall_dnat", "app_gateway")]
                if extra:
                    a.internet_exposed = True
                    a.properties["exposure"] = "; ".join(filter(None, [own_text] + [m["detail"] for m in extra]))
                    if not was_exposed and all(m.get("via") for m in extra):
                        a.properties["exposed_only_via"] = sorted({m["via"] for m in extra})

        step("exposure", finalize_exposure)

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

        step("rbac", rbac)

        def access_policies():
            for vault_id, oid, summary in kv_policies:
                iid = principal_to_identity.get(oid)
                if iid in assets:
                    rels.append(RelationshipRecord(iid, vault_id, "has_access",
                                                   {"role": "Key Vault access policy", "permissions": summary}))
            # data-plane grants: Cosmos DB SQL roles, Redis access policies, Entra database administrators
            for store, oid, props in data_grants:
                iid = principal_to_identity.get(oid)
                if iid in assets and store in assets:
                    rels.append(RelationshipRecord(iid, store, "has_access", {**props, "scope": "resource"}))

        step("keyvault/access-policies", access_policies)

        res.assets.extend(assets.values())
        # drop edges to unknown nodes (e.g. NSG on another subscription) and merge duplicates
        res.relationships.extend(_dedupe(r for r in rels if r.source_id in assets and r.target_id in assets))
