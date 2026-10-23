"""Azure rules for Azure Firewall, private endpoints, App Service and managed databases.

They read the normalized properties the Azure connector writes (see
`connectors/azure.py`); the classic Azure rules (storage, NSG, VM, SQL, Key
Vault, AKS...) live in `posture.py`. Unknown values (None, e.g. a setting the
Reader role cannot read) never raise a finding.
"""
from __future__ import annotations

import re

from . import eol
from .posture import _p, rule

MGMT_PORTS = {22: "SSH", 3389: "RDP", 5985: "WinRM", 5986: "WinRM"}
DB_PORTS = {1433: "SQL Server", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 6380: "Redis",
            27017: "MongoDB", 10255: "Cosmos DB (MongoDB)", 9200: "Elasticsearch", 445: "SMB"}


def tls_below_12(v) -> bool | None:
    """True for TLS 1.0 / 1.1 / no minimum, False for 1.2+, None if unknown."""
    if v is None or str(v).strip() == "":
        return None
    s = str(v).strip().lower().replace("_", ".").replace("tlsv", "").replace("tls", "").strip(". ")
    if s in {"none", "", "1", "1.0", "10", "1.1", "11"}:
        return True
    m = re.match(r"(\d)\.?(\d)?", s)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2) or 0)) < (1, 2)


def _public_despite_pe(a):
    pes = _p(a, "private_endpoints") or []
    state = _p(a, "public_endpoint")
    if pes and state in ("open", "restricted"):
        return {"private_endpoints": pes, "public_endpoint": state,
                "public_network_access": _p(a, "public_network_access")}
    return None


def _pe_rule(id_: str, resource_type: str, label: str, compliance: list[str]) -> None:
    rule(id=id_, title=f"{label}: public access still enabled despite private endpoint", severity="medium",
         resource_type=resource_type,
         description="The resource has a private endpoint but still accepts traffic on its public endpoint, "
         "so it stays reachable from the internet (as far as its firewall allows).",
         remediation="Disable public network access once clients use the private endpoint.",
         compliance=compliance)(_public_despite_pe)


# --------------------------------------------------------------------------- Azure Firewall
def _dnat_from_any(a, ports: dict[int, str]):
    hits = []
    for r in _p(a, "dnat_rules") or []:
        if r.get("source_kind") != "internet":
            continue
        tport = r.get("translated_port")
        if str(tport).isdigit() and int(tport) in ports:
            hits.append({"rule": r.get("name"), "collection": r.get("collection"),
                         "public": f"{r.get('destination')}:{','.join(r.get('ports') or [])}",
                         "translated": f"{r.get('translated_address')}:{tport}", "service": ports[int(tport)]})
    return {"dnat_rules": hits} if hits else None


@rule(id="AZ-FW-001", title="Azure Firewall DNAT forwards a management port from any source", severity="high",
      resource_type="azure_firewall",
      description="A DNAT rule translates traffic from any internet source to SSH, RDP or WinRM on a private host.",
      remediation="Remove the DNAT rule and use Azure Bastion / JIT access, or restrict its source addresses.",
      compliance=["Azure MCSB NS-1", "CIS Azure 6.1", "CIS Azure 6.2"])
def _fw_dnat_mgmt(a):
    return _dnat_from_any(a, MGMT_PORTS)


@rule(id="AZ-FW-002", title="Azure Firewall DNAT forwards a database port from any source", severity="high",
      resource_type="azure_firewall",
      description="A DNAT rule translates traffic from any internet source to a database or file-sharing port.",
      remediation="Remove the DNAT rule or restrict its source addresses; use private endpoints for data stores.",
      compliance=["Azure MCSB NS-1"])
def _fw_dnat_db(a):
    return _dnat_from_any(a, DB_PORTS)


@rule(id="AZ-FW-003", title="Azure Firewall threat intelligence is off", severity="medium",
      resource_type="azure_firewall",
      description="Threat-intelligence based filtering (known malicious IPs and domains) is disabled.",
      remediation="Set threat intelligence mode to Alert and deny (or at least Alert) on the firewall policy.",
      compliance=["Azure MCSB NS-10"])
def _fw_ti(a):
    mode = str(_p(a, "threat_intel_mode") or "").lower()
    return {"threat_intel_mode": _p(a, "threat_intel_mode")} if mode == "off" else None


@rule(id="AZ-FW-004", title="Azure Firewall uses classic rules instead of a Firewall Policy", severity="low",
      resource_type="azure_firewall",
      description="Classic rule collections cannot use policy features (premium IDPS, TLS inspection, "
      "inheritance) and are being superseded.",
      remediation="Migrate the classic rules to an Azure Firewall Policy and associate it with the firewall.",
      compliance=["Azure MCSB NS-1"])
def _fw_classic(a):
    if _p(a, "policy_id") or _p(a, "virtual_hub"):
        return None
    return {"firewall_policy": None} if _p(a, "classic_rule_count", 0) else None


@rule(id="AZ-FW-005", title="Azure Firewall network rule allows any source to any port", severity="medium",
      resource_type="azure_firewall",
      description="An Allow network rule accepts any source address on every destination port.",
      remediation="Replace the any/any rule with rules for the required sources, destinations and ports.",
      compliance=["Azure MCSB NS-1"])
def _fw_anyany(a):
    hits = [r.get("name") for r in _p(a, "network_rules") or []
            if str(r.get("action", "allow")).lower() == "allow" and r.get("source_kind") == "internet"
            and "*" in (r.get("ports") or [])]
    return {"rules": hits} if hits else None


@rule(id="AZ-FW-006", title="Premium Azure Firewall has IDPS turned off", severity="low",
      resource_type="azure_firewall",
      description="The firewall runs the Premium SKU but its policy's intrusion detection and prevention is off.",
      remediation="Set the firewall policy's IDPS mode to Alert or Alert and deny.",
      compliance=["Azure MCSB NS-10"])
def _fw_idps(a):
    if str(_p(a, "sku_tier") or "").lower() != "premium":
        return None
    mode = str(_p(a, "idps_mode") or "").lower()
    return {"idps_mode": _p(a, "idps_mode") or "Off"} if mode in ("off", "") and _p(a, "policy_id") else None


# --------------------------------------------------------------------------- data stores + private endpoints
_pe_rule("AZ-STG-004", "storage_account", "Storage account", ["CIS Azure 3.10"])
_pe_rule("AZ-SQL-004", "sql_server", "SQL server", ["CIS Azure 4.1.2"])
_pe_rule("AZ-KV-003", "key_vault", "Key Vault", ["CIS Azure 8.7"])


@rule(id="AZ-SQL-005", title="SQL server minimum TLS version below 1.2", severity="medium",
      resource_type="sql_server", description="Clients can connect with deprecated TLS 1.0/1.1.",
      remediation="az sql server update -n <name> -g <rg> --minimal-tls-version 1.2",
      compliance=["CIS Azure 4.1.x", "Azure MCSB DP-3"])
def _sql_tls(a):
    return {"min_tls_version": _p(a, "min_tls_version")} if tls_below_12(_p(a, "min_tls_version")) else None


@rule(id="AZ-KV-004", title="Key Vault is reachable from all networks", severity="medium", resource_type="key_vault",
      description="Public network access is enabled and the vault firewall allows every network.",
      remediation="Set the vault firewall to deny by default and use private endpoints or selected networks.",
      compliance=["CIS Azure 8.7"])
def _kv_open(a):
    return {"public_endpoint": "open"} if _p(a, "public_endpoint") == "open" else None


# --------------------------------------------------------------------------- App Service (web + function apps)
def _app_rules(prefix: str, rtype: str, label: str) -> None:
    def add(num: str, title: str, severity: str, description: str, remediation: str, compliance: list[str],
            weakness: bool = False):
        def deco(fn):
            rule(id=f"{prefix}-{num}", title=f"{label} {title}", severity=severity, resource_type=rtype,
                 description=description, remediation=remediation, compliance=compliance,
                 weakness=weakness)(fn)
            return fn
        return deco

    if prefix == "AZ-APP":  # AZ-FN-001 (function app HTTPS) already exists in posture.py
        add("001", "does not enforce HTTPS", "medium", "The app accepts plain-HTTP requests.",
            "az webapp update -n <name> -g <rg> --https-only true", ["CIS Azure 9.2"])(
            lambda a: {"https_only": False} if _p(a, "https_only") is False else None)

    add("002", "minimum TLS version below 1.2", "medium", "Clients can negotiate deprecated TLS 1.0/1.1.",
        "az webapp config set -n <name> -g <rg> --min-tls-version 1.2", ["CIS Azure 9.3"])(
        lambda a: {"min_tls_version": _p(a, "min_tls_version")} if tls_below_12(_p(a, "min_tls_version")) else None)

    add("003", "allows unencrypted FTP deployments", "medium",
        "FTP state is 'AllAllowed': credentials and content can be sent in clear text.",
        "Set FTP state to Disabled (or FTPS only): az webapp config set --ftps-state Disabled",
        ["CIS Azure 9.10"])(
        lambda a: {"ftps_state": _p(a, "ftps_state")} if str(_p(a, "ftps_state") or "").lower() == "allallowed"
        else None)

    add("004", "does not use HTTP/2", "low", "HTTP/2 is disabled.",
        "az webapp config set -n <name> -g <rg> --http20-enabled true", ["CIS Azure 9.9"])(
        lambda a: {"http20_enabled": False} if _p(a, "http20_enabled") is False else None)

    add("005", "has no managed identity", "low",
        "Without a managed identity the app needs stored credentials to reach other Azure services.",
        "Assign a system- or user-assigned managed identity and use it instead of secrets.", ["CIS Azure 9.5"])(
        lambda a: {"managed_identity": False} if _p(a, "managed_identity") is False else None)

    add("006", "has remote debugging enabled", "high",
        "Remote debugging opens additional ports and lets a debugger attach to the running app.",
        "az webapp config set -n <name> -g <rg> --remote-debugging-enabled false", ["Azure MCSB PV-2"])(
        lambda a: {"remote_debugging": True} if _p(a, "remote_debugging") else None)

    add("007", "SCM (Kudu) site is not access-restricted", "medium",
        "The internet-facing app's deployment (SCM / Kudu) endpoint accepts requests from any address.",
        "Add SCM access restrictions (or 'use main site rules' with restricted main rules) and disable basic "
        "publishing credentials.", ["Azure MCSB NS-2"])(
        lambda a: {"scm_access": "open"} if _p(a, "public_endpoint") == "open" and _p(a, "scm_access") == "open"
        else None)

    add("008", "is internet-facing without App Service authentication", "medium",
        "The app is reachable from the internet and App Service Authentication (Easy Auth) is not enabled.",
        "Enable App Service Authentication, or confirm the app authenticates users itself.", ["CIS Azure 9.1"])(
        lambda a: {"auth_enabled": False} if _p(a, "public_endpoint") == "open" and _p(a, "auth_enabled") is False
        else None)

    def _eol(a):
        hits = eol.eol_runtimes(_p(a, "runtime_config") or {})
        if not hits:
            return None
        worst = min(hits, key=lambda h: h["eol_date"])
        return {"_title": f"Runtime {worst['runtime']} is end-of-life since {worst['eol_date']}",
                "runtimes": hits}

    add("009", "runs an end-of-life runtime", "high",
        "The language runtime no longer receives security fixes (end-of-life per endoflife.date).",
        "Upgrade the app to a supported runtime version (Configuration > General settings > Stack).",
        ["CIS Azure 9.6", "CIS Azure 9.7", "CIS Azure 9.8"], weakness=True)(_eol)

    add("010", "does not require client certificates", "low",
        "Incoming client certificates are not requested.",
        "Enable client certificates (Required / Optional interactive user) where clients can present them.",
        ["CIS Azure 9.4"])(
        lambda a: {"client_cert_enabled": False} if _p(a, "client_cert_enabled") is False
        and _p(a, "public_endpoint") == "open" else None)

    _pe_rule(f"{prefix}-011", rtype, label, ["Azure MCSB NS-2"])


_app_rules("AZ-APP", "web_app", "Web app")
_app_rules("AZ-FN", "function_app", "Function app")


# --------------------------------------------------------------------------- PostgreSQL / MySQL
def _allow_all(a):
    bad = [r.get("name") for r in _p(a, "firewall_rules") or []
           if r.get("start_ip") == "0.0.0.0" and r.get("end_ip") == "255.255.255.255"]
    return {"rules": bad} if bad and _p(a, "public_endpoint") == "open" else None


def _azure_services(a):
    bad = [r.get("name") for r in _p(a, "firewall_rules") or []
           if r.get("start_ip") == "0.0.0.0" and r.get("end_ip") == "0.0.0.0"]
    return {"rules": bad} if bad and _p(a, "public_endpoint") in ("open", "restricted") else None


def _db_rules(prefix: str, rtype: str, label: str, engine: str, cis: str) -> None:
    def add(num, title, severity, description, remediation, compliance, fn, weakness=False):
        rule(id=f"{prefix}-{num}", title=f"{label} {title}", severity=severity, resource_type=rtype,
             description=description, remediation=remediation, compliance=compliance, weakness=weakness)(fn)

    add("001", "firewall allows all IPs (0.0.0.0-255.255.255.255)", "critical",
        "Public access is enabled and a firewall rule admits the entire IPv4 internet.",
        "Delete the rule; allow specific client IPs or use private access (VNet) / private endpoints.",
        [f"CIS Azure {cis}"], _allow_all)
    add("002", "allows access from all Azure services", "medium",
        "The 0.0.0.0 'Allow Azure services' rule admits connections from any Azure tenant's resources.",
        "Remove the rule and allow only the required addresses, or use private access.",
        [f"CIS Azure {cis}"], _azure_services)
    add("003", "does not enforce TLS (require_secure_transport off)", "medium",
        "Clients can connect without encryption.", "Set the server parameter require_secure_transport to ON.",
        [f"CIS Azure {cis}"],
        lambda a: {"require_secure_transport": False} if _p(a, "require_secure_transport") is False else None)
    add("004", "minimum TLS version below 1.2", "medium", "Clients can negotiate deprecated TLS 1.0/1.1.",
        "Set the minimum TLS server parameter to TLS 1.2 or later.", [f"CIS Azure {cis}"],
        lambda a: {"min_tls_version": _p(a, "min_tls_version")} if tls_below_12(_p(a, "min_tls_version")) else None)
    add("005", "backups are not geo-redundant", "low",
        "A regional outage could make backups unavailable.",
        "Enable geo-redundant backup (set at server creation; restore into a new geo-redundant server).",
        ["Azure MCSB BR-1"],
        lambda a: {"geo_redundant_backup": False} if _p(a, "geo_redundant_backup") is False else None)
    add("006", "has no Microsoft Entra authentication", "low",
        "Only password (local) authentication is configured.",
        "Configure Microsoft Entra authentication and an Entra administrator.", [f"CIS Azure {cis}"],
        lambda a: {"entra_auth": False} if _p(a, "entra_auth") is False else None)

    def _eol(a):
        ev = eol.eol_check(engine, _p(a, "version"))
        if not ev:
            return None
        return {"_title": f"{label} engine {ev['runtime']} is end-of-life since {ev['eol_date']}", **ev}

    add("007", "engine version is end-of-life", "high",
        "The database engine version no longer receives community security fixes (endoflife.date).",
        "Upgrade the server to a supported major version.", ["Azure MCSB PV-6"], _eol, weakness=True)
    add("008", "is a retired Single Server", "high",
        "Azure Database Single Server is retired and no longer receives updates.",
        "Migrate to Flexible Server.", ["Azure MCSB PV-6"],
        lambda a: {"deployment": "single"} if _p(a, "deployment") == "single" else None)
    _pe_rule(f"{prefix}-009", rtype, label, [f"CIS Azure {cis}"])


_db_rules("AZ-PG", "postgresql_server", "PostgreSQL server", "postgresql", "4.3.x")
_db_rules("AZ-MYSQL", "mysql_server", "MySQL server", "mysql", "4.4.x")


# --------------------------------------------------------------------------- Cosmos DB
@rule(id="AZ-COSMOS-001", title="Cosmos DB account accepts connections from all networks", severity="high",
      resource_type="cosmos_account",
      description="Public network access is enabled without IP or virtual-network filters.",
      remediation="Configure the Cosmos DB firewall (selected networks) or disable public access and use "
      "private endpoints.", compliance=["CIS Azure 4.5.1"])
def _cosmos_open(a):
    return {"public_endpoint": "open"} if _p(a, "public_endpoint") == "open" else None


@rule(id="AZ-COSMOS-002", title="Cosmos DB account allows key (local) authentication", severity="medium",
      resource_type="cosmos_account",
      description="Account keys grant full data access; Entra ID RBAC cannot be enforced while they work.",
      remediation="Set disableLocalAuth=true and grant Cosmos DB data-plane roles to identities.",
      compliance=["CIS Azure 4.5.3"])
def _cosmos_local(a):
    return {"local_auth_disabled": False} if _p(a, "local_auth_disabled") is False else None


@rule(id="AZ-COSMOS-003", title="Cosmos DB minimum TLS version below 1.2", severity="medium",
      resource_type="cosmos_account", description="Clients can negotiate deprecated TLS 1.0/1.1.",
      remediation="Set minimalTlsVersion to Tls12.", compliance=["Azure MCSB DP-3"])
def _cosmos_tls(a):
    return {"min_tls_version": _p(a, "min_tls_version")} if tls_below_12(_p(a, "min_tls_version")) else None


@rule(id="AZ-COSMOS-004", title="Cosmos DB periodic backups are not geo-redundant", severity="low",
      resource_type="cosmos_account", description="Periodic backups are kept in locally or zone-redundant storage.",
      remediation="Set backup storage redundancy to Geo, or use continuous backup.", compliance=["Azure MCSB BR-1"])
def _cosmos_backup(a):
    if str(_p(a, "backup_type") or "").lower() != "periodic":
        return None
    red = _p(a, "backup_redundancy")
    return {"backup_redundancy": red} if red and str(red).lower() != "geo" else None


_pe_rule("AZ-COSMOS-005", "cosmos_account", "Cosmos DB account", ["CIS Azure 4.5.2"])


# --------------------------------------------------------------------------- Azure Cache for Redis
@rule(id="AZ-REDIS-001", title="Redis cache non-TLS port (6379) is enabled", severity="high",
      resource_type="redis_cache", description="Clients can connect without encryption on port 6379.",
      remediation="Disable the non-SSL port: az redis update -n <name> -g <rg> --set enableNonSslPort=false",
      compliance=["Azure MCSB DP-3"])
def _redis_ssl(a):
    return {"non_ssl_port": True} if _p(a, "non_ssl_port") else None


@rule(id="AZ-REDIS-002", title="Redis cache minimum TLS version below 1.2", severity="medium",
      resource_type="redis_cache", description="Clients can negotiate deprecated TLS 1.0/1.1.",
      remediation="Set the minimum TLS version to 1.2.", compliance=["Azure MCSB DP-3"])
def _redis_tls(a):
    return {"min_tls_version": _p(a, "min_tls_version")} if tls_below_12(_p(a, "min_tls_version")) else None


@rule(id="AZ-REDIS-003", title="Redis cache accepts connections from all networks", severity="high",
      resource_type="redis_cache",
      description="Public network access is enabled with no firewall rules (or an allow-all rule).",
      remediation="Add firewall rules, or disable public network access and use private endpoints.",
      compliance=["Azure MCSB NS-2"])
def _redis_open(a):
    return {"public_endpoint": "open"} if _p(a, "public_endpoint") == "open" else None


@rule(id="AZ-REDIS-004", title="Redis cache allows access-key authentication", severity="low",
      resource_type="redis_cache", description="Access keys grant full access; Entra ID cannot be enforced.",
      remediation="Enable Microsoft Entra authentication and disable access-key authentication.",
      compliance=["Azure MCSB IM-1"])
def _redis_keys(a):
    return {"access_key_auth_disabled": False} if _p(a, "access_key_auth_disabled") is False else None


@rule(id="AZ-REDIS-005", title="Redis cache version is end-of-life", severity="high", resource_type="redis_cache",
      description="The Redis version is retired on Azure Cache for Redis (endoflife.date).",
      remediation="Upgrade the cache to Redis 6 or later.", compliance=["Azure MCSB PV-6"], weakness=True)
def _redis_eol(a):
    ev = eol.eol_check("redis", _p(a, "redis_version"))
    return {"_title": f"Redis cache engine {ev['runtime']} is end-of-life since {ev['eol_date']}", **ev} if ev else None


_pe_rule("AZ-REDIS-006", "redis_cache", "Redis cache", ["Azure MCSB NS-2"])


# --------------------------------------------------------------------------- SQL Managed Instance
@rule(id="AZ-SQLMI-001", title="SQL Managed Instance public endpoint is open to the internet", severity="high",
      resource_type="sql_managed_instance",
      description="The public data endpoint (TCP 3342) is enabled and the subnet NSG admits it from any address.",
      remediation="Disable the public data endpoint or restrict the NSG rule for port 3342 to known sources.",
      compliance=["CIS Azure 4.1.2"])
def _mi_public(a):
    return {"public_endpoint": "open"} if _p(a, "public_endpoint") == "open" else None


@rule(id="AZ-SQLMI-002", title="SQL Managed Instance minimum TLS version below 1.2", severity="medium",
      resource_type="sql_managed_instance", description="Clients can negotiate deprecated TLS 1.0/1.1.",
      remediation="Set the minimal TLS version to 1.2.", compliance=["Azure MCSB DP-3"])
def _mi_tls(a):
    return {"min_tls_version": _p(a, "min_tls_version")} if tls_below_12(_p(a, "min_tls_version")) else None


@rule(id="AZ-SQLMI-003", title="SQL Managed Instance allows SQL authentication", severity="low",
      resource_type="sql_managed_instance", description="Microsoft Entra-only authentication is disabled.",
      remediation="Enable Microsoft Entra-only authentication.", compliance=["CIS Azure 4.1.x"])
def _mi_entra(a):
    return {"entra_only": False} if _p(a, "entra_only") is False else None
