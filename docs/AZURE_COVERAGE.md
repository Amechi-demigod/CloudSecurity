# Azure scanner: coverage, exposure model and permissions

The Azure connector (`backend/app/connectors/azure.py`) is read-only: every SDK client is wrapped in
`ReadOnlyClient`, which only lets `list*` / `get*` operations through and additionally blocks reads that return
secrets (storage / Cosmos DB / Redis keys, SAS, publishing profiles, app settings, connection strings, Easy Auth
settings *with* secrets, function keys and admin tokens). The single exception is
`web_apps.get_auth_settings_v2_without_secrets`, which is explicitly secret-free. The built-in **Reader** role is
sufficient for everything below.

## Coverage

| Resource | SDK / API | Inventory and exposure | Rules |
|---|---|---|---|
| Network security groups | azure-mgmt-network | Rules with priority, Allow/Deny, protocol, port ranges and lists, plural (augmented) prefixes, source/destination application security groups, destination prefixes; Azure default rules added | AZ-NSG-001 SSH, -002 RDP, -003 all ports open to the internet, -004 management ports open to public ranges only (partial) |
| Virtual networks, subnets, route tables | azure-mgmt-network | `vnet` assets with subnets (NSG, route table, `0.0.0.0/0` next hop, delegations); forced tunnelling recorded as `egress` on VMs / scale sets (outbound only: never counted as inbound protection) | – |
| VMs, scale sets | azure-mgmt-compute + network | Effective internet-reachable ports per NIC (subnet NSG, then NIC NSG; both must allow): public IP (Standard SKU without NSG = closed, Basic = open), public load balancer rules / inbound NAT rules / NAT pools (backend ports filtered by the NSGs), Application Gateway backends (NIC, IP or FQDN; the gateway's subnet is the source, so Internet NSG rules do not apply), Azure Firewall DNAT | AZ-VM-001/002, AZ-VMSS-001/002 |
| Azure Firewall + Firewall Policy | azure-mgmt-network | Firewalls (public / private IPs, SKU, threat intel, classic rule collections), policies (rule collection groups, base-policy inheritance, threat intel, IDPS). DNAT rules map public IP:port to the translated private IP:port and resolve the owner: VM NIC, internal load balancer frontend (to its VM / scale-set backends and backend port) or private endpoint (to the PaaS resource). Those backends are exposed *via* the firewall and get a `firewall -connects_to-> backend` edge | AZ-FW-001 DNAT to SSH/RDP/WinRM from any source, -002 DNAT to database ports from any source, -003 threat intelligence off, -004 classic rules without policy, -005 any-source/any-port network rule, -006 Premium without IDPS |
| Private endpoints | azure-mgmt-network | `private_endpoint` assets (subnet, VNet, private IPs, target, group ids, approval state); `vnet -contains-> endpoint -connects_to-> target` | per type "public access still enabled despite private endpoint": AZ-STG-004, AZ-SQL-004, AZ-KV-003, AZ-APP-011, AZ-FN-011, AZ-PG-009, AZ-MYSQL-009, AZ-COSMOS-005, AZ-REDIS-006 |
| Storage accounts | azure-mgmt-storage | Public endpoint state (disabled / open / restricted to IP rules / closed), private endpoints. Attack-path entry only with anonymous blob access, as before | AZ-STG-001..004 |
| Key Vault | azure-mgmt-keyvault | Public endpoint state from `networkAcls`, private endpoints, access policies | AZ-KV-001..004 |
| Azure SQL | azure-mgmt-sql | Firewall rules, public access, private endpoints, minimum TLS, Entra-only auth, Entra admin -> `has_access` | AZ-SQL-001..005 |
| SQL Managed Instance | azure-mgmt-sql | Public data endpoint (TCP 3342) evaluated against the subnet NSG, minimum TLS, Entra-only auth, Entra admin -> `has_access` | AZ-SQLMI-001..003 |
| App Service web apps + function apps | azure-mgmt-web | Plans, apps, slots (names), `publicNetworkAccess`, access restrictions for the main and SCM sites (priority, first match, default action, VNet rules, Front Door service tag), private endpoints, client certificates, Easy Auth state, identities, runtime stack | AZ-APP-001..011 (web apps) and AZ-FN-001..011 (function apps): HTTPS only, TLS 1.2, FTP, HTTP/2, managed identity, remote debugging, SCM restricted, authentication on internet-facing apps, **end-of-life runtime**, client certificates, private endpoint |
| PostgreSQL flexible server (+ retired single server) | azure-mgmt-postgresqlflexibleservers (single: generic resource read) | Public access vs. VNet integration, firewall rules, `require_secure_transport`, `ssl_min_protocol_version`, backups, Entra auth + admins -> `has_access`, version | AZ-PG-001..009 (allow-all, Azure services, TLS enforcement, min TLS, geo backup, Entra auth, **engine EOL**, single server retired, private endpoint) |
| MySQL flexible server (+ retired single server) | azure-mgmt-mysqlflexibleservers | Same as PostgreSQL (`tls_version`, Entra administrators) | AZ-MYSQL-001..009 |
| Cosmos DB | azure-mgmt-cosmosdb | Public access, IP rules (`0.0.0.0` = Azure datacenters), VNet filter, private endpoints, local (key) auth, min TLS, backup redundancy; NoSQL data-plane role assignments -> `has_access` | AZ-COSMOS-001..005 |
| Azure Cache for Redis | azure-mgmt-redis | Public access, VNet injection, firewall rules, non-TLS port, min TLS, access-key auth, Entra access policy assignments -> `has_access`, version | AZ-REDIS-001..006 |

Databases are sensitive by default (`sensitive_data=True`); `data_classification` comes from tags
(`data_classification`, `classification`, `sensitivity`...). New data stores are attack-path targets.

### End-of-life table

`backend/app/engine/eol.py` bundles end-of-life dates from [endoflife.date](https://endoflife.date) for PHP,
Node.js, Python, .NET, Ruby, PowerShell, Java 7, PostgreSQL, MySQL and Redis on Azure. No network call is made; update
the table when versions reach end of life. Runtimes are read from `linuxFxVersion` / `windowsFxVersion` /
`netFrameworkVersion` (v5+) / `phpVersion` / `pythonVersion` / `nodeVersion` / `powerShellVersion` / `javaVersion`.
EOL findings have a specific title ("Runtime PHP 7.4 is end-of-life since 2022-11-28") and count as exploitable
weaknesses on any attack-path hop, like an in-use CVE. Each scan also records them as **Vulnerability** rows (`source = eol`, id
`EOL-<STACK>-<version>`, e.g. `EOL-PHP-7.4`, CVSS 7.5, in use) so they appear on the Vulnerabilities page with
the asset's runtime context; a row resolves when the app or server is upgraded.

## Exposure model

Each asset carries:

- `exposure_methods`: `{kind, detail, ports, level}` with kind `public_ip`, `load_balancer`, `lb_nat`, `app_gateway`,
  `firewall_dnat`, `public_endpoint`, `app_service`; level `open` (whole internet), `restricted` (only listed public
  ranges, shown with the CIDR) or `blocked` (e.g. a public IP no NSG rule admits);
- `effective_ports`, `partial_exposure`, `exposure_level`, `network_controls`, `private_endpoints`,
  `public_endpoint` (`open` / `restricted` / `closed` / `disabled`), `exposed_only_via` (e.g. the firewall).

A resource with public network access disabled (or a firewall that admits no public range) and reachable only
through private endpoints is **not** internet-exposed. A resource that still has public access enabled stays exposed
even with a private endpoint, and gets the "public access still enabled despite private endpoint" finding.

**Exposure view**: `GET /api/exposure?provider=&subscription=&type=&port=&level=` lists every open or restricted
asset across Azure, AWS and GCP with how it is reached, effective ports, protecting controls, private endpoints and
linked findings, vulnerabilities and attack paths; `GET /api/exposure/summary` feeds the dashboard tile. The console
page is **Exposure**.

## Permissions

Reader on each subscription (or a management group above them) is enough. What Reader cannot see, or what the
scanner deliberately does not read:

- Secrets of any kind (keys, connection strings, app settings, publishing credentials, Easy Auth client secrets):
  blocked by `ReadOnlyClient` even if the role allowed them.
- Easy Auth state comes from `get_auth_settings_v2_without_secrets`. If a tenant policy denies it, the auth state is
  unknown: the error is recorded on the scan run and AZ-APP-008 / AZ-FN-008 do not fire.
- Azure Firewall diagnostic settings (Microsoft.Insights) are not read, so "no diagnostics" is not checked.
- IP groups referenced by firewall rules are not expanded (a rule using only IP groups is not treated as
  internet-sourced).
- Firewall rules of retired Single Servers are not read (only version, SSL enforcement, TLS and public access).

A service that fails (missing permission, `MissingSubscriptionRegistration` because the resource provider is not
registered, API not available) is recorded in the scan run's errors and the rest of the scan continues.
After upgrading, run a new scan (**Connectors & scans -> Run scan**) to populate the new resource types.

## Remaining limits

- Per-instance NICs of Flexible-orchestration scale sets and VMSS instance private IPs are not listed (DNAT to a
  scale set is resolved through its internal load balancer).
- Multi-NIC VMs: ports are combined across NICs; attack-path attribution intersects NIC and subnet levels.
- Application Gateway listener-to-backend routing and WAF policies are not evaluated (all backend HTTP settings ports
  are considered reachable); private Application Gateway frontends are not DNAT targets.
- Azure Firewall network/application rules are reported (any-to-any rule finding) but not used to mark backends
  exposed: without DNAT the internet cannot initiate connections through the firewall. Route tables are informational.
- Custom role permissions and App Service Environment (ILB ASE) reachability are not interpreted.
- Easy Auth on deployment slots and per-slot access restrictions are not evaluated.
