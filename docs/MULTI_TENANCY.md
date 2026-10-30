# Multi-tenant organisations

One deployment serves many customer **organisations** with strict data
isolation. Each organisation has its own users, devices and agents, enrollment
tokens, runtime-sensor tokens, cloud connector settings and credentials, scans,
findings, vulnerabilities, attack paths and exposure, assets, IT assets,
notification channels and rules, device scripts runs and approvals, schedules,
settings and audit log.

An installation that existed before this feature keeps working unchanged: all
its data is migrated into the **default organisation** automatically, and the
environment-based settings (`AZURE_*`, `AWS_*`, `GCP_*`, `INGEST_API_TOKEN`,
`ENTRA_*`, `SIMULATION_MODE`) keep applying to that organisation.

- [Model](#model)
- [Isolation guarantees](#isolation-guarantees)
- [Machine credentials](#machine-credentials)
- [Background jobs](#background-jobs)
- [Per-organisation cloud connectors](#per-organisation-cloud-connectors)
- [Platform owners](#platform-owners)
- [Onboarding a new organisation](#onboarding-a-new-organisation)
- [Email for invitations](#email-for-invitations)
- [Upgrading an existing installation](#upgrading-an-existing-installation)
- [Limits and deferred items](#limits-and-deferred-items)

## Model

| Table | Scope | Notes |
|---|---|---|
| `organizations` | platform | name, slug (unique), contact email, optional logo URL, status `active` / `suspended`, plan and limit fields for later (not enforced yet), `is_default` |
| `users` | platform | an account; **email addresses are unique on the platform**; `is_platform_admin` |
| `organization_memberships` | organisation | (organisation, user, role); version 1 allows one membership per user (enforced by the application), the table already supports several |
| `organization_invitations` | organisation | email invitations (single-use, expiring token; only its SHA-256 is stored) |
| `user_sessions` | platform | every login session acts in one organisation (`organization_id`) |
| everything a customer owns | organisation | `organization_id` NOT NULL, indexed, foreign key to `organizations` |
| CVE / KEV / EPSS caches and feed status, signed agent releases, signed device-script bundles, MFA secrets, SSO identities, OIDC requests | platform | global reference data |

Roles (`viewer`, `analyst`, `admin`) are per organisation and live on the
membership. A request's user gets the role of the membership its session was
opened with.

**Natural keys.** Cloud resource ids (Azure ARM ids, AWS ARNs, GCP resource
names, sensor host ids) and sensor-supplied event ids were primary keys. Two
organisations may legitimately scan the same subscription, or one sensor could
reuse another's event id, so these tables now have **composite primary keys**
`(organization_id, id)` (`assets`, `runtime_events`) and every table that
references them has a **composite foreign key** `(organization_id, asset_id)`
(findings, vulnerabilities, relationships, asset packages, alert events). A row
can therefore never reference another organisation's asset, even through a bug.
Uniqueness that was global now includes the organisation: findings per (rule,
asset), relationship edges, vulnerability-match state, update ring names and IT
asset tags. Server-generated ids (UUIDs) stay single-column. Single-row
settings tables (scan schedule, agent-update automation, IT asset settings) and
the notification poller state are keyed by organisation.

## Isolation guarantees

Scoping is enforced centrally in the ORM (`backend/app/tenancy.py`), not by hand
in each query:

1. **Every database session has a mode.** *Organisation* mode
   (`db.get_session(org_id)`, or a request after authentication): every ORM
   `SELECT`, `UPDATE` and `DELETE` that touches a tenant table gets
   `organization_id = :org` added through `with_loader_criteria`, including
   joins, eager and lazy relationship loads, subqueries, `Session.get` and bulk
   ORM updates/deletes. *Unscoped* mode (`db.get_session(unscoped=True)`) is
   explicit, for platform and system code (resolving a credential to its
   organisation, the platform console, global feeds). A session with **no
   context refuses** any statement on a tenant table (`TenancyError`): code
   that forgets to choose fails closed instead of reading or writing across
   organisations.
2. **Writes are stamped and checked.** New tenant rows get the session's
   organisation on flush; inserting, updating or deleting a row of another
   organisation, or changing a row's organisation, raises `TenancyError`.
3. **Requests are scoped by the authenticated principal**: the user's session
   (`auth.current_session`), the device credential or enrollment token
   (endpoint agents), the ingest token (runtime sensors). Objects of another
   organisation are simply not found (404), never "forbidden" (no existence
   oracle).
4. **Defense in depth in the schema**: composite foreign keys keep references
   inside one organisation; `organization_id` is NOT NULL with a foreign key
   everywhere.

User accounts are platform-wide, so the few endpoints that address a user by id
(update, reset password / MFA) go through the scoped membership
(`auth.org_user`).

The filter applies to ORM statements; raw SQL (`text()`) and Core statements on
`Table` objects would bypass it, so application code does not use them on
tenant tables (the migrations are the exception).

**PostgreSQL row-level security** is not enabled in this version: the
application connects with one database role, and RLS policies keyed on a
per-transaction setting would duplicate the ORM guard without protecting against
a compromised application. It is listed under [deferred items](#limits-and-deferred-items).

The cross-tenant test-suite (`backend/tests/test_tenancy.py`) creates two
organisations and checks every main list, get, update and delete endpoint, the
agent and sensor APIs, the background jobs, suspension, the per-organisation
connector settings and the ORM guard itself; it runs on SQLite and PostgreSQL in
CI.

## Machine credentials

| Credential | Organisation from | Notes |
|---|---|---|
| Enrollment token (`cne_...`) | the token row | the enrolled device joins that organisation; re-enrollment of the same machine only matches devices of the same organisation |
| Device credential (`cnd_...`) | the credential row | every `/api/agent/*` request is scoped to the device's organisation |
| Ingest token (`cni_...`) | the token row | created by an organisation admin (`POST /api/organization/ingest-tokens`), shown once, SHA-256 stored; `SENSOR_API_TOKEN` of that organisation's sensors |
| `INGEST_API_TOKEN` (environment) | default organisation | unchanged for existing sensors |

Requests from a **suspended** organisation are refused (agents and sensors get
403; its users cannot sign in and their sessions end).

## Background jobs

The leader-elected jobs run once per deployment and iterate over **active**
organisations, each in a session scoped to it:

- **Notifications**: events only match the organisation's own rules and go to
  its own channels; asset-lifecycle, device and attack-path pollers run per
  organisation.
- **Scheduled scans**: each organisation's schedule and connectors; scan locks
  are per (organisation, connector).
- **Vulnerability matching**: KEV / EPSS / NVD / OSV feeds are fetched once for
  the platform (global caches); matching, KEV re-flagging and notifications run
  per organisation.
- **Dashboard snapshots**: once a day, each organisation's point-in-time
  dashboard metrics (all accounts and each cloud account), stored in its own
  rows of `dashboard_snapshots` ([DASHBOARDS.md](DASHBOARDS.md)).
- **Agent update automation**: each organisation's mode, rings and rollout. The
  GitHub Releases auto-import is platform-wide (releases are shared) and
  configured on, audited to and notified to the default organisation.

Events that belong to no organisation (sign-in attempts for unknown accounts,
rejected enrollments, the agent-API rejection monitor, server updates) are
recorded in the default organisation, the platform operator's.

## Per-organisation cloud connectors

`GET/PUT/DELETE /api/organization/connectors/{azure|aws|gcp}` (organisation
admins) stores an organisation's read-only credentials:

| Provider | Settings | Secret (encrypted at rest) |
|---|---|---|
| Azure | tenant id, client id, subscription ids | client secret |
| AWS | access key id, role ARNs, external id, regions, home region | secret access key |
| GCP | project ids, organization id | service-account key JSON |

Secrets are encrypted with the notification key (`NOTIFICATIONS_ENCRYPTION_KEY`,
Fernet, rotated by `python -m app.cli rotate-notification-key`) and only a
masked hint is ever returned.

- The **default organisation** keeps the environment settings; a provider it
  configures in the console overrides the environment for that provider
  (deleting it falls back again).
- **Other organisations** never inherit the environment or the server's own
  identity: managed identity, `DefaultAzureCredential`, boto3's default chain
  and GCP application default credentials belong to the platform operator and
  are disabled for them. They scan only with the credentials they store.
- The simulated demo connector belongs to the default organisation.

For AWS cross-account roles, give each organisation its own external ID.

## Platform owners

A platform owner ("super admin") manages organisations; it is separate from
organisation roles. Grant it with

```bash
python -m app.cli platform-admin you@example.com      # --revoke to remove
sudo cnapp-ctl platform-admin you@example.com          # on-prem
```

or list addresses in `PLATFORM_ADMIN_EMAILS` (comma-separated). `python -m
app.cli org-list` (`sudo cnapp-ctl orgs`) lists organisations with their usage.

Data shared by every organisation can only be changed by a platform owner or an
admin of the default organisation: importing / withdrawing signed agent
releases and device-script bundles, and the GitHub auto-import settings.

Platform console (**Platform → Organisations**, `/api/platform/*`): list
organisations with usage (users, active devices, cloud assets, scans, pending
invitations), create one, edit its profile / plan / limits, suspend and
reactivate it, see its members and invitations, invite or re-invite people.
Every action is recorded in the affected organisation's audit log. There is
**no impersonation**: a platform owner cannot open an organisation's data.

## Onboarding a new organisation

Sign-up is **invite-only**; there is no public registration.

1. A platform owner opens **Platform → Organisations → New organisation**,
   enters the name (the short name is derived from it), an optional contact
   email and plan, and the **first administrator's email**.
2. The first admin receives an invitation email with a link
   `https://<PUBLIC_BASE_URL>/invite#token=cnv_…`. The token is random,
   **single-use** and expires after `INVITE_TTL_HOURS` (default 72); only its
   SHA-256 is stored, and it travels in the URL fragment, so it never reaches
   server logs or `Referer` headers. Re-sending creates a new link and the old
   one stops working.
3. Opening the link shows the organisation and role; they choose a password
   (12+ characters) and are signed in. When their role must use MFA
   (`MFA_REQUIRED_ROLES`), they sign in normally next and enrol their
   authenticator.
4. They invite their teammates from **Administration → Organisation → Invite
   people** (viewer, analyst or admin), create sensor tokens, and enter their
   cloud connector credentials on the same page. Admins can still create users
   with an initial password on the Users page.

Accounts are platform-wide and belong to one organisation in this version, so
an email address that already has an account cannot be invited.

## Email for invitations

Invitations are sent with the same senders as the email notification channel
(SMTP with STARTTLS / implicit TLS, or Azure Communication Services Email) using
platform-level settings:

| Variable | Default | Description |
|---|---|---|
| `PLATFORM_SMTP_HOST` / `PLATFORM_SMTP_PORT` | / `587` | Mail server for transactional email |
| `PLATFORM_SMTP_SECURITY` | `starttls` | `starttls` or `tls` (implicit, port 465) |
| `PLATFORM_SMTP_USERNAME` / `PLATFORM_SMTP_PASSWORD` | | Optional authentication |
| `PLATFORM_SMTP_FROM` | | Sender, e.g. `CloudSecurity <no-reply@example.com>` (required with a host) |
| `PLATFORM_ACS_CONNECTION_STRING` / `PLATFORM_ACS_SENDER` | | Alternative: Azure Communication Services Email |
| `PUBLIC_BASE_URL` | | Base of the invitation links (falls back to the address the console was opened with) |
| `INVITE_TTL_HOURS` | `72` | Invitation lifetime (1 to 720) |

A relay on a private address needs `NOTIFICATIONS_SMTP_ALLOW_PRIVATE=true` (the
same SSRF guard as notification email). **Without a mail server the invitation
is still created and the console shows the link** for the inviter to copy and
pass on securely.

The invitation is a plain transactional email (`app/services/invitation_email.py`,
plain text and HTML, no images or tracking), not the alert layout of
notifications. Invitations sent from the platform console name only the brand
(`BRAND_NAME`): "You've been invited to join {organisation} on {brand}".
Invitations sent by an organisation admin name that admin (display name and
email address): "You have been invited to join {organisation} on {brand}".

## Upgrading an existing installation

Nothing to do: update as usual (`sudo cnapp-ctl update` on-prem, or the deploy
workflow). On start-up the schema migration (`0013_organizations` on
PostgreSQL; an equivalent one-time table rebuild on SQLite) creates the default
organisation (`DEFAULT_ORG_NAME`, default "Default organisation"; rename it in
the console later), moves every existing row into it and turns every user's role
into a membership with the same role. Sessions, device credentials, enrollment
tokens, `INGEST_API_TOKEN`, cloud connectors, schedules and notification rules
keep working.

Optionally make yourself a platform owner (see above) to manage organisations,
rename the default organisation under **Administration → Organisation**, and
configure [email for invitations](#email-for-invitations).

Downgrading below `0013_organizations` deletes every row that does not belong to
the default organisation and deactivates accounts that are not members of it.

## Limits and deferred items

- **One organisation per user** in this version (the membership table is ready
  for several; an organisation switcher would then pick the session's
  organisation at sign-in).
- **Entra ID SSO** is configured by environment and belongs to the default
  organisation: only its members can use it (JIT provisioning creates members of
  it). Per-organisation SSO configuration is deferred.
- **PostgreSQL row-level security** as a second layer is deferred (see above).
- Plan / limit fields (`plan`, `max_users`, `max_devices`) are stored but not
  enforced. The logo URL is stored but not displayed yet (the console's content
  security policy only loads its own images; logo upload is deferred).
- Organisation-specific `MFA_REQUIRED_ROLES`, session timeouts, notification
  encryption keys and simulation mode remain platform-wide settings.
- Deleting an organisation is not supported (suspend it instead).
