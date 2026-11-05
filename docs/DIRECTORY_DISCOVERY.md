# Directory discovery (Active Directory, Microsoft Entra ID + Intune, Google Workspace)

Directory discovery compares what your directories know with what the platform
manages. Two kinds of source exist:

* **On-prem Active Directory** is read from inside your network by a
  **dedicated collector** (a small, separate Windows program that only reads the
  directory; the platform never connects to a domain controller). Sources
  created before dedicated collectors existed keep using endpoint agents
  ("legacy") until you switch them.
* **Cloud directories** are read by the platform server itself over HTTPS:
  **Microsoft Entra ID + Intune** through Microsoft Graph, with the app
  registration of one of your Azure cloud connectors, and **Google Workspace**
  through the Admin SDK and Cloud Identity APIs, with a service account
  ([server-side collection](#server-side-collection)).

The results answer:

* which machines are in use but have **no agent** ("not managed"),
* which computer accounts / device records are **stale** (no activity for 90+ days),
* which computers are **disabled in the directory but still in use** (their agent still checks in),
* which agent devices are joined to a synced domain or Entra tenant but **unknown to the directory**,
  and which are **not domain-joined** at all,
* which devices Intune reports **non-compliant**, and which Windows / macOS agent
  devices of an Intune tenant are **not in Intune**,
* which **disabled or stale users** are signed in on managed devices,
* which **privileged admins** are disabled but still assigned, stale, or use a
  primary device without an agent.

The same physical machine can be an AD computer, an Entra device and an Intune
record at once: it is shown as **one machine** with the sources it is in,
reported once and counted once in agent coverage ([matching](#matching)).

It also adds the owner's directory identity (display name, email, department)
to IT assets, and lets admins **add directory computers to IT assets**.

Phase 1 shipped the framework and on-prem Active Directory; phase 2 adds
server-side collection, Microsoft Entra ID + Intune and Google Workspace. The source `type`, the
provider-neutral object model (stable `external_id` per source, provider
attributes in JSON) and the matching tiers are shared by every source type.

## Contents

- [Architecture](#architecture)
- [Dedicated collectors](#dedicated-collectors) (recommended setup: member server + gMSA; transports; Test)
- [Collector requirements](#collector-requirements)
- [Network ports](#network-ports)
- [Authentication options](#authentication-options)
- [Least privilege](#least-privilege)
- [Setting up a source](#setting-up-a-source)
- [Server-side collection](#server-side-collection)
- [Microsoft Entra ID + Intune](#microsoft-entra-id--intune)
- [Google Workspace](#google-workspace)
- [Scheduling](#scheduling)
- [Domain-join facts](#domain-join-facts)
- [Matching](#matching)
- [Discovery issues](#discovery-issues)
- [Adding computers to IT assets](#adding-computers-to-it-assets)
- [Deploying the agent](#deploying-the-agent)
- [Security model](#security-model)
- [Scaling](#scaling)
- [Notifications and audit](#notifications-and-audit)
- [API reference](#api-reference)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Manual test checklist (real domain)](#manual-test-checklist-real-domain)
- [Manual test checklist (real Entra ID tenant)](#manual-test-checklist-real-entra-id-tenant)
- [Manual test checklist (real Google Workspace)](#manual-test-checklist-real-google-workspace)
- [Limitations and future work](#limitations-and-future-work)

## Architecture

```
 console (admin)             CNAPP server                          your network
 ───────────────     ──────────────────────────────     ─────────────────────────────────────
 Connectors & scans  directory_sources (per organisation)   collector agent (cnapp-agent ≥ 1.3.0,
  → Directories   →  scheduler (leader-elected)         ←── polls /api/agent/commands every ~60 s
                     queues directory_sync (no secrets)  ──► directory_sync: run id, DCs, base DNs,
                     mints single-use upload token            scopes, page size, caps, token,
                     (+ decrypted service account)            [service account]
                                                                │ LDAPS 636 / StartTLS 389
                                                                ▼
                                                           domain controller(s)
                                                                │ paged search, 1000/page
                     POST /api/agent/directory/runs/{id}/  ◄────┘ gzip JSON batches (2000 objects)
                     batches (device credential + token)
                     upsert by (source, objectGUID)
                     final batch → mark missing (complete runs only)
                     → match → findings → notifications
 IT assets → Discovery / Dashboards → Endpoints coverage
```

* **Outbound only.** The collector is an ordinary enrolled agent: it only makes
  outbound HTTPS requests to the platform and LDAPS/StartTLS connections to your
  DCs. Nothing listens; no inbound firewall rule; the platform never sees your DCs.
* **Pull, then stream.** The `directory_sync` command returns immediately ("sync
  started"); the export runs in the background on the agent (command polling
  continues), one page (1000 objects) in memory at a time, uploaded in
  gzip-compressed batches of 2000 objects.
* **Idempotent ingestion.** Objects are upserted by `(source, external_id)`
  (AD objectGUID). Batches carry a strictly increasing sequence number; a
  retried batch is acknowledged as a duplicate, a gap is refused.
* **Missing, not deleted.** Only a *complete* run (succeeded, safety cap not
  reached, totals match, not a test) marks objects it did not return as
  `missing_since`. Missing objects are deleted after
  `DIRECTORY_MISSING_PURGE_DAYS` (30). A failed or truncated run never removes anything.

Code: `backend/app/directory/` (models, schemas, service, matching, reconcile,
scheduler, api, agent_api; cloud, cloud_http, graph, google for server-side sources),
`endpoint-agent/internal/directory/` (LDAP client, decoding, batching),
`endpoint-agent/internal/collect/join*.go` (domain-join facts).

## Dedicated collectors

A dedicated collector ("<BRAND_NAME> Collector", `cnapp-collector.exe`, Windows x64
and Arm64) is **not** an endpoint agent:

| | Dedicated collector | Endpoint agent (legacy collector) |
|---|---|---|
| Program | `endpoint-agent/cmd/cnapp-collector` | `cmd/cnapp-agent` |
| Identity | own enrollment token (`cnct_…`, kind *collector*), own credential (`cnc_…`), table `directory_collectors` | device |
| Commands | **only** `directory_sync`, `collector_diagnostics`, `collector_health`, `check_for_update`; the server refuses to queue anything else and the binary does not contain scripts, remote sessions, isolation, lock, wipe or log collection (a test checks its import graph) | all agent actions |
| Listed in | Connectors & scans → **Collectors** | Devices, IT assets, coverage |
| Transports | Kerberos signing & sealing (389, default), LDAPS, StartTLS | LDAPS, StartTLS |
| Service | `CNAPPCollector`, display name "<BRAND_NAME> Collector", LocalSystem or a gMSA | `CNAPPAgent` |

Collectors are listed with status (online = polled in the last 10 minutes),
version, host, domain, the identity the service runs as (`CORP\HOST$` for the
computer account, `CORP\svc-collector$` for a gMSA), last seen and whether the
host is a **domain controller**. Admins rename, revoke and delete them (all
audited); a collector silent for 15 minutes raises a *collector offline*
notification (once per outage, *collector online* when it is back).

**Recommended setup: two domain-joined member servers, service running as a gMSA.**

* **Domain controllers.** The collector detects a DC host (ProductType
  `LanmanNT`). The console shows a prominent warning on that collector and when
  it is picked for a source, and the interactive installer asks before
  installing: *Domain controllers are your most sensitive servers; we recommend
  a member server. This collector cannot run commands, scripts or remote
  sessions (it only reads the directory), so it is allowed.* A silent install on
  a DC needs `-AllowDomainController`.
* **Identity.** The Kerberos bind (SSPI) always uses the service's own identity:
  under LocalSystem that is the computer account; as a gMSA it is the gMSA. The
  bind code is the same; the collector reports which identity it uses.

### Installing

*Connectors & scans → Collectors → Add collector → Installer* downloads a zip
with `cnapp-collector.exe` (the signed binary bundled in the server image),
`collector.json` (server URL, a fresh **single-use** enrollment token, the
private CA if needed, the service display name, optionally the gMSA) and two
scripts:

```powershell
.\Install-Collector.ps1                                  # interactive
.\Install-Collector.ps1 -Quiet                           # silent (deployment tools)
.\Install-Collector.ps1 -Quiet -Gmsa 'CORP\svc-collector$'
.\Uninstall-Collector.ps1                                # service, program files, credential, logs
```

The service enrolls on start and deletes the token. Nothing listens: it polls
`/api/collector/commands` every minute and sends a heartbeat every 5 minutes.

### gMSA (recommended)

The console shows the PowerShell for each step (*Add collector → gMSA*), with your
domain, gMSA name and collector computers filled in:

1. **KDS root key**, once per forest: `Get-KdsRootKey`, else `Add-KdsRootKey
   -EffectiveImmediately`. Needs **Enterprise Admins** (or Domain Admins in the
   forest root). In production the key is only usable after **10 hours**
   (replication); backdating it (`-EffectiveTime (Get-Date).AddHours(-10)`) is
   for single-DC labs only.
2. `New-ADServiceAccount -Name svc-collector -DNSHostName svc-collector.corp.example.com
   -PrincipalsAllowedToRetrieveManagedPassword 'COLL01$','COLL02$'` (or a group).
3. Hardened OUs only (Authenticated Users lost read): `dsacls <OU> /I:T /G "CORP\svc-collector$:GR"`.
4. On each collector: `Install-ADServiceAccount svc-collector; Test-ADServiceAccount
   svc-collector` (must print `True`; a computer just added to the principals
   reboots or purges its tickets first).
5. Install with `-Gmsa 'CORP\svc-collector$'`, or switch an installed collector:
   `sc.exe config CNAPPCollector obj= "CORP\svc-collector$" password= ""`. The
   installer grants the gMSA **Log on as a service**, full control of its state
   folder (`%ProgramData%\CNAPP Collector`), modify on its program folder (signed
   self-update) and start/stop on its own service; nothing else.

A read-only **service account** with a password stays available for collectors
that are not domain-joined (simple bind, always inside TLS, stored encrypted on
the server); the computer account (LocalSystem) remains the default.

### Transports

| Transport | Port | DC certificate | Auth | Notes |
|---|---|---|---|---|
| **Kerberos signing & sealing** (default for computer account / gMSA on dedicated collectors) | 389 (GC 3268) | **not needed** | Kerberos (Negotiate) as the service identity | integrity + confidentiality from the SASL security layer |
| LDAPS | 636 (GC 3269) | trusted chain + host name | Kerberos or service account | channel binding token sent |
| StartTLS | 389 | trusted chain + host name | Kerberos or service account | |

Many domains have no LDAPS certificate on their DCs (the DC accepts TCP 636 and
then resets the TLS handshake), so the default needs none. The sealed transport
uses the Windows LDAP library (`wldap32.dll`, through syscalls, no cgo):
`ldap_init` → `LDAP_OPT_PROTOCOL_VERSION 3`, referrals off,
`LDAP_OPT_AREC_EXCLUSIVE` (the exact DC name, the `ldap/<dc>` SPN),
`LDAP_OPT_SIGN` and `LDAP_OPT_ENCRYPT` **on** → `ldap_connect` →
`ldap_bind_s(LDAP_AUTH_NEGOTIATE)` with no credentials (the process identity) →
**both options read back; if either is not on, nothing is searched and the
connection is closed** → paged search (`ldap_search_init_page` /
`ldap_get_next_page_s`, RFC 2696 paged results, 1000 per page). It never falls
back to unsigned or unsealed LDAP.

Why sealed 389 is safe: the Kerberos session key signs and encrypts every LDAP
message after the bind, which is what DCs that require LDAP signing
(`LDAPServerIntegrity=2`) enforce. **Channel binding**
(`LdapEnforceChannelBinding`) only applies to LDAP over TLS, so it does not
concern this transport. Service-account passwords are never sent over 389, even
sealed: that combination is refused by the console, the server and the collector.

go-ldap (MIT) stays the backend for LDAPS / StartTLS; endpoint-agent collectors
(legacy) are TLS-only.

### Test (diagnostics on the collector)

*Test & save* on a source (and *Test* on a collector) queues
`collector_diagnostics`; the collector runs, as its own identity, and reports
PASS / WARN / FAIL / SKIP per step:

1. **DC locator** (`_ldap._tcp.dc._msdcs.<domain>`, or the configured DCs);
2. **Port**: each DC; a DC from DNS that refuses or times out is flagged
   *"listed in DNS as a DC but not responding — consider removing the stale SRV
   record or listing DCs explicitly"* and the others are still tried (syncs do
   the same);
3. **Certificate** (LDAPS: chain and host name; skipped when sealed);
4. **Bind** as the collector identity (or the service account) with the
   transport used and *signed+sealed: yes*;
5. **Read 5 objects**.

The copyable PowerShell pre-check stays available as an optional manual tool.

### Legacy sources (endpoint agents as collectors)

Sources that use endpoint agents keep working unchanged and show *Legacy: uses
endpoint agents — move to a dedicated collector*. **Edit → Switch to dedicated
collectors** sets `collector_ids` and drops the agents; objects, issues and run
history are kept (audited as `switched_to_dedicated`). New AD sources can only
pick dedicated collectors (`collector_device_ids` is refused on create). The
endpoint agent's `directory_collector` capability is **deprecated** and kept for
these sources only.

### Updates and release import

`agent-release.yml` builds `cnapp-collector-windows-{amd64,arm64}.exe` with the
agent and signs them in the same bundle as a second manifest
(`collector-manifest.json`, product `cnapp-collector`, same keys and version;
agents never see collector artifacts, so older agents keep updating).
`cnapp-ctl agent-release fetch` / `import` verify and import both. Collectors
follow the organisation's **default ring**: when its target release ships
collector binaries newer than the collector, the heartbeat offers them and the
collector verifies the signature, hashes and version policy itself before
swapping its binary (same rollback watchdog as the agent).

## Collector requirements

| | Computer account (default) | Service account |
|---|---|---|
| Collector OS | Windows 10/11 or Windows Server, **domain-joined** | Windows, macOS or Linux (joined or not) |
| Agent | cnapp-agent **1.3.0+** (advertises `directory_collector`) | same |
| Secret stored | none | username + password, encrypted on the server |
| Bind | Kerberos (SASL GSSAPI via SSPI) as `DOMAIN\HOST$` | LDAP simple bind inside TLS |

* Pick **at least two collectors** per source on different hosts (they are used
  in order; the next one takes over when one is offline).
* The collector needs DNS resolution of `_ldap._tcp.dc._msdcs.<domain>` (DC
  locator) unless you list DCs explicitly, and must trust the DCs' LDAPS
  certificate (Windows: the machine store; otherwise paste your CA under
  *Advanced → Extra CA*).
* Each source covers **one domain** (base DNs default to the domain root). For
  several domains or forests, add one source per domain (each with collectors
  that can reach it). A Global Catalog port (3269) works too for read-only
  forest-wide searches.

## Network ports

| From | To | Port | Purpose |
|---|---|---|---|
| collector | DCs | TCP 389 (Kerberos signing & sealing, default), TCP 636 (LDAPS) **or** 389 + StartTLS | directory reads |
| collector | DNS servers | UDP/TCP 53 | DC locator SRV lookups |
| collector | DCs | TCP/UDP 88 | Kerberos (computer-account auth only) |
| collector | platform | TCP 443 | commands + batch upload (existing agent traffic) |

Unsigned, unencrypted LDAP is **never** used. On 389 the dedicated collector
uses Kerberos signing & sealing (wldap32) or StartTLS; endpoint-agent
collectors only StartTLS (go-ldap negotiates no SASL security layer). Kerberos
(TCP/UDP 88) is needed for the computer account / gMSA.

## Authentication options

1. **Collector's computer account (default, no secret).** The agent runs as
   LocalSystem, whose network identity is the computer account. It binds with
   SASL GSSAPI over SSPI (Kerberos) **inside the TLS session** and sends an RFC
   5929 `tls-server-end-point` channel-binding token, so it also works where DCs
   enforce LDAP channel binding (`LdapEnforceChannelBinding=2`). The SPN is
   `ldap/<dc fqdn>`, so DCs must be addressed by DNS name (not IP).
2. **Read-only service account.** For Linux/macOS or non-joined collectors.
   Username (`user@domain` or `DOMAIN\user`) and password are encrypted on the
   server (Fernet, `NOTIFICATIONS_ENCRYPTION_KEY`, the same key as cloud
   connector secrets) and are **write-only** in the API. They are added only to
   the copy of the command delivered to the chosen collector (inside the TLS
   response), never stored in the command record, never shown in the console,
   never logged, and redacted from any error message the agent reports.

## Least privilege

* Default **Domain Users / Domain Computers** read access is enough for every
  attribute collected. No admin rights, no delegation, no write permissions.
* For a service account: a normal user, *Password never expires* per your
  policy, *Deny log on locally / through RDP*, member of no privileged group.
  Optionally restrict it to the collector hosts (`userWorkstations`).
* Hardened domains that remove *Authenticated Users* read access from OUs must
  grant the computer/service account *Read* (List contents, Read property) on
  the synced OUs.
* Attributes read (fixed in the agent, nothing else is requested):
  * computers: objectGUID, objectSid, cn, dNSHostName, sAMAccountName,
    operatingSystem, operatingSystemVersion, distinguishedName,
    userAccountControl, lastLogonTimestamp, whenCreated, whenChanged;
  * users: objectGUID, objectSid, sAMAccountName, userPrincipalName, mail,
    displayName, givenName, sn, department, title, manager (DN),
    distinguishedName, userAccountControl, lastLogonTimestamp, whenCreated, pwdLastSet.
  * Filters: `(objectCategory=computer)` and `(&(objectCategory=person)(objectClass=user))`.
  * Group memberships (`memberOf`, privileged groups) are **not** read yet.

## Setting up a source

1. Add two [dedicated collectors](#dedicated-collectors) on domain-joined member
   servers that stay on (gMSA recommended).
2. **Connectors & scans → Directories → Add directory → Active Directory.** Enter the
   domain (e.g. `corp.example.com`), choose the collectors (order = failover), keep
   *Collector's identity* (computer account / gMSA) or switch to *Read-only service
   account*. Transport: *Kerberos signing & sealing (port 389, no certificate
   needed)* by default; LDAPS / StartTLS selectable. Advanced: DCs (default: DC
   locator), base DNs (default: domain root), port, extra CA, stale threshold
   (90 days), sync interval (6 h), objects (computers, users).
3. Optional: copy the manual **pre-check script** (the console's Test runs the same
   checks on the collector).
4. **Test & save.** The source is saved and the collector runs its diagnostics
   (DC locator, port, certificate, bind, 5-object read) and reports each step;
   collectors pick up commands within about a minute. Legacy sources still queue
   a test sync (at most 10 objects, nothing stored but their names).
5. The first full sync runs on schedule (immediately for a new source) or with
   **Sync now**. Results: **IT assets → Discovery**.

## Server-side collection

Cloud directories have no on-prem component: the platform server calls the
provider's HTTPS API itself (`backend/app/directory/cloud.py`). Everything else
is the same machinery as AD: sources, sync runs, the scheduler, upsert by
`(source, external_id)`, missing-marking, matching, findings, notifications,
audit, RBAC and tenancy.

```
 console (admin)        CNAPP server                                        provider
 ───────────────  ─────────────────────────────────────────────────  ───────────────────────
 Add directory →  directory_sources (references an Azure connector)
 Test & save    → permission / licence checks (synchronous, GETs) ──► token + 1-object probes
 Sync now /       directory_sync_runs: queued ─► worker pool claims
 scheduler        it (atomic queued→running: one process runs it)
                  parts in order: users → roles → devices → Intune ───► paged GETs (nextLink),
                  one page in memory, upserted + committed per page   ◄── 429 → Retry-After backoff
                  complete parts mark missing; reconcile; notify
```

* **Read-only.** Only GET requests (plus the OAuth token request) to a fixed
  allow-list of hosts (`login.microsoftonline.com`, `graph.microsoft.com`,
  `oauth2.googleapis.com`, `admin.googleapis.com`, `cloudidentity.googleapis.com`);
  a paging link to any other host is refused.
* **Parts degrade independently.** Each part (users, admin roles, Entra
  devices, Intune) is skipped with a status (`missing_permission`,
  `unlicensed`, `error`) when the tenant does not allow it; the others still
  sync. The run succeeds when at least one part completed (its error starts
  with `partial:`) and fails only when nothing could be read or the sign-in
  itself failed. The source card shows the outcome per part.
* **Missing, not deleted (per part).** Only parts that completed mark the
  objects they no longer return as missing; a skipped Intune part never
  removes Intune records. A run that hits `DIRECTORY_MAX_OBJECTS` stops
  (`truncated`) and marks nothing missing.
* **Throttling.** 429 / 503 / 504 and network errors are retried up to 6 times
  per request, honouring `Retry-After` (capped at 120 s) or exponential backoff.
* **Concurrency.** At most 2 cloud syncs run per server process; a run is
  claimed atomically, so several API workers and the scheduler never run it
  twice. A running cloud run that commits no page for 30 minutes (its process
  died) is failed by the scheduler; queued runs nobody picked up are re-kicked.
* **Disable / delete** a source during a sync: the run is cancelled and stops
  before writing its next page.

## Microsoft Entra ID + Intune

The source reuses one of the organisation's **Azure cloud connectors**
(Connectors & scans → Cloud connectors → Azure): its tenant ID, app
registration (client ID) and client secret. The source stores only which
connector it uses; the secret stays in the connector's encrypted settings and
is never copied, returned or logged. The connector must authenticate with a
**client secret**; a connector that uses the server's managed identity or
DefaultAzureCredential (environment configuration of the default organisation)
is listed as unusable, with the reason. **One source per Entra tenant**: a
second source for the same tenant ID is refused.

### Setup

1. Connect Azure under Connectors & scans (tenant ID, client ID, client secret)
   if it is not connected yet.
2. **Directories → Add directory → Microsoft Entra ID + Intune.** Choose the
   connector and the parts to read (users, admin roles, Entra devices, Intune
   devices), the stale threshold (90 days) and sync interval (6 h).
3. Copy the **permission script** (Azure CLI for Cloud Shell, or Microsoft Graph
   PowerShell) and run it as a Global Administrator or Privileged Role
   Administrator. It adds the Microsoft Graph **application** permissions below
   to the connector's app registration and grants admin consent. It changes
   nothing else in the tenant.
4. **Test & save.** The source is saved, then the server signs in as the app,
   reads the permissions granted in its token and probes each part with a
   1-object read. Each permission is reported as granted or missing; Intune
   and sign-in activity report "not licensed" when the tenant has no licence
   (a warning, not a failure). Re-run Test & save after fixing.
5. The first full sync starts within a minute (scheduler) or with **Sync now**.

### Permissions (all read-only application permissions)

| Permission | Needed for | Without it |
|---|---|---|
| `User.Read.All` | Users: enabled / disabled, UPN, email, department, title, on-prem SID / sAMAccountName (links synced users to AD) | users part skipped (and admin roles, which flag users) |
| `AuditLog.Read.All` | Users' last sign-in (`signInActivity`) | last sign-in unknown: stale-user / stale-admin checks are skipped, never guessed |
| `Device.Read.All` | Entra joined, hybrid joined and registered devices, their Entra device id and last sign-in | devices part skipped |
| `DeviceManagementManagedDevices.Read.All` | Intune managed devices: compliance, encryption, last check-in, serial, primary user | Intune part skipped |
| `RoleManagement.Read.Directory` | Privileged directory role assignments | admin-role part skipped, privileged flags kept from the last run |
| `GroupMember.Read.All` | Members of role-assignable groups that hold a privileged role | roles held through groups are not expanded (noted on the roles part) |
| `RoleEligibilitySchedule.Read.Directory` (optional) | PIM **eligible** assignments of the privileged roles (`roleEligibilityScheduleInstances`); needs **Entra ID P2** | eligible admins are not read (*PIM eligible · no permission* / *not licensed*); eligibility seen by the last successful read is kept |

**Licences.** `signInActivity` needs **Microsoft Entra ID P1 or P2**: without
it Graph answers `Authentication_RequestFromNonPremiumTenantOrB2CTenant`, the
sync continues and last sign-in is shown as *unknown*. The Intune part needs an
Intune licence; without it the part is skipped as *not licensed*.

**What is read.** Users: `id, userPrincipalName, mail, displayName, givenName,
surname, department, jobTitle, accountEnabled, createdDateTime, userType,
onPremisesSamAccountName, onPremisesDomainName, onPremisesSecurityIdentifier,
onPremisesDistinguishedName, onPremisesSyncEnabled, signInActivity`. Devices:
the default device properties (`deviceId, displayName, operatingSystem,
trustType, accountEnabled, approximateLastSignInDateTime, ...`). Intune:
`id, deviceName, azureADDeviceId, serialNumber, complianceState, isEncrypted,
lastSyncDateTime, operatingSystem, osVersion, userPrincipalName,
managedDeviceOwnerType, enrolledDateTime, model, manufacturer`. Roles: role
definitions, assignments of the privileged roles (`$filter=roleDefinitionId`,
`$expand=principal`) and the transitive user members of groups holding them.

**Privileged roles** (built-in, matched by role template id or display name):
Global Administrator, Privileged Role Administrator, Privileged Authentication
Administrator, Security Administrator, Conditional Access Administrator,
Application Administrator, Cloud Application Administrator, Hybrid Identity
Administrator, User Administrator, Authentication Administrator, Helpdesk
Administrator, Password Administrator, Exchange Administrator, SharePoint
Administrator, Intune Administrator, Cloud Device Administrator. Service
principals holding roles are ignored.

**PIM eligible admins.** With `RoleEligibilitySchedule.Read.Directory` and
Entra ID P2, the current eligibility instances
(`GET /roleManagement/directory/roleEligibilityScheduleInstances?$filter=roleDefinitionId eq '…'&$expand=principal`,
paged, same throttling / host allow-list) are read for the same privileged
roles, including eligibility through role-assignable groups (expanded with
`GroupMember.Read.All`). An eligible holder is privileged for every privileged
issue, the badge and the filter, and is shown as such: role
"Eligible: Global Administrator (PIM)", issue detail "is eligible (PIM) for
Global Administrator". A role a user holds both actively and as eligible is
shown once, as active. Without the permission or P2 the run records
*PIM eligible* as `missing_permission` / `unlicensed` and keeps the eligibility
the last successful read found; nothing else is affected.

**Device records.** Entra devices are records of kind `entra` (join type
`joined`, `hybrid` or `registered`), Intune devices of kind `intune`
(`external_id` `mdm:<id>`). Registered-only (personal) Entra devices, Intune
devices owned `personal`, phones and anything not Windows / macOS / Linux are
kept and listed, but **no agent is expected** on them: they are never "no
agent" and are not in coverage.

## Google Workspace

The server reads Google Workspace with a **service account with domain-wide
delegation** that impersonates a named Workspace admin, requesting **read-only
scopes only**. The admin uploads the service account's JSON key in the
console: it is stored Fernet-encrypted (`NOTIFICATIONS_ENCRYPTION_KEY`, like
the AD service-account credential), never returned, logged or audited; the
console shows only the client email and key id. The JWT assertion is signed
locally (RS256, `joserfc`, already a dependency) and exchanged at the fixed
endpoint `https://oauth2.googleapis.com/token` (the key file's `token_uri` is
ignored). Each part requests a token for its own scope, so one scope missing
from the delegation only skips that part.

### Setup

1. **Create the service account and key** (Google Cloud Shell, any project you
   administer; the console shows the commands): enable `admin.googleapis.com`
   and `cloudidentity.googleapis.com`, create `cnapp-directory` (no IAM roles),
   create a JSON key, print its OAuth client ID. If your organisation blocks key
   creation (`iam.disableServiceAccountKeyCreation`), ask for an exception on
   this project.
2. **Authorise it** in the Admin console: Security → Access and data control →
   API controls → **Manage domain-wide delegation** → Add new: paste the client
   ID and the comma-separated scope string the console shows (only the parts
   you selected).
3. **Directories → Add directory → Google Workspace.** Enter the admin to
   impersonate (a Super Admin, or an admin with a custom role that can read
   users, devices and admin roles), choose the parts, upload the key,
   **Test & save**: each scope is checked with a token request and a 1-object
   read; missing delegation, an API that is not enabled, or a wrong admin
   email are reported per scope. Delegation changes can take minutes to apply.
4. Advanced: the customer ID (default `my_customer`, the admin's own account).

### Scopes (all read-only)

| Scope | Needed for | Without it |
|---|---|---|
| `admin.directory.user.readonly` | Users: suspended / archived, last login, department, org unit, super admin flag | users part skipped |
| `admin.directory.rolemanagement.readonly` | Admin role assignments | only super admins (from the user list) are flagged |
| `admin.directory.group.member.readonly` | Members of groups an admin role is assigned to (optional) | roles held through groups are not expanded |
| `admin.directory.device.chromeos.readonly` | ChromeOS devices: status, last sync, serial, user | ChromeOS part skipped |
| `admin.directory.device.mobile.readonly` | Android / iOS devices: status, last sync, serial, user | mobile part skipped |
| `cloud-identity.devices.readonly` | Windows / macOS / Linux endpoints (Google endpoint management): host name, serial, encryption, owner, last sync, device users | endpoints part skipped |

**Privileged roles:** every role flagged `isSuperAdminRole` (Super Admin) and
the pre-built User Management Admin, Groups Admin, Help Desk Admin, Services
Admin and Mobile Admin; custom roles are not treated as privileged.

**Device records.** Endpoints (`endpoint`, `external_id` `ci:<device>`) are
matched to agents by serial number, then host name; `BYOD`-owned endpoints,
ChromeOS (`chromeos`) and mobile (`mobile`) devices are listed but no agent
is expected on them. The endpoints part only takes Windows / macOS / Linux
records (Android / iOS / ChromeOS records of Cloud Identity belong to the
mobile and ChromeOS parts). The primary user of an endpoint is the user who
synced it most recently.

**Last login** comes from the user list (`lastLoginTime`), so it is always
known for Google users (never-logged-in users have none).

## Scheduling

The leader-elected scheduler (one per deployment) checks every minute:

* a source is due `interval_hours` after its last scheduled run was queued
  (timing from the database: restarts neither skip nor duplicate syncs);
* runs never overlap (Sync now answers 409 while one is queued/running);
* **failover:** a queued run whose collector has not fetched it within 15 minutes
  (or whose command expired / was cancelled), or a running run silent for 30
  minutes, is failed and re-queued on the next healthy collector of the source
  (each collector once per slot). A collector is healthy when its agent was seen
  in the last 10 minutes (it polls every ~60 s), and runs Windows for
  computer-account auth;
* with no healthy collector the slot is recorded as a failed run and notified;
* cloud sources have no collector: their runs go to the server's worker pool
  (see [server-side collection](#server-side-collection)); a stalled one is
  failed, not failed over;
* matches and findings are re-evaluated every 30 minutes (device check-ins change
  them) and after every sync.

## Domain-join facts

Every agent 1.3.0+ reports how its device is joined (check-in field
`device.directory_join`, all optional, length-capped and validated; stored on
the device and shown on *Devices → device → Directory*):

| Field | Windows | macOS | Linux |
|---|---|---|---|
| `ad_domain`, `ad_netbios`, `ad_forest`, `ad_domain_sid` | LsaQueryInformationPolicy (local, no DC) | `dsconfigad -show` | `realm list` |
| `ad_computer_sid` | LookupAccountName(`DOMAIN\HOST$`), 5 s budget, cached | - | - |
| `dns_hostname` | GetComputerNameEx(DnsFullyQualified) | - | - |
| `entra_device_id`, `entra_tenant_id`, `entra_join_type` | NetGetAadJoinInformation | - | - |
| `intune_enrollment_id` | `HKLM\SOFTWARE\Microsoft\Enrollments` (MS DM Server) | - | - |

`ad_object_guid` is reserved (reading it needs LDAP). Older agents send nothing;
they are still matched by host name.

## Matching

**One machine, several records.** Directory records are first grouped into
physical machines (`cluster_computers` in `backend/app/directory/matching.py`):

* the same object synced by two sources (same external id, e.g. overlapping AD sources);
* an Entra device and its Intune record (same Entra device id, `azureADDeviceId`);
* an AD computer and its hybrid-joined Entra device (same on-prem SID when Graph
  returns it; otherwise the same host name, when that name is unique among AD
  computers and among hybrid-joined devices, since Entra Connect names the
  device after the computer account);
* records with the same real serial number (placeholder serials are ignored);
* records an agent device ties together: it reports the SID of one and the
  Entra device id of the other (only keys that point at exactly one record).

A machine's representative record is the strongest kind (AD computer, then
Entra device, Intune, ...). Machines are matched, reported, listed (*Directory
computers* shows one row per machine with a badge per source) and counted in
coverage **once**.

Machines are then matched to agent devices in tiers, strongest first, using
the keys of all their records (pure and unit-tested). A tier matches only when
the key is unique on both sides among what is still unmatched; otherwise the
machine is **ambiguous** (flagged with its candidates, never guessed) and
weaker tiers are not tried:

| Tier | Key | Confidence |
|---|---|---|
| `directory_sid` / `directory_guid` | computer account SID / objectGUID reported by the agent (AD records) | 100 |
| `entra_device_id` | Entra device id reported by the agent (Windows `NetGetAadJoinInformation`) = Entra `deviceId` / Intune `azureADDeviceId` | 100 |
| `serial` | serial number (Intune; not AD) | 95 |
| `fqdn` | dNSHostName = device FQDN (reported, hostname, or hostname + AD domain) | 90 |
| `hostname_domain` | short host name within the same AD domain | 75 |
| `hostname` | short host name for devices that report no domain (older agents, Entra-only devices), only if the name exists once across **all** directory machines | 50 |

Comparisons are case-insensitive. A machine matched to a device is linked to
that device's IT asset. The `intune_enrollment_id` agents report is the local
MDM enrollment key, not the Intune device id, so it is not a match key.

**Users** are matched to signed-in users (`DOMAIN\user`, `user@upn`) and IT
asset owners by sAMAccountName within the device's domain (the NetBIOS prefix is
mapped via the domain-join facts), or UPN / email. Entra ID users match by UPN /
email; an Entra user synced from AD (same on-prem SID) is the **same person** as
the AD user, not an ambiguity. `AzureAD\…` display names, local and service
accounts are ignored; names present in several domains without a domain hint
are ambiguous and ignored. IT assets keep the agent-always-wins
**username owner rule**: the username stays the owner key; the directory
identity (display name, email, department, enabled) is display-only enrichment
(`owner_directory` in the IT asset API).

## Discovery issues

Computer issues are evaluated per physical machine (all its records together);
"activity" is the AD `lastLogonTimestamp`, the Entra device's approximate last
sign-in or the Intune last check-in, whichever is newest.

| Type | Tab | Meaning |
|---|---|---|
| `not_managed` (No agent) | Computer | A machine the agent belongs on (Windows / macOS / Linux, not personal) with an enabled record active within the stale window, and no matched active agent device. Reported once even if it is in AD, Entra ID and Intune |
| `stale_computer` | Computer | Every enabled record of the machine has had no activity for `stale_days` (default 90; never-active records older than that too) |
| `disabled_but_active` | Computer | Disabled in AD or Entra ID, but its matched agent checked in within 7 days |
| `unknown_to_directory` | Computer | Active agent device joined to a synced AD domain, or to the Entra tenant of a source that synced devices, with no matching directory record (or several possible ones) |
| `not_domain_joined` | Computer | Active agent device (1.3.0+) that reports neither an AD domain nor an Entra join (only when an AD source exists) |
| `non_compliant` | Computer | Intune reports the machine's record `noncompliant` (detail adds "not encrypted" when Intune says so) |
| `not_in_intune` | Computer | Active Windows / macOS agent device joined to an Entra tenant whose source synced Intune successfully, with no Intune record (agents report the tenant on Windows) |
| `disabled_user_signed_in` | User | A user disabled in the directory (AD or Entra ID; for a synced person, disabled in either) is signed in on a managed device |
| `stale_user_signed_in` | User | A signed-in user has no sign-in for `stale_days`; skipped when last sign-in is unknown (Entra ID without P1/P2 or `AuditLog.Read.All`) |
| `privileged_disabled` | User | A disabled account still holds a privileged admin role (assignment left behind) |
| `privileged_stale` | User | An enabled privileged admin has not signed in for `stale_days` (skipped when last sign-in is unknown) |
| `privileged_no_agent` | User | An enabled privileged admin's primary device (Intune primary user, Google endpoint / ChromeOS / mobile user) is a machine the agent belongs on but has no agent; one issue per device |

`lastLogonTimestamp` replicates with up to ~14 days of lag by design, and Entra
`approximateLastSignInDateTime` is updated about weekly, which is why the stale
threshold is in weeks, not days. Issues are stored
(`directory_findings`), keep their first-seen time across re-evaluations, and
are listed with filters, search, pagination and CSV export on **IT assets →
Discovery**, with a source filter (a machine matches every source one of its
records is in) and a badge per source on each row. The same machine from
several sources is reported once.

**Agent coverage** (Discovery and Dashboards → Endpoints) = machines with an
active agent / machines the agent belongs on, each physical machine counted
once (enabled, present records with `agent_expected`).

**Privileged users.** *Directory users* lists users with a *Privileged* filter
and badge (role names on hover); no group browser.

## Device class of directory computers

Directory computers are classified without an agent (the
[device class](DEVICE_MANAGEMENT.md#device-class) of agent devices comes from the
agent itself): an AD computer account with `SERVER_TRUST_ACCOUNT` (0x2000) in
`userAccountControl` is a **domain controller**; "Server" in `operatingSystem`
(AD, Entra ID, Intune, Google endpoints) is a **server**; Linux is a server;
other Windows, macOS and ChromeOS records are **workstations**; phones and
unknown operating systems have no class. Discovery → Computers filters by class
(`GET /api/directory/computers?device_class=domain_controller`), and the
Endpoints dashboard splits agent coverage into workstations, servers and domain
controllers (`coverage.by_class` of `GET /api/directory/summary`).

## Adding computers to IT assets

Directory computers that are not IT assets are only listed under Discovery: they
are **never created automatically**. Admins choose **Add to IT assets** (one or
in bulk, up to 1000 per request): each becomes an asset with source
`directory`, status `in_stock`, tag `DIR-<NAME>`, type `server` (servers and
domain controllers, see below) or `computer`, with the DN in its notes and a
custody event. When that computer
later gets an agent, the device is linked to this asset (matched directory
computer, or same short name and domain) instead of creating a duplicate.

## Deploying the agent

**IT assets → Discovery → Deploy agent** turns the "No agent" list into
coverage. Select machines (checkboxes on *Computer issues* or *Directory
computers*, or **Deploy agent** on one row), or take the whole *No agent* filter
(**Deploy agent to all N**, resolved by the server, up to 5000 machines). The
plan groups the selection by the best route for where each machine was found
and its OS (`plan_machine` in `backend/app/directory/deploy.py`, unit-tested):

| Route | Chosen for | What you do |
|---|---|---|
| **Microsoft Intune** | Windows / macOS machines with an Intune record (wins over Group Policy: it also reaches machines off the corporate network) | Win32 app (`.intunewin`) / macOS PKG app, detection rule, Required assignment to a device group |
| **Group Policy** | Windows computers in on-prem AD (without Intune) | Computer startup script or GPO software installation, linked to the OUs shown |
| **Download / manual** | Entra-only, Google endpoint, unmanaged Windows / macOS machines, Macs bound to AD | Hand the installer to the user or IT, or a one-line install |
| **ConfigMgr / Jamf / RMM** | Only when you choose it per machine (directories do not say which tool manages a machine) | Silent install command + detection rule in your tool |

Excluded with the reason (never deployed): machines that already have an active
agent; phones, tablets and ChromeOS; personal / registered-only devices
(`agent_expected` false); machines disabled in every directory; Linux (no agent
package yet); unknown OS. Every machine can be switched to another route it
allows (for example a Group Policy machine to ConfigMgr).

**Nothing is written to a directory or MDM**: no Intune, Graph or Google write
permission is needed. The platform plans, issues the enrollment material and
tracks progress; you follow the steps in your own tools.

**Creating a deployment** stores its name, the selected machines and their
routes (name, OS, OU copied so the record survives directory clean-up), the
expiry (1-90 days, default 14), an optional device group label and who created
it. Enrollment material is ordinary enrollment tokens, listed under Devices →
Enroll, all expiring with the deployment and capped to the batch (machines +
10%, at least 2 spare; re-installs on an enrolled machine use no enrollment):

* **Installers:** *Windows installer* / *macOS installer* on the deployment page
  build the same pre-configured MSI / pkg as Devices → Enroll (same rate limit,
  CA option, audit `agent_installer_created` with the deployment id), with a new
  package-bound token capped to the deployment's machines of that platform. The
  token only exists inside the file.
* **Command-line token** (optional, default on when the plan has manual
  machines): for the generic installer with `CNAPP_TOKEN` or `cnapp-agent
  configure`. Shown **once**, right after creation; never stored in plaintext or
  returned again.

**Progress** (viewers too): each selected machine is *enrolled* once directory
matching links it to an active agent device ([matching](#matching): after every
directory sync and every 30 minutes), *no agent yet* (with the deployment's
age), or *left the directory*. *Enrolled with this deployment* counts devices
that used its installers or token, selected or not. **Revoke** revokes every
token of the deployment (its installers stop enrolling); enrolled devices stay.
The list is under **Discovery → Deployments**.

### Per-route admin steps

The console shows these steps with the deployment's OUs, machine names and
copyable scripts. Install facts: Windows service `CNAPPAgent`, binary
`C:\Program Files\CNAPP Agent\cnapp-agent.exe`; macOS package id
`com.cloudsecurity.cnapp-agent`.

**Group Policy (computer startup script, recommended)**

1. Download the deployment's Windows installer and copy `cnapp-agent-setup.msi`
   to a share **Domain Computers** can read at boot (e.g. `\\corp.example.com\NETLOGON\cnapp\`).
2. In **Group Policy Management**, right-click each OU listed → *Create a GPO in
   this domain, and Link it here…* (one GPO linked to every OU).
3. Edit it → *Computer Configuration → Policies → Windows Settings → Scripts
   (Startup/Shutdown) → Startup → PowerShell Scripts* → add the script below.
4. Recommended: *Administrative Templates → System → Logon → Always wait for the
   network at computer startup and logon* = Enabled.
5. Pilot with security filtering on a group of a few computers; computers
   install at their next restart.

```powershell
$ErrorActionPreference = 'Stop'
$Msi = '\\corp.example.com\NETLOGON\cnapp\cnapp-agent-setup.msi'
if (Get-Service -Name 'CNAPPAgent' -ErrorAction SilentlyContinue) { exit 0 }
$Log = Join-Path $env:WINDIR 'Temp\cnapp-agent-install.log'
$p = Start-Process -FilePath msiexec.exe -Wait -PassThru -ArgumentList @('/i', "`"$Msi`"", '/qn', '/norestart', '/l*v', "`"$Log`"")
exit $p.ExitCode
```

Or *GPO software installation*: *Computer Configuration → Policies → Software
Settings → Software installation → New → Package*, the MSI by **UNC path**,
*Assigned*. The agent updates itself afterwards.

**Intune**

* Windows: `IntuneWinAppUtil.exe -c C:\cnapp\src -s cnapp-agent-setup.msi -o C:\cnapp\out -q`;
  *Apps → Windows → Add → Windows app (Win32)*; install `msiexec /i "cnapp-agent-setup.msi" /qn /norestart`,
  install behaviour System; requirement 64-bit Windows 10/11; detection *File*
  `C:\Program Files\CNAPP Agent` / `cnapp-agent.exe` exists (or a script testing
  the `CNAPPAgent` service); *Required* to a device group with these machines.
* macOS: *Apps → macOS → Add → macOS app (PKG)*, upload `cnapp-agent-setup.pkg`
  (your signed build if you sign packages), detection bundle id
  `com.cloudsecurity.cnapp-agent`, ignore app version (the agent self-updates),
  *Required* to a device group.

**Configuration Manager / Jamf / other RMM**

* Windows: `msiexec /i cnapp-agent-setup.msi /qn /norestart /l*v "%WINDIR%\Temp\cnapp-agent-install.log"`
  as SYSTEM (exit 0 or 3010). ConfigMgr: *Create Application → Windows Installer
  (MSI)* (product-code detection is filled in), *Required* to a device
  collection. Other tools: detect `CNAPPAgent` / the binary.
* macOS: `sudo installer -pkg cnapp-agent-setup.pkg -target /`, detection
  `pkgutil --pkg-info com.cloudsecurity.cnapp-agent`. Jamf Pro: upload the
  package, a policy (Install, recurring check-in, once per computer) scoped to a
  group of these Macs.

**Download / manual (Google-managed, Entra-only, unmanaged)**

Send the installer through a channel limited to the people concerned (it holds
an enrollment token); the install needs local administrator rights:
`msiexec /i cnapp-agent-setup.msi /qn /norestart` (Windows, elevated) or
`sudo installer -pkg ~/Downloads/cnapp-agent-setup.pkg -target /` (macOS). With
the command-line token instead: `msiexec /i cnapp-agent-windows-x64.msi
CNAPP_SERVER=https://… CNAPP_TOKEN=… /qn`, or the generic pkg then `printf
'%s\n' '<token>' | sudo /usr/local/cnapp-agent/bin/cnapp-agent configure
--server https://… --token-stdin`.

## Security model

* **Admin-gated:** only admins create/edit sources, choose collectors, run
  syncs and add assets. `directory_sync` cannot be queued through the generic
  device command API; it is only delivered to the source's designated collectors.
* **Strict agent validation:** the agent accepts `directory_sync` only with the
  exact parameter set (hosts, DNs, ports, sizes, caps, upload path under
  `/api/agent/directory/runs/` validated), refuses plain LDAP, refuses Kerberos
  on non-Windows, and verifies DC certificates (system trust + optional CA).
* **Two credentials per upload:** the device credential (which also scopes the
  request to the device's organisation) and the run's upload token: minted when
  the command is delivered, single-use per run, stored as SHA-256 only, expires
  with the run (`timeout + 30 min`), cleared when the run ends.
* **Caps:** 5000 objects per batch, 16 MiB compressed / 64 MiB decompressed per
  batch (bomb-safe streaming decompression), `max_objects` per run (agent and
  server); a run exceeding it is failed.
* **Tenant isolation:** all tables use `TenantMixin`; every id of another
  organisation answers 404 (also the agent upload of another organisation's run).
* **Secrets:** see [Authentication options](#authentication-options); audit
  records never contain passwords. An Entra source holds no secret: the Azure
  connector's client secret is decrypted only in memory for the token request
  (form body, never logged; provider errors keep only the error code and
  message). A Google service-account key is stored encrypted, decrypted only in
  memory to sign the token request, and never returned (only its client email
  and key id). `python -m app.cli rotate-notification-key` re-encrypts
  directory credentials too.
* **Cloud sources are organisation-scoped like everything else:** another
  organisation never sees the source, and organisations other than the default
  can never use the server environment's Azure credentials.

## Scaling

Designed for multi-domain, multi-forest directories with 100k+ objects:

* Agent: paged LDAP search (RFC 2696, 1000/page), one page in memory, batches of
  2000, gzip; per-request 2-minute and per-run (1 h; 5 min tests) timeouts;
  safety cap `DIRECTORY_MAX_OBJECTS` (default 500 000 per run).
* Server: per-batch upsert in chunks of 500 keys; missing-marking is one UPDATE
  per scope; matching and findings read only the needed columns and write only
  rows that changed; listings are paginated in SQL with indexes on the match keys.
* Rough sizes: ~1 KB per object in the database; a 100k-object domain is about
  50 batches and a few minutes per sync.

## Notifications and audit

Notification source **Directory discovery** (`directory_source`):
`sync_failed` (grouped per source) and `not_managed_changed` (only when the
count differs from the last one notified, only after syncs). Audit actions:
`directory_source_created / updated / enabled / disabled / deleted`,
`directory_sync_requested / started / finished / failed / failed_over`,
`directory_issues_exported`, `directory_computers_added_to_assets`,
`agent_deployment_created`, `agent_deployment_revoked` (plus `enrollment_token_created`
/ `agent_installer_created` with the deployment id).

## API reference

Session-authenticated (`viewer` reads, `admin` writes), under `/api/directory`:

| Method | Path | Role |
|---|---|---|
| GET | `/sources`, `/sources/{id}` | viewer |
| POST | `/sources` | admin |
| PATCH / DELETE | `/sources/{id}` | admin |
| POST | `/sources/{id}/sync`, `/sources/{id}/test` (cloud: synchronous permission checks in the run's `checks`) | admin |
| GET | `/sources/{id}/runs`, `/runs/{id}` (cloud runs: `scope_status` per part) | viewer |
| GET | `/collectors` | viewer |
| GET | `/azure-connectors` (usable connectors, Graph permissions with app role ids, privileged roles; no secrets) | viewer |
| GET | `/google-scopes` (OAuth scopes per part, privileged roles) | viewer |
| GET | `/summary` (issue counts, coverage, source types) | viewer |
| GET | `/issues`, `/issues/export.csv` (type, kind, source_id, q, domain, limit, offset; rows carry `sources`, `privileged`) | viewer |
| GET | `/computers` (one row per machine with its `sources`; status: all, not_in_assets, matched, unmatched, ambiguous, missing), `/users` (privileged, enabled) | viewer |
| POST | `/computers/add-to-assets` (links every record of the machine) | admin |
| POST | `/deployments/plan` (`computer_ids`, or `use_filter` + `issue_type`, `source_id`, `q`, `domain`; nothing stored) | admin |
| POST | `/deployments` (selection + `name`, `routes` overrides, `expires_in_days`, `device_group`, `command_line_token`; the token is returned once) | admin |
| GET | `/deployments`, `/deployments/{id}` (progress, items, tokens without secrets) | viewer |
| POST | `/deployments/{id}/installer` (`platform`: `windows-msi` / `macos-pkg`), `/deployments/{id}/revoke` | admin |

Source bodies: `{"type": "ad", "config": {...AD...}, "collector_device_ids": [...]}` or
`{"type": "entra", "config": {"connector_id": "org" | "env", "scopes": ["users",
"roles", "devices", "intune"], "stale_days": 90, "interval_hours": 6}}`
(`tenant_id` / `client_id` are copied from the connector by the server), or
`{"type": "google", "config": {"admin_email": "...", "customer_id": "my_customer",
"scopes": ["users", "roles", "chromeos", "mobile", "endpoints"]}, "google_key":
"<service-account JSON>"}` (the key is write-only; PATCH with `google_key`
replaces it; `service_account_email`, `client_id` and `key_id` are set by the server).

Agent: `POST /api/agent/directory/runs/{run_id}/batches` (device credential +
`X-Directory-Sync-Token`, `Content-Encoding: gzip`, JSON `{seq, final,
computers[], users[], status, error, truncated, totals, duration_ms, server}`).

## Configuration

| Variable | Default | |
|---|---|---|
| `DIRECTORY_MAX_OBJECTS` | 500000 | per-run safety cap (100-2 000 000) |
| `DIRECTORY_MISSING_PURGE_DAYS` | 30 | delete objects missing that long |
| `DIRECTORY_SCHEDULER_WORKER_ENABLED` | true | internal (tests) |
| `NOTIFICATIONS_ENCRYPTION_KEY` | | encrypts service-account credentials (required in production) |

## Troubleshooting

| Symptom | Check |
|---|---|
| No collectors listed | Agent < 1.3.0, or not enrolled in this organisation. |
| "no healthy collector" | The collector agents must be online (seen in 10 min); computer-account auth needs Windows collectors. |
| `no domain controller accepted the connection` | DNS SRV lookup, firewall to 636/389, DC certificate trust (paste the CA), host name in the certificate. |
| `bind (kerberos)` fails | Collector domain-joined and running as LocalSystem; DCs listed by DNS name; clock skew < 5 min; SPN `ldap/<dc>` present. |
| `bind (simple)` fails: invalid credentials | Username format (`user@domain` or `DOMAIN\user`), password, account locked/expired. |
| Run fails after 15 min "did not pick up" | The collector is offline or its agent is stuck; failover goes to the next collector. |
| Computers "ambiguous" | Same host name on several devices / domains: update agents to 1.3.0+ (they report their SID and domain). |
| "incomplete: the safety cap was reached" | Raise `DIRECTORY_MAX_OBJECTS` or narrow base DNs. |
| Entra: connector "unusable" | It must be enabled and have tenant ID, client ID and client secret; managed identity / DefaultAzureCredential cannot be used. |
| Entra: sign-in failed `AADSTS7000215` / `AADSTS7000222` | The connector's client secret is wrong / expired: update it under Cloud connectors → Azure. |
| Entra: a part shows "no permission" | Run the permission script (as Global / Privileged Role Administrator), wait a minute for consent to apply, Test & save. |
| Entra: "Last sign-in · not licensed" | The tenant has no Entra ID P1/P2: last sign-in stays unknown; stale checks are skipped. |
| Entra: "Intune · not licensed" | No Intune licence (or the service is not set up): Intune is skipped, other parts sync. |
| Entra: run "throttled Nx" | Graph throttled the app; the sync backs off and continues. Persistent throttling: lengthen the interval. |
| Google: scope "not authorised ... in domain-wide delegation" | Add the client ID with exactly the scope string shown (no spaces); wait a few minutes. |
| Google: "Google refused the service account (Invalid email or User ID)" | The admin to impersonate is wrong or not an admin; or the key was deleted in Google Cloud. |
| Google: "the API is not enabled" | Enable `admin.googleapis.com` / `cloudidentity.googleapis.com` in the service account's project. |
| Google: endpoints empty | Google endpoint management (basic or advanced) must be on, and devices must have synced (Endpoint Verification / Drive for desktop). |

Agent logs (`collect_logs`) contain "directory sync started / finished" lines
with counts and errors, never credentials or tokens.

## Manual test checklist (real domain)

Dedicated collector (nothing below was run against a real domain by CI; the
wldap32 layer is unit-tested with a fake):

1. [ ] Import a release with collector binaries (`cnapp-ctl agent-release fetch`); the
   output lists the collector platforms. Deploy migration `0027_directory_collectors`.
2. [ ] *Collectors → Add collector*: download the installer, run `Install-Collector.ps1`
   on a member server: the collector appears online with host, domain and
   `CORP\HOST$ (computer account)`. It is **not** under Devices or IT assets.
3. [ ] Install on a DC: the installer warns and asks; the console shows the DC warning.
4. [ ] gMSA: run the console's KDS / New-ADServiceAccount / Install-ADServiceAccount
   scripts, `Test-ADServiceAccount` is True; reinstall with `-Gmsa`: run-as shows
   `CORP\svc-collector$ (gMSA)`; a sync works; the state folder and self-update work.
5. [ ] On a domain **without** LDAPS certificates: new source with the default
   transport → **Test**: all PASS, *signed+sealed: yes*; Sync now succeeds.
   Capture with Wireshark: LDAP payloads after the bind are sealed (SASL wrapped).
6. [ ] DCs with `LDAPServerIntegrity=2` (require signing): sealed sync succeeds.
7. [ ] A stale SRV record (an old DC that no longer answers): Test shows WARN *listed in
   DNS as a DC but not responding*, and the sync still uses another DC.
8. [ ] LDAPS and StartTLS still work when chosen; a service-account source refuses sealed.
9. [ ] A legacy source shows the notice; *Switch to dedicated collectors* keeps counts
   and run history; the next sync runs on the collector.
10. [ ] Stop collector 1: after 15 minutes a *collector offline* notification; Sync now
   fails over to collector 2. Revoke a collector: it gets 403 and stops.
11. [ ] Target a newer release on the default ring: the collector self-updates.

Endpoint-agent (legacy) collectors, read-only:

1. [ ] Deploy the server (migration `0020_directory_discovery`), then publish agent **v1.3.0**
   and roll it to two domain-joined Windows member servers and one Linux/macOS host.
2. [ ] *Devices → device* shows the **Directory** card (domain, NetBIOS, computer SID,
   DNS name; Entra/Intune ids on hybrid-joined devices).
3. [ ] *Directories → Add Active Directory*: both Windows agents listed as healthy; the
   Linux/macOS host shows "needs service account".
4. [ ] Run the pre-check script as SYSTEM (`PsExec -s`) on collector 1: all PASS.
5. [ ] **Test & save** (computer account): run succeeds with ≤ 10 sample names.
6. [ ] **Sync now**: object counts match `(Get-ADComputer -Filter *).Count` /
   `(Get-ADUser -Filter *).Count` for the base DN (± objects without objectGUID: none).
7. [ ] Discovery: a known unmanaged PC shows as *not managed*; a disabled computer
   with an agent as *disabled but active*; an old computer as *stale*.
8. [ ] A disabled test user signed in on a managed device → *disabled user signed in*.
9. [ ] *Add to IT assets* on one computer; then install the agent on it: the asset is
   linked, no duplicate.
10. [ ] Stop collector 1's agent; Sync now → fails over to collector 2 within ~15 min.
11. [ ] Service-account source on the Linux host (LDAPS): sync succeeds; the password never
   appears in the console, audit log, server logs or agent logs (`collect_logs`).
12. [ ] StartTLS on 389 works; a DC without a trusted certificate is refused.
13. [ ] On a DC with `LdapEnforceChannelBinding=2` and LDAP signing required, the computer-
   account sync still succeeds.
14. [ ] Move a test computer out of the base DN: after the next complete sync it is
   *missing* (not deleted) and disappears from issues.
15. [ ] Notifications: a failed sync and a change in unmanaged computers raise
   *Directory discovery* events (once).
16. [ ] Dashboards → Endpoints shows the **Agent coverage** tile.

## Manual test checklist (real Entra ID tenant)

Nothing in the test suite talks to Microsoft (Graph is faked). Before go-live,
against a test tenant (read-only):

1. [ ] Deploy the server (migration `0021_directory_cloud_sources`). The Azure connector
   is configured with a client secret.
2. [ ] *Add directory → Microsoft Entra ID + Intune*: the connector is listed as usable;
   a managed-identity / environment connector shows the "cannot call Graph" reason.
3. [ ] Run the Azure CLI script in Cloud Shell, and on a second tenant the PowerShell one:
   both add the permissions and grant consent; the "Check" lines list 6 app role ids.
4. [ ] Before running the script, **Test & save** lists the missing permissions; after, all
   pass. In a tenant without P1/P2 "Last sign-in" shows *not licensed*; without Intune
   "Intune service" shows *not licensed* (warnings only).
5. [ ] **Sync now**: user / device counts match the Entra admin center (Users, Devices) and
   Intune (Devices → All devices) within the safety cap; the run shows the request count.
6. [ ] A hybrid-joined PC with the agent: one row under *Directory computers* with AD,
   Entra ID and Intune badges, matched by SID / Entra device id; coverage counts it once.
7. [ ] An Entra-joined laptop without the agent: *No agent* once (not twice for Entra + Intune).
8. [ ] A device Intune marks non-compliant: *Non-compliant*; a Windows agent device joined to
   the tenant but not enrolled in Intune: *Not in Intune*.
9. [ ] Assign Global Administrator to a disabled test user: *Disabled admin*; to a user
   whose primary device has no agent: *Admin device without agent*; a role held through a
   role-assignable group appears "(via group)".
9a. [ ] (Entra ID P2) Make a test user only PIM-*eligible* for Global Administrator (not
   activated): it appears under *Directory users → Privileged* as "eligible (PIM)", and, if
   it has not signed in for 90+ days, as *Stale admin* "is eligible (PIM) for Global
   Administrator". Activate the role: it shows once, as active. Without P2 (or without
   `RoleEligibilitySchedule.Read.Directory`) Test & save marks PIM optional / not licensed and
   the sync shows *PIM eligible · not licensed* while everything else syncs.
10. [ ] Remove `DeviceManagementManagedDevices.Read.All` and re-sync: Intune *no permission*,
   existing Intune records kept (not missing), other parts succeed.
11. [ ] In a large tenant (10k+ users) the sync pages through everything (nextLink) and
   completes; server logs show "retrying" lines only when Graph throttles.
12. [ ] The client secret never appears in the console, API responses, audit log or server logs.
13. [ ] Disable the source during a sync: the run is cancelled, nothing is marked missing.

## Manual test checklist (real Google Workspace)

Nothing in the test suite talks to Google (faked). Before go-live, against a
test Workspace (read-only):

1. [ ] Run the gcloud commands in Cloud Shell: APIs enabled, service account created with
   no IAM roles, key downloaded, client ID printed.
2. [ ] Add the domain-wide delegation with the console's scope string; **Test & save**: every
   selected scope passes. Remove one scope from the delegation: that scope shows *missing*.
3. [ ] Wrong admin email: one clear "refused" error; the key never appears in the console,
   API responses, audit log or server logs (search for `BEGIN PRIVATE KEY`).
4. [ ] **Sync now**: user count matches Admin console → Users; ChromeOS / mobile / endpoint
   counts match Devices; a 1000+ user domain pages through completely.
5. [ ] A Windows laptop in endpoint management with the agent: matched by serial; one
   without the agent: *No agent*; a BYOD endpoint and phones: listed, no issue.
6. [ ] A suspended Super Admin: *Disabled admin*; a delegated Help Desk Admin who has not
   logged in for 90+ days: *Stale admin*; an admin whose endpoint has no agent: *Admin device
   without agent*; a role assigned to a group: its members appear "(via group)".
7. [ ] Turn off the Cloud Identity API: the endpoints part is skipped (*not enabled*), the
   rest syncs and existing endpoint records are kept.
8. [ ] Replace the key (PATCH with a new key, delete the old one in Google Cloud): the next
   sync uses the new key.

## Limitations and future work

* Okta sources.
* Google: custom admin roles are not treated as privileged; Cloud Identity
  device users give the primary user only for endpoints that report one.
* Entra: PIM for *groups* (eligible membership of a group via PIM for Groups)
  is not read, only eligible role assignments; only the global Azure cloud
  (no national clouds); the connector must use a client secret (certificate /
  managed identity not supported for Graph yet). Cloud-only users signed in on
  Windows as `AzureAD\Name` cannot be resolved to a directory user (the name is
  not the UPN); UPN-style sign-ins are.
* Hybrid AD + Entra linking uses the on-prem SID on the Entra device (when
  Graph returns it), a unique host name, or an agent reporting both ids. A
  hybrid PC without an agent whose name exists in several AD domains (and no
  SID from Graph) shows as two machines and counts twice in coverage.
* Privileged AD group membership (`memberOf`); incremental sync (DirSync /
  uSNChanged, Graph delta queries).
* `ad_object_guid` of the device itself (needs an LDAP read on the device).
* No endpoint actions are taken from discovery (no disabling accounts, no
  uninstalling, no USB / service control): it only reports.
