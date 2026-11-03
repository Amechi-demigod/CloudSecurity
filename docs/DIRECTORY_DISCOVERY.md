# Directory discovery (on-prem Active Directory)

Directory discovery compares what your directory knows with what the platform
manages. Your own enrolled agents read Active Directory from inside your
network (the platform never connects to a domain controller). The results answer:

* which computers sign in to the domain but have **no agent** ("not managed"),
* which computer accounts are **stale** (no domain logon for 90+ days),
* which computers are **disabled in AD but still in use** (their agent still checks in),
* which agent devices are joined to a synced domain but **unknown to the directory**,
  and which are **not domain-joined** at all,
* which **disabled or stale AD users** are signed in on managed devices.

It also adds the owner's directory identity (display name, email, department)
to IT assets, and lets admins **add directory computers to IT assets**.

Phase 1 (this release) ships the shared framework and **on-prem Active
Directory**. The source `type`, the provider-neutral object model (stable
`external_id` per source, provider attributes in JSON) and the matching tiers
are ready for Entra ID, Google Workspace and Okta sources later.

## Contents

- [Architecture](#architecture)
- [Collector requirements](#collector-requirements)
- [Network ports](#network-ports)
- [Authentication options](#authentication-options)
- [Least privilege](#least-privilege)
- [Setting up a source](#setting-up-a-source)
- [Scheduling](#scheduling)
- [Domain-join facts](#domain-join-facts)
- [Matching](#matching)
- [Discovery issues](#discovery-issues)
- [Adding computers to IT assets](#adding-computers-to-it-assets)
- [Security model](#security-model)
- [Scaling](#scaling)
- [Notifications and audit](#notifications-and-audit)
- [API reference](#api-reference)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Manual test checklist (real domain)](#manual-test-checklist-real-domain)
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
scheduler, api, agent_api), `endpoint-agent/internal/directory/` (LDAP client,
decoding, batching), `endpoint-agent/internal/collect/join*.go` (domain-join facts).

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
| collector | DCs | TCP 636 (LDAPS) **or** TCP 389 + StartTLS | directory reads (TLS 1.2+) |
| collector | DNS servers | UDP/TCP 53 | DC locator SRV lookups |
| collector | DCs | TCP/UDP 88 | Kerberos (computer-account auth only) |
| collector | platform | TCP 443 | commands + batch upload (existing agent traffic) |

Plain, unencrypted LDAP is **never** used. go-ldap does not implement SASL
signing/sealing (it negotiates no SASL security layer), so port 389 is only
accepted with StartTLS; integrity and confidentiality always come from TLS.

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

1. Install agent 1.3.0+ on two domain-joined Windows hosts (any member servers
   or admin workstations that stay on).
2. **Connectors & scans → Directories → Add Active Directory.** Enter the
   domain (e.g. `corp.example.com`), choose the collectors (only agents
   advertising `directory_collector` are listed), keep *Collector's computer
   account* or switch to *Read-only service account*. Advanced: DCs (default:
   DC locator), base DNs (default: domain root), LDAPS 636 / StartTLS 389,
   extra CA, stale threshold (90 days), sync interval (6 h), objects (computers, users).
3. Copy the **pre-check script** and run it on the collector (as SYSTEM via
   `PsExec -s powershell` for the computer-account option). It only reads: DNS
   SRV lookup, TCP reachability, the DC certificate, an LDAPS bind and a 5-object
   search.
4. **Test & save.** The source is saved and a test sync (at most 10 objects,
   nothing stored but their names) is queued; collectors pick up commands
   within about a minute.
5. The first full sync runs on schedule (immediately for a new source) or with
   **Sync now**. Results: **IT assets → Discovery**.

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

Computers are matched to agent devices in tiers, strongest first
(`backend/app/directory/matching.py`, pure and unit-tested). A tier matches only
when the key is unique on both sides among what is still unmatched; otherwise
the computer is **ambiguous** (flagged with its candidates, never guessed) and
weaker tiers are not tried:

| Tier | Key | Confidence |
|---|---|---|
| `directory_sid` / `directory_guid` | computer account SID / objectGUID reported by the agent | 100 |
| `serial` | serial number (when the directory has one; not AD today) | 95 |
| `fqdn` | dNSHostName = device FQDN (reported, hostname, or hostname + AD domain) | 90 |
| `hostname_domain` | short host name within the same AD domain | 75 |
| `hostname` | short host name for devices that report no domain (older agents), only if the name exists once across **all** directory computers | 50 |

Comparisons are case-insensitive. The same object synced by two sources
(overlapping configuration, same objectGUID) is matched once. A computer
matched to a device is linked to that device's IT asset.

**Users** are matched to signed-in users (`DOMAIN\user`, `user@upn`) and IT
asset owners by sAMAccountName within the device's domain (the NetBIOS prefix is
mapped via the domain-join facts), or UPN / email. Entra ID (`AzureAD\…`), local
and service accounts are ignored; names present in several domains without a
domain hint are ambiguous and ignored. IT assets keep the agent-always-wins
**username owner rule**: the username stays the owner key; the directory
identity (display name, email, department, enabled) is display-only enrichment
(`owner_directory` in the IT asset API).

## Discovery issues

| Type | Meaning |
|---|---|
| `not_managed` | Enabled computer with a domain logon within the stale window, no matched (active) agent device |
| `stale_computer` | Enabled computer with no domain logon for `stale_days` (default 90; never-logged-on computers older than that too) |
| `disabled_but_active` | Disabled in AD, but its matched agent checked in within 7 days |
| `unknown_to_directory` | Active agent device joined to a synced domain with no matching directory computer (or several possible ones) |
| `not_domain_joined` | Active agent device (1.3.0+) that reports no AD domain |
| `disabled_user_signed_in` | A user disabled in AD is signed in on a managed device |
| `stale_user_signed_in` | A signed-in user has no domain logon for `stale_days` |

`lastLogonTimestamp` replicates with up to ~14 days of lag by design, which is
why the stale threshold is in weeks, not days. Issues are stored
(`directory_findings`), keep their first-seen time across re-evaluations, and
are listed with filters, search, pagination and CSV export on **IT assets →
Discovery**. The same object from two sources is reported once.

## Adding computers to IT assets

Directory computers that are not IT assets are only listed under Discovery: they
are **never created automatically**. Admins choose **Add to IT assets** (one or
in bulk, up to 1000 per request): each becomes an asset with source
`directory`, status `in_stock`, tag `DIR-<NAME>`, type `server` (server OS) or
`computer`, with the DN in its notes and a custody event. When that computer
later gets an agent, the device is linked to this asset (matched directory
computer, or same short name and domain) instead of creating a duplicate.

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
  records never contain passwords.

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
`directory_issues_exported`, `directory_computers_added_to_assets`.

## API reference

Session-authenticated (`viewer` reads, `admin` writes), under `/api/directory`:

| Method | Path | Role |
|---|---|---|
| GET | `/sources`, `/sources/{id}` | viewer |
| POST | `/sources` | admin |
| PATCH / DELETE | `/sources/{id}` | admin |
| POST | `/sources/{id}/sync`, `/sources/{id}/test` | admin |
| GET | `/sources/{id}/runs`, `/runs/{id}` | viewer |
| GET | `/collectors` | viewer |
| GET | `/summary` (issue counts, coverage) | viewer |
| GET | `/issues`, `/issues/export.csv` (type, kind, source_id, q, domain, limit, offset) | viewer |
| GET | `/computers` (status: all, not_in_assets, matched, unmatched, ambiguous, missing), `/users` | viewer |
| POST | `/computers/add-to-assets` | admin |

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

Agent logs (`collect_logs`) contain "directory sync started / finished" lines
with counts and errors, never credentials or tokens.

## Manual test checklist (real domain)

Run before go-live against a test or production domain (read-only):

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

## Limitations and future work

* Entra ID, Google Workspace and Okta sources (the framework is ready: `type`,
  provider-neutral `external_id`, matching tiers incl. Entra device id).
* Privileged group membership (`memberOf`) for "privileged user on unmanaged
  device" findings; incremental sync (DirSync / uSNChanged).
* `ad_object_guid` of the device itself (needs an LDAP read on the device).
* No endpoint actions are taken from discovery (no disabling accounts, no
  uninstalling, no USB / service control): it only reports.
