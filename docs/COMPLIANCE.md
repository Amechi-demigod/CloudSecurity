# Compliance reports

**Compliance** (top of the console navigation) shows how the platform's own
checks line up with common security frameworks: per framework, which controls
the automated evidence passes, fails or only partly covers, which have nothing
to evaluate, and which need manual evidence. It exports CSV and PDF and can
email the PDF on a schedule.

> **Evidence to support an assessment, not an audit opinion.** The platform
> never certifies anything. A score only summarises the controls it can check
> automatically; every framework has controls (policies, people, physical
> security, supplier management...) that need manual evidence, and an auditor
> decides whether a control is met.

## Contents

- [Frameworks](#frameworks)
- [How the mapping works](#how-the-mapping-works)
- [Checks](#checks)
- [Scoring](#scoring)
- [Scope filters](#scope-filters)
- [Trend](#trend)
- [Exports](#exports)
- [Scheduled reports](#scheduled-reports)
- [Security model](#security-model)
- [API reference](#api-reference)
- [Configuration](#configuration)
- [Adding a framework](#adding-a-framework)
- [Limitations](#limitations)

## Frameworks

| File | Framework | Controls | With automated evidence |
|---|---|---|---|
| `cis.json` | CIS Benchmarks: Microsoft Azure, AWS and Google Cloud foundations, AKS / EKS / GKE (the recommendations the cloud rules check), plus CIS Critical Security Controls v8 endpoint and identity safeguards | 83 | 83 |
| `iso27001-2022.json` | ISO/IEC 27001:2022 Annex A | 93 | 25 |
| `soc2-2017.json` | SOC 2, 2017 Trust Services Criteria, common criteria (Security) | 33 | 8 |
| `nist-csf-2.0.json` | NIST Cybersecurity Framework 2.0 (subcategories) | 106 | 17 |
| `pci-dss-4.0.json` | PCI DSS v4.0 (requirements at two levels, e.g. 8.4) | 63 | 22 |

Files live in `backend/app/compliance/frameworks/`. Data protection laws
(NDPA, GDPR...) are not in v1: they are mostly organisational, and can be added
as data files ([Adding a framework](#adding-a-framework)).

**Copyright.** CIS, ISO/IEC, PCI SSC and AICPA texts are copyrighted. The files
hold only control identifiers and our **own short paraphrased titles**, never
the publisher's control text; refer to the publisher for the requirement
itself. NIST CSF is a public-domain US government work (titles are still short
summaries).

**CIS numbering.** The CIS cloud controls are the recommendations the posture
rules are tagged with (`compliance` on each rule in `backend/app/engine/posture*.py`);
their numbers follow the benchmark versions the rules were written against and
can differ in other benchmark versions. Tags like `CIS Azure 4.3.x` stand for
several recommendations of one section and are always "partial".

## How the mapping works

```
framework file ─ group ─ control {id, title, checks, coverage, note}
                                     │
                                     ├─ "cloud:AWS-IAM-001"        a check id
                                     └─ "@encryption-in-transit"   a named check set (checksets.json)
```

* A control lists the checks that provide **automated evidence** for it, either
  directly or through a named **check set** (`checksets.json`, e.g.
  `@public-network-exposure`), and how much of the control they cover:
  * `full`: the checks are the control (only CIS benchmark recommendations that
    one rule checks exactly),
  * `partial`: the checks cover a technical part of the control; the rest needs
    manual evidence. Every ISO, SOC 2, NIST and PCI control is at most partial.
* A control without checks is **manual** ("not assessed automatically").
* The mapping is deliberately conservative: a control gets checks only where
  the platform's checks genuinely evidence it. For example ISO A.8.15 Logging
  uses the cloud audit-logging rules; A.5.24 Incident management planning has
  no automated evidence.
* Each file has a `mapping_version`; increase it when the mapping changes so
  scores before and after are not compared blindly (the trend points carry it).
* `tests/test_compliance.py` checks that every referenced check and check set
  exists, every cloud posture rule belongs to at least one check set, the CIS
  file matches the rules' CIS tags, and no non-CIS control claims full coverage.

## Checks

| Id | Evidence | Pass / fail | No data when |
|---|---|---|---|
| `cloud:<rule id>` | A cloud posture rule (Azure, AWS, GCP) | Fails while the rule has an open finding; otherwise passes | No resource of the rule's type in scope |
| `endpoint:disk_encryption`, `firewall`, `antivirus`, `screen_lock`, `sip`, `gatekeeper`, `secure_boot` | Endpoint agent posture checks | Fails on active devices reporting the check as failed | No active device reports the check (e.g. SIP without macOS devices) |
| `endpoint:av_signatures`, `os_updates`, `checkin` | Signature age, pending OS updates past the grace period, no check-in for a week | Same device issues as the Devices page | No active device |
| `vuln:kev` | Open CISA known-exploited vulnerabilities | Fails while any is open | No vulnerability data and no device in scope |
| `vuln:critical_sla`, `vuln:high_sla` | Critical / high vulnerabilities open longer than `DASHBOARD_SLA_CRITICAL_DAYS` / `DASHBOARD_SLA_HIGH_DAYS` | | |
| `directory:<issue type>` | Directory discovery issues (no agent, stale / disabled accounts, privileged admins at risk, Intune compliance...; [DIRECTORY_DISCOVERY.md](DIRECTORY_DISCOVERY.md#discovery-issues)) | Fails while the issue is open | No synced directory that can report the issue (e.g. Intune issues need an Entra ID source) |
| `inventory:cloud_scan` | A successful cloud scan within 7 days | | No scan yet |
| `inventory:directory_sync` | Every enabled directory synced successfully within 3 days | | No directory |

Suppressed posture findings (accepted risk) do not fail a check. Each failing
check lists up to 25 failing objects with links (finding, device, discovery
issue) and a link to the full filtered list.

## Scoring

Per control, from its coverage and its checks' status:

| Status | Meaning |
|---|---|
| **Fail** | At least one mapped check fails |
| **Pass** | Coverage `full` and every mapped check passes |
| **Partial** | Nothing fails and at least one check passes, but the coverage is partial or some checks have no data: the automated part passes, the rest needs manual evidence |
| **No data** | Checks are mapped but none has anything to evaluate in scope |
| **Manual** | No automated check: not assessed automatically |

* **Score** = (pass + partial) / (pass + partial + fail): the share of
  automatically assessed controls without failing evidence. "n/a" when nothing
  is assessed.
* **Automated coverage** = (pass + partial + fail) / all controls.

Code: `backend/app/compliance/scoring.py` (pure, unit-tested),
`checks.py` (evaluation), `service.py` (posture, snapshots, CSV).

## Scope filters

A report covers the whole organisation, or one **cloud account** (Azure
subscription, AWS account, GCP project), or one **device group**:

* cloud account: cloud checks, vulnerabilities on that account's workloads and
  the cloud scan check; endpoint and directory checks are *out of scope* (they
  count as no data);
* device group: endpoint checks and the group's device vulnerabilities; cloud
  and directory checks are out of scope.

## Trend

The daily snapshot job (the one behind the dashboards' "vs previous period",
leader-elected) also stores each framework's summary per organisation, for the
whole organisation, each cloud account and each device group
(`compliance_snapshots`). The first read of a scope on a day writes it lazily.
The trend chart shows the score and automated coverage for the last 90 days.

## Exports

* **Export CSV**: one row per control and check (control, paraphrased title,
  status, coverage, check, check status, failing / evaluated counts), with the
  disclaimer and scope on the first lines. Spreadsheet formulas are neutralised.
* **PDF report**: the server-generated PDF (the same one scheduled emails
  attach): cover with the disclaimer, then per framework the summary and every
  control with its status and evidence, failing checks with up to 5 failing
  objects each. Dependency-free writer (`backend/app/compliance/pdf.py`,
  standard PDF fonts, A4).
* **Export PDF**: prints the page (or saves it as PDF) like the dashboards.

Exports are audited (`compliance_report_exported`). PDF exports are limited to
10 per user per 10 minutes.

## Scheduled reports

Admins schedule reports under **Compliance → Scheduled reports**: name,
frameworks, weekly (day of week) or monthly (day 1-28), hour (UTC) and
recipients. Up to 10 schedules per organisation, 20 recipients each.

* **Recipients must be active members of the organisation.** A report lists
  the organisation's weaknesses, so it is not sent to arbitrary addresses;
  invite an auditor as a viewer first. A member who is deactivated later is
  skipped (noted in the schedule's last result).
* Sent by the platform's transactional mailer (`PLATFORM_SMTP_*` or
  `PLATFORM_ACS_*`, see [MULTI_TENANCY.md](MULTI_TENANCY.md#email-for-invitations)),
  branded with `BRAND_NAME`, with the PDF attached and a link to the console
  when `PUBLIC_BASE_URL` is set. Without a mail server the schedule records
  "failed: no platform mail server configured".
* A leader-elected worker checks every 5 minutes; a slot missed while the
  server was down is sent once, then the next slot is computed (no backlog).
* **Send now** (admin) sends immediately without moving the schedule; limited
  to 5 per organisation per hour.
* A PDF over `COMPLIANCE_REPORT_MAX_BYTES` is not sent (narrow the report).

## Security model

* **RBAC:** viewers (and above) see posture, trend and schedules and export
  CSV / PDF; only admins create, edit, delete and send schedules and list
  possible recipients.
* **Tenancy:** both tables use `TenantMixin`; every query runs in the
  session's organisation; another organisation's schedule id answers 404; the
  worker processes each organisation in its own scoped session.
* **Audit:** `compliance_schedule_created / updated / deleted`,
  `compliance_report_sent / failed` (trigger, frameworks, recipient count,
  size, errors), `compliance_report_exported` (format, frameworks, scope).
* **Caps:** at most 25 failing objects per check in the API and 5 in the PDF,
  10 schedules per organisation, 20 recipients, PDF size cap, rate limits above.

## API reference

Session-authenticated, under `/api/compliance`:

| Method | Path | Role |
|---|---|---|
| GET | `/frameworks?account=&device_group=` (summary of every framework, scope options) | viewer |
| GET | `/frameworks/{id}?account=&device_group=` (controls, status, checks, failing objects) | viewer |
| GET | `/frameworks/{id}/trend?days=90` | viewer |
| GET | `/frameworks/{id}/export.csv` | viewer |
| GET | `/report.pdf?frameworks=cis,iso27001-2022` | viewer |
| GET | `/schedules` | viewer |
| GET | `/recipients` (active members) | admin |
| POST | `/schedules` `{name, frameworks, frequency, day, hour, recipients, enabled, account?, device_group?}` | admin |
| PATCH / DELETE | `/schedules/{id}` | admin |
| POST | `/schedules/{id}/send` | admin |

## Configuration

| Variable | Default | |
|---|---|---|
| `COMPLIANCE_REPORT_MAX_BYTES` | 8388608 | largest PDF emailed (256 KiB - 20 MiB) |
| `COMPLIANCE_REPORT_WORKER_ENABLED` | true | internal (tests) |
| `DASHBOARD_SLA_CRITICAL_DAYS` / `DASHBOARD_SLA_HIGH_DAYS` | 7 / 30 | SLA of the `vuln:*_sla` checks |

## Adding a framework

1. Add `backend/app/compliance/frameworks/<id>.json` (the `id` equals the file
   name): `name`, `short_name`, `version`, `mapping_version`, `publisher`,
   `notice` (copyright / scope note) and `groups` of `controls`
   (`{"id", "title"}` plus, only where the evidence is genuine, `"checks"` and
   `"coverage": "partial"`; an optional `"note"`). Use your own short titles.
2. Reuse check sets from `checksets.json` where they fit; add a set when
   several controls share the same evidence.
3. Run `pytest tests/test_compliance.py` (unknown checks fail loudly) and add
   the expected control count to `EXPECTED_CONTROLS`.
4. Files are shown after the v1 frameworks (`catalog.ORDER` sets the order).

New checks (a new posture rule, endpoint check or issue type) appear in
`checks.registry()` automatically for rules; endpoint, vulnerability,
directory and inventory checks are listed in `checks.py`. A new posture rule
must be added to a check set (the test enforces it).

## Limitations

* No evidence upload or manual attestation yet: manual controls stay "manual".
* The platform does not know which systems are in a PCI cardholder data
  environment or an ISO scope: automated evidence covers everything in the
  report's scope.
* Endpoint checks cover enrolled devices only; machines without an agent show
  up through the directory `not_managed` check when a directory is connected.
* MFA evidence covers AWS console users (cloud rules); identity-provider MFA
  policies (Entra ID conditional access, Google 2SV) are not read yet.
* SOC 2 availability, confidentiality, processing integrity and privacy
  categories are not included (Security / common criteria only).
