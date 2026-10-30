# Dashboards

The **Dashboards** page (route `/`) has five tabs: **Overview**, **Vulnerabilities**,
**External exposure**, **Identities** and **Endpoints**. Each tab is one API call:

```
GET /api/dashboards                                   tab badges, cloud accounts, settings
GET /api/dashboards/{tab}?range=30d&account=<id>      tab = overview | vulnerabilities | exposure | identities | endpoints
```

Any signed-in user (viewer or above) can read them. Everything is scoped to the
user's organisation (see [MULTI_TENANCY.md](MULTI_TENANCY.md)). The code is in
`backend/app/services/dashboards.py`.

## Filters

| Parameter | Values | Effect |
|---|---|---|
| `range` | `7d`, `30d` (default), `90d` | Period for trends, "new vs resolved", mean time to resolve, and the "vs previous period" changes. Bar charts (new vs resolved) use daily buckets at 7 days and weekly buckets from 30 days; line charts (point-in-time series) stay daily up to 30 days and go weekly at 90. |
| `account` | an Azure subscription, AWS account or GCP project id (`Asset.subscription_id`) | Findings, vulnerabilities, runtime alerts, attack paths, exposure and identities are limited to that account's assets. Endpoint devices are not tied to a cloud account and are never filtered (their vulnerabilities are left out of an account view). |

## Where each number comes from

| Tab | Number | Source |
|---|---|---|
| Overview | Risk score | `engine/risk.overall_risk_score` (same as the old dashboard), scoped to the account |
| | Open issues, Critical & high | open posture findings (`Finding.status = open`) by severity |
| | Mean time to resolve | findings resolved in the period: mean of `resolved_at - first_seen`, per severity; "SLA met" = share of critical and high findings resolved within their SLA target |
| | Internet-exposed assets | the same items as the Exposure page (`services/exposure.exposure_items`), grouped by asset type |
| | Active runtime threats | alerts not resolved, by severity |
| | Attack paths | confirmed attack paths, by severity |
| | Issue trend | findings first seen / resolved per day (or week) |
| | Compliance posture | `analytics.compliance_summary` (a control passes when none of its mapped rules has an open finding), for the frameworks that apply to the asset types present |
| | Open issues by age | open findings by age of `first_seen`: 0–7, 8–30, 31–90, 90+ days |
| | Findings by category | open findings by category (mapping below) |
| | Top risky assets | per asset, the higher of its riskiest open vulnerability's risk (0–100) and a floor from its worst open finding (critical 85, high 65, medium 40, low 15); ties broken by open critical, then open high (findings + vulnerabilities), then internet-exposed, then sensitive data, then name |
| | Endpoints strip | active devices: healthy, failing a posture check (any device issue other than stale / inactive), sign-in suspended (`isolation_status` isolating / isolated / restoring), outdated agent (older than the newest imported release, else the newest version in the fleet) |
| Vulnerabilities | Critical, KEV, Loaded at runtime, Fix available % | open vulnerabilities (`fixed_version` set = fix available) |
| | Critical & high over time | open at the end of each bucket, from `first_seen` / `resolved_at`; "Prioritised" (risk priority critical or high) comes from the daily snapshots |
| | Impact by workload type | open vulnerabilities by asset type group (pods, clusters, VMs, functions) and endpoint devices |
| | Top CVEs to fix first | open vulnerabilities grouped by CVE, ranked KEV first, then runtime + internet, EPSS, risk, CVSS |
| External exposure | Exposed assets, data stores | exposure items (data stores = storage, database and key vault types) |
| | Open management ports | exposed assets with SSH 22, RDP 3389 or WinRM 5985/5986 open to the internet (effective ports, or the rules of the network controls protecting them) |
| | Paths to crown jewels | confirmed attack paths whose target holds sensitive data |
| | Exposure trend | daily snapshots |
| Identities | | identity assets (`identity`, `iam_user`, `iam_role`, `gcp_service_account`); privileged = admin flag / admin roles, or Owner / Contributor / User Access Administrator (roles/owner, roles/editor) at subscription / account / project scope; identity findings = the Identity category |
| Endpoints | | the device fleet (as above) and vulnerabilities found on devices |

Every number links to the filtered list behind it (Findings, Vulnerabilities,
Exposure, Inventory, Runtime threats, Attack paths, Devices).

## Changes "vs previous period" and snapshots

* **Flow metrics** (mean time to resolve) compare the current period with the
  previous period of the same length, from `first_seen` / `resolved_at`.
* **Point-in-time counts** (open issues, exposed assets, risk score, compliance
  %, KEV, ...) cannot be rebuilt from history, so a background job stores them
  once a day in `dashboard_snapshots` (migration `0016`): one row per
  organisation, UTC day and account scope (all accounts, and each cloud
  account). The change is today's value minus the snapshot taken `range` days
  ago (a snapshot up to 2 days older is accepted if the job missed a day; a
  newer one never is).
* With **no snapshot for the comparison day the change is `null`** and the page
  hides the chip. Numbers are never invented.
* The job (`services/dashboard_snapshots.py`) is leader-elected like the scan
  scheduler (one process per deployment) and idempotent. If today's row is
  missing when a dashboard is opened, it is written then.
* **Trends and changes fill in from the day this version is deployed**: on day
  one every chip is hidden and snapshot-based trend lines have a single point;
  after 7 / 30 / 90 days the matching ranges have full comparisons.

## Category mapping (findings by category)

The service code in the rule id decides (`AZ-STG-001` -> `STG`); rules with
an unknown service code fall back to the affected asset's type.

| Category | Rule service codes | Asset types (fallback) |
|---|---|---|
| Network | NSG, SG, FW, VNET, APPGW | nsg, security_group, gcp_firewall_rule, vnet, azure_firewall, firewall_policy, private_endpoint |
| Storage | STG, S3, GCS | storage_account, s3_bucket, gcs_bucket |
| Identity | ID, IAM, SUB | identity, iam_user, iam_role, gcp_service_account, subscription, aws_account, gcp_project |
| Databases | SQL, SQLMI, MYSQL, PG, COSMOS, REDIS, RDS | sql_server, sql_database, sql_managed_instance, postgresql_server, cosmos_account, redis_cache, rds_instance, cloud_sql_instance |
| Kubernetes | AKS, EKS, GKE, POD | aks_cluster, eks_cluster, gke_cluster, pod |
| Secrets | KV, KMS | key_vault, kms_key, gcp_kms_key |
| Compute | VM, VMSS, EC2, GCE, FN, LMB, RUN, APP | vm, vmss, ec2_instance, gce_instance, function_app, web_app, lambda_function, cloud_function, cloud_run_service |
| Other | anything else (e.g. AWS-CT, CloudTrail logging) | |

`GET /api/findings?category=<name>` lists the findings of one category.

## SLA targets

| Variable | Default | Meaning |
|---|---|---|
| `DASHBOARD_SLA_CRITICAL_DAYS` | `7` | A critical finding resolved within this many days of first being seen meets its SLA |
| `DASHBOARD_SLA_HIGH_DAYS` | `30` | Same for high findings |

Both must be more than 0 and at most 3650; otherwise the API refuses to start.

## Limitations

* Snapshot-based numbers (changes, the exposure trend and the "Prioritised"
  line) start on deploy day; there is no backfill.
* Mean time to resolve covers posture findings (not vulnerabilities or alerts).
* Endpoint devices are not tied to cloud accounts, so the account filter does
  not apply to the Endpoints tab or strip.
