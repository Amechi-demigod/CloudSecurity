# Connect GCP (read-only)

The GCP connector inventories Google Cloud projects through the public REST APIs
and feeds the same inventory, posture findings, attack paths and dashboard as the
Azure connector (`source="gcp"`). It never changes anything in Google Cloud:

- the service account only gets **roles/viewer** and **roles/iam.securityReviewer**,
  and
- in code every request goes through `ReadOnlyGcpClient`, which only allows the
  read methods `get*` / `list*` / `aggregatedList` / `search*` on `*.googleapis.com`
  as HTTP GET (POST only for the read-only `getIamPolicy`), and blocks object
  reads, Secret Manager and token/signing methods. Tests enforce it.

It uses **google-auth** for credentials and its authorized HTTP session against
the REST APIs (no discovery documents or per-service client libraries, so the
image grows by about 2 MB).

This guide sets it up for the **on-prem server** (`cnapp-ctl`, settings in
`/opt/cnapp/cnapp.env`, key file in `/opt/cnapp/secrets/gcp/`). For a local/dev
backend set `GCP_CREDENTIALS_FILE` to the key's absolute path in `.env`.

## What is scanned

| Resource | Collected | Rules |
|---|---|---|
| Projects | project number, IAM policy: Owners/Editors, `allUsers` / `allAuthenticatedUsers`, project-level Service Account User / Token Creator | GCP-IAM-003 public members (CIS 1.x), GCP-IAM-004 project-wide SA impersonation (CIS 1.6), GCP-IAM-005 more than 3 Owners (CIS 1.x) |
| Service accounts | project roles, admin roles, user-managed keys and their age | GCP-IAM-001 Owner/Editor/*Admin (CIS 1.5), GCP-IAM-002 key older than 90 days (CIS 1.7) |
| VPC firewall rules | ingress allow rules, source ranges, target tags / service accounts | GCP-FW-001 SSH (CIS 3.6), GCP-FW-002 RDP (CIS 3.7), GCP-FW-003 all ports from 0.0.0.0/0 |
| Compute instances | external IPs, applicable firewall rules, service account + scopes | GCP-GCE-001 external IP (CIS 4.9), GCP-GCE-002 default SA with full API access (CIS 4.2) |
| Cloud Storage buckets | bucket IAM (`allUsers`), public access prevention, uniform bucket-level access, retention, versioning, labels | GCP-GCS-001 public (CIS 5.1), GCP-GCS-002 no uniform access (CIS 5.2) |
| GKE clusters | private nodes / endpoint, authorized networks, legacy ABAC, Workload Identity, node SA | GCP-GKE-001 legacy ABAC (CIS GKE 5.8.4), GCP-GKE-002 public control plane (CIS GKE 5.6.3), GCP-GKE-003 public nodes (CIS GKE 5.6.5), GCP-GKE-004 no Workload Identity (CIS GKE 5.2.2) |
| Cloud SQL | public IP, authorized networks, SSL mode, backups | GCP-SQL-001 0.0.0.0/0 (CIS 6.5), GCP-SQL-002 public IP (CIS 6.6), GCP-SQL-003 SSL not required (CIS 6.4), GCP-SQL-004 no backups (CIS 6.7) |
| Cloud KMS keys | purpose, rotation period | GCP-KMS-001 not rotated within 90 days (CIS 1.10) |
| Cloud Run / Cloud Functions | invoker IAM (`allUsers`), ingress, runtime service account | GCP-RUN-001 / GCP-FN-001 unauthenticated from the internet (CIS 1.x) |

Relationships: firewall rule → instance (`protects`), instance / GKE nodes / Cloud
Run / Functions → service account (`uses_identity`), service account with Owner,
Editor, Storage or Cloud SQL roles (project or bucket IAM) → buckets / Cloud SQL
(`has_access`). A VM is internet-exposed when it has an external IP **and** an
applicable firewall rule allows 0.0.0.0/0, giving attack paths such as
*Internet → web-1 (default SA, full scope) → …-compute@ service account (Editor) →
customer-pii bucket*. Buckets are sensitive when labelled `data-classification` /
`classification` / `sensitivity` / `data` (not `public`); Cloud SQL always is.

## 1. Create the scanner service account

Pick a project to own the service account (e.g. your security / tooling project):

```bash
SEC_PROJECT=acme-security
gcloud iam service-accounts create cnapp-scanner --project "$SEC_PROJECT" \
  --display-name "CloudSecurity CNAPP read-only scanner"
SA="cnapp-scanner@${SEC_PROJECT}.iam.gserviceaccount.com"

# APIs the scanner calls on behalf of its own project (quota / billing project)
gcloud services enable cloudresourcemanager.googleapis.com iam.googleapis.com --project "$SEC_PROJECT"
```

## 2. Grant read-only access

**Per project** (repeat for every project to scan):

```bash
for P in acme-prod acme-dev; do
  for ROLE in roles/viewer roles/iam.securityReviewer; do
    gcloud projects add-iam-policy-binding "$P" --member "serviceAccount:$SA" --role "$ROLE" --condition None
  done
done
```

**Or once for the whole organization** (every current and future project):

```bash
ORG_ID=$(gcloud organizations list --format 'value(ID)' --filter 'displayName=acme.com')
for ROLE in roles/viewer roles/iam.securityReviewer; do
  gcloud organizations add-iam-policy-binding "$ORG_ID" --member "serviceAccount:$SA" --role "$ROLE" --condition None
done
```

(Folder level works the same with `gcloud resource-manager folders add-iam-policy-binding`.)
The scanner only calls an API in a project where it is enabled; disabled APIs are
skipped because no such resources can exist there.

## 3. Create a key and install it on the server

```bash
gcloud iam service-accounts keys create cnapp-scanner.json --iam-account "$SA"
scp cnapp-scanner.json admin@cnapp-server:/tmp/   # any secure copy
```

On the server:

```bash
sudo cnapp-ctl gcp-key install /tmp/cnapp-scanner.json
shred -u /tmp/cnapp-scanner.json                   # remove the original copy
```

`cnapp-ctl gcp-key install`:

- checks the file is a service account key (or workload identity federation
  config) without ever printing it, and shows only its type and service account;
- copies it to `/opt/cnapp/secrets/gcp/credentials.json`: directory 0700, file
  0600, both owned by the backend user (uid 10001), atomically;
- sets `GCP_CREDENTIALS_FILE=/run/secrets/gcp/credentials.json` in `cnapp.env`
  (the path only: **the key is never stored in `cnapp.env`** or logged);
- recreates the backend, which mounts `/opt/cnapp/secrets/gcp` **read-only** at
  `/run/secrets/gcp`.

`sudo cnapp-ctl gcp-key status` shows the file's mode and identity;
`--no-restart` defers the restart. Nightly config backups
(`cnapp-ctl backup`) include `/opt/cnapp/secrets`, so protect them like the other
secrets.

If your organization blocks key creation (`iam.disableServiceAccountKeyCreation`),
use workload identity federation instead: create a pool and provider for an
identity source the server has (e.g. an OIDC token file), then
`gcloud iam workload-identity-pools create-cred-config ... --service-account "$SA" --output-file cnapp-wif.json`
and install that file with the same `cnapp-ctl gcp-key install`. A
`credential_source.file` must point to a path inside the backend container, i.e.
a file you also place in `/opt/cnapp/secrets/gcp/` (owner 10001, mode 0600) and
reference as `/run/secrets/gcp/<name>`. Executable-sourced credentials are not
supported.

## 4. Choose the projects

Edit `/opt/cnapp/cnapp.env` (older installs: add the lines):

```bash
# Either explicit projects (comma-separated project IDs) ...
GCP_PROJECT_IDS=acme-prod,acme-dev
# ... and/or every ACTIVE project under the organization (walks all folders)
GCP_ORGANIZATION_ID=123456789012
```

```bash
sudo cnapp-ctl restart
```

The backend refuses to start on malformed values (a project ID with capitals or
underscores, a non-numeric organization ID, a relative `GCP_CREDENTIALS_FILE`) and
names the setting. A missing or unreadable key file leaves the connector *Not
configured* with the reason on its card.

Then open **Connectors & scans**: the GCP card shows *Configured* and the projects;
click **Run scan** (analyst or admin). `GET /api/health` reports
`gcp_configured: true`. Results appear in **Inventory** and **Findings** (filter
**Cloud = GCP**), attack paths and the dashboard.

## Network and proxy

The server needs outbound HTTPS (TCP 443) to `oauth2.googleapis.com` (token) and
`cloudresourcemanager`, `compute`, `storage`, `container`, `sqladmin`, `iam`,
`cloudkms`, `cloudfunctions` and `run` `.googleapis.com` (federation also needs
`sts.googleapis.com` and `iamcredentials.googleapis.com`). If it must use a proxy,
set it in `/opt/cnapp/cnapp.env`:

```bash
HTTPS_PROXY=http://proxy.corp.local:3128
NO_PROXY=.corp.local
```

and `sudo cnapp-ctl restart`. If the proxy inspects TLS, its CA must be trusted
by the backend image; certificate verification is never disabled.

## Scans, throttling and partial results

- HTTP 429 and 5xx responses are retried with exponential backoff (honouring
  `Retry-After`); list calls follow `nextPageToken`.
- A failure in one project or API (permission denied, outage) is recorded in the
  scan's **errors** (see **Scan history**) and the rest continues; APIs that are
  not enabled are listed on the project asset (`apis_not_enabled`) instead.
- Re-scans resolve findings that now pass. Scheduled scans use the same entry
  point as **Run scan**.

## Rotate or remove the key

```bash
gcloud iam service-accounts keys create new.json --iam-account "$SA"
sudo cnapp-ctl gcp-key install new.json && shred -u new.json
gcloud iam service-accounts keys list --iam-account "$SA" --managed-by user
gcloud iam service-accounts keys delete <old-key-id> --iam-account "$SA"
```

Disconnect: `sudo cnapp-ctl gcp-key remove` (shreds the file, unsets
`GCP_CREDENTIALS_FILE`, restarts the backend), clear `GCP_PROJECT_IDS` /
`GCP_ORGANIZATION_ID`, then delete the key or the service account in Google Cloud.
Note the scanner's own key is reported by GCP-IAM-002 once it is older than 90
days: rotate it.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Card says *Not configured* | Key installed (`cnapp-ctl gcp-key status`) and `GCP_PROJECT_IDS` or `GCP_ORGANIZATION_ID` set, then restart |
| *GCP_CREDENTIALS_FILE ... does not exist / not readable* | Reinstall with `cnapp-ctl gcp-key install` (fixes owner 10001 and mode 0600) |
| `credentials: ...` or `oauth2.googleapis.com` errors | Key deleted/disabled, clock skew, or no route/proxy to Google |
| `<project>/project: ... 403` | The service account has no role on that project, or Cloud Resource Manager API is disabled in `$SEC_PROJECT` |
| `organizations/<id>: project discovery: ... 403` | Grant the roles at organization level (step 2); add `roles/browser` if folder listing is restricted |
| `<project>/<api>: ... 403 PERMISSION_DENIED` | A role or VPC Service Controls perimeter blocks the read; other APIs still scan |
