# Cloud inventory lifecycle

How Sentrigis keeps the cloud inventory (Azure subscriptions, AWS accounts, Google Cloud projects) in step with
what exists in the cloud, and how an administrator removes a subscription / account / project.

Code: `backend/app/services/cloud_lifecycle.py`, `backend/app/services/ingest.py`, the connectors in
`backend/app/connectors/`, endpoints in `backend/app/api/organization.py`.

## Resources deleted in the cloud

A scan only adds and updates assets. To notice resources that were deleted in the cloud, every successful scan
of a scope also counts the assets it did **not** return:

1. **Only successfully read scopes count.** A connector lists in `CollectionResult.scopes_read` the
   subscriptions / accounts / projects it read completely: the scope's collection finished and produced no error
   at all (no failed step, no permission error, no exception). A scan that fails, or fails for one scope, never
   counts for that scope; each scope is judged on its own. A scope that returned no asset (not even its own
   subscription / account / project asset) does not count either. When in doubt, nothing is counted.
2. For each scope read, every cloud asset of that connector in that scope that was not returned gets
   `assets.missed_scans` + 1; one that was returned is reset to 0.
3. At `CLOUD_REMOVE_AFTER_MISSES` misses in a row (default 2) the asset is **removed**: `assets.removed_at` is
   set, its open findings close with the reason `resource_removed` ("Closed · resource removed" in the console)
   and its open vulnerabilities resolve.
4. Removed assets are excluded from the active inventory, risk scores, exposure, attack paths, posture
   evaluation, compliance results, the dashboards and the subscription filters. They show on the **Removed** tab
   of the inventory (Cloud > Inventory) and their closed findings stay visible (Findings: Status = resolved,
   Reason = Resource removed). Findings closed for a removal are not counted as remediation (MTTR, new vs resolved).
5. **If the resource reappears** in a successful scan before it is deleted permanently, it is active again
   (`removed_at` cleared, misses 0) and posture evaluation reopens whatever still fails.
6. **Permanent deletion.** A leader-elected background job (`CloudPurgeWorker`, hourly, one process runs it)
   deletes assets removed more than `CLOUD_REMOVED_RETENTION_DAYS` days ago (default 60) together with their
   findings, vulnerabilities, relationships, packages, alerts and runtime events, and writes a
   `cloud_resources_purged` audit entry.

Only assets of the Azure, AWS and GCP connectors take part. Devices with the agent, directory objects, runtime
sensor hosts, the simulated connector's workloads and external attack-surface hosts have their own lifecycles.
Nothing disappears when this is deployed: existing assets start with 0 misses and follow the same rule.

| Setting | Default | Meaning |
| --- | --- | --- |
| `CLOUD_REMOVE_AFTER_MISSES` | 2 | successful scans of a scope without an asset before it is marked removed |
| `CLOUD_REMOVED_RETENTION_DAYS` | 60 | days a removed asset (and its closed findings) is kept before permanent deletion |
| `CLOUD_PURGE_WORKER_ENABLED` | true | run the purge job in this process (internal; tests turn it off) |

## Removing a subscription, account or project

Settings > Connectors & scans > (cloud) > **Manage subscriptions / accounts / projects** (administrators, Cloud
module) lists every scope known for the organisation: the ones in the connector configuration plus any that only
exist in data (for example left by a failed first scan), with status (Scanned / Not scanned and whether the last
scan failed), resource count and last scan.

**Remove** asks the user to type the first 8 characters of the id, then (`DELETE
/api/organization/connectors/{provider}/scopes/{id}?confirm=...`):

* removes the id from the connector configuration (Azure `subscription_ids`, AWS `role_arns` of that account,
  GCP `project_ids`), so it is no longer scanned;
* deletes the scope's assets and everything that references them, permanently (findings, relationships,
  vulnerabilities, packages, alerts, runtime events; external hosts and network devices are only unlinked);
* writes a `cloud_scope_removed` audit entry with the provider, id and the counts deleted.

The cloud itself is never touched: the read-only role stays until the customer removes it. A scope configured in
the server environment (`AZURE_SUBSCRIPTION_IDS` ...) or found through a Google Cloud organisation cannot be
removed here (it would be scanned again): remove it at its source first. Removal is refused while a scan of that
provider is running. Each organisation can only see and remove its own scopes.
