"""Guidance for the Google Cloud posture rules (GCP-*)."""
from __future__ import annotations

from typing import Any

from .common import g

GUIDANCE: dict[str, dict[str, Any]] = {}

# ----------------------------------------------------------------------------- IAM
GUIDANCE["GCP-IAM-001"] = g(
    8.4, 272, ["T1078.004", "T1548"],
    [("Service account can change anything", "Owner, Editor or an *Admin role lets the account modify or delete most resources in the project."),
     ("Key or token theft is project takeover", "Any workload or person that can use this account inherits those rights."),
     ("Rarely required", "Workloads usually need a handful of specific permissions.")],
    ["Open IAM & Admin > IAM and filter by the service account.", "Note roles such as Owner, Editor or roles/*.admin.", "List what the workload really calls."],
    "gcloud projects get-iam-policy <project> --flatten=\"bindings[].members\" --filter=\"bindings.members:<name>\" --format=\"table(bindings.role)\"",
    ["Open IAM & Admin > IAM and find the service account.", "Remove the broad role.", "Grant predefined or custom roles scoped to the specific services it uses (use the IAM recommender to see unused permissions)."],
    "gcloud projects remove-iam-policy-binding <project> --member=\"serviceAccount:<name>\" --role=\"roles/editor\"\n"
    "gcloud projects add-iam-policy-binding <project> --member=\"serviceAccount:<name>\" --role=\"<specific-role>\"",
    'resource "google_project_iam_member" "scoped" {\n  project = "<project>"\n  role    = "<specific-role>" # not roles/owner, roles/editor or *Admin\n  member  = "serviceAccount:<name>"\n}',
    "Grant least-privilege roles and review the IAM recommender suggestions; use organisation policy to restrict who may grant primitive roles.",
    ["gcp-sa-bp", "gcp-roles", "cis-gcp"])

GUIDANCE["GCP-IAM-002"] = g(
    5.4, 324, ["T1078.004", "T1098.001"],
    [("Old long-lived key", "A user-managed key older than 90 days has had a long time to leak."),
     ("Works from anywhere", "A service account key can be used outside Google Cloud with no further checks."),
     ("Keys are avoidable", "Workload identity and attached service accounts need no downloadable keys.")],
    ["Open IAM & Admin > Service Accounts > the account > Keys.", "Read the key creation dates."],
    "gcloud iam service-accounts keys list --iam-account=<name> --managed-by=user",
    ["Open IAM & Admin > Service Accounts > the account > Keys.", "Create a new key only if keys are unavoidable and update the application.", "Delete the old key. Prefer removing keys entirely in favour of workload identity or attached service accounts."],
    "gcloud iam service-accounts keys delete <key-id> --iam-account=<name>",
    '# Prefer no keys. Block key creation with an organisation policy:\nresource "google_org_policy_policy" "no_sa_keys" {\n  name   = "organizations/<org-id>/policies/iam.disableServiceAccountKeyCreation"\n  parent = "organizations/<org-id>"\n  spec {\n    rules {\n      enforce = "TRUE"\n    }\n  }\n}',
    "Enforce the iam.disableServiceAccountKeyCreation constraint and use workload identity federation for off-Google workloads.",
    ["gcp-sa-keys", "cis-gcp"])

GUIDANCE["GCP-IAM-003"] = g(
    9.4, 284, ["T1530", "T1190"],
    [("The public holds a role on the project", "allUsers or allAuthenticatedUsers (any Google account) is granted access to project resources."),
     ("Data and control exposure", "Depending on the role, anyone can read or change resources."),
     ("Usually a mistake", "Such bindings are normally created by accident or for a quick test.")],
    ["Open IAM & Admin > IAM.", "Search for principals allUsers and allAuthenticatedUsers.", "Note the roles they hold."],
    "gcloud projects get-iam-policy <project> --flatten=\"bindings[].members\" --filter=\"bindings.members:allUsers OR bindings.members:allAuthenticatedUsers\" --format=\"table(bindings.role,bindings.members)\"",
    ["Open IAM & Admin > IAM.", "Find allUsers / allAuthenticatedUsers and remove the binding (select the principal > Remove access).", "Grant the role to specific identities if access is really needed."],
    "gcloud projects remove-iam-policy-binding <project> --member=allUsers --role=<role>\ngcloud projects remove-iam-policy-binding <project> --member=allAuthenticatedUsers --role=<role>",
    '# remove the google_project_iam_member / binding that names allUsers or allAuthenticatedUsers.\n# Prevent recurrence with domain restricted sharing:\nresource "google_org_policy_policy" "domain_restricted" {\n  name   = "organizations/<org-id>/policies/iam.allowedPolicyMemberDomains"\n  parent = "organizations/<org-id>"\n  spec {\n    rules {\n      values {\n        allowed_values = ["<your-customer-id>"]\n      }\n    }\n  }\n}',
    "Enable domain restricted sharing (iam.allowedPolicyMemberDomains) so public principals cannot be granted roles.",
    ["gcp-roles", "cis-gcp", ("Restricting identities by domain", "https://cloud.google.com/resource-manager/docs/organization-policy/restricting-domains")])

GUIDANCE["GCP-IAM-004"] = g(
    6.6, 269, ["T1548", "T1078.004"],
    [("Impersonation of every service account", "Service Account User or Token Creator at project level lets the holder act as any service account in the project."),
     ("Privilege escalation path", "A low-privilege user can become the most privileged service account."),
     ("Should be scoped", "Grant these roles on individual service accounts instead.")],
    ["Open IAM & Admin > IAM.", "Find users or groups with Service Account User or Service Account Token Creator granted on the project."],
    "gcloud projects get-iam-policy <project> --flatten=\"bindings[].members\" --filter=\"bindings.role:(roles/iam.serviceAccountUser OR roles/iam.serviceAccountTokenCreator)\" --format=\"table(bindings.role,bindings.members)\"",
    ["Open IAM & Admin > IAM and remove the project-level binding.", "Open IAM & Admin > Service Accounts > the specific account > Permissions and grant the role only there, only to those who need it."],
    "gcloud projects remove-iam-policy-binding <project> --member=\"user:<user-email>\" --role=roles/iam.serviceAccountUser\n"
    "gcloud iam service-accounts add-iam-policy-binding <sa-email> --member=\"user:<user-email>\" --role=roles/iam.serviceAccountUser",
    'resource "google_service_account_iam_member" "scoped" {\n  service_account_id = "projects/<project>/serviceAccounts/<sa-email>"\n  role               = "roles/iam.serviceAccountUser"\n  member             = "user:<user-email>"\n}',
    "Grant impersonation roles at the service-account level only and review them regularly.",
    ["gcp-imp", "gcp-sa-bp", "cis-gcp"])

GUIDANCE["GCP-IAM-005"] = g(
    5.2, 269, ["T1078.004", "T1098"],
    [("Too many project owners", "More than three principals hold the primitive Owner role."),
     ("Larger takeover surface", "Each Owner account can change access and delete resources."),
     ("Weak accountability", "Broad ownership makes changes harder to attribute.")],
    ["Open IAM & Admin > IAM and filter by role Owner.", "Review each principal."],
    "gcloud projects get-iam-policy <project> --flatten=\"bindings[].members\" --filter=\"bindings.role:roles/owner\" --format=\"table(bindings.members)\"",
    ["Open IAM & Admin > IAM.", "Remove Owner from principals that do not need it and grant narrower predefined roles instead."],
    "gcloud projects remove-iam-policy-binding <project> --member=\"user:<user-email>\" --role=roles/owner",
    '# manage owners explicitly and keep the list short\nresource "google_project_iam_member" "owner" {\n  project = "<project>"\n  role    = "roles/owner"\n  member  = "group:<owners-group>"\n}',
    "Keep Owners to a small, reviewed group and prefer predefined roles.",
    ["gcp-roles", "cis-gcp"])

# ----------------------------------------------------------------------------- VPC firewall
_FW_TF = ('resource "google_compute_firewall" "admin" {\n  name          = "allow-%s-from-iap"\n  network       = "<network>"\n  direction     = "INGRESS"\n  source_ranges = ["35.235.240.0/20"] # Identity-Aware Proxy TCP forwarding range\n'
          '  allow {\n    protocol = "tcp"\n    ports    = ["%s"]\n  }\n}')
_FW_CLI = ("gcloud compute firewall-rules update <name> --source-ranges=35.235.240.0/20   # IAP range, instead of 0.0.0.0/0\n"
           "# or remove the rule:\ngcloud compute firewall-rules delete <name>")

GUIDANCE["GCP-FW-001"] = g(
    8.1, 284, ["T1133", "T1021.004", "T1110"],
    [("SSH reachable from anywhere", "An enabled ingress rule exposes TCP 22 to 0.0.0.0/0."),
     ("Constant brute force", "Open SSH is found and attacked within minutes."),
     ("Foothold in the project", "A compromised VM can use its service account and reach internal systems.")],
    ["Open VPC network > Firewall.", "Find the rule with source 0.0.0.0/0 and tcp:22 (or all).", "Check the target tags / service accounts it applies to."],
    "gcloud compute firewall-rules describe <name> --format=\"yaml(sourceRanges,allowed,targetTags,disabled)\"",
    ["Open VPC network > Firewall and edit the rule.", "Replace the source with your trusted ranges, or the IAP range 35.235.240.0/20 and use IAP TCP forwarding.", "Delete the rule if unneeded."],
    _FW_CLI,
    _FW_TF % ("ssh", "22"),
    "Use IAP TCP forwarding or OS Login for administration, and enforce with an organisation policy or firewall policy that denies 0.0.0.0/0 on admin ports.",
    ["gcp-fw", "gcp-iap", "cis-gcp"])

GUIDANCE["GCP-FW-002"] = g(
    8.1, 284, ["T1133", "T1021.001", "T1110"],
    [("RDP reachable from anywhere", "An enabled ingress rule exposes TCP 3389 to 0.0.0.0/0."),
     ("Ransomware entry point", "Exposed RDP is a common initial access route."),
     ("Credential stuffing", "Leaked passwords are replayed against open RDP endpoints.")],
    ["Open VPC network > Firewall.", "Find the rule with source 0.0.0.0/0 and tcp:3389 (or all)."],
    "gcloud compute firewall-rules describe <name> --format=\"yaml(sourceRanges,allowed,targetTags,disabled)\"",
    ["Open VPC network > Firewall and edit the rule.", "Replace the source with trusted ranges or IAP, or delete the rule."],
    _FW_CLI,
    _FW_TF % ("rdp", "3389"),
    "Use IAP TCP forwarding for RDP and deny 0.0.0.0/0 on admin ports with a firewall policy.",
    ["gcp-fw", "gcp-iap", "cis-gcp"])

GUIDANCE["GCP-FW-003"] = g(
    9.6, 284, ["T1133", "T1190"],
    [("Every port open", "An enabled ingress rule allows all protocols or every port from 0.0.0.0/0."),
     ("No network filtering", "All services on the targeted VMs are reachable from the internet."),
     ("Quick exploitation", "Databases and admin services on open hosts are targeted fast.")],
    ["Open VPC network > Firewall.", "Find an allow rule with 'all protocols' or ports 0-65535 from 0.0.0.0/0."],
    "gcloud compute firewall-rules describe <name> --format=\"yaml(sourceRanges,allowed,targetTags,disabled)\"",
    ["Open VPC network > Firewall and delete the allow-all rule.", "Add rules only for the ports each tier needs."],
    "gcloud compute firewall-rules delete <name>",
    '# remove the google_compute_firewall that allows all protocols from 0.0.0.0/0, then allow only what is needed:\nresource "google_compute_firewall" "https" {\n  name          = "allow-https"\n  network       = "<network>"\n  source_ranges = ["0.0.0.0/0"] # only for a public web tier\n  allow {\n    protocol = "tcp"\n    ports    = ["443"]\n  }\n}',
    "Reject allow-all rules in review and set an organisation-wide deny in hierarchical firewall policies.",
    ["gcp-fw", "cis-gcp"])

# ----------------------------------------------------------------------------- Compute
GUIDANCE["GCP-GCE-001"] = g(
    5.4, 668, ["T1133", "T1190"],
    [("VM directly reachable from the internet", "The instance has an external IP address."),
     ("Larger attack surface", "Every listening service and firewall mistake becomes internet-facing."),
     ("Bypasses central controls", "Traffic does not pass through a load balancer, WAF or Cloud NAT policy.")],
    ["Open Compute Engine > VM instances and check the External IP column.", "Open the VM > Network interfaces to see its access configs."],
    "gcloud compute instances describe <name> --zone <zone> --format=\"yaml(networkInterfaces[].accessConfigs)\"",
    ["Open Compute Engine > VM instances > the VM > Edit.", "Under Network interfaces set External IPv4 address to None.", "Use Cloud NAT for outbound access and IAP for administration."],
    "gcloud compute instances delete-access-config <name> --zone <zone> --access-config-name=\"external-nat\"",
    'resource "google_compute_instance" "this" {\n  name         = "<name>"\n  zone         = "<zone>"\n  machine_type = "e2-medium"\n  network_interface {\n    network = "<network>"\n    # no access_config block: no external IP\n  }\n  # boot_disk ...\n}',
    "Enable the organisation policy constraints/compute.vmExternalIpAccess to restrict external IPs.",
    [("Reserve a static external IP / external IPs on VMs", "https://cloud.google.com/compute/docs/ip-addresses"), "gcp-iap", "cis-gcp"])

GUIDANCE["GCP-GCE-002"] = g(
    7.5, 272, ["T1078.004", "T1552.005", "T1548"],
    [("Default account with broad rights", "The default Compute Engine service account is Editor by default and the full cloud-platform scope removes access-scope limits."),
     ("Code on the VM can reach the project", "Any compromise of the VM, or an SSRF in an app, can use those credentials."),
     ("Hard to see", "The default account is shared by many VMs.")],
    ["Open Compute Engine > the VM > API and identity management.", "Check the service account is the default one and the access scope is 'Allow full access to all Cloud APIs'."],
    "gcloud compute instances describe <name> --zone <zone> --format=\"yaml(serviceAccounts)\"",
    ["Create a dedicated service account with only the roles the workload needs.", "Stop the VM, then edit it: set the service account to the new one and the access scopes to only what is needed.", "Start the VM."],
    "gcloud compute instances stop <name> --zone <zone>\ngcloud compute instances set-service-account <name> --zone <zone> --service-account=<sa-email> --scopes=cloud-platform\ngcloud compute instances start <name> --zone <zone>",
    'resource "google_compute_instance" "this" {\n  name         = "<name>"\n  zone         = "<zone>"\n  machine_type = "e2-medium"\n  service_account {\n    email  = google_service_account.workload.email\n    scopes = ["cloud-platform"] # narrow IAM roles on the dedicated account control access\n  }\n  # boot_disk, network_interface ...\n}',
    "Always create VMs with a dedicated least-privilege service account and disable automatic Editor grants for the default account (iam.automaticIamGrantsForDefaultServiceAccounts).",
    ["gcp-gce-sa", "gcp-sa-bp", "cis-gcp"])

# ----------------------------------------------------------------------------- Storage
GUIDANCE["GCP-GCS-001"] = g(
    9.1, 284, ["T1530"],
    [("Bucket readable by anyone", "The bucket IAM policy grants a role to allUsers or allAuthenticatedUsers."),
     ("Data breach", "Public buckets are routinely discovered and downloaded by scanners."),
     ("Anyone with a Google account", "allAuthenticatedUsers is effectively the whole internet.")],
    ["Open Cloud Storage > the bucket > Permissions.", "Look for allUsers or allAuthenticatedUsers."],
    "gcloud storage buckets get-iam-policy gs://<name> --format=\"yaml(bindings)\"",
    ["Open Cloud Storage > the bucket > Permissions.", "Remove the allUsers / allAuthenticatedUsers principals.", "Turn on Public access prevention (Permissions > Public access > Prevent public access)."],
    "gcloud storage buckets remove-iam-policy-binding gs://<name> --member=allUsers --role=roles/storage.objectViewer\n"
    "gcloud storage buckets update gs://<name> --public-access-prevention",
    'resource "google_storage_bucket" "this" {\n  name                        = "<name>"\n  location                    = "<region>"\n  public_access_prevention    = "enforced"\n  uniform_bucket_level_access = true\n}',
    "Enforce the organisation policy constraints/storage.publicAccessPrevention and serve public content through Cloud CDN with a backend bucket.",
    ["gcp-gcs-pap", "cis-gcp"])

GUIDANCE["GCP-GCS-002"] = g(
    4.4, 732, ["T1530"],
    [("Object ACLs can bypass bucket IAM", "Without uniform bucket-level access, individual objects can be made public through ACLs."),
     ("Inconsistent permissions", "Access is defined in two systems, which is easy to get wrong."),
     ("One setting simplifies it", "Uniform access uses IAM only.")],
    ["Open Cloud Storage > the bucket > Configuration.", "Check Access control is Fine-grained."],
    "gcloud storage buckets describe gs://<name> --format=\"value(uniform_bucket_level_access)\"",
    ["Open Cloud Storage > the bucket > Permissions.", "Switch Access control to Uniform and save (review existing ACLs first)."],
    "gcloud storage buckets update gs://<name> --uniform-bucket-level-access",
    'resource "google_storage_bucket" "this" {\n  name                        = "<name>"\n  location                    = "<region>"\n  uniform_bucket_level_access = true\n}',
    "Enforce constraints/storage.uniformBucketLevelAccess by organisation policy.",
    ["gcp-gcs-ubla", "cis-gcp"])

# ----------------------------------------------------------------------------- GKE
GUIDANCE["GCP-GKE-001"] = g(
    7.5, 285, ["T1078.004", "T1068"],
    [("Static, broad permissions", "Legacy ABAC grants permissions outside Kubernetes RBAC and cannot be audited the same way."),
     ("Bypasses RBAC controls", "A user or service account can have more access than RBAC would allow."),
     ("Deprecated", "ABAC is legacy; RBAC is the supported model.")],
    ["Open Kubernetes Engine > Clusters > the cluster > Security.", "Check 'Legacy authorization' is Enabled."],
    "gcloud container clusters describe <name> --region <region> --format=\"value(legacyAbac.enabled)\"",
    ["Open Kubernetes Engine > Clusters > the cluster.", "In the Security section edit Legacy authorization and disable it.", "Check that required access is expressed in RBAC roles first."],
    "gcloud container clusters update <name> --region <region> --no-enable-legacy-authorization",
    'resource "google_container_cluster" "this" {\n  name     = "<name>"\n  location = "<region>"\n  enable_legacy_abac = false\n  # node_pool or initial_node_count ...\n}',
    "Create clusters with RBAC only (the default) and keep legacy ABAC off.",
    ["gcp-gke-hard", "cis-k8s"])

GUIDANCE["GCP-GKE-002"] = g(
    7.5, 668, ["T1190", "T1133"],
    [("Control plane reachable from anywhere", "The Kubernetes API endpoint is public with no authorized networks."),
     ("Admin interface exposed", "Any API flaw or leaked credential is remotely exploitable."),
     ("Easy to narrow", "Authorized networks or a private endpoint cut exposure.")],
    ["Open Kubernetes Engine > Clusters > the cluster > Networking.", "Check Control plane authorized networks is Disabled."],
    "gcloud container clusters describe <name> --region <region> --format=\"yaml(masterAuthorizedNetworksConfig,privateClusterConfig)\"",
    ["Open Kubernetes Engine > Clusters > the cluster > Networking.", "Enable control plane authorized networks and add your office / CI CIDRs."],
    "gcloud container clusters update <name> --region <region> --enable-master-authorized-networks --master-authorized-networks=203.0.113.0/24",
    'resource "google_container_cluster" "this" {\n  name     = "<name>"\n  location = "<region>"\n  master_authorized_networks_config {\n    cidr_blocks {\n      cidr_block   = "203.0.113.0/24"\n      display_name = "office"\n    }\n  }\n}',
    "Require authorized networks (or a private endpoint) in your GKE module.",
    ["gcp-gke-an", "gcp-gke-priv", "cis-k8s"])

GUIDANCE["GCP-GKE-003"] = g(
    5.4, 668, ["T1133", "T1190"],
    [("Nodes have external IPs", "Without private nodes, every node is addressable from the internet."),
     ("Wider attack surface", "Node-level services and firewall mistakes become exposed."),
     ("Private nodes use Cloud NAT", "Outbound access still works without inbound exposure.")],
    ["Open Kubernetes Engine > Clusters > the cluster > Networking.", "Check Private cluster / private nodes is disabled."],
    "gcloud container clusters describe <name> --region <region> --format=\"yaml(privateClusterConfig,networkConfig)\"",
    ["Create a new cluster (or node pool) with private nodes, or enable private nodes on supported cluster versions.", "Set up Cloud NAT for outbound traffic and migrate workloads."],
    "gcloud container clusters update <name> --region <region> --enable-private-nodes   # on supported versions; otherwise create a new cluster with --enable-private-nodes",
    'resource "google_container_cluster" "this" {\n  name     = "<name>"\n  location = "<region>"\n  private_cluster_config {\n    enable_private_nodes    = true\n    enable_private_endpoint = false\n    master_ipv4_cidr_block  = "172.16.0.0/28"\n  }\n  ip_allocation_policy {}\n}',
    "Create clusters as private clusters by default.",
    ["gcp-gke-priv", "cis-k8s"])

GUIDANCE["GCP-GKE-004"] = g(
    5.0, 272, ["T1552.005", "T1078.004"],
    [("Pods share the node's identity", "Without Workload Identity, pods can use the node service account via the metadata server."),
     ("Excess permissions", "Every pod on the node gets whatever the node account can do."),
     ("Per-workload identity is safer", "Workload Identity maps Kubernetes service accounts to scoped Google service accounts.")],
    ["Open Kubernetes Engine > Clusters > the cluster > Security.", "Check Workload Identity is Disabled."],
    "gcloud container clusters describe <name> --region <region> --format=\"value(workloadIdentityConfig.workloadPool)\"",
    ["Open Kubernetes Engine > Clusters > the cluster > Security.", "Enable Workload Identity (workload pool <project>.svc.id.goog).", "Enable the GKE metadata server on node pools and bind Kubernetes service accounts to Google service accounts."],
    "gcloud container clusters update <name> --region <region> --workload-pool=<project>.svc.id.goog",
    'resource "google_container_cluster" "this" {\n  name     = "<name>"\n  location = "<region>"\n  workload_identity_config {\n    workload_pool = "<project>.svc.id.goog"\n  }\n}',
    "Enable Workload Identity at cluster creation and give each workload its own service account.",
    ["gcp-gke-wi", "cis-k8s"])

# ----------------------------------------------------------------------------- Cloud SQL
GUIDANCE["GCP-SQL-001"] = g(
    9.1, 284, ["T1190", "T1110"],
    [("Database open to the whole internet", "An authorized network of 0.0.0.0/0 admits every IPv4 address to the public IP."),
     ("Credential attacks", "Public database endpoints get constant password-guessing traffic."),
     ("Customer data at risk", "Cloud SQL usually holds application and customer data.")],
    ["Open SQL > the instance > Connections > Networking.", "Find the authorized network 0.0.0.0/0."],
    "gcloud sql instances describe <name> --format=\"yaml(settings.ipConfiguration)\"",
    ["Open SQL > the instance > Connections > Networking.", "Delete the 0.0.0.0/0 authorized network.", "Use private IP, the Cloud SQL Auth Proxy or specific authorized addresses."],
    "gcloud sql instances patch <name> --clear-authorized-networks\n# or set specific ranges:\ngcloud sql instances patch <name> --authorized-networks=203.0.113.0/24",
    'resource "google_sql_database_instance" "this" {\n  name = "<name>"\n  settings {\n    tier = "db-custom-2-7680"\n    ip_configuration {\n      ipv4_enabled    = false\n      private_network = "projects/<project>/global/networks/<network>"\n    }\n  }\n}',
    "Use private IP and the Cloud SQL Auth Proxy; enforce with constraints/sql.restrictAuthorizedNetworks.",
    ["gcp-sql-ip", "cis-gcp"])

GUIDANCE["GCP-SQL-002"] = g(
    5.4, 668, ["T1190", "T1133"],
    [("Instance has a public IPv4 address", "The instance can be reached over the internet if an authorized network allows it."),
     ("Larger attack surface", "Credentials are the main barrier if the network list is wide."),
     ("Private IP is safer", "Private IP keeps traffic on your VPC.")],
    ["Open SQL > the instance > Connections.", "Check Public IP is enabled."],
    "gcloud sql instances describe <name> --format=\"value(settings.ipConfiguration.ipv4Enabled)\"",
    ["Open SQL > the instance > Connections.", "Enable Private IP (private services access) and migrate clients to it.", "Clear the Public IP option and save."],
    "gcloud sql instances patch <name> --network=<network> --no-assign-ip",
    'resource "google_sql_database_instance" "this" {\n  name = "<name>"\n  settings {\n    tier = "db-custom-2-7680"\n    ip_configuration {\n      ipv4_enabled    = false\n      private_network = "projects/<project>/global/networks/<network>"\n    }\n  }\n}',
    "Create instances with private IP only and restrict public IPs by organisation policy (constraints/sql.restrictPublicIp).",
    ["gcp-sql-ip", "cis-gcp"])

GUIDANCE["GCP-SQL-003"] = g(
    5.9, 319, ["T1557", "T1040"],
    [("Unencrypted connections accepted", "Clients can connect to the instance without SSL/TLS."),
     ("Interception", "Credentials and data can be read on the network."),
     ("Enforceable at the instance", "One setting rejects non-TLS connections.")],
    ["Open SQL > the instance > Connections > Security.", "Check 'Allow only SSL connections' / SSL mode."],
    "gcloud sql instances describe <name> --format=\"yaml(settings.ipConfiguration.sslMode,settings.ipConfiguration.requireSsl)\"",
    ["Open SQL > the instance > Connections > Security.", "Select 'Allow only SSL connections' (or SSL mode: encrypted only) and save.", "Update clients to use SSL."],
    "gcloud sql instances patch <name> --ssl-mode=ENCRYPTED_ONLY",
    'resource "google_sql_database_instance" "this" {\n  name = "<name>"\n  settings {\n    tier = "db-custom-2-7680"\n    ip_configuration {\n      ssl_mode = "ENCRYPTED_ONLY"\n    }\n  }\n}',
    "Set ssl_mode in your instance module; the Cloud SQL Auth Proxy always encrypts.",
    ["gcp-sql-ssl", "cis-gcp"])

GUIDANCE["GCP-SQL-004"] = g(
    4.4, 693, ["T1485", "T1490"],
    [("No automated backups", "A mistake, corruption or ransomware may leave nothing to restore from."),
     ("Longer recovery", "You would rely on manual exports."),
     ("Low cost", "Daily backups are inexpensive compared with data loss.")],
    ["Open SQL > the instance > Backups.", "Check automated backups are Disabled."],
    "gcloud sql instances describe <name> --format=\"yaml(settings.backupConfiguration)\"",
    ["Open SQL > the instance > Backups > Edit.", "Enable automated backups, pick a backup window, and enable point-in-time recovery."],
    "gcloud sql instances patch <name> --backup-start-time=03:00 --enable-point-in-time-recovery",
    'resource "google_sql_database_instance" "this" {\n  name = "<name>"\n  settings {\n    tier = "db-custom-2-7680"\n    backup_configuration {\n      enabled                        = true\n      start_time                     = "03:00"\n      point_in_time_recovery_enabled = true\n    }\n  }\n}',
    "Enable backups in your instance module.",
    ["gcp-sql-bkp", "cis-gcp"])

# ----------------------------------------------------------------------------- KMS / serverless
GUIDANCE["GCP-KMS-001"] = g(
    4.4, 324, ["T1552"],
    [("Key not rotated often enough", "The key has no rotation period or one longer than 90 days."),
     ("Bigger blast radius", "A compromised key version protects more data for longer."),
     ("Automatic rotation is simple", "New versions are created on schedule without downtime.")],
    ["Open Security > Key Management > the key ring > the key.", "Check Rotation period."],
    "gcloud kms keys describe <name> --keyring <key-ring> --location <region> --format=\"yaml(rotationPeriod,nextRotationTime)\"",
    ["Open Security > Key Management > the key.", "Edit rotation period and set it to 90 days or less."],
    "gcloud kms keys update <name> --keyring <key-ring> --location <region> --rotation-period=90d --next-rotation-time=<RFC3339-time>",
    'resource "google_kms_crypto_key" "this" {\n  name            = "<name>"\n  key_ring        = google_kms_key_ring.this.id\n  rotation_period = "7776000s" # 90 days\n}',
    "Set rotation_period in your key module.",
    ["gcp-kms-rot", "cis-gcp"])

GUIDANCE["GCP-RUN-001"] = g(
    7.5, 306, ["T1190"],
    [("Anyone can invoke the service", "allUsers or allAuthenticatedUsers hold the invoker role and ingress is open."),
     ("Cost and abuse", "Public invocation can be flooded or used to reach what the service account can reach."),
     ("Application-level auth only", "Any flaw in the app's own checks is exploitable.")],
    ["Open Cloud Run > the service > Security (and Networking).", "Check Authentication is 'Allow unauthenticated invocations' and ingress is All."],
    "gcloud run services get-iam-policy <name> --region <region>",
    ["Open Cloud Run > the service > Security.", "Choose 'Require authentication' (remove allUsers from roles/run.invoker).", "Optionally set Ingress to 'Internal' or 'Internal and Cloud Load Balancing'."],
    "gcloud run services remove-iam-policy-binding <name> --region <region> --member=allUsers --role=roles/run.invoker\ngcloud run services update <name> --region <region> --ingress=internal-and-cloud-load-balancing",
    'resource "google_cloud_run_v2_service" "this" {\n  name     = "<name>"\n  location = "<region>"\n  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"\n  # template { ... }\n}\n# and remove any google_cloud_run_v2_service_iam_member granting roles/run.invoker to allUsers',
    "Restrict public invocation with the organisation policy constraints/run.allowedIngress and domain restricted sharing.",
    ["gcp-run-auth", "cis-gcp"])

GUIDANCE["GCP-FN-001"] = g(
    7.5, 306, ["T1190"],
    [("Anyone can invoke the function", "allUsers or allAuthenticatedUsers can invoke the function and ingress allows all traffic."),
     ("Cost and abuse", "Public functions can be flooded or used to reach what their service account can reach."),
     ("Application-level auth only", "The handler's own checks are the only barrier.")],
    ["Open Cloud Functions (Cloud Run functions) > the function > Permissions.", "Look for allUsers / allAuthenticatedUsers with an invoker role.", "Check the ingress setting."],
    "gcloud functions get-iam-policy <name> --region <region>",
    ["Open the function > Permissions and remove the allUsers / allAuthenticatedUsers invoker principals.", "For 2nd gen functions, also remove them from the underlying Cloud Run service.", "Set Ingress to 'Allow internal traffic only' if it is only called internally."],
    "gcloud functions remove-iam-policy-binding <name> --region <region> --member=allUsers --role=roles/cloudfunctions.invoker\n"
    "gcloud run services remove-iam-policy-binding <name> --region <region> --member=allUsers --role=roles/run.invoker   # 2nd gen",
    'resource "google_cloudfunctions2_function" "this" {\n  name     = "<name>"\n  location = "<region>"\n  service_config {\n    ingress_settings = "ALLOW_INTERNAL_ONLY"\n  }\n  # build_config ...\n}\n# and remove any IAM member granting the invoker role to allUsers',
    "Require authentication on functions by default and restrict public IAM with domain restricted sharing.",
    ["gcp-fn-iam", "cis-gcp"])
