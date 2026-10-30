// Connect-a-cloud setup on Connectors & scans: the read-only setup script per provider and the
// credential fields of PUT /api/organization/connectors/{provider} (backend/app/connectors/org_config.py).
import type { Provider } from "../orgApi";

export const CLOUD_PROVIDERS: Provider[] = ["azure", "aws", "gcp"];

export const CLOUD_NAME: Record<Provider, string> = { azure: "Azure", aws: "AWS", gcp: "Google Cloud" };

/** Brand-ish marker colour of each provider tile (decorative, identical in both themes). */
export const CLOUD_COLOR: Record<Provider, string> = { azure: "#0078d4", aws: "#ff9900", gcp: "#34a853" };

/** What the read-only identity holds, shown as "read-only (…)". */
export const CLOUD_ROLE: Record<Provider, string> = {
  azure: "Reader",
  aws: "SecurityAudit + ViewOnlyAccess",
  gcp: "Viewer + Security Reviewer",
};

export const CLOUD_SCOPE: Record<Provider, [string, string]> = {
  azure: ["subscription", "subscriptions"],
  aws: ["account", "accounts"],
  gcp: ["project", "projects"],
};

export const CLOUD_SHELL: Record<Provider, { name: string; short: string; url: string }> = {
  azure: { name: "Azure Cloud Shell (Bash)", short: "Azure Cloud Shell", url: "https://shell.azure.com" },
  aws: { name: "AWS CloudShell", short: "AWS CloudShell", url: "https://console.aws.amazon.com/cloudshell/home" },
  gcp: { name: "Google Cloud Shell", short: "Google Cloud Shell", url: "https://shell.cloud.google.com" },
};

// Same identity name and permissions as docs/CONNECT_AWS.md, docs/CONNECT_GCP.md and the README's Azure section.
export const SETUP_SCRIPT: Record<Provider, string> = {
  azure: `# Creates a read-only service principal (built-in Reader role) on the current subscription
SUB=$(az account show --query id -o tsv)
az ad sp create-for-rbac --name cnapp-scanner --role Reader \\
  --scopes "/subscriptions/$SUB" \\
  --query "{tenant_id:tenant, client_id:appId, client_secret:password}" -o json
echo "subscription_ids: $SUB"`,
  aws: `# Creates a read-only IAM user (SecurityAudit + ViewOnlyAccess) and an access key
aws iam create-user --user-name cnapp-scanner
aws iam attach-user-policy --user-name cnapp-scanner \\
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam attach-user-policy --user-name cnapp-scanner \\
  --policy-arn arn:aws:iam::aws:policy/job-function/ViewOnlyAccess
aws iam create-access-key --user-name cnapp-scanner \\
  --query "{access_key_id:AccessKey.AccessKeyId, secret_access_key:AccessKey.SecretAccessKey}"`,
  gcp: `# Creates a read-only service account (Viewer + Security Reviewer) and a key
P=$(gcloud config get-value project)
gcloud services enable cloudresourcemanager.googleapis.com iam.googleapis.com --project "$P"
gcloud iam service-accounts create cnapp-scanner --project "$P"
SA="cnapp-scanner@$P.iam.gserviceaccount.com"
for R in roles/viewer roles/iam.securityReviewer; do
  gcloud projects add-iam-policy-binding "$P" --member "serviceAccount:$SA" --role "$R" --condition None
done
gcloud iam service-accounts keys create key.json --iam-account "$SA" && cat key.json && rm key.json
echo "project_ids: $P"`,
};

/** Provider-specific note under the script. */
export const SETUP_NOTE: Record<Provider, string> = {
  azure: "To scan more subscriptions, assign the service principal Reader on each one and add their IDs.",
  aws: "Several accounts: assume a read-only role in each one (Advanced, see docs/CONNECT_AWS.md).",
  gcp: "If key creation is blocked by the iam.disableServiceAccountKeyCreation organisation policy, ask your Google Cloud admin for an exception on this project.",
};

export interface CredentialField {
  name: string;
  label: string;
  hint?: string;
  /** Stored encrypted; never shown again. */
  secret?: boolean;
  /** Comma-separated list. */
  list?: boolean;
  multiline?: boolean;
  /** Behind the "Advanced" disclosure. */
  advanced?: boolean;
}

export const CREDENTIAL_FIELDS: Record<Provider, CredentialField[]> = {
  azure: [
    { name: "tenant_id", label: "Tenant ID", hint: "tenant_id from the output" },
    { name: "client_id", label: "Client ID", hint: "client_id" },
    { name: "client_secret", label: "Client secret", hint: "client_secret · stored encrypted", secret: true },
    { name: "subscription_ids", label: "Subscription IDs", hint: "subscription_ids · comma-separated", list: true },
  ],
  aws: [
    { name: "access_key_id", label: "Access key ID", hint: "access_key_id" },
    { name: "secret_access_key", label: "Secret access key", hint: "secret_access_key · stored encrypted", secret: true },
    { name: "regions", label: "Regions", hint: "optional · empty = every enabled region", list: true },
    { name: "role_arns", label: "Role ARNs (cross-account)", hint: "comma-separated · empty = the key's own account", list: true, advanced: true },
    { name: "external_id", label: "External ID", hint: "required by the roles' trust policy, if any", advanced: true },
    { name: "home_region", label: "Home region", hint: "default us-east-1", advanced: true },
  ],
  gcp: [
    { name: "credentials_json", label: "Service-account key (JSON)", hint: "paste the whole key.json · stored encrypted", secret: true, multiline: true },
    { name: "project_ids", label: "Project IDs", hint: "project_ids · comma-separated", list: true },
    { name: "organization_id", label: "Organization ID (numeric)", hint: "scan every project under it", advanced: true },
  ],
};
