import type { Severity } from "../api";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export const SEV_COLOR: Record<string, string> = {
  critical: "var(--color-sev-critical)",
  high: "var(--color-sev-high)",
  medium: "var(--color-sev-medium)",
  low: "var(--color-sev-low)",
  info: "var(--color-ink-3)",
};

export const fmtTime = (iso: string) => new Date(iso).toLocaleString();
export const fmtAgo = (iso: string) => {
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.max(s, 0)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
};

/** "in 4h", "in 25m"; "now" for times in the past. */
export const fmtUntil = (iso: string) => {
  const s = Math.round((new Date(iso).getTime() - Date.now()) / 1000);
  if (s <= 0) return "now";
  if (s < 3600) return `in ${Math.max(Math.round(s / 60), 1)}m`;
  if (s < 86400) return `in ${Math.round((s / 3600) * 10) / 10}h`;
  return `in ${Math.round((s / 86400) * 10) / 10}d`;
};

/** 6 -> "6 h", 0.5 -> "30 min", 1.5 -> "1.5 h". */
export const fmtHours = (h: number) => (h < 1 ? `${Math.round(h * 60)} min` : `${Math.round(h * 100) / 100} h`);

export const TYPE_LABEL: Record<string, string> = {
  vm: "Virtual machine",
  vmss: "VM scale set",
  storage_account: "Storage account",
  aks_cluster: "AKS cluster",
  pod: "Pod",
  sql_server: "SQL server",
  sql_database: "SQL database",
  nsg: "Network security group",
  identity: "Identity",
  key_vault: "Key Vault",
  function_app: "Function app",
  web_app: "Web app",
  app_service_plan: "App Service plan",
  vnet: "Virtual network",
  private_endpoint: "Private endpoint",
  azure_firewall: "Azure Firewall",
  firewall_policy: "Firewall policy",
  postgresql_server: "PostgreSQL server",
  mysql_server: "MySQL server",
  cosmos_account: "Cosmos DB account",
  redis_cache: "Azure Cache for Redis",
  sql_managed_instance: "SQL Managed Instance",
  subscription: "Subscription",
  internet: "Internet",
  // AWS
  aws_account: "AWS account",
  ec2_instance: "EC2 instance",
  security_group: "Security group",
  s3_bucket: "S3 bucket",
  eks_cluster: "EKS cluster",
  rds_instance: "RDS instance",
  iam_user: "IAM user",
  iam_role: "IAM role",
  kms_key: "KMS key",
  lambda_function: "Lambda function",
  cloudtrail_trail: "CloudTrail trail",
  // GCP
  gcp_project: "GCP project",
  gce_instance: "Compute instance",
  gcp_firewall_rule: "VPC firewall rule",
  gcs_bucket: "Cloud Storage bucket",
  gke_cluster: "GKE cluster",
  cloud_sql_instance: "Cloud SQL instance",
  gcp_service_account: "Service account",
  gcp_kms_key: "Cloud KMS key",
  cloud_function: "Cloud Function",
  cloud_run_service: "Cloud Run service",
};

/** Cloud provider display names (Asset.provider / connector names). */
export const PROVIDER_LABEL: Record<string, string> = { azure: "Azure", aws: "AWS", gcp: "GCP" };

/** What a provider calls its top-level scope (Asset.subscription_id). */
export const SCOPE_LABEL: Record<string, string> = { azure: "Subscription", aws: "Account", gcp: "Project" };
