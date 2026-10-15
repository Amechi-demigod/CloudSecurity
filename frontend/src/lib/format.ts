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

export const TYPE_LABEL: Record<string, string> = {
  vm: "Virtual machine",
  storage_account: "Storage account",
  aks_cluster: "AKS cluster",
  pod: "Pod",
  sql_server: "SQL server",
  sql_database: "SQL database",
  nsg: "Network security group",
  identity: "Identity",
  key_vault: "Key Vault",
  function_app: "Function app",
  subscription: "Subscription",
  internet: "Internet",
};
