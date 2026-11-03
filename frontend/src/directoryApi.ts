// Typed client for /api/directory (directory discovery: on-prem Active Directory today).
import { BASE, qs, request } from "./api";

export type DirectoryScope = "computers" | "users";
export type DirectorySecurity = "ldaps" | "starttls";
export type DirectoryAuth = "computer_account" | "service_account";

export interface AdConfig {
  domain: string;
  servers: string[];
  port: number;
  security: DirectorySecurity;
  base_dns: string[];
  scopes: DirectoryScope[];
  stale_days: number;
  interval_hours: number;
  auth: DirectoryAuth;
  ca_pem: string;
}

export interface Collector {
  id: string;
  hostname: string;
  os_family: string;
  healthy: boolean;
  last_seen_at: string | null;
  ad_domain: string | null;
  agent_version: string;
}

export type RunStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled";

export interface SyncRun {
  id: string;
  source_id: string;
  trigger: "scheduled" | "manual" | "test";
  status: RunStatus;
  device_id: string | null;
  device_hostname: string | null;
  queued_at: string;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  computers_seen: number;
  users_seen: number;
  batches: number;
  truncated: boolean;
  error: string | null;
  attempt: number;
  server: string | null;
  sample: { kind: string; name: string }[];
}

export interface DirectorySource {
  id: string;
  type: "ad";
  name: string;
  enabled: boolean;
  config: AdConfig;
  has_credential: boolean;
  credential_username_hint: string | null;
  collector_device_ids: string[];
  collectors: Collector[];
  last_sync_at: string | null;
  last_sync_status: RunStatus | null;
  last_sync_error: string | null;
  last_success_at: string | null;
  computers_count: number;
  users_count: number;
  next_sync_at: string | null;
  active_run: SyncRun | null;
  created_at: string;
  created_by: string | null;
  updated_at: string;
  updated_by: string | null;
}

export interface Credential {
  username: string;
  password: string;
}

export interface SourceCreate {
  type: "ad";
  name: string;
  enabled?: boolean;
  config: AdConfig;
  collector_device_ids: string[];
  credential?: Credential | null;
}

export interface SourceUpdate {
  name?: string;
  enabled?: boolean;
  config?: AdConfig;
  collector_device_ids?: string[];
  credential?: Credential | null;
  clear_credential?: boolean;
}

export type IssueType =
  | "not_managed"
  | "stale_computer"
  | "disabled_but_active"
  | "unknown_to_directory"
  | "not_domain_joined"
  | "disabled_user_signed_in"
  | "stale_user_signed_in";

export const ISSUE_TYPES: IssueType[] = [
  "not_managed",
  "stale_computer",
  "disabled_but_active",
  "unknown_to_directory",
  "not_domain_joined",
  "disabled_user_signed_in",
  "stale_user_signed_in",
];

export const ISSUE_LABEL: Record<IssueType, string> = {
  not_managed: "No agent",
  stale_computer: "Stale computer",
  disabled_but_active: "Disabled but active",
  unknown_to_directory: "Unknown to directory",
  not_domain_joined: "Not domain-joined",
  disabled_user_signed_in: "Disabled user signed in",
  stale_user_signed_in: "Stale user signed in",
};

export const ISSUE_HINT: Record<IssueType, string> = {
  not_managed: "Enabled directory computers that signed in recently but have no agent",
  stale_computer: "Enabled directory computers with no domain logon within the stale window",
  disabled_but_active: "Disabled in the directory, but the agent still checks in",
  unknown_to_directory: "Agent devices joined to a synced domain with no matching directory computer",
  not_domain_joined: "Agent devices that report no Active Directory domain",
  disabled_user_signed_in: "A user disabled in the directory is signed in on an agent device",
  stale_user_signed_in: "A signed-in user has no recent domain logon",
};

export const ISSUE_TONE: Record<IssueType, "critical" | "warn" | "accent" | "default"> = {
  not_managed: "warn",
  stale_computer: "default",
  disabled_but_active: "critical",
  unknown_to_directory: "accent",
  not_domain_joined: "default",
  disabled_user_signed_in: "critical",
  stale_user_signed_in: "warn",
};

export const USER_ISSUES: IssueType[] = ["disabled_user_signed_in", "stale_user_signed_in"];

export interface Issue {
  id: string;
  type: IssueType;
  kind: "computer" | "user" | "device";
  source_id: string | null;
  name: string;
  domain: string;
  ou: string;
  os: string;
  last_logon_at: string | null;
  enabled: boolean | null;
  detail: string;
  device_id: string | null;
  device_hostname: string | null;
  computer_id: string | null;
  user_id: string | null;
  it_asset_id: string | null;
  first_seen_at: string;
}

export interface IssuePage {
  items: Issue[];
  total: number;
  counts: Record<IssueType, number>;
}

export interface DirComputer {
  id: string;
  source_id: string;
  name: string;
  dns_hostname: string;
  domain: string;
  ou: string;
  os: string;
  os_version: string;
  enabled: boolean;
  last_logon_at: string | null;
  when_created: string | null;
  missing_since: string | null;
  match_status: "matched" | "ambiguous" | "unmatched";
  match_method: string | null;
  match_confidence: number | null;
  device_id: string | null;
  device_hostname: string | null;
  it_asset_id: string | null;
  in_it_assets: boolean;
}

export interface DirUser {
  id: string;
  source_id: string;
  sam_account_name: string;
  user_principal_name: string;
  mail: string;
  display_name: string;
  department: string;
  title: string;
  enabled: boolean;
  last_logon_at: string | null;
  domain: string;
  ou: string;
  missing_since: string | null;
}

export interface DirectorySummary {
  sources: number;
  enabled_sources: number;
  last_sync_at: string | null;
  counts: Record<IssueType, number>;
  coverage: { directory_computers: number; managed: number; pct: number | null };
  users: number;
}

export interface IssueFilters {
  type?: IssueType | "";
  kind?: "computer" | "user" | "device" | "";
  source_id?: string;
  q?: string;
  domain?: string;
  limit?: number;
  offset?: number;
}

export type ComputerStatus = "all" | "not_in_assets" | "matched" | "unmatched" | "ambiguous" | "missing";

export interface ComputerFilters {
  q?: string;
  source_id?: string;
  domain?: string;
  status?: ComputerStatus;
  limit?: number;
  offset?: number;
}

const J = (body: unknown): RequestInit => ({ method: "POST", body: JSON.stringify(body) });

export const directoryApi = {
  sources: () => request<DirectorySource[]>("/api/directory/sources"),
  source: (id: string) => request<DirectorySource>(`/api/directory/sources/${id}`),
  createSource: (body: SourceCreate) => request<DirectorySource>("/api/directory/sources", J(body)),
  updateSource: (id: string, body: SourceUpdate) =>
    request<DirectorySource>(`/api/directory/sources/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteSource: (id: string) => request<void>(`/api/directory/sources/${id}`, { method: "DELETE" }),
  syncNow: (id: string) => request<SyncRun>(`/api/directory/sources/${id}/sync`, { method: "POST" }),
  test: (id: string) => request<SyncRun>(`/api/directory/sources/${id}/test`, { method: "POST" }),
  runs: (id: string, limit = 10) => request<SyncRun[]>(`/api/directory/sources/${id}/runs${qs({ limit })}`),
  run: (runId: string) => request<SyncRun>(`/api/directory/runs/${runId}`),
  collectors: () => request<Collector[]>("/api/directory/collectors"),
  summary: () => request<DirectorySummary>("/api/directory/summary"),
  issues: (f: IssueFilters = {}) => request<IssuePage>(`/api/directory/issues${qs({ ...f })}`),
  issuesExportUrl: (f: IssueFilters = {}) =>
    `${BASE}/api/directory/issues/export.csv${qs({ type: f.type, kind: f.kind, source_id: f.source_id, q: f.q, domain: f.domain })}`,
  computers: (f: ComputerFilters = {}) => request<{ items: DirComputer[]; total: number }>(`/api/directory/computers${qs({ ...f })}`),
  users: (f: { q?: string; source_id?: string; enabled?: boolean; limit?: number; offset?: number } = {}) =>
    request<{ items: DirUser[]; total: number }>(`/api/directory/users${qs({ ...f })}`),
  addToAssets: (computer_ids: string[]) =>
    request<{ created: number; skipped: number; asset_ids: string[] }>("/api/directory/computers/add-to-assets", J({ computer_ids })),
};
