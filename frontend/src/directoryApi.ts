// Typed client for /api/directory (directory discovery: on-prem Active Directory read by a collector agent,
// Microsoft Entra ID + Intune and Google Workspace read by the server).
import { BASE, qs, request, requestFile, type InstallerPlatform } from "./api";

export type DirectoryType = "ad" | "entra" | "google";
export type DirectoryScope = "computers" | "users";
/** sealed: LDAP 389 with Kerberos signing & sealing (dedicated Windows collectors; no DC certificate needed). */
export type DirectorySecurity = "ldaps" | "starttls" | "sealed";
export type DirectoryAuth = "computer_account" | "service_account";
export type EntraScope = "users" | "devices" | "intune" | "roles";

export const DIRECTORY_NAME: Record<DirectoryType, string> = {
  ad: "Active Directory",
  entra: "Microsoft Entra ID",
  google: "Google Workspace",
};

/** Short source badge text: the directory a device / user record comes from. */
export const RECORD_LABEL: Record<string, string> = {
  ad: "AD",
  entra: "Entra ID",
  intune: "Intune",
  endpoint: "Google endpoint",
  chromeos: "ChromeOS",
  mobile: "Google mobile",
  google: "Google",
  user: "",
};

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

export interface EntraConfig {
  connector_id: "org" | "env";
  /** Set by the server from the chosen Azure connector. */
  tenant_id: string;
  client_id: string;
  scopes: EntraScope[];
  stale_days: number;
  interval_hours: number;
}

export type GoogleScope = "users" | "roles" | "chromeos" | "mobile" | "endpoints";

export interface GoogleConfig {
  /** Workspace admin the service account impersonates (domain-wide delegation). */
  admin_email: string;
  customer_id: string;
  scopes: GoogleScope[];
  stale_days: number;
  interval_hours: number;
  /** Set by the server from the uploaded key (public facts only; the key is never returned). */
  service_account_email: string;
  client_id: string;
  key_id: string;
}

export interface GoogleScopeInfo {
  scope: string;
  part: GoogleScope | null;
  why: string;
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

/** A dedicated directory collector (separate program, not an endpoint device). */
export interface DedicatedCollector {
  id: string;
  name: string;
  status: "active" | "revoked";
  state: "online" | "offline" | "never" | "revoked";
  healthy: boolean;
  hostname: string;
  dns_hostname: string;
  domain: string;
  os_name: string;
  os_version: string;
  architecture: string;
  version: string;
  /** e.g. CORP\HOST$ (LocalSystem = computer account) or CORP\svc-collector$ (gMSA) */
  run_as: string;
  run_as_kind: "computer_account" | "gmsa" | "user" | "unknown";
  is_domain_controller: boolean;
  enrolled_at: string;
  last_seen_at: string | null;
  last_ip: string | null;
  revoked_at: string | null;
  update_status: string | null;
  update_status_detail: string | null;
  diagnostics: CollectorDiagnostics | Record<string, never>;
  sources: { id: string; name: string }[];
}

export interface DiagStep {
  id: string;
  label: string;
  status: "pass" | "warn" | "fail" | "skip";
  detail: string;
  duration_ms?: number | null;
}

export interface CollectorDiagnostics {
  command_id: string;
  at: string;
  status: "queued" | "succeeded" | "failed" | "rejected";
  output?: string;
  steps: DiagStep[];
  transport?: string;
  signed_sealed?: boolean;
  server?: string;
  identity?: string;
}

export interface CollectorInstallerInfo {
  service_display_name: string;
  server_url: string | null;
  arches: Record<"amd64" | "arm64", { available: boolean; version?: string; reason?: string; filename: string }>;
}

export type GmsaScripts = Record<"kds_root_key" | "create_gmsa" | "grant_read" | "install_gmsa" | "service_logon" | "precheck", string>;

export type RunStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled";

export type CheckStatus = "ok" | "missing" | "unlicensed" | "missing_permission" | "error";

export interface PermissionCheck {
  id: string;
  label: string;
  status: CheckStatus;
  detail: string;
  required: boolean;
}

/** Outcome of one part of a server-side sync (users, devices, intune, roles, sign_in...). */
export interface ScopeStatus {
  status: "ok" | "missing_permission" | "unlicensed" | "not_enabled" | "error" | "truncated";
  detail?: string;
  count?: number;
}

export interface SyncRun {
  id: string;
  source_id: string;
  trigger: "scheduled" | "manual" | "test";
  status: RunStatus;
  device_id: string | null;
  device_hostname: string | null;
  collector_id?: string | null;
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
  checks: PermissionCheck[];
  scope_status: Record<string, ScopeStatus>;
}

interface SourceBase {
  id: string;
  name: string;
  enabled: boolean;
  has_credential: boolean;
  credential_username_hint: string | null;
  collector_device_ids: string[];
  collectors: Collector[];
  /** dedicated collectors (new sources) */
  collector_ids?: string[];
  dedicated_collectors?: DedicatedCollector[];
  /** true: an older source whose collectors are endpoint agents */
  legacy_collectors?: boolean;
  last_sync_at: string | null;
  last_sync_status: RunStatus | null;
  last_sync_error: string | null;
  last_success_at: string | null;
  computers_count: number;
  users_count: number;
  /** agent: read by a collector agent; server: read by the platform over HTTPS. */
  collection: "agent" | "server";
  scope_status: Record<string, ScopeStatus>;
  next_sync_at: string | null;
  active_run: SyncRun | null;
  created_at: string;
  created_by: string | null;
  updated_at: string;
  updated_by: string | null;
}

export type DirectorySource = SourceBase &
  ({ type: "ad"; config: AdConfig } | { type: "entra"; config: EntraConfig } | { type: "google"; config: GoogleConfig });

export interface Credential {
  username: string;
  password: string;
}

export type SourceCreate =
  | { type: "ad"; name: string; enabled?: boolean; config: AdConfig; collector_ids: string[]; credential?: Credential | null }
  | { type: "entra"; name: string; enabled?: boolean; config: Partial<EntraConfig> & Pick<EntraConfig, "connector_id"> }
  | { type: "google"; name: string; enabled?: boolean; config: Partial<GoogleConfig> & Pick<GoogleConfig, "admin_email">; google_key?: string };

export interface SourceUpdate {
  name?: string;
  enabled?: boolean;
  config?: AdConfig | Partial<EntraConfig> | Partial<GoogleConfig>;
  collector_device_ids?: string[];
  /** dedicated collectors; on a legacy source this switches it (data and history are kept) */
  collector_ids?: string[];
  credential?: Credential | null;
  clear_credential?: boolean;
  /** Google Workspace: a new service-account JSON key (write-only). */
  google_key?: string;
}

export interface AzureConnector {
  id: "org" | "env";
  name: string;
  tenant_id: string;
  client_id: string;
  auth_mode: string;
  usable: boolean;
  /** Why it cannot be used (empty when usable). */
  reason: string;
  /** The Entra ID source already reading this tenant, if any. */
  source: { id: string; name: string } | null;
}

export interface GraphPermission {
  name: string;
  /** App role id of the permission on the Microsoft Graph service principal. */
  id: string;
  scope: EntraScope | null;
  why: string;
}

export interface AzureConnectorsInfo {
  connectors: AzureConnector[];
  graph_app_id: string;
  permissions: GraphPermission[];
  privileged_roles: string[];
}

export type IssueType =
  | "not_managed"
  | "stale_computer"
  | "disabled_but_active"
  | "unknown_to_directory"
  | "not_domain_joined"
  | "non_compliant"
  | "not_in_intune"
  | "disabled_user_signed_in"
  | "stale_user_signed_in"
  | "privileged_disabled"
  | "privileged_stale"
  | "privileged_no_agent";

export const ISSUE_TYPES: IssueType[] = [
  "not_managed",
  "stale_computer",
  "disabled_but_active",
  "unknown_to_directory",
  "not_domain_joined",
  "non_compliant",
  "not_in_intune",
  "disabled_user_signed_in",
  "stale_user_signed_in",
  "privileged_disabled",
  "privileged_stale",
  "privileged_no_agent",
];

export const ISSUE_LABEL: Record<IssueType, string> = {
  not_managed: "No agent",
  stale_computer: "Stale computer",
  disabled_but_active: "Disabled but active",
  unknown_to_directory: "Unknown to directory",
  not_domain_joined: "Not domain-joined",
  non_compliant: "Non-compliant",
  not_in_intune: "Not in Intune",
  disabled_user_signed_in: "Disabled user signed in",
  stale_user_signed_in: "Stale user signed in",
  privileged_disabled: "Disabled admin",
  privileged_stale: "Stale admin",
  privileged_no_agent: "Admin device without agent",
};

export const ISSUE_HINT: Record<IssueType, string> = {
  not_managed: "Enabled directory computers in recent use that have no agent (each physical machine once)",
  stale_computer: "Enabled directory computers with no activity within the stale window",
  disabled_but_active: "Disabled in the directory, but the agent still checks in",
  unknown_to_directory: "Agent devices joined to a synced domain or Entra tenant with no matching directory record",
  not_domain_joined: "Agent devices that report neither an Active Directory domain nor an Entra join",
  non_compliant: "Intune reports the device non-compliant with its compliance policies",
  not_in_intune: "Windows / macOS agent devices joined to an Entra tenant that uses Intune, unknown to Intune",
  disabled_user_signed_in: "A user disabled in the directory is signed in on an agent device",
  stale_user_signed_in: "A signed-in user has no recent sign-in in the directory",
  privileged_disabled: "A disabled account still holds a privileged admin role",
  privileged_stale: "A privileged admin has not signed in within the stale window",
  privileged_no_agent: "A privileged admin's primary device has no agent",
};

export const ISSUE_TONE: Record<IssueType, "critical" | "warn" | "accent" | "default"> = {
  not_managed: "warn",
  stale_computer: "default",
  disabled_but_active: "critical",
  unknown_to_directory: "accent",
  not_domain_joined: "default",
  non_compliant: "warn",
  not_in_intune: "accent",
  disabled_user_signed_in: "critical",
  stale_user_signed_in: "warn",
  privileged_disabled: "critical",
  privileged_stale: "warn",
  privileged_no_agent: "critical",
};

export const USER_ISSUES: IssueType[] = [
  "disabled_user_signed_in",
  "stale_user_signed_in",
  "privileged_disabled",
  "privileged_stale",
  "privileged_no_agent",
];

/** Issue types a directory type can produce (KPI tiles show those of the configured sources). */
export const ISSUES_BY_TYPE: Record<DirectoryType, IssueType[]> = {
  ad: ["not_managed", "stale_computer", "disabled_but_active", "unknown_to_directory", "not_domain_joined", "disabled_user_signed_in", "stale_user_signed_in"],
  entra: [
    "not_managed",
    "stale_computer",
    "disabled_but_active",
    "unknown_to_directory",
    "non_compliant",
    "not_in_intune",
    "disabled_user_signed_in",
    "stale_user_signed_in",
    "privileged_disabled",
    "privileged_stale",
    "privileged_no_agent",
  ],
  google: ["not_managed", "stale_computer", "disabled_but_active", "disabled_user_signed_in", "stale_user_signed_in", "privileged_disabled", "privileged_stale", "privileged_no_agent"],
};

export interface RecordRef {
  id: string;
  source_id: string;
  type: string;
  kind: string;
}

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
  sources: RecordRef[];
  privileged: boolean;
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
  device_kind: string;
  platform: string;
  compliance: string | null;
  encrypted: boolean | null;
  serial_number: string;
  primary_user: string;
  agent_expected: boolean;
  /** workstation / server / domain_controller from the directory attributes; null = unknown */
  device_class?: "workstation" | "server" | "domain_controller" | null;
  /** Every record of this physical machine. */
  sources: RecordRef[];
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
  source_type: string;
  privileged: boolean;
  privileged_roles: string[];
  sign_in_known: boolean;
}

export interface DirectorySummary {
  sources: number;
  enabled_sources: number;
  source_types: DirectoryType[];
  last_sync_at: string | null;
  counts: Record<IssueType, number>;
  coverage: {
    directory_computers: number;
    managed: number;
    pct: number | null;
    /** split by device class (workstation / server / domain_controller / unknown) */
    by_class?: Record<string, { directory_computers: number; managed: number; pct: number | null }>;
  };
  users: number;
}

export interface IssueFilters {
  type?: IssueType | "";
  kind?: "computer" | "user" | "device" | "machine" | "";
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
  device_class?: string;
  limit?: number;
  offset?: number;
}

export interface UserFilters {
  q?: string;
  source_id?: string;
  enabled?: boolean;
  privileged?: boolean;
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
  azureConnectors: () => request<AzureConnectorsInfo>("/api/directory/azure-connectors"),
  googleScopes: () => request<{ scopes: GoogleScopeInfo[]; privileged_roles: string[] }>("/api/directory/google-scopes"),
  summary: () => request<DirectorySummary>("/api/directory/summary"),
  issues: (f: IssueFilters = {}) => request<IssuePage>(`/api/directory/issues${qs({ ...f })}`),
  issuesExportUrl: (f: IssueFilters = {}) =>
    `${BASE}/api/directory/issues/export.csv${qs({ type: f.type, kind: f.kind, source_id: f.source_id, q: f.q, domain: f.domain })}`,
  computers: (f: ComputerFilters = {}) => request<{ items: DirComputer[]; total: number }>(`/api/directory/computers${qs({ ...f })}`),
  users: (f: UserFilters = {}) => request<{ items: DirUser[]; total: number }>(`/api/directory/users${qs({ ...f })}`),
  addToAssets: (computer_ids: string[]) =>
    request<{ created: number; skipped: number; asset_ids: string[] }>("/api/directory/computers/add-to-assets", J({ computer_ids })),
  deployPlan: (sel: DeploySelection) => request<DeployPlan>("/api/directory/deployments/plan", J(sel)),
  createDeployment: (body: DeploymentCreate) => request<Deployment & { token?: string }>("/api/directory/deployments", J(body)),
  deployments: () => request<Deployment[]>("/api/directory/deployments"),
  deployment: (id: string) => request<Deployment>(`/api/directory/deployments/${id}`),
  revokeDeployment: (id: string) => request<Deployment>(`/api/directory/deployments/${id}/revoke`, { method: "POST" }),
  deploymentInstaller: (id: string, platform: InstallerPlatform) => requestFile(`/api/directory/deployments/${id}/installer`, { platform }),
};

// --- Deploy agent (docs/DIRECTORY_DISCOVERY.md#deploying-the-agent) ---
export type DeployRoute = "gpo" | "intune" | "rmm" | "manual";
export type ExcludedReason = "has_agent" | "mobile" | "no_agent_expected" | "disabled" | "linux" | "unknown_os" | "gone";

/** Explicit computers, or every computer issue matching a Discovery filter (use_filter). */
export interface DeploySelection {
  computer_ids?: string[];
  use_filter?: boolean;
  issue_type?: string | null;
  source_id?: string | null;
  q?: string | null;
  domain?: string | null;
}

export interface DeployMachine {
  computer_id: string;
  name: string;
  os: string;
  platform: string;
  domain: string;
  ou: string;
  kinds: string[];
  source_ids: string[];
  route: DeployRoute | null;
  allowed_routes: DeployRoute[];
  reason: ExcludedReason | "";
}

export interface RouteFacts {
  route: DeployRoute;
  label: string;
  count: number;
  platforms: Record<string, number>;
  ous?: { domain: string; ou: string; count: number }[];
}

type InstallerAvailability = Record<InstallerPlatform, { available: boolean; label: string; filename: string; version?: string; reason?: string }>;

export interface DeployPlan {
  routes: (RouteFacts & { items: DeployMachine[] })[];
  excluded: { reason: ExcludedReason; label: string; count: number; items: DeployMachine[] }[];
  total: number;
  deployable: number;
  server_url: string | null;
  agent_download_url: string | null;
  installers: InstallerAvailability;
}

export interface DeploymentCreate extends DeploySelection {
  name: string;
  routes?: Record<string, DeployRoute>;
  expires_in_days: number;
  device_group?: string | null;
  command_line_token: boolean;
}

export interface DeploymentItem {
  computer_id: string;
  name: string;
  os: string;
  platform: string;
  route: DeployRoute;
  domain: string;
  ou: string;
  kinds: string[];
  status: "enrolled" | "pending" | "gone";
  device_id: string | null;
  device_hostname: string | null;
  enrolled_at: string | null;
  via_deployment: boolean;
}

export interface Deployment {
  id: string;
  name: string;
  state: "active" | "expired" | "revoked";
  route_counts: Partial<Record<DeployRoute, number>>;
  excluded_counts: Partial<Record<ExcludedReason, number>>;
  selection_filter: Record<string, string> | null;
  device_group: string | null;
  expires_at: string;
  created_by: string | null;
  created_at: string;
  revoked_at: string | null;
  revoked_by: string | null;
  progress: { total: number; enrolled: number; pending: number; gone: number; pct: number | null; enrolled_with_tokens: number; age_days: number };
  // Detail only:
  items?: DeploymentItem[];
  routes?: RouteFacts[];
  tokens?: { id: string; name: string; token_prefix: string; package_platform: InstallerPlatform | null; max_uses: number | null; use_count: number; expires_at: string; state: string }[];
  server_url?: string | null;
  agent_download_url?: string | null;
  installers?: InstallerAvailability;
}

export const ROUTE_LABEL: Record<DeployRoute, string> = {
  gpo: "Group Policy",
  intune: "Microsoft Intune",
  rmm: "ConfigMgr / Jamf / RMM",
  manual: "Download / manual",
};

export const collectorApi = {
  list: () => request<DedicatedCollector[]>("/api/collectors"),
  get: (id: string) => request<DedicatedCollector>(`/api/collectors/${id}`),
  rename: (id: string, name: string) =>
    request<DedicatedCollector>(`/api/collectors/${id}`, { method: "PATCH", body: JSON.stringify({ name }) }),
  revoke: (id: string) => request<DedicatedCollector>(`/api/collectors/${id}/revoke`, { method: "POST" }),
  remove: (id: string) => request<void>(`/api/collectors/${id}`, { method: "DELETE" }),
  test: (id: string, source_id?: string | null) =>
    request<{ command_id: string; status: string }>(`/api/collectors/${id}/test`, J({ source_id: source_id ?? null })),
  createToken: (name: string, max_uses = 1) =>
    request<{ id: string; token: string; expires_at: string; server_url: string | null }>("/api/collectors/enrollment-tokens", J({ name, max_uses })),
  installerInfo: () => request<CollectorInstallerInfo>("/api/collectors/installer/info"),
  downloadInstaller: (body: { name: string; arch: "amd64" | "arm64"; gmsa: string }) => requestFile("/api/collectors/installer", body),
  setupScripts: (o: { domain: string; gmsa: string; hosts: string }) => request<GmsaScripts>(`/api/collectors/setup/scripts${qs(o)}`),
};

/** Shown on DC collectors and when one is picked for a source. */
export const DC_WARNING =
  "Domain controllers are your most sensitive servers; we recommend a member server. This collector cannot run commands, " +
  "scripts or remote sessions (it only reads the directory), so it is allowed here.";
