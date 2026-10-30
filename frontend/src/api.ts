// Typed API client for the FastAPI backend.
import type { PendingUpdate } from "./updatesApi";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Asset {
  id: string;
  name: string;
  type: string;
  provider: string;
  subscription_id: string | null;
  subscription_name: string | null;
  resource_group: string | null;
  region: string | null;
  tags: Record<string, string>;
  internet_exposed: boolean;
  sensitive_data: boolean;
  properties: Record<string, unknown>;
  source: string;
  first_seen: string;
  last_seen: string;
}

export interface AssetSummary extends Asset {
  open_findings: number;
  vulnerabilities: number;
  max_risk: number;
  open_alerts: number;
}

export interface Finding {
  id: string;
  rule_id: string;
  asset_id: string;
  title: string;
  description: string;
  severity: Severity;
  status: "open" | "resolved" | "suppressed";
  remediation: string;
  compliance: string[];
  evidence: Record<string, unknown>;
  source: string;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  asset_name: string | null;
  asset_type: string | null;
}

export interface Vulnerability {
  id: string;
  /** Cloud workload / sensor host. Null for endpoint-device vulnerabilities. */
  asset_id: string | null;
  /** Laptop (endpoint agent). Null for asset vulnerabilities. */
  device_id?: string | null;
  device_name?: string | null;
  cve_id: string;
  package: string;
  version: string;
  fixed_version: string | null;
  title: string;
  cvss: number;
  severity: Severity;
  exploit_available: boolean;
  in_use: boolean;
  in_use_source?: string | null;
  in_use_last_seen?: string | null;
  internet_exposed: boolean;
  sensitive_data_access: boolean;
  risk_score: number;
  priority: Severity;
  status: string;
  asset_name: string | null;
  asset_type: string | null;
  /** simulated | nvd (endpoint software by CPE) | osv (Linux packages) */
  source?: string;
  first_seen?: string | null;
  kev?: boolean | null;
  epss?: number | null;
  last_seen?: string | null;
  resolved_at?: string | null;
  evidence?: Record<string, unknown> | null;
}

export interface VulnByCve {
  cve_id: string;
  title: string;
  cvss: number;
  severity: Severity;
  kev: boolean;
  epss: number | null;
  max_risk: number;
  packages: string[];
  fixed_versions: string[];
  devices: string[];
  assets: string[];
  device_count: number;
  asset_count: number;
  sources: string[];
}

export interface VulnBySoftware {
  package: string;
  cve_count: number;
  kev_count: number;
  severity: Severity;
  by_severity: Record<string, number>;
  versions: string[];
  fixed_versions: string[];
  device_count: number;
  asset_count: number;
  max_risk: number;
}

export interface VulnFeed {
  feed: string;
  label: string;
  host: string;
  last_success_at: string | null;
  last_attempt_at: string | null;
  last_error: string | null;
  items: number | null;
}

export interface VulnTargetCounts {
  total: number;
  matched: number;
  pending: number;
  errors: number;
  last_matched_at: string | null;
}

export interface VulnStatus {
  enabled: boolean;
  worker_running: boolean;
  nvd_api_key_configured: boolean;
  rematch_interval_hours: number;
  feeds: VulnFeed[];
  devices: VulnTargetCounts;
  assets: VulnTargetCounts;
  software_checked: number;
  software_not_checked: number;
  not_checked_top: { name: string; devices: number; reason: string }[];
  mapping_rules: number;
}

export interface CheckedSoftware {
  name: string;
  version: string;
  product?: string;
  cpe?: string;
  rule?: string;
  publisher?: string;
  reason?: string;
}

export interface DeviceVulnerabilities {
  vulnerabilities: Vulnerability[];
  matched_at: string | null;
  pending: boolean;
  error: string | null;
  os: { cpe?: string; version?: string; label?: string };
  checked: CheckedSoftware[];
  not_checked: CheckedSoftware[];
}

export interface Alert {
  id: string;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  asset_id: string | null;
  mitre_tactic: string;
  mitre_technique_id: string;
  mitre_technique_name: string;
  status: "open" | "acknowledged" | "resolved";
  event_count: number;
  first_seen: string;
  last_seen: string;
  asset_name: string | null;
  asset_type: string | null;
}

export interface RuntimeEvent {
  id: string;
  timestamp: string;
  asset_id: string | null;
  event_type: string;
  summary: string;
  data: Record<string, unknown>;
  sensor_id: string | null;
  source: string;
  triggered?: boolean;
}

export interface AlertDetail extends Alert {
  asset: Asset | null;
  timeline: RuntimeEvent[];
}

export interface PathStep {
  asset_id: string;
  name: string;
  type: string;
  reasons: string[];
  /** This hop carries a confirmed exploitable weakness. */
  weak: boolean;
}

export interface AttackPath {
  id: string;
  title: string;
  score: number;
  severity: Severity;
  entry_id: string;
  target_id: string;
  steps: PathStep[];
  edges: { source: string; target: string; type: string }[];
  /** True if some hop carries an exploitable weakness; false for an exposure path. */
  confirmed: boolean;
  weaknesses: string[];
  /** Why an exposure path is not confirmed (null for confirmed paths). */
  note: string | null;
}

export interface ComplianceFramework {
  framework: string;
  controls: number;
  passing: number;
  score: number;
  failing_controls: string[];
}

export interface NoiseReduction {
  total: number;
  in_use: number;
  dormant: number;
  percent: number;
}

export interface Dashboard {
  risk_score: number;
  assets: { total: number; internet_exposed: number; by_type: Record<string, number> };
  findings_by_severity: Record<string, number>;
  open_findings: number;
  vulnerabilities: {
    total: number;
    prioritized: number;
    by_priority: Record<string, number>;
    noise_reduction: NoiseReduction;
  };
  alerts: { open: number; by_severity: Record<string, number>; events_24h: number };
  alerts_over_time: { hour: string; critical: number; high: number; medium: number; low: number }[];
  attack_paths: { total: number; critical: number; exposure?: number };
  top_risks: {
    kind: "attack_path" | "vulnerability" | "finding";
    id: string;
    title: string;
    severity: Severity;
    score: number | null;
    asset_id: string;
  }[];
  compliance: ComplianceFramework[];
}

export interface Connector {
  name: string;
  provider: string;
  description: string;
  configured: boolean;
  /** Configured scan targets: subscriptions, account IDs (role ARNs), projects / organization. */
  scope: string[];
  /** What to set when not configured. */
  setup_hint: string;
  auth_mode?: string | null;
  /** AWS: regions scanned. */
  regions?: string[];
  /** GCP: credentials file problem (missing / unreadable). */
  problem?: string | null;
  last_scan: ScanRun | null;
  /** Subscriptions / accounts / projects found by previous scans of this connector. */
  discovered_scopes: { id: string; name: string }[];
}

export interface ScanRun {
  id: string;
  connector: string;
  status: "running" | "succeeded" | "failed" | "skipped";
  started_at: string;
  finished_at: string | null;
  assets_found: number;
  findings_open: number;
  errors: string[];
  message: string;
  /** manual | scheduled (null: recorded before scheduled scans existed) */
  trigger: "manual" | "scheduled" | null;
}

export interface ConnectorSchedule {
  name: string;
  provider: string;
  configured: boolean;
  scheduled: boolean;
  not_scheduled_reason: string | null;
  last_run: ScanRun | null;
  last_scheduled_run: ScanRun | null;
  /** null while scheduled: due now (overdue, or never scanned on schedule) */
  next_run_at: string | null;
  running: boolean;
}

export interface ScanSchedule {
  enabled: boolean;
  interval_hours: number;
  enabled_overridden: boolean;
  interval_overridden: boolean;
  default_enabled: boolean;
  default_interval_hours: number;
  min_interval_hours: number;
  max_interval_hours: number;
  updated_at: string | null;
  updated_by: string | null;
  connectors: ConnectorSchedule[];
}

export interface Health {
  status: string;
  /** Product branding (BRAND_NAME / BRAND_TAGLINE); absent on servers older than this console. */
  brand?: { name: string; tagline: string };
  simulation_mode: boolean;
  simulator_running: boolean;
  azure_configured: boolean;
  aws_configured: boolean;
  gcp_configured: boolean;
}

export type Role = "admin" | "analyst" | "viewer";

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
  locked_until: string | null;
  failed_login_count: number;
  mfa_enabled: boolean;
  /** "password" and/or linked identity providers, e.g. "entra" */
  auth_sources: string[];
}

export interface OrganizationBrief {
  id: string;
  name: string;
  slug: string;
  status: "active" | "suspended";
  is_default: boolean;
  logo_url: string | null;
}

export interface SessionInfo {
  user: User;
  csrf_token: string;
  expires_at: string;
  idle_timeout_minutes: number;
  /** The organisation this session acts in. */
  organization: OrganizationBrief | null;
  /** May open the platform console (manage organisations). */
  platform_admin: boolean;
}

/** Returned by login instead of a session when a second step is needed. */
export interface MfaChallenge {
  mfa_required: true;
  purpose: "verify" | "enroll";
  mfa_token: string;
  expires_in: number;
}

export type LoginResult = SessionInfo | MfaChallenge;

export function isMfaChallenge(r: LoginResult): r is MfaChallenge {
  return "mfa_token" in r;
}

export interface LoginComplete extends SessionInfo {
  /** only after a forced enrolment: shown once */
  recovery_codes?: string[] | null;
}

export interface MfaSetup {
  secret: string;
  otpauth_uri: string;
  /** data:image/svg+xml URI rendered by the backend */
  qr_svg: string;
  digits: number;
  period: number;
}

export interface MfaStatus {
  enabled: boolean;
  enabled_at: string | null;
  required: boolean;
  recovery_codes_remaining: number;
  has_password: boolean;
  sso_user: boolean;
}

export interface AuthProviders {
  password: boolean;
  entra: boolean;
  entra_label: string;
}

export interface AuditEntry {
  id: number;
  timestamp: string;
  action: string;
  actor_id: string | null;
  actor_email: string | null;
  target: string | null;
  ip: string | null;
  detail: Record<string, unknown>;
}

// --- device management -------------------------------------------------------

export type DeviceHealth = "healthy" | "warning" | "critical" | "unknown";
export type Connectivity = "active" | "stale" | "inactive" | "never";
export type CheckStatus = "pass" | "fail" | "unknown" | "info";

export interface DeviceIssue {
  code: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  detail: string;
}

export type DeviceState = "active" | "lost" | "wipe_pending" | "isolated" | "revoked";

export interface DeviceSummary {
  id: string;
  hostname: string;
  os_family: "windows" | "macos" | "linux";
  os_name: string;
  os_version: string;
  architecture: string;
  serial_number: string;
  manufacturer: string;
  model: string;
  agent_version: string;
  status: "active" | "revoked";
  /** lifecycle state including lost mode / pending wipe */
  device_state: DeviceState;
  enrolled_at: string;
  last_seen_at: string | null;
  last_checkin_at: string | null;
  logged_in_users: string[];
  device_group: string | null;
  health: DeviceHealth;
  connectivity: Connectivity;
  issues: DeviceIssue[];
}

export interface PostureCheck {
  status: CheckStatus;
  detail: string;
  error?: string | null;
  data: Record<string, unknown>;
}

export interface DeviceInventory {
  hostname?: string;
  cpu?: string;
  cpu_cores?: number | null;
  memory_bytes?: number | null;
  disks?: { mount: string; filesystem: string; size_bytes: number | null; free_bytes: number | null }[];
  uptime_seconds?: number | null;
  last_boot?: string | null;
  logged_in_users?: string[];
  network?: { name: string; mac: string; ips: string[] }[];
  timezone?: string;
}

export interface LostModeState {
  status: null | "enabling" | "active" | "disabling";
  message: string | null;
  phone: string | null;
  since: string | null;
  requested_by: string | null;
  /** what the agent last reported (null = no report yet) */
  reported_active: boolean | null;
}

export type WipeStatus = "queued" | "acknowledged" | "started" | "failed" | "expired";

export interface WipeState {
  supported: boolean;
  unsupported_reason: string | null;
  /** chosen at install time (MSI property CNAPP_ALLOW_WIPE=1) */
  opted_in: boolean;
  ready: boolean;
  /** raw readiness keys reported by the agent (opt_in, winre_enabled, mdm_bridge, methods, ...) */
  readiness: Record<string, unknown>;
  readiness_detail: string;
  status: WipeStatus | null;
  status_at: string | null;
  command_id: string | null;
}

/** Suspend sign-in state (internal name: host isolation - see endpoint-agent/internal/signin). */
export interface IsolationState {
  supported: boolean;
  status: null | "isolating" | "isolated" | "restoring";
  since: string | null;
  requested_by: string | null;
  /** what the agent last reported at check-in (null = no report yet) */
  reported_isolated: boolean | null;
  /** pre-flight findings (local admins, LAPS) from the latest isolate_host command's result_data */
  readiness: Record<string, unknown>;
  recovered_at_boot: boolean | null;
  recovery_outcome: null | "rolled_back" | "completed";
}

export interface DeviceDetail extends DeviceSummary {
  os_build: string;
  last_ip: string | null;
  check_in_interval_seconds: number;
  software_count: number;
  updates_pending_since: string | null;
  revoked_at: string | null;
  inventory: DeviceInventory;
  posture: Record<string, PostureCheck>;
  collection_errors: Record<string, string>;
  lost_mode: LostModeState;
  wipe: WipeState;
  isolation: IsolationState;
}

export interface DeviceSoftware {
  name: string;
  version: string;
  publisher: string;
  identifier: string;
  install_date: string;
  source: string;
}

export interface PostureSnapshot {
  id: number;
  received_at: string;
  collected_at: string | null;
  agent_version: string;
  os_version: string;
  posture: Record<string, PostureCheck>;
  issues: string[];
  software_count: number | null;
}

export type CommandType =
  | "recheck_posture"
  | "collect_logs"
  | "lock_device"
  | "restart_agent"
  | "update_check_in_interval"
  | "check_for_update"
  | "enable_lost_mode"
  | "disable_lost_mode"
  | "wipe_device"
  | "run_script"
  | "isolate_host"
  | "restore_host";

export interface DeviceCommand {
  id: string;
  device_id: string;
  type: CommandType;
  params: Record<string, unknown>;
  status: "pending" | "delivered" | "succeeded" | "failed" | "rejected" | "expired" | "cancelled";
  reason: string;
  requested_by_email: string | null;
  created_at: string;
  expires_at: string;
  delivered_at: string | null;
  completed_at: string | null;
  output: string;
  log_bundle_id: string | null;
  exit_code: number | null;
  result_data: Record<string, unknown> | null;
  approval_id: string | null;
  approved_by_email: string | null;
  acknowledged_at: string | null;
}

export interface DeviceFleetSummary {
  total: number;
  revoked: number;
  by_os: Record<string, number>;
  by_health: Record<DeviceHealth, number>;
  connectivity: Record<Connectivity, number>;
  issues: Record<string, number>;
  encrypted_percent: number | null;
  firewall_percent: number | null;
  encryption_known: number;
  firewall_known: number;
}

export interface EnrollmentToken {
  id: string;
  name: string;
  token_prefix: string;
  package_platform: InstallerPlatform | null;
  device_group: string | null;
  max_uses: number | null;
  use_count: number;
  created_by: string | null;
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  state: "active" | "expired" | "exhausted" | "revoked";
}

export type InstallerPlatform = "windows-msi" | "macos-pkg";

export interface InstallerInfo {
  server_url: string | null;
  server_error: string | null;
  ca_configured: boolean;
  ca_error: string | null;
  include_ca_default: boolean;
  platforms: Record<InstallerPlatform, { available: boolean; label: string; filename: string; version?: string; size_bytes?: number; reason?: string }>;
  defaults: { expires_in_days: number; max_devices: number };
}

export interface InstallerRequest {
  platform: InstallerPlatform;
  name?: string | null;
  expires_in_days: number;
  max_devices: number;
  device_group?: string | null;
  include_ca: boolean;
  /** windows-msi only: let admins remote-wipe devices installed with this package */
  allow_wipe?: boolean;
}

// --- two-person approvals ---
export type ApprovalStatus = "pending" | "approved" | "executed" | "rejected" | "cancelled" | "expired" | "failed";
export type RiskLevel = "low" | "medium" | "high";

export interface Approval {
  id: string;
  device_id: string;
  hostname: string;
  os_family: string;
  action: "wipe_device" | "run_script";
  params: Record<string, unknown>;
  summary: string;
  risk: RiskLevel;
  reason: string;
  status: ApprovalStatus;
  requested_by_email: string | null;
  requested_at: string;
  expires_at: string;
  decided_by_email: string | null;
  decided_at: string | null;
  decision_reason: string | null;
  self_approved: boolean;
  /** self-approved requests run only after this time (cooling-off) */
  execute_after: string | null;
  executed_at: string | null;
  command_id: string | null;
  is_own_request: boolean;
  can_decide: boolean;
}

export interface ApprovalSettings {
  ttl_hours: number;
  allow_self_approval: boolean;
  self_approval_cooldown_minutes: number;
  wipe_command_ttl_minutes: number;
}

export interface ApprovalSummary {
  pending: number;
  actionable: number;
  cooling_off: number;
  settings: ApprovalSettings;
}

export type WipeMode = "protected" | "standard";

// --- signed script library ---
export interface ScriptParam {
  name: string;
  type: "string" | "enum" | "int" | "bool";
  description?: string;
  required?: boolean;
  default?: string | number | boolean | null;
  pattern?: string;
  max_length?: number;
  values?: string[];
  min?: number;
  max?: number;
}

export interface LibraryScript {
  name: string;
  description: string;
  platform: "windows" | "macos";
  interpreter: string;
  risk: RiskLevel;
  timeout_seconds: number;
  parameters: ScriptParam[];
  sha256: string;
  size_bytes: number;
  requires_approval: boolean;
}

export interface ScriptBundle {
  id: string;
  version: string;
  key_id: string;
  released_at: string;
  expires_at: string;
  notes: string;
  bundle_sha256: string;
  imported_by: string;
  imported_at: string;
  expired: boolean;
  scripts: string[];
}

export interface ScriptLibrary {
  bundle: ScriptBundle | null;
  scripts: LibraryScript[];
  trusted_keys: string[];
}

export type ScriptParamValue = string | number | boolean;

export interface ScriptRun {
  id: string;
  device_id: string;
  hostname: string;
  script: string;
  bundle_version: string;
  parameters: Record<string, unknown>;
  status: DeviceCommand["status"];
  exit_code: number | null;
  output: string;
  reason: string;
  requested_by_email: string | null;
  approved_by_email: string | null;
  approval_id: string | null;
  created_at: string;
  completed_at: string | null;
  expires_at: string;
}

export interface ScriptRunResult {
  mode: "command" | "approval";
  command_id: string | null;
  approval: Approval | null;
}

// --- agent auto-update ---
export interface AgentReleaseArtifact {
  os: string;
  arch: string;
  name: string;
  sha256: string;
  size_bytes: number;
}

export interface AgentRelease {
  id: string;
  version: string;
  key_id: string;
  released_at: string;
  expires_at: string;
  min_supported_version: string;
  notes: string;
  rollback_allowed_from: string[];
  bundle_sha256: string;
  imported_by: string;
  imported_at: string;
  withdrawn_at: string | null;
  withdrawn_reason: string | null;
  expired: boolean;
  artifacts: AgentReleaseArtifact[];
  devices_running: number;
}

export interface UpdateRing {
  id: string;
  name: string;
  description: string;
  position: number;
  device_groups: string[];
  is_default: boolean;
  target_release_id: string | null;
  target_version: string | null;
  rollout_percent: number;
  paused: boolean;
  updated_at: string;
  updated_by: string;
  explicit_devices: number;
}

export interface UpdateRingPatch {
  name?: string;
  description?: string;
  position?: number;
  device_groups?: string[];
  target_release_id?: string;
  clear_target?: boolean;
  rollout_percent?: number;
  paused?: boolean;
  reason: string;
}

export interface UpdateSummary {
  devices: number;
  versions: { version: string; devices: number }[];
  statuses: Record<string, number>;
  rings: { ring_id: string; name: string; devices: number; on_target: number; updating: number; failed: number; target_version: string | null }[];
}

export interface DeviceUpdateState {
  device_id: string;
  agent_version: string;
  ring: { id: string; name: string } | null;
  ring_assignment: "explicit" | "group" | "default";
  pinned_release: { id: string; version: string } | null;
  target_version: string | null;
  target_reason: string;
  status: string | null;
  status_version: string | null;
  status_detail: string | null;
  status_at: string | null;
  /** What happens next (offered / waiting for check-in / blocked ...). */
  pending?: PendingUpdate;
  history: { id: number; release_id: string | null; from_version: string; to_version: string; status: string; detail: string; created_at: string }[];
}

const BASE = import.meta.env.VITE_API_BASE ?? "";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** Error carrying the HTTP status, so callers can tell 401/403 from other failures. */
export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// Session-wide state set by the auth provider. The CSRF token is kept in memory
// only (never in localStorage) and sent on every state-changing request.
let csrfToken: string | null = null;
let onUnauthorized: (() => void) | null = null;
let onForbidden: ((message: string) => void) | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

export function setAuthHandlers(h: { unauthorized: () => void; forbidden: (message: string) => void }) {
  onUnauthorized = h.unauthorized;
  onForbidden = h.forbidden;
}

export async function request<T>(path: string, init?: RequestInit & { skipAuthHandling?: boolean }): Promise<T> {
  const method = (init?.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (!SAFE_METHODS.has(method) && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    credentials: "same-origin",
    headers: { ...headers, ...((init?.headers as Record<string, string>) ?? {}) },
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* ignore */
    }
    if (!init?.skipAuthHandling) {
      if (res.status === 401) onUnauthorized?.();
      if (res.status === 403) {
        const msg = `Not permitted: ${detail}`;
        onForbidden?.(msg);
        throw new ApiError(403, msg);
      }
    }
    throw new ApiError(res.status, detail || `HTTP ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

/** POST that returns a file (e.g. a generated installer): the bytes plus the suggested filename. */
export async function requestFile(path: string, body: unknown): Promise<{ blob: Blob; filename: string; sha256: string | null }> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const res = await fetch(`${BASE}${path}`, { method: "POST", credentials: "same-origin", headers, body: JSON.stringify(body) });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const b = await res.json();
      detail = typeof b.detail === "string" ? b.detail : JSON.stringify(b.detail);
    } catch {
      /* ignore */
    }
    if (res.status === 401) onUnauthorized?.();
    throw new ApiError(res.status, detail || `HTTP ${res.status}`);
  }
  const cd = res.headers.get("Content-Disposition") ?? "";
  const m = /filename="([^"]+)"/.exec(cd);
  return { blob: await res.blob(), filename: m ? m[1] : "installer", sha256: res.headers.get("X-Content-SHA256") };
}

/** Upload a signed agent release bundle (raw .tar.gz body). */
export async function uploadAgentRelease(file: File): Promise<AgentRelease> {
  return uploadGzip<AgentRelease>("/api/updates/releases", file);
}

/** Upload a signed script-library bundle (raw .tar.gz body). */
export async function uploadScriptBundle(file: File): Promise<ScriptBundle> {
  return uploadGzip<ScriptBundle>("/api/scripts/bundles", file);
}

async function uploadGzip<T>(path: string, file: File): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/gzip" };
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const res = await fetch(`${BASE}${path}`, { method: "POST", credentials: "same-origin", headers, body: file });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const b = await res.json();
      detail = typeof b.detail === "string" ? b.detail : JSON.stringify(b.detail);
    } catch {
      /* ignore */
    }
    if (res.status === 401) onUnauthorized?.();
    throw new ApiError(res.status, detail || `HTTP ${res.status}`);
  }
  return res.json();
}

export function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

export interface ExposureMethod {
  kind: string;
  label: string;
  detail: string;
  ports: string[];
  level: "open" | "restricted" | "blocked";
  partial?: { source: string; rule?: string; ports?: string[] | number[] }[];
  via?: string;
  note?: string;
}

export interface ExposureItem {
  id: string;
  name: string;
  type: string;
  provider: string;
  subscription_id: string | null;
  subscription_name: string | null;
  resource_group: string | null;
  region: string | null;
  level: "open" | "restricted";
  attack_path_entry: boolean;
  exposure: string | null;
  exposed_only_via: string[];
  methods: ExposureMethod[];
  effective_ports: string[];
  partial_exposure: { source: string; rule?: string; ports?: (string | number)[]; via?: string }[];
  network_controls: string[];
  private_endpoints: string[];
  public_endpoint: string | null;
  public_network_access: string | boolean | null;
  sensitive_data: boolean;
  data_classification: string | null;
  egress: string | null;
  findings: { count: number; by_severity: Record<string, number>; top: { id: string; rule_id: string; title: string; severity: Severity }[] };
  vulnerabilities: { count: number; prioritized: number; top: { id: string; cve_id: string; package: string; severity: string }[] };
  attack_paths: { id: string; title: string; severity: Severity; confirmed: boolean; score: number; role: string }[];
}

export interface ExposureSummary {
  total: number;
  open: number;
  restricted: number;
  attack_path_entries: number;
  risky_ports_open: number;
  with_private_endpoint: number;
  sensitive: number;
  by_provider: Record<string, number>;
  by_method: Record<string, number>;
}


// --- Dashboards (/api/dashboards/*; backend/app/services/dashboards.py) ---
export type DashRange = "7d" | "30d" | "90d";
export type DashTab = "overview" | "vulnerabilities" | "exposure" | "identities" | "endpoints";
export type SevCounts = { critical: number; high: number; medium: number; low: number };
/** A composition part: an asset group, type or port (fixed order from the backend). */
export interface DashPart {
  key: string;
  label: string;
  count: number;
  types?: string[];
  port?: number;
}
/** `delta` is today minus the value one period ago; null when there is no history to compare with. */
export interface DashKpi<P = SevCounts> {
  value: number | null;
  delta: number | null;
  parts?: P;
}
export interface DashFrame {
  range: DashRange;
  days: number;
  account: string | null;
  generated_at: string;
  bucket: "day" | "week";
  compare_day: string;
  history_since: string | null;
}
export interface DashMeta extends DashFrame {
  tabs: { vulnerabilities: number; exposure: number; identities: number; endpoints: number };
  accounts: { id: string; name: string; provider: string }[];
  ranges: DashRange[];
  sla_days: { critical: number; high: number };
}
export interface DashBucket {
  start: string;
  end: string;
}
export interface EndpointStats {
  managed: number;
  healthy: number;
  failing: number;
  suspended: number;
  outdated: number;
  latest_agent_version: string | null;
  by_os: Record<string, number>;
  by_health: { healthy: number; warning: number; critical: number; unknown: number };
  connectivity: { active: number; stale: number; inactive: number; never: number };
  issues: { code: string; title: string; severity: Severity; devices: number }[];
  agent_versions: { version: string; devices: number }[];
}
export interface DashOverview extends DashFrame {
  risk_score: { value: number; delta: number | null; severity: Severity; critical_findings: number; critical_paths: number };
  kpis: {
    open_issues: DashKpi;
    critical_high: DashKpi<{ critical: number; high: number }>;
    mttr: {
      value: number | null;
      delta: number | null;
      resolved: number;
      critical: number | null;
      high: number | null;
      sla_met_pct: number | null;
      sla_days: { critical: number; high: number };
    };
    exposed_assets: DashKpi<DashPart[]>;
    runtime_threats: DashKpi;
    attack_paths: DashKpi;
  };
  issue_trend: { bucket: "day" | "week"; points: (DashBucket & { new: number; resolved: number })[] };
  compliance: { framework: string; controls: number; passing: number; score: number; delta: number | null; failing_controls: string[] }[];
  age: ({ bucket: string; label: string } & SevCounts)[];
  categories: ({ category: string; total: number } & SevCounts)[];
  top_assets: {
    id: string;
    name: string;
    type: string;
    type_label: string;
    risk: number;
    critical: number;
    high: number;
    findings: number;
    vulnerabilities: number;
    internet_exposed: boolean;
    sensitive_data: boolean;
  }[];
  endpoints: EndpointStats;
}
export interface DashCve {
  cve_id: string;
  package: string;
  version: string;
  severity: Severity;
  epss: number | null;
  kev: boolean;
  runtime: boolean;
  internet: boolean;
  endpoint: boolean;
  assets: number;
  risk: number | null;
  cvss: number | null;
  fix_available: boolean;
}
export interface DashVulns extends DashFrame {
  kpis: {
    critical: DashKpi<never> & { fix_available: number; no_fix: number };
    kev: DashKpi;
    in_use: DashKpi;
    fix_available: DashKpi<never> & { fixable: number; no_fix: number };
  };
  total: number;
  over_time: { bucket: "day" | "week"; points: (DashBucket & { critical: number; high: number; prioritized: number | null })[] };
  by_severity: { severity: Severity; vulns: number; cves: number; assets: number }[];
  noise_reduction: { total: number; in_use: number; dormant: number; percent: number };
  workloads: ({ key: string; label: string; types: string[]; total: number } & SevCounts)[];
  top_cves: DashCve[];
}
export interface DashPath {
  id: string;
  title: string;
  severity: Severity;
  score: number;
  confirmed: boolean;
  entry: { id: string; name: string; detail: string | null };
  target: { id: string; name: string };
  steps: { id: string; name: string; type: string }[];
  weaknesses: string[];
}
export interface DashExposure extends DashFrame {
  kpis: {
    exposed_assets: DashKpi<DashPart[]>;
    mgmt_ports: DashKpi<DashPart[]>;
    data_stores: DashKpi<DashPart[]>;
    crown_jewels: DashKpi;
  };
  by_type: { type: string; label: string; group: string; count: number }[];
  levels: { open: number; restricted: number };
  trend: { bucket: "day" | "week"; points: (DashBucket & { exposed_assets: number | null; crown_jewel_paths: number | null })[] };
  paths: DashPath[];
  paths_total: number;
}
export interface DashIdentities extends DashFrame {
  kpis: {
    identities: DashKpi<DashPart[]>;
    privileged: DashKpi<DashPart[]>;
    findings: DashKpi;
    on_paths: { value: number; parts: SevCounts };
  };
  findings_by_severity: SevCounts;
  rules: { rule_id: string; title: string; severity: Severity; findings: number; identities: number }[];
  identities: {
    id: string;
    name: string;
    type: string;
    type_label: string;
    provider: string;
    principal_type: string | null;
    privileged: boolean;
    roles: string[];
    scope: string | null;
    findings: number;
    attack_path: Severity | null;
  }[];
  total: number;
}
export interface DashEndpoints extends DashFrame, EndpointStats {
  kpis: {
    managed: DashKpi<Record<string, number>>;
    failing: DashKpi<never>;
    suspended: DashKpi<never>;
    outdated: DashKpi<never>;
  };
  vulnerabilities: { total: number; kev: number; by_severity: SevCounts };
}
export type DashParams = { range: DashRange; account?: string };

export const api = {
  // --- auth ---
  me: () => request<SessionInfo>("/api/auth/me", { skipAuthHandling: true }),
  login: (email: string, password: string) =>
    request<LoginResult>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
      skipAuthHandling: true,
    }),
  logout: () => request<void>("/api/auth/logout", { method: "POST", skipAuthHandling: true }),
  changePassword: (current_password: string, new_password: string) =>
    request<void>("/api/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ current_password, new_password }),
    }),
  // --- MFA / SSO ---
  providers: () => request<AuthProviders>("/api/auth/providers", { skipAuthHandling: true }),
  loginMfa: (mfa_token: string, code: string) =>
    request<LoginComplete>("/api/auth/login/mfa", {
      method: "POST",
      body: JSON.stringify({ mfa_token, code }),
      skipAuthHandling: true,
    }),
  enrollStart: (mfa_token: string) =>
    request<MfaSetup>("/api/auth/login/mfa/enroll/start", {
      method: "POST",
      body: JSON.stringify({ mfa_token }),
      skipAuthHandling: true,
    }),
  enrollConfirm: (mfa_token: string, code: string) =>
    request<LoginComplete>("/api/auth/login/mfa/enroll/confirm", {
      method: "POST",
      body: JSON.stringify({ mfa_token, code }),
      skipAuthHandling: true,
    }),
  mfaStatus: () => request<MfaStatus>("/api/auth/mfa"),
  mfaSetup: () => request<MfaSetup>("/api/auth/mfa/totp/setup", { method: "POST" }),
  mfaEnable: (code: string) =>
    request<{ recovery_codes: string[] }>("/api/auth/mfa/totp/enable", { method: "POST", body: JSON.stringify({ code }) }),
  mfaDisable: (password: string | null, code: string) =>
    request<void>("/api/auth/mfa/totp/disable", { method: "POST", body: JSON.stringify({ password, code }) }),
  regenerateRecoveryCodes: (password: string | null, code: string) =>
    request<{ recovery_codes: string[] }>("/api/auth/mfa/recovery-codes", {
      method: "POST",
      body: JSON.stringify({ password, code }),
    }),
  // --- admin ---
  resetMfa: (id: string) => request<User>(`/api/users/${id}/reset-mfa`, { method: "POST" }),
  users: () => request<User[]>("/api/users"),
  createUser: (u: { email: string; name: string; role: Role; password: string }) =>
    request<User>("/api/users", { method: "POST", body: JSON.stringify(u) }),
  updateUser: (id: string, patch: Partial<Pick<User, "name" | "role" | "is_active">>) =>
    request<User>(`/api/users/${id}`, { method: "PATCH", body: JSON.stringify(patch) }),
  resetPassword: (id: string, password: string) =>
    request<User>(`/api/users/${id}/reset-password`, { method: "POST", body: JSON.stringify({ password }) }),
  auditLog: (f: { action?: string; limit?: number } = {}) => request<AuditEntry[]>(`/api/audit-log${qs(f)}`),
  // --- devices ---
  devices: (f: Record<string, string | undefined> = {}) => request<DeviceSummary[]>(`/api/devices${qs(f)}`),
  deviceSummary: () => request<DeviceFleetSummary>("/api/devices/summary"),
  deviceIssueTypes: () => request<{ code: string; severity: string; title: string }[]>("/api/devices/issue-types"),
  device: (id: string) => request<DeviceDetail>(`/api/devices/${id}`),
  deviceSoftware: (id: string, q?: string) => request<DeviceSoftware[]>(`/api/devices/${id}/software${qs({ q })}`),
  deviceHistory: (id: string, limit = 50) => request<PostureSnapshot[]>(`/api/devices/${id}/history${qs({ limit })}`),
  deviceCommands: (id: string) => request<DeviceCommand[]>(`/api/devices/${id}/commands`),
  queueCommand: (id: string, body: { type: CommandType; reason: string; params?: Record<string, unknown>; confirm_hostname?: string }) =>
    request<DeviceCommand>(`/api/devices/${id}/commands`, { method: "POST", body: JSON.stringify(body) }),
  cancelCommand: (id: string, commandId: string, reason: string) =>
    request<DeviceCommand>(`/api/devices/${id}/commands/${commandId}/cancel`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  revokeDevice: (id: string, reason: string) =>
    request<DeviceDetail>(`/api/devices/${id}/revoke`, { method: "POST", body: JSON.stringify({ reason }) }),
  deleteDevice: (id: string, reason: string) =>
    request<void>(`/api/devices/${id}${qs({ reason })}`, { method: "DELETE" }),
  requestWipe: (id: string, body: { reason: string; confirm_hostname: string; mode: WipeMode }) =>
    request<Approval>(`/api/devices/${id}/wipe`, { method: "POST", body: JSON.stringify(body) }),
  logBundleUrl: (id: string, bundleId: string) => `${BASE}/api/devices/${id}/log-bundles/${bundleId}`,
  enrollmentTokens: () => request<EnrollmentToken[]>("/api/devices/enrollment-tokens"),
  createEnrollmentToken: (body: { name: string; max_uses: number | null; expires_in_hours: number }) =>
    request<EnrollmentToken & { token: string }>("/api/devices/enrollment-tokens", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  installerInfo: () => request<InstallerInfo>("/api/devices/installers"),
  downloadInstaller: (body: InstallerRequest) => requestFile("/api/devices/installers", body),
  revokeEnrollmentToken: (id: string) =>
    request<EnrollmentToken>(`/api/devices/enrollment-tokens/${id}/revoke`, { method: "POST" }),
  // --- agent auto-update ---
  updateSummary: () => request<UpdateSummary>("/api/updates/summary"),
  updateKeys: () => request<{ keys: { key_id: string; source: string }[]; error: string | null }>("/api/updates/keys"),
  agentReleases: () => request<AgentRelease[]>("/api/updates/releases"),
  withdrawRelease: (id: string, reason: string) =>
    request<AgentRelease>(`/api/updates/releases/${id}/withdraw`, { method: "POST", body: JSON.stringify({ reason }) }),
  updateRings: () => request<UpdateRing[]>("/api/updates/rings"),
  createRing: (body: UpdateRingPatch) =>
    request<UpdateRing>("/api/updates/rings", { method: "POST", body: JSON.stringify(body) }),
  updateRing: (id: string, body: UpdateRingPatch) =>
    request<UpdateRing>(`/api/updates/rings/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteRing: (id: string, reason: string) => request<void>(`/api/updates/rings/${id}${qs({ reason })}`, { method: "DELETE" }),
  deviceUpdate: (id: string) => request<DeviceUpdateState>(`/api/updates/devices/${id}`),
  setDeviceUpdate: (
    id: string,
    body: { ring_id?: string; clear_ring?: boolean; pinned_release_id?: string; clear_pin?: boolean; reason: string },
  ) => request<DeviceUpdateState>(`/api/updates/devices/${id}`, { method: "PUT", body: JSON.stringify(body) }),
  // --- approvals (admin) ---
  approvals: (f: { status?: "open" | "pending" | "approved" | "final" | "all"; device_id?: string; limit?: number } = {}) =>
    request<Approval[]>(`/api/approvals${qs(f)}`),
  approvalSummary: () => request<ApprovalSummary>("/api/approvals/summary"),
  approval: (id: string) => request<Approval>(`/api/approvals/${id}`),
  approveApproval: (id: string, body: { reason?: string; confirm_hostname?: string }) =>
    request<Approval>(`/api/approvals/${id}/approve`, { method: "POST", body: JSON.stringify(body) }),
  rejectApproval: (id: string, reason: string) =>
    request<Approval>(`/api/approvals/${id}/reject`, { method: "POST", body: JSON.stringify({ reason }) }),
  cancelApproval: (id: string, reason: string) =>
    request<Approval>(`/api/approvals/${id}/cancel`, { method: "POST", body: JSON.stringify({ reason }) }),
  // --- script library ---
  scripts: () => request<ScriptLibrary>("/api/scripts"),
  scriptBundles: () => request<ScriptBundle[]>("/api/scripts/bundles"),
  runScript: (body: { device_id: string; script: string; parameters: Record<string, ScriptParamValue>; reason: string }) =>
    request<ScriptRunResult>("/api/scripts/run", { method: "POST", body: JSON.stringify(body) }),
  scriptRuns: (f: { device_id?: string; script?: string; limit?: number } = {}) => request<ScriptRun[]>(`/api/scripts/runs${qs(f)}`),
  scriptPendingApprovals: () => request<Approval[]>("/api/scripts/pending-approvals"),
  // --- platform ---
  health: () => request<Health>("/api/health"),
  dashboard: () => request<Dashboard>("/api/dashboard"),
  dashboards: (p: DashParams) => request<DashMeta>(`/api/dashboards${qs(p)}`),
  dashOverview: (p: DashParams) => request<DashOverview>(`/api/dashboards/overview${qs(p)}`),
  dashVulns: (p: DashParams) => request<DashVulns>(`/api/dashboards/vulnerabilities${qs(p)}`),
  dashExposure: (p: DashParams) => request<DashExposure>(`/api/dashboards/exposure${qs(p)}`),
  dashIdentities: (p: DashParams) => request<DashIdentities>(`/api/dashboards/identities${qs(p)}`),
  dashEndpoints: (p: DashParams) => request<DashEndpoints>(`/api/dashboards/endpoints${qs(p)}`),
  assets: (f: Record<string, string | boolean | undefined> = {}) => request<AssetSummary[]>(`/api/assets${qs(f)}`),
  facets: () =>
    request<{
      types: string[];
      providers: string[];
      regions: string[];
      sources: string[];
      subscriptions: { id: string; name: string; provider: string }[];
    }>(
      "/api/assets/facets",
    ),
  assetDetail: (id: string) =>
    request<{
      asset: Asset;
      relationships: { type: string; direction: "in" | "out"; asset: { id: string; name: string; type: string } }[];
      findings: Finding[];
      vulnerabilities: Vulnerability[];
      alerts: Alert[];
    }>(`/api/assets/detail${qs({ id })}`),
  findings: (f: Record<string, string | undefined> = {}) => request<Finding[]>(`/api/findings${qs(f)}`),
  finding: (id: string) => request<Finding>(`/api/findings/${encodeURIComponent(id)}`),
  updateFinding: (id: string, status: Finding["status"]) =>
    request<Finding>(`/api/findings/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }),
  vulnerabilities: (f: Record<string, string | boolean | undefined> = {}) =>
    request<Vulnerability[]>(`/api/vulnerabilities${qs(f)}`),
  vulnStats: () =>
    request<{
      noise_reduction: NoiseReduction;
      by_severity: Record<string, number>;
      by_priority: Record<string, number>;
      critical_cvss_total: number;
      critical_cvss_in_use: number;
      in_use_and_exposed: number;
      exploitable_in_use: number;
      total: number;
      assets: { open: number; affected: number };
      devices: { open: number; affected: number };
      kev: { open: number; cves: number };
    }>("/api/vulnerabilities/stats"),
  vulnByCve: (f: Record<string, string | boolean | undefined> = {}) =>
    request<VulnByCve[]>(`/api/vulnerabilities/by-cve${qs(f)}`),
  vulnBySoftware: (f: Record<string, string | boolean | undefined> = {}) =>
    request<VulnBySoftware[]>(`/api/vulnerabilities/by-software${qs(f)}`),
  vulnStatus: () => request<VulnStatus>("/api/vulnerabilities/status"),
  /** Analyst: queue every device / asset for matching now. */
  vulnRematch: () => request<{ queued: number; worker_running: boolean }>("/api/vulnerabilities/rematch", { method: "POST" }),
  deviceVulnerabilities: (id: string, status = "open") =>
    request<DeviceVulnerabilities>(`/api/devices/${encodeURIComponent(id)}/vulnerabilities${qs({ status })}`),
  alerts: (f: Record<string, string | undefined> = {}) => request<Alert[]>(`/api/alerts${qs(f)}`),
  alert: (id: string) => request<AlertDetail>(`/api/alerts/${id}`),
  updateAlert: (id: string, status: Alert["status"]) =>
    request<Alert>(`/api/alerts/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }),
  events: (limit = 50, source?: string) => request<RuntimeEvent[]>(`/api/runtime/events${qs({ limit, source })}`),
  attackPaths: (limit = 20, confirmedOnly = false) =>
    request<AttackPath[]>(`/api/attack-paths${qs({ limit, confirmed_only: confirmedOnly ? "true" : undefined })}`),
  attackGraph: (limit = 10, confirmedOnly = false) =>
    request<{
      nodes: { id: string; name: string; type: string; internet_exposed?: boolean; sensitive_data?: boolean }[];
      edges: { source: string; target: string; type: string; paths: string[] }[];
      paths: AttackPath[];
    }>(`/api/attack-paths/graph${qs({ limit, confirmed_only: confirmedOnly ? "true" : undefined })}`),
  exposure: (f: { provider?: string; subscription?: string; type?: string; port?: string; level?: string } = {}) =>
    request<{
      items: ExposureItem[];
      facets: { providers: string[]; subscriptions: string[]; types: string[]; ports: string[] };
      summary: ExposureSummary;
    }>(`/api/exposure${qs(f)}`),
  exposureSummary: () => request<ExposureSummary>("/api/exposure/summary"),
  connectors: () => request<Connector[]>("/api/connectors"),
  scans: () => request<ScanRun[]>("/api/scans"),
  scanSchedule: () => request<ScanSchedule>("/api/scan-schedule"),
  /** Admin. Only the fields sent change; null resets a field to the environment default. */
  updateScanSchedule: (body: { enabled?: boolean | null; interval_hours?: number | null }) =>
    request<ScanSchedule>("/api/scan-schedule", { method: "PUT", body: JSON.stringify(body) }),
  startScan: (connector: string) =>
    request<ScanRun>("/api/scans", { method: "POST", body: JSON.stringify({ connector }) }),
  postureRules: () =>
    request<{ id: string; title: string; severity: Severity; resource_type: string; compliance: string[] }[]>(
      "/api/rules/posture",
    ),
  detectionRules: () =>
    request<
      { id: string; title: string; severity: Severity; mitre_tactic: string; mitre_technique_id: string; mitre_technique_name: string }[]
    >("/api/rules/detection"),
};
