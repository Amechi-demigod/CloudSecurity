// Typed API client for the FastAPI backend.

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
  asset_id: string;
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
  attack_paths: { total: number; critical: number };
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
}

export interface ScanRun {
  id: string;
  connector: string;
  status: "running" | "succeeded" | "failed";
  started_at: string;
  finished_at: string | null;
  assets_found: number;
  findings_open: number;
  errors: string[];
  message: string;
}

export interface Health {
  status: string;
  simulation_mode: boolean;
  simulator_running: boolean;
  azure_configured: boolean;
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

export interface SessionInfo {
  user: User;
  csrf_token: string;
  expires_at: string;
  idle_timeout_minutes: number;
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

export type CommandType = "recheck_posture" | "collect_logs" | "lock_device" | "restart_agent" | "update_check_in_interval";

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

export function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

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
  queueCommand: (id: string, body: { type: CommandType; reason: string; params?: Record<string, unknown> }) =>
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
  logBundleUrl: (id: string, bundleId: string) => `${BASE}/api/devices/${id}/log-bundles/${bundleId}`,
  enrollmentInfo: () =>
    request<{ agent_download_url: string | null; default_check_in_interval_seconds: number; command_poll_seconds: number }>(
      "/api/devices/enrollment/info",
    ),
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
  // --- platform ---
  health: () => request<Health>("/api/health"),
  dashboard: () => request<Dashboard>("/api/dashboard"),
  assets: (f: Record<string, string | boolean | undefined> = {}) => request<AssetSummary[]>(`/api/assets${qs(f)}`),
  facets: () =>
    request<{ types: string[]; regions: string[]; sources: string[]; subscriptions: { id: string; name: string }[] }>(
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
    }>("/api/vulnerabilities/stats"),
  alerts: (f: Record<string, string | undefined> = {}) => request<Alert[]>(`/api/alerts${qs(f)}`),
  alert: (id: string) => request<AlertDetail>(`/api/alerts/${id}`),
  updateAlert: (id: string, status: Alert["status"]) =>
    request<Alert>(`/api/alerts/${id}`, { method: "PATCH", body: JSON.stringify({ status }) }),
  events: (limit = 50, source?: string) => request<RuntimeEvent[]>(`/api/runtime/events${qs({ limit, source })}`),
  attackPaths: (limit = 20) => request<AttackPath[]>(`/api/attack-paths${qs({ limit })}`),
  attackGraph: (limit = 10) =>
    request<{
      nodes: { id: string; name: string; type: string; internet_exposed?: boolean; sensitive_data?: boolean }[];
      edges: { source: string; target: string; type: string; paths: string[] }[];
      paths: AttackPath[];
    }>(`/api/attack-paths/graph${qs({ limit })}`),
  connectors: () => request<Connector[]>("/api/connectors"),
  scans: () => request<ScanRun[]>("/api/scans"),
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
