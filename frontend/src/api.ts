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

const BASE = import.meta.env.VITE_API_BASE ?? "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* ignore */
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json() as Promise<T>;
}

function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

export const api = {
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
