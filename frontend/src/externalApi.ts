// Typed client for the Attack surface & pre-ASV module (backend app/external, docs/ATTACK_SURFACE.md).
// Pre-ASV only: nothing here is an ASV scan report or an Attestation of Scan Compliance.
import { BASE, request } from "./api";

export type ExtSeverity = "critical" | "high" | "medium" | "low" | "info";
export type ExtStatus = "open" | "resolved" | "accepted" | "disputed";
export type ExtResult = "pass" | "fail" | null;

export interface ExtProof {
  txt_name: string;
  txt_value: string;
  txt_name_alt: string;
  file_url: string;
  file_content: string;
}

export interface ExtTarget {
  id: string;
  kind: "domain" | "ip" | "cidr";
  value: string;
  verified: boolean;
  verified_method: string | null;
  verified_at: string | null;
  verified_detail: string | null;
  last_check_at: string | null;
  last_check_error: string | null;
  approval_status: "none" | "requested" | "approved" | "rejected";
  approval_note: string | null;
  attested_by: string | null;
  attestation: string | null;
  default_password_checks: boolean;
  consent_by: string | null;
  consent_at: string | null;
  window_start_hour: number | null;
  window_end_hour: number | null;
  created_at: string;
  proof: ExtProof | null;
}

export interface ExtScan {
  id: string;
  trigger: string;
  status: "running" | "succeeded" | "failed" | "partial";
  started_at: string;
  finished_at: string | null;
  started_by: string | null;
  hosts: number;
  open_ports: number;
  new_hosts: number;
  findings_open: number;
  result: ExtResult;
  targets: string[];
  skipped: { value: string; reason: string }[];
  message: string;
}

export interface ExtOverview {
  hosts: number;
  open_ports: number;
  new_since_last_scan: number;
  open_findings: number;
  failing_findings: number;
  by_severity: Record<ExtSeverity, number>;
  result: ExtResult;
  result_label: string;
  last_scan: ExtScan | null;
  running: boolean;
  schedule: { enabled: boolean; interval_hours: number; next_scan_at: string | null };
  scope: { text: string; confirmed_by: string | null; confirmed_at: string | null };
  limits: { max_targets: number; max_cidr_addresses: number };
  disclaimer: string;
}

export interface ExtHost {
  id: string;
  host: string;
  ip: string | null;
  ports: { port: number; service: string; banner: string; product: string | null; version: string | null }[];
  software: { product: string; version: string; port: number }[];
  tls_summary: string | null;
  asset_id: string | null;
  active: boolean;
  first_seen: string;
  last_seen: string;
  findings: number;
}

export interface ExtFinding {
  id: string;
  ref: string;
  check_id: string;
  title: string;
  severity: ExtSeverity;
  cvss: number;
  vector: string | null;
  cwe: string | null;
  cve_id: string | null;
  host: string;
  ip: string | null;
  port: number | null;
  url: string | null;
  status: ExtStatus;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  auto_fail: boolean;
  dos_only: boolean;
  fails: boolean;
  exempt?: boolean;
  service?: string | null;
  special_note: string | null;
  fix_due: string | null;
  overdue_days: number | null;
  days_left: number | null;
}

export type ExtFindingFilter = {
  status?: string;
  severity?: string;
  host?: string;
  pre_asv?: string;
  target?: string;
  q?: string;
  sort?: string;
  dir?: string;
};

export type ExtPreAsv = "fail" | "pass" | "exception" | null;

/** One affected finding inside a group (host:port). */
export interface ExtGroupMember {
  id: string;
  ref: string;
  host: string;
  port: number | null;
  status: ExtStatus;
  severity: ExtSeverity;
  cvss: number;
  fails: boolean;
  auto_fail: boolean;
  exempt: boolean;
  pre_asv: ExtPreAsv;
  fix_due: string | null;
  overdue_days: number | null;
  days_left: number | null;
}

/** One row per check over the whole filtered result. */
export interface ExtFindingGroup {
  check_id: string;
  title: string;
  severity: ExtSeverity;
  cvss: number;
  affected: number;
  hosts: number;
  pre_asv: ExtPreAsv;
  auto_fail: boolean;
  status_counts: Record<"open" | "disputed" | "accepted" | "resolved", number>;
  fix_due: string | null;
  overdue_days: number | null;
  days_left: number | null;
  first_seen: string;
  last_seen: string;
  findings: ExtGroupMember[];
}

export interface ExtDispute {
  id: string;
  finding_id: string;
  kind: "false_positive" | "compensating_control";
  reason: string;
  submitted_by: string;
  submitted_at: string;
  status: "pending" | "accepted" | "rejected";
  reviewed_by: string | null;
  review_note: string | null;
  ref?: string;
  title?: string;
  host?: string;
  severity?: string;
  cvss?: number;
  organization?: string;
  fail_reason?: string | null;
}

export interface ExtFindingDetail extends ExtFinding {
  detail: {
    description: string;
    impact: string;
    steps: string[];
    fix: Record<string, string>;
    references: string[];
    compliance: Record<string, string[]>;
  };
  evidence: Record<string, unknown>;
  status_note: string | null;
  fail_reason: string | null;
  sla_basis: string | null;
  disputes: ExtDispute[];
}

export interface ExtReportData {
  title: string;
  disclaimer: string;
  generated_at: string;
  customer: { name: string };
  scan: { id: string; started_at: string; finished_at: string | null; trigger: string; targets: string[]; skipped: unknown[] } | null;
  result: ExtResult;
  result_label: string;
  rules: { rule: string; result: string }[];
  components: { host: string; ip: string | null; ports: number[]; failing: number; findings: number; result: string }[];
  vulnerabilities: {
    ref: string; title: string; host: string; ip: string | null; port: number | null; severity: string; cvss: number;
    result: string; reason: string | null; exception: { kind: string; reason: string; reviewed_by: string; note: string } | null;
  }[];
  special_notes: { key: string; label: string; items: { host: string; port: number | null; item: string }[] }[];
  exceptions: unknown[];
  scope: { text: string; confirmed_by: string | null; confirmed_at: string | null };
}

export interface ExtReportRow {
  id: string;
  scan_id: string | null;
  generated_at: string;
  generated_by: string | null;
  result: string;
  result_label: string;
}

export interface ExtApproval extends ExtTarget {
  organization_id: string;
  organization: string;
}

const j = (body: unknown) => ({ body: JSON.stringify(body) });
const qs = (p: Record<string, string | undefined>) => {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(p)) if (v) u.set(k, v);
  const s = u.toString();
  return s ? `?${s}` : "";
};

export const externalApi = {
  overview: () => request<ExtOverview>("/api/external/overview"),
  targets: () => request<ExtTarget[]>("/api/external/targets"),
  addTarget: (value: string) => request<ExtTarget>("/api/external/targets", { method: "POST", ...j({ value }) }),
  removeTarget: (id: string) => request<void>(`/api/external/targets/${id}`, { method: "DELETE" }),
  verify: (id: string) =>
    request<{ verified: boolean; method?: string; error?: string; target: ExtTarget }>(`/api/external/targets/${id}/verify`, { method: "POST" }),
  requestApproval: (id: string, attestation: string) =>
    request<ExtTarget>(`/api/external/targets/${id}/request-approval`, { method: "POST", ...j({ attestation }) }),
  setDefaultPasswords: (id: string, enabled: boolean, consent: boolean) =>
    request<ExtTarget>(`/api/external/targets/${id}/default-passwords`, { method: "PUT", ...j({ enabled, consent }) }),
  setWindow: (id: string, start_hour: number | null, end_hour: number | null) =>
    request<ExtTarget>(`/api/external/targets/${id}/window`, { method: "PUT", ...j({ start_hour, end_hour }) }),
  setScope: (text: string, confirm: boolean) => request<ExtOverview["scope"]>("/api/external/scope", { method: "PUT", ...j({ text, confirm }) }),
  setSchedule: (enabled: boolean | null, interval_hours: number | null) =>
    request<ExtOverview["schedule"]>("/api/external/schedule", { method: "PUT", ...j({ enabled, interval_hours }) }),
  scans: () => request<ExtScan[]>("/api/external/scans"),
  scanNow: () => request<ExtScan>("/api/external/scans", { method: "POST" }),
  scanTarget: (id: string) => request<ExtScan>(`/api/external/targets/${id}/scan`, { method: "POST" }),
  hosts: () => request<ExtHost[]>("/api/external/hosts"),
  findings: (p: ExtFindingFilter = {}) => request<ExtFinding[]>(`/api/external/findings${qs(p)}`),
  findingsGrouped: (p: ExtFindingFilter = {}) => request<ExtFindingGroup[]>(`/api/external/findings/grouped${qs(p)}`),
  finding: (id: string) => request<ExtFindingDetail>(`/api/external/findings/${id}`),
  acceptRisk: (id: string, reason: string) => request<ExtFindingDetail>(`/api/external/findings/${id}/accept-risk`, { method: "POST", ...j({ reason }) }),
  reopen: (id: string) => request<ExtFindingDetail>(`/api/external/findings/${id}/reopen`, { method: "POST" }),
  dispute: (id: string, kind: ExtDispute["kind"], reason: string) =>
    request<ExtFindingDetail>(`/api/external/findings/${id}/dispute`, { method: "POST", ...j({ kind, reason }) }),
  retest: (id: string) => request<ExtScan>(`/api/external/findings/${id}/retest`, { method: "POST" }),
  findingPdfUrl: (id: string) => `${BASE}/api/external/findings/${id}/pdf`,
  reports: () => request<ExtReportRow[]>("/api/external/reports"),
  preview: () => request<ExtReportData>("/api/external/report/preview"),
  report: (id: string) => request<ExtReportData>(`/api/external/reports/${id}`),
  generateReport: () => request<ExtReportRow>("/api/external/reports", { method: "POST" }),
  reportPdfUrl: (id: string) => `${BASE}/api/external/reports/${id}/pdf`,
  // Platform owners
  platformApprovals: () => request<ExtApproval[]>("/api/platform/external/approvals"),
  decideApproval: (id: string, approve: boolean, note: string) =>
    request<ExtTarget>(`/api/platform/external/approvals/${id}/decide`, { method: "POST", ...j({ approve, note }) }),
  platformDisputes: () => request<ExtDispute[]>("/api/platform/external/disputes"),
  decideDispute: (id: string, approve: boolean, note: string) =>
    request<ExtDispute>(`/api/platform/external/disputes/${id}/decide`, { method: "POST", ...j({ approve, note }) }),
};
