// Typed client for /api/compliance (framework posture from the platform's own checks, exports, scheduled reports).
// Reports are evidence to support an assessment, not an audit opinion (docs/COMPLIANCE.md).
import { BASE, qs, request } from "./api";

export type ControlStatus = "pass" | "fail" | "partial" | "no_data" | "manual";
export type CheckStatus = "pass" | "fail" | "no_data" | "out_of_scope";
export type CheckKind = "cloud" | "endpoint" | "vuln" | "directory" | "inventory";

export interface ComplianceSummary {
  pass: number;
  fail: number;
  partial: number;
  no_data: number;
  manual: number;
  total: number;
  assessed: number;
  mapped: number;
  /** Controls without failing evidence / controls assessed automatically; null when nothing is assessed. */
  score: number | null;
  /** Controls assessed automatically / all controls. */
  coverage: number;
}

export interface FrameworkMeta {
  id: string;
  name: string;
  short_name: string;
  version: string;
  mapping_version: number;
  publisher: string;
  notice: string;
  controls: number;
  automated_controls: number;
}

export interface FrameworkOverview extends FrameworkMeta {
  summary: ComplianceSummary;
}

export interface CheckItem {
  label: string;
  detail: string;
  since?: string | null;
  link: string;
}

export interface CheckResult {
  id: string;
  kind: CheckKind;
  title: string;
  status: CheckStatus;
  failing: number;
  total: number | null;
  detail: string;
  link: string | null;
  items: CheckItem[];
}

export interface Control {
  id: string;
  title: string;
  status: ControlStatus;
  coverage: "full" | "partial" | null;
  note: string;
  failing: number;
  checks: CheckResult[];
}

export interface FrameworkPosture {
  framework: FrameworkMeta;
  scope: { account: string | null; device_group: string | null; label: string };
  generated_at: string;
  summary: ComplianceSummary;
  groups: { id: string; title: string; controls: Control[] }[];
  disclaimer: string;
}

export interface TrendPoint {
  day: string;
  mapping_version: number;
  score: number | null;
  coverage: number | null;
  pass: number;
  fail: number;
  partial: number;
}

export interface Schedule {
  id: string;
  name: string;
  enabled: boolean;
  frameworks: string[];
  frequency: "weekly" | "monthly";
  day: number;
  hour: number;
  recipients: string[];
  account: string | null;
  device_group: string | null;
  next_run_at: string | null;
  last_run_at: string | null;
  last_status: "sent" | "partial" | "failed" | null;
  last_error: string | null;
  created_by: string | null;
}

export type ScheduleBody = Omit<Schedule, "id" | "next_run_at" | "last_run_at" | "last_status" | "last_error" | "created_by">;

export interface Scope {
  account?: string;
  device_group?: string;
}

export const STATUS_LABEL: Record<ControlStatus, string> = {
  pass: "Pass",
  fail: "Fail",
  partial: "Partial",
  no_data: "No data",
  manual: "Manual",
};

export const STATUS_HINT: Record<ControlStatus, string> = {
  pass: "Every automated check passes and they cover the whole control",
  fail: "At least one automated check fails",
  partial: "The automated checks pass, but they cover only part of the control: add manual evidence",
  no_data: "Checks are mapped, but nothing in scope to evaluate (for example no AWS account connected)",
  manual: "Not assessed automatically: needs manual evidence",
};

export const CHECK_KIND_LABEL: Record<CheckKind, string> = {
  cloud: "Cloud posture",
  endpoint: "Endpoint agent",
  vuln: "Vulnerabilities",
  directory: "Directory",
  inventory: "Inventory",
};

export const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

export const complianceApi = {
  frameworks: (s: Scope) =>
    request<{ frameworks: FrameworkOverview[]; scopes: { accounts: { id: string; name: string; provider: string }[]; device_groups: string[] }; disclaimer: string }>(
      `/api/compliance/frameworks${qs({ ...s })}`,
    ),
  posture: (id: string, s: Scope) => request<FrameworkPosture>(`/api/compliance/frameworks/${encodeURIComponent(id)}${qs({ ...s })}`),
  trend: (id: string, s: Scope, days = 90) =>
    request<{ framework: string; mapping_version: number; points: TrendPoint[] }>(`/api/compliance/frameworks/${encodeURIComponent(id)}/trend${qs({ ...s, days })}`),
  csvUrl: (id: string, s: Scope) => `${BASE}/api/compliance/frameworks/${encodeURIComponent(id)}/export.csv${qs({ ...s })}`,
  pdfUrl: (ids: string[], s: Scope) => `${BASE}/api/compliance/report.pdf${qs({ frameworks: ids.join(","), ...s })}`,
  schedules: () => request<{ items: Schedule[]; mail_configured: boolean; max_schedules: number }>("/api/compliance/schedules"),
  recipients: () => request<{ emails: string[] }>("/api/compliance/recipients"),
  createSchedule: (b: ScheduleBody) => request<Schedule>("/api/compliance/schedules", { method: "POST", body: JSON.stringify(b) }),
  updateSchedule: (id: string, b: Partial<ScheduleBody>) =>
    request<Schedule>(`/api/compliance/schedules/${id}`, { method: "PATCH", body: JSON.stringify(b) }),
  deleteSchedule: (id: string) => request<void>(`/api/compliance/schedules/${id}`, { method: "DELETE" }),
  sendNow: (id: string) =>
    request<{ status: string; sent: number; errors: string[]; schedule: Schedule }>(`/api/compliance/schedules/${id}/send`, { method: "POST" }),
};
