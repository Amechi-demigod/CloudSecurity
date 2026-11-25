// Typed client for /api/reports/executive (the executive report: on-screen data, PDF, scheduled emails).
// See docs/EXECUTIVE_REPORT.md.
import { BASE, qs, request } from "./api";

export type ReportPeriod = "daily" | "weekly" | "monthly" | "quarterly";
export const PERIODS: { value: ReportPeriod; label: string }[] = [
  { value: "daily", label: "Day" },
  { value: "weekly", label: "Week" },
  { value: "monthly", label: "Month" },
  { value: "quarterly", label: "Quarter" },
];
export const PERIOD_NAME: Record<ReportPeriod, string> = { daily: "Daily", weekly: "Weekly", monthly: "Monthly", quarterly: "Quarterly" };
export const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

export interface TopRisk {
  title: string;
  why: string;
  who: string;
  severity: "critical" | "high" | "medium" | "low";
}

export interface ExecutiveReport {
  organization: string;
  brand: string;
  generated_at: string;
  modules: string[];
  period: { key: ReportPeriod; name: string; days: number; start: string; end: string; compared_with: string; label: string };
  headline: { text: string; score: number | null; delta: number | null; direction: "better" | "worse" | "same" | "unknown"; level: string | null; explain: string };
  top_risks: TopRisk[];
  changes: { compared_with: string; comparison_available: boolean; improved: string[]; worse: string[]; notes: string[]; explain: string };
  coverage: { lines: string[]; data: Record<string, number>; explain: string };
  compliance?: { frameworks: { name: string; score: number | null; coverage: number | null; failing: number }[]; disclaimer: string; explain: string };
  exposure?: {
    findings: Record<string, number>;
    total: number;
    domains: { domain: string; grade: string | null; score: number | null; meaning: string; open_issues: number }[];
    lines: string[];
    explain: string;
  };
  overdue?: { total: number; open: number; by_severity: Record<string, number>; oldest_days: number; lines: string[]; explain: string };
  next_steps: string[];
}

export interface Recipient {
  id: string;
  kind: "admin" | "external";
  user_id: string | null;
  name: string;
  email: string;
  job_title: string | null;
  state: "active" | "unsubscribed" | "not_admin";
}

export interface Subscription {
  id: string;
  name: string;
  enabled: boolean;
  frequency: ReportPeriod;
  day: number;
  hour: number;
  next_run_at: string | null;
  last_run_at: string | null;
  last_status: "sent" | "partial" | "failed" | null;
  last_error: string | null;
  recipients: Recipient[];
}

export interface SubscriptionBody {
  name: string;
  enabled: boolean;
  frequency: ReportPeriod;
  day: number;
  hour: number;
}

export type RecipientBody = { kind: "admin"; user_id: string } | { kind: "external"; name: string; email: string; job_title?: string };

const B = "/api/reports/executive";
const json = (b: unknown) => JSON.stringify(b);

export const executiveApi = {
  report: (period: ReportPeriod) => request<ExecutiveReport>(`${B}${qs({ period })}`),
  pdfUrl: (period: ReportPeriod) => `${BASE}${B}/pdf${qs({ period })}`,
  subscriptions: () =>
    request<{ items: Subscription[]; mail_configured: boolean; max_subscriptions: number; max_recipients: number; admins: { id: string; name: string; email: string }[] }>(`${B}/subscriptions`),
  create: (b: SubscriptionBody) => request<Subscription>(`${B}/subscriptions`, { method: "POST", body: json(b) }),
  update: (id: string, b: Partial<SubscriptionBody>) => request<Subscription>(`${B}/subscriptions/${id}`, { method: "PATCH", body: json(b) }),
  remove: (id: string) => request<void>(`${B}/subscriptions/${id}`, { method: "DELETE" }),
  addRecipient: (id: string, b: RecipientBody) => request<Subscription>(`${B}/subscriptions/${id}/recipients`, { method: "POST", body: json(b) }),
  removeRecipient: (id: string, rid: string) => request<Subscription>(`${B}/subscriptions/${id}/recipients/${rid}`, { method: "DELETE" }),
  sendNow: (id: string) => request<{ status: string; sent: number; errors: string[]; subscription: Subscription }>(`${B}/subscriptions/${id}/send`, { method: "POST" }),
};
