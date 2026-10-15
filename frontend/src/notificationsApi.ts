// Typed client for /api/notifications (channels, rules, delivery log).
import { request, qs, type Severity } from "./api";

export type ChannelType = "teams" | "slack" | "email" | "webhook";

export interface FieldSpec {
  name: string;
  label: string;
  kind: "text" | "url" | "int" | "list" | "select" | "email";
  secret: boolean;
  required: boolean;
  help: string;
  options: string[];
  default: string | number | null;
  provider: string;
}

export interface NotificationMeta {
  channel_types: { type: ChannelType; label: string; description: string; fields: FieldSpec[]; allowed_hosts: string[] }[];
  sources: { name: string; label: string; event_types: string[]; description: string }[];
  severities: Severity[];
  public_base_url: string | null;
  encryption_configured: boolean;
}

export interface NotificationStatus {
  worker_running: boolean;
  worker_leader: boolean;
  last_tick_at: string | null;
  deliveries: { pending: number; sending: number; sent: number; dead: number };
  sent_24h: number;
  event_backlog: number;
}

export interface Channel {
  id: string;
  name: string;
  type: ChannelType;
  enabled: boolean;
  config: Record<string, unknown>;
  secret_hints: Record<string, string>;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  last_test_at: string | null;
  last_test_status: "ok" | "failed" | null;
}

export interface ChannelInput {
  name: string;
  type: ChannelType;
  enabled?: boolean;
  config: Record<string, unknown>;
  secrets: Record<string, string>;
}

export interface RuleInput {
  name: string;
  enabled: boolean;
  sources: string[];
  event_types: string[];
  min_severity: Severity;
  subscription_ids: string[];
  asset_ids: string[];
  asset_types: string[];
  tags: Record<string, string>;
  rule_ids: string[];
  mitre_techniques: string[];
  include_status_changes: boolean;
  channel_ids: string[];
  throttle_minutes: number;
  mode: "immediate" | "digest";
  digest_hour: number;
  timezone: string;
  quiet_start: string | null;
  quiet_end: string | null;
  quiet_bypass_severity: Severity | null;
}

export interface Rule extends RuleInput {
  id: string;
  last_digest_at: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface Delivery {
  id: string;
  created_at: string;
  channel_id: string | null;
  channel_name: string;
  channel_type: string;
  rule_id: string | null;
  rule_name: string;
  event_id: string | null;
  kind: "event" | "digest" | "test";
  severity: Severity;
  title: string;
  status: "pending" | "sending" | "sent" | "dead";
  attempts: number;
  next_attempt_at: string;
  last_attempt_at: string | null;
  sent_at: string | null;
  response_status: number | null;
  last_error: string | null;
  link: string | null;
}

const BASE = "/api/notifications";
const json = (method: string, body?: unknown) => ({ method, body: body === undefined ? undefined : JSON.stringify(body) });

export const notificationsApi = {
  meta: () => request<NotificationMeta>(`${BASE}/meta`),
  status: () => request<NotificationStatus>(`${BASE}/status`),
  channels: () => request<Channel[]>(`${BASE}/channels`),
  createChannel: (c: ChannelInput) => request<Channel>(`${BASE}/channels`, json("POST", c)),
  updateChannel: (id: string, patch: Partial<Omit<ChannelInput, "type">>) =>
    request<Channel>(`${BASE}/channels/${id}`, json("PATCH", patch)),
  deleteChannel: (id: string) => request<void>(`${BASE}/channels/${id}`, json("DELETE")),
  testChannel: (id: string) => request<{ ok: boolean; delivery: Delivery }>(`${BASE}/channels/${id}/test`, json("POST")),
  rules: () => request<Rule[]>(`${BASE}/rules`),
  createRule: (r: RuleInput) => request<Rule>(`${BASE}/rules`, json("POST", r)),
  updateRule: (id: string, r: RuleInput) => request<Rule>(`${BASE}/rules/${id}`, json("PUT", r)),
  deleteRule: (id: string) => request<void>(`${BASE}/rules/${id}`, json("DELETE")),
  deliveries: (f: { status?: string; kind?: string; channel_id?: string; limit?: number } = {}) =>
    request<Delivery[]>(`${BASE}/deliveries${qs(f)}`),
  retryDelivery: (id: string) => request<Delivery>(`${BASE}/deliveries/${id}/retry`, json("POST")),
};
