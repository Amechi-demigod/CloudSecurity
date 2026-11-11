// Typed client for /api/network (network discovery: scans on a dedicated collector, SNMP credentials, discovered devices).
import { BASE, getFile, qs, request } from "./api";

export type NetDeviceType = "switch" | "router" | "firewall" | "access_point" | "printer" | "ups" | "phone" | "camera" | "server" | "workstation" | "unknown";
export type Tracked = "agent" | "ad" | "it_asset" | "sensor" | "none";
export type SnmpVersion = "v3" | "v2c";

export const TYPE_LABEL: Record<string, string> = {
  switch: "Switch",
  router: "Router",
  firewall: "Firewall",
  access_point: "Access point",
  printer: "Printer",
  ups: "UPS",
  phone: "Phone",
  camera: "Camera",
  server: "Server",
  workstation: "Workstation",
  unknown: "Unknown",
};

export const TRACK_TONE: Record<Tracked, "good" | "accent" | "default" | "warn"> = { agent: "good", ad: "accent", it_asset: "accent", sensor: "accent", none: "warn" };

/** The fixed light port check (the server sends the same list to the collector). */
export const PORT_CHIPS = ["22", "23", "80", "443", "445", "3389", "161/udp", "8080", "8443", "9100"];

export interface NetRun {
  id: string;
  scan_id: string | null;
  name: string;
  trigger: "scheduled" | "manual" | "test" | "rescan";
  status: "queued" | "running" | "succeeded" | "failed" | "cancelled";
  collector_id: string | null;
  queued_at: string;
  started_at: string | null;
  finished_at: string | null;
  devices_seen: number;
  summary: { addresses?: number; alive?: number; snmp?: number; duration_s?: number; errors?: string[] };
  error: string | null;
  requested_by: string | null;
  targets: string[];
  port_check: boolean | null;
}

export interface NetScan {
  id: string;
  name: string;
  enabled: boolean;
  collector_id: string | null;
  collector: { id: string; name: string; state: string; ip: string | null; version: string } | null;
  targets: string[];
  exclude: string[];
  target_notes: Record<string, string>;
  port_check: boolean;
  ports: { port: number; proto: string }[];
  concurrency: 20 | 64;
  pace: "gentle" | "normal";
  credential_ids: string[];
  schedule: "daily" | "weekly" | "manual";
  schedule_time: string;
  schedule_weekday: number;
  address_count: number;
  next_run_at: string | null;
  last_run_id: string | null;
  last_run_at: string | null;
  last_status: string | null;
  last_summary: { addresses?: number; alive?: number; snmp?: number; devices?: number; duration_s?: number; error?: string; errors?: string[] };
  created_at: string;
  created_by: string | null;
  updated_at: string;
  updated_by: string | null;
}

export interface NetCredential {
  id: string;
  name: string;
  version: SnmpVersion;
  username_hint: string;
  level: string;
  auth_proto: string;
  priv_proto: string;
  label: string;
  created_at: string;
  created_by: string | null;
  secret_stored: boolean;
}

export interface CredentialIn {
  name: string;
  version: SnmpVersion;
  username?: string;
  level?: "authPriv" | "authNoPriv";
  auth_proto?: "SHA" | "SHA256" | "SHA512";
  priv_proto?: "AES128" | "AES256";
  auth_password?: string;
  priv_password?: string;
  community?: string;
}

export interface Suggestion {
  subnet: string;
  name: string;
  source: "ad_site" | "dhcp";
  suggested_by: string;
  suggested_by_all: string[];
  addresses: number;
}

export interface SuggestionSet {
  collector_id: string;
  collector_name: string;
  at: string | null;
  pending: boolean;
  items: Suggestion[];
  errors: string[];
}

export interface ScanIn {
  name: string;
  collector_id: string;
  targets: string[];
  exclude: string[];
  target_notes: Record<string, string>;
  port_check: boolean;
  concurrency: 20 | 64;
  credential_ids: string[];
  schedule: "daily" | "weekly" | "manual";
  schedule_time: string;
  schedule_weekday: number;
  run_now: boolean;
}

export interface NetIssue {
  id: string;
  rule_id: string;
  severity: string;
  title: string;
}

export interface NetDeviceRow {
  id: string;
  name: string;
  ip: string;
  mac: string;
  mac_vendor: string;
  hostname: string;
  device_type: NetDeviceType;
  type_label: string;
  vendor: string;
  model: string;
  firmware: string;
  snmp_version: SnmpVersion | "";
  identified_by: string;
  subnet: string;
  open_ports: { port: number; proto: string; service: string }[];
  vulns: { open: number; kev: number; max_severity: string | null };
  findings: NetIssue[];
  tracked: Tracked;
  tracked_label: string;
  it_asset_id: string | null;
  device_id: string | null;
  first_seen: string;
  last_seen: string;
  new_this_week: boolean;
}

export interface NetSummary {
  devices: number;
  with_snmp: number;
  ping_arp_only: number;
  infrastructure: number;
  not_in_it_assets: number;
  with_vulns: number;
  kev: number;
  vulns: number;
  last_scan: NetRun | null;
  subnets: string[];
}

export interface NetFix {
  title: string;
  current: string;
  target: string | null;
  cve_count: number;
  kev_count: number;
  max_severity: string;
  cves: { cve_id: string; severity: string; cvss: number; kev: boolean; fixed_version: string | null; title: string }[];
  advisory: { label: string; url: string } | null;
  workaround: { text: string; source: string; url: string } | null;
  steps: string[];
}

export interface ConnectedRow {
  mac: string;
  vendor: string;
  port: string;
  vlan: number | null;
  first_seen: string;
  uplink: boolean;
  device: { id: string; name: string; ip: string } | null;
  endpoint: boolean;
  unmanaged: boolean;
}

export interface NetDeviceDetail extends NetDeviceRow {
  sys_descr: string;
  sys_object_id: string;
  sys_location: string;
  sys_contact: string;
  uptime_s: number | null;
  serial: string;
  family: string;
  default_community: string | null;
  alive_via: string[];
  cpe: { product: string; version: string; update: string } | null;
  interfaces: { index: number; name: string; descr: string; mac: string; oper_up: boolean; speed_mbps: number | null }[];
  interfaces_up: number;
  interfaces_down: number;
  vulnerabilities: {
    id: string;
    cve_id: string;
    severity: string;
    cvss: number;
    kev: boolean;
    epss: number | null;
    package: string;
    version: string;
    fixed_version: string | null;
    title: string;
    risk_score: number;
    first_seen: string;
  }[];
  fixes: NetFix[];
  vuln_status: { checked: boolean; reason: string | null; at?: string | null; pending?: boolean; error?: string | null };
  finding_list: { id: string; rule_id: string; severity: string; title: string; first_seen: string; description: string }[];
  connected: { total: number; unmanaged: number; rows: ConnectedRow[] };
  events: { at: string; kind: string; detail: string }[];
  it_asset: { id: string; asset_tag: string; assignee_name: string; assignee_email: string; location: string; status: string; warranty_end: string | null; supplier: string; notes: string } | null;
  end_of_support: { date: string; source: string; url: string; reviewed: string } | null;
  endpoint: { id: string; hostname: string } | null;
  last_run: NetRun | null;
  collector_id: string | null;
}

export interface DeviceFilters {
  q?: string;
  type?: string;
  status?: string;
  subnet?: string;
  limit?: number;
}

const J = (body: unknown, method = "POST"): RequestInit => ({ method, body: JSON.stringify(body) });

export const networkApi = {
  scans: () => request<NetScan[]>("/api/network/scans"),
  scan: (id: string) => request<NetScan>(`/api/network/scans/${id}`),
  createScan: (b: ScanIn) => request<NetScan & { run: NetRun | null; run_error?: string }>("/api/network/scans", J(b)),
  editScan: (id: string, b: Partial<ScanIn> & { enabled?: boolean }) => request<NetScan>(`/api/network/scans/${id}`, J(b, "PATCH")),
  deleteScan: (id: string) => request<void>(`/api/network/scans/${id}`, { method: "DELETE" }),
  runScan: (id: string) => request<NetRun>(`/api/network/scans/${id}/run`, { method: "POST" }),
  scanRuns: (id: string) => request<NetRun[]>(`/api/network/scans/${id}/runs`),
  run: (id: string) => request<NetRun>(`/api/network/runs/${id}`),
  credentials: () => request<NetCredential[]>("/api/network/credentials"),
  createCredential: (b: CredentialIn) => request<NetCredential>("/api/network/credentials", J(b)),
  deleteCredential: (id: string) => request<void>(`/api/network/credentials/${id}`, { method: "DELETE" }),
  suggestions: (collector_id: string) => request<SuggestionSet[]>(`/api/network/suggestions${qs({ collector_id })}`),
  refreshSuggestions: (collector_id: string) => request<{ command_id: string }>("/api/network/suggestions/refresh", J({ collector_id })),
  test: (b: { collector_id: string; address: string; credential_ids: string[]; port_check: boolean }) => request<NetRun>("/api/network/test", J(b)),
  summary: () => request<NetSummary>("/api/network/summary"),
  devices: (f: DeviceFilters = {}) => request<NetDeviceRow[]>(`/api/network/devices${qs({ ...f })}`),
  device: (id: string) => request<NetDeviceDetail>(`/api/network/devices/${id}`),
  rescan: (id: string) => request<NetRun>(`/api/network/devices/${id}/rescan`, { method: "POST" }),
  devicePdf: (id: string) => getFile(`/api/network/devices/${id}/report.pdf`),
  exportUrl: (f: DeviceFilters = {}) => `${BASE}/api/network/devices/export.csv${qs({ q: f.q, type: f.type, status: f.status, subnet: f.subnet })}`,
  addToAssets: (ids: string[]) =>
    request<{ created: { id: string; it_asset_id: string; asset_tag: string }[]; skipped: { id: string; reason: string }[] }>("/api/network/devices/add-to-it-assets", J({ device_ids: ids })),
};
