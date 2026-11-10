// Typed client for vulnerability fix guidance: the CVE page, a device's fixes grouped by
// remediation and the PDF exports (docs/VULNERABILITIES.md#fixes-and-guidance). Read-only:
// nothing here changes a device.
import { BASE, request } from "./api";

export type FixSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface FixCommand {
  label: string;
  code: string;
}

export interface FixLink {
  label: string;
  url: string;
}

/** One way to apply a fix (a tab): Windows Update, Intune, WSUS / manual, winget, apt, vendor updater... */
export interface FixMethod {
  id: string;
  label: string;
  steps: string[];
  commands: FixCommand[];
  links?: FixLink[];
}

export type FixStateCode = "offered" | "restart_pending" | "failing" | "not_offered" | "unknown";

export interface FixState {
  code: FixStateCode;
  label: string;
  detail: string;
  offered_kb?: string | null;
}

export interface FixCve {
  cve_id: string;
  severity: FixSeverity;
  cvss: number;
  kev: boolean;
  title: string;
  fixed_version: string | null;
  first_seen: string | null;
}

export interface DeviceFix {
  id: string;
  kind: "windows_update" | "os_update" | "app_update";
  title: string;
  package: string;
  current_version: string;
  target_version: string | null;
  target: { kb?: string | null; build?: string | null; os?: string; version?: string | null; source?: string | null };
  restart_required: boolean | null;
  state: FixState;
  steps: string[];
  methods: FixMethod[];
  links: FixLink[];
  cves: FixCve[];
  cve_count: number;
  kev_count: number;
  max_severity: FixSeverity;
  max_cvss: number;
  top_cve: string;
  top_cve_kev: boolean;
  oldest_open_days: number;
  os_updates_tab: string | null;
  msrc_covered?: boolean;
  unmapped_cves?: number;
}

export interface MsrcStatus {
  enabled: boolean;
  has_data: boolean;
  updated_at: string | null;
  error: string | null;
}

export interface DeviceFixes {
  device: { id: string; hostname: string; os_family: string; os_name: string; os_version: string; os_build: string };
  summary: { fixes: number; open: number; kev: number; oldest_open_days: number | null };
  fixes: DeviceFix[];
  os_updates_tab: string | null;
  msrc: MsrcStatus;
  generated_at: string;
}

export interface WindowsFixRow {
  os: string;
  build: number;
  kb: string | null;
  fixed_build: string | null;
  restart: boolean | null;
  supersedes: string | null;
  source: string | null;
  devices: number;
  links: FixLink[];
}

export interface AppFix {
  package: string;
  current: string;
  fixed_version: string | null;
  devices: number;
  assets: number;
  methods: FixMethod[];
  advisory: string;
  title: string;
}

export interface CveAffectedDevice {
  device_id: string;
  hostname: string;
  device_group: string | null;
  os_name: string;
  os_version: string;
  current: string;
  package: string;
  needs: string;
  state: FixState | null;
  first_seen: string | null;
  risk_score: number;
  os_family: string;
}

export interface CveDetail {
  cve_id: string;
  title: string;
  description: string;
  severity: FixSeverity;
  cvss: number;
  cvss_label: string;
  vector: string | null;
  cwe: string[];
  kev: boolean;
  kev_info: { added?: string; due?: string; ransomware?: string; name?: string };
  epss: number | null;
  exploit: { kev: boolean; ransomware: boolean; msrc: string | null };
  published: string | null;
  products: string[];
  patch_available: boolean;
  fix_type: "windows_update" | "package_upgrade" | "os_update" | "mixed" | "none";
  fixed_in: string | null;
  affected: { open_devices: number; fleet_devices: number; fleet_label: string; assets: number; asset_names: string[]; network_devices: number; open_findings: number };
  first_seen: string | null;
  days_open: number | null;
  fix_due: { due_at: string; basis: string; overdue_days: number | null; days_left: number | null } | null;
  guidance: {
    windows: { table: WindowsFixRow[]; methods: FixMethod[]; msrc: boolean; degraded: boolean } | null;
    apps: AppFix[];
    fix_type: string;
    patch_available: boolean;
    mitigations: string[];
    workarounds: string[];
  };
  devices: CveAffectedDevice[];
  network_devices: { network_device_id: string; name: string; ip: string; device_type: string; vendor: string; model: string; firmware: string; fixed_version: string | null; needs: string }[];
  devices_total: number;
  progress: { total: number; patched: number; open: number; restart_pending: number; offered: number; failing: number; not_offered: number };
  compliance: { framework: string; control: string; title: string }[];
  business_impact: string[];
  references: FixLink[];
  timeline: { date: string; label: string }[];
  msrc: MsrcStatus;
  generated_at: string;
}

export const FIX_TYPE_LABEL: Record<CveDetail["fix_type"], string> = {
  windows_update: "Windows update",
  package_upgrade: "Package / app update",
  os_update: "OS update",
  mixed: "Windows and app updates",
  none: "No fix named yet",
};

export const vulnFixesApi = {
  cve: (id: string) => request<CveDetail>(`/api/vulnerabilities/${encodeURIComponent(id)}`),
  deviceFixes: (id: string) => request<DeviceFixes>(`/api/devices/${encodeURIComponent(id)}/vulnerability-fixes`),
  cveReportUrl: (id: string) => `${BASE}/api/vulnerabilities/${encodeURIComponent(id)}/report.pdf`,
  deviceReportUrl: (id: string) => `${BASE}/api/devices/${encodeURIComponent(id)}/vulnerability-fixes/report.pdf`,
};
