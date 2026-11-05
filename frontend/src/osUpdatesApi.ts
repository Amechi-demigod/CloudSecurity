// Typed client for missing OS updates: the read-only Windows Update report per
// device, "Check for updates now" and the CSV export (docs/PATCHING.md).
import { BASE, qs, request } from "./api";

export type UpdateClassification =
  | "security"
  | "critical"
  | "definition"
  | "feature_pack"
  | "service_pack"
  | "tool"
  | "update_rollup"
  | "update"
  | "driver"
  | "upgrade"
  | "other";

export type UpdateSource = "wsus" | "wufb" | "microsoft_update" | "windows_update" | "unknown";

export interface MissingUpdate {
  update_id: string;
  kb_ids: string[];
  title: string;
  classification: UpdateClassification;
  msrc_severity: "Critical" | "Important" | "Moderate" | "Low" | "Unspecified" | "";
  release_date: string | null;
  age_days: number | null;
  cve_ids: string[];
  /** CVEs that also appear in the vulnerability views of this organisation */
  known_cves: string[];
  reboot_behavior: "never" | "always" | "can_request" | "";
  size_bytes: number | null;
  downloaded: boolean;
  security: boolean;
}

export interface OsUpdateReport {
  reported_at: string;
  scanned_at: string | null;
  scan_status: "ok" | "failed";
  scan_error: string;
  scan_trigger: "schedule" | "command";
  scan_duration_seconds: number | null;
  last_success_at: string | null;
  last_install_success_at: string | null;
  /** when the search behind the update list ran; null = no search succeeded yet (list unknown) */
  listed_at: string | null;
  source: UpdateSource;
  source_detail: string;
  service_state: string;
  service_start_type: string;
  reboot_pending: boolean;
  reboot_pending_since: string | null;
  missing_count: number;
  security_count: number;
  critical_count: number;
  oldest_security_days: number | null;
  updates: MissingUpdate[];
}

export interface DeviceOsUpdates {
  supported: boolean;
  unsupported_reason: string | null;
  agent_update_required: boolean;
  min_agent_version: string;
  thresholds: { critical_days: number; security_days: number; reboot_days: number; scan_stale_days: number };
  pending_scan: { command_id: string; status: "pending" | "delivered"; requested_at: string; requested_by: string | null } | null;
  issues: { code: string; detail: string }[];
  report: OsUpdateReport | null;
}

/** Compact figures on each row of the Devices list (null: no report). */
export interface OsUpdatesSummary {
  /** false: no search succeeded yet, the counts are unknown */
  listed: boolean;
  missing: number;
  security: number;
  critical: number;
  oldest_security_days: number | null;
  reboot_pending: boolean;
  scan_status: "ok" | "failed";
  scanned_at: string | null;
  source: UpdateSource;
}

/** Endpoints dashboard tile. */
export interface OsUpdatesFleet {
  reporting: number;
  devices_missing_security: number;
  devices_missing_critical: number;
  devices_missing_any: number;
  oldest_security_days: number | null;
}

export const SOURCE_LABEL: Record<UpdateSource, string> = {
  wsus: "WSUS",
  wufb: "Windows Update for Business",
  microsoft_update: "Microsoft Update",
  windows_update: "Windows Update",
  unknown: "Unknown",
};

export const CLASSIFICATION_LABEL: Record<UpdateClassification, string> = {
  security: "Security",
  critical: "Critical",
  definition: "Definition",
  feature_pack: "Feature pack",
  service_pack: "Service pack",
  tool: "Tool",
  update_rollup: "Update rollup",
  update: "Update",
  driver: "Driver",
  upgrade: "Upgrade",
  other: "Other",
};

export const catalogUrl = (kb: string) => `https://www.catalog.update.microsoft.com/Search.aspx?q=${encodeURIComponent(kb)}`;

export const osUpdatesApi = {
  device: (id: string) => request<DeviceOsUpdates>(`/api/devices/${id}/os-updates`),
  scan: (id: string, reason?: string) =>
    request<{ command_id: string; status: string; requested_at: string }>(`/api/devices/${id}/os-updates/scan`, {
      method: "POST",
      body: JSON.stringify(reason ? { reason } : {}),
    }),
  exportUrl: (f: { scope?: "security" | "all"; device_id?: string } = {}) => `${BASE}/api/os-updates/export.csv${qs(f)}`,
};
