// Typed client for missing-device mode (backend app/tracking/missing_api.py, docs/DEVICE_TRACKING.md).
import { getFile, request } from "./api";

export interface MissingSighting {
  /** When the sighting started (clipped to the moment the device was marked missing). */
  when: string;
  last_seen_at: string;
  city: string | null;
  country: string | null;
  country_code: string | null;
  is_private: boolean;
  office: string | null;
  timezone: string;
  signed_in: string | null;
  // analysts and admins only
  ip?: string;
  provider?: string | null;
  region?: string | null;
}

export interface MissingLastSeen {
  when: string;
  city: string | null;
  country: string | null;
  is_private: boolean;
  office: string | null;
  timezone: string;
  provider?: string | null;
  ip?: string;
  region?: string | null;
}

export interface MissingView {
  missing: boolean;
  since: string | null;
  by: string | null;
  reason: string | null;
  recovered_at: string | null;
  recovered_by: string | null;
  check_in_seconds: number | null;
  previous_check_in_seconds: number | null;
  eligible: boolean;
  tracking_enabled: boolean;
  detail: "full" | "basic";
  timezone: string;
  lost_mode: { status: "enabling" | "active" | "disabling" | null; message: string | null; phone: string | null };
  sightings: MissingSighting[];
  last_seen: MissingLastSeen | null;
  /** null = nothing to compare with; [] = no changes */
  hardware_changes: string[] | null;
}

export interface MarkMissingBody {
  reason: string;
  confirm_hostname: string;
  message?: string;
  phone?: string;
  email?: string;
}

export const missingApi = {
  get: (deviceId: string) => request<MissingView>(`/api/devices/${deviceId}/missing`),
  mark: (deviceId: string, body: MarkMissingBody) =>
    request<MissingView & { lost_mode_action: string }>(`/api/devices/${deviceId}/missing`, { method: "POST", body: JSON.stringify(body) }),
  recover: (deviceId: string, exitLostMode: boolean) =>
    request<MissingView & { lost_mode_action: string; interval_action: string }>(`/api/devices/${deviceId}/missing/recover`, {
      method: "POST",
      body: JSON.stringify({ exit_lost_mode: exitLostMode }),
    }),
  reportPdf: (deviceId: string) => getFile(`/api/devices/${deviceId}/missing/report.pdf`),
};
