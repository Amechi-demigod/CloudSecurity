// Typed client for device tracking (backend app/tracking, docs/DEVICE_TRACKING.md).
import { request } from "./api";

export interface TrackingSettings {
  enabled: boolean;
  timezone: string;
  allowed_countries: string[];
  alert_outside_countries: boolean;
  alert_not_seen_days: number | null;
  alert_after_hours: boolean;
  after_hours_start: string;
  after_hours_end: string;
  after_hours_weekdays: number[];
  alert_hardware_changed: boolean;
  alert_agent_stopped: boolean;
  auto_lost_mode_outside_countries: boolean;
  updated_by: string | null;
  updated_at: string;
  retention_days: number;
  tile_url: string;
  database_available: boolean;
}

export type TrackingSettingsPatch = Partial<
  Pick<TrackingSettings, "enabled" | "timezone" | "allowed_countries">
>;

export interface TrackingOffice {
  id: string;
  name: string;
  networks: string[];
  timezone: string | null;
  devices_now: number;
  created_at: string;
  updated_at: string;
}

export interface OfficeInput {
  name: string;
  networks: string[];
  timezone?: string | null;
}

export interface Country {
  code: string;
  name: string;
}

export interface LocationView {
  first_seen_at: string;
  last_seen_at: string;
  city: string | null;
  country: string | null;
  country_code: string | null;
  is_private: boolean;
  network: "office" | "away" | "private";
  office: string | null;
  // analysts and admins only
  region?: string | null;
  ip?: string;
  latitude?: number | null;
  longitude?: number | null;
  accuracy_km?: number | null;
  asn?: number | null;
  provider?: string | null;
}

export interface LocationEvent extends LocationView {
  kind: "arrived" | "away" | "new_country" | "private";
  at: string;
}

export interface DeviceLocation {
  enabled: boolean;
  eligible: boolean;
  detail: "full" | "basic";
  timezone: string;
  tile_url: string;
  retention_days: number;
  days: number;
  database_available: boolean;
  current: (LocationView & { timezone: string; available: boolean }) | null;
  history: LocationEvent[];
}

export const trackingApi = {
  settings: () => request<TrackingSettings>("/api/device-tracking/settings"),
  saveSettings: (body: TrackingSettingsPatch) =>
    request<TrackingSettings>("/api/device-tracking/settings", { method: "PUT", body: JSON.stringify(body) }),
  countries: () => request<Country[]>("/api/device-tracking/countries"),
  offices: () => request<TrackingOffice[]>("/api/device-tracking/offices"),
  createOffice: (body: OfficeInput) =>
    request<TrackingOffice>("/api/device-tracking/offices", { method: "POST", body: JSON.stringify(body) }),
  updateOffice: (id: string, body: Partial<OfficeInput> & { clear_timezone?: boolean }) =>
    request<TrackingOffice>(`/api/device-tracking/offices/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteOffice: (id: string) => request<void>(`/api/device-tracking/offices/${id}`, { method: "DELETE" }),
  location: (deviceId: string, days = 7) => request<DeviceLocation>(`/api/devices/${deviceId}/location?days=${days}`),
  locateNow: (deviceId: string) =>
    request<{ command_id: string; status: string }>(`/api/devices/${deviceId}/location/refresh`, { method: "POST" }),
};

/** Format a time in a given IANA time zone ("Mon 14:05"), falling back to the browser's zone. */
export function fmtInZone(iso: string, timeZone: string): string {
  try {
    return new Intl.DateTimeFormat(undefined, {
      timeZone, weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit",
    }).format(new Date(iso));
  } catch {
    return new Date(iso).toLocaleString();
  }
}

/** All time zones the browser knows (UTC first). */
export function timeZones(): string[] {
  const fn = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf;
  const all = fn ? fn("timeZone") : [];
  return ["UTC", ...all.filter((z) => z !== "UTC")];
}
