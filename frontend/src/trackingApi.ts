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
  auto_lost_mode_phone: string | null;
  auto_lost_mode_email: string | null;
  updated_by: string | null;
  updated_at: string;
  retention_days: number;
  tile_url: string;
  database_available: boolean;
}

export type TrackingSettingsPatch = Partial<
  Pick<
    TrackingSettings,
    | "enabled" | "timezone" | "allowed_countries" | "alert_outside_countries" | "alert_not_seen_days" | "alert_after_hours"
    | "after_hours_start" | "after_hours_end" | "after_hours_weekdays" | "alert_hardware_changed" | "alert_agent_stopped"
    | "auto_lost_mode_outside_countries" | "auto_lost_mode_phone" | "auto_lost_mode_email"
  >
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
  alert?: undefined;
}

export type AlertKind = "outside_countries" | "not_seen" | "after_hours" | "hardware_changed" | "agent_stopped" | "auto_lost_mode";

/** An alert shown in the history (city and country only, for every role). */
export interface AlertEvent {
  kind: AlertKind;
  alert: true;
  at: string;
  title: string;
  severity: string;
  city: string | null;
  country: string | null;
  country_code: string | null;
}

export interface FleetCity {
  city: string | null;
  country: string | null;
  country_code: string | null;
  count: number;
  flagged: boolean;
  device_ids: string[];
  // analysts and admins only
  latitude?: number;
  longitude?: number;
}

export interface FleetDevice {
  id: string;
  hostname: string;
  group: string | null;
  network: "office" | "away" | "private" | "unlocated";
  office: string | null;
  city: string | null;
  country: string | null;
  country_code: string | null;
  last_seen_at: string | null;
  status: "active" | "stale" | "inactive";
  outside_countries: boolean;
  not_seen: boolean;
  lost_mode: boolean;
}

export interface Fleet {
  enabled: boolean;
  detail: "full" | "basic";
  tile_url: string;
  database_available: boolean;
  not_seen_days: number;
  timezone: string;
  tiles: { at_office: number; away: number; outside_countries: number; missing: number; unlocated: number };
  groups: string[];
  cities: FleetCity[];
  devices: FleetDevice[];
  truncated: boolean;
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
  history: (LocationEvent | AlertEvent)[];
}

export type AlertGroup = "outside_countries" | "not_seen" | "hardware" | "locked";

export interface RecentAlert {
  id: string;
  kind: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  detail_line: string;
  at: string;
  device_id: string;
  hostname: string;
  city: string | null;
  country: string | null;
  country_code: string | null;
}

export interface RecentAlerts {
  enabled: boolean;
  detail: "full" | "basic";
  days: number;
  group: string | null;
  count_24h: number;
  total: number;
  notified: boolean;
  items: RecentAlert[];
}

export const trackingApi = {
  settings: () => request<TrackingSettings>("/api/device-tracking/settings"),
  saveSettings: (body: TrackingSettingsPatch) =>
    request<TrackingSettings>("/api/device-tracking/settings", { method: "PUT", body: JSON.stringify(body) }),
  fleet: (f: { group?: string; status?: string; notSeen?: boolean } = {}) => {
    const q = new URLSearchParams();
    if (f.group) q.set("group", f.group);
    if (f.status) q.set("status", f.status);
    if (f.notSeen) q.set("not_seen", "true");
    const qs = q.toString();
    return request<Fleet>(`/api/device-tracking/fleet${qs ? `?${qs}` : ""}`);
  },
  recentAlerts: (f: { group?: AlertGroup | ""; limit?: number; days?: number } = {}) => {
    const q = new URLSearchParams();
    if (f.group) q.set("group", f.group);
    if (f.limit) q.set("limit", String(f.limit));
    if (f.days) q.set("days", String(f.days));
    const qs = q.toString();
    return request<RecentAlerts>(`/api/device-tracking/alerts${qs ? `?${qs}` : ""}`);
  },
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
