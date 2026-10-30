// Typed client for /api/it-assets (IT asset lifecycle).
import { ApiError, qs, request } from "./api";

export type AssetStatus =
  | "in_stock"
  | "assigned"
  | "in_repair"
  | "retrieval_pending"
  | "retrieved"
  | "lost"
  | "stolen"
  | "disposed";

export interface ItAsset {
  id: string;
  asset_tag: string;
  serial_number: string;
  asset_type: string;
  manufacturer: string;
  model: string;
  status: AssetStatus;
  source: "manual" | "agent" | "import";
  device_id: string | null;
  device_hostname: string | null;
  /** Main name: the computer name for agent devices, else the asset tag. */
  display_name: string;
  device_last_seen_at: string | null;
  idle: boolean;
  assignee_name: string;
  assignee_email: string;
  assignee_department: string;
  assigned_at: string | null;
  location: string;
  purchase_date: string | null;
  supplier: string;
  purchase_cost: number | null;
  currency: string;
  warranty_end: string | null;
  warranty_expiring: boolean;
  refresh_date: string | null;
  notes: string;
  custom_fields: Record<string, string>;
  retrieval_due: string | null;
  retrieval_overdue: boolean;
  offboarding_id: string | null;
  disposal_method: string | null;
  disposal_date: string | null;
  disposal_vendor: string | null;
  disposal_notes: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface AssetBrief {
  id: string;
  asset_tag: string;
  display_name: string;
  asset_type: string;
  model: string;
  assignee_name: string;
  assignee_email: string;
  warranty_end: string | null;
  retrieval_due: string | null;
  device_hostname: string | null;
  device_last_seen_at: string | null;
}

export interface AssetSummary {
  total: number;
  active: number;
  by_status: Record<AssetStatus, number>;
  by_type: Record<string, number>;
  with_agent: number;
  value_by_currency: Record<string, number>;
  default_currency: string;
  warranty_warning_days: number;
  idle_days: number;
  warranty_expiring: number;
  warranty_expiring_assets: AssetBrief[];
  retrieval_overdue: number;
  retrieval_overdue_assets: AssetBrief[];
  idle: number;
  idle_assets: AssetBrief[];
  refresh_due_90d: number;
}

export interface AssetEvent {
  id: number;
  at: string;
  actor_email: string | null;
  event_type: string;
  from_status: string | null;
  to_status: string | null;
  from_assignee: string | null;
  to_assignee: string | null;
  notes: string;
  detail: Record<string, unknown>;
}

export interface Certificate {
  id: string;
  filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  uploaded_by: string | null;
  uploaded_at: string;
}

export interface Offboarding {
  id: string;
  person_email: string;
  person_username: string;
  person_name: string;
  department: string;
  leave_date: string;
  retrieval_due: string;
  status: "open" | "completed" | "cancelled";
  notes: string;
  created_by: string | null;
  created_at: string;
  closed_at: string | null;
  assets_total: number;
  assets_outstanding: number;
  overdue: boolean;
  assets?: ItAsset[];
}

export interface AssetSettings {
  default_currency: string;
  locations: string[];
  custom_fields: { key: string; label: string }[];
  idle_days: number;
  warranty_warning_days: number;
  retrieval_due_days: number;
  certificate_max_bytes: number;
  import_max_bytes: number;
  import_max_rows: number;
  statuses: AssetStatus[];
  types: string[];
  disposal_methods: string[];
  certificate_types: string[];
}

export interface ImportResult {
  rows: number;
  created: number;
  updated: number;
  unchanged: number;
  errors: { row: number; asset_tag: string; error: string }[];
  dry_run: boolean;
  message?: string;
}

export type AssetInput = Partial<
  Pick<
    ItAsset,
    | "asset_tag"
    | "serial_number"
    | "asset_type"
    | "manufacturer"
    | "model"
    | "location"
    | "purchase_date"
    | "supplier"
    | "currency"
    | "warranty_end"
    | "refresh_date"
    | "notes"
    | "custom_fields"
    | "assignee_department"
    | "assignee_name"
    | "assignee_email"
    | "status"
  >
> & { purchase_cost?: string | number | null; device_id?: string | null; note?: string };

export type AssetFilters = Record<string, string | undefined>;

const BASE = import.meta.env.VITE_API_BASE ?? "";
const json = (body: unknown) => JSON.stringify(body);

/** Import: a 422 carries the per-row errors in `detail`; return them instead of throwing. */
async function importCsv(file: File, dryRun: boolean): Promise<ImportResult> {
  try {
    return await request<ImportResult>(`/api/it-assets/import${qs({ dry_run: dryRun })}`, {
      method: "POST",
      body: file,
      headers: { "Content-Type": "text/csv" },
    });
  } catch (e) {
    if (e instanceof ApiError && e.status === 422) {
      try {
        const detail = JSON.parse(e.message) as ImportResult;
        if (Array.isArray(detail.errors)) return detail;
      } catch {
        /* not a row-level error */
      }
    }
    throw e;
  }
}

export const assetsApi = {
  list: (f: AssetFilters = {}) => request<ItAsset[]>(`/api/it-assets${qs(f)}`),
  summary: () => request<AssetSummary>("/api/it-assets/summary"),
  get: (id: string) => request<ItAsset>(`/api/it-assets/${id}`),
  byDevice: (deviceId: string) => request<ItAsset>(`/api/it-assets/by-device/${deviceId}`, { skipAuthHandling: true }),
  events: (id: string) => request<AssetEvent[]>(`/api/it-assets/${id}/events`),
  create: (body: AssetInput) => request<ItAsset>("/api/it-assets", { method: "POST", body: json(body) }),
  update: (id: string, body: AssetInput) => request<ItAsset>(`/api/it-assets/${id}`, { method: "PATCH", body: json(body) }),
  remove: (id: string, reason: string) => request<void>(`/api/it-assets/${id}${qs({ reason })}`, { method: "DELETE" }),
  assign: (id: string, body: { assignee_name: string; assignee_email: string; assignee_department: string; notes: string }) =>
    request<ItAsset>(`/api/it-assets/${id}/assign`, { method: "POST", body: json(body) }),
  returnAsset: (id: string, body: { notes: string; status?: string; location?: string }) =>
    request<ItAsset>(`/api/it-assets/${id}/return`, { method: "POST", body: json(body) }),
  setStatus: (id: string, body: { status: string; notes: string; retrieval_due?: string }) =>
    request<ItAsset>(`/api/it-assets/${id}/status`, { method: "POST", body: json(body) }),
  dispose: (id: string, body: { method: string; disposal_date: string; vendor: string; notes: string }) =>
    request<ItAsset>(`/api/it-assets/${id}/dispose`, { method: "POST", body: json(body) }),
  certificates: (id: string) => request<Certificate[]>(`/api/it-assets/${id}/certificates`),
  uploadCertificate: (id: string, file: File) =>
    request<Certificate>(`/api/it-assets/certificates/${id}${qs({ filename: file.name })}`, {
      method: "POST",
      body: file,
      headers: { "Content-Type": file.type || "application/octet-stream" },
    }),
  certificateUrl: (id: string, certId: string) => `${BASE}/api/it-assets/${id}/certificates/${certId}`,
  deleteCertificate: (id: string, certId: string, reason: string) =>
    request<void>(`/api/it-assets/${id}/certificates/${certId}${qs({ reason })}`, { method: "DELETE" }),
  exportUrl: (f: AssetFilters = {}) => `${BASE}/api/it-assets/export.csv${qs(f)}`,
  importCsv,
  offboardings: (status?: string) => request<Offboarding[]>(`/api/it-assets/offboardings${qs({ status })}`),
  offboarding: (id: string) => request<Offboarding>(`/api/it-assets/offboardings/${id}`),
  createOffboarding: (body: { person_email: string; person_username: string; person_name: string; department: string; leave_date: string; retrieval_due?: string; notes: string }) =>
    request<Offboarding>("/api/it-assets/offboardings", { method: "POST", body: json(body) }),
  cancelOffboarding: (id: string, notes: string) =>
    request<Offboarding>(`/api/it-assets/offboardings/${id}/cancel`, { method: "POST", body: json({ notes }) }),
  settings: () => request<AssetSettings>("/api/it-assets/settings"),
  saveSettings: (body: Partial<Omit<AssetSettings, "statuses" | "types" | "disposal_methods" | "certificate_types">>) =>
    request<AssetSettings>("/api/it-assets/settings", { method: "PUT", body: json(body) }),
};
