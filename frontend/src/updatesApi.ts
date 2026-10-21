// Typed client for agent update automation: update mode, automatic rollout,
// GitHub Releases auto-import, and "update now" (docs/AGENT_UPDATES.md).
import { request } from "./api";

export type UpdateMode = "automatic" | "manual";

export interface UpdateAutomation {
  mode: UpdateMode;
  soak_hours: number;
  rollout: {
    release_id: string | null;
    version: string | null;
    stage: "pilot" | "all" | "paused" | null;
    stage_at: string | null;
    promote_at: string | null;
    paused_reason: string | null;
    pilot_ring: string | null;
    pilot_devices: number;
  };
  auto_import: {
    enabled: boolean;
    enabled_default: boolean;
    repo: string;
    interval_minutes: number;
    checked_at: string | null;
    status: "ok" | "offline" | "error" | null;
    message: string | null;
    failed_version: string | null;
    api: string;
  };
  jitter_seconds: number;
  updated_at: string | null;
  updated_by: string;
  tick?: { action: string; detail: string };
}

export interface UpdateAutomationPatch {
  mode?: UpdateMode;
  soak_hours?: number;
  auto_import_enabled?: boolean;
  auto_import_repo?: string;
  auto_import_interval_minutes?: number;
  reason?: string;
}

/** What happens next for a device (instead of a bare "—"). */
export interface PendingUpdate {
  state: "none" | "no_target" | "up_to_date" | "updating" | "blocked" | "update_now_requested" | "offered" | "waiting_checkin";
  message: string;
  offered_at: string | null;
  starts_by: string | null;
  next_checkin_by: string | null;
  check_in_interval_seconds: number;
  update_now_requested_at: string | null;
  update_now_supported: boolean;
  can_update_now: boolean;
}

export interface UpdateNowResult {
  queued: { device_id: string; hostname: string; command: string; command_id: string; target_version: string | null; delay_seconds: number }[];
  skipped: { device_id: string; hostname: string; reason: string }[];
}

export const updatesApi = {
  automation: () => request<UpdateAutomation>("/api/updates/automation"),
  setAutomation: (body: UpdateAutomationPatch) =>
    request<UpdateAutomation>("/api/updates/automation", { method: "PUT", body: JSON.stringify(body) }),
  promote: (reason: string) =>
    request<UpdateAutomation>("/api/updates/automation/promote", { method: "POST", body: JSON.stringify({ reason }) }),
  checkGithub: () =>
    request<{ status: string; message: string; imported: string | null; automation: UpdateAutomation }>("/api/updates/automation/check-github", {
      method: "POST",
    }),
  updateNow: (target: { device_id: string } | { ring_id: string } | { all: true }, reason?: string) =>
    request<UpdateNowResult>("/api/updates/update-now", { method: "POST", body: JSON.stringify({ ...target, ...(reason ? { reason } : {}) }) }),
};

/** "in 3m", "in 45s", "overdue" for an ISO time in the future. */
export function fmtIn(iso: string | null): string {
  if (!iso) return "";
  const s = Math.round((new Date(iso).getTime() - Date.now()) / 1000);
  if (s <= 0) return "any moment now";
  if (s < 90) return `within ${s}s`;
  if (s < 5400) return `within ${Math.ceil(s / 60)} min`;
  return `within ${Math.round(s / 3600)} h`;
}

export function summarizeUpdateNow(r: UpdateNowResult): string {
  const n = r.queued.length;
  const skipped = r.skipped.length ? ` ${r.skipped.length} skipped (up to date or not eligible).` : "";
  if (!n) return `No device has a pending update.${skipped}`;
  return `${n} device(s) will check in at their next command poll (about a minute) and start updating right away.${skipped}`;
}
