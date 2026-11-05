// Typed client for the built-in endpoint actions: services inventory, service
// stop / start / disable / restore, uninstall, USB storage block, bulk actions
// (docs/DEVICE_MANAGEMENT.md#endpoint-actions).
import { qs, request, type DeviceCommand } from "./api";

export type ServiceAction = "stop" | "start" | "disable" | "restore";
export type StartType = "boot" | "system" | "auto" | "auto_delayed" | "manual" | "disabled" | "other";

export interface DeviceServiceRow {
  name: string;
  display_name: string;
  status: "running" | "stopped" | "start_pending" | "stop_pending" | "paused" | "other";
  start_type: StartType;
}

export interface EndpointActionsInfo {
  supported: boolean;
  unsupported_reason: string | null;
  agent_update_required: boolean;
  min_agent_version: string;
  usb_storage: {
    state: "blocked" | "allowed" | null;
    detail: string;
    blocked_by_agent: boolean;
    blocked_since: string | null;
    usbstor_start: number | null;
    deny_read: boolean | null;
    deny_all: boolean | null;
  };
  protected_services: string[];
  services_reported: number;
}

export interface BulkResult {
  queued: number;
  skipped: number;
  results: { device_id: string; hostname: string | null; status: "queued" | "skipped"; detail?: string; command_id?: string }[];
}

export const START_TYPE_LABEL: Record<string, string> = {
  boot: "Boot",
  system: "System",
  auto: "Automatic",
  auto_delayed: "Automatic (delayed start)",
  manual: "Manual",
  disabled: "Disabled",
  other: "Other",
};

export const ENDPOINT_ACTION_TYPES = ["manage_service", "uninstall_software", "block_usb_storage", "unblock_usb_storage"] as const;

export const endpointActionsApi = {
  services: (id: string, q?: string) => request<DeviceServiceRow[]>(`/api/devices/${id}/services${qs({ q })}`),
  bulk: (body: { device_ids: string[]; type: "block_usb_storage" | "unblock_usb_storage" | "manage_service"; params?: Record<string, unknown>; reason: string }) =>
    request<BulkResult>("/api/devices/bulk-commands", { method: "POST", body: JSON.stringify(body) }),
};

/** Human label of an endpoint-action command (command history, inline status). */
export function endpointActionLabel(c: DeviceCommand): string | null {
  const p = c.params as Record<string, string | undefined>;
  switch (c.type) {
    case "manage_service": {
      const verb = { stop: "Stop service", start: "Start service", disable: "Disable service", restore: "Restore startup type" }[p.action ?? ""] ?? "Service";
      return `${verb} ${p.service ?? ""}`.trim();
    }
    case "uninstall_software":
      return `Uninstall ${p.name ?? ""} ${p.version ?? ""}`.trim();
    case "block_usb_storage":
      return "Block USB storage";
    case "unblock_usb_storage":
      return "Unblock USB storage";
  }
  return null;
}
