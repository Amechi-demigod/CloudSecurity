import type { AssetStatus } from "../assetsApi";

export const STATUS_LABEL: Record<AssetStatus, string> = {
  in_stock: "In stock",
  assigned: "Assigned",
  in_repair: "In repair",
  retrieval_pending: "Retrieval pending",
  retrieved: "Retrieved",
  lost: "Lost",
  stolen: "Stolen",
  disposed: "Disposed",
};

export const STATUS_ORDER: AssetStatus[] = ["in_stock", "assigned", "in_repair", "retrieval_pending", "retrieved", "lost", "stolen", "disposed"];

export const TYPE_LABEL: Record<string, string> = {
  laptop: "Laptop",
  desktop: "Desktop",
  computer: "Computer",
  monitor: "Monitor",
  phone: "Phone",
  tablet: "Tablet",
  dock: "Dock",
  peripheral: "Peripheral",
  headset: "Headset",
  printer: "Printer",
  network: "Network",
  server: "Server",
  other: "Other",
};

export const DISPOSAL_LABEL: Record<string, string> = {
  recycled: "Recycled",
  destroyed: "Destroyed",
  resold: "Resold",
  donated: "Donated",
  returned_to_vendor: "Returned to vendor",
  other: "Other",
};

export const EVENT_LABEL: Record<string, string> = {
  created: "Created",
  updated: "Edited",
  assigned: "Assigned",
  returned: "Returned",
  status_changed: "Status changed",
  offboarding: "Owner leaving: retrieval requested",
  offboarding_cancelled: "Offboarding cancelled",
  disposed: "Disposed",
  imported: "CSV import",
  device_linked: "Agent device linked",
  certificate_uploaded: "Certificate uploaded",
  certificate_deleted: "Certificate deleted",
};

/** Owner shown in lists: the name (for agent-set owners, the OS username), else the email. */
export function ownerLabel(a: { assignee_name: string; assignee_email: string }): string {
  return a.assignee_name || a.assignee_email;
}

/** True for agent devices: the computer name is the main name and the tag goes beneath it. */
export function namedByHost(a: { display_name: string; asset_tag: string }): boolean {
  return !!a.display_name && a.display_name !== a.asset_tag;
}

export function fmtMoney(value: number | null | undefined, currency: string): string {
  if (value === null || value === undefined) return "—";
  try {
    return new Intl.NumberFormat(undefined, { style: "currency", currency, maximumFractionDigits: 2 }).format(value);
  } catch {
    return `${currency} ${value.toLocaleString()}`;
  }
}

export const fmtDate = (d: string | null | undefined) => (d ? new Date(`${d.slice(0, 10)}T00:00:00`).toLocaleDateString() : "—");

/** Today as YYYY-MM-DD in local time (for date inputs). */
export function todayIso(): string {
  const d = new Date();
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 10);
}

export function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
