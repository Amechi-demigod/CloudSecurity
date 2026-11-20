/** Plain-word labels for raw statuses shown as tags. One place, so every page says the same thing. */
const STATUS: Record<string, string> = {
  open: "Open",
  suppressed: "Snoozed",
  resolved: "Fixed",
  closed: "Closed",
  acknowledged: "Acknowledged",
  investigating: "Investigating",
  succeeded: "Done",
  success: "Done",
  completed: "Done",
  done: "Done",
  failed: "Failed",
  error: "Failed",
  queued: "Waiting",
  pending: "Waiting",
  running: "Running",
  in_progress: "Running",
  approved: "Approved",
  denied: "Declined",
  rejected: "Declined",
  expired: "Expired",
  cancelled: "Cancelled",
  canceled: "Cancelled",
  revoked: "Removed",
  active: "Active",
  disabled: "Off",
  enabled: "On",
  sent: "Sent",
  delivered: "Delivered",
  dead_lettered: "Couldn't be delivered",
  dead: "Couldn't be delivered",
  retrying: "Trying again",
  skipped: "Skipped",
  stale: "Not checking in",
  online: "Online",
  offline: "Offline",
};

/** "dead_lettered" -> "Couldn't be delivered"; unknown values are tidied ("some_thing" -> "Some thing"). */
export function statusLabel(status: string | null | undefined): string {
  if (!status) return "";
  const key = status.toLowerCase();
  if (STATUS[key]) return STATUS[key];
  const t = status.replace(/_/g, " ");
  return t.charAt(0).toUpperCase() + t.slice(1);
}
