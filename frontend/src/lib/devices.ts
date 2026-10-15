/** Human labels for posture checks reported by the agent. */
export const CHECK_LABEL: Record<string, string> = {
  disk_encryption: "Disk encryption",
  firewall: "Firewall",
  antivirus: "Antivirus / EDR",
  os_updates: "OS updates",
  screen_lock: "Screen lock",
  sip: "System Integrity Protection",
  gatekeeper: "Gatekeeper",
  secure_boot: "Secure Boot",
  tpm: "TPM",
  local_admins: "Local administrators",
};

export const OS_LABEL: Record<string, string> = { windows: "Windows", macos: "macOS", linux: "Linux" };

export function fmtBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

export function fmtDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`;
}
