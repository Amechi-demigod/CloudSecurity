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
  // Linux servers (agent 1.7.0+)
  security_updates: "Security updates pending",
  reboot_required: "Reboot required",
  auto_updates: "Automatic security updates",
  ssh_root_login: "SSH root login",
  ssh_password_login: "SSH password login",
  admin_accounts: "Admin accounts",
  endpoint_protection: "Endpoint protection",
  mandatory_access_control: "SELinux / AppArmor",
  audit_logging: "Audit logging",
  time_sync: "Time sync",
  listening_ports: "Listening ports",
  package_inventory: "Package inventory",
};

/** Command types a Linux server agent runs; everything else is hidden (the agent refuses it too). */
export const LINUX_COMMANDS = ["recheck_posture", "collect_logs", "restart_agent", "update_check_in_interval", "check_for_update"];

/** The OS line of a device: Linux shows the distribution (Ubuntu 22.04.5 LTS), others the OS family and version. */
export function osLine(d: { os_family: string; os_name: string; os_version: string }): { main: string; sub: string } {
  if (d.os_family === "linux") return { main: d.os_name || "Linux", sub: "Linux server" };
  return { main: OS_LABEL[d.os_family] ?? d.os_family, sub: d.os_version };
}

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
