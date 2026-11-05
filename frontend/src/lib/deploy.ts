// Deploy agent (IT assets -> Discovery): shared texts and helpers (docs/DIRECTORY_DISCOVERY.md#deploying-the-agent).
// Install facts (service CNAPPAgent, %ProgramFiles%\CNAPP Agent, pkg id com.cloudsecurity.cnapp-agent) come from
// endpoint-agent/packaging.
import { ISSUE_LABEL, type DeployRoute, type Deployment, type IssueType } from "../directoryApi";

export const MSI = "cnapp-agent-setup.msi";
export const PKG = "cnapp-agent-setup.pkg";
export const PKG_ID = "com.cloudsecurity.cnapp-agent";
export const INSTALL_DIR = "C:\\Program Files\\CNAPP Agent";

export const ROUTE_HINT: Record<DeployRoute, string> = {
  gpo: "On-prem Active Directory Windows computers: a computer startup script or GPO software installation, linked to their OUs.",
  intune: "Windows and macOS devices Intune manages: a Win32 app (.intunewin) or a macOS PKG app, assigned to a device group.",
  rmm: "Configuration Manager, Jamf or another RMM: a silent install command with a detection rule. Choose this for machines your tool manages.",
  manual: "Entra-only, Google-managed or unmanaged Windows and macOS machines: hand the installer to the user or IT, or run a one-line install.",
};

export const EXCLUDED_LABEL: Record<string, string> = {
  has_agent: "Already have an agent",
  mobile: "Phones, tablets, ChromeOS",
  no_agent_expected: "Personal / registered-only devices",
  disabled: "Disabled in the directory",
  linux: "Linux",
  unknown_os: "Unknown OS",
  gone: "No longer in a directory",
};

export const EXCLUDED_HINT: Record<string, string> = {
  has_agent: "These already report to the platform.",
  mobile: "The agent runs on Windows and macOS computers only. Phones, tablets and Chromebooks stay with their MDM (Intune, Google).",
  no_agent_expected: "Personal (BYOD) or registered-only devices: not counted in agent coverage, so no agent is expected.",
  disabled: "Re-enable the account first if the machine is still in use.",
  linux: "There is no Linux agent package yet.",
  unknown_os: "The directory does not say which OS the machine runs. Check it, then install by hand if it is Windows or macOS.",
  gone: "The machine is no longer in any directory.",
};

export function startupScript(domain: string): string {
  const share = `\\\\${domain || "corp.example.com"}\\NETLOGON\\cnapp\\${MSI}`;
  return [
    "# CNAPP agent: Group Policy computer startup script (runs as SYSTEM at boot).",
    "# Installs the pre-configured MSI once; does nothing when the agent is already installed.",
    "$ErrorActionPreference = 'Stop'",
    `$Msi = '${share}'   # the share you copied the installer to`,
    "if (Get-Service -Name 'CNAPPAgent' -ErrorAction SilentlyContinue) { exit 0 }",
    "$Log = Join-Path $env:WINDIR 'Temp\\cnapp-agent-install.log'",
    "$p = Start-Process -FilePath msiexec.exe -Wait -PassThru -ArgumentList @('/i', \"`\"$Msi`\"\", '/qn', '/norestart', '/l*v', \"`\"$Log`\"\")",
    "exit $p.ExitCode",
  ].join("\n");
}

export const DEP_STATE_TONE: Record<Deployment["state"], "good" | "default" | "warn"> = { active: "good", expired: "default", revoked: "warn" };

/** Label for a filter-based selection ("All “No agent” machines in corp.example.com"). */
export function filterLabel(type: string, q: string, domain: string): string {
  const what = type ? `All “${ISSUE_LABEL[type as IssueType] ?? type}” machines` : "All machines with a computer issue";
  return [what, domain && `in ${domain}`, q && `matching “${q}”`].filter(Boolean).join(" ");
}
