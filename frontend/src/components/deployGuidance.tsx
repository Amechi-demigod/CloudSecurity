// Deploy agent (IT assets -> Discovery): per-route admin steps and copyable scripts for rolling the agent out to
// directory machines that have none. The platform never writes to a directory or MDM: these are steps the admin
// follows in Group Policy Management, Intune, Configuration Manager / Jamf or by hand.
// Install facts (service CNAPPAgent, %ProgramFiles%\CNAPP Agent, pkg id com.cloudsecurity.cnapp-agent) come from
// endpoint-agent/packaging; see docs/DIRECTORY_DISCOVERY.md#deploying-the-agent.
import { Download } from "lucide-react";
import type { ReactNode } from "react";
import type { InstallerPlatform } from "../api";
import type { RouteFacts } from "../directoryApi";
import { INSTALL_DIR, MSI, PKG, PKG_ID, startupScript } from "../lib/deploy";
import { CodeBox } from "./directoryShared";
import { Button, Tag } from "./ui";

function Steps({ children }: { children: ReactNode }) {
  return <ol className="ml-5 list-decimal space-y-1.5 text-sm text-ink-2 marker:text-ink-3">{children}</ol>;
}

function H({ children }: { children: ReactNode }) {
  return <h4 className="mb-1.5 mt-4 text-xs font-semibold uppercase tracking-wide text-ink-3 first:mt-0">{children}</h4>;
}

function Path({ children }: { children: ReactNode }) {
  return <span className="font-medium text-ink">{children}</span>;
}

export interface GuidanceProps {
  facts: RouteFacts;
  names: string[];
  /** Download the deployment's installer (only once the deployment exists). */
  onDownload?: (platform: InstallerPlatform) => void;
  downloading?: InstallerPlatform | null;
  available?: Partial<Record<InstallerPlatform, boolean>>;
  serverUrl?: string | null;
  /** The command-line token, only right after creation (it is shown once). */
  token?: string | null;
}

function InstallerButtons({ facts, onDownload, downloading, available }: GuidanceProps) {
  const plats: InstallerPlatform[] = [];
  if (facts.platforms.windows) plats.push("windows-msi");
  if (facts.platforms.macos) plats.push("macos-pkg");
  if (!onDownload)
    return (
      <p className="text-xs text-ink-3">
        The installer download for this batch (its own enrollment token, capped to these machines and expiring with the deployment) is available once you
        create the deployment.
      </p>
    );
  return (
    <div className="flex flex-wrap items-center gap-2">
      {plats.map((p) => (
        <Button key={p} onClick={() => onDownload(p)} disabled={!!downloading || available?.[p] === false}>
          <Download aria-hidden className="mr-1 inline h-3.5 w-3.5" />
          {downloading === p ? "Building…" : p === "windows-msi" ? `Windows installer (${MSI})` : `macOS installer (${PKG})`}
        </Button>
      ))}
      {plats.some((p) => available?.[p] === false) && <Tag tone="warn">not bundled with this server</Tag>}
      <span className="text-xs text-ink-3">Each download mints a new package-bound token; keep the file like a password.</span>
    </div>
  );
}

function MachineNames({ names }: { names: string[] }) {
  if (names.length === 0) return null;
  return (
    <details className="mt-3">
      <summary className="cursor-pointer text-xs font-medium text-accent">Machine names ({names.length}) for a device group or collection</summary>
      <div className="mt-2">
        <CodeBox testId="deploy-names" text={names.join("\n")} />
      </div>
    </details>
  );
}

const WIN_DETECT = [
  "# Detection: the agent service exists (exit 0 + output = installed)",
  "if (Get-Service -Name 'CNAPPAgent' -ErrorAction SilentlyContinue) { Write-Output 'Installed'; exit 0 }",
  "exit 1",
].join("\n");

function Gpo(p: GuidanceProps) {
  const ous = p.facts.ous ?? [];
  const domain = ous[0]?.domain ?? "";
  return (
    <div>
      <H>1. Installer</H>
      <InstallerButtons {...p} />
      <p className="mt-2 text-sm text-ink-2">
        Copy <code>{MSI}</code> to a share every computer can read at boot (read access for <Path>Domain Computers</Path>), for example{" "}
        <code>\\{domain || "corp.example.com"}\NETLOGON\cnapp\</code> or a DFS share.
      </p>
      <H>2. OUs to target</H>
      {ous.length ? (
        <ul className="space-y-0.5 text-sm">
          {ous.map((o) => (
            <li key={`${o.domain}|${o.ou}`} className="flex items-baseline gap-2">
              <code className="break-all text-xs text-ink">{o.ou || `(domain root) ${o.domain}`}</code>
              <span className="text-xs text-ink-3">
                {o.count} computer{o.count === 1 ? "" : "s"}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-ink-3">No OU information.</p>
      )}
      <H>3a. Computer startup script (recommended)</H>
      <Steps>
        <li>
          Open <Path>Group Policy Management</Path> (gpmc.msc). For each OU above, right-click it → <Path>Create a GPO in this domain, and Link it here…</Path>{" "}
          (one GPO, e.g. &quot;CNAPP agent deployment&quot;, linked to every OU).
        </li>
        <li>
          Edit the GPO → <Path>Computer Configuration → Policies → Windows Settings → Scripts (Startup/Shutdown) → Startup</Path> →{" "}
          <Path>PowerShell Scripts</Path> tab → <Path>Show Files…</Path>, save the script below as <code>Install-CnappAgent.ps1</code> there, then <Path>Add</Path> it.
        </li>
        <li>
          Recommended: <Path>Computer Configuration → Policies → Administrative Templates → System → Logon → Always wait for the network at computer startup and logon</Path>{" "}
          = Enabled, so the share is reachable at boot.
        </li>
        <li>To pilot first, replace Authenticated Users under Security Filtering with a security group holding a few computers.</li>
        <li>
          Computers install the agent at their next restart (test one with <code>gpupdate /force</code> and a restart; check <code>Get-Service CNAPPAgent</code>).
        </li>
      </Steps>
      <div className="mt-3">
        <CodeBox testId="deploy-gpo-script" text={startupScript(domain)} note="Change $Msi to your share. The token is inside the MSI, not in the script." />
      </div>
      <H>3b. Or: GPO software installation</H>
      <Steps>
        <li>
          Edit the GPO → <Path>Computer Configuration → Policies → Software Settings → Software installation</Path> → right-click → <Path>New → Package…</Path>
        </li>
        <li>
          Pick the MSI through its <b>UNC path</b> (not a local drive), choose <Path>Assigned</Path>. It installs at the next restart, before sign-in.
        </li>
        <li>The agent updates itself afterwards (Devices → Agent updates); no need to re-assign new versions.</li>
      </Steps>
      <MachineNames names={p.names} />
    </div>
  );
}

function Intune(p: GuidanceProps) {
  const win = !!p.facts.platforms.windows;
  const mac = !!p.facts.platforms.macos;
  return (
    <div>
      <H>1. Installer</H>
      <InstallerButtons {...p} />
      {win && (
        <>
          <H>2. Windows: Win32 app</H>
          <Steps>
            <li>
              Put <code>{MSI}</code> alone in a folder (e.g. <code>C:\cnapp\src</code>) and package it with Microsoft&apos;s Win32 Content Prep Tool:
            </li>
          </Steps>
          <div className="mt-2">
            <CodeBox testId="deploy-intunewin" text={`IntuneWinAppUtil.exe -c C:\\cnapp\\src -s ${MSI} -o C:\\cnapp\\out -q`} note={`Produces C:\\cnapp\\out\\cnapp-agent-setup.intunewin.`} />
          </div>
          <Steps>
            <li>
              <Path>Intune admin center → Apps → Windows → Add → Windows app (Win32)</Path>, upload the <code>.intunewin</code>.
            </li>
            <li>
              Program: install command <code>msiexec /i &quot;{MSI}&quot; /qn /norestart</code>, uninstall command as filled in from the MSI, install behaviour{" "}
              <Path>System</Path>, device restart behaviour <Path>No specific action</Path>.
            </li>
            <li>Requirements: 64-bit Windows 10 or 11.</li>
            <li>
              Detection rule: <Path>Manually configure → File</Path>, path <code>{INSTALL_DIR}</code>, file <code>cnapp-agent.exe</code>, method <Path>File or folder exists</Path>,
              64-bit: Yes. (Or a custom script, below.)
            </li>
            <li>
              Assignments: <Path>Required</Path> → a device group holding these machines (names below).
            </li>
          </Steps>
          <div className="mt-3">
            <CodeBox testId="deploy-intune-detect" text={WIN_DETECT} />
          </div>
        </>
      )}
      {mac && (
        <>
          <H>{win ? "3" : "2"}. macOS: PKG app</H>
          <Steps>
            <li>
              <Path>Intune admin center → Apps → macOS → Add → macOS app (PKG)</Path>, upload <code>{PKG}</code> (use your signed build if you sign packages; see
              docs/DEVICE_MANAGEMENT.md).
            </li>
            <li>
              Detection: included app / bundle ID <code>{PKG_ID}</code> (the package receipt), <Path>Ignore app version: Yes</Path> (the agent updates itself).
            </li>
            <li>
              Assignments: <Path>Required</Path> → a device group holding these Macs.
            </li>
          </Steps>
        </>
      )}
      <MachineNames names={p.names} />
    </div>
  );
}

function Rmm(p: GuidanceProps) {
  const win = !!p.facts.platforms.windows;
  const mac = !!p.facts.platforms.macos;
  return (
    <div>
      <H>1. Installer</H>
      <InstallerButtons {...p} />
      {win && (
        <>
          <H>Windows: silent install</H>
          <CodeBox testId="deploy-rmm-win" text={`msiexec /i ${MSI} /qn /norestart /l*v "%WINDIR%\\Temp\\cnapp-agent-install.log"`} note="Run as SYSTEM. Success: exit code 0 (or 3010)." />
          <Steps>
            <li>
              <b>Configuration Manager:</b> <Path>Software Library → Applications → Create Application</Path>, type <Path>Windows Installer (*.msi file)</Path> from the
              content share (the product-code detection is filled in), deploy as <Path>Required</Path> to a device collection holding these machines.
            </li>
            <li>
              <b>Other RMM:</b> push the MSI and run the command above; detect with the script below or the file <code>{INSTALL_DIR}\cnapp-agent.exe</code>.
            </li>
          </Steps>
          <div className="mt-3">
            <CodeBox testId="deploy-rmm-detect" text={WIN_DETECT} />
          </div>
        </>
      )}
      {mac && (
        <>
          <H>macOS: silent install</H>
          <CodeBox testId="deploy-rmm-mac" text={`sudo installer -pkg ${PKG} -target /\n# detection: installed when this succeeds\npkgutil --pkg-info ${PKG_ID}`} />
          <Steps>
            <li>
              <b>Jamf Pro:</b> upload the pkg under <Path>Settings → Computer management → Packages</Path>, create a <Path>Policy</Path> with the package (Install),
              trigger <Path>Recurring check-in</Path>, frequency <Path>Once per computer</Path>, scoped to a smart or static group of these Macs.
            </li>
            <li>
              <b>Other MDM / RMM:</b> deploy the pkg and detect with the <code>pkgutil</code> receipt above.
            </li>
          </Steps>
        </>
      )}
      <MachineNames names={p.names} />
    </div>
  );
}

function Manual(p: GuidanceProps) {
  const win = !!p.facts.platforms.windows;
  const mac = !!p.facts.platforms.macos;
  const server = p.serverUrl ?? "https://cnapp.example.com";
  const token = p.token ?? "<command-line token, shown once when the deployment was created>";
  return (
    <div>
      <H>1. Installer</H>
      <InstallerButtons {...p} />
      <p className="mt-2 text-sm text-ink-2">
        Send the file to the user or IT through a channel limited to them (it carries an enrollment token); the install needs local administrator rights.
        Revoke the deployment when the rollout is finished.
      </p>
      <H>2. One-line install</H>
      {win && <CodeBox testId="deploy-manual-win" text={`:: Windows (elevated Command Prompt, in the folder with the file)\nmsiexec /i ${MSI} /qn /norestart`} />}
      {mac && <CodeBox testId="deploy-manual-mac" text={`# macOS (Terminal)\nsudo installer -pkg ~/Downloads/${PKG} -target /`} />}
      <details className="mt-2" open={!!p.token}>
        <summary className="cursor-pointer text-xs font-medium text-accent">With the generic installer and a command-line token instead</summary>
        <div className="mt-2 space-y-2">
          {win && (
            <CodeBox
              testId="deploy-manual-win-token"
              text={`:: Windows: generic MSI + properties (the token is hidden from the MSI log)\nmsiexec /i cnapp-agent-windows-x64.msi CNAPP_SERVER=${server} CNAPP_TOKEN=${token} /qn`}
            />
          )}
          {mac && (
            <CodeBox
              testId="deploy-manual-mac-token"
              text={`# macOS: generic pkg, then configure (token on stdin, not in the process list)\nsudo installer -pkg cnapp-agent-macos-universal.pkg -target /\nprintf '%s\\n' '${token}' | sudo /usr/local/cnapp-agent/bin/cnapp-agent configure --server ${server} --token-stdin`}
            />
          )}
        </div>
      </details>
      <MachineNames names={p.names} />
    </div>
  );
}

export function RouteGuidance(props: GuidanceProps) {
  switch (props.facts.route) {
    case "gpo":
      return <Gpo {...props} />;
    case "intune":
      return <Intune {...props} />;
    case "rmm":
      return <Rmm {...props} />;
    default:
      return <Manual {...props} />;
  }
}
