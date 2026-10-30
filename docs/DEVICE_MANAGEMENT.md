# Device management (endpoint agent)

CloudSecurity can track company laptops and desktops alongside cloud workloads. A small agent of our own (`cnapp-agent`, in [`endpoint-agent/`](../endpoint-agent)) runs on **Windows 10/11** and **macOS**. It reports hardware/OS inventory, security posture and installed software, and it runs a short, fixed list of remote actions that an admin or analyst queues in the UI.

It works in the spirit of Intune, with deliberate limits:

- **Our own agent only.** There is no Microsoft Graph / Intune integration and no Apple or Windows MDM protocol, so no MDM enrollment profiles or Apple Push certificates are needed.
- **Inventory, posture and safe remote actions.** The OS and installed software are matched against public CVE data (NVD by CPE, CISA KEV, EPSS; see [VULNERABILITIES.md](VULNERABILITIES.md)) and shown on the device's **Vulnerabilities** tab. Compliance policies are not implemented yet.
- **No arbitrary command execution.** The agent never runs scripts or shell commands written on the server. The only scripts it runs are **approved scripts**: reviewed in this repository, signed with a dedicated script-signing key the server never holds, verified by the agent right before running, with typed, validated parameters ([DEVICE_SCRIPTS.md](DEVICE_SCRIPTS.md), [ADR-0001](ADR-0001-signed-device-scripts.md)).
- **High-risk actions need two admins.** Remote wipe (Windows only) and medium/high-risk scripts run only after a second admin approves them ([Two-person approval](#two-person-approval)).

Linux is not supported yet. The code is split so it can be added later: see [Adding Linux](#adding-linux).

## Contents

- [Architecture](#architecture)
- [Roll out to all devices](#roll-out-to-all-devices) (one pre-configured MSI / pkg: GPO, Intune, SCCM, Jamf, Kandji)
- [Enrolling devices](#enrolling-devices) one by one: [Windows](#windows-1011) and [macOS](#macos)
- [What data is collected](#what-data-is-collected) (privacy)
- [Device health and issues](#device-health-and-issues)
- [Remote actions](#remote-actions)
- [Two-person approval](#two-person-approval)
- [Lost mode](#lost-mode)
- [Suspend sign-in](#suspend-sign-in)
- [Remote wipe (Windows)](#remote-wipe-windows)
- [Remote sessions (Windows)](#remote-sessions-windows) (attended remote desktop)
- [Approved scripts](#approved-scripts) (details: [DEVICE_SCRIPTS.md](DEVICE_SCRIPTS.md))
- [Security model](#security-model)
- [Service install, upgrade and uninstall](#service-install-upgrade-and-uninstall) (and **[automatic, signed agent updates](AGENT_UPDATES.md)**)
- [Packaging and code signing](#packaging-and-code-signing)
- [API reference](#api-reference)
- [Configuration](#configuration)
- [Testing](#testing)
- [Limitations](#limitations)

## Architecture

```mermaid
flowchart LR
  subgraph endpoint["Windows / macOS device"]
    svc["cnapp-agent<br/>Windows service (LocalSystem)<br/>or LaunchDaemon (root)"]
    col["Collectors<br/>CIM/PowerShell, registry,<br/>fdesetup, socketfilterfw, plists..."]
    st[("state.json<br/>device id + secret<br/>SYSTEM/Admins or root 0600")]
    svc --> col
    svc --- st
  end

  subgraph cnapp["CNAPP deployment"]
    nginx["Frontend nginx<br/>/api/agent/* (8 MiB bodies)<br/>/api/* (1 MiB)"]
    agentapi["Agent API /api/agent/*<br/>device credential auth,<br/>rate limit per device"]
    userapi["User API /api/devices/*<br/>session + CSRF, RBAC"]
    db[("PostgreSQL / SQLite<br/>devices, posture snapshots,<br/>software, commands, log bundles")]
    audit[("audit_log")]
  end
  ui["Browser (admin / analyst / viewer)"]

  svc -- "HTTPS, outbound only<br/>enroll / check-in every 15 min /<br/>poll commands every ~60 s" --> nginx
  nginx --> agentapi --> db
  ui -- "session cookie" --> nginx --> userapi --> db
  userapi -- "every remote action + reason" --> audit
```

**Pull model.** The agent never listens on a port. It makes outbound HTTPS requests only:

| Request | When | Purpose |
|---|---|---|
| `POST /api/agent/enroll` | once (and on re-enrollment) | exchange an enrollment token for a per-device credential |
| `POST /api/agent/checkin` | at start, then every check-in interval (default 15 min, ±10% jitter) | full inventory, posture and software report |
| `GET /api/agent/commands` | about every 60 s (±10% jitter) | small request that fetches queued remote actions and works as a heartbeat |
| `POST /api/agent/commands/{id}/result` | after running a command | status and output |
| `POST /api/agent/commands/{id}/logs` | for `collect_logs` | upload a gzip log bundle |

When a request fails, the agent backs off exponentially with full jitter (30 s, 1 min, 2 min, ... up to 30 min). If the server rejects the credential (revoked or superseded), the agent logs that it must be re-enrolled and retries only once an hour. It does not exit, so the service manager does not get stuck in a restart loop.

## Roll out to all devices

**One installer file for every device, with no per-device token.** In **Devices → Enroll devices → Download installer** (admin only) choose:

| Setting | Default | Meaning |
|---|---|---|
| Platform | Windows (MSI, x64) | or macOS (pkg, Intel + Apple silicon) |
| Expires after | 30 days | the installer stops enrolling *new* devices after this (1–365) |
| Maximum devices | 500 | each new device uses one enrollment; re-installs and upgrades do not |
| Device group | (none) | label applied to every device enrolled with it (filter `GET /api/devices?group=`) |
| Include the server's CA certificate | on when the server has a private CA | see [TLS and the CA](#tls-and-the-ca) |
| Allow remote wipe | **off** | Windows only: devices installed from this package opt in to [remote wipe](#remote-wipe-windows). Stored in the device's protected local policy; the server cannot turn it on later |

The server mints a dedicated **package-bound enrollment token** (stored hashed like every token, listed under *Enrollment tokens* with an "installer" tag, revocable there, every download audit-logged as `agent_installer_created` with the file's SHA-256) and returns one file:

- `cnapp-agent-setup.msi`: the generic MSI with the enrollment config written into its hidden `CNAPP_PRESET` property;
- `cnapp-agent-setup.pkg`: the generic pkg with `enroll.json` added next to its install scripts.

The plaintext token exists **only inside that file**: it is not stored, logged or shown again. Treat the file like a password until it expires or you revoke its token, and do not post it anywhere public.

**What happens on a device.** The installer puts the agent in place, registers the service (Windows: `CNAPPAgent`, LocalSystem, automatic start, restart on failure; macOS: LaunchDaemon) and stores the enrollment config in the protected state directory (`%ProgramData%\CNAPP Agent\enroll.json` / `/Library/Application Support/CNAPP Agent/enroll.json`, SYSTEM/Administrators or root only). When the service starts it enrolls, retrying with backoff while the server is unreachable, then **deletes enroll.json**. The device shows up in **Devices** within a minute or two.

- Already enrolled (re-install, repair, upgrade): the config is ignored and deleted; the device keeps its identity and uses no enrollment. To move a device on purpose, run `cnapp-agent enroll`, or `uninstall --purge` and reinstall.
- Token expired, revoked or out of devices: the agent logs `enrollment token rejected by the server ...` and retries every 30 minutes. Download a new installer, or raise the limit by issuing a new one.
- The same machine enrolling again (for example after a reinstall with `--purge`) gets its **existing device record** back (matched by OS machine id), so counts stay correct.

### Windows: Group Policy, Intune, SCCM, manual

The MSI is per-machine and supports silent install, repair and uninstall. It registers the `CNAPPAgent` service (LocalSystem, automatic delayed start) and sets its recovery actions (restart after 5 s / 30 s / 2 min) through a small deferred action that runs `cnapp-agent service-recovery`, because Windows Installer's own `MsiServiceConfigFailureActions` table rejects restart actions (error 1939).

```bat
msiexec /i cnapp-agent-setup.msi /qn /l*v %TEMP%\cnapp-agent-install.log
msiexec /x cnapp-agent-setup.msi /qn            :: or Settings > Apps > CNAPP Endpoint Agent > Uninstall
```

Uninstall stops and removes the service, the binary, the credential and the logs (set `CNAPP_KEEP_STATE=1` to keep the credential). An upgrade (newer MSI) keeps the device identity.

- **Group Policy (Active Directory).** Copy the MSI to a share that domain computers can read (`\\fileserver\deploy$\cnapp\cnapp-agent-setup.msi`, *Domain Computers*: Read). Create a GPO linked to the computers' OU: **Computer Configuration → Policies → Software Settings → Software Installation → New → Package**, pick the UNC path, choose **Assigned**. Computers install it at the next restart (`gpupdate /force` then reboot to test). A **startup script** works too: Computer Configuration → Policies → Windows Settings → Scripts → Startup → `msiexec.exe /i \\fileserver\deploy$\cnapp\cnapp-agent-setup.msi /qn`.
- **Intune.** *Apps → Windows → Add → Line-of-business app*, upload the MSI (Intune detects the product code and installs it silently in the device context), assign to a device group. Or as a **Win32 app** (wrap with `IntuneWinAppUtil.exe -c . -s cnapp-agent-setup.msi -o .`): install command `msiexec /i cnapp-agent-setup.msi /qn`, uninstall `msiexec /x {ProductCode} /qn`, install behavior *System*, detection rule *MSI product code*.
- **SCCM / ConfigMgr.** Create an Application from the MSI (*Windows Installer (\*.msi file)* deployment type); the install program is `msiexec /i "cnapp-agent-setup.msi" /qn`, detection by product code, deploy to a device collection.
- **Manual.** Double-click the MSI (one UAC prompt, no questions), or run the `msiexec` line above in an elevated prompt.

**Option B: your own signed generic MSI + properties.** The CI artifact `cnapp-agent-windows-msi` (`cnapp-agent-windows-x64.msi`) carries no enrollment. Sign it yourself and pass the enrollment on the command line:

```bat
msiexec /i cnapp-agent-windows-x64.msi /qn CNAPP_SERVER=https://cnapp.wakanow.com CNAPP_TOKEN=cne_... [CNAPP_CA_B64=<base64 of the CA PEM>]
```

Create the multi-use token under *Enrollment tokens* (it is shown once). The properties are hidden from MSI logs. For **Group Policy**, which cannot pass properties directly, create a transform with Orca or the Windows SDK's `msitran`/`WiRunSQL.vbs`: add rows `CNAPP_SERVER` and `CNAPP_TOKEN` to the `Property` table and save it as `cnapp.mst`, then on *Software Installation → New → Package → Advanced → Modifications* add the `.mst`. For **Intune**, put the properties on the Win32 app's install command (or the LOB app's *Command-line arguments*). `CNAPP_CA_B64` is only needed for a private CA that the devices do not already trust: `[Convert]::ToBase64String([IO.File]::ReadAllBytes('cnapp-root-ca.crt'))`.

### macOS: Jamf, Kandji, Intune, manual

```bash
sudo installer -pkg cnapp-agent-setup.pkg -target /
sudo /usr/local/cnapp-agent/bin/cnapp-uninstall.sh     # uninstall (add --keep-state to keep the credential)
```

- **Jamf Pro.** *Settings → Computer management → Packages → New*, upload the pkg; add it to a policy (trigger *Recurring check-in* / *Enrollment complete*, execution *Once per computer*) scoped to your Macs.
- **Kandji.** *Library → Add new → Custom App*, installer type *Package*, upload the pkg, assign to a Blueprint.
- **Intune.** *Apps → macOS → Add → macOS app (PKG)* (for an unsigned package; the LOB type requires a signed pkg), upload, assign.
- **Manual.** Double-click (an unsigned downloaded pkg needs right-click → Open the first time), or the `installer` command above.

**MDM with your own signed pkg.** Install the generic, signable pkg (CI artifact `cnapp-agent-macos-pkg`); the LaunchDaemon starts and waits. Then push the enrollment from an MDM script (it is picked up within a minute):

```bash
printf '%s\n' 'cne_...' | /usr/local/cnapp-agent/bin/cnapp-agent configure --server https://cnapp.wakanow.com --token-stdin [--ca-file /path/cnapp-root-ca.crt]
```

### TLS and the CA

Agents always verify the server certificate (system trust store, plus a private CA when one is configured). The installer embeds the CA **only when needed**:

- **Built-in CA (`cnapp-ctl` default) or an internal/enterprise CA**: `cnapp-ctl` sets `AGENT_CA_CERT_B64` and the download includes the CA by default. Untick it once your CA is deployed to all devices by GPO/MDM.
- **Publicly trusted certificate**: no CA is configured, nothing is embedded, and the box is disabled. This is the Wakanow production setup: `https://cnapp.wakanow.com` with a publicly trusted DigiCert wildcard certificate (`*.wakanow.com`, imported with `cnapp-ctl tls import-pfx`). Installers downloaded there contain only `https://cnapp.wakanow.com` and the token; Windows and macOS already trust DigiCert, so devices need no CA file, GPO certificate deployment or MDM certificate payload. (If `AGENT_CA_CERT_B64` is still set from the earlier built-in CA, re-run `cnapp-ctl tls import-pfx` or set it empty and `cnapp-ctl restart`; `GET /api/devices/installers` shows `ca_configured: false` when correct.)

The server URL inside the installer is `PUBLIC_BASE_URL` (on-prem: `https://<CNAPP_HOSTNAME>`, changed with `cnapp-ctl set-hostname`). Download new installers after changing the hostname or certificate. Devices that are already enrolled keep using the URL they enrolled with; on-prem, `cnapp-ctl tls import-pfx` keeps serving the old built-in certificate to clients that connect by IP address or by the old name, so they keep working ([DEPLOY_ONPREM.md](DEPLOY_ONPREM.md#switch-to-a-dns-name-and-your-own-certificate-pfx)).

### Token lifetime, limits and revocation

- An installer works until its token **expires** (default 30 days) or reaches **maximum devices** (default 500), whichever comes first. Devices already enrolled are not affected by either: they authenticate with their own per-device credential.
- **Revoke** the installer's token under *Enrollment tokens* when the rollout is done or if the file leaks. Devices that have not enrolled yet then log the rejection and retry every 30 minutes; enrolled devices keep working.
- Shorter is safer: pick the smallest expiry and device count that cover your rollout window, and download a fresh installer for later waves.

### Code signing

- The **pre-configured MSI and pkg are unsigned**: injecting the enrollment changes the file, which would invalidate any signature (signing them on the server would need your code-signing key there, which this feature deliberately does not do). Windows SmartScreen and macOS Gatekeeper therefore warn on a *double-click* of a downloaded file. Deployment tools (GPO, Intune, SCCM, Jamf, `installer`) are not affected.
- The **agent binary inside** can be signed: CI builds it, you sign `cnapp-agent.exe` (Authenticode) or the macOS binary (Developer ID) and build the MSI/pkg from it ([Packaging](#packaging-and-code-signing)). Signing the binary keeps EDR/AV allow-listing simple even when the package is unsigned.
- For SmartScreen-free rollouts and Intune's macOS LOB type, use **option B**: sign the *generic* MSI / pkg yourself and supply the enrollment via properties (Windows) or `cnapp-agent configure` (macOS). Use the pre-configured download for convenience.
- Why MSI rather than a `setup.exe`: MSI is what GPO Software Installation, Intune LOB and SCCM install natively (silent, per-machine, repair, clean uninstall, upgrade, product-code detection). A bootstrapper `.exe` would add another unsigned binary without adding a capability, so none is built.

### Troubleshooting

| Check | Windows | macOS |
|---|---|---|
| Service running | `sc.exe query CNAPPAgent` / `Get-Service CNAPPAgent` | `sudo launchctl print system/com.cloudsecurity.cnapp-agent` |
| Enrollment state | `& "$env:ProgramFiles\CNAPP Agent\cnapp-agent.exe" status` (elevated) | `sudo /usr/local/cnapp-agent/bin/cnapp-agent status` |
| Agent log | `%ProgramData%\CNAPP Agent\logs\agent.log` | `/Library/Logs/CNAPP Agent/agent.log` and `launchd.log` |
| Installer log | `msiexec /i ... /l*v install.log` (properties shown as `**********`) | `/var/log/install.log` |

`status` prints `"enrolled": false` with `pending_enrollment` while the service is still trying. Typical log lines: `enrollment failed; retrying ... x509: certificate signed by unknown authority` (CA not embedded and not trusted: download with *Include CA*, or deploy the CA), `... no such host` / `connection refused` (DNS / firewall to the server), `enrollment token rejected` (expired, revoked or used up).

## Enrolling devices

For a handful of devices, or scripted installs, you can also enroll one by one with a token.


You need the URL of your CNAPP deployment (for example `https://cnapp-web.<env>.<region>.azurecontainerapps.io`) and an **admin** account.

1. In the UI open **Devices → Enroll devices** and click **Create token**. Choose:
   - a **name** (for example "Finance laptops, Oct 2026");
   - **single device** or **multiple devices** (an optional maximum; empty means unlimited until expiry);
   - an **expiry** (default 24 h, maximum 90 days).

   The token (`cne_...`) is shown **once**. Anyone who holds a valid token can enroll a device, so keep tokens short-lived and revoke them when you are done.
2. Get the agent build for the platform from the CI artifacts (see [Packaging](#packaging-and-code-signing)) or your internal download location.
3. Run the commands below on the device. The device appears in **Devices** within about a minute.

### Windows 10/11

Open **PowerShell as administrator** in the folder that contains `cnapp-agent-windows-amd64.exe` (use `-arm64` on ARM devices) and `install.ps1`:

```powershell
.\install.ps1 -Server https://cnapp.example.com -Token cne_xxxxxxxx -BinaryPath .\cnapp-agent-windows-amd64.exe
```

Or download directly from your release location with an integrity check:

```powershell
.\install.ps1 -Server https://cnapp.example.com -Token cne_xxxxxxxx `
  -DownloadUrl https://downloads.example.com/cnapp-agent/0.1.0/cnapp-agent-windows-amd64.exe `
  -Sha256 <value from SHA256SUMS> -RequireSignature
```

`install.ps1` checks that it is elevated and that the URL is https. It verifies the SHA-256 and, with `-RequireSignature`, the Authenticode signature. It enrolls the device, passing the token on **stdin** so it never appears in the process list, and then runs `cnapp-agent install`. That copies the binary to `C:\Program Files\CNAPP Agent\cnapp-agent.exe` and registers the **CNAPP Endpoint Agent** (`CNAPPAgent`) service. The service is set to automatic (delayed) start, runs as LocalSystem and restarts on failure.

Without the script:

```powershell
$env:CNAPP_ENROLL_TOKEN = 'cne_xxxxxxxx'
.\cnapp-agent-windows-amd64.exe enroll --server https://cnapp.example.com
.\cnapp-agent-windows-amd64.exe install
Remove-Item Env:CNAPP_ENROLL_TOKEN
```

**Server with an internal certificate (on-prem).** If the server's certificate comes from an internal CA that Windows does not trust yet (for example the CA created by `cnapp-ctl tls init`, see [DEPLOY_ONPREM.md](DEPLOY_ONPREM.md)), either deploy that root CA to the machine store first (Group Policy, or `certutil -addstore -f Root cnapp-root-ca.crt`), or pass it to the agent: `.\install.ps1 ... -CaFile .\cnapp-root-ca.crt` (or `enroll --ca-file`). The agent keeps a protected copy next to its credentials, so the file can be deleted afterwards. There is no option to skip certificate verification.

Check the result with `Get-Service CNAPPAgent`, `& 'C:\Program Files\CNAPP Agent\cnapp-agent.exe' status` and the log at `C:\ProgramData\CNAPP Agent\logs\agent.log`.

### macOS

In **Terminal**, as an administrator. Use `darwin-arm64` on Apple silicon and `darwin-amd64` on Intel Macs:

```bash
chmod +x cnapp-agent-darwin-arm64
xattr -d com.apple.quarantine cnapp-agent-darwin-arm64 2>/dev/null   # unsigned builds only
echo 'cne_xxxxxxxx' | sudo ./cnapp-agent-darwin-arm64 enroll --server https://cnapp.example.com --token-stdin
sudo ./cnapp-agent-darwin-arm64 install
```

`install` copies the binary to `/usr/local/cnapp-agent/bin/cnapp-agent` and writes `/Library/LaunchDaemons/com.cloudsecurity.cnapp-agent.plist`, with `RunAtLoad`, `KeepAlive` and a 30 s throttle. It then loads and starts the daemon with `launchctl bootstrap` and `kickstart`.

You can also use the installer package from CI (`cnapp-agent-macos-universal.pkg`, a universal binary):

```bash
sudo installer -pkg cnapp-agent-macos-universal.pkg -target /
echo 'cne_xxxxxxxx' | sudo /usr/local/cnapp-agent/bin/cnapp-agent enroll --server https://cnapp.example.com --token-stdin
sudo /usr/local/cnapp-agent/bin/cnapp-agent install
```

A deployment tool can enroll during package install instead. Before running the installer, write `/var/root/.cnapp-enroll` (root, `0600`) with the server URL on line 1 and the token on line 2. The `postinstall` script enrolls, deletes the file and starts the daemon. On an upgrade of an enrolled Mac, `postinstall` simply restarts the daemon.

`packaging/macos/install.sh --server URL --binary PATH [--ca-file cnapp-root-ca.crt]` combines the binary steps and prompts for the token.

**Server with an internal certificate (on-prem).** Add `--ca-file cnapp-root-ca.crt` to `enroll` (or to `install.sh`), or put the CA path on a third line of `/var/root/.cnapp-enroll` for package installs. Alternatively trust the root CA system-wide first (`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain cnapp-root-ca.crt`, or an MDM certificate payload); the agent always uses the system trust store too. Example:

```bash
echo 'cne_xxxxxxxx' | sudo ./cnapp-agent-darwin-arm64 enroll --server https://cnapp.corp.local --token-stdin --ca-file ./cnapp-root-ca.crt
sudo ./cnapp-agent-darwin-arm64 install
```

Check with `sudo /usr/local/cnapp-agent/bin/cnapp-agent status`, `sudo launchctl print system/com.cloudsecurity.cnapp-agent` and `/Library/Logs/CNAPP Agent/agent.log`.

### Re-enrollment and revocation

- Running `enroll` again with a new token **re-enrolls** the device. The server recognizes the machine by a SHA-256 of its OS machine identifier (Windows `MachineGuid`, macOS `IOPlatformUUID`). It keeps the same device record and history, issues a new secret and invalidates the old one. This also reactivates a revoked device.
- **Revoke** (admin, device page) invalidates the credential immediately and cancels pending actions. The agent keeps running but is rejected (`403`) until someone re-enrolls it.
- **Delete** (admin, after revoking) removes the device and all its data.
- The device secret is never displayed. `cnapp-agent status` prints the state with the secret redacted.

### Local testing over plain http

`enroll --insecure-dev` allows `http://` URLs, for example `http://localhost:8000` with `uvicorn`. Never use it in production. Without it the agent refuses anything but https. `--home DIR` (or `CNAPP_AGENT_HOME`) keeps state and logs under `DIR`, so you can try the agent without root:

```bash
cd endpoint-agent && go build -o cnapp-agent ./cmd/cnapp-agent
./cnapp-agent inventory --print            # what would be sent (no network)
./cnapp-agent enroll --server http://localhost:8000 --token cne_... --insecure-dev --home /tmp/agent
./cnapp-agent checkin --home /tmp/agent    # one check-in + command poll
```

## What data is collected

Everything is **read-only** and uses OS-native tools with timeouts, so the user sees no prompts or pop-ups. Each collector fails independently. When one fails, its check is reported as `unknown` with the error, and the agent does not crash.

| Area | Windows | macOS |
|---|---|---|
| Device | hostname, BIOS serial, manufacturer/model, CPU and cores, RAM, fixed disks (size/free), OS caption/version/build (incl. UBR, display version), architecture, last boot/uptime, users with an interactive session (owners of `explorer.exe`), time zone | hostname, serial (`ioreg`), model, CPU (`sysctl`), RAM, root volume (size/free), `sw_vers`, architecture, boot time/uptime, console user and `who`, time zone |
| Network | adapters that are up, with MAC and IP addresses, and the agent version | same |
| Disk encryption | BitLocker on the OS volume (`Win32_EncryptableVolume`: protection and conversion status) | FileVault (`fdesetup status`) |
| Firewall | Windows Defender Firewall, every profile (`Get-NetFirewallProfile -PolicyStore ActiveStore`) | application firewall (`socketfilterfw --getglobalstate`, stealth mode) |
| Antivirus / EDR | Microsoft Defender (`Get-MpComputerStatus`: real-time protection, signature age and version, tamper protection) and products registered in Windows Security Center (`SecurityCenter2`, client SKUs) | XProtect version and age (`xprotect version` on macOS 15+, else the XProtect bundle) |
| Screen lock | machine inactivity limit policy (`InactivityTimeoutSecs`) or a password-protected screen saver of 15 min or less for each signed-in user | `sysadminctl -screenLock status` for the console user, or a managed `com.apple.screensaver` profile |
| OS updates | pending updates from the **local** Windows Update cache (offline search, no network scan), last install date, reboot required | `/Library/Preferences/com.apple.SoftwareUpdate.plist` (results the OS itself caches; no `softwareupdate --list`), last OS install |
| Platform | Secure Boot (`Confirm-SecureBootUEFI`), TPM (`Get-Tpm`) | SIP (`csrutil status`), Gatekeeper (`spctl --status`) |
| Local admins | members of the Administrators group (by SID, so it works in any language) | members of the `admin` group |
| Software | uninstall registry keys: HKLM 64-bit, HKLM 32-bit and loaded user hives (name, version, publisher, install date; system components and updates excluded) | `.app` bundles in `/Applications` (2 levels) and `~/Applications` (name, version, bundle id) |

**Privacy note.** The agent does **not** collect files, documents, browsing data, screenshots, keystrokes, location, process lists or network traffic. It records the user names of signed-in users and local administrators, IP and MAC addresses, the serial number and the installed applications. Tell your users about it as your policies require. Data is kept until the device is deleted. Posture history is capped per device (`DEVICE_HISTORY_LIMIT`, default 200 snapshots).

## Device health and issues

The server derives **issues** from the latest posture and timestamps whenever a device is read. They are built-in signals, not configurable compliance policies:

| Issue | Severity | Raised when |
|---|---|---|
| `disk_encryption_off` | high | BitLocker / FileVault check fails (off, suspended, or still encrypting) |
| `firewall_off` | high | any Windows firewall profile, or the macOS application firewall, is off |
| `antivirus_off` | high | no active real-time antivirus |
| `av_signatures_outdated` | medium | Defender (or a Security Center product) signatures older than `DEVICE_AV_SIGNATURE_MAX_AGE_DAYS` (7) |
| `os_updates_pending` | medium | updates have been pending for more than `DEVICE_UPDATES_GRACE_DAYS` (14), counted from the first check-in that reported them |
| `screen_lock_off` | low | screen lock explicitly not enforced |
| `sip_disabled` | high | macOS System Integrity Protection off or weakened |
| `gatekeeper_off` | medium | Gatekeeper disabled |
| `secure_boot_off` | medium | Secure Boot reported off |
| `stale` | medium | no contact for more than `DEVICE_STALE_HOURS` (24) |
| `inactive` | high | no contact for more than `DEVICE_INACTIVE_DAYS` (7) |

**Health** is *At risk* if any issue is high, *Warning* if there are only medium or low issues, *Healthy* if there are none, and *No data* before the first check-in. The dashboard tile and the Devices page show fleet totals: device counts, % encrypted, % with the firewall on, and stale devices. Checks that report `unknown` (for example BitLocker on Windows Server, or Secure Boot on a VM) never raise issues.

**Notifications:** new issues, devices becoming stale/inactive and remote action results are also events of the *Endpoint device* notification source, so admins can route them to Teams, Slack, email or webhooks with a rule (see [NOTIFICATIONS.md](NOTIFICATIONS.md#endpoint-device-events)).

## Remote actions

There is no generic "run command". Only the following actions exist, and each one is allow-listed **on the server** (the API rejects any other type or parameter) and **again in the agent**, which refuses anything not on its own list whatever the server sends:

| Action | Minimum role | What the agent does |
|---|---|---|
| `recheck_posture` | analyst | immediate full check-in |
| `collect_logs` | analyst | uploads a gzip tar with the agent's own logs (last 2 MiB + 1 MiB of the rotated file), its state with the **secret redacted**, and a fresh inventory/posture snapshot without software. No user files. At most 4 MiB from the agent, at most 5 MiB on the server, stored in the database. Downloading needs analyst. |
| `lock_device` | admin | locks the interactive session (details below); the UI asks you to type the hostname to confirm |
| `restart_agent` | admin | reports success, then exits so the service manager restarts it (Windows SCM recovery actions; launchd `KeepAlive`) |
| `update_check_in_interval` | admin | sets the full check-in interval to 300-86,400 s and stores it in the agent state |
| `enable_lost_mode` / `disable_lost_mode` | admin | shows a message + contact phone on the sign-in / lock screen and locks the sessions until cleared; exiting restores the previous settings ([Lost mode](#lost-mode)). Typed hostname to enable; no second approval (reversible) |
| `isolate_host` / `restore_host` | analyst / admin | blocks standard interactive sign-in while local admin access keeps working, then restores it exactly ([Suspend sign-in](#suspend-sign-in)). Internal names kept for API compatibility; the UI only ever says "Suspend sign-in" / "Restore sign-in". Typed hostname to suspend; no second approval (reversible) |
| `wipe_device` | admin **+ a second admin** | Windows only, device opted in at install time: factory-resets the device through `MDM_RemoteWipe` ([Remote wipe](#remote-wipe-windows)). Never queued directly: `POST /api/devices/{id}/wipe` creates an approval request |
| `run_script` | admin (**+ a second admin** unless the signed manifest says `risk: low`) | runs one approved, signed script with validated parameters ([Approved scripts](#approved-scripts)) |
| `start_remote_session` | analyst (View only) / admin (View and control) | Windows only: opens an attended remote session after the signed-in user allows it ([Remote sessions](#remote-sessions-windows)). Never queued directly: `POST /api/devices/{id}/remote-sessions` |

Every action requires a **reason**. Creating one is written to the audit log (`device_command_created`, with actor, device, type, parameters and reason), and so are cancellation, completion (reported by the device), log-bundle downloads, token creation and revocation, enrollment, re-enrollment, revocation and deletion.

**Lifecycle.** `pending` → `delivered` (handed to the agent exactly once, through a conditional update) → `succeeded` / `failed` / `rejected`. A pending command can also become `cancelled` (pending only) or `expired`. Commands are bound to one device and have an expiry (default 24 h, `DEVICE_COMMAND_TTL_HOURS`) and a random nonce. The agent checks the device binding and the expiry, adjusted for clock skew using the server time, before it runs a command. It records the command id **before** executing it, so it never runs a command twice, even after a crash or a replay. The result must echo the nonce.

### How `lock_device` works

| Platform | Mechanism | Notes |
|---|---|---|
| Windows | The service (LocalSystem, session 0) enumerates active sessions (`WTSEnumerateSessions`). For each one it gets the user's token (`WTSQueryUserToken`) and starts `rundll32.exe user32.dll,LockWorkStation` on that session's `winsta0\default` desktop (`CreateProcessAsUser`). If that fails, it disconnects the session (`WTSDisconnectSession`), which also returns it to the sign-in screen without logging the user off. Run interactively, the agent calls `LockWorkStation` directly. | Works for console and RDP sessions. The result lists every session and how it was locked. With no one signed in it reports `failed: no active interactive session`. |
| macOS | If `CGSession -suspend` exists (macOS 10.x only; removed in 11+) it runs in the console user's context. Otherwise it runs `pmset displaysleepnow`, which locks the session only when the user requires a password **immediately** (or within the delay) after sleep or screen saver. That is the macOS default, and our `screen_lock` posture check reports it. | The result output includes the user's actual `screenLock` setting. If no password is required, the action is reported as **failed** ("screen is NOT locked"). There is no supported API that lets a root daemon force-lock a macOS session without MDM. |

## Two-person approval

Remote wipe and running a **medium**- or **high**-risk approved script are "maker-checker" actions:

1. An admin requests the action with a reason (`POST /api/devices/{id}/wipe`, or *Run script* for a non-low-risk script). Nothing is sent to the device yet; the request appears under **Approvals** (badge in the navigation) and raises an `approval_requested` notification (source *Device approvals*, route it to Teams / Slack / email with a rule, [NOTIFICATIONS.md](NOTIFICATIONS.md#device-approval-events)).
2. A **different** active admin approves or rejects it (with an optional / required reason). For a wipe the approver must type the device name again. Approval queues the command at once; every step is in the audit log (`device_approval_requested`, `_approved`, `_rejected`, `_cancelled`, `_expired`, `device_command_created` with `approval_id` and `approved_by`).
3. Requests **expire** after `DEVICE_APPROVAL_TTL_HOURS` (24 h). The requester or any admin can cancel a pending request. Decisions are race-safe (conditional update: two admins cannot both decide).

**Lost mode is not an approval action**: it is reversible and audited like every remote action.

**Single-admin installs: self-approval.** Off by default: the requester's own *Approve* is refused (`403`). On-prem, `sudo cnapp-ctl approvals self-approval enable` (or `DEVICE_APPROVAL_ALLOW_SELF=true`) lets the requester approve their own request, but then they must **type the device name** and the action only runs after a **cooling-off delay** (`DEVICE_APPROVAL_SELF_COOLDOWN_MINUTES`, default 15) during which any admin can cancel it (the request shows *self-approved: runs at ...*). The delayed action is released by the device's next command poll, so no background job is needed.

> **Risk of self-approval.** It removes the second person: a single compromised admin account or session, or one mistaken click plus a typed name, is enough to factory-reset a laptop or run a risky script. The typed name and delay only protect against accidents and give you time to notice the `approval_approved` notification. Create a second admin account (ideally a different person, with MFA at sign-in) and disable self-approval as soon as you can.

There is deliberately **no MFA step-up** in the approval flow (MFA is asked only at sign-in, see [AUTH.md](AUTH.md)); the second admin is the control.

## Lost mode

*Lost mode* (admin, **Devices > device > Lost mode**) puts a message and a contact phone number on the device's sign-in / lock screen and locks the interactive sessions; while it is active the agent locks any active session again every 5 minutes, until an admin clicks **Exit lost mode**. The device reports its state with every check-in (posture check `lost_mode`), and the device shows **Lost** (`device_state: "lost"`, issue `lost_mode`) in the console. Enabling needs the hostname typed; no second admin is needed (it is reversible). Exiting restores exactly the values that were there before (they are saved in `lostmode.json` in the protected state directory; uninstalling the agent also restores them).

| | Windows | macOS |
|---|---|---|
| Message | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` `LegalNoticeCaption` ("This device has been reported lost") and `LegalNoticeText` (message + "If found, please call: <phone>") | `/Library/Preferences/com.apple.loginwindow` `LoginwindowText` (the "Show message when screen is locked" text), then `diskutil apfs updatePreboot /` so the FileVault unlock screen shows it too (best effort) |
| Where it shows | Winlogon shows the notice **before the credential prompt at every sign-in** (after a restart, sign-out or *switch user*). Windows 10/11 do **not** show it when unlocking an already signed-in, locked session; the agent locks the sessions (same mechanism as `lock_device`), so the message appears as soon as anyone restarts the device or signs in again | on the **lock screen** and the login window (and the FileVault screen after the Preboot update) |
| Lock | every active session locked (console and RDP); with nobody signed in the lock is skipped and the message still stays | `pmset displaysleepnow`: locks only if the user requires a password after sleep (the macOS default; see `lock_device`) |
| Limits | a domain GPO that sets the same legal-notice values overwrites them at the next policy refresh | no supported way for a root daemon to force a lock without MDM; no Apple "Lost Mode" (that is an MDM command for supervised iOS devices) |

Without an MDM this is a **deterrent and a contact channel, not a kill switch**: the device still boots and a user who knows a password can sign in. For a stolen Windows device, combine it with [remote wipe](#remote-wipe-windows) (and BitLocker); for a Mac, FileVault + a firmware password, and an MDM if you need remote lock/erase.

## Suspend sign-in

*Suspend sign-in* (analyst, **Devices > device > Suspend sign-in**) blocks **standard interactive sign-in** on a device while leaving local admin access working, so IT can still get in to investigate or remediate. **Restore sign-in** (admin) puts it back exactly as it was. Internal names (`isolate_host`/`restore_host`, the `host_isolation` notification source, audit event types) are kept for API/compatibility reasons; every string a user sees says "Suspend sign-in" / "Restore sign-in" / "Sign-in suspended".

> **This is not network isolation.** The device stays connected and reachable on the network the whole time; nothing here touches firewall rules, Wi-Fi/Ethernet, or VPN state. It only narrows who can start an interactive session.

**Pre-flight (lockout prevention).** Before changing anything, the agent enumerates **enabled local administrator accounts** (macOS: members of the `admin` group; Windows: raw Win32 `NetLocalGroupGetMembers`/`NetUserGetInfo`, not PowerShell `Get-LocalGroupMember`, which throws on Entra-joined devices with Azure AD/Entra members in the Administrators group - those are logged and skipped, never miscounted as a usable local admin) and refuses to suspend sign-in if **none** would remain able to sign in (`rejected`, reported as `ERR_NO_LOCAL_ADMIN_PRESENT`; shown on the device page as *Suspend sign-in blocked - no local admin would remain*, severity critical). A probe error (could not enumerate at all) is also fail-closed, and distinct from "checked, found none". Windows-only best-effort LAPS telemetry (registry policy presence - legacy LAPS's `AdmPwdEnabled` or Windows LAPS's `BackupDirectory` - **never** a password; nothing in that code path calls a password-retrieval API) is reported alongside, so you can see whether a LAPS-rotated local admin password would still work. Suspend sign-in and [lost mode](#lost-mode) refuse to run at the same time (both compete for the sign-in screen); exit the active one first.

| Platform | Mechanism | Session sign-out |
|---|---|---|
| Windows | Snapshots the current holders of `SeInteractiveLogonRight` and `SeRemoteInteractiveLogonRight` (secpol.msc: *Allow log on locally* / *Allow log on through Remote Desktop Services*), then restricts both to **`BUILTIN\Administrators`** plus any built-in service/virtual account that already held them (`NT SERVICE` `S-1-5-80-*`, Window Manager `S-1-5-90-*`, Font Driver Host `S-1-5-96-*` - classified by SID prefix, not by localized name, and never removed). A **deny** right is deliberately never added: `BUILTIN\Administrators` members' tokens include `BUILTIN\Users` by default, and Windows deny rights override allow rights, so denying `Users` would lock out admins too. A mandatory post-apply check re-reads both rights and confirms the holder set is exactly as expected before anyone is signed out; on failure the first-time attempt rolls back automatically. | Active and RDP sessions that are not an admin's are signed out (`WTSLogoffSession`) |
| macOS | Nests the local `admin` group as the **sole** member of `com.apple.access_loginwindow` (created with `dseditgroup -o create` if it doesn't already exist; existing members reconciled away). Confirmed against real CI hardware that `dseditgroup -o edit -a <group> -t group <target>` stores a nested group in the `NestedGroups` dscl attribute, not `GroupMembers`. `system.login.console` and other authorization rights, and PAM, are never touched. | The console user's session is ended (`launchctl bootout gui/<uid>`), skipped entirely if the console user is a local admin |

A sign-in-suspended banner reuses lost mode's own mechanism (registry `LegalNoticeCaption`/`LegalNoticeText` on Windows, `LoginwindowText` on macOS - see [Lost mode](#lost-mode) for exactly where each shows): "Sign-in is suspended. Contact IT/Security.", with an optional **incident reference** (typed in the console, 1-64 characters: letters, digits, `.`, `_`, `:`, `-`; falls back to the command id) appended as "Reference: ...".

**Crash-safe and idempotent.** Everything Suspend is about to change is snapshotted and persisted **before** any live change, the same pattern as lost mode and remote wipe, so a crash mid-way is always resolvable: a phase marker in the agent's local record (`signin.json` - see [Manual recovery](#manual-recovery) below) tracks exactly how far it got, and `cnapp-agent`'s startup recovery finishes forward or rolls back on the next launch, reporting the outcome (`rolled_back` / `completed`) on exactly one later check-in (shown on the device page under *Crash recovery*, and as a high-severity audit entry / notification). **The console and backend refuse to queue a second *Suspend sign-in* while one is already active or in progress** (`409`: an operator cannot trigger a repeat suspend by hand). The agent's own idempotent re-apply path exists purely as a safety net for the same command being **delivered twice** (a retried request, or a crash recovered mid-way) - it re-runs pre-flight and updates the incident reference in place, **never** re-snapshotting or rolling back on a failure, so a redelivered command can't accidentally undo an active suspension. While suspended, the agent also re-asserts the restriction and banner every 5 minutes, correcting drift from an external tool or policy refresh.

**Limits worth knowing**

- A domain **GPO** that re-asserts `SeInteractiveLogonRight`/`SeRemoteInteractiveLogonRight` (or the legacy-notice values lost mode uses) overwrites them at the next policy refresh - the same limitation lost mode's legal notice already has.
- **FileVault's pre-boot authentication happens before the agent (and the login-window restriction) ever runs.** A standard user who knows the FileVault password can still unlock the disk at the pre-boot screen; the restriction only takes effect once macOS itself reaches the login window. The same caveat applies to lost mode's message on the FileVault screen.
- No supported API lets a root daemon force a lock without MDM (same as `lock_device`/lost mode); Suspend sign-in narrows *who* can sign in, it does not lock an already-signed-in session shut.

### Manual recovery

If the agent is unreachable or broken and you need to get a local admin back in by hand:

**Windows.** Open **Local Security Policy** (`secpol.msc`) → **Local Policies → User Rights Assignment**, and add the accounts back to **Allow log on locally** and **Allow log on through Remote Desktop Services**. To see exactly who held each right before suspension, read `C:\ProgramData\CNAPP Agent\signin.json`'s `previous.logon_restriction.holders` (one array of SID strings per right) - or run `cnapp-agent status` (elevated) to confirm whether sign-in is even suspended (`signin.active`, `signin.since`, `signin.incident_id`). If `signin.json` itself is unreadable (corrupt state, disk issue), fall back to a stock Windows workstation's defaults rather than guessing: **Allow log on locally** = `Administrators`, `Users`, `Backup Operators`; **Allow log on through Remote Desktop Services** = `Administrators`, `Remote Desktop Users`. Confirm against your own gold image or GPO baseline where one exists, since a domain policy may have set different defaults before the device was ever suspended.

**macOS.** Check the current state with `sudo dscl . -read /Groups/com.apple.access_loginwindow NestedGroups GroupMembers GroupMembership`.

- **Quick unblock:** `sudo dseditgroup -o delete com.apple.access_loginwindow`. macOS allows everyone at the login window when that group doesn't exist at all, so this always restores normal sign-in immediately - it's also exactly what *Restore sign-in* itself does when the group didn't exist before suspension. (The opposite command, `dseditgroup -o edit -a admin -t group com.apple.access_loginwindow`, is what **Suspend** does: running it manually keeps standard users blocked, it does not undo the suspension.)
- **Exact restore** (matches what *Restore sign-in* does): read `previous.logon_restriction` from `/Library/Application Support/CNAPP Agent/signin.json`. If `group_existed` is `false`, the quick unblock above is the exact restore too. Otherwise: `sudo dseditgroup -o edit -d admin -t group com.apple.access_loginwindow` (removes the nesting Suspend added), then re-add every original member recorded in that snapshot - `sudo dseditgroup -o edit -a <name> -t user com.apple.access_loginwindow` for each entry in `user_members` and each `members` entry with `is_group: false`, or `-t group` for each `members` entry with `is_group: true` and each entry in `nested_groups` (this naturally re-nests `admin` too if it was already a member before suspension, and does nothing extra if it wasn't).
- **Verify:** re-run the `dscl -read` command above and compare its `NestedGroups`/`GroupMembers`/`GroupMembership` against `previous.logon_restriction`; a standard user should be able to reach the login window normally.

In both cases, uninstalling the agent (`uninstall --purge` or an ordinary uninstall) also attempts to restore sign-in first, mirroring lost mode's uninstall behavior.

### Hardware checklist (not exercised in CI)

CI's real-runner integration tests (`windows-latest` under the runner's own administrator account; `macos-latest` **as root**, via `sudo` - see [Testing](#testing) below) confirm the actual LSA rights and `com.apple.access_loginwindow` group state, but a few things only a real interactive session can show:

- **Windows:** sign in locally **and** over RDP as the admin while suspended (desktop renders normally, not just that `LogonUser` succeeds); a standard, domain and Entra user is refused at both; the suspended-sign-in message appears at Winlogon before the credential prompt; a reboot during suspension keeps it suspended; restore brings everything back, including RDP for the previously-refused accounts.
- **macOS:** a standard user is refused at the login window; the admin is allowed in; the **FileVault-unlock-then-login-window** sequence behaves as documented above; restore works exactly, including when `com.apple.access_loginwindow` did not exist before suspension (it is removed again, not left empty).

### RBAC

Unlike [remote wipe](#remote-wipe-windows) and medium/high-risk [approved scripts](#approved-scripts), Suspend sign-in needs **no two-person approval**: it is reversible and fully audited, the same as [lost mode](#lost-mode), not a destructive or hard-to-undo action. An **analyst** can suspend sign-in immediately with a reason (typed hostname required, mirroring lost mode's enable step); only an **admin** can restore it.

## Remote wipe (Windows)

**Windows only.** Erasing a Mac requires a real Apple MDM (`EraseDevice` over APNs), which this product deliberately does not have; the console does not offer wipe for macOS and explains why.

**How it works.** The agent (LocalSystem) calls the **MDM Bridge WMI provider**: namespace `root\cimv2\mdm\dmmap`, class `MDM_RemoteWipe` (instance `ParentID='./Vendor/MSFT'`, `InstanceID='RemoteWipe'`), which exposes the RemoteWipe CSP to SYSTEM without MDM enrollment:

| Mode | Method | Behaviour |
|---|---|---|
| `protected` (**default**) | `doWipeProtectedMethod` | "Reset this PC - remove everything", cleaning the drive. Unlike `doWipe` it **keeps trying after a power cycle**, so switching the device off does not stop it. Microsoft warns that some device configurations may be left unable to boot. |
| `standard` | `doWipeMethod` | the same reset, but it can be stopped by power-cycling during the reset |
| (not offered) | `doWipePersistUserDataMethod` | keeps user data: not a wipe of a lost device |

**Prerequisites** (reported with every check-in as posture check `remote_wipe`, shown on the device page): the Windows Recovery Environment must be **enabled** (`reagentc /info`; `reagentc /enable` fixes it), the `MDM_RemoteWipe` class and the method must exist (the RemoteWipe CSP documents `doWipeProtected` from Windows 10 1703; Microsoft lists Pro, Enterprise and Education; the agent reports the edition and whether the class and methods are present, so check the device page rather than assume), and the device must have **opted in**. A reset can take an hour or more. Using the WMI bridge without MDM enrollment is a widely used, but not formally documented, way to trigger the CSP: **test it on a spare device of each model/edition** before relying on it. The agent, its credential and every user file are removed by the reset.

**Safety controls**

- **Install-time opt-in, off by default.** Only devices installed with `CNAPP_ALLOW_WIPE=1` (MSI property; or the *Allow remote wipe* option of a pre-configured installer, or `cnapp-agent configure --allow-wipe=1` as administrator) can be wiped. The opt-in lives in `policy.json` in the protected state directory (SYSTEM/Administrators only); **no server command can write it**, so a compromised server cannot wipe devices that did not opt in. `CNAPP_ALLOW_WIPE=0` opts out; an upgrade without the property keeps the setting.
- **Two-person approval** (always), with the device name typed by the requester **and** the approver.
- **Short validity window, single use.** The approved command expires after `DEVICE_WIPE_COMMAND_TTL_MINUTES` (60; the device must be online by then, or request again). The agent refuses wipe commands whose validity window exceeds 24 h, that name another hostname, or that it has already executed (command ids are recorded before execution; the server hands a command out once and accepts one acknowledgement and one result).
- **Final acknowledgement.** Before calling the method the agent sends `POST /api/agent/commands/{id}/ack`; it only wipes when the server confirms. The console then shows **Wipe pending** (`wipe.status`: `queued` -> `acknowledged` -> `started`; `device_state: "wipe_pending"`), even if the device never reports again.
- Nothing from the server reaches the PowerShell that calls WMI: the method name is one of two constants.

**After a wipe** the device record stays (state *Wipe pending / started*) for your asset records; revoke and delete it when the hardware is disposed of or re-imaged (a reset device enrolls as a new machine).

**Testing.** CI never calls the method. Unit tests drive the whole command path with a fake WMI executor (opt-in, hostname, validity window, WinRE, ack-before-wipe, replay), and on `windows-latest` CI runs `cnapp-agent wipe-readiness` **as SYSTEM** (scheduled task) and checks that `MDM_RemoteWipe` exposes `doWipeMethod` and `doWipeProtectedMethod`. Try a real wipe on a spare device before relying on it.

## Remote sessions (Windows)

IT support can **view**, and with permission **control**, the screen of a managed Windows device to help the
signed-in user: **Devices > device > Remote session**. Sessions are **attended**: nothing is shared until the user
clicks **Allow**, a banner stays on their screen for the whole session, and they can end it at any time. Version 1 is
screen view plus keyboard and mouse. Clipboard, file transfer and session recording are not part of it, and the screen
is never stored.

**Windows only for now.** macOS and Linux agents refuse the command with `ERR_UNSUPPORTED_PLATFORM` (audited as
`remote_session_failed`), and the console disables the button with a "Windows only for now" tooltip. See
[Future work](#future-work-remote-sessions).

### Flow

```mermaid
sequenceDiagram
  participant V as Viewer (browser)
  participant API as Backend API
  participant R as Relay (1 process)
  participant S as Agent service (SYSTEM)
  participant H as Helper (user session)
  V->>API: POST /api/devices/{id}/remote-sessions (mode, reason)
  API-->>V: session (requested) + start_remote_session queued
  V->>R: wss /api/remote/{sid} (cookie, Origin)
  S->>API: GET /api/agent/commands (poll, ~60 s)
  API-->>S: command + single-use token (minted now, 2 min)
  S->>R: wss /api/agent/remote/{sid} (device credential + token)
  S->>H: CreateProcessAsUser + named pipes (SYSTEM + user only)
  H->>H: consent prompt (name, email, organisation, mode, reason)
  H-->>S: Allow
  S-->>R: consent allow, then tiles
  R-->>V: tiles (JPEG) / state
  V-->>R: input (View and control only), acks
  R-->>S: input
  S-->>H: input (SendInput)
```

1. An **analyst** (View only) or **admin** (View and control) clicks **Remote session**, picks the mode and enters a
   reason (3-500 characters, like every remote action). The backend records a `remote_sessions` row and queues a
   `start_remote_session` command. The console shows "Waiting for the device": commands are delivered by polling,
   about every 60 seconds; the poll interval is not shortened for this.
2. When the agent polls, the server **mints the single-use session token** (valid `REMOTE_SESSION_TOKEN_TTL_SECONDS`,
   120 s) and stores only its SHA-256. The token is never in the command's stored parameters, so it is not visible in
   the console's Commands tab.
3. The agent checks the command like any other: allowlist, device binding, nonce, expiry and replay protection. It
   checks that someone is signed in and the screen is unlocked (`ERR_NO_ATTENDED_USER` otherwise; unattended access is
   not supported). Then it dials `wss://<enrolled server>/api/agent/remote/{id}`. The URL always comes from the
   enrolled server URL, never from the command; redirects are refused; and when the agent was enrolled with a CA, only
   that CA is trusted.
4. The service starts the **helper** (`cnapp-agent remote-helper`) in the user's session, which shows the **consent
   prompt** with the requester's name and email, the organisation, the mode and the reason. **Deny**, or no answer
   within `REMOTE_SESSION_CONSENT_TIMEOUT_SECONDS` (60), ends the session as `denied` (audited).
5. On **Allow**, an always-on-top banner reads "IT support (name) is viewing / controlling your screen" with **End
   session**, and capture starts.

Both sides dial **out** to the server; neither accepts inbound connections. The relay pairs the two sockets and
forwards their messages.

### What runs where

| Piece | Where | Notes |
|---|---|---|
| Relay | the `relay` compose service (backend image, **one** process: `python -m app.relay_main`) | Pairs the agent's and the viewer's WebSocket **in memory**, so both ends must reach one process. Agents arrive on `:8001` and viewers on `:8002`, two listeners of that process, each refusing frames over its own size cap before buffering them. The gunicorn backend runs `REMOTE_RELAY_MODE=api` and refuses these paths. Chosen over PostgreSQL `LISTEN/NOTIFY` (8 KB payloads would chunk every tile) and Redis (not part of the stack). |
| Service | `cnapp-agent` as LocalSystem | Never captures. Owns the relay socket (the helper never sees the device credential or the token) and enforces the rules locally: no frame before consent, input dropped in View only mode, consent / idle / hard limits, session switch and lock. |
| Helper | `cnapp-agent remote-helper`, started with `CreateProcessAsUser` on `winsta0\default` of the attended session, inside a **kill-on-close Job object** | Consent prompt, banner, DXGI Desktop Duplication capture (GDI fallback), `SendInput`. Talks to the service over two one-way named pipes with a DACL for SYSTEM and that user only, `FILE_FLAG_FIRST_PIPE_INSTANCE` and `PIPE_REJECT_REMOTE_CLIENTS`; the service accepts only the process it started (client PID), and the helper only a SYSTEM-owned pipe. Parameters go over the pipe, never on the command line, so a local user cannot start a capture session for someone else. |

### Screen and input

* **Encoding:** JPEG tiles of the changed regions of the active monitor (64 px grid, merged runs), capped at
  `REMOTE_SESSION_MAX_FPS` (15). The viewer acknowledges each frame. With more than 3 frames unacknowledged, capture
  pauses and JPEG quality drops, then recovers. We chose this over WebRTC (H.264 with Pion): it needs no ICE/STUN/TURN,
  no codec licensing and no third-party relay, it fits the existing CSP (`connect-src 'self'`), and Go's standard
  library encodes JPEG (it has no WebP encoder) while browsers decode it natively (`createImageBitmap`).
* **Monitors and DPI:** the helper is per-monitor DPI aware (physical pixels). The viewer has a monitor picker and
  shows each monitor's resolution and scale.
* **Input (View and control only):** keys are sent as the browser's `KeyboardEvent.code` and replayed as
  layout-independent scan codes, so shortcuts work as pressed (Ctrl+C, Alt+Tab, Win+E, Shift+arrows). Mouse positions
  are relative to the active monitor. The viewer captures the keyboard only after a click on the screen and shows how
  to release it (**Ctrl+Alt+Shift**). Pointer moves are merged into one message per animation frame, well under the
  relay's limit.
* **Nothing stays pressed.** Every click carries a position: the viewer sends none from the letterbox bars, and the
  helper drops a click without one rather than clicking at the user's own cursor. A press captures the pointer, so its
  release arrives even when the drag leaves the image. Keys and buttons still held are released when the viewer's
  window loses focus or closes, and the helper releases everything it pressed for the viewer when the session stops.
* **Input is dropped in View only mode** by the relay, by the service and by the helper, whatever the server or
  browser sends.
* **Ctrl+Alt+Del** is a toolbar button. The service sends it with `sas.dll!SendSAS`, which Windows only honours when
  the **SoftwareSASGeneration** policy allows services (Group Policy: *Computer Configuration > Administrative
  Templates > Windows Components > Windows Logon Options > Disable or enable software Secure Attention Sequence* =
  *Services*, or registry `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SoftwareSASGeneration` =
  `1` or `3`). The agent never changes this policy; without it the button reports an error.
* **Protected desktops:** the UAC secure desktop and the sign-in / Ctrl+Alt+Del screen are **not** captured in v1.
  While one is shown, the viewer says "the user's screen is on a protected prompt" and resumes when it closes.
* **The banner cannot be dismissed by the viewer.** The prompt and banner windows never take focus (`WS_EX_NOACTIVATE`),
  so injected keys such as Alt+F4 reach the foreground application, never them. Injected clicks on them are dropped,
  and they re-assert "topmost" every second.
* **Consent cannot be forged.** **Allow** and **Deny** act only on a press and a release on the same button, both from
  a real mouse, touch screen, pen or touchpad (`GetCurrentInputMessageSource`): another program of the user posting
  `WM_LBUTTONUP`, or `SendInput`, does not answer the prompt. Clicks in the first second after the prompt appears are
  ignored, so a click already on its way does not allow anything. **End session** needs a press and release on it,
  from any source: ending stays easy, also with assistive tools. If the banner is closed, destroyed or hidden anyway, the session ends
  (`indicator_closed`); it is never silently re-created.
* **End session** on the banner stops capture and input at once in the helper, then tells the service. It works even
  when the server is unreachable.

### Limits and termination

A session ends, and both WebSockets, the helper process, the prompt and the banner are torn down, when:

* the viewer, the user (End session) or an admin (`POST /api/remote-sessions/{id}/end`, any session in the
  organisation) ends it;
* nobody uses the viewer for `REMOTE_SESSION_IDLE_TIMEOUT_MINUTES` (15). Mouse, keyboard and activity heartbeats count;
  frame acknowledgements do not;
* it reaches `REMOTE_SESSION_MAX_DURATION_MINUTES` (120) after the user allowed it;
* the device is revoked, put in lost mode, isolated (Suspend sign-in) or a wipe is requested;
* the requester's account is disabled, removed from the organisation or loses the role the mode needs;
* the viewer's sign-in session ends: sign-out, sign-out everywhere, a password reset, or its expiry or idle timeout
  (`viewer_session_revoked`; activity in the viewer counts as use of the sign-in session);
* the user switches Windows user, disconnects the RDP session or locks the screen;
* the agent stops, the device disconnects or the relay restarts (`relay_restart`: a `cnapp-ctl update`, rollback or
  restore restarts it, which **ends live sessions**).

The relay re-checks every live session every `REMOTE_SESSION_RECHECK_SECONDS` (5): an end through the API, a revoke or
a role change closes both sockets within about 5 s. The agent applies the idle and hard limits locally too, capped at
2 h idle and 8 h overall whatever the server sends.

**Concurrency:** one open session per device (a unique key on the open session), at most
`REMOTE_SESSION_MAX_PER_ORG` (5) open sessions per organisation (creates lock the organisation row, so racing requests
cannot both pass the cap), and one viewer and one agent socket per session. A relay that stops writing heartbeats for
three re-checks (at least 60 s) is presumed gone, and its sessions end as `relay_lost`.

### RBAC, audit, notifications

| Role | Can |
|---|---|
| viewer | see the session history (History tab) |
| analyst | start **View only** sessions, view and end their own |
| admin | start **View and control** sessions; end anyone's session |

Only the requester watches a session. Another organisation's device or session is 404, through the API and through
both WebSockets.

Every transition is audited with the requester, device, mode, reason, client IP (the trusted-proxy address, as for the
REST API), timestamps, duration and byte counts:

* `remote_session_requested`, `remote_session_consented`, `remote_session_denied` (with `user_denied` or
  `consent_timeout`), `remote_session_started`;
* `remote_session_ended`, with the end reason;
* `remote_session_failed`, with the error code: `ERR_NO_ATTENDED_USER`, `ERR_UNSUPPORTED_PLATFORM`,
  `ERR_DEVICE_TIMEOUT` (never polled in time), `ERR_TOKEN_EXPIRED`, `ERR_HELPER` and similar.

The **Remote sessions** notification source (`remote_session`: requested, started, denied, ended, failed) routes them to
Teams, Slack or email like any other source ([NOTIFICATIONS.md](NOTIFICATIONS.md)). The device page's History tab lists
every session: who, when, how long, mode and outcome.

**Privacy:** frame content and keystrokes are never logged or stored. Only metadata, byte counts and durations are
kept.

### Security

* **Both ends are authenticated.** The agent socket uses the device credential and the single-use token; a wrong,
  expired or replayed token is refused (close codes 4401, 4410, 4409), and so is a second connection. The viewer
  socket uses the session cookie plus an **Origin** check. In production only the server's own origin is accepted (the
  `Host` the browser sent, or `PUBLIC_BASE_URL`); in development, explicit `CORS_ORIGINS` entries are accepted too
  (never `*`).
* **Message size and rate limits:** agent messages at most `REMOTE_SESSION_AGENT_MAX_MESSAGE_BYTES` (1 MiB) and
  `REMOTE_SESSION_AGENT_MAX_BYTES_PER_SECOND` (8 MiB/s); viewer messages at most
  `REMOTE_SESSION_VIEWER_MAX_MESSAGE_BYTES` (16 KiB) and `REMOTE_SESSION_VIEWER_MAX_MSGS_PER_SECOND` (120/s). Bursts of
  twice the rate are allowed; beyond that the session ends. Each end has its own relay listener whose uvicorn
  `ws_max_size` refuses a much larger frame before it is buffered. A send to a peer that stopped reading gives up after
  5 s, so one stuck socket cannot stall the other. Ends caused by the viewer (disconnect, rate limit, protocol error)
  are audited with the viewer's IP, the others with the device's.
* **The helper is not trusted beyond its job.** It runs as the signed-in user, so the service forwards only known end
  reasons and error codes from it, cuts its error text to 200 characters, and rebuilds every forwarded message with the
  fields of its type only.
* **Commands are not cryptographically signed.** `start_remote_session` is trusted like every remote action: TLS to the
  enrolled server (pinned CA when enrolled with one), the per-device credential, the allowlist and parameter
  validation, device binding, a nonce, expiry and anti-replay. A server compromise could therefore ask for a session,
  but the user must still allow it on their own screen, and the banner shows who is watching.
* **nginx** upgrades only `/api/remote/{id}` (internal networks, like the console) and `/api/agent/remote/{id}` (like the
  rest of the agent API), with long read timeouts on these two paths only. The CSP stays `default-src 'self'`.

### Setup

Nothing to configure on devices: agents that support it advertise `remote_session` (Windows builds), and the button is
enabled when the device runs one. On-prem, `cnapp-ctl install` / `update` start the `relay` service. Optional: allow
Ctrl+Alt+Del with the SoftwareSASGeneration policy (above).

**Azure / Container Apps is not supported in v1.** The relay needs one process for both ends, and the Azure template
runs up to two backend replicas without a relay app. The Bicep template sets `REMOTE_SESSION_ENABLED=false`, and a
backend in `REMOTE_RELAY_MODE=all` with `WEB_CONCURRENCY` above 1 offers no remote sessions either (the button says why).
Use the on-prem stack.

### Hardware checklist (Windows, not exercised in CI)

GitHub-hosted runners have no interactive session to capture, so CI uses a `-tags remote_fake` build. Check on real
hardware before relying on it:

- [ ] consent prompt: **Allow** starts the session; **Deny** and no answer (60 s) end it as denied; a click on
      **Allow** within the first second after it appears does nothing
- [ ] a program of the user posting a click (`PostMessage(WM_LBUTTONUP)`) or `SendInput` on **Allow** does not answer
      the prompt; **End session** still works with the on-screen keyboard or another assistive tool
- [ ] hold Ctrl (or a mouse button) in the viewer and close the tab: nothing stays pressed on the device
- [ ] the banner stays visible and on top (full-screen apps, Win+D, moving windows); Alt+F4 from the viewer does not
      close it; closing it with Task Manager ends the session
- [ ] multi-monitor: the picker switches monitors, positions are right on monitors with different scaling
- [ ] typing and shortcuts (Ctrl+C / Ctrl+V, Alt+Tab, Win+E, Shift+arrows, AltGr on a non-US layout)
- [ ] Ctrl+Alt+Del button with the SoftwareSASGeneration policy set, and the error without it
- [ ] a UAC prompt shows "the user's screen is on a protected prompt", and the view resumes afterwards
- [ ] **elevated windows:** an elevated ("Run as administrator") window can be seen but not clicked or typed into
- [ ] the user's **End session** works, also with the network cable unplugged (capture stops at once)
- [ ] fast user switching, RDP disconnect and locking the screen end the session
- [ ] afterwards no `cnapp-agent.exe remote-helper` process is left in Task Manager (also after killing the service)
- [ ] View only: mouse and keyboard in the viewer do nothing on the device

### Future work (remote sessions)

* **macOS:** a signed Swift helper app (ScreenCaptureKit, `CGEventPost`) launched as a per-user LaunchAgent, behind
  the same platform interface (`internal/remote`). It needs a guide to Screen Recording and Accessibility (TCC)
  permissions: the user grants them once, or an MDM PPPC profile lets standard users approve Screen Recording
  (`AllowStandardUserToSetSystemService`) and pre-approves Accessibility for the helper's code signature. It also
  needs posture reporting of the permission state, so the console can say "remote control not available: Screen
  Recording not granted" before a session starts.
* **Unattended access** (nobody signed in, locked screen): only as an install-time opt-in like `allow_wipe`, with
  two-person approval.
* Capturing the secure desktop (UAC, sign-in screen), clipboard, file transfer, session recording.
* A relay for the Azure deployment (a single-replica relay app).

## Approved scripts

Admins can run **approved scripts** from a signed library on a device (**Devices > device > Run script**, or **Devices > Scripts** for the library and run history): Windows PowerShell or macOS zsh/bash, run as SYSTEM / root with a timeout, the exit code and truncated stdout/stderr returned. Scripts live in [`device-scripts/`](../device-scripts) and only change by reviewed pull request; a tag `scripts-vX.Y.Z` signs them with the **script-signing key** (separate from the agent release key) and the server imports the bundle. Read-only scripts marked `risk: low` run with one admin; `medium` / `high` need a second admin. Full guide, threat model and setup: **[DEVICE_SCRIPTS.md](DEVICE_SCRIPTS.md)**; why this keeps the agent bounded: **[ADR-0001](ADR-0001-signed-device-scripts.md)**.

## Security model

- **Outbound-only pull model.** No inbound ports on endpoints. A compromised server cannot push code: it can only queue the allow-listed actions above, which the agent validates itself; it cannot forge an approved script (the agent verifies the script-signing key compiled into it and the script hash) nor wipe a device that did not opt in locally.
- **Enrollment tokens** are 256-bit random values (`cne_...`). Only their SHA-256 is stored. They are single- or multi-use with a maximum count, expire, can be revoked, and are used up atomically, so concurrent enrollments cannot exceed the limit. Enrollment is rate-limited per client IP.
- **Per-device credentials** are 256-bit random secrets (`cnd_...`) issued at enrollment. The server stores only their SHA-256, unique-indexed for lookup. A random 256-bit secret cannot be brute-forced, so a slow hash adds nothing, and unlike the session HMAC this does not depend on `SESSION_SECRET` (rotating that secret does not cut off devices). Credentials are rotated on re-enrollment and revoked server-side.
- **Credential storage on the device:**
  - Windows: `%ProgramData%\CNAPP Agent\state.json`. The directory gets a **protected DACL** granting full control to `SYSTEM` and `BUILTIN\Administrators` only (`D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`), with no ACEs inherited from ProgramData.
  - macOS: `/Library/Application Support/CNAPP Agent/state.json`, owned by root, file `0600`, directory `0700`.
  - The file is written atomically (temp file and rename).
- **Separate authentication planes.** `/api/agent/*` only accepts `Authorization: Bearer cnd_...` and never reads cookies, so there is no CSRF surface. `/api/devices/*` and every other user API only accept a user session (with CSRF on writes) and RBAC. A device credential cannot call user APIs, a session cannot act as a device, and the sensor ingest token is not a device credential. The tests cover all of these.
- **Transport.** HTTPS only (TLS 1.2+), the system trust store plus an optional `--ca-file` (or `CNAPP_CA_FILE`) for private PKI, copied into the protected state directory at enrollment, no redirects followed (so the credential cannot be sent elsewhere), and responses capped at 1 MiB. Plain http is possible only with the explicit `--insecure-dev` flag.
- **Strict input validation.** Agent payloads are validated by Pydantic models that reject unknown fields and limit every string, list and map: at most 10,000 software items, 40 posture checks and 16 KiB of data per check. `/api/agent/*` bodies are capped at 6 MiB (`AGENT_MAX_REQUEST_BYTES`; nginx allows 8 MiB on that path only) and other APIs stay at 1 MiB. Log bundles must be gzip and at most `DEVICE_LOG_BUNDLE_MAX_BYTES`. Each device is rate-limited (`DEVICE_RATE_LIMIT` requests per `DEVICE_RATE_WINDOW_SECONDS`).
- **No shells.** Collectors run fixed commands by absolute path with fixed arguments. PowerShell scripts are constants passed with `-EncodedCommand`, and nothing from the server is ever interpolated into them.
- **Agent logs** rotate at 5 MiB with one backup, in an owner-only directory.

## Service install, upgrade and uninstall

| | Windows | macOS |
|---|---|---|
| Install | MSI (above), or `cnapp-agent install` (elevated) | pkg (above), or `sudo cnapp-agent install` |
| Binary | `C:\Program Files\CNAPP Agent\cnapp-agent.exe` | `/usr/local/cnapp-agent/bin/cnapp-agent` |
| Service | `CNAPPAgent`, LocalSystem, automatic (delayed), restart on failure (5 s / 30 s / 2 min) | `/Library/LaunchDaemons/com.cloudsecurity.cnapp-agent.plist`, root, `RunAtLoad` + `KeepAlive` |
| State | `C:\ProgramData\CNAPP Agent\state.json` | `/Library/Application Support/CNAPP Agent/state.json` |
| Logs | `C:\ProgramData\CNAPP Agent\logs\agent.log` | `/Library/Logs/CNAPP Agent/agent.log` (+ `launchd.log`) |
| Pending enrollment | `C:\ProgramData\CNAPP Agent\enroll.json` (deleted after enrolling) | `/Library/Application Support/CNAPP Agent/enroll.json` (same) |
| Upgrade | **automatic**: signed releases in rollout rings with automatic rollback ([AGENT_UPDATES.md](AGENT_UPDATES.md)); or a newer MSI (keeps identity), or the new binary's `install` | **automatic** (same); or install the new `.pkg`, or the new binary's `install` |
| Uninstall | `msiexec /x` / Apps & features (MSI), or `packaging\windows\uninstall.ps1 [-Purge]` / `cnapp-agent uninstall [--purge]` | `sudo /usr/local/cnapp-agent/bin/cnapp-uninstall.sh`, or `sudo cnapp-agent uninstall [--purge]` |

`--purge` also deletes the credential and logs. Revoke or delete the device in the console as well.

**Auto-update.** The service installs agent releases that an admin imported and
assigned to its rollout ring (Devices > Agent updates), but only if the release
manifest is signed by a release key compiled into the agent; the CNAPP server
cannot sign anything itself. A new version that does not check in successfully
is rolled back automatically. Setup (signing key, GitHub secret), release
process, rings and the interaction with MSI/GPO deployments:
**[docs/AGENT_UPDATES.md](AGENT_UPDATES.md)**.

Other commands: `configure` (store a pending enrollment for the service: `--server URL --token-stdin [--ca-file PEM | --ca-b64 B64]` or `--from-file enroll.json`; a no-op on an enrolled device), `purge` (delete credential, pending enrollment and logs), `install --wait-for-enrollment` (install the service before any enrollment), `status`, `inventory --print [--no-software]`, `checkin` (one check-in and command poll now), `run` (foreground loop, which is what the service runs) and `version`.

## Packaging and code signing

CI produces:

- **`cnapp-agent-binaries`**: static (`CGO_ENABLED=0`) binaries for `windows/amd64`, `windows/arm64`, `darwin/amd64` and `darwin/arm64`, plus `install.ps1`, `uninstall.ps1`, `install.sh` and `SHA256SUMS`;
- **`cnapp-agent-macos-pkg`**: an unsigned universal (`lipo`) `.pkg` built with `pkgbuild` on the macOS runner;
- **`cnapp-agent-windows-msi`**: the generic x64 MSI (`endpoint-agent/packaging/windows/msi/cnapp-agent.wxs`, WiX Toolset v5, built on the Windows runner by `build-msi.ps1`).

The two installers are also **bundled into the backend image** (`backend/installers/` with a `manifest.json` of their SHA-256, checked before every use), so pre-configured downloads work offline on-prem. To serve your own (e.g. signed) generic builds instead, put them with a matching `manifest.json` in a directory and set `AGENT_INSTALLERS_DIR`; remember a pre-configured download of a signed MSI/pkg is no longer validly signed.

**How the enrollment is injected** (`backend/app/services/installers.py`):

- **MSI**: the generic MSI carries a hidden property `CNAPP_PRESET` whose value is a fixed-length (16,000 character) placeholder. The server overwrites exactly those bytes of the MSI's string data with `CNAPPPRESET:v1:<base64 enroll.json>` padded to the same length, and replaces the package code (a same-length GUID in the summary information), in pure Python (`msipatch.py`, `olefile`). Nothing changes size or position, so tables, row order, the cabinet and file hashes stay exactly as WiX built them (rewriting MSI tables with a generic library proved fragile: msitools' `msibuild` reused freed string ids, leaving the `Property` table unsorted, which Windows Installer then refused to query). The MSI's deferred custom action (as SYSTEM, target hidden from logs) runs `cnapp-agent configure`, which prefers explicit `CNAPP_SERVER`/`CNAPP_TOKEN`/`CNAPP_CA_B64` properties, otherwise decodes the preset, validates it and writes the protected `enroll.json`; with neither (generic MSI) it does nothing and the service waits.
- **pkg**: the component package's `Scripts` archive (gzip cpio) gets `enroll.json` added next to `postinstall`; the xar container is rewritten in pure Python (`pkgtools.py`, TOC checksums recomputed, any signature removed). The `Payload` and `Bom` are copied byte-for-byte. The postinstall hands the file to `cnapp-agent configure`.

Signing needs your organization's certificates, so it is a **manual** step:

**Windows (Authenticode).** With a code-signing certificate (ideally EV, or Azure Trusted Signing):

```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a cnapp-agent-windows-amd64.exe
signtool verify /pa cnapp-agent-windows-amd64.exe
# Optionally sign the installer scripts as well:
Set-AuthenticodeSignature -FilePath install.ps1 -Certificate (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)[0] -TimestampServer http://timestamp.digicert.com
```

Then build the MSI from the signed binary and sign the MSI (`build-msi.ps1` shows the `signtool` lines), or deploy with `install.ps1 -RequireSignature`.

**macOS (Developer ID + notarization).** With a *Developer ID Application* and a *Developer ID Installer* certificate in the keychain:

```bash
lipo -create -output cnapp-agent cnapp-agent-darwin-amd64 cnapp-agent-darwin-arm64
CODESIGN_IDENTITY="Developer ID Application: Example Corp (TEAMID)" \
PKG_SIGN_IDENTITY="Developer ID Installer: Example Corp (TEAMID)" \
  endpoint-agent/packaging/macos/build-pkg.sh 0.1.0 cnapp-agent cnapp-agent-0.1.0.pkg
xcrun notarytool submit cnapp-agent-0.1.0.pkg --keychain-profile <profile> --wait
xcrun stapler staple cnapp-agent-0.1.0.pkg
```

`build-pkg.sh` signs the binary with the hardened runtime and a timestamp, and signs the package, when those variables are set. Unsigned builds work. Downloaded files carry the quarantine attribute, which the instructions remove, and Gatekeeper blocks double-clicking an unsigned `.pkg`; `sudo installer -pkg` from Terminal still works.

Publish signed builds somewhere your devices can reach (an internal share or release page) for manual installs. `AGENT_DOWNLOAD_URL` is still accepted and returned by `GET /api/devices/enrollment/info`, but the console no longer shows it: the **Download installer** button is the primary path.

## API reference

Agent API (device credential):

| Method & path | Body / response |
|---|---|
| `POST /api/agent/enroll` | `{token, device:{hostname, os_family, os_name, os_version, serial_number, machine_id, agent_version}}` → `{device_id, device_secret, check_in_interval_seconds, command_poll_seconds, server_time, reenrolled}` |
| `POST /api/agent/checkin` | `{schema_version:1, collected_at, device:{...}, posture:{name:{status,detail,error,data}}, software:[...] or null, errors:{}}` → `{device_id, server_time, pending_commands, issues}` |
| `GET /api/agent/commands` | → `{server_time, commands:[{id, device_id, type, params, nonce, issued_at, expires_at}]}` |
| `POST /api/agent/commands/{id}/result` | `{nonce, status: succeeded / failed / rejected, output, result_data?}` → 204. `result_data` is `isolate_host`/`restore_host` only (pre-flight findings, crash-recovery outcome); any other command type sending a non-empty one gets 422, and each of those two is validated against its own strict schema (unknown keys rejected) |
| `POST /api/agent/commands/{id}/logs` | gzip body, header `X-Command-Nonce` → `{id, size_bytes, sha256}` |
| `POST /api/agent/commands/{id}/ack` | `wipe_device` only: `{nonce}` → `{proceed: true}` (once; the agent wipes only after it) |
| `GET /api/agent/scripts/bundles/{id}/manifest`, `GET .../scripts/{name}` | signed script manifest envelope; script bytes (only while a `run_script` is delivered to the device) |

User API (session; viewer unless noted): `GET /api/devices` (filters `q`, `os`, `health`, `issue`, `connectivity`, `status`), `GET /api/devices/summary`, `GET /api/devices/issue-types`, `GET /api/devices/{id}`, `.../software?q=`, `.../history`, `.../commands`, `POST .../commands` (role per action, `{type, reason, params}`), `POST .../commands/{cid}/cancel` (same role as the action), `GET .../log-bundles/{bid}` (analyst), `POST .../revoke` and `DELETE /api/devices/{id}?reason=` (admin), and `GET/POST /api/devices/enrollment-tokens`, `POST .../enrollment-tokens/{id}/revoke` and `GET /api/devices/enrollment/info` (admin). Device detail also returns `lost_mode`, `wipe` and `isolation` (Suspend sign-in: status, since, requested-by, agent-reported state, pre-flight readiness, crash-recovery outcome), and every device `device_state` (`active` / `lost` / `wipe_pending` / `isolated` / `revoked`). `POST /api/devices/{id}/wipe` (admin, `{reason, confirm_hostname, mode: protected|standard}`) creates an approval request.

Approvals (admin): `GET /api/approvals?status=open|pending|approved|final|all&device_id=`, `GET /api/approvals/summary` (badge counts + settings), `GET /api/approvals/{id}`, `POST .../{id}/approve` (`{reason?, confirm_hostname?}`), `POST .../{id}/reject` and `.../cancel` (`{reason}`). Scripts: see [DEVICE_SCRIPTS.md](DEVICE_SCRIPTS.md#api).

Installers (admin; CSRF on POST; `AGENT_INSTALLER_RATE_LIMIT` downloads per admin per `AGENT_INSTALLER_RATE_WINDOW_SECONDS`):

| Method & path | Body / response |
|---|---|
| `GET /api/devices/installers` | → `{server_url, server_error, ca_configured, include_ca_default, platforms:{windows-msi|macos-pkg:{available, version, label, filename, reason}}, defaults}` (never a token) |
| `POST /api/devices/installers` | `{platform: "windows-msi" | "macos-pkg", expires_in_days: 1-365 [30], max_devices: 1-100000 [500], device_group?, name?, include_ca?: bool (null = when configured)}` → the file (`Content-Disposition: attachment`, `Cache-Control: no-store`, headers `X-Content-SHA256`, `X-Enrollment-Token-Id`, `X-Agent-Version`, `X-CA-Included`). 409: `PUBLIC_BASE_URL` missing / not https, or CA requested but none configured; 503: base installer not bundled or checksum mismatch; 429: rate limit. |

## Configuration

Backend environment variables (defaults in brackets): `AGENT_MAX_REQUEST_BYTES` [6 MiB], `DEVICE_LOG_BUNDLE_MAX_BYTES` [5 MiB], `DEVICE_RATE_LIMIT` [120] per `DEVICE_RATE_WINDOW_SECONDS` [600], `ENROLL_RATE_LIMIT` [300] and `ENROLL_FAILURE_LIMIT` [20] (a stricter budget counted only on failed attempts), both per `ENROLL_RATE_WINDOW_SECONDS` [600], `DEVICE_STALE_HOURS` [24], `DEVICE_INACTIVE_DAYS` [7], `DEVICE_UPDATES_GRACE_DAYS` [14], `DEVICE_AV_SIGNATURE_MAX_AGE_DAYS` [7], `DEVICE_HISTORY_LIMIT` [200], `DEVICE_COMMAND_TTL_HOURS` [24] and `AGENT_DOWNLOAD_URL` [unset]. Approvals and wipe: `DEVICE_APPROVAL_TTL_HOURS` [24], `DEVICE_APPROVAL_ALLOW_SELF` [false], `DEVICE_APPROVAL_SELF_COOLDOWN_MINUTES` [15], `DEVICE_WIPE_COMMAND_TTL_MINUTES` [60]. Scripts: `DEVICE_SCRIPT_TRUSTED_KEYS`, `DEVICE_SCRIPT_MAX_BUNDLE_BYTES` [512 KiB]. Migration `0009_device_approvals_scripts` adds the approval and script tables and the lost-mode / wipe columns. Suspend sign-in has no dedicated environment variables; migration `0014_host_isolation` adds the isolation-status columns and `0015_command_result_data` adds `device_commands.result_data`.

Remote sessions ([details](#remote-sessions-windows)): `REMOTE_SESSION_ENABLED` [true], `REMOTE_RELAY_MODE` [all; on-prem the backend runs `api` and the relay service `relay`], `REMOTE_SESSION_TOKEN_TTL_SECONDS` [120] (single-use agent token and command lifetime), `REMOTE_SESSION_CONSENT_TIMEOUT_SECONDS` [60], `REMOTE_SESSION_IDLE_TIMEOUT_MINUTES` [15], `REMOTE_SESSION_MAX_DURATION_MINUTES` [120], `REMOTE_SESSION_MAX_PER_ORG` [5], `REMOTE_SESSION_MAX_FPS` [15], `REMOTE_SESSION_AGENT_MAX_MESSAGE_BYTES` [1 MiB], `REMOTE_SESSION_VIEWER_MAX_MESSAGE_BYTES` [16 KiB], `REMOTE_SESSION_VIEWER_MAX_MSGS_PER_SECOND` [120], `REMOTE_SESSION_AGENT_MAX_BYTES_PER_SECOND` [8 MiB], `REMOTE_SESSION_RECHECK_SECONDS` [5]. Out-of-range values stop the server at start. Migration `0018_remote_sessions` adds the `remote_sessions` table.

Installers: `PUBLIC_BASE_URL` (required, https; embedded in installers), `AGENT_CA_CERT_B64` (base64 PEM of a private CA to embed; set by `cnapp-ctl` on-prem) or `AGENT_CA_CERT_FILE`, `AGENT_INSTALLERS_DIR` [`/app/installers`], `AGENT_INSTALLER_RATE_LIMIT` [10] per `AGENT_INSTALLER_RATE_WINDOW_SECONDS` [600], `AGENT_INSTALLER_MAX_PARALLEL` [2]. Migration `0005_agent_installers` adds the package/group columns.

**Azure deployment.** No infrastructure change is needed. Agents use the public frontend URL (`https://<frontend-fqdn>`). nginx proxies `/api/agent/*` to the internal backend with an 8 MiB body limit, and the Container Apps ingress needs nothing else. Per-IP enrollment rate limiting uses the real client IP through `TRUSTED_PROXY_CIDRS`. The database tables come with Alembic migration `0002_device_management`, applied automatically on startup.

## Testing

- **Backend** (`backend/tests/test_devices.py`, on SQLite and PostgreSQL in CI): enrollment (single/multi-use, expiry, revocation, rate limit, re-enrollment and credential rotation), authentication isolation in both directions, revoked-device rejection, strict check-in validation and size limits, issue and health derivation, command RBAC, server-side allowlist and parameter validation, expiry, at-most-once delivery, device binding, nonces, log-bundle upload, size cap and download RBAC, audit entries, and delete cascade.
- **Agent** (`go test ./...`): fixture-based parser tests for every Windows and macOS collector (they run on any OS, see `endpoint-agent/testdata/`), including PowerShell 5.1 JSON quirks; the command allowlist; validation and expiry; backoff and jitter; state file permissions; the HTTP client (https enforcement, no redirects); and an agent loop test against a fake server covering replay protection, the log bundle and revoked-device back-off.
- **CI on real `windows-latest` and `macos-latest` runners**:
  - `go vet` and `go test`;
  - the real collectors (`cnapp-agent inventory --print` must produce valid JSON with all posture checks and software);
  - `scripts/agent_e2e.py --service`, which starts the real backend, creates a token through the API, enrolls the agent, checks in, runs `recheck_posture`, `collect_logs` and `update_check_in_interval`, then **installs the real Windows service / LaunchDaemon**, waits for its check-in, sends `restart_agent` and verifies that the service manager restarts it, verifies the Windows state-directory ACL, uninstalls, re-enrolls, revokes and checks that the agent is rejected.
  - The macOS leg also builds the `.pkg`.
- Release binaries are cross-compiled for all four targets.
- **Installers** (`backend/tests/test_installers.py`): pkg injection read back (enroll.json, untouched Payload/Bom), MSI injection read back with msitools' `msiinfo` (preset decodes to the config, same size, new package code, generic MSI unchanged), token limits / expiry / revocation, RBAC and CSRF, rate limit, configuration errors, tampered or missing base artifacts, audit detail, and that the plaintext token is in no database table. Agent: `internal/agent/autoenroll_test.go` (auto-enroll over TLS with the embedded CA, token deleted, idempotent on an enrolled device, rejected-token retry, waiting for a config) and `internal/state/enroll_test.go`.
- **Installer end-to-end** (`scripts/installer_e2e.py`): the CI `images` job builds the backend image with the bundled installers, runs it, and downloads a pre-configured MSI and pkg through the API (generated on Linux by the image's Python code; read back with msitools' `msiinfo` as an independent check). Then on real `windows-latest` and `macos-latest` runners the backend runs over HTTPS with a private CA on the same database, and the job installs the package silently (`msiexec /qn` / `installer -pkg`), checks the service is running, the device auto-enrolled (group label, CA trusted from the installer), the token file is gone and absent from the MSI log; re-installs/repairs without re-enrolling; uninstalls and checks service, files, state (and the pkg receipt) are gone; then repeats with the generic MSI + `CNAPP_*` properties and the generic pkg + `cnapp-agent configure`.

- **Approvals, lost mode, wipe, scripts** (`backend/tests/test_approvals_lost_wipe.py`, `test_device_scripts.py`): different-admin rule, self-approval off by default / typed name / cooling-off / cancel, expiry, RBAC, race-safe decisions, single-use wipe command + acknowledgement + replay, device state, notifications; bundle signature / tampering / expiry / anti-rollback / wrong signing context, typed parameter validation, low-risk direct runs vs approval. Agent: `internal/wipe` (fake WMI executor), `internal/lostmode` (fake notice backend, restore), `internal/scripts` (signature, hash, parameters, timeout and process-tree kill, output cap), `internal/agent/protect_test.go` (end to end against a fake server). The real e2e (`agent_e2e.py --script-key-file`) runs a signed script on the Windows and macOS runners, sets and restores the Windows legal notice, and checks a non-opted-in device cannot be wiped.
- **Suspend sign-in** (`backend/tests/test_host_isolation.py`): roles (analyst suspends, only admin restores), parameter validation (`incident_id` pattern), lifecycle and state transitions, failure/cancellation leaving the right state, `result_data` round-trip and its strict per-command-type schema (unexpected keys / wrong command type / oversized payload all rejected), the pre-flight-blocked path (`ERR_NO_LOCAL_ADMIN_PRESENT`) versus an ordinary failure, crash-recovery reporting on check-in (reported exactly once, malformed data ignored, and a crash mid-apply that resolves itself locally never leaves the command or device state stuck), audit entries and notifications, multi-tenant isolation. Agent: `internal/signin` (fake backend/admin-probe/session-terminator/LAPS-probe fakes covering pre-flight abort, snapshot-before-any-change, Apply-vs-Reapply never rolling back a repeat suspend, every crash-recovery phase, idempotent repeat suspend/restore), `internal/agent/protect_test.go` (end to end against a fake server, including that `result_data`'s JSON keys match the backend's schema and that oversized `local_admins`/`kept_service_accounts` lists are capped before they could get the whole result rejected). CI-gated **real-runner** integration tests (`internal/signin/integration_windows_test.go`, `integration_darwin_test.go`) run **only** on GitHub-hosted `windows-latest`/`macos-latest` runners, double-gated by `CI=true` **and** `RUN_HARDWARE_INTEGRATION_TESTS=1` so a developer's own machine never touches real local accounts, LSA rights or the `com.apple.access_loginwindow` group: the Windows leg creates real local test accounts and confirms `LogonUser` is refused/allowed as expected, including a simulated crash-recovery finish-forward; the macOS leg runs **as root** (asserted explicitly) and confirms the real group's `NestedGroups`/`GroupMembers`/`GroupMembership` match exactly, suspended and restored. What that still can't cover - an actual interactive login-window/Winlogon refusal, RDP, and the FileVault-unlock-then-login-window sequence - is the [hardware checklist](#hardware-checklist-not-exercised-in-ci) above.

- **Remote sessions** (`backend/tests/test_remote_sessions.py`, SQLite and PostgreSQL): RBAC per role and mode, organisation isolation of the API and both WebSockets, the single-use token (minted on delivery, hashed, expiry, replay, wrong token), one session per device and the per-organisation cap, termination (revoke, lost mode, isolation, role loss, disabled user, admin end, idle and hard limits, consent timeout), the audit trail and notifications, and the relay itself with fake agent and browser WebSocket clients: pairing, forwarding, no frames before consent, View only input dropped, second connections refused, Origin rules (production and development), client IP through trusted proxies, size limits, and a fast drag that is not rate-limited while a flood is. Agent: `internal/remote` (fake platform, helper and socket: View only drops input, no frames before consent, End session / banner closed / server unreachable / session switch / agent stop all close the helper, consent timeout means denied, idle and hard limits, `ERR_NO_ATTENDED_USER`, `ERR_UNSUPPORTED_PLATFORM`, parameter validation and local caps, the relay URL), `internal/remote/helper` (consent, End session stops capture first, the closed banner ends the session, View only, clicks on the banner dropped, monitor mapping, back-pressure, tile diffing, JPEG colours, key map) and, on `windows-latest`, the pipe protections (other users refused, wrong client PID refused, no second pipe instance). End to end: `scripts/agent_e2e.py --remote-agent` on `windows-latest` with a `-tags remote_fake` build (synthetic screen; CI checks that release builds do not contain it). The agent opens the WSS socket, frames reach a test browser client, View only input never reaches the device, a session ended by the viewer and one ended by the user both close both sockets, and the audit trail is complete. On-prem: `onprem_e2e.py relay` checks the WebSocket upgrade through nginx after install, update, rollback and restore. Real capture and input are covered by the [hardware checklist](#hardware-checklist-windows-not-exercised-in-ci).

`lock_device` is **not** exercised in CI, because CI runners have no interactive user session to lock. Its logic is unit-tested with a stub, but the Windows session-token path and the macOS `pmset` path have to be checked on real hardware before you rely on them.

## Limitations

- Windows 10/11 and macOS only. Windows Server works for inventory, but Security Center and BitLocker checks may report `unknown` there. Linux reports only basic inventory.
- No compliance policies, no software deployment, no MDM features (configuration profiles, Apple Business Manager / Autopilot). Remote wipe is Windows only (no macOS erase without MDM); lost mode on macOS cannot force a lock.
- `lock_device` on macOS depends on the user's "require password after sleep" setting (see above). On Windows it needs a signed-in session.
- Commands run within about a minute only while the device is online and polling. Offline devices pick them up within the 24 h expiry.
- Windows screen-lock detection reads the machine inactivity policy and the screen-saver settings of signed-in users. When neither is configured it reports `unknown`, although Windows may still require sign-in on wake.
- Software inventory covers registry uninstall entries (Windows) and `.app` bundles (macOS). Packages installed without either (for example Homebrew formulae, portable apps or Microsoft Store apps for other users) are not listed.
- CVE matching covers the operating system build and the applications in the curated CPE mapping; everything else is listed as "not checked" on the device's Vulnerabilities tab. Microsoft 365 Apps / Office are recognised but not matched, because NVD publishes no fixed build numbers for them ([VULNERABILITIES.md](VULNERABILITIES.md#limits)).
- Rate limiting is in-memory per backend process, like the login limiter.
- Log bundles are stored in the database (capped). Large fleets should move them to Blob Storage.
- Binaries are not signed by CI. See [Packaging and code signing](#packaging-and-code-signing). Pre-configured installers are always unsigned ([Code signing](#code-signing)).
- The Windows MSI is x64 only (it runs on Windows on ARM through emulation); the native `windows-arm64` binary is available for `install.ps1`.
- A pre-configured installer contains a live enrollment token: anyone holding the file can enroll devices until it expires, is revoked or hits its device limit.
- Remote sessions are Windows only, attended only (someone signed in, screen unlocked) and on-prem only (no relay on Azure in v1). The secure desktop (UAC prompts, sign-in screen) is not shown.
- **Remote control cannot reach elevated windows.** The helper runs at the user's normal privilege (medium integrity), so Windows UIPI blocks its input to elevated ("Run as administrator") windows. They can be seen but not clicked or typed into; ask the user to do that part.
- **The consent prompt needs a real pointing device.** Assistive tools that inject clicks (the on-screen keyboard, eye or
  voice control) cannot press **Allow**, by design (forged input must not consent); such users answer with a mouse,
  touch or pen, or the session is not started. **End session** works with any input.
- Remote-session rate limits are per relay process (there is one), like the other in-memory limiters.

### Adding Linux

Add `internal/collect/collect_linux.go` (build tag `linux`, replacing the generic `collect_other.go`), `internal/commands/lock_linux.go` (for example `loginctl lock-sessions`) and a systemd unit in `internal/service/`. Parsers belong in an OS-independent file with fixtures, like `windows.go` and `macos.go`. The server already accepts `os_family: "linux"`.
