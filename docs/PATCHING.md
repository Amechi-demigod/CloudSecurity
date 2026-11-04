# OS patching: missing Windows updates (report)

Which Windows devices are missing which **OS updates**, how old the missing security updates are, whether a restart is pending, and where each device gets its updates from. This is **step 1** of patching and it is **read-only**: nothing is downloaded, installed, hidden or approved.

| Step | Status |
|---|---|
| 1. **Report** missing OS updates per device (this document) | done: Windows, agent **1.4.0+** |
| 2. Install OS updates by ring (Pilot → Broad → All, maintenance windows, restart handling) | planned |
| 3. Third-party application updates | planned |
| macOS / Linux reports | planned (the agent answers "Windows only in this version") |

Keep installing updates with what you use today (WSUS, Windows Update for Business, Intune, Configuration Manager); this report shows whether that is working.

## Contents

- [What the agent does](#what-the-agent-does)
- [Update source (WSUS / WUfB / Microsoft Update)](#update-source)
- [What is reported](#what-is-reported)
- [Issues and notifications](#issues-and-notifications)
- [Console](#console)
- [API](#api)
- [Configuration](#configuration)
- [Why PowerShell and not go-ole](#why-an-embedded-powershell-script)
- [Limitations](#limitations)
- [Manual test checklist (real Windows)](#manual-test-checklist-real-windows)

## What the agent does

Agents **1.4.0+ on Windows** advertise the feature `windows_updates` and then:

- run a Windows Update search **about every 12 hours** (± 1 hour of jitter), the first one 5-30 minutes after the agent starts (so a fleet that restarts together does not hit WSUS at once). The time of the last search is kept in the agent state, so restarts do not cause extra searches;
- run one **on demand** when an analyst clicks **Check for updates now** (command `scan_os_updates`, no parameters);
- search **in the background**: check-ins and command polling continue while it runs (searches against a slow WSUS server can take many minutes). One search at a time; a second request while one runs just says so;
- stop a search after **30 minutes** and report it as failed;
- upload the result to `POST /api/agent/os-updates` (retried 3 times over ~20 minutes if the server is unreachable), separately from the check-in.

The search is the Windows Update Agent API, the same one Windows itself uses:

```
Microsoft.Update.Session → CreateUpdateSearcher() → Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
```

- **Software only**: drivers (`Type='Driver'`) are not listed.
- **Hidden updates are not listed** (`IsHidden=0`): an update an administrator declined/hid is not "missing".
- The searcher keeps its defaults (`ServerSelection = ssDefault`, `Online = true`), so it asks the **configured** source. The agent never switches a WSUS-managed device to Microsoft's servers and never changes any Windows Update setting.

## Update source

The report says where the device gets its updates from:

| Source | Detected from |
|---|---|
| `wsus` | Group Policy `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\WUServer` with `...\AU\UseWUServer = 1` (detail: the WSUS URL; "Windows Update for Business policies also set" when deferral policies exist as well, i.e. a dual-scan setup), or the default Automatic Updates service is *Windows Server Update Service* |
| `wufb` | Windows Update for Business policies (Group Policy or MDM / Intune `PolicyManager\current\device\Update`): `DeferQualityUpdates`, `DeferFeatureUpdates`, `...PeriodInDays`, `TargetReleaseVersion`, `ProductVersion`, `BranchReadinessLevel`, pause dates (detail: which ones) |
| `microsoft_update` | default Automatic Updates service is *Microsoft Update* (the "updates for other Microsoft products" opt-in) |
| `windows_update` | default Automatic Updates service is *Windows Update* |
| `unknown` | none of the above could be read |

## What is reported

Per device (one current report, replaced by each successful search; a **failed** search keeps the last known list and records the error):

- every missing update: **KB numbers**, title, **classification** (Security, Critical, Definition, Feature pack, Service pack, Tool, Update rollup, Update, Upgrade, Other; matched by the classification's GUID, so it also works on non-English Windows), **MSRC severity** (Critical / Important / Moderate / Low), **release date** (`LastDeploymentChangeTime`, i.e. when it was published to this device's source), **CVE ids**, **restart behaviour** (never / may / always), **download size**, whether it is already downloaded;
- **restart pending**: the update agent (`Microsoft.Update.SystemInfo.RebootRequired`), `WindowsUpdate\Auto Update\RebootRequired` or `Component Based Servicing\RebootPending`. The server records since when;
- **last successful search** and **last successful installation** (Windows' own Automatic Updates results, or this agent's search, whichever is later);
- **Windows Update service** (`wuauserv`): state and start type (automatic / delayed / manual / disabled). Manual is normal on Windows 10/11 (the service is trigger-started);
- the **update source** (above), search duration and whether it was scheduled or requested.

Limits: at most 1000 updates per report (Critical first, then security), titles 512 characters, 500 CVEs per update. Validation is strict on the server: unknown fields, malformed KB / CVE ids and unknown classifications are rejected.

## Issues and notifications

The report raises device issues (derived on read, like all [device issues](DEVICE_MANAGEMENT.md#device-health-and-issues), so age-based ones are always current):

| Issue | Severity | Raised when |
|---|---|---|
| `os_critical_updates_missing` | high | a missing update rated **Critical** by Microsoft (MSRC) was released more than `DEVICE_OS_UPDATES_CRITICAL_DAYS` (14) days ago |
| `os_security_updates_missing` | medium | any missing **security or critical** update (classification Security / Critical, or any MSRC rating) was released more than `DEVICE_OS_UPDATES_SECURITY_DAYS` (30) days ago |
| `os_reboot_pending` | medium | a restart has been pending for `DEVICE_OS_UPDATES_REBOOT_DAYS` (7) days |
| `windows_update_disabled` | high | the Windows Update service start type is **Disabled** |
| `os_update_scan_stale` | medium | no update search succeeded for `DEVICE_OS_UPDATES_SCAN_STALE_DAYS` (7) days (counted from the first report when none ever succeeded); the detail includes the last error |

Once a device has a report, the older posture-based `os_updates_pending` issue (a count from the local Windows Update cache) is no longer raised for it: the report is more precise.

They feed device **health** (At risk / Warning), the Devices list *Issue* filter and the Endpoints dashboard like every other issue, and are events of the *Endpoint device* notification source (raised with the device's next check-in after the report, only when an issue appears), so rules can route them to Teams, Slack, email or webhooks ([NOTIFICATIONS.md](NOTIFICATIONS.md#endpoint-device-events)). A failed `scan_os_updates` command is a `command_failed` event like other remote actions.

## Console

- **Device → OS updates** (Windows devices only; the existing **Updates** tab is the agent's own version and rollout): summary (missing / security / critical, oldest security update, restart pending, source, service, last checked), the last search error, the device's update issues, and the missing-update list (security & critical by default, or all). **KB numbers** link to the Microsoft Update Catalog; **CVE ids** link to *Vulnerabilities* when the same CVE is already in your vulnerability views. **Check for updates now** (analyst) queues the search; the tab shows "Checking…" until the report arrives. **CSV** downloads this device's list.
- Devices that cannot report show **Agent update required** (agent older than 1.4.0, with a link to Agent updates for admins) or "Windows only in this version".
- **Devices** list: an *OS updates* column (security updates missing, total, restart pending, last check failed; sortable) and a *Missing updates* filter (security missing / any missing / up to date / not reported, `?updates=`).
- **Dashboards → Endpoints**: *Missing security updates* tile: Windows devices missing security updates (split into MSRC-critical / other), the oldest missing security update's age and how many devices report.

## API

| Method | Path | Role | |
|---|---|---|---|
| `POST` | `/api/agent/os-updates` | device credential | the agent's report (Windows devices only) |
| `GET` | `/api/devices/{id}/os-updates` | viewer | the report, thresholds, pending check, issues; `supported` / `agent_update_required` / `unsupported_reason` |
| `POST` | `/api/devices/{id}/os-updates/scan` | analyst | queue `scan_os_updates` (optional `{"reason": ...}`); 409 when not supported, the agent is too old, or a check is already queued. Audited as `device_command_created`; visible in the device's Commands tab; analysts can cancel it while pending |
| `GET` | `/api/os-updates/export.csv?scope=security\|all&device_id=` | viewer | one row per device and missing update (hostname, group, source, KBs, title, classification, severity, release date, age, CVEs, restart, size, catalog link). Audited as `os_updates_exported`; cells are formula-neutralised |
| `GET` | `/api/devices?updates=security\|any\|none\|unknown` | viewer | Devices list filter; every row has an `os_updates` summary |

`scan_os_updates` is **not** accepted by the generic `POST /api/devices/{id}/commands`. Everything is scoped to the caller's organisation ([MULTI_TENANCY.md](MULTI_TENANCY.md)); the agent's report is stored in the organisation of its device credential.

## Configuration

| Variable | Default | |
|---|---|---|
| `DEVICE_OS_UPDATES_CRITICAL_DAYS` | 14 | age of a missing MSRC-Critical update before `os_critical_updates_missing` |
| `DEVICE_OS_UPDATES_SECURITY_DAYS` | 30 | age of any missing security / critical update before `os_security_updates_missing` |
| `DEVICE_OS_UPDATES_REBOOT_DAYS` | 7 | restart pending this long before `os_reboot_pending` |
| `DEVICE_OS_UPDATES_SCAN_STALE_DAYS` | 7 | no successful search this long before `os_update_scan_stale` |

Database: migration `0022_windows_updates` adds the `device_os_updates` table (one row per device, deleted with the device).

**Rollout:** deploy the server first (migration), then publish agent **v1.4.0** (tag `agent-v1.4.0`, [AGENT_UPDATES.md](AGENT_UPDATES.md)) and roll it out through the rings. Until a device runs 1.4.0 the console shows *Agent update required* for it; nothing else changes for older agents.

## Why an embedded PowerShell script

The Windows Update Agent is a COM API. The agent calls it through a fixed, read-only PowerShell script (`endpoint-agent/internal/osupdates/scan_windows.go`, passed with `-EncodedCommand`, output one JSON document), exactly like its other Windows collectors, rather than through a Go COM binding such as `go-ole`:

- **no new dependency and no cgo** in a binary that runs as LocalSystem; the release build and its supply-chain checks stay unchanged;
- COM apartment threading, `IDispatch` variants and reference counting are handled by PowerShell, which is part of every supported Windows version; a crash or leak in a long search cannot take the agent down, and the 30-minute timeout simply kills the child process;
- the parsing and every decision (classification, source, restart flags, limits) is in Go and unit-tested against recorded outputs (`endpoint-agent/testdata/windows/os_updates_*.json`), including Windows PowerShell 5.1's single-element and `{"value": [...]}` list shapes and the UTF-8 byte order mark.

The cost is a PowerShell process start (about a second) twice a day.

## Limitations

- Windows only; macOS / Linux later.
- Read-only: no install, no approval, no hiding. Step 2 (install by ring) will reuse the rings of [agent updates](AGENT_UPDATES.md).
- OS updates only (whatever Windows Update offers for this device, including Microsoft products when Microsoft Update is enabled); no third-party applications.
- Drivers are not listed.
- A WSUS server only offers updates an administrator **approved**: unapproved updates do not appear as missing. That is the WSUS administrator's choice; compare with Microsoft's catalog if in doubt.
- The release date is when the update was published to the device's source (for WSUS: synchronised), which can be later than Microsoft's release.
- Issues and notifications follow the next check-in after a report (minutes, at the check-in interval).

## Manual test checklist (real Windows)

Not exercised in CI (CI uses recorded outputs and fakes). On a Windows 10/11 machine with agent 1.4.0+ enrolled:

1. [ ] Within 30 minutes of the agent starting, *Device → OS updates* shows a report; `%ProgramData%\CNAPP Agent\logs\agent.log` has "Windows Update search started / finished" with the duration and count.
2. [ ] The missing list matches **Settings → Windows Update** (and `Get-WindowsUpdate` / `usoclient` if you use them): same KB numbers; Defender definition updates appear as *Definition*.
3. [ ] **Check for updates now**: the button shows *Checking…*, the Commands tab shows *Check for OS updates* succeeded ("search started"), and the report's *Last checked* says *on request* within a few minutes. Check-ins keep arriving during the search.
4. [ ] Install one update from Settings, then **Check for updates now**: it disappears from the list; if it needs a restart, *Restart pending* says Yes. After the restart and another check, Restart pending is No.
5. [ ] Set the Windows Update service to Disabled (`sc.exe config wuauserv start= disabled`), check again: the search fails with `0x80070422`, the tab shows the error and keeps the last list, and the device gets `windows_update_disabled`. Restore it (`sc.exe config wuauserv start= demand`).
6. [ ] Non-English Windows (e.g. German): classifications are still *Security* / *Critical* (matched by GUID).
7. [ ] **WSUS-managed machine** (GPO *Specify intranet Microsoft update service location*): source **WSUS** with the server URL; only updates approved on WSUS appear; the search does not contact Microsoft (check with the WSUS server's client report / a proxy log); unapprove an update on WSUS and it disappears after the next check.
8. [ ] WSUS unreachable (block the port): the search fails (e.g. `0x8024401C` / `0x80072EE2`), the error is shown, and after 7 days (or by shortening `DEVICE_OS_UPDATES_SCAN_STALE_DAYS`) the device gets `os_update_scan_stale`.
9. [ ] **Windows Update for Business** machine (Intune update ring or GPO deferrals): source **Windows Update for Business** with the policy names.
10. [ ] Microsoft Update opt-in (*Receive updates for other Microsoft products*): source **Microsoft Update**; Office / .NET updates appear.
11. [ ] Restart the agent service right after a search: no new search for ~12 hours (the time is in the agent state).
12. [ ] Devices list: *OS updates* column and the *Missing updates* filter; Endpoints dashboard: *Missing security updates* tile counts and links.
13. [ ] An agent older than 1.4.0 shows **Agent update required** and the API refuses the check (409).
