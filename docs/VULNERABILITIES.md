# Vulnerability (CVE) matching

The Vulnerabilities page and each device's **Vulnerabilities** tab show real CVEs found on:

| What | Inventory from | Matched against | Where it shows up |
|---|---|---|---|
| **Laptops** (Windows 10/11, macOS) | endpoint agent check-ins: OS build + installed applications | [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) by CPE, through a curated mapping table | device detail → Vulnerabilities, Vulnerabilities page (Affected = Laptops) |
| **Linux servers / VMs / Kubernetes nodes** | runtime sensor package inventory (dpkg, apk, rpm, pip) | [OSV.dev](https://osv.dev) (`querybatch`) | the host's asset (inventory drawer), Vulnerabilities page, attack paths |
| Simulated environment | seed data | - | unchanged (`source = simulated`) |

Every match is enriched with:

- **CISA KEV** ([Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), refreshed daily): `kev = true` and `exploit_available = true`, which raises the risk score (`engine/risk.py`) and is shown as a **KEV** badge / filter.
- **FIRST EPSS** ([exploit prediction score](https://www.first.org/epss/), daily): the probability of exploitation in the next 30 days, shown next to CVSS and available as a sort order.
- CVSS score / severity (NVD primary CVSS v3.1, else v3.0, v4.0, v2; OSV CVSS v3 vectors are scored locally), the fixed version when the data states one, and links to NVD / OSV.

## How it works

1. **Inventory changes are queued, never matched inline.** An agent check-in with a changed software list or OS build, or a sensor package report, only stores a hash and a "match requested" timestamp (`vuln_match_state`). Nothing in a check-in or ingest request talks to the internet.
2. **A leader-elected background worker** (`app/vulnmatch/worker.py`, one per deployment like the scan scheduler, using `app/locks.py`) runs every 30 s:
   - refreshes the KEV catalog (and EPSS) when older than `VULN_KEV_REFRESH_HOURS` (retries hourly after a failure);
   - matches targets whose last inventory change is older than `VULN_DEBOUNCE_SECONDS` (bursts of check-ins are handled together), and re-matches every device / host every `VULN_REMATCH_INTERVAL_HOURS` because new CVEs are published daily;
   - resolves the vulnerabilities of revoked devices and forgets deleted ones.
3. **Feed responses are cached in the database** (`vuln_feed_cache`): NVD data per CPE product (incremental refresh with `lastModStartDate` every `VULN_NVD_CACHE_HOURS`, full re-download every 30 days), OSV query results and records, the KEV catalog, EPSS scores. One fleet-wide product (Chrome) is downloaded once, not once per laptop.
4. **Reconciliation**: a vulnerability is keyed by (device or asset, product, CVE). It is created when found, updated when the installed version changes but is still affected, **resolved automatically** (`status = resolved`, `resolved_at`) when the software is upgraded past the fix or removed, and re-opened if it comes back. It is only resolved when the product was actually checked in that pass - if the feed was unreachable, existing findings are kept.
5. **Notifications** use the existing *Vulnerability* source (rules, channels, throttling in Notifications). New **critical** vulnerabilities (`VULN_NOTIFY_MIN_SEVERITY`) and every **KEV-listed** one are aggregated **per CVE**: a Chrome CVE found on 300 laptops in one pass is one message ("CVE-... in Google Chrome on 300 devices"), and a CVE is not re-notified for 24 h; a CVE that is newly added to KEV sends "Now known exploited: ...". Group key: `vulnerability:<CVE>:aggregate`.

### Laptops: NVD by CPE

NVD describes affected software with CPE match criteria and version ranges:

```json
{"vulnerable": true, "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "versionEndExcluding": "130.0.6723.91"}
```

The matcher (`app/vulnmatch/cpe.py`) evaluates whole CVE configurations:

- `versionStartIncluding/Excluding`, `versionEndIncluding/Excluding` and exact versions, compared segment by segment (`app/vulnmatch/versions.py`): numeric segments as numbers (`130.0.6723.100 > 130.0.6723.91`), missing trailing segments as 0 (7-Zip's `24.08.00.0 == 24.08`), pre-release tags before releases;
- multi-node **AND** configurations ("Chrome *running on* Windows") need the other nodes to be satisfied by the device's platform (its OS and other mapped software); negated nodes are honoured;
- `target_sw` must fit the device (a Chrome-for-Android CVE never matches a laptop), `target_hw` its architecture (`x64` / `arm64`), the `update` field is compared for Java 8 (`1.8.0:update431`), and Adobe's `continuous` / `classic` track is derived from the build number;
- criteria **without any version information** (`*` without a range, or `-`) are never matched to an installed product: NVD uses them for products whose fixes are tracked by build elsewhere (Microsoft 365 Apps), and matching them would flag every CVE ever published.

The **operating system** is always checked: Windows by feature release and build (`Microsoft Windows 11 Pro 23H2` + build `22631.4317` → `cpe:2.3:o:microsoft:windows_11_23h2` version `10.0.22631.4317`; Windows 10 21H2/22H2/1809/1607/1507, Windows 11 21H2-25H2, Server 2016/2019/2022/2022 23H2/2025), macOS by version (`o:apple:macos`).

### Curated mapping table (agent software → CPE)

Applications are only checked when a rule in `app/vulnmatch/mapping.py` recognises them exactly: on Windows the Uninstall-registry **DisplayName must fully match** the rule's pattern **and** the publisher must match; on macOS the app's **bundle id** must match. Everything else is listed as **not checked** (device tab and Vulnerabilities → Coverage) - fuzzy name matching against NVD produces false positives. The table currently has **50 entries** (47 matched, 3 recognised but deliberately not matched):

| Product | Platforms | NVD CPE product(s) | Note |
|---|---|---|---|
| Google Chrome | Windows / macOS | `a:google:chrome` |  |
| Microsoft Edge | Windows / macOS | `a:microsoft:edge_chromium` |  |
| Mozilla Firefox | Windows / macOS | `a:mozilla:firefox` |  |
| Mozilla Firefox ESR | Windows / macOS | `a:mozilla:firefox_esr` |  |
| Mozilla Thunderbird | Windows / macOS | `a:mozilla:thunderbird` |  |
| Brave | Windows / macOS | `a:brave:brave` |  |
| Opera | Windows / macOS | `a:opera:opera_browser` |  |
| Safari | macOS | `a:apple:safari` |  |
| Zoom Workplace | Windows / macOS | `a:zoom:workplace_desktop`, `a:zoom:workplace`, `a:zoom:meetings`, `a:zoom:zoom` |  |
| Microsoft Teams | Windows / macOS | `a:microsoft:teams` |  |
| Slack | Windows / macOS | — | not matched: NVD has no CPE product with version data for the Slack desktop app |
| Cisco Webex Meetings | Windows / macOS | `a:cisco:webex_meetings` |  |
| Microsoft 365 Apps / Office | Windows / macOS | — | not matched: NVD lists Microsoft 365 Apps / Office without fixed build numbers; check the Office update channel (Click-to-Run version) instead |
| Adobe Acrobat Reader | Windows / macOS | `a:adobe:acrobat_reader_dc`, `a:adobe:acrobat_reader` |  |
| Adobe Acrobat | Windows / macOS | `a:adobe:acrobat_dc`, `a:adobe:acrobat` |  |
| Foxit PDF Reader | Windows / macOS | `a:foxit:pdf_reader` |  |
| Foxit PDF Editor | Windows / macOS | `a:foxit:pdf_editor` |  |
| LibreOffice | Windows / macOS | `a:libreoffice:libreoffice` |  |
| Notepad++ | Windows | `a:notepad-plus-plus:notepad++` |  |
| Oracle Java 8 (JRE) | Windows | `a:oracle:jre` |  |
| Oracle Java SE Development Kit 8 | Windows | `a:oracle:jdk` |  |
| Oracle Java SE Development Kit | Windows | `a:oracle:jdk` |  |
| OpenJDK (Temurin / Microsoft / Zulu builds) | Windows | `a:oracle:openjdk` |  |
| Python | Windows | `a:python:python` |  |
| Node.js | Windows | `a:nodejs:node.js` |  |
| Git | Windows | `a:git-scm:git` |  |
| Visual Studio Code | Windows / macOS | `a:microsoft:visual_studio_code` |  |
| PowerShell 7 | Windows | `a:microsoft:powershell` |  |
| Docker Desktop | Windows / macOS | `a:docker:desktop` |  |
| Wireshark | Windows / macOS | `a:wireshark:wireshark` |  |
| Oracle VirtualBox | Windows / macOS | `a:oracle:vm_virtualbox` |  |
| VMware Workstation | Windows | `a:vmware:workstation` |  |
| 7-Zip | Windows | `a:7-zip:7-zip` |  |
| WinRAR | Windows | `a:rarlab:winrar` |  |
| PuTTY | Windows | `a:putty:putty` |  |
| WinSCP | Windows | `a:winscp:winscp` |  |
| FileZilla Client | Windows | `a:filezilla-project:filezilla_client` |  |
| VLC media player | Windows / macOS | `a:videolan:vlc_media_player` |  |
| GIMP | Windows / macOS | `a:gimp:gimp` |  |
| AnyDesk | Windows / macOS | `a:anydesk:anydesk` |  |
| TeamViewer | Windows / macOS | `a:teamviewer:teamviewer` |  |
| OpenVPN (community client) | Windows | `a:openvpn:openvpn` |  |
| OpenVPN Connect | Windows / macOS | `a:openvpn:connect` |  |
| FortiClient | Windows / macOS | `a:fortinet:forticlient` |  |
| Cisco AnyConnect Secure Mobility Client | Windows / macOS | `a:cisco:anyconnect_secure_mobility_client` |  |
| Cisco Secure Client | Windows / macOS | `a:cisco:secure_client` |  |
| Citrix Workspace | Windows / macOS | — | not matched: NVD mixes year-month (2402) and dotted (24.2.0) versions for Citrix Workspace, so ranges cannot be compared reliably |
| TightVNC | Windows | `a:tightvnc:tightvnc` |  |
| KeePass Password Safe | Windows | `a:keepass:keepass` |  |
| Microsoft OneDrive | Windows / macOS | `a:microsoft:onedrive` |  |

Versions are normalised per rule where the reported version is not the product version: Python (`3.12.4150.0` → from the name `Python 3.12.4`), Oracle Java 8 (`Java 8 Update 431` → `1.8.0` update `update431`), Oracle JDK / OpenJDK builds (from the name), OpenVPN (`2.6.12-I001`), Brave (`130.1.71.118` → `1.71.118`), Zoom (`6.2.5 (47909)` → `6.2.5`).

### Linux hosts: OSV

The sensor (`sensor/runtime_sensor/inventory.py`) reports the host's packages every `SENSOR_INVENTORY_INTERVAL` (6 h) to `POST /api/runtime/packages` ([schema](../sensor/EVENT_SCHEMA.md#package-inventory)). The backend stores them on the host's asset - the cloud VM it already knows (by `cloud.resource_id`, then VM name = host), or a new sensor-backed asset (`type vm`, `source sensor`, id `sensor:<host>`) for on-prem servers - and queries OSV with one `querybatch` per run:

| Distribution | OSV ecosystem | Package name / version sent |
|---|---|---|
| Debian | `Debian:<major>` | dpkg *source* package and source version |
| Ubuntu | `Ubuntu:<version>[:LTS]` | dpkg source package and version |
| Alpine | `Alpine:v<major.minor>` | apk origin package |
| Rocky Linux / AlmaLinux 9+ | `Rocky Linux:<major>`, `AlmaLinux:<major>` | rpm name, `[epoch:]version-release` (sqlite rpmdb) |
| RHEL 9+ | `Red Hat` (best effort) | rpm name and EVR |
| pip packages in `/usr/local/lib/python3*` | `PyPI` | distribution name / version |

OSV evaluates the version ranges itself (distribution version semantics). Advisories are turned into one vulnerability per CVE they list (`upstream` / `aliases`), with the fixed version from the advisory. The vulnerability keeps the binary package names (`libssl3` for the `openssl` source package), so the sensor's existing `library_loaded` events mark it **in use at runtime**, the risk score uses the asset's exposure and data access, and **attack paths** treat an in-use CVSS ≥ 7 vulnerability on a workload as an exploitable hop - exactly like the simulated data.

## Risk score and the noise-reduction stat

Asset vulnerabilities use the runtime-aware formula in the README ("Risk scoring"). Laptops have no runtime sensor, so their vulnerabilities are scored as in use (users launch installed desktop apps) without internet exposure, e.g. a KEV-listed CVSS 8.8 Chrome bug scores 52.8 (high priority). The **noise-reduction** stat and the dashboard's top risks only count workload (asset) vulnerabilities, so they keep meaning "share of workload CVEs in packages never loaded".

## Configuration

Defaults are in `backend/app/config.py`; on-prem they are in `/opt/cnapp/cnapp.env` (new installs get them from `cnapp-ctl`; existing installs use the defaults until you add them).

| Setting | Default | |
|---|---|---|
| `VULN_MATCHING_ENABLED` | `true` | turn matching (worker, feeds) on/off |
| `NVD_API_KEY` | empty | optional [free NVD API key](https://nvd.nist.gov/developers/request-an-api-key): 50 instead of 5 requests / 30 s. Sent as the `apiKey` header, never logged |
| `VULN_REMATCH_INTERVAL_HOURS` | `12` | re-match every device / host this often (1-720) |
| `VULN_KEV_REFRESH_HOURS` | `24` | KEV and EPSS refresh (1-720) |
| `VULN_NVD_CACHE_HOURS` / `VULN_OSV_CACHE_HOURS` | `12` | reuse feed data this long before an (incremental) refresh |
| `VULN_DEBOUNCE_SECONDS` | `120` | wait this long after an inventory change before matching |
| `EPSS_ENABLED` | `true` | fetch EPSS scores |
| `VULN_NOTIFY_MIN_SEVERITY` | `critical` | notify from this severity up (KEV always) |
| `NVD_API_URL`, `OSV_API_URL`, `KEV_URL`, `EPSS_API_URL` | public endpoints | point at an internal mirror if you have one |
| sensor `SENSOR_INVENTORY_INTERVAL` | `21600` | seconds between package inventories, `0` disables |

Analysts can force a pass with **Re-match now** (`POST /api/vulnerabilities/rematch`, audited).

### Egress

The backend needs outbound HTTPS to:

| Host | Used for |
|---|---|
| `services.nvd.nist.gov` | NVD CVE API 2.0 (laptop software / OS) |
| `api.osv.dev` | OSV `querybatch` and advisory records (Linux packages) |
| `www.cisa.gov` | KEV catalog JSON |
| `api.first.org` | EPSS scores |

`HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` from `cnapp.env` are honoured (httpx `trust_env`), as are `SSL_CERT_FILE` / a corporate CA. **Offline or blocked**: check-ins and sensor ingest keep working; matching continues from the cached data, the page shows "updated <time>" and the last error per feed (Vulnerabilities → Coverage), and findings of products whose data could not be fetched are kept, not resolved. A server that has never reached NVD lists that software as "not checked (feed offline)".

The first NVD download of a fleet's products takes a few minutes without an API key (NVD asks clients to space requests ~6 s apart; Chrome alone is ~7,000 CVEs in 4 pages). Later refreshes only fetch what changed.

## Limits

- **Unmapped software is not checked.** Only the products in the table above (plus the OS) are matched; the Coverage view lists the rest with how many devices have it. Microsoft 365 Apps / Office, Slack and Citrix Workspace are recognised but deliberately not matched (no usable NVD version data).
- **NVD lag.** New CVEs are often "awaiting analysis" in NVD for days or weeks, without CPE configurations; they cannot be matched until NVD analyses them (KEV-listed ones are usually prioritised by NVD).
- **Windows cumulative updates**: the OS is matched by build (`UBR`) as NVD publishes it; Windows components updated outside the cumulative update (Edge WebView, Store apps) are not covered.
- **Per-user and portable software** that is not in the Uninstall registry / `/Applications` is not inventoried by the agent.
- **No container image scanning** yet: the sensor inventories the host's packages, not the images running in containers. Distributions without an OSV ecosystem (Amazon Linux, SUSE, Container-Optimized OS, Arch) are not matched; RHEL 7/8 (BerkeleyDB rpmdb) is not read.
- **Cloud connectors** (Azure, AWS, GCP) are posture-only; VMs only get CVE data when the runtime sensor runs on them.
- OSV advisories without a CVSS score (some distro advisories) use the distro's severity label, or a default of 5.0 (flagged as `score_missing` in the evidence).

## Adding a mapping

1. Find the product's CPE on [NVD CPE search](https://nvd.nist.gov/products/cpe/search) and check recent CVEs list it **with version ranges or exact versions** (not just `-`). Note `target_sw` values and how versions are written.
2. Find exactly what the agent reports: device detail → Software (DisplayName / version / publisher on Windows, bundle id on macOS).
3. Add a `Rule` to `RULES` in `backend/app/vulnmatch/mapping.py`: `names` (full-match regexes), `publishers`, `bundle_ids`, `platforms`, and `version_from_name` / `version_pattern` if the reported version is not the product version. Use `unsupported="why"` for products that must be recognised but not matched.
4. Add a case to `backend/tests/test_vuln_engine.py` (`test_windows_mapping` / `test_macos_mapping_by_bundle_id`) and, if it has unusual version semantics, a CPE range test.
5. After deployment the next re-match (or **Re-match now**) checks it on every device.
