# Network discovery

Network discovery finds the devices on the customer's networks (switches, routers, firewalls, access points, printers,
UPSes, cameras, servers), identifies them, checks their firmware for CVEs and flags risky configuration. It is
**read-only**: the collector never logs in to a device, never brute-forces and never tries an exploit. It pings / ARPs,
makes light TCP connections to a fixed list of ports, reads the SNMP system group and (when SNMP works) the interface
and forwarding tables.

The collector half is documented in [NETWORK_DISCOVERY_COLLECTOR.md](NETWORK_DISCOVERY_COLLECTOR.md).

Scans run on the existing **dedicated collector** (Windows, `cnct_` enrollment, `cnc_` credential, see
[DIRECTORY_DISCOVERY.md](DIRECTORY_DISCOVERY.md#dedicated-collectors)), never on endpoint agents. Endpoint agents can
never be sent the two new command types.

Where it lives in the console: **IT assets > Discovery > Add network scan** (wizard), **Endpoints & assets > Network
devices** (list), a device page, and **Network scans** (management). Network device CVEs appear on the existing
Vulnerabilities and CVE pages; findings in the existing Findings flow.

## Collector contract

Two new collector command types (added to the collector-allowed set `directory_sync`, `collector_diagnostics`,
`collector_health`, `check_for_update`): `network_subnets` and `network_scan`. `new_command` refuses anything else.

### `network_subnets`

No params. Reads AD Sites (subnet objects) and DHCP scopes. Result (`result_data`, up to 256 KB):

```json
{"ad_sites": [{"site": "HQ", "subnet": "10.10.1.0/24", "description": "..."}],
 "dhcp_scopes": [{"server": "HQ-DC01", "scope": "10.10.10.0", "mask": "255.255.254.0", "name": "Staff Wi-Fi",
                  "start": "10.10.10.10", "end": "10.10.11.250"}],
 "errors": ["..."]}
```

The console shows the newest successful result per collector as subnet suggestions ("Suggested by: AD Site: HQ" /
"DHCP: HQ-DC01"). Invalid subnets are dropped; strings are capped and sanitised.

### `network_scan`

Stored params (also what is shown in the run; **no secrets**):

```json
{"scan_id": "<run id>", "targets": ["10.10.1.0/24", "10.30.0.10-10.30.0.50"],
 "exclude": ["10.10.1.40", "10.10.20.200-10.10.20.220"], "port_check": true,
 "ports": [{"port": 22, "proto": "tcp"}, {"port": 23, "proto": "tcp"}, {"port": 80, "proto": "tcp"},
           {"port": 443, "proto": "tcp"}, {"port": 445, "proto": "tcp"}, {"port": 3389, "proto": "tcp"},
           {"port": 161, "proto": "udp"}, {"port": 8080, "proto": "tcp"}, {"port": 8443, "proto": "tcp"},
           {"port": 9100, "proto": "tcp"}],
 "concurrency": 20, "timeout_ms": 1500,
 "snmp": [{"id": "<cred id>", "version": "v3", "username": "...", "auth_proto": "SHA256", "priv_proto": "AES128",
           "level": "authPriv"},
          {"id": "<cred id>", "version": "v2c"}],
 "upload_url": "/api/collector/network/batches"}
```

* `scan_id` is the id of **this execution** (the run). It is not the saved scan's id (a one-address test or a device
  re-scan has no saved scan). Use it in every batch.
* `ports` is empty when `port_check` is false (the admin switched the port check off for this scan).
* `concurrency` is 20 ("Gentle") or 64 ("Normal"); `timeout_ms` is 1500.
* `snmp` is ordered: SNMPv3 credentials first, then v2c. Try them in order; stop at the first that answers.
* `targets` / `exclude` are IPv4 CIDRs or inclusive `a-b` ranges, already validated (below).

The **delivered** copy (the `GET /api/collector/commands` response only; never stored, logged or returned by any
other API) adds the secrets per credential: v3 `auth_password`, `priv_password`; v2c `community`.

Credentials are stored encrypted with the mechanism directory sources use for their service-account secret (Fernet,
`NOTIFICATIONS_ENCRYPTION_KEY`) and are write-only in the API. They are re-encrypted by `python -m app.cli rotate-notification-key`.

### Batches

The collector POSTs (collector credential, `Authorization: Bearer cnc_...`, JSON; gzip with
`Content-Encoding: gzip` is accepted too) to `/api/collector/network/batches`:

```json
{"scan_id": "<run id>", "seq": 0, "final": false,
 "devices": [{"ip": "10.10.1.1", "mac": "00:1e:13:aa:bb:01", "mac_vendor": "Cisco", "hostname": "sw-core.corp.example.com",
              "alive_via": ["icmp", "arp", "tcp"],
              "snmp": {"version": "v3", "credential_id": "<id>", "sys_name": "", "sys_descr": "", "sys_object_id": "",
                       "sys_location": "", "sys_contact": "", "uptime_s": 123},
              "default_community": null,
              "vendor": "", "model": "", "firmware": "", "serial": "", "device_type": "switch",
              "interfaces": [{"index": 1, "name": "Gi1/0/1", "descr": "", "mac": "", "oper_up": true, "speed_mbps": 1000}],
              "fdb": [{"mac": "aa:bb:cc:dd:ee:ff", "port_name": "Gi1/0/5", "vlan": 10}],
              "open_ports": [{"port": 22, "proto": "tcp", "service": "ssh", "banner": "SSH-2.0-..."}]}],
 "summary": {"addresses": 256, "alive": 40, "snmp": 12, "duration_s": 93, "errors": []}}
```

* `summary` is sent with the `final` batch. At most 500 devices per batch. `seq` starts at 0 and is unique per run.
* **Idempotent per (`scan_id`, `seq`)**: a repeated seq is acknowledged (`{"accepted": 0, "duplicate": true}`) and
  ignored, so a retry after a timeout is safe. After the final batch, new seqs get 409.
* `interfaces` / `fdb` absent (not `[]`) means "not collected": the stored data is left alone. `fdb` present replaces the
  switch's table.
* `default_community` is `"public"` or `"private"` when the device answered that well-known community, else `null`.
* `device_type` is a hint (`switch|router|firewall|access_point|printer|ups|phone|camera|server|workstation|unknown`);
  the server normalises from `sys_descr` / `sys_object_id` and uses the hint only when it cannot tell.
* Banners are at most 200 characters: the first bytes a service sends unprompted, or the HTTP `Server` header from a
  `GET /` status line (no HEAD). Everything is sanitised (control characters removed) and length-capped server-side.
* Identity: a device is merged by MAC when known, else by IP; a MAC-less record is upgraded when its MAC shows up; a
  known MAC on a new IP updates the IP (history event).
* Collector auth only: the run must belong to the calling collector (404 otherwise).

Responses: `200 {"accepted": n, "duplicate": false, "status": "running|succeeded"}`; `401` bad credential; `404` run
not found / not yours; `409` not delivered yet or already finished; `413`/`422` malformed.

Command result (`POST /api/collector/commands/{id}/result`): for `network_scan` a `failed` / `rejected` status fails the
run with the command output; success needs no result data (the final batch finishes the run).

## Refinements agreed with the collector

`alive_via` also allows `snmp`; `default_community` is always present; `snmp` only when a supplied credential worked;
`vlan` 0 = unknown. A `network_scan` command expires 6 hours after queueing (the collector stops the scan then);
`network_subnets` after 30 minutes. Collectors must list the `network_discovery` feature (collector 1.6.0+), else the API
answers 409 "update the collector". At most 16 credentials per scan; the API returns 4xx on a batch only for invalid input.

## Validation (server side)

* each target a CIDR or `a-b` range, IPv4 only for now;
* no single target larger than /16 (65,536 addresses); at most 262,144 addresses per scan after exclusions;
* refused: `0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `224.0.0.0/3` (multicast and reserved), including inside ranges;
* exclusions use the same syntax; concurrency only 20 or 64.

## Scans, schedule, runs

A scan stores its configuration (collector, targets, exclusions, port check, SNMP credentials, pace, schedule). Schedules:
daily or weekly at a UTC time, or manual. The directory scheduler queues a due scan only when its collector is online
(seen in the last 10 minutes); if the collector is offline it retries for 4 hours and then records the slot as failed.
A run nobody picks up within 15 minutes, or that sends nothing for 30 minutes, fails. Every create / edit / delete /
run-now / credential change is audited. *Test on one address* and *Re-scan device* queue a `network_scan` with a single
`/32` target; the result arrives like any scan.

## Identification

`app/network/normalize.py` normalises vendor, model, firmware and device type from `sysObjectID` (IANA enterprise
number) and `sysDescr` for Cisco IOS / IOS XE / NX-OS / ASA, Fortinet FortiOS, Palo Alto PAN-OS, Juniper Junos,
Aruba / HPE, Ubiquiti, MikroTik RouterOS, Sophos Firewall (SFOS), HP / Brother / Canon / Ricoh / Xerox printers and APC UPS.
Sophos Firewall reports a plain Linux `sysDescr`; it is recognised by `sysObjectID` 1.3.6.1.4.1.2604.5 and its model,
firmware and serial come from SFOS-FIREWALL-MIB, which the collector reads from **1.6.1** (a 1.6.0 collector still names
it a Sophos firewall, but without firmware it is "not checked" for CVEs). Without SNMP the
MAC OUI (small bundled table) names the vendor and the open ports hint at the type. A device it cannot identify stays
`unknown` and is not matched for CVEs: the device page says so.

**Linux / Unix servers by SSH banner.** The banner the collector already reads from an open SSH port is used when SNMP
did not identify the device. Debian-family and FreeBSD OpenSSH builds name the OS in the banner
(`SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`, `...Debian-2+deb12u3`, `...Raspbian-...`, `...FreeBSD-20240701`); those
become device type `server`, vendor `Linux` (`FreeBSD` for FreeBSD) and family `Ubuntu` / `Debian` / `Raspbian` /
`FreeBSD`. A plain `SSH-2.0-OpenSSH_8.7` (RHEL, Rocky, Alma, Amazon Linux, but also Juniper, some firewalls and NAS
boxes) does not name the OS and is **not** used: such a device stays `unknown` unless SNMP, the vendor or a rule
identifies it. The banner never overrides SNMP, an enterprise number, the vendor rules, printer ports or a MAC that
says network gear (a net-snmp host keeps `Linux (net-snmp)`). It beats only the weak port guess (SMB / RDP). No CVE or
CPE matching is done from the banner. Caveat: FreeBSD-based firewalls (pfSense, OPNsense) print a FreeBSD banner and are
shown as servers until SNMP or a rule identifies them.

## Vulnerabilities

The normalised firmware is mapped to a CPE (`o:cisco:ios_xe`, `o:cisco:ios`, `o:cisco:nx-os`,
`o:cisco:adaptive_security_appliance_software`, `o:fortinet:fortios`, `o:paloaltonetworks:pan-os`, `o:juniper:junos`,
`o:arubanetworks:arubaos`, `o:arubanetworks:arubaos-cx`, `o:ubnt:edgeos`, `o:mikrotik:routeros`, `o:sophos:sfos`) and
matched by the **same engine** as endpoint software (`vulnmatch`: NVD by CPE, CISA KEV, FIRST EPSS, the same cache and worker). Rows are
`vulnerabilities` with the new `network_device_id` column (a CVE belongs to exactly one of asset / device / network
device). They show on **Vulnerabilities** (scope `network`) and on the **CVE page**, whose "Affected network devices"
lists each device, its firmware and the fixed firmware. Printers, UPSes and Aruba/HPE switch firmware have no usable CPE
mapping yet: they are listed as "not checked". NVD configurations that also name specific hardware are matched on the
firmware range only (flagged `hardware_not_checked` in the evidence).

"Fix first" on the device page groups the open CVEs by the firmware upgrade that closes them (KEV first) with the
vendor advisory link; an interim workaround is shown only for the few CVEs where the vendor published one
(`insight.WORKAROUNDS`).

## Findings

Rules `NET-*` (`app/network/rules.py`) store ordinary rows in `findings` (`source = "network"`), keyed to a shadow
cloud-inventory asset (`type = network_device`, `provider = onprem`, id `netdev-<device id>`), so the Findings list,
finding detail page, status changes, SLA and PDF work unchanged. Guidance has the posture structure (impact, CWE, ATT&CK,
verify, device console steps, CLI, config template, prevention, references).

| Rule | Severity | Fires when |
|---|---|---|
| NET-SNMP-001 | high | the device answers the default community `public` / `private` |
| NET-SNMP-002 | medium | the device answers SNMPv3 and also a default community (v2c enabled) |
| NET-TELNET-001 | high | 23/tcp open |
| NET-HTTP-001 | medium | 80 or 8080/tcp open on a switch, router, firewall, access point, printer, UPS or camera |
| NET-SMB-001 | medium | 445/tcp open on a non-Windows network device type |
| NET-FW-001 | high | firmware release train past the vendor's end of support (small table, `normalize.EOS`) |
| NET-FDB-001 | low | a MAC new in a switch's forwarding table is not a scanned device, interface or enrolled endpoint |

NET-FDB-001 ignores the first table seen from a switch (the baseline) and ports that learned more than 24 MACs (assumed
uplinks). Findings resolve when the cause is gone at the next scan; suppressed findings stay suppressed.

## Linking and IT assets

Each device is linked, after the final batch of a scan, to the enrolled endpoint (by MAC or IP in the agent's network
inventory, else by unique host name) and to an AD computer (by short name). A host that runs the Linux runtime sensor is linked to
the sensor's asset (`assets.source = sensor`, created by the package inventory) by short host name, only when exactly
one sensor asset has that name (the sensor reports no MAC or IP; cloud VMs the sensor resolved to a cloud asset are not
matched). "Tracked" in the list is Agent, AD, IT asset, Runtime sensor or Not registered, in that order of precedence. **Add to IT assets** (analyst) creates an IT asset (`source = network`, tag `NET-<name>`) for the selected
devices.

## API

Viewers read, analysts export / add to IT assets, admins configure and run. Another organisation's ids answer 404.

| Endpoint | |
|---|---|
| `GET/POST /api/network/scans`, `GET/PATCH/DELETE /api/network/scans/{id}`, `POST .../run`, `GET .../runs` | scans |
| `GET /api/network/runs/{id}` | one run |
| `GET/POST /api/network/credentials`, `PUT/DELETE .../{id}` | SNMP credentials (secrets write-only) |
| `GET /api/network/suggestions`, `POST .../refresh` | subnets from AD Sites / DHCP |
| `POST /api/network/test` | test one address (queues a `/32` scan, returns the run) |
| `GET /api/network/summary`, `GET /api/network/devices` (`q`, `type`, `status`, `subnet`) | list and stats |
| `GET /api/network/devices/{id}`, `POST .../rescan`, `GET .../report.pdf`, `DELETE` | one device |
| `GET /api/network/devices/export.csv`, `POST /api/network/devices/add-to-it-assets` | export / IT assets |
| `POST /api/collector/network/batches` | collector upload |

## Simulated data

With `SIMULATION_MODE` the simulated environment also gets a simulated network estate (`app/network/demo.py`, switch off
with `NETWORK_DEMO_DATA=false`) so the pages demo without a collector. `python -m app.network.demo` seeds it, plus two
simulated online collectors and subnet suggestions, into a development database.

## Things to review

* End-of-support dates in `normalize.EOS` (FortiOS 6.0 / 6.2 / 6.4 / 7.0, PAN-OS 8.1) are from the vendors' public
  lifecycle pages as understood when written; check them before relying on NET-FW-001.
* SFOS: Sophos's notice states 30 Apr 2025 for 18.5 and 19.5. Older releases (16.x, 17.x, 18.0, 19.0) are listed as
  "no later than" that date because their own notices were not readable; 20.0 and later have no row yet. Sophos's
  retirement calendar (community.sophos.com/kb/en-us/121502) is the source to update them from.
* NVD files Sophos Firewall CVEs under five product names (`o:sophos:sfos`, `o:sophos:firewall_firmware`,
  `o:sophos:xg_firewall_firmware`, `a:sophos:firewall`, `o:sophos:firewall`); `normalize.CPE_ALIASES` makes a SFOS device
  match all of them. Some NVD records give only the major release (e.g. "up to 19.0") and so miss later MRs of it.
* Vendor `sysDescr` regexes and CPE mappings were written from sample strings; a vendor that prints something else is
  "unknown" / "not checked", never guessed. Junos is matched with version `20.4` and update `r3-s3` (service release
  dropped).
* NET-SNMP-002 can only see v2c when a default community answers (the contract carries one SNMP version per device).
