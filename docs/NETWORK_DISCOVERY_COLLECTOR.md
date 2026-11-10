# Network discovery: the collector side

Network discovery finds devices (switches, routers, firewalls, printers, servers) on
address ranges you choose. The scanning happens **only in the dedicated collector**
(`cnapp-collector`, Windows) - never in the endpoint agent, which rejects the
network commands with a clear error. The server (console) creates scans and shows
results; see the console-side document for the UI, API and data model. This page is
what the collector does, what it needs, and what it never does.

Added in collector **1.6.0** (it advertises the `network_discovery` feature in its heartbeat).

## Commands

| Command | Parameters | Result |
| --- | --- | --- |
| `network_subnets` | none | `{"ad_sites":[{"site","subnet","description"}],"dhcp_scopes":[{"server","scope","mask","name","start","end"}],"errors":[...]}` |
| `network_scan` | `scan_id`, `targets`, `exclude`, `port_check`, `ports`, `concurrency`, `timeout_ms`, `snmp`, `upload_url` | `{"scan_id","addresses","alive","snmp","duration_s","batches","errors"}` |

Both are read-only. `network_scan` runs in the background (the collector keeps
heartbeating and polling) and reports its command result when it finishes; the devices
themselves are uploaded in batches while it runs. One scan at a time per collector.

### Subnet suggestions (`network_subnets`)

* **AD Sites**: subnet objects under `CN=Subnets,CN=Sites,CN=Configuration,<forest root>`
  (`cn` is the CIDR, `siteObject` the site, `description`), read over the collector's
  existing Kerberos signed-and-sealed LDAP session. For a child domain the Configuration
  partition of the forest root is found by trying the domain's parents. IPv6 subnets are
  skipped.
* **DHCP**: the DHCP servers authorised in AD (`dhcpClass` objects under
  `CN=NetServices,CN=Services,CN=Configuration`) are queried with the DHCP Server
  Management API (`dhcpsapi.dll`: `DhcpEnumSubnets`, `DhcpGetSubnetInfo`,
  `DhcpEnumSubnetElements`). No PowerShell. A server that refuses or is unreachable
  produces one line in `errors` (for example "access denied: add the collector's account
  to the 'DHCP Users' group on dhcp01") and never fails the command.
* On non-Windows builds the command fails with "unsupported on this platform".

### Scan (`network_scan`)

Parameters are **re-validated on the collector** whatever the server sent: IPv4 only; a
target is `a.b.c.d`, `a.b.c.d/n` or `a.b.c.d-e.f.g.h`; each range at most a /16; at most
262,144 addresses after exclusions; ranges touching `0.0.0.0/8`, `127.0.0.0/8`,
`169.254.0.0/16` or `224.0.0.0` and above are refused. For CIDR targets of /30 or
shorter the network and broadcast addresses are not probed (exclusions do cover them).
`concurrency` is 1-64 (the console uses 20 or 64), `timeout_ms` 100-30,000, at most 16
SNMP credentials and 100 ports. `upload_url` must be a path under `/api/collector/` on
the enrolled server (an absolute URL is accepted only for that server's host).

Per address, through a bounded worker pool and a global packet-rate cap
(about 200 packets/s at concurrency up to 20, 500 above):

1. **ICMP echo** with `IcmpSendEcho2` (`iphlpapi.dll`; no raw sockets, no driver, no
   elevation). Skipped on non-Windows builds.
2. **ARP** with `SendARP` for addresses on a directly attached subnet; gives the MAC.
3. **Port check** (when `port_check` is true; the console's default): a TCP connect to
   each listed port. Open means alive. For an open port the collector reads up to 200
   bytes the service sends unprompted within one second (SSH / Telnet / FTP banners),
   control characters stripped. For 80 / 8080 and 443 / 8443 it sends a minimal
   `GET / HTTP/1.0` with a `Host` header and keeps **only the status line and the
   `Server` header** (TLS is accepted without certificate verification because only
   headers are read and nothing is trusted or sent). No credentials are ever sent. UDP
   161 counts as open only if SNMP answered. Other UDP ports are not probed.
4. **SNMP** (UDP 161, 1.5 s timeout, one retry; no retry for hosts that did not answer
   anything else). Credentials are tried **in the order given; the first that answers
   wins**. It then reads `sysDescr`, `sysObjectID`, `sysName`, `sysLocation`,
   `sysContact`, `sysUpTime`; ENTITY-MIB serial / model / software revision of the first
   chassis entry; IF-MIB `ifTable` / `ifXTable` (index, name, descr, MAC, oper status,
   `ifHighSpeed`; at most **512** interfaces); and the bridge forwarding table
   (Q-BRIDGE `dot1qTpFdbPort`, else BRIDGE `dot1dTpFdbPort`, port to interface name via
   `dot1dBasePortIfIndex`; at most **4,096** entries). GETBULK with small
   max-repetitions; at most about 20 s of SNMP per device. SNMP is also tried (with the
   supplied credentials only) on addresses that did not answer anything else, because
   many devices drop ping.
5. **Default community check**: only when no supplied credential worked, or the device
   answered with a v2c credential, and only for hosts that are alive: **one**
   `sysDescr` GET with community `public` and **one** with `private` (v2c, no retry).
   If one answers it is reported in `default_community` (`private` wins if both do). No
   dictionary, nothing else.
6. **Reverse DNS** with a short timeout, for devices that are reported.

Only alive devices are reported. `alive_via` lists `icmp`, `arp`, `tcp` and / or `snmp`.
`vendor`, `model`, `firmware`, `device_type` are **best-effort hints** from ENTITY-MIB,
the `sysObjectID` enterprise number and keywords in `sysDescr`; the server normalises
authoritatively.

### Uploading results

Batches of at most **500** devices are POSTed as JSON to `upload_url` with the
collector's credential (the same client as directory batches):
`{"scan_id","seq","final","devices":[...],"summary"?}`. `seq` starts at 0 and is
idempotent: a failed attempt (network error, 408, 429, 5xx) is retried with back-off
(2 s, 10 s, 30 s) with the **identical body** and the same `seq`; any other 4xx stops
the scan (nothing more is sent). A partial batch is also sent every minute so the
console shows progress. The `final` batch carries
`summary {"addresses","alive","snmp","duration_s","errors"}`.

### Cancellation and deadline

The scan ends at the command's `expires_at` (server clock) or after six hours,
whichever is first, and stops when the collector service stops. It then sends a final
batch with what it found, and an entry in `errors` saying how far it got. The server
should therefore set `expires_at` of a `network_scan` to the latest acceptable end of
the scan.

## What it never does

* It never logs in to anything, never guesses passwords (apart from the two default SNMP
  communities above, one request each), never runs an exploit and **never sends an SNMP
  SET**. Only GET and GETBULK are used.
* It never scans anything the console did not send, and never loopback, link-local,
  multicast or reserved space.
* It never scans from the endpoint agent: that binary does not contain the scanner and
  answers `network_scan` / `network_subnets` with "runs only on the dedicated network
  collector".
* **Secrets** (SNMP communities and v3 passwords) are held in memory for the duration of
  one scan. They are never written to disk, logged, included in diagnostics, echoed in
  results or error messages (error text is redacted before it is reported).

## Requirements on the collector host

* **Permissions**
  * Scanning needs no elevated rights (ICMP / ARP through the IP Helper API).
  * **DHCP suggestions** need the collector's account (the computer account under
    LocalSystem, or the gMSA) to be a member of the **DHCP Users** group on each DHCP
    server. Without it, AD-site suggestions still work and each DHCP server is reported
    as an error line.
  * AD site suggestions need read access to the Configuration partition (every
    authenticated user has it by default).
* **Firewall** (outbound from the collector): ICMP echo to the scanned ranges; UDP 161
  to devices; the TCP ports in the scan's port list; RPC (TCP 135 and dynamic ports) to
  DHCP servers for the DHCP suggestions; and the usual LDAP to domain controllers.
  Inbound rules are not needed.
* **Security tools**: scanning looks like reconnaissance. Some EDR and IDS products will
  flag or block the collector. Tell your security team before the first scan and
  consider an exclusion for `cnapp-collector.exe` or an alert-suppression window. Use
  the scan's exclude list for sensitive segments.
* Place the collector so it can reach the ranges (a collector in a data-centre VLAN
  cannot ARP a branch office; routed ranges rely on ICMP, TCP and SNMP).

## Diagnostics

`collector_diagnostics` results gain a `network` section: whether `IcmpSendEcho2`,
`SendARP` and the DHCP API are available on this host, and the last scan's summary
(`scan_id`, address / alive / SNMP counts, duration, batches, errors). It contains no
credentials, communities or targets.

## Time and volume

At 200 packets per second a /24 takes a few seconds to a minute; a /16 with the port
check on takes hours, because every address costs ICMP, ARP / ports and SNMP attempts.
Addresses that answer nothing cost the most (SNMP with each supplied credential is tried
on them too, 1.5 s each, no retry). Prefer several smaller scans, exclude known-empty
space, and keep the number of credentials small.

## Not verified on real hardware

The scanner is covered by tests that use loopback listeners, an in-process fake SNMP
agent (v2c) and injected interfaces; the Windows API calls compile for amd64 and arm64
but were not run against real devices. Please verify on a test segment before relying on
them:

* ICMP echo (`IcmpSendEcho2`) and ARP (`SendARP`) on a real Windows host.
* SNMPv3 against real devices (the v3 configuration is unit-tested, the exchange is
  not). `AES256` means the Blumenthal variant; some vendors (notably Cisco) use the
  Reeder variant (AES256C), which is not offered.
* The DHCP Server Management API calls against a real DHCP server.
* Vendor-specific behaviour of ENTITY-MIB, IF-MIB and bridge-table walks.

## Manual test checklist

1. On a collector 1.6.0, run **diagnostics** and check the `network` section
   (`icmp_available`, `arp_available`, `dhcp_available` all true).
2. Run subnet suggestions: AD subnets appear; a DHCP server without membership of "DHCP
   Users" gives the access-denied line; after adding the account, scopes appear.
3. Scan a /28 in a lab that contains a managed switch: check alive_via, MAC, hostname,
   SNMP block, interfaces and forwarding table, and the open ports with banners.
4. Scan with a wrong SNMP credential first and the right one second: the right one is
   reported; the device's logs show the wrong one tried first and the right one next.
5. Cancel (stop the service) mid-scan: a final batch arrives with the partial summary.
6. Confirm no secrets in `cnapp-collector` logs, the command result or the diagnostics.
