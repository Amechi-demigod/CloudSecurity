# Attack surface & pre-ASV

Product module `external` ("Attack surface & pre-ASV"). An external, non-intrusive scanner that looks at your
internet-facing domains and addresses from outside, writes VAPT-style findings and produces a **pre-ASV report** in the
layout of the PCI ASV scan report.

> **It is not an ASV.** Every report and page says *pre-ASV, not an ASV scan report or attestation*. Only a PCI SSC
> Approved Scanning Vendor can issue an ASV scan report or an Attestation of Scan Compliance. The result ("Likely pass" /
> "Likely fail") helps you get ready.
>
> **No exploitation.** The scanner connects, reads banners and headers and sends harmless probes (HEAD / 256-byte range
> requests, the standard IIS tilde probe). It does not send exploit or injection payloads and never downloads or
> stores file contents.

Code: `backend/app/external/` (guard, net, dnsclient, tlsprobe, checks, catalog, engine, rules, cve, service, report,
api, scheduler). Migration `0032_attack_surface`. UI: Attack surface, Findings, Reports (sidebar group "Attack surface &
pre-ASV"); platform owners: Platform > Attack surface review.

## Module and organisations

`external` is a fifth product module (`app/modules.py`). Migration 0032 does **not** add it to existing organisations
(they never bought it; the explicit lists written by 0031 stay as they are). A NULL `organizations.modules` still means
"all modules", now including `external` (only databases that predate modules; the migrations write explicit lists).
All `/api/external/*` routes answer 403 `module_disabled` without it; the platform owner switches it per organisation
(Platform > Organisations, audited like the other modules). Turning it off keeps targets, findings and reports.

## How it works

1. **Add targets**: domains, public IPv4 addresses or CIDR ranges of at most a /24 (256 addresses), up to
   `EXTERNAL_MAX_TARGETS` (25) per organisation. Private, reserved and metadata ranges are refused when added.
2. **Prove ownership** (always, before any scan, see below).
3. **Discover**: DNS (A, AAAA, CNAME, MX, NS), subdomains from certificate transparency (crt.sh JSON, **verified
   domains only**, filtered to names equal to or below the verified domain), each name resolved and guard-checked.
4. **Scan**: TCP connect scan of the fixed port list, banners, TLS profile, web checks, risky-service checks.
5. **Findings** (EXT-0001, ...) with CVSS 3.1, CWE, evidence, steps, per-server fixes, references, compliance mapping,
   first / last seen and a fix-by date (`services/vuln_sla.py`: critical 7 days, high 14, medium 30, low 90).
   A finding is resolved automatically when a later scan of an alive host no longer sees it, and re-opens if it returns.
6. **Report**: pre-ASV PDF and console view.

Scans run weekly by default (configurable from daily to 90 days) and on demand ("Scan now", per-finding "Re-test now",
which scans only that finding's host). They run in a background thread started by the API or by the leader-elected
`ExternalScheduler` (like the cloud scan scheduler).

## Ownership proof

Unverified targets are **never scanned**.

* **Domain**: a DNS TXT record `sentrigis-verification=<token>` on the domain or on `_sentrigis.<domain>`, **or** a file
  `https://<domain>/.well-known/sentrigis-verification.txt` containing the token. Subdomains of a verified domain are
  covered. The proof is re-checked at the start of every scan; if it has disappeared the domain is skipped. The HTTP check
  goes through the address guard, so a domain pointing at an internal address cannot be "verified".
* **IP address or CIDR**: scanned, per address, only if (a) a verified domain resolves to it, (b) it is a public IP of
  the organisation's connected cloud inventory (needs the Cloud module), or (c) a platform owner approved it after the
  customer attested authorisation (the request, the approval and the owner's note are audit-logged in the
  organisation's log).
* **Scope declaration**: the customer lists the in-scope internet-facing systems and confirms it (admin, audit-logged).
  Editing the text withdraws the confirmation. It is Part 3c of the report and must be confirmed before a report can
  be generated.

## Safety limits (the scanner runs on the shared server)

| Guard | Detail |
|---|---|
| Address guard (`guard.py`) | Refuses private (RFC 1918), loopback, link-local (incl. 169.254.169.254), CGNAT (100.64/10, incl. 100.100.100.200), multicast, reserved, documentation, benchmarking and "this network" ranges, **all IPv6** (IPv4 only in v1; covers fd00:ec2::254 and IPv4-mapped forms), this server's own addresses, the configured egress IP and `EXTERNAL_BLOCKED_CIDRS`. |
| DNS rebinding | Names are resolved and **every** resolved address checked immediately before **every** connection (nothing cached); the connection is then made to the checked IP literal. If any one answer is refused the whole name is refused. |
| Concurrency | `EXTERNAL_MAX_CONCURRENT_SCANS` (2, whole server) and `EXTERNAL_MAX_SCANS_PER_ORG` (1), checked under an advisory lock; a busy scanner answers 429/409. |
| Rate limiting | Per host: `EXTERNAL_HOST_RATE` connection attempts per second (20) and `EXTERNAL_HOST_PARALLEL` parallel connections (10). |
| Timeouts | Connect `EXTERNAL_CONNECT_TIMEOUT` (4 s), read `EXTERNAL_READ_TIMEOUT` (6 s). |
| Maximum duration | `EXTERNAL_MAX_SCAN_SECONDS` (3600): the scan stops, the result is marked partial and nothing is auto-resolved. Scans left "running" by a dead process are failed after the limit plus 10 minutes. |
| Scan window | Optional per target (UTC hours, may wrap midnight, `PUT /api/external/targets/{id}/window`); targets outside it are skipped. (API only; no console control yet.) |
| Limits | 25 targets per organisation, /24 per range, 512 hosts per scan, 200 subdomains per domain. |
| Identification | HTTP User-Agent `Sentrigis-AttackSurface/1.0 (+https://sentrigis.com/scanner)`. The server's egress IP (`EXTERNAL_SCANNER_EGRESS_IP`) is shown on the Attack surface page and in the report so customers can allow-list it. |
| No contents stored | File probes are HEAD / `Range: bytes=0-255`; only status, size, type and "signature matched" are stored. Cookie values and credentials never are. |
| Tests | Never touch the network: mocks, or local servers on 127.0.0.1 with `guard.allow_for_tests` (refused when `APP_ENV` is production). |

## Ports scanned

TCP connect scan (no raw packets) of these ports (`ports.py`, 115 ports): 21 22 23 25 53 80 81 88 110 111 119 123 135
137 139 143 161 179 389 443 445 465 500 514 515 548 554 587 631 636 873 990 993 995 1080 1194 1433 1434 1521 1701 1723
1883 2049 2082 2083 2086 2087 2181 2222 2375 2376 3000 3128 3306 3389 3478 4000 4443 4567 5000 5001 5060 5222 5432 5601
5672 5900 5901 5984 5985 5986 6000 6379 6443 7001 7070 7443 7547 8000 8008 8080 8081 8082 8083 8086 8088 8090 8123 8181
8243 8280 8443 8444 8500 8800 8834 8880 8888 9000 9042 9090 9092 9100 9200 9300 9418 9443 9999 10000 10250 11211 15672
27017 32400 50000. Server-first services (FTP, SSH, Telnet, SMTP, POP3, IMAP, MySQL, VNC) have their banner read. UDP
and STARTTLS are not covered.

## Checks

* **TLS** (`tlsprobe.py`): SSLv3, TLS 1.0 and 1.1 probed with a hand-built ClientHello (the ServerHello is read;
  independent of the scanner's OpenSSL build), TLS 1.2 / 1.3 through the ssl module; accepted weak cipher classes (RC4,
  3DES, EXPORT, NULL, anonymous DH); certificate expired / expiring (30 days) / self-signed / untrusted chain / host name
  mismatch / RSA < 2048 or SHA-1 / MD5 signature.
* **Web**: missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options; cookie flags (Secure, HttpOnly, SameSite);
  Server / X-Powered-By version disclosure; exposed files (.git, .env, .htpasswd, .DS_Store, backups, archives, SQL
  dumps, config backups, phpinfo, server-status) matched by file signature and baselined against soft-404 pages;
  admin panels (phpMyAdmin, WordPress, Tomcat manager, Jenkins, Grafana, actuator, ...); API docs (Swagger / OpenAPI,
  ReDoc, GraphQL playground); directory listing; IIS short-name (tilde) disclosure using the standard two-request probe
  (no enumeration); verbose error pages (stack traces); scripts and frames from other domains (Part 3b).
* **Services**: risky services reachable from the internet: Telnet, FTP, RDP, VNC, SMB, NetBIOS, MS-RPC, WinRM, NFS,
  SNMP, rsync, MySQL, PostgreSQL, SQL Server, Oracle, MongoDB, Redis, Elasticsearch, Memcached, CouchDB, Docker API.
* **Known CVEs** for software versions detected from banners (Apache, nginx, IIS, OpenSSH, ProFTPD, vsFTPd, PHP, Exim,
  lighttpd, OpenSSL) using the existing NVD cache and CPE matcher (`app/vulnmatch`), highest 15 per product. Versions
  from banners can be backported by distributions; the finding says so and can be disputed.
* **End of life** (automatic fail) for: PHP < 8.1, Apache < 2.4, IIS < 8.5, OpenSSL < 1.1.1, OpenSSH < 7.4.
* **Default passwords: opt-in per target.** Off by default. An org admin switches it on with an explicit consent
  checkbox (audit-logged with who and when). It tries a built-in list of 6 vendor-default logins on HTTP Basic
  realms found on the target, 1.5 s apart, stops at the first success, and first checks that a random login is refused
  (a server accepting anything is not reported). Nothing about the credentials is stored, shown or logged; the finding
  only says "default credentials accepted for HTTP Basic at /path".

## Pass / fail rules (`rules.py`)

| Rule | Result |
|---|---|
| CVSS base score 4.0 or higher | Fail |
| SSLv3, TLS 1.0 or TLS 1.1 offered | Automatic fail, whatever the score |
| SQL injection or cross-site scripting indicated (CWE-89 / CWE-79 on a matched CVE) | Automatic fail |
| Vendor default credentials accepted | Automatic fail |
| End-of-life / unsupported software detected from banners | Automatic fail |
| Denial-of-service-only vulnerability (CVE with no confidentiality / integrity impact) | Does not fail |
| Accepted dispute (false positive / compensating control) | Does not fail; listed as an exception in Part 3a |
| Resolved finding | Not counted |
| "Accepted risk" status | Still counts |

A host passes when none of its counted findings fails; the overall result is "Likely pass" only if every host passes.
The scanner sends no injection payloads, so SQL injection / XSS can only be indicated through matched CVEs.

**Marked as uncertain (confirm with an ASV):** certificate failures rely on the CVSS scores chosen in
`catalog.py` (4.2 for an expired, self-signed, untrusted or mismatched certificate); headers, cookie flags, banners,
API docs, browsable directories and admin panels are scored below 4.0 so they are listed but do not fail; directory
listings and remote access services are also copied to Part 3b.

## Report (ASV layout)

Cover (title, "not an ASV scan report or Attestation of Scan Compliance", customer, scan dates, scanner IP, result);
Part 1 scan information; Part 2 component compliance summary (pass / fail per host); Part 3a vulnerabilities noted per
component with severity, CVSS, status and exceptions / false positives / compensating controls; Part 3b special notes
(remote access, browsable directories, scripts from other domains, default credentials); Part 3c customer-declared
scope; the rule table. PDF through the repository's dependency-free PDF writer, plus an in-console view. A generated
report is a stored snapshot.

## Disputes

A customer analyst or admin disputes a finding (false positive or compensating control, with a reason; text only). The
finding shows "disputed" and still counts until a platform owner (Platform > Attack surface review) accepts or rejects it
with a required note. Accepted disputes do not fail the report and appear in Part 3a; rejected ones re-open the finding.
Submissions, reviews, approvals, consent, scope and schedule changes, target changes, scans and reports are all
audit-logged.

## Cross-module

* Vulnerabilities: CVE findings of external hosts that match a **cloud asset** (its public IP is in inventory) are also
  listed in Vulnerabilities with source `external` when the organisation has that module. Hosts with no matching asset
  are not listed there (a Vulnerability needs an asset, device or network device): follow-up.
* Cloud: an exposed IP matching a cloud asset links the external host to it (`ExternalHost.asset_id`).
* Notifications: source `external_finding` (module `external`) raises an event for each new or re-opened critical or high
  finding.

## Not in this version

IPv6; UDP; STARTTLS; evidence file upload for disputes (text only); FTP / SSH default credentials; a console control
for scan windows; resolving findings of hosts that vanished from DNS; a Vulnerabilities entry for hosts without a cloud
asset. No exploit validation, and nothing here is an ASV attestation.
