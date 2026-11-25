# Reputation checks

Part of the `external` module ("Attack surface & pre-ASV", [ATTACK_SURFACE.md](ATTACK_SURFACE.md)). For every
**verified domain** of an organisation it reports how the domain looks to the outside world: email security,
look-alike domains, blocklists and recently issued certificates. Code: `backend/app/external/reputation/`.
Migration `0037_reputation`. Backend only in part 1 (the console pages follow).

> **Passive only.** DNS look-ups and one certificate-transparency query per domain. No port is connected to, no web
> page is fetched, nothing is sent to a look-alike or third-party host, and an unverified domain is never assessed
> (the same ownership proof as the attack-surface scanner: DNS TXT, well-known file, or a subdomain of a verified domain).

## What is checked

| Group | Checks (finding `check_id`) | Severity |
| --- | --- | --- |
| Email security | SPF missing / several records / `+all` / `?all` / no ending policy / more than 10 DNS look-ups (`rep.spf_*`) | medium, high for `+all`, low for no ending |
| | DMARC missing / several / no valid policy / `p=none` / no `rua` (`rep.dmarc_*`) | high (missing, when the domain has MX), medium, low |
| | DKIM: a list of common selectors (`default google selector1 selector2 k1 k2 s1 s2 mail dkim`); "not found on common selectors" is **informational**, not a failure (`rep.dkim_not_found`) | info |
| | No MX, no MTA-STS, no TLS-RPT (`rep.mx_missing`, `rep.mta_sts_missing`, `rep.tls_rpt_missing`) | info |
| Look-alike domains | Up to `REPUTATION_LOOKALIKE_MAX` (default 300) permutations: omitted / repeated / swapped letters, neighbouring-key typos, homoglyphs (`0/o`, `1/l`, `rn/m`, `vv/w`, ...), hyphenation and other endings (TLD swap). Those that resolve (A / AAAA / MX, DNS only) are reported; the ones with **MX records** rank higher (`rep.lookalike_mail`, one finding each, at most 25) and the rest are one roll-up finding (`rep.lookalike_registered`). Only registrable domains (`example.com`, `example.co.uk`), not subdomains. Domains the organisation owns itself are skipped | medium / low |
| Blocklists | Pluggable DNSBL check of the domain and its MX / A addresses (`rep.blocklisted`). **Off unless zones are configured** | high |
| Certificate transparency | Certificates issued in the last `REPUTATION_CT_DAYS` (default 90): issuer, names, wildcard. An issuer not seen before for the domain (`rep.ct_new_issuer`); wildcard certificates (`rep.ct_wildcard`) | low / info |

The first successful certificate run of a domain only records its issuers (a baseline); an issuer first seen later is
flagged for `REPUTATION_CT_DAYS` days. Every finding has a plain-English title, a description and fix guidance.

## Findings, summary and lifecycle

Reputation findings (`REP-0001`, ...) have the lifecycle of external findings: **open**, **resolved automatically** when a
later run completes the check group and no longer sees the problem (re-opened if it returns), and **accepted risk**
(analysts, with a reason, audit-logged). Each domain has a summary: score (100 minus 25 / 15 / 8 / 3 per open
critical / high / medium / low finding; info costs nothing), grade (A 90+, B 80+, C 70+, D 50+, F), counts, last run
and the data behind it (email records seen, look-alikes found, recent certificates, blocklist state). A domain that
answers no DNS query at all (outage) concludes nothing: the run is "partial" and no finding is closed.

New high findings queue a `reputation_finding` notification (organisations with the `external` module).

## Runs

* **Weekly by default**, from the existing leader-elected `ExternalScheduler` (same `schedule_enabled` and
  `interval_hours` settings as the scans, Attack surface > schedule).
* **On demand**: `POST /api/external/reputation/runs` (analyst and above) with an optional `{"domain": "..."}`.
  Cooldown per organisation (`REPUTATION_COOLDOWN_SECONDS`, default 900) and one run at a time per organisation.
  Manual runs are audit-logged (`reputation_run_started`); so are accepting and re-opening findings.
* DNS look-ups are rate limited (`REPUTATION_DNS_RATE`, default 10 per second, per run).

## API (module `external`, same gate and roles as `/api/external/*`)

| Method and path | Role | |
| --- | --- | --- |
| `GET /api/external/reputation/domains` | viewer | summary per verified domain, last run, cooldown left, which checks are enabled |
| `GET /api/external/reputation/domains/{domain}` | viewer | one summary with the data behind it |
| `GET /api/external/reputation/findings` | viewer | filters `status, severity, category (email\|lookalike\|blocklist\|certificate), domain, q`, `sort`, `dir` |
| `GET /api/external/reputation/findings/{id}` | viewer | with evidence |
| `POST .../findings/{id}/accept-risk` (`{reason}`), `POST .../findings/{id}/reopen` | analyst | |
| `POST /api/external/reputation/runs` | analyst | 202; 409 nothing verified / already running; 422 unverified domain; 429 cooldown |
| `GET /api/external/reputation/runs`, `GET .../runs/{id}` | viewer | run status |

All data is per organisation (strict tenant isolation); one organisation never sees another's results.

## Data sources and their terms

| Source | Used for | Notes |
| --- | --- | --- |
| DNS (the resolvers of the server, falling back to 1.1.1.1 / 9.9.9.9, via the module's `dnsclient`) | everything except certificates | ordinary look-ups; rate limited |
| crt.sh JSON (`https://crt.sh/?q=%.domain&output=json`) | certificate transparency | a free public service run by Sectigo with no SLA and no formal commercial-use terms; it rate limits and is sometimes slow or down. We send one query per domain, cache the answer (`REPUTATION_CT_CACHE_SECONDS`, 6 h), cap the response and time out. It can be disabled (`REPUTATION_CT_ENABLED=false`) or pointed at another compatible source (`REPUTATION_CT_URL`, https only). The attack-surface discovery already uses it |
| DNS blocklists | blocklist checks | **none enabled by default**: see below |

### Blocklists (off by default)

Commercial-use terms differ per list. Spamhaus, for example, blocks queries from public resolvers and requires a paid
Data Query Service (DQS) key for commercial use; others are free only for low volume or non-commercial use. The
operator therefore chooses the zones after reading each list's terms:

* `REPUTATION_DNSBL_ZONES` : comma-separated zones that list IPv4 addresses, e.g. `zone.example` (queried as `4.3.2.1.zone.example`).
* `REPUTATION_DNSBL_DOMAIN_ZONES` : zones that list domain names (queried as `example.com.zone.example`).

With both empty (the default) no blocklist query is ever sent. Only global IPv4 addresses are looked up; answers in
`127.255.255.x` (query refused / over limit) are not treated as listings. Lists that need a per-customer key in the zone name (Spamhaus DQS) are not supported in v1: zone names are shown in
findings, so a key must not be placed there.

## What is never done

* No assessment of a domain that is not verified; no assessment of anything but a verified domain and names derived
  from it (look-alikes are only looked up in DNS).
* No HTTP request to a look-alike or any host other than the CT source; no port connection; no WHOIS / RDAP in v1.
* No exploitation or credential guessing. No blocklist query unless the operator configured zones.

## Configuration

| Variable | Default | |
| --- | --- | --- |
| `REPUTATION_DNSBL_ZONES`, `REPUTATION_DNSBL_DOMAIN_ZONES` | empty | blocklist zones (off) |
| `REPUTATION_CT_ENABLED` | `true` | certificate transparency on / off |
| `REPUTATION_CT_URL` | `https://crt.sh/` | https only |
| `REPUTATION_CT_DAYS` | `90` | certificate window and how long a new issuer stays flagged |
| `REPUTATION_CT_MAX_CERTS` | `200` | certificates kept per domain |
| `REPUTATION_CT_CACHE_SECONDS` / `REPUTATION_CT_TIMEOUT` | `21600` / `20` | |
| `REPUTATION_LOOKALIKE_MAX` | `300` | candidates per domain (10 to 500) |
| `REPUTATION_DNS_RATE` | `10` | DNS queries per second, 0 = unlimited |
| `REPUTATION_COOLDOWN_SECONDS` | `900` | between manual runs of an organisation |

## Not done yet

* **Risk score**: reputation findings do not feed the overall risk score. External findings do not feed it
  today either, so a consistent hook does not exist yet (TODO once the external findings are included).
* Console pages, PDF report section and look-alike WHOIS age are later parts.
