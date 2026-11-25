# Executive report

A short report (two to three pages) that a CEO or director can read in five minutes: a plain-language view of the
whole environment, with no jargon. It is shown on screen (**Compliance & reports > Executive report**), downloadable
as a PDF, and can be emailed on a schedule to administrators and to named people who have no console account.

## Contents

- [What it contains](#what-it-contains)
- [Periods and trends](#periods-and-trends)
- [Recipients](#recipients)
- [Schedules](#schedules)
- [Security model](#security-model)
- [API reference](#api-reference)
- [Configuration](#configuration)
- [Limitations](#limitations)

## What it contains

Sections appear only for the modules the organisation has (`app/modules.py`); a module that was not bought is simply
absent. Every number is explained in a sentence.

| # | Section | Needs module |
|---|---------|--------------|
| 1 | Headline: "Your overall risk is 58 out of 100 (moderate; lower is better), 6 points better than last month." Without the cloud module the headline counts serious problems instead of a score. | any |
| 2 | Top 5 risks to act on, each with why it matters and who should act. Candidates: known-exploited software flaws, critical flaws, routes an attacker could follow, top cloud issues, device protection problems, internet weaknesses, reputation findings. Ranked by severity; at most two per area so the list stays varied. | cloud, vulnerabilities, endpoints, external |
| 3 | What improved / got worse: items fixed vs new, critical counts, compared with the same measures one period earlier. | cloud, vulnerabilities, endpoints |
| 4 | Coverage: cloud accounts connected, devices reporting vs not seen, domains monitored. | cloud, endpoints, external |
| 5 | Compliance at a glance: automated score and coverage per framework, with the standard disclaimer (evidence, not certification). | cloud, endpoints or vulnerabilities |
| 6 | Internet exposure and reputation: weaknesses by severity and the reputation grade (A to F) per domain, from the reputation tables ([REPUTATION.md](REPUTATION.md)). | external |
| 7 | Overdue fixes: open vulnerabilities past their fix-by date ([VULNERABILITIES.md](VULNERABILITIES.md), `services/vuln_sla.py`). | vulnerabilities |
| 8 | Recommended next steps: three bullets chosen by simple rules from the data (overdue fixes first, then the biggest critical risk, serious internet weaknesses, poorly graded domains, devices not reporting, unconnected cloud accounts, the weakest framework), padded with general advice. No AI. | any |

Footer of every page: organisation name, period covered, generated date, page number and the Sentrigis name. The
cover line carries the organisation name. There is never MSP branding (MSPs are hidden from clients,
[MSP.md](MSP.md)). The code is `app/executive/data.py` (assembly), `pdf.py` (rendering, built on the dependency-free
writer of the compliance report, `app/compliance/pdf.py`) and `delivery.py` (scheduling and email).

## Periods and trends

`period` is `daily`, `weekly`, `monthly` or `quarterly`, covering the last 1, 7, 30 or 90 days. Trends reuse the daily
dashboard snapshots ([DASHBOARDS.md](DASHBOARDS.md)): the comparison point is the snapshot taken one period earlier
(2 days of tolerance). When none exists the report says the comparison is not available yet instead of inventing one;
it fills in as history builds up. "Fixed" and "new" counts come straight from the findings and vulnerabilities
(resolved or first seen inside the period).

## Recipients

* **Administrators** (console users with the admin role): each can opt in per report. They are resolved at send time,
  so someone who is later demoted or removed stops receiving it.
* **Named people with no console account** (CEO, directors): name, email, optional job title. Each email carries a
  personal **unsubscribe link**: a signed token (HMAC with `SESSION_SECRET`) naming one recipient of one organisation.
  Opening the link only shows a confirmation button (mail scanners that prefetch links change nothing); pressing it
  switches that person off for that report. The link grants nothing else: it creates no session, cannot reach an
  administrator recipient, and a token for another organisation finds nothing.

Emails are validated (no control characters, one address each). At most 25 recipients per report and 10 reports
per organisation. Each recipient gets their own email: a short summary (headline and three biggest risks) with the PDF
attached; administrators also get a link to the page in the console.

## Schedules

An organisation can have several subscriptions, each with a name, frequency, enabled switch and recipient list.

| Frequency | `day` | Sent |
|-----------|-------|------|
| daily | unused | every day at `hour` UTC |
| weekly | 0 (Monday) to 6 | that weekday |
| monthly | 1 to 28 | that day of the month |
| quarterly | 1 to 28 | that day in January, April, July and October |

The leader-elected worker (`ExecReportWorker`, like the compliance report worker) checks every five minutes and sends
what is due; a missed slot is sent once on the next tick, never repeated per missed period. The report period matches
the frequency. Each send records the outcome (`last_status`: `sent`, `partial` or `failed`, and the reason). A PDF
larger than `COMPLIANCE_REPORT_MAX_BYTES` is not sent.

## Security model

The report is sensitive.

* Only organisation **admins** manage subscriptions, recipients and "Send now". Viewers and analysts can read the
  on-screen report and download the PDF (they can already see the underlying data in the console).
* Recipient list changes (`exec_report_recipient_added` / `_removed`), subscription changes, sends
  (`exec_report_sent` / `exec_report_failed`), downloads (`exec_report_downloaded`) and unsubscribes
  (`exec_report_unsubscribed`) are audit-logged.
* PDF downloads are limited to 10 per 10 minutes per user; "Send now" to 5 per hour per organisation; the public
  unsubscribe endpoint to 30 per 10 minutes per IP.
* Everything is read through the tenant-scoped session: one organisation's report never contains another's data, and
  another organisation's subscription or recipient ids answer 404. An administrator of another organisation cannot be
  added as a recipient.
* MSP staff working inside a client manage that client's reports like any admin (same role mapping, stand-in
  identity); their audit rows name the real person and are hidden from the client ([MSP.md](MSP.md)).
* Emails need a platform mail server (`PLATFORM_SMTP_*` or `PLATFORM_ACS_*`, [NOTIFICATIONS.md](NOTIFICATIONS.md));
  without one a send fails with a clear message. Unsubscribe links need `PUBLIC_BASE_URL`; without it external
  recipients get no link.

## API reference

All under `/api/reports/executive`. Session-authenticated except the unsubscribe pair.

| Method and path | Role | Purpose |
|-----------------|------|---------|
| `GET ?period=` | viewer | The report as JSON (the console renders it) |
| `GET /pdf?period=` | viewer | PDF download (audited, rate-limited) |
| `GET /subscriptions` | admin | Subscriptions with recipients, the organisation's admins, limits, `mail_configured` |
| `POST /subscriptions` | admin | `{name, frequency, day, hour, enabled}` |
| `PATCH /subscriptions/{id}` | admin | Any of those fields |
| `DELETE /subscriptions/{id}` | admin | Delete with its recipients |
| `POST /subscriptions/{id}/recipients` | admin | `{kind: "admin", user_id}` or `{kind: "external", name, email, job_title?}` |
| `DELETE /subscriptions/{id}/recipients/{rid}` | admin | Remove a recipient |
| `POST /subscriptions/{id}/send` | admin | Send now (rate-limited) |
| `GET /unsubscribe?token=` | public | Confirmation page (changes nothing) |
| `POST /unsubscribe?token=` | public | Unsubscribe that recipient |

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `EXECUTIVE_REPORT_WORKER_ENABLED` | true | Run the scheduled-report thread in this process |
| `PUBLIC_BASE_URL` | empty | Base of the links in emails (console page and unsubscribe) |
| `SESSION_SECRET` | none | Signs unsubscribe tokens (required in production) |
| `COMPLIANCE_REPORT_MAX_BYTES` | 8 MiB | Largest PDF that is emailed |

## Limitations

* Compliance numbers are the automated score and coverage only; the section always repeats that it is evidence, not
  certification.
* The report covers the whole organisation; it has no per-account or per-group scope.
* Known-exploited flaws use the 14-day rule, not the exact catalogue due date.
* Rankings are simple rules, not a model; the wording of a finding comes from the rule that raised it.
