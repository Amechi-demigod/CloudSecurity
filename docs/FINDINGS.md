# Posture findings: the detail page and report

`/findings/:id` is the one place that explains a posture finding and how to fix it. Exposure
(per-resource "Linked risk") and the Inventory asset drawer ("Findings (N)") link to it; they do not
repeat it.

## What the page shows

Header (severity, status, context chips, title, `rule id · resource · type · account · region`),
summary grid (severity, CVSS-style risk score 0-10, CWE weakness, MITRE ATT&CK, resource, account,
first seen / days open, fix due), then description, business impact, evidence (read-only
`key = value`, secret-looking keys masked), how to verify, how to fix (console | CLI | Terraform tabs
plus "Prevent it coming back"), compliance mapping and references. The right column has resource
facts, "Why this is critical here" (only when the asset is internet exposed, holds sensitive data or
sits on an attack path), the same rule on other resources, other findings on the resource and a
timeline.

There is no "Create ticket" or "Re-scan resource" button: no ticketing integration and no
per-resource rescan endpoint exist yet. Export, Resolve, Suppress and Reopen need the analyst role.

## Fix-by SLA

Counted from `first_seen`: critical 7 days, high 14, medium 30, low 90 (info: none). Past due the
page shows "Overdue by N days"; resolved findings show "Resolved".

## API

* `GET /api/findings/{id}` adds `guidance`, `risk_score`, `sla_days`, `sla_due`, `days_open`,
  `overdue_days`, `context` (`internet_exposed`, `sensitive_data`, `attack_paths`) and `asset`.
  `evidence` is returned with secret-looking keys (secret, password, token, key, credential) masked.
* `GET /api/findings/{id}/report.pdf` (analyst or above, tenant-scoped, audited as
  `finding_report_exported`, rate limited) renders the same sections as a PDF with the compliance
  report's writer (`app/compliance/finding_report.py`).

## Guidance data

`backend/app/engine/guidance/{azure,aws,gcp}.py` hold one entry per rule id (shared vocabulary in
`common.py`): impact, CWE, ATT&CK, risk score, verify steps and read-only command, console steps,
CLI, Terraform, prevention and https references. `<name>`, `<rg>`, `<region>`, `<subscription>` are
replaced at render time with the asset's own values, but only when the value is a plain identifier
(never text with shell metacharacters).

Adding a rule: add the `@rule` and a `GUIDANCE["<id>"] = g(...)` entry. `tests/test_finding_detail.py`
fails if any registered rule lacks complete guidance, if the risk score is outside the severity's
CVSS band (critical 9.0-10, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9), if a reference is not https
or if a verify command looks mutating. Everything is guidance: the platform never runs a command.
