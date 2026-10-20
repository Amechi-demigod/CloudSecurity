# IT asset management (hardware lifecycle)

**IT assets** tracks company hardware from purchase to disposal: who has what, where it is, what it cost, when its warranty ends, and what happened to it over time. It covers the software side of tools like Workwize (records, custody, offboarding, disposal evidence), but not logistics such as shipping, warehousing or procurement.

- **Agent devices are tracked automatically.** Every laptop or desktop enrolled with the [endpoint agent](DEVICE_MANAGEMENT.md) gets an asset record. Its serial number, make and model come from the agent inventory.
- **Other assets are added by IT**, by hand or from CSV: monitors, phones, docks, headsets, laptops that are not enrolled yet, and so on.
- **Everything is on a timeline.** Assignments, returns, status changes, offboarding, disposal and certificate uploads are recorded with who, when and notes. Each change is also written to the audit log.

## Contents

- [Concepts](#concepts)
- [Using it](#using-it)
- [Agent devices](#agent-devices)
- [Offboarding and retrieval](#offboarding-and-retrieval)
- [Disposal and certificates](#disposal-and-certificates)
- [Utilization (idle devices)](#utilization-idle-devices)
- [CSV import and export](#csv-import-and-export)
- [Notifications](#notifications)
- [Roles](#roles)
- [API reference](#api-reference)
- [Configuration](#configuration)
- [Storage, backups and upgrades](#storage-backups-and-upgrades)

## Concepts

| Field | Notes |
|---|---|
| Asset tag | Unique (case-insensitive), 1-64 characters: letters, digits, `. _ / # -`. Agent devices get `AGT-<device id>`; rename freely |
| Serial number | Filled from the agent inventory when empty |
| Type | laptop, desktop, computer, monitor, phone, tablet, dock, peripheral, headset, printer, network, server, other |
| Make / model | Filled from the agent inventory when empty |
| Status | see below |
| Owner | name, email (lower-cased), department |
| Location / site | Free text. Admins keep a list of sites that the form suggests |
| Purchase | date, supplier, cost + currency (ISO 4217; default **NGN**, configurable) |
| Warranty end, expected refresh | Dates; drive the "warranty expiring" flag and notification |
| Notes, custom fields | Custom fields are admin-defined `key=Label` pairs (up to 50; values up to 500 characters) |

Statuses:

| Status | Meaning | How it is set |
|---|---|---|
| In stock | Available | Create, *Record return*, *Change status* |
| Assigned | Someone has it | *Assign* / *Reassign* (from in stock, assigned, in repair or retrieved) |
| In repair | At a repair shop; the owner is kept | *Change status* |
| Retrieval pending | The owner is leaving, or IT asked for it back; it has a due date | Offboarding, or *Change status* |
| Retrieved | Collected and waiting for checks or a wipe | *Record return* on a retrieval-pending asset, or *Change status* |
| Lost / Stolen | Written off; the last owner is kept. Raises a high-severity notification | *Change status* |
| Disposed | Final. Method, date, vendor and certificates are recorded | *Dispose* (not allowed while assigned or retrieval pending) |

"Total asset value" on the dashboard adds up purchase costs per currency for assets that are not disposed, lost or stolen. Different currencies are never converted.

## Using it

Open **IT assets** in the navigation:

- **Dashboard tiles.** Assets in use, assigned and in stock, total value, overdue retrievals, warranties expiring soon and idle devices. Below them are counts by status and type, the overdue list and the list of warranties expiring soon.
- **List.** Search by tag, serial, model, owner, site or agent hostname. Filter by status, type, site or agent, or by flag (retrieval overdue, warranty expiring, idle). *Export CSV* exports exactly what the current filters show.
- **Asset page.** Shows the details, purchase and warranty, the linked agent device (with a link to its device page), certificates and the **chain of custody** timeline. The available actions depend on the asset's status and your role.
- **Device page link.** Every device page (Devices → device) shows an **Asset ‹tag›** link with the status next to the health badges.
- **Offboarding.** Leavers and their outstanding assets.
- **Settings** (admins only). Default currency, idle and warranty windows, default retrieval delay, sites and custom fields.

## Agent devices

When someone opens the IT assets list or dashboard, any enrolled device without an asset record gets one:

1. If an asset without an agent has the **same serial number** (case-insensitive), the device is linked to it. This covers a laptop that IT recorded before it was enrolled, so no duplicate is created.
2. Otherwise a new record is created with status *in stock*, source *agent*, tag `AGT-<first 8 hex digits of the device id>`, and a type guessed from the model ("MacBook", "ThinkPad", "Latitude" give *laptop*; "iMac", "OptiPlex" give *desktop*; anything else gives *computer*).

Blank serial, make and model fields are filled from the inventory later too, because the serial number may only arrive with a later check-in. Values you type are never overwritten. Analysts can link or unlink a device by hand (`PATCH device_id`); a device can only be linked to one asset. If a device record is deleted under Devices, the asset and its history stay and only the link is cleared.

The asset sync only reads device rows. It does not touch the agent API or the agent itself.

## Offboarding and retrieval

**Offboarding → Person leaving** takes an email, a leave date and an optional retrieval due date (by default the leave date plus `retrieval_due_days`, which is 7). Every asset that is *assigned* or *in repair* for that email moves to **retrieval pending** with that due date, and the timeline records the change. Each person can have only one open offboarding at a time.

- **Record return** on a pending asset makes it *retrieved*, or *in stock* or *in repair* if you choose. When none of the person's assets is still pending (all retrieved, lost or stolen), the offboarding is marked **completed**.
- After the due date the asset is **overdue**. It is flagged in the list, counted on the dashboard and notified once (`retrieval_overdue`).
- **Cancel offboarding** (the person stays) moves the pending assets back to *assigned*.
- You can also put a single asset into retrieval with **Change status → Retrieval pending** and an optional due date.

## Disposal and certificates

**Dispose** records the method (recycled, destroyed, resold, donated, returned to vendor, other), the date (not in the future and not before the purchase date), the vendor and notes. A disposed asset cannot change status again.

**Certificates** (wipe or destruction evidence) can be uploaded at any time, before or after disposal:

- Only **PDF, PNG or JPEG** are accepted. The `Content-Type` must be one of those, and the file must start with the matching magic bytes (`%PDF-`, the PNG signature, `FF D8 FF`). Anything else returns 415, so an HTML or script file renamed `.pdf` is rejected.
- Files are limited to `ASSET_CERTIFICATE_MAX_BYTES` (5 MiB by default). The limit is enforced by the backend body limit, by the endpoint and by nginx (8 MiB on the upload path).
- The filename is reduced to safe characters, with the extension set from the detected type. The SHA-256 hash is stored and shown.
- Downloads are always `attachment` and carry `Content-Security-Policy: default-src 'none'; sandbox` and `nosniff`, so a file is never rendered inside the app.
- Analysts upload and download, and admins delete (with a reason). Every upload, download and deletion is audited.

## Utilization (idle devices)

An asset with an agent device that has not checked in for **`idle_days`** (default 30; or that never checked in and was enrolled that long ago) is an **idle candidate**. These assets are flagged in the list (filter *Flag → Idle device*) and counted on the dashboard. A notification (`device_unseen`) is sent once per quiet period. Use this list to reclaim or reassign hardware, or to find agents that have stopped working. Disposed, lost and stolen assets and revoked devices are ignored.

## CSV import and export

**Export** (`GET /api/it-assets/export.csv`, viewer and above, audited) writes UTF-8 CSV with these columns: `asset_tag, serial_number, asset_type, manufacturer, model, status, assignee_name, assignee_email, assignee_department, location, purchase_date, supplier, purchase_cost, currency, warranty_end, refresh_date, notes`, one `custom.<key>` column per custom field, and then read-only columns (`retrieval_due, disposal_*, device_hostname, device_last_seen_at, source, id`).

**Formula-injection guard:** any cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return is prefixed with `'`. Excel, LibreOffice and Google Sheets then show it as text and never evaluate it, so a value such as `=HYPERLINK(...)` typed into a notes field cannot run when someone opens the export. Import removes that prefix again, so you can edit an export and import it back.

**Import** (**Import CSV**, analyst and above):

- The header row must include `asset_tag`. Unknown columns, or `custom.<key>` columns for undefined fields, reject the file. Read-only export columns are ignored.
- Rows are matched by asset tag, ignoring case. New tags are created with source *import*. For existing tags, **empty cells leave the value unchanged**.
- Dates use the `YYYY-MM-DD` format. Costs are non-negative numbers; thousands separators are allowed. Currencies use 3-letter codes.
- `status` can be `in_stock`, `assigned`, `in_repair`, `retrieved`, `lost` or `stolen`. Retrieval and disposal go through their workflows and cannot be imported, and assets that are *retrieval pending* or *disposed* cannot be changed by import. Setting an `assignee_email` assigns the asset.
- **All or nothing.** If any row is invalid, nothing is imported and you get the list of errors per row. **Check file** runs the same validation without saving.
- Limits are `ASSET_IMPORT_MAX_BYTES` (2 MiB) and `ASSET_IMPORT_MAX_ROWS` (5,000). Files must be UTF-8, with or without a BOM. Each change goes on the asset's timeline as *CSV import*, and the import is audited with the file's SHA-256.

## Notifications

The notification source is **`asset_lifecycle`** (*IT asset lifecycle* in the rule builder). The event types are `retrieval_overdue`, `warranty_expiring`, `device_unseen` and `lost_or_stolen`; see [NOTIFICATIONS.md](NOTIFICATIONS.md#it-asset-lifecycle-events). To get a weekly-style summary, create a rule for this source with a *daily digest*.

## Roles

| Role | Can |
|---|---|
| viewer | Read everything: dashboard, list, asset pages, timelines, offboardings, settings; export CSV. Certificate file names are visible, but downloading requires analyst |
| analyst | Plus: create and edit assets, assign, return, change status, offboard and cancel offboardings, dispose, upload and download certificates, import CSV |
| admin | Plus: settings (currency, thresholds, sites, custom fields), delete asset records, delete certificates |

The API enforces the same rules and returns 403 otherwise. State-changing requests need the session's CSRF token like the rest of the API. There is no extra MFA step-up for asset actions.

Audit actions: `it_asset_created`, `it_asset_updated`, `it_asset_assigned`, `it_asset_returned`, `it_asset_status_changed`, `it_asset_disposed`, `it_asset_deleted`, `it_asset_certificate_uploaded` / `_downloaded` / `_deleted`, `it_asset_offboarding_created` / `_cancelled`, `it_assets_imported`, `it_assets_exported`, `it_asset_settings_updated`.

## API reference

All endpoints are under `/api/it-assets` and use session authentication.

| Method & path | Role | Purpose |
|---|---|---|
| `GET /` | viewer | List; query `q, status (active or a status), type, location, assignee, department, agent=yes/no, flag=idle/warranty_expiring/retrieval_overdue, limit, offset` |
| `GET /summary` | viewer | Dashboard counts |
| `GET /export.csv` | viewer | CSV export (same filters as the list) |
| `GET /by-device/{device_id}` | viewer | The asset record of an agent device (404 if none) |
| `GET /settings` · `PUT /settings` | viewer · admin | Effective settings; update (`null` resets a value to its env default) |
| `POST /import?dry_run=` | analyst | CSV import (raw `text/csv` body) |
| `POST /` · `GET /{id}` · `PATCH /{id}` · `DELETE /{id}?reason=` | analyst · viewer · analyst · admin | Create, read, edit, delete |
| `GET /{id}/events` | viewer | Chain of custody, newest first |
| `POST /{id}/assign` · `/return` · `/status` · `/dispose` | analyst | Lifecycle actions (409 if the current status does not allow the action) |
| `GET /offboardings` · `POST /offboardings` · `GET /offboardings/{id}` · `POST /offboardings/{id}/cancel` | viewer · analyst · viewer · analyst | Leavers |
| `POST /certificates/{asset_id}?filename=` | analyst | Upload (raw body, `Content-Type: application/pdf`, `image/png` or `image/jpeg`) |
| `GET /{id}/certificates` · `GET /{id}/certificates/{cid}` · `DELETE /{id}/certificates/{cid}?reason=` | viewer · analyst · admin | List, download, delete |

## Configuration

| Variable | Default | Description |
|---|---|---|
| `ASSET_DEFAULT_CURRENCY` | `NGN` | Currency for new assets (UI-overridable) |
| `ASSET_IDLE_DAYS` | `30` | Agent device unseen for this long = idle candidate (UI-overridable) |
| `ASSET_WARRANTY_WARNING_DAYS` | `30` | "Warranty expiring" window (UI-overridable) |
| `ASSET_RETRIEVAL_DUE_DAYS` | `7` | Default retrieval due date = leave date + N days (UI-overridable) |
| `ASSET_CERTIFICATE_MAX_BYTES` | `5242880` | Certificate size limit (nginx allows 8 MiB on the upload path; raise both together) |
| `ASSET_IMPORT_MAX_BYTES` / `ASSET_IMPORT_MAX_ROWS` | `2097152` / `5000` | CSV import limits |
| `ASSET_NOTIFICATION_POLL_SECONDS` | `3600` | How often the notification dispatcher checks overdue retrievals, warranties and idle devices (minimum 60) |

## Storage, backups and upgrades

- The data lives in new tables: `it_assets`, `it_asset_events`, `it_asset_offboardings`, `it_asset_certificates` and `it_asset_settings`. They are created by Alembic migration `0007_it_asset_lifecycle`, which runs automatically on startup (`DB_AUTO_MIGRATE=true`) or with `python -m app.cli migrate`. The migration only adds tables, and the downgrade drops them.
- **Certificates are stored in the database** (like agent log bundles), not on the file system. The nightly `cnapp-ctl backup` (`pg_dump`) and `cnapp-ctl restore` therefore include them with no extra volume or configuration. Expect the database, and so the backups, to grow by the size of the uploaded certificates.
- On-prem and container nginx configurations include an upload location (`/api/it-assets/import`, `/api/it-assets/certificates/`) that allows 8 MiB request bodies. On-prem it is reachable from the internal networks only, like the rest of the user API.
