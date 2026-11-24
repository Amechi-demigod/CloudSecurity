# MSP accounts (partner organisations)

A **managed service provider (MSP)** is a partner company with its own Sentrigis account. It onboards and manages
its own **client organisations**: it creates them, chooses their modules, suspends them, invites their first admin,
and its staff work inside them with the whole console.

This is part 1 (backend). See [MULTI_TENANCY.md](MULTI_TENANCY.md) for the tenancy model it builds on and
[AUTH.md](AUTH.md) for sessions.

- [Model](#model)
- [Roles](#roles)
- [Working inside a client](#working-inside-a-client)
- [Visibility rule: the client does not see the MSP](#visibility-rule-the-client-does-not-see-the-msp)
- [Audit rule](#audit-rule)
- [Security model](#security-model)
- [API](#api)

## Model

| Field | Meaning |
|---|---|
| `organizations.kind` | `customer` (default; every existing organisation) or `msp` |
| `organizations.partner_org_id` | on a client: the MSP that manages it (nullable, FK, indexed) |
| `organizations.max_clients` | on an MSP: most clients it may have (null = unlimited) |
| `organizations.status_set_by` | `platform` / `partner`: who last suspended or reactivated it |
| `user_sessions.acting_org_id` | MSP staff only: the client the session currently works in |
| `audit_log.via_partner_org_id` | set on rows written by MSP staff inside a client |

Only the **platform owner** creates an MSP, marks an organisation as one, sets `max_clients`, and moves a client
between MSPs (or ends the partnership). An MSP cannot be a client; the default organisation can be neither.
An MSP's own staff are ordinary members of the MSP organisation (managed with the normal `/api/users` and
`/api/organization/invitations` endpoints while in the MSP organisation).

## Roles

Roles are the existing ones, in the MSP organisation:

| MSP role | In the MSP | Inside a client |
|---|---|---|
| `admin` | create / edit / suspend clients, set modules, invite client admins, manage MSP staff | `admin` |
| `analyst` | list and enter clients | `analyst` |
| `viewer` | list and enter clients | `viewer` |

The role inside a client is the MSP role, mapped one to one. MSP staff are never platform owners inside a client.

## Working inside a client

`POST /api/msp/switch {"organization_id": "<client id>"}` stores the client on the session (`acting_org_id`).
From then on every console API acts in that client, scoped by the same tenancy guard as a normal member
(`/api/auth/me` reports the client as the organisation, plus `home_organization` and `acting_as_client`).
`{"organization_id": null}` goes back. The `/api/msp/*` endpoints work in both states.

Access is **derived on every request** from the partner relationship, not from a membership row in the client:
the session's organisation must be an active MSP, the client must have `partner_org_id` = that MSP and be
active. If any of it stops being true (client moved away, MSP suspended, staff removed from the MSP, client
suspended) the session falls back to the MSP organisation or ends, on the very next request.

Module switches apply inside the client exactly as for its own users (`403 module_disabled`).

## Visibility rule: the client does not see the MSP

* MSP staff have no membership in the client, so they are absent from the client's user list, admin counts
  (last-admin guard), onboarding "team" step, invitations and usage numbers, and a client admin cannot find,
  update, reset or delete them (404).
* While acting in a client, MSP staff use a **stand-in identity**: the real user id (so "different person"
  rules such as approvals work) but a neutral display name, `Managed security team`. Every place that stores
  an actor name or email (created_by, requested_by, invited_by, scan triggered_by, ...) shows that label, never
  the person. Invitations sent by the MSP have no inviter name; the email names the brand only.
* The client's own API never returns `kind` / `partner_org_id`; `PATCH /api/organization` rejects them.
* Client admins cannot change or remove the partnership: only `/api/platform/*` can, and it is owner-only.

## Audit rule

* Everything MSP staff do inside a client is written to the **client's** audit log with the **real actor**
  (id and email) and `via_partner_org_id` = the MSP. These rows are filtered out of the client's
  `GET /api/audit-log` (and of the scan "triggered by" lookup). They are visible to the platform owner:
  `GET /api/platform/organizations/{id}/audit-log` (`?via_partner=true|false`).
* MSP-level actions are audited in the **MSP's own** log: `msp_client_created`, `msp_client_updated`,
  `msp_client_module_enabled` / `_disabled`, `msp_client_suspended`, `msp_client_reactivated`,
  `msp_client_user_invited`, `msp_client_invitation_resent`, `msp_client_entered`, `msp_client_left`,
  `msp_client_partnership_changed` (by the platform owner), plus the usual staff events (`user_created`,
  `user_updated`, `user_invited`, ...).
* There is no MSP-facing "activity in clients" endpoint in this version.
* Platform actions on the partnership (`organization_partner_changed`) are written to the client's log with the
  flag, so the client never sees them either.

## Security model

* Fail closed: `/api/msp/*` requires staff of an *active MSP*; everything else 403/401.
* Clients are looked up only through `partner_client(msp, id)`. Another MSP's client, a plain customer, the
  default organisation, the MSP itself and unknown ids all answer 404 (no existence oracle).
* No escalation: platform endpoints stay owner-only (a platform owner who is also MSP staff is not one inside a
  client); MSP staff cannot create MSPs or change `partner_org_id`.
* Suspended MSP: attach-membership fails, so its staff's sessions end (all clients). A client suspended by the
  platform owner cannot be reactivated by its MSP (`status_set_by`).
* Approvals: an MSP admin in a client counts as an admin there but cannot approve their own request (same
  user id); another MSP admin or a client admin can.
* CSRF and cookies are unchanged: switching is an ordinary POST with the CSRF header.

## API

MSP staff (`/api/msp`, any MSP role unless noted):

| Endpoint | Role | Purpose |
|---|---|---|
| `GET /api/msp` | any | the MSP, own role, client count and limit |
| `POST /api/msp/switch` | any | enter a client / go back (`organization_id` null) |
| `GET /api/msp/clients`, `GET /api/msp/clients/{id}` | any | clients with status, modules, pending invitations |
| `POST /api/msp/clients` | admin | create a client: name, contact email, modules (any), optional `admin_email` (invites the first admin) |
| `PATCH /api/msp/clients/{id}` | admin | name, contact email |
| `PUT /api/msp/clients/{id}/modules` | admin | set the module list (any module) |
| `POST /api/msp/clients/{id}/suspend`, `/activate` | admin | suspend / reactivate (`{"reason": ...}`) |
| `GET/POST /api/msp/clients/{id}/invitations`, `POST .../{inv}/resend` | admin | invite the client's (first) admin; same invitation flow |
| `GET /api/msp/overview?limit&offset` | any | per client: status, modules, risk score, open critical findings, devices, assets, users, last scan |

The overview computes the risk score per client with the dashboards service, so one request covers at most 100
clients (`truncated` / `total_clients` tell the UI to page with `offset`); counts come from grouped queries.
Suspended clients are listed without numbers.

Platform owner (`/api/platform`): `POST /organizations` with `kind: "msp"`, `max_clients`, or `partner_org_id`;
`PATCH /organizations/{id}` with `kind` / `max_clients`; `PUT /organizations/{id}/partner`
(`{"partner_org_id": id|null}`); `GET /organizations/{id}/audit-log`. Organisation listings show `kind`,
`partner_org_id`, `max_clients` and `clients`.

Deleting a client stays with the platform owner. Client deletion by MSPs is out of scope.
