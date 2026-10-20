# Multi-factor authentication and Microsoft Entra ID sign-in

This guide covers the two sign-in features added on top of the password login
from Phase 2:

* **TOTP MFA**: a 6-digit code from an authenticator app (RFC 6238) as a second
  step after the password, with one-time recovery codes.
* **Sign in with Microsoft**: single sign-on with Microsoft Entra ID (OpenID
  Connect, authorization code flow with PKCE).

Both end in the same thing: a normal CloudSecurity session (the same httpOnly
cookie, CSRF token, idle timeout and RBAC as a password login).

- [How sign-in works](#how-sign-in-works)
- [MFA (TOTP)](#mfa-totp)
- [Microsoft Entra ID single sign-on](#microsoft-entra-id-single-sign-on)
- [Password login policy and break-glass access](#password-login-policy-and-break-glass-access)
- [Settings reference](#settings-reference)
- [Audit events](#audit-events)
- [Security design](#security-design)
- [Limitations](#limitations)

## How sign-in works

```
Password ──► POST /api/auth/login ──┬─► session cookie + CSRF token          (no MFA needed)
                                    ├─► {mfa_required, purpose: verify}  ──► POST /api/auth/login/mfa            ──► session
                                    └─► {mfa_required, purpose: enroll}  ──► .../login/mfa/enroll/start + confirm ──► session + recovery codes

Microsoft ──► GET /api/auth/sso/entra/login ──► Entra ID ──► GET /api/auth/sso/entra/callback ──► session cookie ──► app
                                                                     (local TOTP only with ENTRA_ENFORCE_LOCAL_MFA=true)
```

The login page asks `GET /api/auth/providers` (public) which methods to show:
the **Sign in with Microsoft** button appears only when Entra ID is configured,
and the password form is hidden when password login is disabled (with an
"Emergency administrator sign-in" link for break-glass accounts).

## MFA (TOTP)

### For users

1. User menu → **Security (two-step verification)** → **Set up authenticator app**.
2. Scan the QR code with Microsoft Authenticator, Google Authenticator,
   1Password, … (or type the setup key), then enter the 6-digit code. MFA is
   only switched on once a correct code is entered (verify-before-enable).
3. Save the 10 **recovery codes** (copy or download). They are shown once; each
   one works once in place of an app code.

From the same page you can generate new recovery codes or turn MFA off. Both
need your current password **and** a current app or recovery code (users who
only sign in with Microsoft have no local password, so only the code is asked).
Turning MFA off signs out your other sessions.

MFA is asked **only at sign-in**. Once signed in, actions inside the app
(user management, device actions, agent update releases/rings/pins,
notifications, …) need no further authenticator code; they are protected by the
session, role-based access control and CSRF, and every change is written to the
audit log. Only managing your own MFA (turning it off, new recovery codes) asks
for a current code, as above.

### For administrators

* **Require MFA for roles**: `MFA_REQUIRED_ROLES=admin,analyst`. Users with these
  roles who have not enrolled are taken through enrolment at their next password
  login (they cannot reach the app before finishing it) and cannot turn MFA off.
* **Lost device**: Administration → Users → **Reset MFA** removes the user's
  authenticator and recovery codes and signs them out. If their role requires
  MFA they enrol again at their next login. Audited as `mfa_reset`.
* The Users list shows each user's MFA status and how they sign in
  (Password / Microsoft).
* **Encryption key** (required in production): `MFA_ENCRYPTION_KEY`, any string
  of 32+ characters, e.g. `openssl rand -hex 32`. On Azure it is generated on the
  first deployment and kept in Key Vault (`mfa-encryption-key`); nothing to do.
  Rotation: set `MFA_ENCRYPTION_KEY=<new>,<old>`; the first key encrypts new
  secrets, all keys decrypt. Losing every key means every user must re-enrol
  (recovery codes keep working, they are hashed, not encrypted).

### Lockout and rate limiting

Wrong MFA codes count towards the same account lockout as wrong passwords
(`LOGIN_MAX_FAILURES` within one login, then `LOGIN_LOCKOUT_MINUTES`). A correct
password does **not** reset the counter while the second step is pending, so
the password cannot be used to buy more code guesses. Each challenge token is
valid for `MFA_CHALLENGE_TTL_SECONDS` (300) and `MFA_CHALLENGE_MAX_ATTEMPTS` (5)
wrong codes, and the code endpoints share the per-IP rate limit
(`LOGIN_RATE_LIMIT` per `LOGIN_RATE_WINDOW_SECONDS`).

A code is accepted for its 30-second step and one step either side (clock
drift). Once a code has been used, it and every older code are rejected, even
inside the window (replay protection).

## Microsoft Entra ID single sign-on

### What you get

* **Sign in with Microsoft** on the login page; the backend validates the ID
  token (signature against the tenant's JWKS, issuer, audience, tenant id,
  nonce, expiry) and issues a normal session.
* Users are matched by their Entra **object id** after the first sign-in, and
  by e-mail before that (see [User matching](#user-matching)).
* Optional just-in-time provisioning and app-role / group → role mapping.
* MFA for Microsoft sign-ins is enforced **by Entra ID** with Conditional
  Access; the local authenticator is skipped for them unless
  `ENTRA_ENFORCE_LOCAL_MFA=true`.

### Option A: deployed on Azure (recommended, no secret)

After the first deployment (docs/DEPLOY_AZURE.md):

```bash
az login            # an account that can create app registrations
gh auth login
infra/setup.sh --entra-sso --dry-run      # review
infra/setup.sh --entra-sso
# also allow local / Codespaces testing against the same app registration:
infra/setup.sh --entra-sso \
  --sso-redirect-uri http://localhost:5173/api/auth/sso/entra/callback
```

This creates (idempotently) an app registration `cloudsecurity-cnapp-<prefix>-sso`
that is single-tenant, has the redirect URI
`https://<web app fqdn>/api/auth/sso/entra/callback`, the app roles
`CNAPP.Admin`, `CNAPP.Analyst` and `CNAPP.Viewer`, and "assignment required" on
its enterprise application. It also adds a **federated credential that trusts
the backend's managed identity**: the backend proves its identity to Entra with
a managed-identity token instead of a client secret, so there is no secret to
store or rotate. It sets the repository variables `CNAPP_ENTRA_CLIENT_ID` and
`CNAPP_ENTRA_CLIENT_AUTH=managed_identity`.

Then:

1. Assign users or groups to an app role: Entra admin center → Enterprise
   applications → `cloudsecurity-cnapp-<prefix>-sso` → Users and groups → Add.
2. Add Conditional Access (below).
3. Run the **Deploy to Azure** workflow. The deployment sets `ENTRA_TENANT_ID`,
   `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_AUTH`, `ENTRA_REDIRECT_URI` (derived from
   the web app URL; also a deployment output) and `ENTRA_ROLE_MAP`.

Optional repository variables read by the deploy workflow: `CNAPP_ENTRA_ROLE_MAP`
(default `CNAPP.Admin=admin,CNAPP.Analyst=analyst,CNAPP.Viewer=viewer`),
`CNAPP_ENTRA_JIT_PROVISIONING` (`false`), `CNAPP_ENTRA_DEFAULT_ROLE`
(`viewer`), `CNAPP_MFA_REQUIRED_ROLES`, `CNAPP_PASSWORD_LOGIN_ENABLED`
(`true`), `CNAPP_BREAK_GLASS_EMAILS` (default: the admin e-mail),
`CNAPP_ENTRA_CLIENT_AUTH` and `CNAPP_ENTRA_CREDENTIAL_SECRET_NAME` (option C).

### Option B: manual registration with the az CLI (local, Codespaces, other hosts)

```bash
TENANT_ID=$(az account show --query tenantId -o tsv)
# Redirect URIs: one per place the app runs (exact match, path included).
#   Local (Vite dev server or docker compose): http://localhost:5173/api/auth/sso/entra/callback
#   GitHub Codespaces: https://<codespace-name>-5173.app.github.dev/api/auth/sso/entra/callback
#   Azure:             https://<web app fqdn>/api/auth/sso/entra/callback
APP_ID=$(az ad app create --display-name cloudsecurity-cnapp-sso --sign-in-audience AzureADMyOrg \
  --web-redirect-uris http://localhost:5173/api/auth/sso/entra/callback \
  --app-roles '[{"id":"6f2d6b1e-6b3c-4b8e-9a51-1c7c0c0a0001","value":"CNAPP.Admin","displayName":"CNAPP Admin","description":"Admin","allowedMemberTypes":["User"],"isEnabled":true},
                {"id":"6f2d6b1e-6b3c-4b8e-9a51-1c7c0c0a0002","value":"CNAPP.Analyst","displayName":"CNAPP Analyst","description":"Analyst","allowedMemberTypes":["User"],"isEnabled":true},
                {"id":"6f2d6b1e-6b3c-4b8e-9a51-1c7c0c0a0003","value":"CNAPP.Viewer","displayName":"CNAPP Viewer","description":"Viewer","allowedMemberTypes":["User"],"isEnabled":true}]' \
  --query appId -o tsv)
az ad sp create --id "$APP_ID"
az ad sp update --id "$APP_ID" --set appRoleAssignmentRequired=true
# Add a redirect URI later (the list is replaced, so pass all of them):
#   az ad app update --id "$APP_ID" --web-redirect-uris <uri1> <uri2>
```

Choose a client credential (option C), then set in `.env`:

```bash
ENTRA_TENANT_ID=<TENANT_ID>
ENTRA_CLIENT_ID=<APP_ID>
ENTRA_REDIRECT_URI=http://localhost:5173/api/auth/sso/entra/callback
ENTRA_ROLE_MAP=CNAPP.Admin=admin,CNAPP.Analyst=analyst,CNAPP.Viewer=viewer
```

`ENTRA_REDIRECT_URI` must be the public URL the browser uses (the frontend
origin; `/api` is proxied to the backend), not the backend's own port. Entra ID
accepts `http://` only for `localhost`; Codespaces forwards over https.

### Option C: client credential (certificate or secret)

Order of preference: **managed identity** federated credential (option A, only
possible where the backend has a managed identity) > **certificate** > secret.

Certificate (`ENTRA_CLIENT_AUTH=certificate`): the backend signs a
`private_key_jwt` client assertion with the key; Entra only ever sees the
public certificate.

```bash
# Create the certificate in Key Vault (key never leaves the vault's control) ...
az keyvault certificate create --vault-name <kv> -n entra-sso-cert -p "$(az keyvault certificate get-default-policy)"
# ... upload its public part to the app registration
az keyvault certificate download --vault-name <kv> -n entra-sso-cert -f cert.pem -e PEM
az ad app credential reset --id "$APP_ID" --cert @cert.pem --append && rm cert.pem
```

Key Vault exposes the certificate with its private key as the secret
`entra-sso-cert` (PEM). On Azure set the repository variables
`CNAPP_ENTRA_CLIENT_AUTH=certificate` and
`CNAPP_ENTRA_CREDENTIAL_SECRET_NAME=entra-sso-cert`; the Container App then
reads it from Key Vault into `ENTRA_CLIENT_CERTIFICATE`. Locally, put the PEM
(private key + certificate) in `ENTRA_CLIENT_CERTIFICATE`.

Client secret (`ENTRA_CLIENT_AUTH=secret`), simplest for local testing:

```bash
az ad app credential reset --id "$APP_ID" --display-name cnapp-local --years 1 --query password -o tsv
# -> ENTRA_CLIENT_SECRET in .env (never commit it). On Azure, store it in Key Vault:
#    az keyvault secret set --vault-name <kv> -n entra-client-secret --value <secret>
#    and set CNAPP_ENTRA_CLIENT_AUTH=secret, CNAPP_ENTRA_CREDENTIAL_SECRET_NAME=entra-client-secret
```

### Role mapping

`ENTRA_ROLE_MAP` maps **app role values** (the `roles` claim) and/or **group
object ids** (the `groups` claim; enable "groups claim" in Token configuration)
to local roles, e.g.
`CNAPP.Admin=admin,CNAPP.Analyst=analyst,0f6c…-group-id=viewer`. Matching is
case-insensitive and the highest role wins.

* With a mapped role, the user's local role is set to it at **every** Microsoft
  sign-in (audited as `user_updated` with `source: entra_role_map`). The last
  active admin is never demoted this way (`user_role_sync_skipped`).
* Without a match, an existing user keeps their role; a just-in-time user gets
  `ENTRA_DEFAULT_ROLE`. `ENTRA_REQUIRE_ROLE=true` refuses the sign-in instead.
* App roles are preferred over groups: they are scoped to this app and do not
  hit the groups-overage limit (200 groups).

### User matching

1. A user who signed in with Microsoft before is found by tenant id + object id
   (`oid`), even if their UPN or e-mail later changes.
2. Otherwise by e-mail: the `email` claim only when Microsoft marks its domain
   as verified by your tenant (`xms_edov`), else `preferred_username` (the
   user's UPN in your tenant). Guest UPNs (`#EXT#`) are not used. The local
   account is then linked to the Entra identity (`sso_identity_linked`).
3. No local account: refused (`not_provisioned`) unless
   `ENTRA_JIT_PROVISIONING=true`, which creates one without a local password.

### Conditional Access (MFA in Entra ID)

Because Microsoft sign-ins skip the local authenticator, require MFA in Entra:
Entra admin center → Protection → Conditional Access → New policy → Users:
the groups assigned to the app (exclude your emergency-access accounts) →
Target resources: `cloudsecurity-cnapp-<prefix>-sso` → Grant: **Require
authentication strength: Multifactor** (or phishing-resistant MFA) → On.
Consider also "Require compliant device" and sign-in risk conditions. Set
`ENTRA_ENFORCE_LOCAL_MFA=true` if you also want the local TOTP after Microsoft
sign-in (then `MFA_REQUIRED_ROLES` applies to SSO users too).

## Password login policy and break-glass access

| Setting | Default | Effect |
|---|---|---|
| `AUTH_PASSWORD_LOGIN_ENABLED` | `true` | `false`: only Microsoft sign-in, except break-glass accounts |
| `AUTH_PASSWORD_LOGIN_FOR_SSO_USERS` | `false` | Users linked to an Entra identity may also use their local password |
| `AUTH_BREAK_GLASS_EMAILS` | `ADMIN_EMAIL` | Local accounts that may always sign in with password (+ their MFA) |

The policy is checked only **after** a correct password, so it reveals nothing
to someone who does not know the password (a wrong password always gets the
generic 401). Refusals are audited as `login_password_disabled`.

**Break-glass procedure** (Entra ID unavailable, misconfigured, or nobody can
sign in with Microsoft):

1. Use a break-glass account (by default the bootstrap `ADMIN_EMAIL`): on the
   login page choose **Emergency administrator sign-in**, then its password and
   MFA code (or a recovery code). Keep these credentials and recovery codes
   offline (e.g. a sealed envelope or a password manager vault with restricted
   access), give the account MFA, never link it to Entra, and review the
   `login_success` audit entries for it.
2. If the break-glass admin lost the password or authenticator, use the CLI
   inside the backend container (Azure: `az containerapp exec -g <rg> -n
   <prefix>-api --command bash`; compose: `docker compose exec backend bash`):
   ```bash
   python -m app.cli reset-password --email admin@example.com   # also unlocks
   python -m app.cli reset-mfa --email admin@example.com        # removes the authenticator
   ```
3. As a last resort, temporarily set `AUTH_PASSWORD_LOGIN_ENABLED=true` and
   redeploy.

## Settings reference

| Variable | Default | Description |
|---|---|---|
| `MFA_ENCRYPTION_KEY` | dev key (warning) | 32+ chars; comma-separated for rotation. **Required in production** |
| `MFA_REQUIRED_ROLES` | | e.g. `admin,analyst` |
| `MFA_ISSUER` | `CloudSecurity CNAPP` | Name shown in authenticator apps |
| `MFA_CHALLENGE_TTL_SECONDS` | `300` | Lifetime of the password → code step |
| `MFA_CHALLENGE_MAX_ATTEMPTS` | `5` | Wrong codes per challenge |
| `ENTRA_TENANT_ID` | | Directory (tenant) id. Multi-tenant aliases (`common`, `organizations`) are rejected |
| `ENTRA_CLIENT_ID` | | Application (client) id |
| `ENTRA_CLIENT_AUTH` | `auto` | `certificate`, `secret`, `managed_identity`; `auto` picks certificate > secret > managed identity |
| `ENTRA_CLIENT_CERTIFICATE` | | PEM with private key and certificate |
| `ENTRA_CLIENT_SECRET` | | Client secret |
| `ENTRA_MANAGED_IDENTITY_CLIENT_ID` | `AZURE_MANAGED_IDENTITY_CLIENT_ID` | Managed identity used as federated credential |
| `ENTRA_REDIRECT_URI` | derived from the request | Must match the app registration exactly; **required (https) in production** |
| `ENTRA_AUTHORITY_HOST` | `https://login.microsoftonline.com` | Sovereign clouds, e.g. `https://login.microsoftonline.us` |
| `ENTRA_JIT_PROVISIONING` | `false` | Create unknown users at first sign-in |
| `ENTRA_DEFAULT_ROLE` | `viewer` | Role for JIT users without a mapped role |
| `ENTRA_ROLE_MAP` | | `value=role,...` (app role values or group ids) |
| `ENTRA_REQUIRE_ROLE` | `false` | Refuse sign-in without a mapped role |
| `ENTRA_ENFORCE_LOCAL_MFA` | `false` | Also require the local TOTP after Microsoft sign-in |
| `AUTH_PASSWORD_LOGIN_ENABLED`, `AUTH_PASSWORD_LOGIN_FOR_SSO_USERS`, `AUTH_BREAK_GLASS_EMAILS` | | See [above](#password-login-policy-and-break-glass-access) |

Invalid values (unknown roles in `MFA_REQUIRED_ROLES` / `ENTRA_ROLE_MAP` /
`ENTRA_DEFAULT_ROLE`, multi-tenant tenant ids) stop the app at startup.

## Audit events

`mfa_setup_started`, `mfa_enabled` (`forced` for enrolment at login),
`mfa_enable_failure`, `mfa_challenge_issued`, `mfa_enrollment_required`,
`mfa_failure` (with `failed_count` / `locked_until`), `mfa_locked`,
`mfa_recovery_code_used` (`remaining`), `mfa_disabled`, `mfa_disable_failure`,
`mfa_recovery_codes_regenerated`, `mfa_recovery_codes_regenerate_failure`,
`mfa_reset` (admin or `cli`), `login_success` (`method: password|entra`,
`mfa: totp|recovery_code`), `login_password_disabled`, `sso_login_failure`
(`reason`: `invalid_state`, `expired`, `idp_error`, `token_exchange_failed`,
`invalid_token`, `not_provisioned`, `no_email_claim`, `no_role_assigned`,
`inactive`, …), `sso_identity_linked`, `user_provisioned`, `user_updated`
(`source: entra_role_map`), `user_role_sync_skipped`.

## Security design

* **TOTP secrets** are encrypted at rest with Fernet (AES-128-CBC +
  HMAC-SHA256) under a key derived (HKDF-SHA256) from `MFA_ENCRYPTION_KEY`.
  The QR code is rendered by the backend as an SVG data URI; the secret is never
  sent to a third-party service.
* **Recovery codes**: 80 bits of randomness each, stored as SHA-256 only;
  using one is an atomic conditional update (cannot be used twice, even
  concurrently).
* **Replay**: the matched time step is stored with an atomic
  compare-and-set, so a code works once and older codes never again.
* **Challenge tokens**: random 256-bit tokens, stored as HMAC (keyed by
  `SESSION_SECRET`) like session tokens, short-lived, single-use, attempt-limited.
  They are not sessions: no API endpoint accepts them except the second step.
* **OIDC**: authorization code flow with PKCE (S256), `state` and `nonce` kept
  server-side (HMAC-keyed, single use, 10-minute expiry) and **bound to the
  browser** by a random httpOnly cookie, so a callback URL cannot be replayed in
  another browser (login CSRF). `response_mode=query` keeps the SameSite=Lax
  cookies working on the return navigation. The ID token must be RS256-signed by
  a key from the tenant's JWKS (re-fetched once on an unknown `kid` for key
  rollover) and carry `iss` = `https://login.microsoftonline.com/<tenant>/v2.0`,
  `aud` = the client id (no other audiences), `tid` = the tenant, the stored
  `nonce`, and valid `exp`/`nbf`/`iat` (60 s leeway). The discovery document's
  issuer must match too. Redirect targets after sign-in are same-app paths only.
* The session issued after SSO is created by the same code as a password login.

## Limitations

* TOTP only (no WebAuthn / passkeys yet); one authenticator per user.
* Single tenant: guest users from other tenants can sign in only through your
  tenant (their `tid` is your tenant), and are matched by object id / UPN.
* No front-channel or back-channel logout: signing out of CloudSecurity does not
  sign you out of Microsoft, and disabling a user in Entra ends their access at
  the next sign-in (existing sessions last up to `SESSION_IDLE_MINUTES` /
  `SESSION_MAX_AGE_HOURS`; deactivate the user here to end them immediately).
* Role sync happens at sign-in only (no SCIM provisioning).
* The per-IP rate limiter is in memory per process (as for passwords); the
  account lockout is in the database and shared by all replicas.
