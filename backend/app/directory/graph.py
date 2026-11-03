"""Microsoft Entra ID + Intune directory source, read by the server through
Microsoft Graph (docs/DIRECTORY_DISCOVERY.md#microsoft-entra-id--intune).

Authentication reuses one of the organisation's Azure cloud connectors: its
tenant, app registration (client id) and client secret, which stay in the
connector's own encrypted settings (the source only stores which connector it
uses). The app needs these Microsoft Graph APPLICATION permissions, all
read-only, granted with admin consent (the console shows a script):

| Permission | Used for | Without it |
|---|---|---|
| User.Read.All | users (enabled, UPN, department, on-prem SID) | users part skipped |
| AuditLog.Read.All | users' last sign-in (signInActivity, needs Entra ID P1/P2) | last sign-in unknown |
| Device.Read.All | Entra joined / hybrid / registered devices | devices part skipped |
| DeviceManagementManagedDevices.Read.All | Intune managed devices, compliance | Intune part skipped |
| RoleManagement.Read.Directory | privileged directory role assignments | roles part skipped |
| GroupMember.Read.All | members of role-assignable groups holding a role | group-held roles ignored |

Every call is a GET (plus the client-credentials token request); requests
are paged (@odata.nextLink) and throttling is retried (directory/cloud_http.py).
"""
from __future__ import annotations

import base64
import json
import re
import time
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from .. import config, tenancy
from .cloud import FatalError, Part, PartSkipped, Provider, SyncContext, check
from .cloud_http import CloudApiError
from .matching import short_host
from .models import DirectoryComputer, DirectorySource, DirectoryUser
from .service import AGENT_PLATFORMS, DirectoryError, parent_dn, platform_of

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
TENANT_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
ZERO_GUID = "00000000-0000-0000-0000-000000000000"

# Microsoft Graph application permissions (app role ids of the Graph service
# principal, identical in every tenant), why each is needed, and the scope that
# requires it (None: optional enrichment).
PERMISSIONS: tuple[dict[str, Any], ...] = (
    {"name": "User.Read.All", "id": "df021288-bdef-4463-88db-98f22de89214", "scope": "users",
     "why": "Users: enabled / disabled, UPN, email, department, on-prem account link"},
    {"name": "AuditLog.Read.All", "id": "b0afded3-3588-46d8-8b3d-9842eff778da", "scope": None,
     "why": "Users' last sign-in (signInActivity; needs Entra ID P1 or P2). Without it last sign-in is unknown"},
    {"name": "Device.Read.All", "id": "7438b122-aefc-4978-80ed-43db9fcc7715", "scope": "devices",
     "why": "Entra joined, hybrid joined and registered devices"},
    {"name": "DeviceManagementManagedDevices.Read.All", "id": "2f51be20-0bb4-4fed-bf7b-db946066c75e",
     "scope": "intune", "why": "Intune managed devices: compliance, encryption, last check-in, serial, primary user"},
    {"name": "RoleManagement.Read.Directory", "id": "483bed4a-2ad3-4361-a73b-c83ccdbdc53c", "scope": "roles",
     "why": "Privileged directory role assignments (Global Administrator, ...)"},
    {"name": "GroupMember.Read.All", "id": "98830695-27a2-44f7-8c18-0c3ebc9698f6", "scope": None,
     "why": "Members of role-assignable groups that hold a privileged role"},
)
PERMISSION_BY_SCOPE = {p["scope"]: p["name"] for p in PERMISSIONS if p["scope"]}

# Built-in Entra roles treated as privileged (role template id -> name). Matched
# by template id, or by display name for renamed / localised tenants.
PRIVILEGED_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
    "7698a772-787b-4ac8-901f-60d6b08affd2": "Cloud Device Administrator",
}
_PRIVILEGED_NAMES = {n.lower() for n in PRIVILEGED_ROLES.values()}

USER_SELECT = ("id,userPrincipalName,mail,displayName,givenName,surname,department,jobTitle,accountEnabled,"
               "createdDateTime,userType,onPremisesSamAccountName,onPremisesDomainName,"
               "onPremisesSecurityIdentifier,onPremisesDistinguishedName,onPremisesSyncEnabled")
INTUNE_SELECT = ("id,deviceName,azureADDeviceId,serialNumber,complianceState,isEncrypted,lastSyncDateTime,"
                 "operatingSystem,osVersion,userPrincipalName,managedDeviceOwnerType,enrolledDateTime,model,"
                 "manufacturer")
# Graph's answer when signInActivity is read in a tenant without Entra ID P1/P2.
NO_PREMIUM = "Authentication_RequestFromNonPremiumTenantOrB2CTenant"
TOKEN_REFRESH_MARGIN = 300


def dt(value: Any) -> datetime | None:
    """ISO 8601 (Graph / Google) -> naive UTC; None for empty or epoch placeholders."""
    if not value or not isinstance(value, str):
        return None
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is not None:
        d = d.astimezone(UTC).replace(tzinfo=None)
    return d if d.year >= 1990 else None


def _s(value: Any, n: int = 256) -> str:
    return (value if isinstance(value, str) else "")[:n]


def _guid(value: Any) -> str | None:
    v = _s(value, 64).strip().lower()
    return v if v and v != ZERO_GUID else None


# ----------------------------------------------------------------------------- Azure connectors
def azure_connectors(db: Session) -> list[dict[str, Any]]:
    """The organisation's Azure cloud connectors an Entra source can use, with
    whether they can call Microsoft Graph (client-secret auth only)."""
    from ..connectors import org_config
    from ..connectors.azure import resolve_auth_mode

    out: list[dict[str, Any]] = []
    row = org_config.rows(db).get("azure")
    if row is not None:
        cfg = row.config or {}
        tenant = (cfg.get("tenant_id") or "").strip().lower()
        reason = ""
        if not row.enabled:
            reason = "The Azure connector is disabled."
        elif not tenant or not cfg.get("client_id"):
            reason = "The Azure connector has no tenant ID / client ID."
        elif not (row.secret_hints or {}).get("client_secret"):
            reason = "The Azure connector has no client secret."
        out.append({"id": "org", "name": "Azure connector", "tenant_id": tenant,
                    "client_id": (cfg.get("client_id") or "").strip(), "auth_mode": "client_secret",
                    "usable": not reason, "reason": reason})
    elif tenancy.is_default(tenancy.require_org(db)):
        s = config.settings
        mode = resolve_auth_mode(s)
        if mode or s.azure_tenant_id:
            reason = ""
            if mode == "managed_identity":
                reason = ("This connector signs in with the server's managed identity. Directory discovery calls "
                          "Microsoft Graph as an app registration with a client secret: configure the Azure "
                          "connector with a tenant ID, client ID and client secret.")
            elif mode == "default":
                reason = ("This connector uses DefaultAzureCredential, whose identity is not fixed. Directory "
                          "discovery calls Microsoft Graph as an app registration with a client secret: configure "
                          "the Azure connector with a tenant ID, client ID and client secret.")
            elif mode != "client_secret":
                reason = "The Azure connector has no complete client-secret credential."
            out.append({"id": "env", "name": "Azure connector (server environment)",
                        "tenant_id": (s.azure_tenant_id or "").strip().lower(),
                        "client_id": (s.azure_client_id or s.azure_managed_identity_client_id or "").strip(),
                        "auth_mode": mode or "none", "usable": not reason, "reason": reason})
    for c in out:
        if c["tenant_id"] and not TENANT_RE.match(c["tenant_id"]) and not c["reason"]:
            c["usable"], c["reason"] = False, "The connector's tenant ID must be the directory (tenant) ID GUID."
    return out


def connector_credentials(db: Session, connector_id: str) -> tuple[str, str, str]:
    """(tenant id, client id, client secret) of a usable Azure connector."""
    from ..connectors import org_config
    from ..notifications import crypto

    conn = next((c for c in azure_connectors(db) if c["id"] == connector_id), None)
    if conn is None:
        raise FatalError("the Azure connector this source uses no longer exists (Connectors & scans → Azure)")
    if not conn["usable"]:
        raise FatalError(conn["reason"])
    if connector_id == "env":
        s = config.settings
        return conn["tenant_id"], s.azure_client_id or "", s.azure_client_secret or ""
    row = org_config.rows(db)["azure"]
    try:
        secret = crypto.decrypt_secrets(row.secret_ciphertext).get("client_secret") or ""
    except (crypto.DecryptionFailed, crypto.EncryptionUnavailable):
        secret = ""
    if not secret:
        raise FatalError("the Azure connector's client secret cannot be decrypted (NOTIFICATIONS_ENCRYPTION_KEY "
                         "changed?): enter it again under Connectors & scans → Azure")
    return conn["tenant_id"], conn["client_id"], secret


def token_roles(access_token: str) -> set[str] | None:
    """Application permissions in a Graph access token (its `roles` claim). The
    token is only decoded, not verified: it came straight from Microsoft over
    TLS and is used only to report missing permissions."""
    try:
        payload = access_token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError):
        return None
    roles = claims.get("roles") if isinstance(claims, dict) else None
    return {r for r in roles if isinstance(r, str)} if isinstance(roles, list) else set()


# ----------------------------------------------------------------------------- provider
class EntraProvider(Provider):
    type = "entra"
    label = "Microsoft Entra ID"

    def __init__(self, db, src, http):
        super().__init__(db, src, http)
        self._token = ""
        self._expires = 0.0
        self._creds: tuple[str, str, str] | None = None
        self.granted: set[str] | None = None

    # -- credentials
    def validate(self) -> None:
        cfg = self.src.config or {}
        conn = next((c for c in azure_connectors(self.db) if c["id"] == cfg.get("connector_id")), None)
        if conn is None:
            raise DirectoryError(422, "choose one of the organisation's Azure connectors")
        if not conn["usable"]:
            raise DirectoryError(422, conn["reason"])

    def connect(self) -> None:
        self.token()

    def token(self) -> str:
        if self._token and time.monotonic() < self._expires - TOKEN_REFRESH_MARGIN:
            return self._token
        if self._creds is None:
            self._creds = connector_credentials(self.db, (self.src.config or {}).get("connector_id", ""))
            tenant = self._creds[0]
            if tenant != (self.src.config or {}).get("tenant_id"):
                raise FatalError(f"the Azure connector now points at tenant {tenant}, not this source's tenant "
                                 f"{(self.src.config or {}).get('tenant_id')}: add a source for that tenant instead")
        tenant, client_id, secret = self._creds
        try:
            body = self.http.post_form(f"{LOGIN}/{tenant}/oauth2/v2.0/token", {
                "grant_type": "client_credentials", "client_id": client_id, "client_secret": secret,
                "scope": "https://graph.microsoft.com/.default"})
        except CloudApiError as e:
            raise FatalError(f"sign-in as the Azure connector's app registration failed: {e.code or e.status} "
                             f"{e.message}".strip()) from None
        tok = body.get("access_token")
        if not isinstance(tok, str) or not tok:
            raise FatalError("the token endpoint returned no access token")
        self._token = tok
        self._expires = time.monotonic() + float(body.get("expires_in") or 3600)
        self.granted = token_roles(tok)
        return tok

    def _require(self, name: str) -> None:
        if self.granted is not None and name not in self.granted:
            raise PartSkipped("missing_permission", f"{name} is not granted to the app registration (run the "
                                                    "permission script, then grant admin consent)")

    @staticmethod
    def _skip(e: CloudApiError, name: str) -> PartSkipped | CloudApiError:
        if e.status in (401, 403):
            return PartSkipped("missing_permission", f"{name}: access denied ({e.code or e.status}): {e.message}")
        return e

    # -- parts
    def parts(self, scopes: list[str]) -> list[Part]:
        out = []
        if "users" in scopes:
            out.append(Part("users", "Users", self._users, (DirectoryUser, None)))
            if "roles" in scopes:
                out.append(Part("roles", "Admin roles", self._roles))
        if "devices" in scopes:
            out.append(Part("devices", "Entra devices", self._devices, (DirectoryComputer, ("entra",))))
        if "intune" in scopes:
            out.append(Part("intune", "Intune devices", self._intune, (DirectoryComputer, ("intune",))))
        return out

    def _sign_in_status(self) -> tuple[str, str]:
        """Can signInActivity be read? ("ok", "") or (status, why not)."""
        if self.granted is not None and "AuditLog.Read.All" not in self.granted:
            return "missing_permission", "AuditLog.Read.All is not granted: last sign-in is unknown"
        try:
            self.http.get_json(f"{GRAPH}/users", self.token, {"$select": "id,signInActivity", "$top": "1"})
        except CloudApiError as e:
            if e.code == NO_PREMIUM:
                return "unlicensed", ("last sign-in needs Microsoft Entra ID P1 or P2 in this tenant: last "
                                      "sign-in is unknown, stale-user checks are skipped")
            if e.status in (401, 403):
                return "missing_permission", f"last sign-in cannot be read ({e.code or e.status}): last sign-in is unknown"
            raise
        return "ok", ""

    def _users(self, ctx: SyncContext) -> dict[str, Any]:
        self._require("User.Read.All")
        try:
            sign_in, why = self._sign_in_status()
        except CloudApiError as e:
            raise self._skip(e, "User.Read.All") from None
        ctx.status["sign_in"] = {"status": sign_in, **({"detail": why} if why else {})}
        select = USER_SELECT + (",signInActivity" if sign_in == "ok" else "")
        n = 0
        try:
            for page in self.http.pages(f"{GRAPH}/users", self.token, {"$select": select, "$top": "999"}):
                n += ctx.store_users([self.user(u, sign_in == "ok") for u in page if _guid(u.get("id"))])
        except CloudApiError as e:
            raise self._skip(e, "User.Read.All") from None
        return {"count": n}

    @staticmethod
    def user(u: dict[str, Any], sign_in: bool) -> dict[str, Any]:
        upn = _s(u.get("userPrincipalName")).lower()
        sam = _s(u.get("onPremisesSamAccountName"))
        dn = _s(u.get("onPremisesDistinguishedName"), 2048)
        domain = (_s(u.get("onPremisesDomainName"), 255) or upn.partition("@")[2]).lower()
        last = None
        if sign_in:
            act = u.get("signInActivity") if isinstance(u.get("signInActivity"), dict) else {}
            times = [dt(act.get(k)) for k in ("lastSignInDateTime", "lastNonInteractiveSignInDateTime",
                                              "lastSuccessfulSignInDateTime")]
            last = max((t for t in times if t), default=None)
        return {
            "external_id": _guid(u.get("id")), "sam_account_name": sam, "sam_key": sam.lower(),
            "user_principal_name": upn, "mail": _s(u.get("mail")).lower(),
            "display_name": _s(u.get("displayName")), "given_name": _s(u.get("givenName")),
            "surname": _s(u.get("surname")), "department": _s(u.get("department")), "title": _s(u.get("jobTitle")),
            "manager_dn": "", "object_sid": _s(u.get("onPremisesSecurityIdentifier"), 184).upper() or None,
            "distinguished_name": dn, "domain": domain, "ou": parent_dn(dn), "enabled": u.get("accountEnabled") is not False,
            "user_account_control": None, "last_logon_at": last, "when_created": dt(u.get("createdDateTime")),
            "pwd_last_set_at": None,
            "attributes": {"user_type": _s(u.get("userType"), 16), "synced": bool(u.get("onPremisesSyncEnabled")),
                           "sign_in_known": sign_in},
        }

    def _roles(self, ctx: SyncContext) -> dict[str, Any]:
        self._require("RoleManagement.Read.Directory")
        holders: dict[str, set[str]] = defaultdict(set)
        groups: dict[str, set[str]] = defaultdict(set)
        try:
            defs: dict[str, str] = {}
            for page in self.http.pages(f"{GRAPH}/roleManagement/directory/roleDefinitions", self.token,
                                        {"$select": "id,displayName,templateId"}):
                for d in page:
                    tid = _guid(d.get("templateId")) or _guid(d.get("id"))
                    name = _s(d.get("displayName"), 128)
                    if tid in PRIVILEGED_ROLES or name.lower() in _PRIVILEGED_NAMES:
                        defs[_s(d.get("id"), 64)] = name or PRIVILEGED_ROLES.get(tid or "", "")
            for rid, name in sorted(defs.items()):
                for page in self.http.pages(f"{GRAPH}/roleManagement/directory/roleAssignments", self.token,
                                            {"$filter": f"roleDefinitionId eq '{rid}'", "$expand": "principal"}):
                    for a in page:
                        pid = _guid(a.get("principalId"))
                        kind = _s((a.get("principal") or {}).get("@odata.type"), 64).lower()
                        if not pid or "serviceprincipal" in kind:
                            continue
                        (groups if kind.endswith(".group") else holders)[pid].add(name)
        except CloudApiError as e:
            raise self._skip(e, "RoleManagement.Read.Directory") from None
        note, complete = "", True
        for gid, names in sorted(groups.items()):
            try:
                for page in self.http.pages(f"{GRAPH}/groups/{gid}/transitiveMembers/microsoft.graph.user",
                                            self.token, {"$select": "id", "$top": "999"}):
                    for m in page:
                        if _guid(m.get("id")):
                            holders[_guid(m.get("id"))].update(f"{n} (via group)" for n in names)
            except CloudApiError as e:
                if e.status not in (401, 403):
                    raise
                note, complete = ("roles held through role-assignable groups were not expanded: "
                                  "GroupMember.Read.All is not granted"), False
                break
        n = ctx.set_privileged(holders, complete=complete)
        return {"count": n, **({"detail": note} if note else {})}

    def _devices(self, ctx: SyncContext) -> dict[str, Any]:
        self._require("Device.Read.All")
        n = 0
        try:
            # No $select: the default device properties include the on-prem SID
            # of hybrid-joined devices where Graph has it.
            for page in self.http.pages(f"{GRAPH}/devices", self.token, {"$top": "999"}):
                n += ctx.store_computers([self.device(d) for d in page if _guid(d.get("id"))])
        except CloudApiError as e:
            raise self._skip(e, "Device.Read.All") from None
        return {"count": n}

    @staticmethod
    def device(d: dict[str, Any]) -> dict[str, Any]:
        name = _s(d.get("displayName"))
        trust = _s(d.get("trustType"), 32)
        join = {"azuread": "joined", "serverad": "hybrid", "workplace": "registered"}.get(trust.lower(), "")
        os_name = _s(d.get("operatingSystem"))
        platform = platform_of(os_name)
        return {
            "external_id": _guid(d.get("id")), "device_kind": "entra", "cloud_device_id": _guid(d.get("deviceId")),
            "name": name, "short_name": short_host(name), "dns_hostname": "", "sam_account_name": "",
            "serial_number": "", "operating_system": os_name, "os_version": _s(d.get("operatingSystemVersion")),
            "object_sid": _s(d.get("onPremisesSecurityIdentifier"), 184).upper() or None,
            "distinguished_name": "", "domain": "", "ou": "", "enabled": d.get("accountEnabled") is not False,
            "user_account_control": None, "last_logon_at": dt(d.get("approximateLastSignInDateTime")),
            "when_created": dt(d.get("registrationDateTime")), "when_changed": None, "platform": platform,
            # Registered-only (personal / BYOD) devices are not expected to run the agent.
            "agent_expected": platform in AGENT_PLATFORMS and platform != "" and join != "registered",
            "compliance": None, "encrypted": None, "primary_user": "",
            "attributes": {"join": join, "trust_type": trust, "is_managed": d.get("isManaged"),
                           "is_compliant": d.get("isCompliant"), "profile_type": _s(d.get("profileType"), 32)},
        }

    def _intune(self, ctx: SyncContext) -> dict[str, Any]:
        self._require("DeviceManagementManagedDevices.Read.All")
        n = 0
        try:
            for page in self.http.pages(f"{GRAPH}/deviceManagement/managedDevices", self.token,
                                        {"$select": INTUNE_SELECT}):
                n += ctx.store_computers([self.managed(m) for m in page if _guid(m.get("id"))])
        except CloudApiError as e:
            if e.status in (400, 403) and (self.granted is None or
                                           "DeviceManagementManagedDevices.Read.All" in self.granted):
                raise PartSkipped("unlicensed", f"Intune is not available in this tenant (no Intune licence?): "
                                                f"{e.message}") from None
            raise self._skip(e, "DeviceManagementManagedDevices.Read.All") from None
        return {"count": n}

    @staticmethod
    def managed(m: dict[str, Any]) -> dict[str, Any]:
        name = _s(m.get("deviceName"))
        os_name = _s(m.get("operatingSystem"))
        platform = platform_of(os_name)
        owner = _s(m.get("managedDeviceOwnerType"), 16).lower()
        enc = m.get("isEncrypted")
        return {
            "external_id": f"mdm:{_guid(m.get('id'))}", "device_kind": "intune",
            "cloud_device_id": _guid(m.get("azureADDeviceId")), "name": name, "short_name": short_host(name),
            "dns_hostname": "", "sam_account_name": "", "serial_number": _s(m.get("serialNumber"), 128),
            "operating_system": os_name, "os_version": _s(m.get("osVersion")), "object_sid": None,
            "distinguished_name": "", "domain": "", "ou": "", "enabled": True, "user_account_control": None,
            "last_logon_at": dt(m.get("lastSyncDateTime")), "when_created": dt(m.get("enrolledDateTime")),
            "when_changed": None, "platform": platform,
            "agent_expected": platform in AGENT_PLATFORMS and platform != "" and owner != "personal",
            "compliance": _s(m.get("complianceState"), 24) or None,
            "encrypted": enc if isinstance(enc, bool) else None,
            "primary_user": _s(m.get("userPrincipalName")).lower(),
            "attributes": {"owner": owner, "model": _s(m.get("model"), 128),
                           "manufacturer": _s(m.get("manufacturer"), 128)},
        }

    # -- Test & save
    def checks(self) -> list[dict[str, Any]]:
        scopes = set((self.src.config or {}).get("scopes") or [])
        try:
            self.token()
        except FatalError as e:
            return [check("error", "token", "Sign in as the app registration", str(e))]
        out = [check("ok", "token", "Sign in as the app registration",
                     f"tenant {(self.src.config or {}).get('tenant_id')}")]
        granted = self.granted
        for p in PERMISSIONS:
            needed = p["scope"] in scopes if p["scope"] else bool(scopes & {"users", "roles"})
            if granted is None:
                status, detail = "ok", "not listed in the token: verified by the probes below"
            elif p["name"] in granted:
                status, detail = "ok", p["why"]
            else:
                status, detail = "missing", f"not granted. {p['why']}"
            out.append(check(status, p["name"], p["name"], detail, required=bool(p["scope"]) and needed))
        if "users" in scopes:
            try:
                self.http.get_json(f"{GRAPH}/users", self.token, {"$select": "id", "$top": "1"})
                status, why = self._sign_in_status()
                out.append(check(status, "sign_in", "Last sign-in (Entra ID P1/P2)",
                                 why or "available", required=False))
            except CloudApiError as e:
                out.append(check("error", "users", "Read users", str(e)))
        if "intune" in scopes and (granted is None or "DeviceManagementManagedDevices.Read.All" in granted):
            try:
                self.http.get_json(f"{GRAPH}/deviceManagement/managedDevices", self.token,
                                   {"$select": "id", "$top": "1"})
                out.append(check("ok", "intune", "Intune service", "available", required=False))
            except CloudApiError as e:
                out.append(check("unlicensed", "intune", "Intune service",
                                 f"not available (no Intune licence?): the Intune part will be skipped. {e.message}",
                                 required=False))
        return out


def source_from_connector(db: Session, src: DirectorySource) -> None:
    """Copy the chosen connector's tenant / client id into the source config
    (display and tenant de-duplication; never the secret)."""
    cfg = dict(src.config or {})
    conn = next((c for c in azure_connectors(db) if c["id"] == cfg.get("connector_id")), None)
    if conn is None:
        raise DirectoryError(422, "choose one of the organisation's Azure connectors")
    if not conn["usable"]:
        raise DirectoryError(422, conn["reason"])
    cfg["tenant_id"], cfg["client_id"] = conn["tenant_id"], conn["client_id"]
    src.config = cfg
