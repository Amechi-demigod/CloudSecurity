"""Google Workspace directory source, read by the server through the Admin SDK
Directory API and the Cloud Identity Devices API
(docs/DIRECTORY_DISCOVERY.md#google-workspace).

Authentication: a service account with domain-wide delegation impersonates a
named Workspace admin. The admin uploads the service-account JSON key in the
console; it is stored Fernet-encrypted like the AD service-account credential
(never returned: the console only shows the client email and key id). Each
part requests a token for its own read-only scope, so a scope missing from
the domain-wide delegation only skips that part:

| Scope | Used for |
|---|---|
| admin.directory.user.readonly | users (suspended / archived, last login, department, super admin) |
| admin.directory.rolemanagement.readonly | admin role assignments |
| admin.directory.group.member.readonly | members of groups holding an admin role (optional) |
| admin.directory.device.chromeos.readonly | ChromeOS devices |
| admin.directory.device.mobile.readonly | Android / iOS devices |
| cloud-identity.devices.readonly | Windows / macOS / Linux endpoints (Cloud Identity Devices) |

The token is obtained with a JWT bearer assertion (RFC 7523) signed RS256 with
the key (joserfc, already used for SSO); every call is a GET, paged with
pageToken, throttling retried (directory/cloud_http.py).
"""
from __future__ import annotations

import json
import re
import time
from collections import defaultdict
from typing import Any

from joserfc import jwt
from joserfc.jwk import RSAKey

from .cloud import FatalError, Part, PartSkipped, Provider, SyncContext, check
from .cloud_http import CloudApiError
from .graph import dt
from .matching import short_host
from .models import DirectoryComputer, DirectoryUser
from .service import DirectoryError, load_secret, platform_of

TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105 (endpoint, not a secret)
DIRECTORY = "https://admin.googleapis.com/admin/directory/v1"
CLOUD_IDENTITY = "https://cloudidentity.googleapis.com/v1"
SCOPE_BASE = "https://www.googleapis.com/auth/"
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}$")
CUSTOMER_RE = re.compile(r"^(my_customer|C[0-9a-z]{5,20})$")
TOKEN_REFRESH_MARGIN = 300

# OAuth scopes (read-only), the part that needs each, and why.
SCOPES: tuple[dict[str, Any], ...] = (
    {"scope": SCOPE_BASE + "admin.directory.user.readonly", "part": "users",
     "why": "Users: suspended / archived, last login, department, org unit, super admin"},
    {"scope": SCOPE_BASE + "admin.directory.rolemanagement.readonly", "part": "roles",
     "why": "Admin role assignments (Super Admin, User Management Admin, ...)"},
    {"scope": SCOPE_BASE + "admin.directory.group.member.readonly", "part": None,
     "why": "Members of groups an admin role is assigned to (optional)"},
    {"scope": SCOPE_BASE + "admin.directory.device.chromeos.readonly", "part": "chromeos",
     "why": "ChromeOS devices: status, last sync, serial, user"},
    {"scope": SCOPE_BASE + "admin.directory.device.mobile.readonly", "part": "mobile",
     "why": "Android / iOS devices: status, last sync, serial, user"},
    {"scope": SCOPE_BASE + "cloud-identity.devices.readonly", "part": "endpoints",
     "why": "Windows / macOS / Linux endpoints: serial, host name, encryption, last sync, user"},
)
SCOPE_BY_PART = {s["part"]: s["scope"] for s in SCOPES if s["part"]}
GROUP_SCOPE = SCOPE_BASE + "admin.directory.group.member.readonly"

# Pre-built admin roles treated as privileged (roleName -> display name), plus
# every role flagged isSuperAdminRole.
PRIVILEGED_ROLES = {
    "_SEED_ADMIN_ROLE": "Super Admin",
    "_USER_MANAGEMENT_ADMIN_ROLE": "User Management Admin",
    "_GROUPS_ADMIN_ROLE": "Groups Admin",
    "_HELP_DESK_ADMIN_ROLE": "Help Desk Admin",
    "_SERVICES_ADMIN_ROLE": "Services Admin",
    "_MOBILE_ADMIN_ROLE": "Mobile Admin",
}
ENDPOINT_PLATFORMS = {"WINDOWS": "windows", "MAC_OS": "macos", "LINUX": "linux"}
ENDPOINT_OS = {"WINDOWS": "Windows", "MAC_OS": "macOS", "LINUX": "Linux"}
INACTIVE_ENDPOINT_STATES = {"BLOCKED", "UNPROVISIONED", "WIPING", "WIPED"}


def _s(value: Any, n: int = 256) -> str:
    return (value if isinstance(value, str) else "")[:n]


# ----------------------------------------------------------------------------- key
def parse_key(raw: str) -> dict[str, str]:
    """Validate an uploaded service-account key; returns its public facts.
    Raises DirectoryError(422) without echoing any of the key."""
    try:
        key = json.loads(raw)
    except ValueError:
        raise DirectoryError(422, "the file is not a JSON service-account key") from None
    if not isinstance(key, dict) or key.get("type") != "service_account":
        raise DirectoryError(422, "the file is not a service-account key (\"type\": \"service_account\")")
    email, kid, cid, pem = (key.get(k) for k in ("client_email", "private_key_id", "client_id", "private_key"))
    if not (isinstance(email, str) and EMAIL_RE.match(email) and email.endswith(".iam.gserviceaccount.com")):
        raise DirectoryError(422, "the key has no valid client_email")
    if not (isinstance(kid, str) and re.fullmatch(r"[0-9a-f]{8,64}", kid)):
        raise DirectoryError(422, "the key has no valid private_key_id")
    if not (isinstance(cid, str) and cid.isdigit()):
        raise DirectoryError(422, "the key has no numeric client_id")
    try:
        RSAKey.import_key(pem)
    except Exception:
        raise DirectoryError(422, "the key's private_key is not a valid RSA private key") from None
    return {"service_account_email": email, "client_id": cid, "key_id": kid[:8]}


def key_hint(facts: dict[str, str]) -> str:
    return f"{facts['service_account_email']} · key {facts['key_id']}…"


# ----------------------------------------------------------------------------- provider
class GoogleProvider(Provider):
    type = "google"
    label = "Google Workspace"

    def __init__(self, db, src, http):
        super().__init__(db, src, http)
        self._key: dict[str, Any] | None = None
        self._signing_key: RSAKey | None = None
        self._tokens: dict[str, tuple[str, float]] = {}
        self.super_admins: set[str] = set()

    @property
    def customer(self) -> str:
        return (self.src.config or {}).get("customer_id") or "my_customer"

    def validate(self) -> None:
        cfg = self.src.config or {}
        if not self.src.secret_ciphertext:
            raise DirectoryError(422, "upload the service account's JSON key")
        if not EMAIL_RE.match(cfg.get("admin_email") or ""):
            raise DirectoryError(422, "enter the email of the Workspace admin to impersonate")

    def connect(self) -> None:
        self._load_key()

    def _load_key(self) -> dict[str, Any]:
        if self._key is None:
            data = load_secret(self.src)
            try:
                key = json.loads((data or {}).get("key_json") or "")
                self._signing_key = RSAKey.import_key(key["private_key"])
            except (ValueError, KeyError, TypeError):
                raise FatalError("the service-account key is missing or cannot be decrypted "
                                 "(NOTIFICATIONS_ENCRYPTION_KEY changed?): upload it again") from None
            self._key = key
        return self._key

    def token(self, scope: str) -> str:
        """Access token for one scope, impersonating the configured admin."""
        cached = self._tokens.get(scope)
        if cached and time.monotonic() < cached[1] - TOKEN_REFRESH_MARGIN:
            return cached[0]
        key = self._load_key()
        now = int(time.time())
        assertion = jwt.encode(
            {"alg": "RS256", "typ": "JWT", "kid": key.get("private_key_id", "")},
            {"iss": key["client_email"], "sub": (self.src.config or {}).get("admin_email", ""), "scope": scope,
             "aud": TOKEN_URL, "iat": now, "exp": now + 3600},
            self._signing_key)
        try:
            body = self.http.post_form(TOKEN_URL, {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                                   "assertion": assertion})
        except CloudApiError as e:
            name = scope.removeprefix(SCOPE_BASE)
            if e.code == "unauthorized_client":
                raise PartSkipped("missing_permission", f"{name} is not authorised for the service account's "
                                                        "client ID in domain-wide delegation") from None
            if e.code == "invalid_grant":
                raise FatalError(f"Google refused the service account ({e.message}): check the admin email to "
                                 "impersonate and that the key is not deleted") from None
            raise FatalError(f"Google token request failed: {e.code or e.status} {e.message}".strip()) from None
        tok = body.get("access_token")
        if not isinstance(tok, str) or not tok:
            raise FatalError("the token endpoint returned no access token")
        self._tokens[scope] = (tok, time.monotonic() + float(body.get("expires_in") or 3600))
        return tok

    def _bearer(self, scope: str):
        return lambda: self.token(scope)

    @staticmethod
    def _api_error(e: CloudApiError, what: str) -> PartSkipped | CloudApiError:
        if "accessNotConfigured" in e.code or "SERVICE_DISABLED" in e.message or "has not been used" in e.message:
            return PartSkipped("not_enabled", f"{what}: the API is not enabled in the service account's Google Cloud "
                                              f"project ({e.message})")
        if e.status in (401, 403):
            return PartSkipped("missing_permission", f"{what}: access denied ({e.message}); the impersonated admin "
                                                     "needs an admin role that can read it")
        return e

    def _pages(self, url: str, scope: str, params: dict[str, Any], items_key: str, what: str):
        try:
            yield from self.http.token_pages(url, self._bearer(scope), params, items_key=items_key)
        except CloudApiError as e:
            raise self._api_error(e, what) from None

    # -- parts
    def parts(self, scopes: list[str]) -> list[Part]:
        out = []
        if "users" in scopes:
            out.append(Part("users", "Users", self._users, (DirectoryUser, None)))
            if "roles" in scopes:
                out.append(Part("roles", "Admin roles", self._roles))
        if "chromeos" in scopes:
            out.append(Part("chromeos", "ChromeOS devices", self._chromeos, (DirectoryComputer, ("chromeos",))))
        if "mobile" in scopes:
            out.append(Part("mobile", "Mobile devices", self._mobile, (DirectoryComputer, ("mobile",))))
        if "endpoints" in scopes:
            out.append(Part("endpoints", "Endpoints", self._endpoints, (DirectoryComputer, ("endpoint",))))
        return out

    def _users(self, ctx: SyncContext) -> dict[str, Any]:
        n = 0
        for page in self._pages(f"{DIRECTORY}/users", SCOPE_BY_PART["users"],
                                {"customer": self.customer, "maxResults": 500, "projection": "basic"},
                                "users", "users"):
            for u in page:
                if u.get("isAdmin") is True and u.get("id"):
                    self.super_admins.add(_s(u["id"], 64))
            n += ctx.store_users([self.user(u) for u in page if u.get("id")])
        # Super admins are known from the user list itself: authoritative when
        # admin roles are not read, only added to otherwise (the roles part decides).
        ctx.set_privileged({u: ["Super Admin"] for u in self.super_admins},
                           complete="roles" not in (ctx.run.scopes or []))
        return {"count": n}

    @staticmethod
    def user(u: dict[str, Any]) -> dict[str, Any]:
        email = _s(u.get("primaryEmail")).lower()
        name = u.get("name") if isinstance(u.get("name"), dict) else {}
        orgs = [o for o in (u.get("organizations") or []) if isinstance(o, dict)]
        org = next((o for o in orgs if o.get("primary")), orgs[0] if orgs else {})
        return {
            "external_id": _s(u.get("id"), 64), "sam_account_name": "", "sam_key": "", "user_principal_name": email,
            "mail": email, "display_name": _s(name.get("fullName")), "given_name": _s(name.get("givenName")),
            "surname": _s(name.get("familyName")), "department": _s(org.get("department")), "title": _s(org.get("title")),
            "manager_dn": "", "object_sid": None, "distinguished_name": "", "domain": email.partition("@")[2],
            "ou": _s(u.get("orgUnitPath"), 1024),
            "enabled": not u.get("suspended") and not u.get("archived"), "user_account_control": None,
            "last_logon_at": dt(u.get("lastLoginTime")), "when_created": dt(u.get("creationTime")),
            "pwd_last_set_at": None,
            "attributes": {"is_admin": bool(u.get("isAdmin")), "delegated_admin": bool(u.get("isDelegatedAdmin")),
                           "suspended": bool(u.get("suspended")), "archived": bool(u.get("archived"))},
        }

    def _roles(self, ctx: SyncContext) -> dict[str, Any]:
        scope = SCOPE_BY_PART["roles"]
        roles: dict[str, str] = {}
        for page in self._pages(f"{DIRECTORY}/customer/{self.customer}/roles", scope, {"maxResults": 100},
                                "items", "admin roles"):
            for r in page:
                name = _s(r.get("roleName"), 128)
                if r.get("isSuperAdminRole") or name in PRIVILEGED_ROLES:
                    roles[_s(str(r.get("roleId")), 64)] = PRIVILEGED_ROLES.get(name, name)
        holders: dict[str, set[str]] = defaultdict(set)
        groups: dict[str, set[str]] = defaultdict(set)
        for page in self._pages(f"{DIRECTORY}/customer/{self.customer}/roleassignments", scope, {"maxResults": 200},
                                "items", "admin role assignments"):
            for a in page:
                name = roles.get(_s(str(a.get("roleId")), 64))
                who = _s(a.get("assignedTo"), 64)
                if not name or not who:
                    continue
                (groups if (a.get("assigneeType") or "user").lower() == "group" else holders)[who].add(name)
        for uid in self.super_admins:
            holders[uid].add("Super Admin")
        note, complete = "", True
        for gid, names in sorted(groups.items()):
            try:
                for page in self.http.token_pages(f"{DIRECTORY}/groups/{gid}/members", self._bearer(GROUP_SCOPE),
                                                  {"includeDerivedMembership": "true", "maxResults": 200},
                                                  items_key="members"):
                    for m in page:
                        if (m.get("type") or "USER").upper() == "USER" and m.get("id"):
                            holders[_s(m["id"], 64)].update(f"{n} (via group)" for n in names)
            except (PartSkipped, CloudApiError):
                note, complete = ("admin roles held through groups were not expanded: "
                                  "admin.directory.group.member.readonly is not authorised"), False
                break
        n = ctx.set_privileged(holders, complete=complete)
        return {"count": n, **({"detail": note} if note else {})}

    def _chromeos(self, ctx: SyncContext) -> dict[str, Any]:
        n = 0
        for page in self._pages(f"{DIRECTORY}/customer/{self.customer}/devices/chromeos", SCOPE_BY_PART["chromeos"],
                                {"maxResults": 200, "projection": "BASIC"}, "chromeosdevices", "ChromeOS devices"):
            n += ctx.store_computers([self.chromeos(d) for d in page if d.get("deviceId")])
        return {"count": n}

    @staticmethod
    def chromeos(d: dict[str, Any]) -> dict[str, Any]:
        serial = _s(d.get("serialNumber"), 128)
        name = _s(d.get("annotatedAssetId")) or serial or _s(d.get("model")) or _s(d.get("deviceId"), 12)
        recent = [r for r in (d.get("recentUsers") or []) if isinstance(r, dict) and r.get("email")]
        user = _s(d.get("annotatedUser")) or (_s(recent[0]["email"]) if recent else "")
        return {
            "external_id": f"chromeos:{_s(d.get('deviceId'), 54)}", "device_kind": "chromeos", "cloud_device_id": None,
            "name": name, "short_name": short_host(name), "dns_hostname": "", "sam_account_name": "",
            "serial_number": serial, "operating_system": "ChromeOS", "os_version": _s(d.get("osVersion")),
            "object_sid": None, "distinguished_name": "", "domain": "", "ou": _s(d.get("orgUnitPath"), 1024),
            "enabled": (d.get("status") or "ACTIVE") == "ACTIVE", "user_account_control": None,
            "last_logon_at": dt(d.get("lastSync")), "when_created": None, "when_changed": None,
            "platform": "chromeos", "agent_expected": False, "compliance": None, "encrypted": None,
            "primary_user": user.lower(),
            "attributes": {"status": _s(d.get("status"), 32), "model": _s(d.get("model"), 128)},
        }

    def _mobile(self, ctx: SyncContext) -> dict[str, Any]:
        n = 0
        for page in self._pages(f"{DIRECTORY}/customer/{self.customer}/devices/mobile", SCOPE_BY_PART["mobile"],
                                {"maxResults": 100, "projection": "BASIC"}, "mobiledevices", "mobile devices"):
            n += ctx.store_computers([self.mobile(d) for d in page if d.get("resourceId")])
        return {"count": n}

    @staticmethod
    def mobile(d: dict[str, Any]) -> dict[str, Any]:
        kind = _s(d.get("type"), 32).upper()
        platform = "android" if kind.startswith("ANDROID") else "ios" if kind.startswith("IOS") else platform_of(
            _s(d.get("os")))
        names = [n for n in (d.get("name") or []) if isinstance(n, str)]
        emails = [e for e in (d.get("email") or []) if isinstance(e, str)]
        name = (names[0] if names else "") or _s(d.get("model")) or _s(d.get("serialNumber")) or "mobile device"
        return {
            "external_id": f"mobile:{_s(d.get('resourceId'), 56)}", "device_kind": "mobile", "cloud_device_id": None,
            "name": name[:256], "short_name": short_host(name), "dns_hostname": "", "sam_account_name": "",
            "serial_number": _s(d.get("serialNumber"), 128), "operating_system": _s(d.get("os")) or kind,
            "os_version": "", "object_sid": None, "distinguished_name": "", "domain": "", "ou": "",
            "enabled": (d.get("status") or "APPROVED") == "APPROVED", "user_account_control": None,
            "last_logon_at": dt(d.get("lastSync")), "when_created": dt(d.get("firstSync")), "when_changed": None,
            "platform": platform, "agent_expected": False, "compliance": None, "encrypted": None,
            "primary_user": (emails[0] if emails else "").lower()[:256],
            "attributes": {"status": _s(d.get("status"), 32), "type": kind, "model": _s(d.get("model"), 128)},
        }

    def _endpoints(self, ctx: SyncContext) -> dict[str, Any]:
        scope = SCOPE_BY_PART["endpoints"]
        customer = f"customers/{self.customer}"
        n = 0
        for page in self._pages(f"{CLOUD_IDENTITY}/devices", scope, {"customer": customer, "pageSize": 100},
                                "devices", "endpoints"):
            # Android / iOS / ChromeOS are the mobile and ChromeOS parts' records.
            n += ctx.store_computers([self.endpoint(d) for d in page
                                      if d.get("name") and (d.get("deviceType") or "") in ENDPOINT_PLATFORMS])
        # Primary user: the most recently synced user of each device (a second, streamed pass).
        users: dict[str, tuple[str, str]] = {}
        for page in self._pages(f"{CLOUD_IDENTITY}/devices/-/deviceUsers", scope,
                                {"customer": customer, "pageSize": 100}, "deviceUsers", "endpoint users"):
            for du in page:
                parts = _s(du.get("name"), 512).split("/")
                email = _s(du.get("userEmail")).lower()
                if len(parts) >= 2 and email:
                    ext = f"ci:{parts[1][:60]}"
                    synced = _s(du.get("lastSyncTime"), 40)
                    if ext not in users or synced > users[ext][1]:
                        users[ext] = (email, synced)
            if len(users) >= 500:
                ctx.update_computers({k: {"primary_user": v[0]} for k, v in users.items()}, ("endpoint",))
                users.clear()
        if users:
            ctx.update_computers({k: {"primary_user": v[0]} for k, v in users.items()}, ("endpoint",))
        return {"count": n}

    @staticmethod
    def endpoint(d: dict[str, Any]) -> dict[str, Any]:
        kind = _s(d.get("deviceType"), 32)
        platform = ENDPOINT_PLATFORMS.get(kind, "")
        host = _s(d.get("hostname"))
        serial = _s(d.get("serialNumber"), 128)
        name = host or _s(d.get("model")) or serial or "endpoint"
        state = _s(d.get("managementState"), 32)
        enc = _s(d.get("encryptionState"), 32)
        return {
            "external_id": f"ci:{_s(d.get('name'), 512).split('/')[-1][:60]}", "device_kind": "endpoint",
            "cloud_device_id": None, "name": name, "short_name": short_host(host or name), "dns_hostname": "",
            "sam_account_name": "", "serial_number": serial,
            "operating_system": ENDPOINT_OS.get(kind, kind.title()), "os_version": _s(d.get("osVersion")),
            "object_sid": None, "distinguished_name": "", "domain": "", "ou": "",
            "enabled": state not in INACTIVE_ENDPOINT_STATES, "user_account_control": None,
            "last_logon_at": dt(d.get("lastSyncTime")), "when_created": dt(d.get("createTime")), "when_changed": None,
            "platform": platform, "agent_expected": bool(platform) and _s(d.get("ownerType"), 16) != "BYOD",
            "compliance": None, "encrypted": True if enc == "ENCRYPTED" else False if enc == "NOT_ENCRYPTED" else None,
            "attributes": {"owner": _s(d.get("ownerType"), 16), "management_state": state,
                           "model": _s(d.get("model"), 128)},
        }

    # -- Test & save
    def checks(self) -> list[dict[str, Any]]:
        cfg = self.src.config or {}
        parts = set(cfg.get("scopes") or [])
        try:
            self._load_key()
        except FatalError as e:
            return [check("error", "key", "Service-account key", str(e))]
        out = [check("ok", "key", "Service-account key", f"{self._key['client_email']} impersonating "
                                                         f"{cfg.get('admin_email')}")]
        probes = {
            "users": (f"{DIRECTORY}/users", {"customer": self.customer, "maxResults": 1}),
            "roles": (f"{DIRECTORY}/customer/{self.customer}/roles", {"maxResults": 1}),
            "chromeos": (f"{DIRECTORY}/customer/{self.customer}/devices/chromeos", {"maxResults": 1}),
            "mobile": (f"{DIRECTORY}/customer/{self.customer}/devices/mobile", {"maxResults": 1}),
            "endpoints": (f"{CLOUD_IDENTITY}/devices", {"customer": f"customers/{self.customer}", "pageSize": 1}),
        }
        for s in SCOPES:
            needed = s["part"] in parts if s["part"] else "roles" in parts
            if not needed:
                continue
            name = s["scope"].removeprefix(SCOPE_BASE)
            required = bool(s["part"])
            try:
                self.token(s["scope"])
                if s["part"]:
                    url, params = probes[s["part"]]
                    self.http.get_json(url, self._bearer(s["scope"]), params)
                out.append(check("ok", name, name, s["why"], required=required))
            except PartSkipped as e:
                out.append(check("missing", name, name, f"{e.detail}. {s['why']}", required=required))
            except FatalError as e:
                out.append(check("error", name, name, str(e), required=required))
                break  # the same refusal for every scope
            except CloudApiError as e:
                err = self._api_error(e, name)
                detail = err.detail if isinstance(err, PartSkipped) else str(err)
                out.append(check("error", name, name, detail, required=required))
        return out
