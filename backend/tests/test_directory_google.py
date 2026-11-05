"""Directory discovery, Google Workspace source: service-account key upload
(validated, encrypted, never returned), Test & save per OAuth scope, server-side
sync through the Admin SDK Directory API and Cloud Identity Devices (paging,
throttling, domain-wide delegation missing for a scope, API not enabled),
matching by serial, admin roles and the privileged issues, tenant isolation.
Google is faked with an httpx.MockTransport: no test talks to Google."""
from __future__ import annotations

import json
import logging
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from joserfc import jwt
from joserfc.jwk import RSAKey
from sqlalchemy import select

from app import db
from app.directory import cloud, cloud_http, google
from app.directory.models import DirectoryComputer, DirectorySource, DirectoryUser
from app.models import AuditLog, utcnow
from tests.test_devices import agent_client, enroll, new_token, windows_checkin
from tests.test_tenancy import ACME_ADMIN, ACME_PASSWORD, create_org, org_client

ADMIN = "it-admin@example.org"
SA = "cnapp-directory@acme-dir-123.iam.gserviceaccount.com"
ALL_SCOPES = {s["scope"] for s in google.SCOPES}


def iso(days: float | None) -> str:
    return "1970-01-01T00:00:00.000Z" if days is None else (utcnow() - timedelta(days=days)).isoformat() + "Z"


@pytest.fixture(scope="module")
def private_pem() -> str:
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption()).decode()


@pytest.fixture()
def key_json(private_pem) -> str:
    return json.dumps({"type": "service_account", "project_id": "acme-dir-123", "private_key_id": "0123456789abcdef" * 2,
                       "private_key": private_pem, "client_email": SA, "client_id": "112233445566778899001",
                       "token_uri": "https://evil.example.com/token"})


def gu(n: int, email: str, *, days: float | None = 1, suspended: bool = False, admin: bool = False) -> dict:
    return {"id": f"1{n:020d}", "primaryEmail": email, "name": {"fullName": email.split("@")[0].title()},
            "suspended": suspended, "archived": False, "isAdmin": admin, "isDelegatedAdmin": False,
            "lastLoginTime": iso(days), "creationTime": "2020-01-01T00:00:00.000Z", "orgUnitPath": "/Staff",
            "organizations": [{"department": "Engineering", "primary": True}]}


class FakeGoogle:
    def __init__(self, public_key: RSAKey):
        self.public_key = public_key
        self.authorised = set(ALL_SCOPES)  # domain-wide delegation
        self.admin = ADMIN
        self.disabled_apis: set[str] = set()
        self.page_size = 2
        self.throttle: set[str] = set()
        self.users: list[dict] = []
        self.roles = [{"roleId": "1", "roleName": "_SEED_ADMIN_ROLE", "isSuperAdminRole": True, "isSystemRole": True},
                      {"roleId": "2", "roleName": "_HELP_DESK_ADMIN_ROLE", "isSystemRole": True},
                      {"roleId": "3", "roleName": "Read-only auditors", "isSystemRole": False}]
        self.assignments: list[dict] = []
        self.group_members: dict[str, list[str]] = {}
        self.chromeos: list[dict] = []
        self.mobile: list[dict] = []
        self.devices: list[dict] = []
        self.device_users: list[dict] = []
        self.assertions: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = urlsplit(str(request.url))
        if url.hostname == "oauth2.googleapis.com":
            assert url.path == "/token"  # never the key's token_uri
            form = parse_qs(request.content.decode())
            assert form["grant_type"] == ["urn:ietf:params:oauth:grant-type:jwt-bearer"]
            tok = jwt.decode(form["assertion"][0], self.public_key)
            claims = tok.claims
            self.assertions.append(claims)
            assert tok.header["alg"] == "RS256" and claims["iss"] == SA and claims["aud"] == google.TOKEN_URL
            if claims["sub"] != self.admin:
                return httpx.Response(400, json={"error": "invalid_grant", "error_description": "Invalid email or User ID"})
            if claims["scope"] not in self.authorised:
                return httpx.Response(401, json={"error": "unauthorized_client", "error_description":
                                                 "Client is unauthorized to retrieve access tokens using this method"})
            return httpx.Response(200, json={"access_token": "tok:" + claims["scope"], "expires_in": 3599})
        assert request.method == "GET"
        scope = request.headers["authorization"].removeprefix("Bearer tok:")
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.path in self.throttle:
            self.throttle.discard(url.path)
            return httpx.Response(429, headers={"Retry-After": "2"}, json={})
        api = "cloudidentity" if url.hostname == "cloudidentity.googleapis.com" else "admin"
        if api in self.disabled_apis:
            return httpx.Response(403, json={"error": {"code": 403, "status": "PERMISSION_DENIED", "message":
                                                       "Admin SDK API has not been used in project 123 before or it is disabled.",
                                                       "errors": [{"reason": "accessNotConfigured"}]}})
        p = url.path

        def need(s: str) -> None:
            assert scope == google.SCOPE_BASE + s, (p, scope)

        if p == "/admin/directory/v1/users":
            need("admin.directory.user.readonly")
            assert q["customer"] == "my_customer"
            return self.page(q, "users", self.users)
        if p == "/admin/directory/v1/customer/my_customer/roles":
            need("admin.directory.rolemanagement.readonly")
            return self.page(q, "items", self.roles)
        if p == "/admin/directory/v1/customer/my_customer/roleassignments":
            need("admin.directory.rolemanagement.readonly")
            return self.page(q, "items", self.assignments)
        if p.startswith("/admin/directory/v1/groups/") and p.endswith("/members"):
            need("admin.directory.group.member.readonly")
            assert q["includeDerivedMembership"] == "true"
            members = [{"id": m, "type": "USER"} for m in self.group_members.get(p.split("/")[5], [])]
            return self.page(q, "members", members)
        if p == "/admin/directory/v1/customer/my_customer/devices/chromeos":
            need("admin.directory.device.chromeos.readonly")
            return self.page(q, "chromeosdevices", self.chromeos)
        if p == "/admin/directory/v1/customer/my_customer/devices/mobile":
            need("admin.directory.device.mobile.readonly")
            return self.page(q, "mobiledevices", self.mobile)
        if p == "/v1/devices":
            need("cloud-identity.devices.readonly")
            assert q["customer"] == "customers/my_customer"
            return self.page(q, "devices", self.devices)
        if p == "/v1/devices/-/deviceUsers":
            need("cloud-identity.devices.readonly")
            return self.page(q, "deviceUsers", self.device_users)
        return httpx.Response(404, json={"error": {"code": 404, "message": p}})

    def page(self, q: dict, key: str, items: list[dict]) -> httpx.Response:
        start = int(q.get("pageToken", "0"))
        size = min(self.page_size, int(q.get("maxResults") or q.get("pageSize") or 100))
        body: dict = {key: items[start:start + size]}
        if start + size < len(items):
            body["nextPageToken"] = str(start + size)
        return httpx.Response(200, json=body)


@pytest.fixture()
def admin(empty_client):
    return empty_client


@pytest.fixture()
def fake(monkeypatch, private_pem):
    f = FakeGoogle(RSAKey.import_key(private_pem))
    sleeps: list[float] = []
    cloud_http.set_transport(httpx.MockTransport(f))
    cloud_http.set_sleep(sleeps.append)
    monkeypatch.setattr(cloud, "INLINE", True)
    f.sleeps = sleeps
    yield f
    cloud_http.set_transport(None)
    cloud_http.set_sleep(None)


def make_google(client, key: str | None, **config) -> dict:
    body = {"type": "google", "name": "Example Workspace", "config": {"admin_email": ADMIN, **config}}
    if key is not None:
        body["google_key"] = key
    r = client.post("/api/directory/sources", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def sync(client, source_id: str) -> dict:
    r = client.post(f"/api/directory/sources/{source_id}/sync")
    assert r.status_code == 202, r.text
    return client.get(f"/api/directory/runs/{r.json()['id']}").json()


def add_agent(admin, hostname: str, machine: str, serial: str, os_family: str = "windows",
              users: list[str] | None = None) -> str:
    agent = agent_client(admin.app)
    r = enroll(agent, new_token(admin), machine_id=machine, hostname=hostname, os_family=os_family)
    assert r.status_code == 200, r.text
    agent.headers["Authorization"] = f"Bearer {r.json()['device_secret']}"
    body = windows_checkin()
    body["device"].update({"hostname": hostname, "os_family": os_family, "serial_number": serial,
                           "logged_in_users": users or []})
    assert agent.post("/api/agent/checkin", json=body).status_code == 200
    return r.json()["device_id"]


def by_type(client) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for i in client.get("/api/directory/issues", params={"limit": 1000}).json()["items"]:
        out.setdefault(i["type"], set()).add(i["name"])
    return out


# ----------------------------------------------------------------------------- key
def test_key_upload_is_validated_encrypted_and_never_returned(admin, fake, key_json, private_pem, caplog):
    caplog.set_level(logging.DEBUG)
    assert admin.get("/api/directory/google-scopes").json()["scopes"][0]["scope"].endswith("user.readonly")
    # Without a key, or with something that is not a service-account key: refused without echoing it.
    r = admin.post("/api/directory/sources", json={"type": "google", "name": "x", "config": {"admin_email": ADMIN}})
    assert r.status_code == 422 and "JSON key" in r.json()["detail"]
    junk_pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
    bad_key = json.dumps({**json.loads(key_json), "private_key": junk_pem})
    for bad in ("x" * 200, json.dumps({"type": "authorized_user", "pad": "x" * 200}), bad_key):
        r = admin.post("/api/directory/sources", json={"type": "google", "name": "x", "google_key": bad,
                                                      "config": {"admin_email": ADMIN}})
        assert r.status_code == 422, r.text
        assert "AAAA" not in r.text and "authorized_user" not in r.text
    r = admin.post("/api/directory/sources", json={"type": "google", "name": "x", "google_key": key_json,
                                                  "config": {"admin_email": "not-an-email"}})
    assert r.status_code == 422
    src = make_google(admin, key_json, service_account_email="forged@x.iam.gserviceaccount.com")
    cfg = src["config"]
    assert (cfg["service_account_email"], cfg["client_id"], cfg["key_id"]) == (SA, "112233445566778899001", "01234567")
    assert src["has_credential"] and src["credential_username_hint"].startswith("key 01234567… · cnapp-directory@")
    assert src["collection"] == "server"
    secret_bits = ("BEGIN PRIVATE KEY", private_pem.splitlines()[1])
    sync(admin, src["id"])
    texts = [admin.get("/api/directory/sources").text, json.dumps(src), caplog.text,
             admin.post(f"/api/directory/sources/{src['id']}/test").text]
    with db.get_session("default") as s:
        row = s.get(DirectorySource, src["id"])
        texts.append(row.secret_ciphertext + json.dumps(row.config))
        texts += [json.dumps(a.detail or {}, default=str) for a in s.scalars(select(AuditLog))]
    for t in texts:
        assert not any(b in t for b in secret_bits)
    # Editing without a new key keeps it (and the server-set facts); a new key replaces it.
    r = admin.patch(f"/api/directory/sources/{src['id']}", json={"config": {"admin_email": ADMIN, "scopes": ["users"]}})
    assert r.status_code == 200 and r.json()["config"]["service_account_email"] == SA and r.json()["has_credential"]
    other = json.dumps({**json.loads(key_json), "private_key_id": "fedcba98" * 4})
    r = admin.patch(f"/api/directory/sources/{src['id']}", json={"google_key": other})
    assert r.status_code == 200 and r.json()["config"]["key_id"] == "fedcba98"


def test_test_and_save_checks_each_scope(admin, fake, key_json):
    src = make_google(admin, key_json)
    fake.authorised = {google.SCOPE_BY_PART["users"], google.SCOPE_BY_PART["chromeos"]}
    run = admin.post(f"/api/directory/sources/{src['id']}/test").json()
    assert run["status"] == "failed"
    checks = {c["id"]: c for c in run["checks"]}
    assert checks["key"]["status"] == "ok" and ADMIN in checks["key"]["detail"]
    assert checks["admin.directory.user.readonly"]["status"] == "ok"
    assert checks["admin.directory.device.chromeos.readonly"]["status"] == "ok"
    miss = checks["admin.directory.device.mobile.readonly"]
    assert miss["status"] == "missing" and miss["required"] and "domain-wide delegation" in miss["detail"]
    assert checks["admin.directory.group.member.readonly"]["required"] is False
    # Each scope is requested on its own (one missing scope never hides the others).
    assert {a["scope"] for a in fake.assertions} == ALL_SCOPES
    # Admin SDK not enabled in the project: said so.
    fake.authorised, fake.disabled_apis = set(ALL_SCOPES), {"admin"}
    run = admin.post(f"/api/directory/sources/{src['id']}/test").json()
    users = next(c for c in run["checks"] if c["id"] == "admin.directory.user.readonly")
    assert users["status"] == "error" and "not enabled" in users["detail"]
    # Wrong admin to impersonate: one clear error.
    fake.disabled_apis, fake.admin = set(), "someone-else@example.org"
    run = admin.post(f"/api/directory/sources/{src['id']}/test").json()
    assert run["status"] == "failed" and "admin email" in run["error"]
    fake.admin = ADMIN
    assert admin.post(f"/api/directory/sources/{src['id']}/test").json()["status"] == "succeeded"


# ----------------------------------------------------------------------------- sync
def populate(fake: FakeGoogle) -> None:
    fake.users = [gu(1, "ana@example.org", admin=True), gu(2, "ben@example.org", suspended=True, admin=True),
                  gu(3, "cy@example.org", days=200), gu(4, "dee@example.org"), gu(5, "eve@example.org", days=None)]
    fake.assignments = [{"roleId": "2", "assignedTo": "1" + "3".zfill(20), "assigneeType": "user"},
                        {"roleId": "2", "assignedTo": "group-1", "assigneeType": "group"},
                        {"roleId": "3", "assignedTo": "1" + "5".zfill(20), "assigneeType": "user"}]
    fake.group_members = {"group-1": ["1" + "4".zfill(20)]}
    fake.chromeos = [{"deviceId": "cros-1", "serialNumber": "CROS1", "status": "ACTIVE", "lastSync": iso(2),
                      "annotatedAssetId": "CB-101", "annotatedUser": "ana@example.org", "osVersion": "126",
                      "orgUnitPath": "/Staff"}]
    fake.mobile = [{"resourceId": "mob-1", "deviceId": "d1", "serialNumber": "", "status": "APPROVED", "type": "IOS_SYNC",
                    "lastSync": iso(1), "email": ["ana@example.org"], "model": "iPhone 15", "os": "iOS 18.1"}]
    fake.devices = [
        {"name": "devices/win-1", "deviceType": "WINDOWS", "hostname": "WIN-LAPTOP1", "serialNumber": "SER-W1",
         "lastSyncTime": iso(1), "ownerType": "COMPANY", "encryptionState": "ENCRYPTED", "osVersion": "10.0.22631",
         "managementState": "APPROVED"},
        {"name": "devices/mac-1", "deviceType": "MAC_OS", "hostname": "MAC-1", "serialNumber": "SER-M1",
         "lastSyncTime": iso(3), "ownerType": "COMPANY", "encryptionState": "NOT_ENCRYPTED", "osVersion": "15.1"},
        {"name": "devices/byod-1", "deviceType": "WINDOWS", "hostname": "HOME-PC", "serialNumber": "SER-B1",
         "lastSyncTime": iso(1), "ownerType": "BYOD"},
        {"name": "devices/and-1", "deviceType": "ANDROID", "serialNumber": "AND1", "lastSyncTime": iso(1)},
        {"name": "devices/old-1", "deviceType": "LINUX", "hostname": "OLD-BOX", "serialNumber": "SER-L1",
         "lastSyncTime": iso(400), "ownerType": "COMPANY"}]
    fake.device_users = [
        {"name": "devices/win-1/deviceUsers/u1", "userEmail": "cy@example.org", "lastSyncTime": iso(10)},
        {"name": "devices/win-1/deviceUsers/u2", "userEmail": "ana@example.org", "lastSyncTime": iso(1)},
        {"name": "devices/mac-1/deviceUsers/u3", "userEmail": "dee@example.org", "lastSyncTime": iso(3)}]


def test_sync_paging_matching_roles_and_issues(admin, fake, key_json):
    populate(fake)
    fake.throttle = {"/admin/directory/v1/users", "/v1/devices"}
    laptop = add_agent(admin, "WIN-LAPTOP1", "a" * 64, "ser-w1", users=["ben@example.org"])
    src = make_google(admin, key_json)
    run = sync(admin, src["id"])
    assert run["status"] == "succeeded" and run["error"] is None, run
    assert fake.sleeps == [2.0, 2.0] and run["users_seen"] == 5
    st = run["scope_status"]
    assert {k: v["status"] for k, v in st.items()} == {"users": "ok", "roles": "ok", "chromeos": "ok", "mobile": "ok",
                                                      "endpoints": "ok"}
    assert st["endpoints"]["count"] == 4  # the Android record belongs to the mobile part
    comps = {c["name"]: c for c in admin.get("/api/directory/computers?status=all").json()["items"]}
    assert set(comps) == {"CB-101", "iPhone 15", "WIN-LAPTOP1", "MAC-1", "HOME-PC", "OLD-BOX"}
    win = comps["WIN-LAPTOP1"]
    assert (win["device_id"], win["match_method"]) == (laptop, "serial")
    assert win["primary_user"] == "ana@example.org" and win["encrypted"] is True
    assert comps["MAC-1"]["encrypted"] is False and comps["MAC-1"]["primary_user"] == "dee@example.org"
    assert not comps["CB-101"]["agent_expected"] and not comps["iPhone 15"]["agent_expected"]
    assert not comps["HOME-PC"]["agent_expected"]
    # Coverage: WIN-LAPTOP1 (agent), MAC-1, OLD-BOX.
    cov = {k: v for k, v in admin.get("/api/directory/summary").json()["coverage"].items() if k != "by_class"}
    assert cov == {"directory_computers": 3, "managed": 1,
                                                                     "pct": 33.3}
    roles = {u["user_principal_name"]: u["privileged_roles"] for u in
             admin.get("/api/directory/users?privileged=true").json()["items"]}
    assert roles == {"ana@example.org": ["Super Admin"], "ben@example.org": ["Super Admin"],
                     "cy@example.org": ["Help Desk Admin"], "dee@example.org": ["Help Desk Admin (via group)"]}
    by = by_type(admin)
    assert by["not_managed"] == {"MAC-1"}
    assert by["stale_computer"] == {"OLD-BOX"}
    assert by["disabled_user_signed_in"] == {"ben@example.org"}
    assert by["privileged_disabled"] == {"ben@example.org"}
    assert by["privileged_stale"] == {"cy@example.org"}
    assert by["privileged_no_agent"] == {"dee@example.org"}  # MAC-1; ana's laptop has the agent
    assert "non_compliant" not in by and "not_in_intune" not in by
    nm = next(i for i in admin.get("/api/directory/issues?type=not_managed").json()["items"])
    assert nm["detail"].startswith("Active in Google endpoints") and nm["sources"][0]["type"] == "google"
    # Google sign-in is always known: users show it.
    u = {x["user_principal_name"]: x for x in admin.get("/api/directory/users").json()["items"]}
    assert u["eve@example.org"]["last_logon_at"] is None and u["eve@example.org"]["sign_in_known"]


def test_scope_without_delegation_or_api_is_skipped_and_keeps_data(admin, fake, key_json):
    populate(fake)
    src = make_google(admin, key_json)
    sync(admin, src["id"])
    fake.authorised = ALL_SCOPES - {google.SCOPE_BY_PART["endpoints"], google.GROUP_SCOPE}
    run = sync(admin, src["id"])
    assert run["status"] == "succeeded" and run["error"].startswith("partial: ")
    st = run["scope_status"]
    assert st["endpoints"]["status"] == "missing_permission" and "domain-wide delegation" in st["endpoints"]["detail"]
    assert st["roles"]["status"] == "ok" and "not expanded" in st["roles"]["detail"]
    with db.get_session("default") as s:
        ends = s.scalars(select(DirectoryComputer).where(DirectoryComputer.device_kind == "endpoint")).all()
        assert len(ends) == 4 and all(c.missing_since is None for c in ends)
        # Group-held roles were not expanded: flags only added, dee keeps hers.
        dee = s.scalars(select(DirectoryUser).where(DirectoryUser.user_principal_name == "dee@example.org")).one()
        assert dee.privileged
    # Only the users scope: super admins are still flagged (from the user list).
    admin.patch(f"/api/directory/sources/{src['id']}", json={"config": {"admin_email": ADMIN, "scopes": ["users"]}})
    fake.authorised = {google.SCOPE_BY_PART["users"]}
    sync(admin, src["id"])
    roles = {u["user_principal_name"] for u in admin.get("/api/directory/users?privileged=true").json()["items"]}
    assert roles == {"ana@example.org", "ben@example.org"}
    # The Admin SDK disabled: every part fails, the run fails, nothing is lost.
    fake.disabled_apis = {"admin"}
    run = sync(admin, src["id"])
    assert run["status"] == "failed" and "not enabled" in run["error"]
    assert admin.get(f"/api/directory/sources/{src['id']}").json()["users_count"] == 5


def test_tenant_isolation(admin, fake, key_json):
    populate(fake)
    src = make_google(admin, key_json)
    sync(admin, src["id"])
    create_org("acme", ACME_ADMIN, ACME_PASSWORD)
    acme = org_client(admin.app, ACME_ADMIN, ACME_PASSWORD)
    assert acme.get("/api/directory/sources").json() == []
    assert acme.get("/api/directory/users?privileged=true").json()["total"] == 0
    assert acme.get("/api/directory/computers").json()["total"] == 0
    for method, path, body in (("patch", f"/api/directory/sources/{src['id']}", {"google_key": key_json}),
                               ("post", f"/api/directory/sources/{src['id']}/test", None),
                               ("post", f"/api/directory/sources/{src['id']}/sync", None)):
        r = getattr(acme, method)(path, **({"json": body} if body else {}))
        assert r.status_code == 404
    # Another organisation may connect the same Workspace with its own key: a separate source.
    other = make_google(acme, key_json)
    assert other["id"] != src["id"] and sync(acme, other["id"])["status"] == "succeeded"
    assert admin.get("/api/directory/summary").json()["users"] == 5
