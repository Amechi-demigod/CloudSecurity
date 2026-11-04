"""Directory discovery, Microsoft Entra ID + Intune source: Azure connector
reuse, Test & save permission checks, server-side sync through Microsoft
Graph (paging, throttling, missing permission / licence degradation, safety
cap), machine grouping across AD / Entra / Intune, the new issue types,
scheduler, secrets and tenant isolation. Microsoft Graph is faked with an
httpx.MockTransport: no test talks to Microsoft."""
from __future__ import annotations

import base64
import json
import logging
from datetime import timedelta
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import pytest
from sqlalchemy import select

from app import config, db
from app.directory import cloud, cloud_http, graph
from app.directory.models import DirectoryComputer, DirectorySource, DirectorySyncRun, DirectoryUser
from app.directory.scheduler import DirectoryScheduler
from app.models import AuditLog, utcnow
from tests.conftest import login, make_user
from tests.test_directory import add_device, computer, join, make_source, run_sync, user
from tests.test_tenancy import ACME_ADMIN, ACME_PASSWORD, create_org, org_client

TENANT = "11111111-2222-4333-8444-555555555555"
CLIENT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
SECRET = "Graph-client-s3cret-value~never-shown"
ALL_ROLES = {p["name"] for p in graph.PERMISSIONS}
GA = "62e90394-69f5-4237-9190-012177145e10"
SEC_ADMIN = "194ae4cb-b126-40b2-bd5b-6091b380977d"
USER_ADMIN = "fe930be7-5e62-47db-91af-98c3a49a38b1"
READER = "4a5d8f65-41da-4de4-8968-e035b65339cf"  # Reports Reader: not privileged
GROUP = "99999999-0000-4000-8000-000000000001"


def gid(n: int) -> str:
    return f"{n:08x}-1111-4111-8111-{n:012x}"


E1, E2, E9 = gid(901), gid(902), gid(909)  # Entra device ids (deviceId)


def iso(days: float | None) -> str | None:
    return None if days is None else (utcnow() - timedelta(days=days)).isoformat() + "Z"


def guser(n: int, upn: str, *, enabled: bool = True, days: float | None = 1, sid: str = "", sam: str = "",
          domain: str = "") -> dict:
    return {"id": gid(n), "userPrincipalName": upn, "mail": upn, "displayName": upn.split("@")[0].title(),
            "givenName": "", "surname": "", "department": "IT", "jobTitle": "Engineer", "accountEnabled": enabled,
            "createdDateTime": "2020-01-01T00:00:00Z", "userType": "Member",
            "onPremisesSamAccountName": sam or None, "onPremisesDomainName": domain or None,
            "onPremisesSecurityIdentifier": sid or None, "onPremisesDistinguishedName": None,
            "onPremisesSyncEnabled": bool(sid) or None, "signInActivity": {"lastSignInDateTime": iso(days)}}


def gdevice(n: int, name: str, device_id: str, *, trust: str = "AzureAd", os_name: str = "Windows",
            days: float = 1, enabled: bool = True, sid: str = "") -> dict:
    return {"id": gid(n), "deviceId": device_id, "displayName": name, "operatingSystem": os_name,
            "operatingSystemVersion": "10.0.22631", "accountEnabled": enabled, "trustType": trust,
            "approximateLastSignInDateTime": iso(days), "registrationDateTime": "2024-01-01T00:00:00Z",
            "isManaged": True, "isCompliant": True, "profileType": "RegisteredDevice",
            **({"onPremisesSecurityIdentifier": sid} if sid else {})}


def gmanaged(n: int, name: str, aad: str, *, compliance: str = "compliant", serial: str = "", upn: str = "",
             owner: str = "company", os_name: str = "Windows", days: float = 1, encrypted: bool = True) -> dict:
    return {"id": gid(n), "deviceName": name, "azureADDeviceId": aad, "serialNumber": serial,
            "complianceState": compliance, "isEncrypted": encrypted, "lastSyncDateTime": iso(days),
            "operatingSystem": os_name, "osVersion": "10.0.22631", "userPrincipalName": upn,
            "managedDeviceOwnerType": owner, "enrolledDateTime": "2024-01-01T00:00:00Z", "model": "Laptop 7",
            "manufacturer": "Contoso"}


def fake_jwt(roles: set[str]) -> str:
    def enc(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'RS256'})}.{enc({'tid': TENANT, 'roles': sorted(roles)})}.c2ln"


class FakeGraph:
    """Microsoft Graph + the Entra token endpoint, in memory."""

    def __init__(self):
        self.roles = set(ALL_ROLES)
        self.premium = True
        self.intune = True
        self.page_size = 2
        self.users: list[dict] = []
        self.devices: list[dict] = []
        self.managed: list[dict] = []
        self.role_defs = [{"id": GA, "displayName": "Global Administrator", "templateId": GA},
                          {"id": SEC_ADMIN, "displayName": "Security Administrator", "templateId": SEC_ADMIN},
                          {"id": USER_ADMIN, "displayName": "User Administrator", "templateId": USER_ADMIN},
                          {"id": READER, "displayName": "Reports Reader", "templateId": READER}]
        self.assignments: dict[str, list[tuple[str, str]]] = {}  # role id -> [(principal id, odata type)]
        self.eligible: dict[str, list[tuple[str, str]]] = {}  # PIM eligibility, same shape
        self.p2 = True  # Entra ID P2 (PIM)
        self.group_members: dict[str, list[str]] = {}
        self.throttle: set[str] = set()  # paths answered 429 once
        self.calls: list[tuple[str, str]] = []
        self.on_request = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = urlsplit(str(request.url))
        self.calls.append((request.method, url.path))
        if self.on_request:
            self.on_request(url.path)
        if url.hostname == "login.microsoftonline.com":
            form = parse_qs(request.content.decode())
            assert url.path == f"/{TENANT}/oauth2/v2.0/token"
            if form.get("client_secret") != [SECRET] or form.get("client_id") != [CLIENT]:
                return httpx.Response(401, json={"error": "invalid_client",
                                                 "error_description": "AADSTS7000215: Invalid client secret provided."})
            return httpx.Response(200, json={"access_token": fake_jwt(self.roles), "expires_in": 3599})
        assert url.hostname == "graph.microsoft.com", url
        assert request.method == "GET"
        assert request.headers["authorization"].startswith("Bearer ")
        if url.path in self.throttle:
            self.throttle.discard(url.path)
            return httpx.Response(429, headers={"Retry-After": "1"}, json={"error": {"code": "TooManyRequests"}})
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        path = url.path.removeprefix("/v1.0")
        if path == "/users":
            if "User.Read.All" not in self.roles:
                return self.denied()
            items = [dict(u) for u in self.users]
            if "signInActivity" in q.get("$select", ""):
                if "AuditLog.Read.All" not in self.roles:
                    return self.denied()
                if not self.premium:
                    return httpx.Response(403, json={"error": {
                        "code": graph.NO_PREMIUM, "message": "Neither tenant is B2C or tenant doesn't have premium license"}})
            else:
                for u in items:
                    u.pop("signInActivity", None)
            return self.page(url, q, items)
        if path == "/devices":
            return self.page(url, q, self.devices) if "Device.Read.All" in self.roles else self.denied()
        if path == "/deviceManagement/managedDevices":
            if "DeviceManagementManagedDevices.Read.All" not in self.roles:
                return self.denied()
            if not self.intune:
                return httpx.Response(403, json={"error": {"code": "Forbidden", "message": "Forbidden: no Intune license"}})
            return self.page(url, q, self.managed)
        if path == "/roleManagement/directory/roleDefinitions":
            return self.page(url, q, self.role_defs) if "RoleManagement.Read.Directory" in self.roles else self.denied()
        if path in ("/roleManagement/directory/roleAssignments",
                    "/roleManagement/directory/roleEligibilityScheduleInstances"):
            pim = path.endswith("Instances")
            if ("RoleEligibilitySchedule.Read.Directory" if pim else "RoleManagement.Read.Directory") not in self.roles:
                return self.denied()
            if pim and not self.p2:
                return httpx.Response(400, json={"error": {"code": "AadPremiumLicenseRequired", "message":
                                                           "The tenant needs an AAD Premium 2 license"}})
            if "$filter" not in q:  # Test & save probe
                return self.page(url, q, [])
            rid = q["$filter"].split("'")[1]
            assert q.get("$expand") == "principal"
            items = [{"id": f"a-{p}", "principalId": p, "roleDefinitionId": rid, "principal": {"@odata.type": t}}
                     for p, t in (self.eligible if pim else self.assignments).get(rid, [])]
            return self.page(url, q, items)
        if path.startswith("/groups/") and path.endswith("/transitiveMembers/microsoft.graph.user"):
            if "GroupMember.Read.All" not in self.roles:
                return self.denied()
            return self.page(url, q, [{"id": m} for m in self.group_members.get(path.split("/")[2], [])])
        return httpx.Response(404, json={"error": {"code": "Request_ResourceNotFound", "message": path}})

    @staticmethod
    def denied() -> httpx.Response:
        return httpx.Response(403, json={"error": {"code": "Authorization_RequestDenied",
                                                   "message": "Insufficient privileges to complete the operation."}})

    def page(self, url, q: dict, items: list[dict]) -> httpx.Response:
        start = int(q.get("$skiptoken", "0"))
        size = min(self.page_size, int(q.get("$top", "1000")))
        body: dict = {"value": items[start:start + size]}
        if start + size < len(items):
            nq = {k: v for k, v in q.items()}
            nq["$skiptoken"] = str(start + size)
            body["@odata.nextLink"] = f"https://graph.microsoft.com{url.path}?{urlencode(nq)}"
        return httpx.Response(200, json=body)


@pytest.fixture()
def admin(empty_client):
    return empty_client


@pytest.fixture()
def fake(monkeypatch):
    f = FakeGraph()
    sleeps: list[float] = []
    cloud_http.set_transport(httpx.MockTransport(f))
    cloud_http.set_sleep(sleeps.append)
    monkeypatch.setattr(cloud, "INLINE", True)
    f.sleeps = sleeps
    yield f
    cloud_http.set_transport(None)
    cloud_http.set_sleep(None)


@pytest.fixture()
def scheduler():
    sched = DirectoryScheduler()
    yield sched
    sched.stop()


def connect_azure(client) -> None:
    r = client.put("/api/organization/connectors/azure", json={
        "config": {"tenant_id": TENANT, "client_id": CLIENT, "subscription_ids": []},
        "secrets": {"client_secret": SECRET}})
    assert r.status_code == 200, r.text


def make_entra(client, **config) -> dict:
    r = client.post("/api/directory/sources", json={"type": "entra", "name": "Contoso Entra",
                                                    "config": {"connector_id": "org", **config}})
    assert r.status_code == 201, r.text
    return r.json()


def sync(client, source_id: str) -> dict:
    r = client.post(f"/api/directory/sources/{source_id}/sync")
    assert r.status_code == 202, r.text
    return client.get(f"/api/directory/runs/{r.json()['id']}").json()


def entra_join(device_id: str, tenant: str = TENANT) -> dict:
    return {"ad_domain": "", "ad_netbios": "", "ad_forest": "", "ad_domain_sid": "", "ad_computer_sid": "",
            "ad_object_guid": "", "dns_hostname": "", "entra_device_id": device_id, "entra_tenant_id": tenant,
            "entra_join_type": "joined", "intune_enrollment_id": "", "source": "lsa"}


def issues_by_type(client, **params) -> dict[str, set[str]]:
    by: dict[str, set[str]] = {}
    for i in client.get("/api/directory/issues", params={"limit": 1000, **params}).json()["items"]:
        by.setdefault(i["type"], set()).add(i["name"])
    return by


# ----------------------------------------------------------------------------- sources
def test_connector_reuse_and_source_rules(admin, fake, monkeypatch):
    # No Azure connector yet: nothing to choose, and a source cannot be created.
    assert admin.get("/api/directory/azure-connectors").json()["connectors"] == []
    r = admin.post("/api/directory/sources", json={"type": "entra", "name": "x", "config": {"connector_id": "org"}})
    assert r.status_code == 422
    connect_azure(admin)
    info = admin.get("/api/directory/azure-connectors").json()
    assert info["connectors"] == [{"id": "org", "name": "Azure connector", "tenant_id": TENANT, "client_id": CLIENT,
                                   "auth_mode": "client_secret", "usable": True, "reason": "", "source": None}]
    assert [p["name"] for p in info["permissions"]] == [p["name"] for p in graph.PERMISSIONS]
    assert info["graph_app_id"] == graph.GRAPH_APP_ID and "Global Administrator" in info["privileged_roles"]
    src = make_entra(admin, tenant_id="forged", client_id="forged")
    # Tenant and client id come from the connector; the secret is never copied or returned.
    assert (src["config"]["tenant_id"], src["config"]["client_id"]) == (TENANT, CLIENT)
    assert src["collection"] == "server" and src["collectors"] == [] and not src["has_credential"]
    with db.get_session("default") as s:
        row = s.get(DirectorySource, src["id"])
        assert row.secret_ciphertext is None and SECRET not in json.dumps(row.config)
    assert admin.get("/api/directory/azure-connectors").json()["connectors"][0]["source"]["id"] == src["id"]
    # One Entra source per tenant.
    r = admin.post("/api/directory/sources", json={"type": "entra", "name": "dup", "config": {"connector_id": "org"}})
    assert r.status_code == 409 and "one source per tenant" in r.json()["detail"]
    # Cloud sources take no collectors / AD credential; unknown scopes are refused.
    for body in ({"collector_device_ids": ["a" * 32]}, {"credential": {"username": "u", "password": "p"}},
                 {"config": {"connector_id": "org", "scopes": ["mailboxes"]}}):
        r = admin.post("/api/directory/sources", json={"type": "entra", "name": "x",
                                                       "config": {"connector_id": "org"}, **body})
        assert r.status_code == 422, body
    # Edit: scopes change, tenant / client id stay the connector's.
    r = admin.patch(f"/api/directory/sources/{src['id']}", json={"config": {
        "connector_id": "org", "tenant_id": "x", "scopes": ["users", "devices"], "stale_days": 30}})
    assert r.status_code == 200, r.text
    assert r.json()["config"]["scopes"] == ["users", "devices"] and r.json()["config"]["tenant_id"] == TENANT
    # Viewers cannot create, edit or sync.
    from fastapi.testclient import TestClient

    make_user(admin, "viewer")
    viewer = TestClient(admin.app, base_url=str(admin.base_url))
    login(viewer, "viewer@example.com", "a-long-test-password")
    assert viewer.get("/api/directory/azure-connectors").status_code == 200
    assert viewer.post(f"/api/directory/sources/{src['id']}/sync").status_code == 403
    assert viewer.post(f"/api/directory/sources/{src['id']}/test").status_code == 403


def test_environment_connector_with_managed_identity_cannot_call_graph(admin, fake, monkeypatch):
    monkeypatch.setattr(config.settings, "azure_tenant_id", TENANT)
    monkeypatch.setattr(config.settings, "azure_managed_identity_client_id", CLIENT)
    monkeypatch.setattr(config.settings, "azure_auth_mode", "managed_identity")
    conn = admin.get("/api/directory/azure-connectors").json()["connectors"]
    assert len(conn) == 1 and conn[0]["id"] == "env" and not conn[0]["usable"]
    assert "managed identity" in conn[0]["reason"]
    r = admin.post("/api/directory/sources", json={"type": "entra", "name": "x", "config": {"connector_id": "env"}})
    assert r.status_code == 422 and "managed identity" in r.json()["detail"]
    # With a client secret in the environment it is usable.
    monkeypatch.setattr(config.settings, "azure_auth_mode", "auto")
    monkeypatch.setattr(config.settings, "azure_client_id", CLIENT)
    monkeypatch.setattr(config.settings, "azure_client_secret", SECRET)
    assert admin.get("/api/directory/azure-connectors").json()["connectors"][0]["usable"]
    src = admin.post("/api/directory/sources", json={"type": "entra", "name": "x", "config": {"connector_id": "env"}})
    assert src.status_code == 201
    fake.users = [guser(1, "alice@contoso.com")]
    assert sync(admin, src.json()["id"])["status"] == "succeeded"


def test_test_and_save_reports_each_permission(admin, fake):
    connect_azure(admin)
    src = make_entra(admin)
    fake.roles = {"User.Read.All", "Device.Read.All"}
    run = admin.post(f"/api/directory/sources/{src['id']}/test").json()
    assert run["trigger"] == "test" and run["status"] == "failed"
    checks = {c["id"]: c for c in run["checks"]}
    assert checks["token"]["status"] == "ok"
    assert checks["User.Read.All"]["status"] == "ok" and checks["Device.Read.All"]["status"] == "ok"
    assert checks["DeviceManagementManagedDevices.Read.All"]["status"] == "missing"
    assert checks["DeviceManagementManagedDevices.Read.All"]["required"]
    assert checks["RoleManagement.Read.Directory"]["status"] == "missing"
    assert checks["AuditLog.Read.All"]["status"] == "missing" and not checks["AuditLog.Read.All"]["required"]
    assert checks["sign_in"]["status"] == "missing_permission" and not checks["sign_in"]["required"]
    assert "DeviceManagementManagedDevices.Read.All" in run["error"]
    # All granted, but no Entra ID P1/P2 and no Intune licence: passes with warnings.
    fake.roles, fake.premium, fake.intune = set(ALL_ROLES), False, False
    run = admin.post(f"/api/directory/sources/{src['id']}/test").json()
    checks = {c["id"]: c for c in run["checks"]}
    assert run["status"] == "succeeded", run
    assert checks["sign_in"]["status"] == "unlicensed" and "P1 or P2" in checks["sign_in"]["detail"]
    assert checks["intune"]["status"] == "unlicensed"
    # A wrong secret fails the sign-in check with Microsoft's message, never the secret.
    fake.roles = set(ALL_ROLES)
    with db.get_session("default") as s:
        from app.connectors import org_config

        org_config.upsert(s, "azure", config_in={"tenant_id": TENANT, "client_id": CLIENT, "subscription_ids": []},
                          secrets_in={"client_secret": "wrong-secret-value"}, actor="t")
        s.commit()
    run = admin.post(f"/api/directory/sources/{src['id']}/test").json()
    assert run["status"] == "failed" and run["checks"][0]["id"] == "token"
    assert "AADSTS7000215" in run["checks"][0]["detail"] and "wrong-secret-value" not in json.dumps(run)
    # Test runs never change the source's sync status.
    assert admin.get(f"/api/directory/sources/{src['id']}").json()["last_sync_status"] is None


# ----------------------------------------------------------------------------- sync
def populate(fake: FakeGraph) -> None:
    fake.users = [guser(1, "alice@contoso.com"), guser(2, "bob@contoso.com", enabled=False),
                  guser(3, "carol@contoso.com", days=200), guser(4, "dave@contoso.com"),
                  guser(5, "erin@contoso.com", days=None)]
    fake.assignments = {GA: [(gid(1), "#microsoft.graph.user"), (gid(2), "#microsoft.graph.user"),
                             (gid(77), "#microsoft.graph.servicePrincipal")],
                        SEC_ADMIN: [(GROUP, "#microsoft.graph.group")],
                        USER_ADMIN: [(gid(4), "#microsoft.graph.user")],
                        READER: [(gid(5), "#microsoft.graph.user")]}
    fake.group_members = {GROUP: [gid(3)]}
    # PIM: erin is only eligible for Global Administrator; alice is also eligible for the role she holds
    # actively, and the group is eligible for the role it holds (both deduped).
    fake.eligible = {GA: [(gid(5), "#microsoft.graph.user"), (gid(1), "#microsoft.graph.user")],
                     SEC_ADMIN: [(GROUP, "#microsoft.graph.group")]}
    fake.devices = [gdevice(11, "LAPTOP1", E1), gdevice(12, "LAPTOP-NOAGENT", E2),
                    gdevice(13, "Erin's iPhone", gid(913), trust="Workplace", os_name="iOS"),
                    gdevice(14, "OLD-PC", gid(914), days=400)]
    fake.managed = [gmanaged(21, "LAPTOP1", E1, compliance="noncompliant", serial="SER-1", upn="alice@contoso.com",
                             encrypted=False),
                    gmanaged(22, "LAPTOP-NOAGENT", E2, upn="dave@contoso.com"),
                    gmanaged(23, "Erin's iPhone", gid(913), owner="personal", os_name="iOS", upn="erin@contoso.com")]


def test_sync_pages_throttling_grouping_and_issues(admin, fake):
    connect_azure(admin)
    populate(fake)
    fake.throttle = {"/v1.0/users", "/v1.0/devices"}
    # Agent devices: LAPTOP1 (Entra joined, reports its device id; bob is signed in), DESK2 (joined to the
    # tenant, but neither an Entra device nor in Intune).
    _, laptop = add_device(admin, "LAPTOP1", "c" * 64, join_facts=entra_join(E1), users=["bob@contoso.com"],
                           collector=False)
    _, desk = add_device(admin, "DESK2", "d" * 64, join_facts=entra_join(E9), collector=False)
    src = make_entra(admin)
    run = sync(admin, src["id"])
    assert run["status"] == "succeeded" and run["error"] is None, run
    assert run["users_seen"] == 5 and run["computers_seen"] == 7 and run["batches"] > 6
    assert fake.sleeps == [1.0, 1.0] and "throttled 2x" in run["server"]
    status = run["scope_status"]
    assert {k: v["status"] for k, v in status.items()} == {"users": "ok", "sign_in": "ok", "roles": "ok",
                                                           "eligible": "ok", "devices": "ok", "intune": "ok"}
    assert status["roles"]["count"] == 5  # alice, bob (GA), carol (via group), dave, erin (eligible); not reader / app
    s = admin.get(f"/api/directory/sources/{src['id']}").json()
    assert s["last_sync_status"] == "succeeded" and s["computers_count"] == 7 and s["users_count"] == 5
    assert s["scope_status"]["intune"]["status"] == "ok" and s["next_sync_at"]
    # One row per physical machine: LAPTOP1 is an Entra device + an Intune record, matched to its agent.
    comps = {c["name"]: c for c in admin.get("/api/directory/computers?status=all").json()["items"]}
    assert set(comps) == {"LAPTOP1", "LAPTOP-NOAGENT", "Erin's iPhone", "OLD-PC"}
    lap = comps["LAPTOP1"]
    assert lap["device_kind"] == "entra" and {x["kind"] for x in lap["sources"]} == {"entra", "intune"}
    assert (lap["device_id"], lap["match_method"], lap["match_confidence"]) == (laptop, "entra_device_id", 100)
    assert not comps["Erin's iPhone"]["agent_expected"]
    # Coverage counts machines the agent belongs on, once each: LAPTOP1 (agent), LAPTOP-NOAGENT, OLD-PC.
    summary = admin.get("/api/directory/summary").json()
    cov = {k: v for k, v in summary["coverage"].items() if k != "by_class"}
    assert cov == {"directory_computers": 3, "managed": 1, "pct": 33.3}
    assert summary["source_types"] == ["entra"]
    by = issues_by_type(admin)
    assert by["not_managed"] == {"LAPTOP-NOAGENT"}  # once, although it is in Entra ID and Intune
    assert by["stale_computer"] == {"OLD-PC"}
    assert by["non_compliant"] == {"LAPTOP1"}
    assert by["not_in_intune"] == {"DESK2"}
    assert by["unknown_to_directory"] == {"DESK2"}
    assert "not_domain_joined" not in by  # no AD source: an Entra-joined device is fine
    assert by["disabled_user_signed_in"] == {"bob@contoso.com"}
    assert by["privileged_disabled"] == {"bob@contoso.com"}
    assert by["privileged_stale"] == {"carol@contoso.com", "erin@contoso.com"}
    assert by["privileged_no_agent"] == {"dave@contoso.com"}
    assert "stale_user_signed_in" not in by
    items = admin.get("/api/directory/issues", params={"limit": 1000}).json()["items"]
    nm = next(i for i in items if i["type"] == "not_managed")
    assert "Active in Entra ID, Intune" in nm["detail"] and {x["kind"] for x in nm["sources"]} == {"entra", "intune"}
    nc = next(i for i in items if i["type"] == "non_compliant")
    assert "not encrypted" in nc["detail"] and nc["device_id"] == laptop
    pna = next(i for i in items if i["type"] == "privileged_no_agent")
    assert "User Administrator" in pna["detail"] and "LAPTOP-NOAGENT" in pna["detail"] and pna["privileged"]
    assert next(i for i in items if i["type"] == "not_in_intune")["device_id"] == desk
    # Privileged users (filter + roles); the reader role is not privileged.
    priv = admin.get("/api/directory/users?privileged=true").json()
    roles = {u["user_principal_name"]: u["privileged_roles"] for u in priv["items"]}
    assert roles == {"alice@contoso.com": ["Global Administrator"], "bob@contoso.com": ["Global Administrator"],
                     "carol@contoso.com": ["Security Administrator (via group)"],
                     "dave@contoso.com": ["User Administrator"],
                     "erin@contoso.com": ["Eligible: Global Administrator (PIM)"]}
    assert all(u["source_type"] == "entra" and u["sign_in_known"] for u in priv["items"])
    # Issue filters: by source, user kind.
    assert admin.get("/api/directory/issues", params={"source_id": src["id"], "type": "not_managed"}).json()["total"] == 1
    assert admin.get("/api/directory/issues?kind=user").json()["total"] == 5
    # "Add to IT assets" on a machine links every record of it (Entra device + Intune record).
    r = admin.post("/api/directory/computers/add-to-assets", json={"computer_ids": [comps["LAPTOP-NOAGENT"]["id"]]})
    assert r.json()["created"] == 1
    asset = r.json()["asset_ids"][0]
    sync(admin, src["id"])
    with db.get_session("default") as s:
        rows = s.scalars(select(DirectoryComputer).where(DirectoryComputer.name == "LAPTOP-NOAGENT")).all()
        assert len(rows) == 2 and {r.it_asset_id for r in rows} == {asset}
    assert admin.get(f"/api/it-assets/{asset}").json()["serial_number"] == ""
    # A role removed in Entra clears the flag on the next complete sync.
    fake.assignments[USER_ADMIN] = []
    sync(admin, src["id"])
    assert "dave@contoso.com" not in {u["user_principal_name"] for u in
                                      admin.get("/api/directory/users?privileged=true").json()["items"]}
    assert "privileged_no_agent" not in issues_by_type(admin)


def test_pim_eligible_admins(admin, fake):
    connect_azure(admin)
    populate(fake)
    src = make_entra(admin)
    run = sync(admin, src["id"])
    assert run["scope_status"]["eligible"] == {"status": "ok", "count": 2}  # users eligible directly
    users = {u["user_principal_name"]: u for u in admin.get("/api/directory/users?privileged=true").json()["items"]}
    # Eligible-only admin: privileged, marked as eligible; active + eligible for the same role: active only.
    assert users["erin@contoso.com"]["privileged_roles"] == ["Eligible: Global Administrator (PIM)"]
    assert users["alice@contoso.com"]["privileged_roles"] == ["Global Administrator"]
    assert users["carol@contoso.com"]["privileged_roles"] == ["Security Administrator (via group)"]
    stale = next(i for i in admin.get("/api/directory/issues?type=privileged_stale&limit=100").json()["items"]
                 if i["name"] == "erin@contoso.com")
    assert stale["detail"].startswith("Is eligible (PIM) for Global Administrator, but no sign-in") and stale["privileged"]
    # An eligible-only group member.
    fake.group_members[GROUP] = [gid(3), gid(4)]
    fake.eligible[SEC_ADMIN] = [(GROUP, "#microsoft.graph.group")]
    fake.assignments[SEC_ADMIN] = []
    sync(admin, src["id"])
    users = {u["user_principal_name"]: u for u in admin.get("/api/directory/users?privileged=true").json()["items"]}
    assert users["dave@contoso.com"]["privileged_roles"] == [
        "User Administrator", "Eligible: Security Administrator (PIM, via group)"]
    # Permission missing: eligibility skipped with a status, the last known eligibility is kept, nothing else fails.
    fake.roles = ALL_ROLES - {"RoleEligibilitySchedule.Read.Directory"}
    run = sync(admin, src["id"])
    assert run["status"] == "succeeded" and run["scope_status"]["roles"]["status"] == "ok"
    assert run["scope_status"]["eligible"]["status"] == "missing_permission"
    assert "RoleEligibilitySchedule.Read.Directory" in run["scope_status"]["eligible"]["detail"]
    users = {u["user_principal_name"]: u for u in admin.get("/api/directory/users?privileged=true").json()["items"]}
    assert users["erin@contoso.com"]["privileged_roles"] == ["Eligible: Global Administrator (PIM)"]
    # No Entra ID P2: skipped as unlicensed, data kept.
    fake.roles, fake.p2 = set(ALL_ROLES), False
    run = sync(admin, src["id"])
    assert run["scope_status"]["eligible"]["status"] == "unlicensed" and "P2" in run["scope_status"]["eligible"]["detail"]
    assert "erin@contoso.com" in {u["user_principal_name"] for u in
                                  admin.get("/api/directory/users?privileged=true").json()["items"]}
    # Test & save: the optional permission and the P2 probe.
    checks = {c["id"]: c for c in admin.post(f"/api/directory/sources/{src['id']}/test").json()["checks"]}
    assert checks["RoleEligibilitySchedule.Read.Directory"]["status"] == "ok"
    assert not checks["RoleEligibilitySchedule.Read.Directory"]["required"]
    assert checks["pim"]["status"] == "unlicensed" and not checks["pim"]["required"]
    fake.roles = ALL_ROLES - {"RoleEligibilitySchedule.Read.Directory"}
    run = admin.post(f"/api/directory/sources/{src['id']}/test").json()
    checks = {c["id"]: c for c in run["checks"]}
    assert checks["RoleEligibilitySchedule.Read.Directory"]["status"] == "missing" and run["status"] == "succeeded"
    # P2 back: eligibility removed in Entra is cleared on the next complete read.
    fake.roles, fake.p2, fake.eligible = set(ALL_ROLES), True, {}
    sync(admin, src["id"])
    assert "erin@contoso.com" not in {u["user_principal_name"] for u in
                                      admin.get("/api/directory/users?privileged=true").json()["items"]}


def test_missing_licence_and_permission_degrade_without_losing_data(admin, fake):
    connect_azure(admin)
    populate(fake)
    src = make_entra(admin)
    assert sync(admin, src["id"])["status"] == "succeeded"
    # The tenant loses Intune and P1, and RoleManagement.Read.Directory is revoked.
    fake.premium, fake.intune = False, False
    fake.roles = ALL_ROLES - {"RoleManagement.Read.Directory"}
    run = sync(admin, src["id"])
    assert run["status"] == "succeeded" and run["error"].startswith("partial: ")
    st = {k: v["status"] for k, v in run["scope_status"].items()}
    assert st == {"users": "ok", "sign_in": "unlicensed", "roles": "missing_permission", "devices": "ok",
                  "intune": "unlicensed"}
    assert "Entra ID P1 or P2" in run["scope_status"]["sign_in"]["detail"]
    assert "RoleManagement.Read.Directory" in run["scope_status"]["roles"]["detail"]
    with db.get_session("default") as s:
        # Intune records from the last complete listing are kept (not marked missing).
        intune = s.scalars(select(DirectoryComputer).where(DirectoryComputer.device_kind == "intune")).all()
        assert len(intune) == 3 and all(c.missing_since is None for c in intune)
        # Last sign-in is unknown now; privileged flags were kept (the roles part did not run).
        users = s.scalars(select(DirectoryUser)).all()
        assert all(u.last_logon_at is None for u in users)
        assert {u.user_principal_name for u in users if u.privileged} == {
            "alice@contoso.com", "bob@contoso.com", "carol@contoso.com", "dave@contoso.com", "erin@contoso.com"}
    by = issues_by_type(admin)
    # Unknown sign-in is never "stale"; disabled admins are still reported.
    assert "privileged_stale" not in by and "stale_user_signed_in" not in by
    assert by["privileged_disabled"] == {"bob@contoso.com"}
    users = {u["user_principal_name"]: u for u in admin.get("/api/directory/users").json()["items"]}
    assert users["alice@contoso.com"]["sign_in_known"] is False
    # A sync where every part fails is a failed run (and the data stays).
    fake.roles = set()
    run = sync(admin, src["id"])
    assert run["status"] == "failed" and "User.Read.All" in run["error"]
    assert admin.get(f"/api/directory/sources/{src['id']}").json()["computers_count"] == 7


def test_bad_credential_fails_the_run_and_notifies(admin, fake):
    connect_azure(admin)
    src = make_entra(admin)
    with db.get_session("default") as s:
        from app.connectors import org_config

        org_config.upsert(s, "azure", config_in={"tenant_id": TENANT, "client_id": CLIENT, "subscription_ids": []},
                          secrets_in={"client_secret": "nope"}, actor="t")
        s.commit()
    run = sync(admin, src["id"])
    assert run["status"] == "failed" and "AADSTS7000215" in run["error"]
    from app.notifications.models import NotificationEvent

    with db.get_session("default") as s:
        assert [e.event_type for e in s.scalars(select(NotificationEvent).where(
            NotificationEvent.source == "directory_source"))] == ["sync_failed"]
    # Disabling the connector makes the source unusable with a clear reason.
    admin.put("/api/organization/connectors/azure", json={"enabled": False, "config": {
        "tenant_id": TENANT, "client_id": CLIENT, "subscription_ids": []}, "secrets": {}})
    run = sync(admin, src["id"])
    assert run["status"] == "failed" and "disabled" in run["error"]


def test_safety_cap_truncates_and_marks_nothing_missing(admin, fake, monkeypatch):
    connect_azure(admin)
    populate(fake)
    src = make_entra(admin)
    sync(admin, src["id"])
    monkeypatch.setattr(config.settings, "directory_max_objects", 3)
    run = sync(admin, src["id"])
    assert run["status"] == "succeeded" and run["truncated"] and run["users_seen"] == 3
    assert run["scope_status"]["users"]["status"] == "truncated" and "devices" not in run["scope_status"]
    s = admin.get(f"/api/directory/sources/{src['id']}").json()
    assert s["last_sync_error"].startswith("incomplete") and s["users_count"] == 5 and s["computers_count"] == 7


def test_cross_source_machine_and_person_with_active_directory(admin, fake):
    """PC1 is an AD computer, its hybrid-joined Entra device and an Intune record:
    one machine (one issue, counted once). alice is an AD user synced to Entra ID:
    one person."""
    from tests.test_directory import SID

    collector_agent, collector = add_device(admin, "COLLECTOR1", "1" * 64, join_facts=join("COLLECTOR1", 1100))
    ad = make_source(admin, [collector])
    run_sync(admin, collector_agent, ad["id"], computers=[computer(1, "COLLECTOR1", rid=1100), computer(2, "PC1",
                                                                                                         rid=2001)],
             users=[user(1, "alice", uac=512 | 2)])
    connect_azure(admin)
    fake.users = [guser(1, "alice@corp.example.com", sid=f"{SID}-5001", sam="alice", domain="corp.example.com")]
    fake.devices = [gdevice(11, "PC1", E1, trust="ServerAd", sid=f"{SID}-2001")]
    fake.managed = [gmanaged(21, "PC1", E1, serial="SER-PC1")]
    entra = make_entra(admin)
    sync(admin, entra["id"])
    by = issues_by_type(admin)
    assert by["not_managed"] == {"PC1"}
    nm = next(i for i in admin.get("/api/directory/issues?type=not_managed").json()["items"])
    assert {x["kind"] for x in nm["sources"]} == {"ad", "entra", "intune"} and nm["detail"].startswith("Active in")
    # Coverage: COLLECTOR1 (agent) and PC1, each counted once.
    cov = {k: v for k, v in admin.get("/api/directory/summary").json()["coverage"].items() if k != "by_class"}
    assert cov == {"directory_computers": 2, "managed": 1,
                                                                     "pct": 50.0}
    comps = admin.get("/api/directory/computers?status=all").json()
    assert comps["total"] == 2
    pc1 = next(c for c in comps["items"] if c["name"] == "PC1")
    assert pc1["device_kind"] == "ad" and len(pc1["sources"]) == 3
    # The machine filtered by the Entra source is still one row.
    assert admin.get("/api/directory/computers", params={"source_id": entra["id"]}).json()["total"] == 1
    # The agent installed on PC1 reports only its SID: every record of the machine is matched.
    _, pc1_dev = add_device(admin, "PC1", "e" * 64, join_facts=join("PC1", 2001), users=["CORP\\alice"],
                            collector=False)
    sync(admin, entra["id"])
    with db.get_session("default") as s:
        rows = s.scalars(select(DirectoryComputer).where(DirectoryComputer.name == "PC1")).all()
        assert len(rows) == 3 and {r.device_id for r in rows} == {pc1_dev}
        assert len({r.machine_id for r in rows}) == 1
    by = issues_by_type(admin)
    assert "not_managed" not in by
    # alice: disabled in AD, enabled in Entra ID, same person: one "disabled user signed in".
    assert by["disabled_user_signed_in"] == {"alice"}
    assert admin.get("/api/directory/summary").json()["coverage"]["managed"] == 2
    with db.get_session("default") as s:
        rows = s.scalars(select(DirectoryComputer).where(DirectoryComputer.name == "PC1")).all()
        assert len({r.it_asset_id for r in rows}) == 1 and rows[0].it_asset_id  # the agent's IT asset


def test_scheduler_runs_cloud_sources_and_fails_stalled_runs(admin, fake, scheduler):
    connect_azure(admin)
    fake.users = [guser(1, "alice@contoso.com")]
    src = make_entra(admin, scopes=["users"])
    out = scheduler.tick()
    assert len(out["queued"]) == 1
    run = admin.get(f"/api/directory/runs/{out['queued'][0]}").json()
    assert run["status"] == "succeeded" and run["trigger"] == "scheduled" and run["device_id"] is None
    # Not due again within the interval.
    assert scheduler.tick()["queued"] == []
    # A run nobody claimed (e.g. queued before a restart) is executed on the next tick.
    with db.get_session("default") as s:
        r = DirectorySyncRun(source_id=src["id"], trigger="manual", status="queued", scopes=["users"],
                             max_objects=100, tried_device_ids=[])
        s.add(r)
        s.commit()
        queued = r.id
    scheduler.tick()
    assert admin.get(f"/api/directory/runs/{queued}").json()["status"] == "succeeded"
    # A running run that stopped making progress (its process died) is failed.
    with db.get_session("default") as s:
        old = utcnow() - timedelta(hours=1)
        r = DirectorySyncRun(source_id=src["id"], trigger="manual", status="running", scopes=["users"],
                             max_objects=100, tried_device_ids=[], queued_at=old, started_at=old, last_batch_at=old)
        s.add(r)
        s.commit()
        stalled = r.id
    assert stalled in scheduler.tick()["failed"]
    assert "no progress" in admin.get(f"/api/directory/runs/{stalled}").json()["error"]


def test_disabling_the_source_cancels_a_running_sync(admin, fake, scheduler):
    connect_azure(admin)
    populate(fake)
    src = make_entra(admin)

    def disable_mid_sync(path: str) -> None:
        if path == "/v1.0/devices":
            fake.on_request = None
            with db.get_session("default") as s:
                from app.directory import service as svc

                row = s.get(DirectorySource, src["id"])
                row.enabled = False
                svc.fail_run(s, svc.active_run(s, src["id"]), "cancelled: disabled", status="cancelled")
                s.commit()

    fake.on_request = disable_mid_sync
    run = sync(admin, src["id"])
    assert run["status"] == "cancelled"
    with db.get_session("default") as s:
        assert s.scalars(select(DirectoryComputer)).all() == []  # the devices page was not stored
        assert len(s.scalars(select(DirectoryUser)).all()) == 5


def test_secret_never_returned_logged_or_audited(admin, fake, caplog):
    caplog.set_level(logging.DEBUG)
    connect_azure(admin)
    populate(fake)
    src = make_entra(admin)
    responses = [admin.get("/api/directory/sources").text, admin.get("/api/directory/azure-connectors").text,
                 admin.post(f"/api/directory/sources/{src['id']}/test").text]
    run = sync(admin, src["id"])
    responses += [json.dumps(run), admin.get(f"/api/directory/sources/{src['id']}/runs").text]
    for text in responses:
        assert SECRET not in text
    assert SECRET not in caplog.text
    with db.get_session("default") as s:
        for a in s.scalars(select(AuditLog)):
            assert SECRET not in json.dumps(a.detail or {}, default=str)
        for r in s.scalars(select(DirectorySyncRun)):
            assert SECRET not in json.dumps([r.error, r.checks, r.scope_status, r.server])


def test_tenant_isolation(admin, fake):
    connect_azure(admin)
    populate(fake)
    src = make_entra(admin)
    sync(admin, src["id"])
    create_org("acme", ACME_ADMIN, ACME_PASSWORD)
    acme = org_client(admin.app, ACME_ADMIN, ACME_PASSWORD)
    # Another organisation has no Azure connector (and never the environment's).
    assert acme.get("/api/directory/azure-connectors").json()["connectors"] == []
    for cid in ("org", "env"):
        r = acme.post("/api/directory/sources", json={"type": "entra", "name": "x", "config": {"connector_id": cid}})
        assert r.status_code == 422
    assert acme.get("/api/directory/computers").json()["total"] == 0
    assert acme.get("/api/directory/users?privileged=true").json()["total"] == 0
    assert acme.get("/api/directory/issues").json()["total"] == 0
    for method, path in (("get", f"/api/directory/sources/{src['id']}"), ("post", f"/api/directory/sources/{src['id']}/sync"),
                         ("post", f"/api/directory/sources/{src['id']}/test")):
        assert getattr(acme, method)(path).status_code == 404
    # Its own connector in the same Microsoft tenant is its own source (no cross-organisation dedupe).
    connect_azure(acme)
    assert acme.post("/api/directory/sources", json={"type": "entra", "name": "x",
                                                     "config": {"connector_id": "org"}}).status_code == 201


def test_graph_client_refuses_foreign_paging_links_and_gives_up_on_endless_throttling(fake):
    http = cloud_http.CloudHttp()
    with pytest.raises(cloud_http.CloudApiError):
        http.request("GET", "https://evil.example.com/v1.0/users")
    with pytest.raises(cloud_http.CloudApiError):
        http.request("GET", "http://graph.microsoft.com/v1.0/users")

    def endless(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1.0/users":
            return httpx.Response(200, json={"value": [], "@odata.nextLink": "https://evil.example.com/next"})
        return httpx.Response(429, json={})

    cloud_http.set_transport(httpx.MockTransport(endless))
    http = cloud_http.CloudHttp()
    with pytest.raises(cloud_http.CloudApiError):
        list(http.pages("https://graph.microsoft.com/v1.0/users", "t"))
    with pytest.raises(cloud_http.CloudApiError) as e:
        http.get_json("https://graph.microsoft.com/v1.0/devices", "t")
    assert e.value.status == 429 and len(fake.sleeps) == cloud_http.MAX_ATTEMPTS - 1
