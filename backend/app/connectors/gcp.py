"""Real GCP posture connector (opt-in, READ-ONLY).

Talks to the Google Cloud REST APIs (Resource Manager, Compute, Cloud Storage,
GKE, Cloud SQL Admin, IAM, Cloud KMS, Cloud Functions, Cloud Run) with an
authorized `requests` session from **google-auth** (no google-api-python-client
discovery documents or per-service client libraries: a much smaller image) and
normalizes the resources into `AssetRecord`s (`source="gcp"`).

Safety: every request goes through `ReadOnlyGcpClient`, which only allows the
read methods `get*` / `list*` / `aggregatedList` / `search*` on
`*.googleapis.com`, sent as HTTP GET (POST only for `getIamPolicy` / `search`,
which the APIs define as POST but which change nothing), blocks object/secret
reads (Cloud Storage objects, Secret Manager, token / signing methods) and
raises `ReadOnlyViolation` on anything else. The service account should
additionally only hold **roles/viewer** and **roles/iam.securityReviewer**
(docs/CONNECT_GCP.md).

429 / 5xx responses are retried with exponential backoff; list calls follow
`nextPageToken`; a failing project or API is recorded in
`CollectionResult.errors` and the rest of the scan continues. APIs that are not
enabled in a project are skipped (no resources of that kind can exist).
"""
from __future__ import annotations

import logging
import os
import re
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlsplit

from ..config import Settings
from .base import AssetRecord, CollectionResult, Connector, RelationshipRecord, sensitive_from_tags

log = logging.getLogger(__name__)

READ_METHOD_PREFIXES = ("get", "list", "aggregatedList", "search")
# Read-looking methods that return customer data or secrets / mint credentials.
BLOCKED_METHOD_MARKERS = ("objects.", "secretmanager.", "secret", "token", "signblob", "signjwt", "decrypt",
                          "generate", "accesssecret", "getserialportoutput", "getscreenshot")
POST_READ_METHODS = ("getIamPolicy", "search", "searchAll")
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
MAX_PAGES = 1000

PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}
SA_IMPERSONATION_ROLES = {"roles/iam.serviceAccountUser", "roles/iam.serviceAccountTokenCreator"}
STORAGE_DATA_ROLES = {"roles/owner", "roles/editor", "roles/storage.admin", "roles/storage.objectAdmin",
                      "roles/storage.objectViewer", "roles/storage.legacyBucketOwner", "roles/storage.legacyBucketReader"}
SQL_DATA_ROLES = {"roles/owner", "roles/editor", "roles/cloudsql.admin", "roles/cloudsql.editor", "roles/cloudsql.client"}
INVOKER_ROLES = {"roles/run.invoker", "roles/cloudfunctions.invoker"}
FULL_API_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
INTERNET = {"0.0.0.0/0", "::/0"}


class ReadOnlyViolation(PermissionError):
    pass


class GcpApiError(Exception):
    def __init__(self, status: int, method_id: str, message: str, reason: str = ""):
        super().__init__(f"{method_id}: HTTP {status} {reason} {message}".strip())
        self.status = status
        self.reason = reason
        self.method_id = method_id

    @property
    def service_disabled(self) -> bool:
        text = f"{self.reason} {self.args[0]}".lower()
        return self.status == 403 and ("service_disabled" in text or "accessnotconfigured" in text
                                       or "has not been used in project" in text or "is disabled" in text)


def is_admin_role(role: str) -> bool:
    """CIS GCP 1.5: Owner / Editor or any *Admin / *admin role."""
    name = role.rsplit("/", 1)[-1]
    return role in PRIMITIVE_ROLES or name.lower().endswith("admin")


def check_method(method_id: str, http_method: str, url: str) -> None:
    """Raise `ReadOnlyViolation` unless this is a permitted read request."""
    host = urlsplit(url).hostname or ""
    if urlsplit(url).scheme != "https" or not host.endswith(".googleapis.com"):
        raise ReadOnlyViolation(f"Blocked GCP request to non-Google API host: {host or url}")
    last = method_id.rsplit(".", 1)[-1]
    if not last.startswith(READ_METHOD_PREFIXES):
        raise ReadOnlyViolation(f"Blocked non read-only GCP call: {method_id}")
    low = method_id.lower()
    if any(m in low for m in BLOCKED_METHOD_MARKERS):
        raise ReadOnlyViolation(f"Blocked data/secret-returning GCP call: {method_id}")
    verb = http_method.upper()
    if verb == "POST" and last in POST_READ_METHODS:
        return
    if verb != "GET":
        raise ReadOnlyViolation(f"Blocked GCP {verb} request: {method_id}")


class ReadOnlyGcpClient:
    """The only way the connector talks to Google: guarded, retried, paginated reads."""

    def __init__(self, session: Any, sleep: Callable[[float], None] = time.sleep, timeout: float = 60,
                 max_attempts: int = 6):
        self._session = session
        self._sleep = sleep
        self._timeout = timeout
        self._max_attempts = max_attempts

    def call(self, method_id: str, url: str, params: dict | None = None, http_method: str = "GET",
             body: dict | None = None) -> dict:
        check_method(method_id, http_method, url)
        delay = 1.0
        for attempt in range(1, self._max_attempts + 1):
            resp = self._session.request(http_method.upper(), url, params=params, json=body, timeout=self._timeout)
            status = int(getattr(resp, "status_code", 0))
            if status in (429, 500, 502, 503, 504) and attempt < self._max_attempts:
                retry_after = (getattr(resp, "headers", None) or {}).get("Retry-After")
                wait = float(retry_after) if retry_after and str(retry_after).isdigit() else delay
                log.debug("GCP %s throttled/failed (HTTP %s), retrying in %.0fs", method_id, status, wait)
                self._sleep(min(wait, 60.0))
                delay = min(delay * 2, 32.0)
                continue
            if status >= 400:
                reason, message = "", getattr(resp, "text", "")[:300]
                try:
                    err = (resp.json() or {}).get("error", {})
                    message = str(err.get("message", message))[:300]
                    reason = str(err.get("status") or "")
                    for d in err.get("details", []) or []:
                        reason = str(d.get("reason") or reason)
                    for e in err.get("errors", []) or []:
                        reason = str(e.get("reason") or reason)
                except (ValueError, AttributeError):
                    pass
                raise GcpApiError(status, method_id, message, reason)
            if status == 204 or not getattr(resp, "content", b"x"):
                return {}
            return resp.json() or {}
        raise GcpApiError(429, method_id, "retries exhausted")  # pragma: no cover - loop always returns/raises

    def paginate(self, method_id: str, url: str, items_key: str, params: dict | None = None) -> Iterator[dict]:
        params = dict(params or {})
        for _ in range(MAX_PAGES):
            page = self.call(method_id, url, params=params)
            yield from page.get(items_key, []) or []
            token = page.get("nextPageToken")
            if not token:
                return
            params["pageToken"] = token

    def aggregated(self, method_id: str, url: str, items_key: str) -> Iterator[tuple[str, dict]]:
        """compute aggregatedList: yields (scope e.g. 'zones/europe-west1-b', item)."""
        params: dict[str, Any] = {"returnPartialSuccess": "true"}
        for _ in range(MAX_PAGES):
            page = self.call(method_id, url, params=params)
            for scope, block in (page.get("items") or {}).items():
                for item in (block or {}).get(items_key, []) or []:
                    yield scope, item
            token = page.get("nextPageToken")
            if not token:
                return
            params["pageToken"] = token


AUTH_MODES = ("credentials_json", "credentials_file", "default")


def resolve_auth_mode(settings: Settings) -> str | None:
    if settings.gcp_credentials_json:
        return "credentials_json"
    if settings.gcp_credentials_file:
        return "credentials_file"
    if settings.gcp_use_default_credentials:
        return "default"
    return None


def credentials_file_problem(settings: Settings) -> str | None:
    path = settings.gcp_credentials_file
    if not path:
        return None
    if not os.path.isfile(path):
        return f"GCP_CREDENTIALS_FILE {path} does not exist (cnapp-ctl gcp-key install)"
    if not os.access(path, os.R_OK):
        return f"GCP_CREDENTIALS_FILE {path} is not readable by the backend user"
    return None


def build_session(settings: Settings) -> Any:
    """Authorized requests session (service account key, WIF config or ADC)."""
    import google.auth
    from google.auth.transport.requests import AuthorizedSession

    mode = resolve_auth_mode(settings)
    if mode == "credentials_json":
        import json

        creds, _ = google.auth.load_credentials_from_dict(json.loads(settings.gcp_credentials_json), scopes=SCOPES)
    elif mode == "credentials_file":
        problem = credentials_file_problem(settings)
        if problem:
            raise RuntimeError(problem)
        creds, _ = google.auth.load_credentials_from_file(settings.gcp_credentials_file, scopes=SCOPES)
    elif mode == "default":
        creds, _ = google.auth.default(scopes=SCOPES)
    else:
        raise RuntimeError("GCP connector is not configured: set GCP_CREDENTIALS_FILE (or "
                           "GCP_USE_DEFAULT_CREDENTIALS=true) and GCP_PROJECT_IDS or GCP_ORGANIZATION_ID")
    return AuthorizedSession(creds)


# ----------------------------------------------------------------------------- helpers
CRM = "https://cloudresourcemanager.googleapis.com/v3"
COMPUTE = "https://compute.googleapis.com/compute/v1"
STORAGE = "https://storage.googleapis.com/storage/v1"
CONTAINER = "https://container.googleapis.com/v1"
SQLADMIN = "https://sqladmin.googleapis.com/v1"
IAM = "https://iam.googleapis.com/v1"
KMS = "https://cloudkms.googleapis.com/v1"
FUNCTIONS = "https://cloudfunctions.googleapis.com/v2"
RUN = "https://run.googleapis.com/v2"


def _last(url: str | None) -> str:
    return (url or "").rstrip("/").rsplit("/", 1)[-1]


def _region_of_zone(zone: str) -> str:
    return zone.rsplit("-", 1)[0] if re.match(r"^[a-z]+-[a-z]+\d+-[a-z]$", zone) else zone


def _seconds(v: str | None) -> int | None:
    if not v:
        return None
    try:
        return int(float(str(v).rstrip("s")))
    except ValueError:
        return None


def _age_days(ts: str | None, now: datetime) -> int | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, (now - (dt if dt.tzinfo else dt.replace(tzinfo=UTC))).days)


def firewall_rules(fw: dict) -> list[dict]:
    """VPC firewall rule -> the normalized rule shape `posture.open_to_internet` understands."""
    if str(fw.get("direction", "INGRESS")).upper() != "INGRESS":
        return []
    access = "Allow" if fw.get("allowed") and not fw.get("disabled") else "Deny"
    entries = fw.get("allowed") or fw.get("denied") or []
    sources = list(fw.get("sourceRanges") or [])
    out = []
    for i, e in enumerate(entries):
        proto = str(e.get("IPProtocol", "all")).lower()
        if proto in {"all"}:
            ports = ["*"]
        elif proto in {"tcp", "udp", "sctp", "6", "17"}:
            ports = list(e.get("ports") or ["*"])
        else:
            ports = ["none"]
        out.append({"name": f"{fw.get('name')}#{i} {proto}/{','.join(ports)}", "direction": "Inbound",
                    "access": access, "protocol": proto, "source_prefixes": sources, "port_ranges": ports,
                    "priority": fw.get("priority")})
    return out


def _internet_rules(rules: list[dict]) -> list[str]:
    return [r["name"] for r in rules if r["access"] == "Allow" and r["port_ranges"] != ["none"]
            and any(s in INTERNET for s in r["source_prefixes"])]


def _public_members(policy: dict, roles: set[str] | None = None) -> list[str]:
    return sorted({f"{b.get('role')}:{m}" for b in policy.get("bindings", []) or []
                   for m in b.get("members", []) or []
                   if m in PUBLIC_MEMBERS and (roles is None or b.get("role") in roles)})


class GcpConnector(Connector):
    name = "gcp"
    provider = "gcp"
    description = "Read-only GCP posture scan via Google Cloud REST APIs (Viewer + Security Reviewer)."
    setup_hint = ("set GCP_PROJECT_IDS or GCP_ORGANIZATION_ID and install the service account key with "
                  "`cnapp-ctl gcp-key install KEY.json` (sets GCP_CREDENTIALS_FILE), or "
                  "GCP_USE_DEFAULT_CREDENTIALS=true; see docs/CONNECT_GCP.md")

    def __init__(self, settings: Settings, session_factory: Callable[[], Any] | None = None,
                 sleep: Callable[[float], None] = time.sleep, now: Callable[[], datetime] | None = None):
        self.settings = settings
        self._session_factory = session_factory
        self._sleep = sleep
        self._now = now or (lambda: datetime.now(UTC))

    def is_configured(self) -> bool:
        s = self.settings
        if not (s.gcp_project_ids or s.gcp_organization_id):
            return False
        if self._session_factory is not None:
            return True
        mode = resolve_auth_mode(s)
        return mode in ("default", "credentials_json") or (
            mode == "credentials_file" and credentials_file_problem(s) is None)

    def scope(self) -> list[str]:
        s = self.settings
        return list(s.gcp_project_ids) + ([f"organizations/{s.gcp_organization_id}"] if s.gcp_organization_id else [])

    def info(self) -> dict:
        return {**super().info(), "auth_mode": resolve_auth_mode(self.settings),
                "problem": credentials_file_problem(self.settings)}

    # ------------------------------------------------------------------ main entry
    def collect(self) -> CollectionResult:
        res = CollectionResult()
        try:
            session = self._session_factory() if self._session_factory else build_session(self.settings)
        except Exception as exc:
            res.errors.append(f"credentials: {type(exc).__name__}: {exc}")
            return res
        client = ReadOnlyGcpClient(session, sleep=self._sleep)
        for project in self._projects(client, res):
            pid = project.get("projectId", "?")
            try:
                self._collect_project(client, project, res)
            except ReadOnlyViolation:
                raise
            except Exception as exc:  # keep scanning other projects
                log.warning("GCP scan failed for project %s: %s", pid, exc)
                res.errors.append(f"{pid}: {type(exc).__name__}: {exc}")
        return res

    def _projects(self, client: ReadOnlyGcpClient, res: CollectionResult) -> list[dict]:
        found: dict[str, dict] = {}
        for pid in self.settings.gcp_project_ids:
            try:
                found[pid] = client.call("cloudresourcemanager.projects.get", f"{CRM}/projects/{quote(pid)}")
            except ReadOnlyViolation:
                raise
            except Exception as exc:
                res.errors.append(f"{pid}/project: {type(exc).__name__}: {exc}")
                found[pid] = {"projectId": pid}
        org = self.settings.gcp_organization_id
        if org:
            try:
                queue, seen = [f"organizations/{org}"], set()
                while queue and len(seen) < 10000:
                    parent = queue.pop(0)
                    if parent in seen:
                        continue
                    seen.add(parent)
                    for p in client.paginate("cloudresourcemanager.projects.list", f"{CRM}/projects", "projects",
                                             {"parent": parent}):
                        if p.get("state", "ACTIVE") == "ACTIVE" and p.get("projectId"):
                            found.setdefault(p["projectId"], p)
                    for f in client.paginate("cloudresourcemanager.folders.list", f"{CRM}/folders", "folders",
                                             {"parent": parent}):
                        if f.get("state", "ACTIVE") == "ACTIVE" and f.get("name"):
                            queue.append(f["name"])
            except ReadOnlyViolation:
                raise
            except Exception as exc:
                res.errors.append(f"organizations/{org}: project discovery: {type(exc).__name__}: {exc}")
        return list(found.values())

    def _collect_project(self, cl: ReadOnlyGcpClient, project: dict, res: CollectionResult) -> None:  # noqa: C901
        pid = project["projectId"]
        number = _last(project.get("name")) if str(project.get("name", "")).startswith("projects/") else None
        now = self._now()
        base = dict(provider="gcp", subscription_id=pid, subscription_name=project.get("displayName") or pid)
        assets: dict[str, AssetRecord] = {}
        rels: list[RelationshipRecord] = []
        disabled_apis: list[str] = []

        def add(a: AssetRecord) -> AssetRecord:
            assets[a.id] = a
            return a

        proj = add(AssetRecord(id=f"//cloudresourcemanager.googleapis.com/projects/{pid}", name=pid,
                               type="gcp_project", region="global", tags=dict(project.get("labels") or {}), **base,
                               properties={"project_number": number, "parent": project.get("parent"),
                                           "display_name": project.get("displayName")}))

        def step(label: str, fn: Callable[[], None]) -> None:
            try:
                fn()
            except ReadOnlyViolation:
                raise
            except GcpApiError as exc:
                if exc.service_disabled:
                    disabled_apis.append(label)
                    log.debug("GCP %s/%s: API not enabled", pid, label)
                    return
                log.warning("GCP %s/%s failed: %s", pid, label, exc)
                res.errors.append(f"{pid}/{label}: {exc}")
            except Exception as exc:
                log.warning("GCP %s/%s failed: %s", pid, label, exc)
                res.errors.append(f"{pid}/{label}: {type(exc).__name__}: {exc}")

        # ----------------------------------------------------------- project IAM policy
        sa_project_roles: dict[str, set[str]] = {}

        def iam_policy():
            pol = cl.call("cloudresourcemanager.projects.getIamPolicy", f"{CRM}/projects/{quote(pid)}:getIamPolicy",
                          http_method="POST", body={"options": {"requestedPolicyVersion": 3}})
            owners, editors, sa_users = [], [], []
            for b in pol.get("bindings", []) or []:
                role = b.get("role", "")
                for m in b.get("members", []) or []:
                    if role == "roles/owner":
                        owners.append(m)
                    elif role == "roles/editor":
                        editors.append(m)
                    if role in SA_IMPERSONATION_ROLES and m.startswith(("user:", "group:", "domain:")):
                        sa_users.append(f"{role}:{m}")
                    if m.startswith("serviceAccount:"):
                        sa_project_roles.setdefault(m.split(":", 1)[1].lower(), set()).add(role)
            proj.properties.update({
                "owners": sorted(owners), "editors": sorted(editors),
                "primitive_role_members": sorted({m for m in owners + editors if not m.startswith("serviceAccount:")}),
                "public_bindings": _public_members(pol), "sa_impersonation_bindings": sorted(sa_users)})

        step("iam policy", iam_policy)

        # ----------------------------------------------------------- service accounts + keys
        sa_by_email: dict[str, AssetRecord] = {}

        def service_accounts():
            for sa in cl.paginate("iam.projects.serviceAccounts.list", f"{IAM}/projects/{quote(pid)}/serviceAccounts",
                                  "accounts"):
                email = str(sa.get("email", "")).lower()
                keys = []
                try:
                    for k in cl.call("iam.projects.serviceAccounts.keys.list",
                                     f"{IAM}/projects/{quote(pid)}/serviceAccounts/{quote(email, safe='@')}/keys",
                                     params={"keyTypes": "USER_MANAGED"}).get("keys", []) or []:
                        if k.get("disabled"):
                            continue
                        keys.append({"id": _last(k.get("name"))[-8:], "age_days": _age_days(k.get("validAfterTime"), now),
                                     "expires": k.get("validBeforeTime")})
                except ReadOnlyViolation:
                    raise
                except Exception as exc:
                    res.errors.append(f"{pid}/service account keys {email}: {type(exc).__name__}: {exc}")
                roles = sorted(sa_project_roles.get(email, set()))
                admin = [r for r in roles if is_admin_role(r)]
                sa_by_email[email] = add(AssetRecord(
                    id=f"//iam.googleapis.com/projects/{pid}/serviceAccounts/{email}", name=email,
                    type="gcp_service_account", region="global", **base,
                    properties={"email": email, "display_name": sa.get("displayName"), "disabled": bool(sa.get("disabled")),
                                "principal_type": "ServiceAccount",
                                "default_compute": email.endswith("-compute@developer.gserviceaccount.com"),
                                "user_managed_keys": keys, "roles": roles, "admin_roles": admin, "admin": bool(admin),
                                "scope": "project" if admin else "resource"}))

        step("service accounts", service_accounts)

        def sa_asset(email: str | None) -> AssetRecord | None:
            if not email:
                return None
            email = email.lower()
            if email == "default" and number:
                email = f"{number}-compute@developer.gserviceaccount.com"
            return sa_by_email.get(email)

        # ----------------------------------------------------------- compute: firewalls + instances
        def compute():
            fws = []
            for fw in cl.paginate("compute.firewalls.list", f"{COMPUTE}/projects/{quote(pid)}/global/firewalls", "items"):
                rules = firewall_rules(fw)
                fws.append((fw, rules, add(AssetRecord(
                    id=f"//compute.googleapis.com/projects/{pid}/global/firewalls/{fw.get('name')}",
                    name=str(fw.get("name")), type="gcp_firewall_rule", region="global",
                    resource_group=_last(fw.get("network")), **base,
                    properties={"network": _last(fw.get("network")), "direction": fw.get("direction", "INGRESS"),
                                "disabled": bool(fw.get("disabled")), "priority": fw.get("priority"),
                                "target_tags": list(fw.get("targetTags") or []),
                                "target_service_accounts": list(fw.get("targetServiceAccounts") or []),
                                "security_rules": rules, "internet_ingress": _internet_rules(rules)}))))
            for scope, inst in cl.aggregated("compute.instances.aggregatedList",
                                             f"{COMPUTE}/projects/{quote(pid)}/aggregated/instances", "instances"):
                zone = _last(inst.get("zone")) or scope.split("/")[-1]
                tags = set((inst.get("tags") or {}).get("items") or [])
                sas = inst.get("serviceAccounts") or []
                sa_email = str(sas[0].get("email", "")).lower() if sas else None
                scopes = list(sas[0].get("scopes") or []) if sas else []
                nets, ext_ips = set(), []
                for nic in inst.get("networkInterfaces", []) or []:
                    nets.add(_last(nic.get("network")))
                    ext_ips += [ac["natIP"] for ac in nic.get("accessConfigs", []) or [] if ac.get("natIP")]
                applied, rules = [], []
                for fw, fw_rules, fw_asset in fws:
                    if _last(fw.get("network")) not in nets or fw.get("disabled"):
                        continue
                    tt, tsa = set(fw.get("targetTags") or []), {s.lower() for s in fw.get("targetServiceAccounts") or []}
                    if (tt and not tt & tags) or (tsa and sa_email not in tsa):
                        continue
                    applied.append(fw_asset)
                    rules += fw_rules
                open_rules = _internet_rules(rules)
                exposed = bool(ext_ips) and bool(open_rules) and inst.get("status", "RUNNING") != "TERMINATED"
                labels = dict(inst.get("labels") or {})
                sens, cls = sensitive_from_tags(labels)
                meta = {i.get("key"): i.get("value") for i in (inst.get("metadata") or {}).get("items", []) or []}
                aid = f"//compute.googleapis.com/projects/{pid}/zones/{zone}/instances/{inst.get('name')}"
                add(AssetRecord(
                    id=aid, name=str(inst.get("name")), type="gce_instance", region=_region_of_zone(zone),
                    resource_group=",".join(sorted(nets)) or None, tags=labels, internet_exposed=exposed,
                    sensitive_data=sens, **base,
                    properties={"zone": zone, "status": inst.get("status"), "machine_type": _last(inst.get("machineType")),
                                "external_ips": ext_ips, "public_ips": ext_ips, "network_tags": sorted(tags),
                                "service_account": sa_email, "scopes": scopes, "full_api_access": FULL_API_SCOPE in scopes,
                                "default_service_account": bool(sa_email and sa_email.endswith(
                                    "-compute@developer.gserviceaccount.com")),
                                "block_project_ssh_keys": str(meta.get("block-project-ssh-keys", "")).lower() == "true",
                                "security_rules": rules, "internet_ingress": open_rules, "data_classification": cls,
                                "exposure": (f"external IP {', '.join(ext_ips)}, open via {', '.join(open_rules[:3])}"
                                             if exposed else None)}))
                for fa in applied:
                    rels.append(RelationshipRecord(fa.id, aid, "protects"))
                sa = sa_asset(sa_email)
                if sa is not None:
                    rels.append(RelationshipRecord(aid, sa.id, "uses_identity", {"scopes": scopes}))

        step("compute", compute)

        # ----------------------------------------------------------- Cloud Storage
        buckets: list[AssetRecord] = []

        def storage():
            for b in cl.paginate("storage.buckets.list", f"{STORAGE}/b", "items", {"project": pid}):
                name = b["name"]
                pol = {}
                try:
                    pol = cl.call("storage.buckets.getIamPolicy", f"{STORAGE}/b/{quote(name, safe='')}/iam")
                except ReadOnlyViolation:
                    raise
                except Exception as exc:
                    res.errors.append(f"{pid}/bucket iam {name}: {type(exc).__name__}: {exc}")
                iamc = b.get("iamConfiguration") or {}
                pap = iamc.get("publicAccessPrevention", "inherited")
                public_members = [] if pap == "enforced" else _public_members(pol)
                labels = dict(b.get("labels") or {})
                sens, cls = sensitive_from_tags(labels)
                aid = f"//storage.googleapis.com/projects/_/buckets/{name}"
                buckets.append(add(AssetRecord(
                    id=aid, name=name, type="gcs_bucket", region=str(b.get("location", "")).lower() or None,
                    tags=labels, internet_exposed=bool(public_members), sensitive_data=sens, **base,
                    properties={"public_members": public_members, "is_public": bool(public_members),
                                "public_access_prevention": pap,
                                "uniform_access": bool((iamc.get("uniformBucketLevelAccess") or {}).get("enabled")),
                                "retention_seconds": _seconds((b.get("retentionPolicy") or {}).get("retentionPeriod")),
                                "retention_locked": bool((b.get("retentionPolicy") or {}).get("isLocked")),
                                "versioning": bool((b.get("versioning") or {}).get("enabled")),
                                "cmek": bool((b.get("encryption") or {}).get("defaultKmsKeyName")),
                                "data_classification": cls,
                                "exposure": f"IAM grants {', '.join(public_members)}" if public_members else None})))
                for bnd in pol.get("bindings", []) or []:
                    for m in bnd.get("members", []) or []:
                        if m.startswith("serviceAccount:"):
                            sa = sa_asset(m.split(":", 1)[1])
                            if sa is not None:
                                rels.append(RelationshipRecord(sa.id, aid, "has_access", {"role": bnd.get("role")}))

        step("storage", storage)

        # ----------------------------------------------------------- GKE
        def gke():
            data = cl.call("container.projects.locations.clusters.list",
                           f"{CONTAINER}/projects/{quote(pid)}/locations/-/clusters")
            for c in data.get("clusters", []) or []:
                pcc = c.get("privateClusterConfig") or {}
                man = c.get("masterAuthorizedNetworksConfig") or {}
                cidrs = [x.get("cidrBlock") for x in man.get("cidrBlocks", []) or []]
                private_endpoint = bool(pcc.get("enablePrivateEndpoint"))
                restricted = bool(man.get("enabled")) and not any(x in INTERNET for x in cidrs)
                exposed = not private_endpoint and not restricted
                loc = c.get("location") or c.get("zone")
                aid = f"//container.googleapis.com/projects/{pid}/locations/{loc}/clusters/{c.get('name')}"
                add(AssetRecord(
                    id=aid, name=str(c.get("name")), type="gke_cluster", region=_region_of_zone(str(loc)),
                    resource_group=_last(c.get("network")) or None, tags=dict(c.get("resourceLabels") or {}),
                    internet_exposed=exposed, **base,
                    properties={"kubernetes_version": c.get("currentMasterVersion"),
                                "legacy_abac": bool((c.get("legacyAbac") or {}).get("enabled")),
                                "private_nodes": bool(pcc.get("enablePrivateNodes")),
                                "private_endpoint": private_endpoint,
                                "master_authorized_networks": bool(man.get("enabled")),
                                "authorized_cidrs": cidrs,
                                "workload_identity": bool((c.get("workloadIdentityConfig") or {}).get("workloadPool")),
                                "node_service_account": (c.get("nodeConfig") or {}).get("serviceAccount"),
                                "exposure": "public control plane without authorized networks" if exposed else None}))
                sa = sa_asset((c.get("nodeConfig") or {}).get("serviceAccount"))
                if sa is not None:
                    rels.append(RelationshipRecord(aid, sa.id, "uses_identity"))

        step("gke", gke)

        # ----------------------------------------------------------- Cloud SQL
        sql_assets: list[AssetRecord] = []

        def cloudsql():
            for i in cl.paginate("sql.instances.list", f"{SQLADMIN}/projects/{quote(pid)}/instances", "items"):
                st = i.get("settings") or {}
                ipc = st.get("ipConfiguration") or {}
                nets = [n.get("value") for n in ipc.get("authorizedNetworks", []) or []]
                public = bool(ipc.get("ipv4Enabled"))
                ssl_mode = ipc.get("sslMode")
                ssl_required = bool(ipc.get("requireSsl")) or ssl_mode in {"ENCRYPTED_ONLY",
                                                                            "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}
                open_all = [n for n in nets if n in INTERNET]
                labels = dict(st.get("userLabels") or {})
                _, cls = sensitive_from_tags(labels)
                sql_assets.append(add(AssetRecord(
                    id=f"//cloudsql.googleapis.com/projects/{pid}/instances/{i.get('name')}", name=str(i.get("name")),
                    type="cloud_sql_instance", region=i.get("region"), tags=labels,
                    internet_exposed=public and bool(open_all), sensitive_data=True, **base,
                    properties={"database_version": i.get("databaseVersion"), "public_ip": public,
                                "authorized_networks": nets, "open_to_all": bool(open_all),
                                "ssl_required": ssl_required, "ssl_mode": ssl_mode,
                                "backups_enabled": bool((st.get("backupConfiguration") or {}).get("enabled")),
                                "data_classification": cls or "database",
                                "exposure": "public IP with authorized network 0.0.0.0/0" if public and open_all else None})))

        step("cloud sql", cloudsql)

        # ----------------------------------------------------------- Cloud KMS
        def kms():
            for loc in cl.paginate("cloudkms.projects.locations.list", f"{KMS}/projects/{quote(pid)}/locations",
                                   "locations"):
                loc_id = loc.get("locationId")
                for ring in cl.paginate("cloudkms.projects.locations.keyRings.list",
                                        f"{KMS}/projects/{quote(pid)}/locations/{loc_id}/keyRings", "keyRings"):
                    for k in cl.paginate("cloudkms.projects.locations.keyRings.cryptoKeys.list",
                                         f"{KMS}/{ring['name']}/cryptoKeys", "cryptoKeys"):
                        period = _seconds(k.get("rotationPeriod"))
                        add(AssetRecord(
                            id=f"//cloudkms.googleapis.com/{k['name']}", name=_last(k["name"]), type="gcp_kms_key",
                            region=loc_id, resource_group=_last(ring["name"]), tags=dict(k.get("labels") or {}), **base,
                            properties={"purpose": k.get("purpose"), "rotation_period_days": period // 86400 if period else None,
                                        "next_rotation_time": k.get("nextRotationTime"),
                                        "primary_state": (k.get("primary") or {}).get("state")}))

        step("kms", kms)

        # ----------------------------------------------------------- Cloud Run + Cloud Functions
        run_public: dict[str, bool] = {}

        def run():
            for s in cl.paginate("run.projects.locations.services.list",
                                 f"{RUN}/projects/{quote(pid)}/locations/-/services", "services"):
                pol = cl.call("run.projects.locations.services.getIamPolicy", f"{RUN}/{s['name']}:getIamPolicy")
                public_members = _public_members(pol, INVOKER_ROLES)
                ingress = s.get("ingress", "INGRESS_TRAFFIC_ALL")
                public = bool(public_members) and ingress == "INGRESS_TRAFFIC_ALL"
                run_public[s["name"]] = public
                aid = f"//run.googleapis.com/{s['name']}"
                add(AssetRecord(
                    id=aid, name=_last(s["name"]), type="cloud_run_service", region=s["name"].split("/")[3],
                    tags=dict(s.get("labels") or {}), internet_exposed=public, **base,
                    properties={"uri": s.get("uri"), "ingress": ingress, "public_invoker": public_members,
                                "allows_unauthenticated": bool(public_members),
                                "service_account": (s.get("template") or {}).get("serviceAccount"),
                                "exposure": f"{s.get('uri')} invokable by allUsers" if public else None}))
                sa = sa_asset((s.get("template") or {}).get("serviceAccount")
                              or (f"{number}-compute@developer.gserviceaccount.com" if number else None))
                if sa is not None:
                    rels.append(RelationshipRecord(aid, sa.id, "uses_identity"))

        step("cloud run", run)

        def functions():
            for f in cl.paginate("cloudfunctions.projects.locations.functions.list",
                                 f"{FUNCTIONS}/projects/{quote(pid)}/locations/-/functions", "functions"):
                pol = cl.call("cloudfunctions.projects.locations.functions.getIamPolicy",
                              f"{FUNCTIONS}/{f['name']}:getIamPolicy")
                sc = f.get("serviceConfig") or {}
                public_members = _public_members(pol, INVOKER_ROLES)
                backing = sc.get("service")
                ingress = sc.get("ingressSettings", "ALLOW_ALL")
                public = (bool(public_members) or bool(backing and run_public.get(backing))) and ingress == "ALLOW_ALL"
                aid = f"//cloudfunctions.googleapis.com/{f['name']}"
                add(AssetRecord(
                    id=aid, name=_last(f["name"]), type="cloud_function", region=f["name"].split("/")[3],
                    tags=dict(f.get("labels") or {}), internet_exposed=public, **base,
                    properties={"environment": f.get("environment"), "runtime": (f.get("buildConfig") or {}).get("runtime"),
                                "url": f.get("url") or sc.get("uri"), "ingress": ingress,
                                "public_invoker": public_members, "allows_unauthenticated": public,
                                "service_account": sc.get("serviceAccountEmail"),
                                "exposure": f"{f.get('url') or sc.get('uri')} invokable by allUsers" if public else None}))
                sa = sa_asset(sc.get("serviceAccountEmail"))
                if sa is not None:
                    rels.append(RelationshipRecord(aid, sa.id, "uses_identity"))

        step("cloud functions", functions)

        # ----------------------------------------------------------- service account -> data store edges
        for email, sa in sa_by_email.items():
            roles = sa_project_roles.get(email, set())
            if roles & STORAGE_DATA_ROLES:
                via = ", ".join(sorted(roles & STORAGE_DATA_ROLES))
                rels.extend(RelationshipRecord(sa.id, b.id, "has_access", {"role": via}) for b in buckets)
            if roles & SQL_DATA_ROLES:
                via = ", ".join(sorted(roles & SQL_DATA_ROLES))
                rels.extend(RelationshipRecord(sa.id, d.id, "has_access", {"role": via}) for d in sql_assets)

        proj.properties["apis_not_enabled"] = sorted(disabled_apis)
        res.assets.extend(assets.values())
        seen: set[tuple[str, str, str]] = set()
        for r in rels:
            k = (r.source_id, r.target_id, r.type)
            if r.source_id in assets and r.target_id in assets and k not in seen:
                seen.add(k)
                res.relationships.append(r)
