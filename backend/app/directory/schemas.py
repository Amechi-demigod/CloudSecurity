"""Pydantic schemas for directory discovery: the console API (sources) and the
agent batch upload (strictly validated, size-limited input from collectors)."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from ..schemas import UTCDateTime

DOMAIN_RE = r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+$"
SERVER_RE = r"^[A-Za-z0-9.:-]{1,253}$"
SID_RE = r"^S-1-[0-9-]{1,180}$"
GUID_RE = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
_CTRL = re.compile(r"[\x00-\x1f\x7f]")

Scope = Literal["computers", "users"]
# sealed: LDAP on 389 with a Kerberos (Negotiate) bind and SASL signing +
# sealing (dedicated Windows collectors only; no DC certificate needed).
Security = Literal["ldaps", "starttls", "sealed"]
AuthMode = Literal["computer_account", "service_account"]

MAX_BATCH_OBJECTS = 5000


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ----------------------------------------------------------------------------- console API
class AdConfig(_Strict):
    """Settings of an on-prem Active Directory source."""

    domain: Annotated[str, StringConstraints(min_length=3, max_length=253, to_lower=True)]
    servers: list[Annotated[str, StringConstraints(pattern=SERVER_RE)]] = Field(default_factory=list, max_length=10)
    # None: chosen by the server (sealed for the computer account / gMSA on
    # dedicated collectors, else LDAPS); port None: the transport's default.
    port: int | None = Field(None, ge=1, le=65535)
    security: Security | None = None
    base_dns: list[Annotated[str, StringConstraints(min_length=4, max_length=1024)]] = Field(
        default_factory=list, max_length=10)
    scopes: list[Scope] = Field(default_factory=lambda: ["computers", "users"], min_length=1, max_length=2)
    stale_days: int = Field(90, ge=7, le=3650)
    interval_hours: float = Field(6, ge=1, le=168)
    auth: AuthMode = "computer_account"
    # Extra PEM CA trusted for LDAPS (private PKI); public, not a secret.
    ca_pem: Annotated[str, StringConstraints(max_length=16384)] = ""

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str) -> str:
        if not re.match(DOMAIN_RE, v):
            raise ValueError("domain must be a DNS domain name such as corp.example.com")
        return v

    @field_validator("base_dns")
    @classmethod
    def _dns(cls, v: list[str]) -> list[str]:
        for dn in v:
            if _CTRL.search(dn) or not re.search(r"(?i)\bdc=", dn):
                raise ValueError("base DNs must be distinguished names such as OU=Laptops,DC=corp,DC=example,DC=com")
        return list(dict.fromkeys(v))

    @field_validator("scopes")
    @classmethod
    def _scopes(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(v))

    @field_validator("ca_pem")
    @classmethod
    def _pem(cls, v: str) -> str:
        if v and "-----BEGIN CERTIFICATE-----" not in v:
            raise ValueError("ca_pem must be one or more PEM certificates")
        return v

    @model_validator(mode="after")
    def _transport(self) -> AdConfig:
        if self.security == "ldaps" and self.port == 389:
            raise ValueError("port 389 is plain LDAP: use security=starttls (or LDAPS on 636)")
        if self.security == "sealed" and self.port in (636, 3269):
            raise ValueError("Kerberos signing & sealing runs on LDAP port 389 (or 3268), not on an LDAPS port")
        if self.security == "sealed" and self.auth == "service_account":
            raise ValueError("a service-account password is only ever sent inside TLS: use LDAPS or StartTLS")
        return self


EntraScope = Literal["users", "devices", "intune", "roles"]


class EntraConfig(_Strict):
    """Settings of a Microsoft Entra ID (+ Intune) source. `tenant_id` and
    `client_id` are copied from the chosen Azure connector by the server."""

    connector_id: Literal["org", "env"]
    tenant_id: Annotated[str, StringConstraints(max_length=64)] = ""
    client_id: Annotated[str, StringConstraints(max_length=64)] = ""
    scopes: list[EntraScope] = Field(default_factory=lambda: ["users", "devices", "intune", "roles"],
                                     min_length=1, max_length=4)
    stale_days: int = Field(90, ge=7, le=3650)
    interval_hours: float = Field(6, ge=1, le=168)

    @field_validator("scopes")
    @classmethod
    def _scopes(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(v))


GoogleScope = Literal["users", "roles", "chromeos", "mobile", "endpoints"]


class GoogleConfig(_Strict):
    """Settings of a Google Workspace source. The service account facts
    (`service_account_email`, `client_id`, `key_id`) are set by the server
    from the uploaded key; the key itself is stored encrypted."""

    admin_email: Annotated[str, StringConstraints(min_length=3, max_length=254, to_lower=True,
                                                  pattern=r"^[^@\s]{1,64}@[a-z0-9.-]{1,253}$")]
    customer_id: Annotated[str, StringConstraints(pattern=r"^(my_customer|C[0-9a-z]{5,20})$")] = "my_customer"
    scopes: list[GoogleScope] = Field(default_factory=lambda: ["users", "roles", "chromeos", "mobile", "endpoints"],
                                      min_length=1, max_length=5)
    stale_days: int = Field(90, ge=7, le=3650)
    interval_hours: float = Field(6, ge=1, le=168)
    service_account_email: Annotated[str, StringConstraints(max_length=254)] = ""
    client_id: Annotated[str, StringConstraints(max_length=32)] = ""
    key_id: Annotated[str, StringConstraints(max_length=16)] = ""

    @field_validator("scopes")
    @classmethod
    def _scopes(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(v))


CONFIG_MODELS: dict[str, type[_Strict]] = {"ad": AdConfig, "entra": EntraConfig, "google": GoogleConfig}
# Uploaded Google service-account key (JSON text, a few KB).
GoogleKey = Annotated[str, StringConstraints(min_length=100, max_length=16384, strip_whitespace=False)]


def parse_config(type_: str, raw: dict) -> dict:
    """Validate a source config for its type (raises pydantic ValidationError)."""
    model = CONFIG_MODELS.get(type_)
    if model is None:
        raise ValueError(f"unsupported directory type {type_!r}")
    return model.model_validate(raw).model_dump()


class Credential(_Strict):
    username: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    password: Annotated[str, StringConstraints(min_length=1, max_length=256, strip_whitespace=False)]

    @field_validator("username")
    @classmethod
    def _user(cls, v: str) -> str:
        if _CTRL.search(v):
            raise ValueError("username must not contain control characters")
        return v


Name = Annotated[str, StringConstraints(min_length=1, max_length=128)]
DeviceId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]


class SourceCreate(_Strict):
    type: Literal["ad", "entra", "google"] = "ad"
    name: Name
    enabled: bool = True
    # Validated per type (AdConfig, EntraConfig, GoogleConfig).
    config: dict
    # AD: the dedicated collectors (at least one); cloud types: none.
    collector_ids: list[DeviceId] = Field(default_factory=list, max_length=10)
    # Endpoint agents as collectors: legacy, refused for new sources.
    collector_device_ids: list[DeviceId] = Field(default_factory=list, max_length=10)
    credential: Credential | None = None
    # Google Workspace: the service account's JSON key (write-only).
    google_key: GoogleKey | None = None

    @model_validator(mode="after")
    def _config(self) -> SourceCreate:
        self.config = parse_config(self.type, self.config)
        if self.type != "ad" and (self.collector_device_ids or self.collector_ids or self.credential):
            raise ValueError("cloud directories are read by the server: no collectors or AD credential")
        if self.google_key is not None and self.type != "google":
            raise ValueError("google_key only applies to Google Workspace sources")
        return self


class SourceUpdate(_Strict):
    name: Name | None = None
    enabled: bool | None = None
    # Validated against the source's type by the API.
    config: dict | None = None
    # Dedicated collectors; on a legacy source this switches it to them (its
    # endpoint-agent collectors are dropped; objects and history are kept).
    collector_ids: list[DeviceId] | None = Field(None, max_length=10)
    # Legacy sources only: their endpoint-agent collectors.
    collector_device_ids: list[DeviceId] | None = Field(None, max_length=10)
    credential: Credential | None = None
    clear_credential: bool = False
    google_key: GoogleKey | None = None


class AddToAssetsIn(_Strict):
    computer_ids: list[DeviceId] = Field(min_length=1, max_length=1000)


class CollectorOut(BaseModel):
    id: str
    hostname: str
    os_family: str
    healthy: bool
    last_seen_at: UTCDateTime | None
    ad_domain: str | None = None
    agent_version: str = ""


class RunOut(BaseModel):
    collector_id: str | None = None
    id: str
    source_id: str
    trigger: str
    status: str
    device_id: str | None
    device_hostname: str | None = None
    queued_at: UTCDateTime
    started_at: UTCDateTime | None
    finished_at: UTCDateTime | None
    duration_ms: int | None = None
    computers_seen: int
    users_seen: int
    batches: int
    truncated: bool
    error: str | None
    attempt: int
    server: str | None = None
    sample: list[dict] = []
    checks: list[dict] = []
    scope_status: dict = {}


class SourceOut(BaseModel):
    id: str
    type: str
    name: str
    enabled: bool
    config: dict
    has_credential: bool
    credential_username_hint: str | None
    collector_device_ids: list[str]
    collectors: list[CollectorOut]
    # Dedicated collectors (directory/collectors.py collector_out) and whether
    # the source still uses endpoint agents (legacy).
    collector_ids: list[str] = []
    dedicated_collectors: list[dict] = []
    legacy_collectors: bool = False
    last_sync_at: UTCDateTime | None
    last_sync_status: str | None
    last_sync_error: str | None
    last_success_at: UTCDateTime | None
    computers_count: int
    users_count: int
    collection: str  # agent | server
    scope_status: dict
    next_sync_at: UTCDateTime | None
    active_run: RunOut | None
    created_at: UTCDateTime
    created_by: str | None
    updated_at: UTCDateTime
    updated_by: str | None


class IssueOut(BaseModel):
    id: str
    type: str
    kind: str
    source_id: str | None
    name: str
    domain: str
    ou: str
    os: str
    last_logon_at: UTCDateTime | None
    enabled: bool | None
    detail: str
    device_id: str | None
    device_hostname: str | None = None
    computer_id: str | None
    user_id: str | None
    it_asset_id: str | None = None
    first_seen_at: UTCDateTime
    # Sources the object is in ({"id", "type", "kind"}): every record of the
    # physical machine for computer issues, the user's source for user issues.
    sources: list[dict] = []
    privileged: bool = False


class IssuePage(BaseModel):
    items: list[IssueOut]
    total: int
    counts: dict[str, int]


class ComputerOut(BaseModel):
    id: str
    source_id: str
    name: str
    dns_hostname: str
    domain: str
    ou: str
    os: str
    os_version: str
    enabled: bool
    last_logon_at: UTCDateTime | None
    when_created: UTCDateTime | None
    missing_since: UTCDateTime | None
    match_status: str
    match_method: str | None
    match_confidence: int | None
    device_id: str | None
    device_hostname: str | None = None
    it_asset_id: str | None
    in_it_assets: bool
    device_kind: str = "ad"
    platform: str = ""
    compliance: str | None = None
    encrypted: bool | None = None
    serial_number: str = ""
    primary_user: str = ""
    agent_expected: bool = True
    # Every record of this physical machine ({"id", "source_id", "type", "kind"}).
    sources: list[dict] = []


class ComputerPage(BaseModel):
    items: list[ComputerOut]
    total: int


class UserOut(BaseModel):
    id: str
    source_id: str
    sam_account_name: str
    user_principal_name: str
    mail: str
    display_name: str
    department: str
    title: str
    enabled: bool
    last_logon_at: UTCDateTime | None
    domain: str
    ou: str
    missing_since: UTCDateTime | None
    source_type: str = "ad"
    privileged: bool = False
    privileged_roles: list[str] = []
    # False when the directory cannot tell (Entra ID without P1/P2 or AuditLog.Read.All).
    sign_in_known: bool = True


class UserPage(BaseModel):
    items: list[UserOut]
    total: int


# ----------------------------------------------------------------------------- agent upload
S256 = Annotated[str, StringConstraints(max_length=256)]
DN = Annotated[str, StringConstraints(max_length=2048)]
Sid = Annotated[str, StringConstraints(pattern=SID_RE)] | Literal[""]
Guid = Annotated[str, StringConstraints(pattern=GUID_RE, to_lower=True)]
Uac = Annotated[int, Field(ge=0, le=2**32 - 1)]


class _Upload(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ComputerIn(_Upload):
    object_guid: Guid
    object_sid: Sid = ""
    cn: S256 = ""
    dns_hostname: S256 = ""
    sam_account_name: S256 = ""
    operating_system: S256 = ""
    operating_system_version: S256 = ""
    distinguished_name: DN = ""
    user_account_control: Uac | None = None
    last_logon_timestamp: datetime | None = None
    when_created: datetime | None = None
    when_changed: datetime | None = None


class UserIn(_Upload):
    object_guid: Guid
    object_sid: Sid = ""
    sam_account_name: S256 = ""
    user_principal_name: S256 = ""
    mail: S256 = ""
    display_name: S256 = ""
    given_name: S256 = ""
    sn: S256 = ""
    department: S256 = ""
    title: S256 = ""
    manager_dn: DN = ""
    distinguished_name: DN = ""
    user_account_control: Uac | None = None
    last_logon_timestamp: datetime | None = None
    when_created: datetime | None = None
    pwd_last_set: datetime | None = None


class Totals(_Upload):
    computers: int = Field(0, ge=0)
    users: int = Field(0, ge=0)


class BatchIn(_Upload):
    seq: int = Field(ge=0, le=1_000_000)
    final: bool = False
    computers: list[ComputerIn] = Field(default_factory=list, max_length=MAX_BATCH_OBJECTS)
    users: list[UserIn] = Field(default_factory=list, max_length=MAX_BATCH_OBJECTS)
    status: Literal["succeeded", "failed"] | None = None
    error: Annotated[str, StringConstraints(max_length=2000)] = ""
    truncated: bool = False
    totals: Totals | None = None
    duration_ms: int | None = Field(None, ge=0, le=7 * 24 * 3600 * 1000)
    server: Annotated[str, StringConstraints(max_length=253)] = ""

    @model_validator(mode="after")
    def _check(self) -> BatchIn:
        if len(self.computers) + len(self.users) > MAX_BATCH_OBJECTS:
            raise ValueError(f"at most {MAX_BATCH_OBJECTS} objects per batch")
        if self.final and self.status is None:
            raise ValueError("the final batch needs a status")
        return self


# ----------------------------------------------------------------------------- dedicated collectors
_HOST = Annotated[str, StringConstraints(max_length=255, pattern=r"^[A-Za-z0-9._-]{0,255}$")]
_TEXT64 = Annotated[str, StringConstraints(max_length=64)]


class CollectorFacts(_Strict):
    """What a collector reports about its host (enrollment and heartbeat)."""

    hostname: _HOST = ""
    dns_hostname: _HOST = ""
    domain: Annotated[str, StringConstraints(max_length=255, to_lower=True, pattern=r"^[a-z0-9.-]{0,255}$")] = ""
    os_name: Annotated[str, StringConstraints(max_length=128)] = ""
    os_version: _TEXT64 = ""
    architecture: Annotated[str, StringConstraints(max_length=16)] = ""
    version: _TEXT64 = ""
    run_as: Annotated[str, StringConstraints(max_length=256)] = ""
    run_as_kind: Literal["computer_account", "gmsa", "user", "unknown"] = "unknown"
    is_domain_controller: bool = False
    features: Annotated[str, StringConstraints(max_length=256, pattern=r"^[a-z0-9_,]{0,256}$")] = ""

    @field_validator("run_as", "os_name")
    @classmethod
    def _plain(cls, v: str) -> str:
        if _CTRL.search(v):
            raise ValueError("must not contain control characters")
        return v


class CollectorEnrollIn(_Strict):
    token: Annotated[str, StringConstraints(min_length=10, max_length=128)]
    machine_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")] | Literal[""] = ""
    facts: CollectorFacts


class CollectorHeartbeatIn(_Strict):
    facts: CollectorFacts


class CollectorResultIn(_Strict):
    nonce: Annotated[str, StringConstraints(min_length=16, max_length=64)]
    status: Literal["succeeded", "failed", "rejected"]
    output: Annotated[str, StringConstraints(max_length=8000)] = ""
    result_data: dict | None = None


class CollectorUpdateStatusIn(_Strict):
    release_id: Annotated[str, StringConstraints(max_length=32)] = ""
    from_version: _TEXT64 = ""
    to_version: _TEXT64 = ""
    status: Literal["downloading", "verified", "installing", "installed", "rolled_back", "failed", "rejected"]
    detail: Annotated[str, StringConstraints(max_length=500)] = ""


class CollectorRename(_Strict):
    name: Name


class CollectorTokenIn(_Strict):
    name: Name = "collector"
    max_uses: int | None = Field(1, ge=1, le=100)
    expires_in_hours: int = Field(24, ge=1, le=24 * 30)


class CollectorTestIn(_Strict):
    source_id: DeviceId | None = None


class CollectorInstallerIn(_Strict):
    name: Name = "collector"
    arch: Literal["amd64", "arm64"] = "amd64"
    expires_in_hours: int = Field(24, ge=1, le=24 * 30)
    # gMSA to run the service as (DOMAIN\name$); empty: LocalSystem (computer account).
    gmsa: Annotated[str, StringConstraints(max_length=256, pattern=r"^([A-Za-z0-9.-]{1,64}\\[A-Za-z0-9._-]{1,63}\$)?$")] = ""
    include_ca: bool = True
