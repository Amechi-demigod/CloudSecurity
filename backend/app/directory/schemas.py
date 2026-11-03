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
Security = Literal["ldaps", "starttls"]
AuthMode = Literal["computer_account", "service_account"]

MAX_BATCH_OBJECTS = 5000


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ----------------------------------------------------------------------------- console API
class AdConfig(_Strict):
    """Settings of an on-prem Active Directory source."""

    domain: Annotated[str, StringConstraints(min_length=3, max_length=253, to_lower=True)]
    servers: list[Annotated[str, StringConstraints(pattern=SERVER_RE)]] = Field(default_factory=list, max_length=10)
    port: int = Field(636, ge=1, le=65535)
    security: Security = "ldaps"
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
        return self


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
    type: Literal["ad"] = "ad"
    name: Name
    enabled: bool = True
    config: AdConfig
    collector_device_ids: list[DeviceId] = Field(min_length=1, max_length=10)
    credential: Credential | None = None


class SourceUpdate(_Strict):
    name: Name | None = None
    enabled: bool | None = None
    config: AdConfig | None = None
    collector_device_ids: list[DeviceId] | None = Field(None, min_length=1, max_length=10)
    credential: Credential | None = None
    clear_credential: bool = False


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
    last_sync_at: UTCDateTime | None
    last_sync_status: str | None
    last_sync_error: str | None
    last_success_at: UTCDateTime | None
    computers_count: int
    users_count: int
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
