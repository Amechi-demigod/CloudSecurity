"""Pydantic schemas for device management: the agent API (strictly validated,
size-limited input from endpoints) and the user-facing /api/devices API."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from .schemas import ORM, UTCDateTime

# Commands an agent can be asked to run, and the minimum role to queue each.
# The agent enforces its own copy of this allowlist as well.
COMMAND_ROLES: dict[str, str] = {
    "recheck_posture": "analyst",
    "collect_logs": "analyst",
    "lock_device": "admin",
    "restart_agent": "admin",
    "update_check_in_interval": "admin",
}
CommandType = Literal["recheck_posture", "collect_logs", "lock_device", "restart_agent", "update_check_in_interval"]
CommandStatus = Literal["pending", "delivered", "succeeded", "failed", "rejected", "expired", "cancelled"]
OsFamily = Literal["windows", "macos", "linux"]
MIN_INTERVAL_SECONDS = 300
MAX_INTERVAL_SECONDS = 86400

Str64 = Annotated[str, StringConstraints(max_length=64)]
Str128 = Annotated[str, StringConstraints(max_length=128)]
Str255 = Annotated[str, StringConstraints(max_length=255)]
Str1k = Annotated[str, StringConstraints(max_length=1024)]
CheckName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,39}$")]

MAX_DATA_JSON = 16 * 1024  # bytes of free-form data per posture check


class Strict(BaseModel):
    """Agent input: unknown fields are rejected, strings are not coerced."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ----------------------------------------------------------------------------- agent API
class EnrollDevice(Strict):
    hostname: Str255 = Field(min_length=1)
    os_family: OsFamily
    os_name: Str128 = ""
    os_version: Str64 = ""
    serial_number: Str128 = ""
    machine_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")] | Literal[""] = ""
    agent_version: Annotated[str, StringConstraints(max_length=32)] = ""


class EnrollRequest(Strict):
    token: Annotated[str, StringConstraints(min_length=10, max_length=128)]
    device: EnrollDevice


class EnrollResponse(BaseModel):
    device_id: str
    device_secret: str
    check_in_interval_seconds: int
    command_poll_seconds: int
    server_time: UTCDateTime
    reenrolled: bool


class Disk(Strict):
    mount: Str255 = ""
    filesystem: Str64 = ""
    size_bytes: int | None = Field(None, ge=0)
    free_bytes: int | None = Field(None, ge=0)


class NetInterface(Strict):
    name: Str128 = ""
    mac: Str64 = ""
    ips: list[Str64] = Field(default_factory=list, max_length=32)


class DeviceInfo(Strict):
    hostname: Str255 = Field(min_length=1)
    os_family: OsFamily
    os_name: Str128 = ""
    os_version: Str64 = ""
    os_build: Str64 = ""
    architecture: Annotated[str, StringConstraints(max_length=32)] = ""
    serial_number: Str128 = ""
    manufacturer: Str128 = ""
    model: Str128 = ""
    cpu: Str255 = ""
    cpu_cores: int | None = Field(None, ge=0, le=4096)
    memory_bytes: int | None = Field(None, ge=0)
    disks: list[Disk] = Field(default_factory=list, max_length=64)
    uptime_seconds: int | None = Field(None, ge=0)
    last_boot: datetime | None = None
    logged_in_users: list[Str128] = Field(default_factory=list, max_length=64)
    network: list[NetInterface] = Field(default_factory=list, max_length=64)
    timezone: Str64 = ""
    agent_version: Annotated[str, StringConstraints(max_length=32)] = ""


class PostureCheck(Strict):
    # pass / fail / unknown; "info" for data-only checks such as local admins.
    status: Literal["pass", "fail", "unknown", "info"]
    detail: Str1k = ""
    error: Str1k | None = None
    data: dict[str, Any] = Field(default_factory=dict)

    @field_validator("data")
    @classmethod
    def _data_small(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(json.dumps(v, default=str)) > MAX_DATA_JSON:
            raise ValueError(f"posture check data larger than {MAX_DATA_JSON} bytes")
        return v


class SoftwareItem(Strict):
    name: Str255 = Field(min_length=1)
    version: Str128 = ""
    publisher: Str255 = ""
    identifier: Str255 = ""
    install_date: Annotated[str, StringConstraints(max_length=32)] = ""
    source: Annotated[str, StringConstraints(max_length=32)] = ""


class CheckinRequest(Strict):
    schema_version: Literal[1] = 1
    collected_at: datetime | None = None
    device: DeviceInfo
    posture: dict[CheckName, PostureCheck] = Field(default_factory=dict, max_length=40)
    # None = not collected this time (keep the previous list).
    software: list[SoftwareItem] | None = Field(None, max_length=10000)
    errors: dict[CheckName, Str1k] = Field(default_factory=dict, max_length=40)


class CheckinResponse(BaseModel):
    device_id: str
    server_time: UTCDateTime
    pending_commands: int
    issues: list[str]
    # Signed agent release this device should install (docs/AGENT_UPDATES.md).
    update: dict[str, Any] | None = None


class AgentCommand(BaseModel):
    id: str
    device_id: str
    type: str
    params: dict[str, Any]
    nonce: str
    issued_at: UTCDateTime
    expires_at: UTCDateTime


class AgentCommandList(BaseModel):
    server_time: UTCDateTime
    commands: list[AgentCommand]


class CommandResultIn(Strict):
    nonce: Annotated[str, StringConstraints(min_length=16, max_length=64)]
    status: Literal["succeeded", "failed", "rejected"]
    output: Annotated[str, StringConstraints(max_length=16384)] = ""


# ----------------------------------------------------------------------------- user API
class DeviceIssue(BaseModel):
    code: str
    severity: Literal["critical", "high", "medium", "low"]
    title: str
    detail: str = ""


class DeviceSummaryOut(ORM):
    id: str
    hostname: str
    os_family: str
    os_name: str
    os_version: str
    architecture: str
    serial_number: str
    manufacturer: str
    model: str
    agent_version: str
    status: str
    enrolled_at: UTCDateTime
    last_seen_at: UTCDateTime | None
    last_checkin_at: UTCDateTime | None
    logged_in_users: list[str] = []
    device_group: str | None = None
    health: Literal["healthy", "warning", "critical", "unknown"]
    connectivity: Literal["active", "stale", "inactive", "never"]
    issues: list[DeviceIssue]


class DeviceDetailOut(DeviceSummaryOut):
    os_build: str
    last_ip: str | None
    check_in_interval_seconds: int
    software_count: int
    updates_pending_since: UTCDateTime | None
    revoked_at: UTCDateTime | None
    inventory: dict[str, Any]
    posture: dict[str, Any]
    collection_errors: dict[str, Any]


class SoftwareOut(ORM):
    name: str
    version: str
    publisher: str
    identifier: str
    install_date: str
    source: str


class SnapshotOut(ORM):
    id: int
    received_at: UTCDateTime
    collected_at: UTCDateTime | None
    agent_version: str
    os_version: str
    posture: dict[str, Any]
    issues: list[str]
    software_count: int | None


class CommandOut(ORM):
    id: str
    device_id: str
    type: str
    params: dict[str, Any]
    status: str
    reason: str
    requested_by_email: str | None
    created_at: UTCDateTime
    expires_at: UTCDateTime
    delivered_at: UTCDateTime | None
    completed_at: UTCDateTime | None
    output: str
    log_bundle_id: str | None


class CommandCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: CommandType
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=500)]
    params: dict[str, Any] = Field(default_factory=dict)
    expires_in_hours: float | None = Field(None, gt=0, le=168)


class DeviceAction(BaseModel):
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=500)]


class EnrollmentTokenCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
    # 1 = single use; None = unlimited until expiry.
    max_uses: int | None = Field(1, ge=1, le=100000)
    expires_in_hours: float = Field(24, gt=0, le=24 * 90)


class InstallerCreate(BaseModel):
    """A downloadable installer with a dedicated multi-use enrollment token."""
    model_config = ConfigDict(extra="forbid")

    platform: Literal["windows-msi", "macos-pkg"]
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)] | None = None
    expires_in_days: int = Field(30, ge=1, le=365)
    max_devices: int = Field(500, ge=1, le=100000)
    device_group: Annotated[str, StringConstraints(strip_whitespace=True, max_length=64,
                                                   pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._\-]*$")] | None = None
    # None: include the private CA when the server has one configured.
    include_ca: bool | None = None


class EnrollmentTokenOut(ORM):
    id: str
    name: str
    token_prefix: str
    package_platform: str | None = None
    device_group: str | None = None
    max_uses: int | None
    use_count: int
    created_by: str | None
    created_at: UTCDateTime
    expires_at: UTCDateTime
    last_used_at: UTCDateTime | None
    revoked_at: UTCDateTime | None
    state: Literal["active", "expired", "exhausted", "revoked"]


class EnrollmentTokenCreated(EnrollmentTokenOut):
    token: str  # shown exactly once
