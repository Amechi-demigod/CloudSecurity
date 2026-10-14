"""Pydantic v2 API schemas."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PlainSerializer

# Timestamps are stored as naive UTC; serialize them with an explicit "Z".
UTCDateTime = Annotated[
    datetime,
    PlainSerializer(lambda d: d.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z"), return_type=str),
]

Severity = Literal["critical", "high", "medium", "low", "info"]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ----------------------------------------------------------------------------- inventory
class AssetOut(ORM):
    id: str
    name: str
    type: str
    provider: str
    subscription_id: str | None
    subscription_name: str | None
    resource_group: str | None
    region: str | None
    tags: dict[str, Any]
    internet_exposed: bool
    sensitive_data: bool
    properties: dict[str, Any]
    source: str
    first_seen: UTCDateTime
    last_seen: UTCDateTime


class AssetSummary(AssetOut):
    open_findings: int = 0
    vulnerabilities: int = 0
    max_risk: float = 0.0
    open_alerts: int = 0


class AssetRef(BaseModel):
    id: str
    name: str
    type: str


class RelationshipOut(BaseModel):
    type: str
    direction: Literal["in", "out"]
    asset: AssetRef


class FindingOut(ORM):
    id: str
    rule_id: str
    asset_id: str
    title: str
    description: str
    severity: str
    status: str
    remediation: str
    compliance: list[str]
    evidence: dict[str, Any]
    source: str
    first_seen: UTCDateTime
    last_seen: UTCDateTime
    resolved_at: UTCDateTime | None
    asset_name: str | None = None
    asset_type: str | None = None


class FindingUpdate(BaseModel):
    status: Literal["open", "resolved", "suppressed"]


class VulnerabilityOut(ORM):
    id: str
    asset_id: str
    cve_id: str
    package: str
    version: str
    fixed_version: str | None
    title: str
    cvss: float
    severity: str
    exploit_available: bool
    in_use: bool
    in_use_source: str | None = None  # "sensor" when observed by a real runtime sensor
    in_use_last_seen: UTCDateTime | None = None
    internet_exposed: bool
    sensitive_data_access: bool
    risk_score: float
    priority: str
    status: str
    asset_name: str | None = None
    asset_type: str | None = None


class AlertOut(ORM):
    id: str
    rule_id: str
    title: str
    description: str
    severity: str
    asset_id: str | None
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    status: str
    event_count: int
    first_seen: UTCDateTime
    last_seen: UTCDateTime
    asset_name: str | None = None
    asset_type: str | None = None


class AlertUpdate(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]


class RuntimeEventOut(ORM):
    id: str
    timestamp: UTCDateTime
    asset_id: str | None
    event_type: str
    summary: str
    data: dict[str, Any]
    sensor_id: str | None
    source: str


class TimelineEntry(RuntimeEventOut):
    triggered: bool = False  # True if this event is linked to the alert


class AlertDetail(AlertOut):
    asset: AssetOut | None = None
    timeline: list[TimelineEntry]


# ----------------------------------------------------------------------------- runtime ingest
# Bounded string / int types: every field of an ingested event ends up in the
# database and the UI, so lengths and ranges are capped.
Short = Annotated[str, Field(max_length=256)]
Long = Annotated[str, Field(max_length=4096)]
Port = Annotated[int, Field(ge=0, le=65535)]
NonNeg = Annotated[int, Field(ge=0, le=2**32)]


class ProcessInfo(BaseModel):
    name: Short
    cmdline: Long | None = None
    pid: NonNeg | None = None
    ppid: NonNeg | None = None
    parent_name: Short | None = None
    user: Short | None = None
    uid: NonNeg | None = None
    exe: Long | None = None


class NetworkInfo(BaseModel):
    direction: Literal["inbound", "outbound"] = "outbound"
    protocol: Annotated[str, Field(max_length=16)] = "tcp"
    src_ip: Annotated[str, Field(max_length=64)] | None = None
    src_port: Port | None = None
    dst_ip: Annotated[str, Field(max_length=64)] | None = None
    dst_port: Port | None = None
    dst_domain: Short | None = None
    bytes_sent: Annotated[int, Field(ge=0)] | None = None


class FileInfo(BaseModel):
    path: Long
    operation: Literal["read", "write", "delete", "chmod", "exec"] = "read"


class PrivilegeInfo(BaseModel):
    from_uid: NonNeg | None = None
    to_uid: NonNeg | None = 0
    method: Short | None = None


class ContainerInfo(BaseModel):
    id: Short | None = None
    name: Short | None = None
    image: Long | None = None
    pod: Short | None = None
    namespace: Short | None = None


class RuntimeEventIn(BaseModel):
    """Legacy (pre-v1.0) runtime event schema accepted by POST /api/runtime/events.

    Still used by the built-in simulator and by the sensor's `cnapp-mvp`
    payload format. The native sensor schema is `SensorEventV1` below.
    """

    timestamp: datetime | None = Field(None, description="Event time (ISO-8601). Defaults to receipt time.")
    asset_id: Long | None = Field(None, description="Inventory asset id (e.g. ARM id of the VM or AKS pod id).")
    event_type: Literal["process_exec", "network_connection", "file_access", "privilege_escalation"]
    sensor_id: Short | None = None
    process: ProcessInfo | None = None
    network: NetworkInfo | None = None
    file: FileInfo | None = None
    privilege: PrivilegeInfo | None = None
    container: ContainerInfo | None = None
    labels: Annotated[dict[Short, Annotated[str, Field(max_length=2048)]], Field(max_length=64)] | None = None


# --- native runtime-sensor schema v1.0 (sensor/EVENT_SCHEMA.md) ---------------
class SensorProcess(BaseModel):
    pid: NonNeg | None = None
    ppid: NonNeg | None = None
    name: Short | None = None
    exe: Long | None = None
    cmdline: Long | None = None
    uid: NonNeg | None = None
    euid: NonNeg | None = None
    user: Short | None = None
    parent_name: Short | None = None


class SensorNetwork(BaseModel):
    src_ip: Annotated[str, Field(max_length=64)] | None = None
    src_port: Port | None = None
    dst_ip: Annotated[str, Field(max_length=64)] | None = None
    dst_port: Port | None = None
    protocol: Annotated[str, Field(max_length=16)] = "tcp"
    direction: Literal["inbound", "outbound"] | None = None


class SensorFile(BaseModel):
    path: Long
    operation: Literal["open", "write", "attrib", "create", "delete", "rename"] = "open"


class SensorLibrary(BaseModel):
    path: Long
    package: Short | None = None
    version: Short | None = None
    kind: Literal["shared_object", "python_package"] | None = None
    source: Literal["dpkg", "apk", "dist-info", "soname"] | None = None


class SensorK8s(BaseModel):
    namespace: Short | None = None
    pod: Short | None = None
    node: Short | None = None
    pod_uid: Short | None = None
    container: Short | None = None


class SensorCloud(BaseModel):
    provider: Literal["aws", "gcp", "azure"] | None = None
    resource_id: Long | None = None


SENSOR_EVENT_TYPES = ("process_exec", "network_connect", "network_accept", "file_access", "library_loaded",
                      "privilege_change")


class SensorEventV1(BaseModel):
    """Native runtime-sensor event, schema v1.0 (see sensor/EVENT_SCHEMA.md)."""

    schema_version: Annotated[str, Field(pattern=r"^1\.\d+$")]
    event_id: Annotated[str, Field(max_length=64, pattern=r"^[0-9a-fA-F-]{8,64}$")] | None = None
    timestamp: datetime | None = None
    sensor_id: Short | None = None
    host: Short | None = None
    event_type: Literal["process_exec", "network_connect", "network_accept", "file_access", "library_loaded",
                        "privilege_change"]
    container_id: Annotated[str, Field(max_length=128)] | None = None
    k8s: SensorK8s | None = None
    process: SensorProcess | None = None
    network: SensorNetwork | None = None
    file: SensorFile | None = None
    library: SensorLibrary | None = None
    cloud: SensorCloud | None = None
    severity_hint: Literal["info", "low", "medium", "high", "critical"] = "info"
    tags: Annotated[list[Annotated[str, Field(max_length=128)]], Field(max_length=64)] = Field(default_factory=list)


class IngestResult(BaseModel):
    accepted: int
    alerts_triggered: int
    alert_ids: list[str]
    duplicates: int = 0  # native events whose event_id was already ingested
    in_use_updates: int = 0  # vulnerabilities newly flagged "in use at runtime" by library_loaded events


# ----------------------------------------------------------------------------- scans
class ScanRequest(BaseModel):
    connector: str = "azure"


class ScanRunOut(ORM):
    id: str
    connector: str
    status: str
    started_at: UTCDateTime
    finished_at: UTCDateTime | None
    assets_found: int
    findings_open: int
    errors: list[str]
    message: str


# --- Authentication ---------------------------------------------------------------

Role = Literal["admin", "analyst", "viewer"]


class LoginRequest(BaseModel):
    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


class UserOut(ORM):
    id: str
    email: str
    name: str
    role: Role
    is_active: bool
    created_at: UTCDateTime
    last_login_at: UTCDateTime | None = None
    locked_until: UTCDateTime | None = None
    failed_login_count: int = 0


class SessionInfo(BaseModel):
    user: UserOut
    csrf_token: str
    expires_at: UTCDateTime
    idle_timeout_minutes: float


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=1, max_length=1024)


class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+$")
    name: str = Field("", max_length=128)
    role: Role = "viewer"
    password: str = Field(min_length=1, max_length=1024)


class UserUpdate(BaseModel):
    name: str | None = Field(None, max_length=128)
    role: Role | None = None
    is_active: bool | None = None


class PasswordReset(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


class AuditLogOut(ORM):
    id: int
    timestamp: UTCDateTime
    action: str
    actor_id: str | None = None
    actor_email: str | None = None
    target: str | None = None
    ip: str | None = None
    detail: dict[str, Any] = {}
