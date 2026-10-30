"""Pydantic v2 API schemas."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PlainSerializer

from .config import MAX_INTERVAL_HOURS, MIN_INTERVAL_HOURS

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
    asset_id: str | None = None
    device_id: str | None = None
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
    device_name: str | None = None
    source: str = "simulated"
    first_seen: UTCDateTime | None = None
    kev: bool | None = None
    epss: float | None = None
    last_seen: UTCDateTime | None = None
    resolved_at: UTCDateTime | None = None
    evidence: dict[str, Any] | None = None


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


class SensorOs(BaseModel):
    id: Short | None = None  # os-release ID: debian | ubuntu | alpine | rocky | almalinux | rhel ...
    version_id: Short | None = None
    pretty_name: Short | None = None


class SensorPackage(BaseModel):
    name: Short
    version: Short
    # OSV ecosystem, e.g. "Debian:12", "Ubuntu:22.04:LTS", "Alpine:v3.20", "Rocky Linux:9", "PyPI"
    ecosystem: Annotated[str, Field(max_length=64)] | None = None
    source_name: Short | None = None  # dpkg Source / apk origin / rpm source package
    source_version: Short | None = None
    kind: Literal["deb", "apk", "rpm", "python"] | None = None


class SensorPackageInventoryV1(BaseModel):
    """Package inventory of one Linux host (sensor/EVENT_SCHEMA.md#package-inventory),
    POSTed to /api/runtime/packages every few hours."""

    schema_version: Annotated[str, Field(pattern=r"^1\.\d+$")]
    sensor_id: Short | None = None
    host: Short | None = None
    collected_at: datetime | None = None
    os: SensorOs | None = None
    cloud: SensorCloud | None = None
    packages: Annotated[list[SensorPackage], Field(max_length=50000)]


class PackageIngestResult(BaseModel):
    asset_id: str
    asset_created: bool
    packages: int
    match_requested: bool


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
    # manual | scheduled | first_scan (None: recorded before scheduled scans existed)
    trigger: str | None = None
    # Who started a manual / first scan (from the scan_started audit record); GET /api/scans only.
    triggered_by: str | None = None


class ConnectorScheduleOut(ORM):
    name: str
    provider: str
    configured: bool
    scheduled: bool
    not_scheduled_reason: str | None
    last_run: ScanRunOut | None
    last_scheduled_run: ScanRunOut | None
    next_run_at: UTCDateTime | None  # None while scheduled: due now
    running: bool


class ScanScheduleOut(ORM):
    enabled: bool
    interval_hours: float
    enabled_overridden: bool
    interval_overridden: bool
    default_enabled: bool
    default_interval_hours: float
    min_interval_hours: float
    max_interval_hours: float
    updated_at: UTCDateTime | None
    updated_by: str | None
    connectors: list[ConnectorScheduleOut]


class ScanScheduleUpdate(BaseModel):
    """Console overrides; null resets a field to its environment default."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    interval_hours: float | None = Field(default=None, ge=MIN_INTERVAL_HOURS, le=MAX_INTERVAL_HOURS,
                                         allow_inf_nan=False)


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
    mfa_enabled: bool = False
    # "password" (has a local password) and/or linked identity providers ("entra").
    auth_sources: list[str] = []


class OrganizationBrief(ORM):
    id: str
    name: str
    slug: str
    status: str
    is_default: bool = False
    logo_url: str | None = None


class SessionInfo(BaseModel):
    user: UserOut
    csrf_token: str
    expires_at: UTCDateTime
    idle_timeout_minutes: float
    # The organisation this session acts in, and whether the user may open the
    # platform console (manage organisations).
    organization: OrganizationBrief | None = None
    platform_admin: bool = False


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


# --- MFA and single sign-on ---------------------------------------------------------

class MfaChallengeOut(BaseModel):
    """Returned by /login (or the SSO callback) instead of a session when a second step is needed."""
    mfa_required: bool = True
    # verify: enter a TOTP / recovery code. enroll: MFA is mandatory for the role, set it up now.
    purpose: Literal["verify", "enroll"]
    mfa_token: str
    expires_in: int


class LoginComplete(SessionInfo):
    # Only after a forced enrolment: shown once.
    recovery_codes: list[str] | None = None


class MfaCodeRequest(BaseModel):
    mfa_token: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=1, max_length=64)


class MfaTokenRequest(BaseModel):
    mfa_token: str = Field(min_length=1, max_length=128)


class MfaSetupOut(BaseModel):
    secret: str
    otpauth_uri: str
    qr_svg: str  # data:image/svg+xml URI
    digits: int
    period: int


class MfaStatus(BaseModel):
    enabled: bool
    enabled_at: UTCDateTime | None = None
    required: bool
    recovery_codes_remaining: int
    has_password: bool
    sso_user: bool


class MfaEnableRequest(BaseModel):
    code: str = Field(min_length=1, max_length=64)


class MfaManageRequest(BaseModel):
    """Disable / regenerate: password (if the account has one) + a current TOTP or recovery code."""
    password: str | None = Field(None, max_length=1024)
    code: str = Field(min_length=1, max_length=64)


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]


class AuthProviders(BaseModel):
    password: bool
    entra: bool
    entra_label: str = "Microsoft"
