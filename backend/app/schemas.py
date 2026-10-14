"""Pydantic v2 API schemas."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PlainSerializer

# Timestamps are stored as naive UTC; serialize them with an explicit "Z".
UTCDateTime = Annotated[
    datetime,
    PlainSerializer(lambda d: d.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z"), return_type=str),
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
class ProcessInfo(BaseModel):
    name: str
    cmdline: str | None = None
    pid: int | None = None
    ppid: int | None = None
    parent_name: str | None = None
    user: str | None = None
    uid: int | None = None
    exe: str | None = None


class NetworkInfo(BaseModel):
    direction: Literal["inbound", "outbound"] = "outbound"
    protocol: str = "tcp"
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    dst_domain: str | None = None
    bytes_sent: int | None = None


class FileInfo(BaseModel):
    path: str
    operation: str = "read"  # read | write | delete | chmod | exec


class PrivilegeInfo(BaseModel):
    from_uid: int | None = None
    to_uid: int | None = 0
    method: str | None = None


class ContainerInfo(BaseModel):
    id: str | None = None
    name: str | None = None
    image: str | None = None
    pod: str | None = None
    namespace: str | None = None


class RuntimeEventIn(BaseModel):
    """Runtime-sensor event schema accepted by POST /api/runtime/events.

    A future eBPF sensor (Falco/Tetragon-style) should map its native events
    onto this shape.
    """

    timestamp: datetime | None = Field(None, description="Event time (ISO-8601). Defaults to receipt time.")
    asset_id: str | None = Field(None, description="Inventory asset id (e.g. ARM id of the VM or AKS pod id).")
    event_type: Literal["process_exec", "network_connection", "file_access", "privilege_escalation"]
    sensor_id: str | None = None
    process: ProcessInfo | None = None
    network: NetworkInfo | None = None
    file: FileInfo | None = None
    privilege: PrivilegeInfo | None = None
    container: ContainerInfo | None = None
    labels: dict[str, str] | None = None


class IngestResult(BaseModel):
    accepted: int
    alerts_triggered: int
    alert_ids: list[str]


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
