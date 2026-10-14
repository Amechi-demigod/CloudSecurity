"""Runtime event schema (v1.0).

This module is the single source of truth for the JSON the sensor emits.
It is intentionally stdlib-only (dataclasses) so the sensor stays dependency
light; the backend can mirror it with Pydantic. See ``sensor/EVENT_SCHEMA.md``
and ``sensor/schema/runtime-event.schema.json``.
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "1.0"

EVENT_TYPES = (
    "process_exec",
    "network_connect",
    "network_accept",
    "file_access",
    "library_loaded",
    "privilege_change",
)

SEVERITIES = ("info", "low", "medium", "high", "critical")
DIRECTIONS = ("outbound", "inbound")
FILE_OPERATIONS = ("open", "write", "attrib", "create", "delete", "rename")
LIBRARY_KINDS = ("shared_object", "python_package")


def utc_now_iso() -> str:
    """ISO8601 UTC timestamp with millisecond precision and a 'Z' suffix."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


@dataclass
class ProcessInfo:
    pid: int
    ppid: Optional[int] = None
    name: Optional[str] = None
    exe: Optional[str] = None
    cmdline: Optional[str] = None  # space-joined, redacted, truncated
    uid: Optional[int] = None  # real uid
    euid: Optional[int] = None  # effective uid
    user: Optional[str] = None
    parent_name: Optional[str] = None


@dataclass
class NetworkInfo:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str = "tcp"
    direction: str = "outbound"  # outbound | inbound


@dataclass
class FileInfo:
    path: str
    operation: str  # open | write | attrib | create | delete | rename


@dataclass
class LibraryInfo:
    path: str
    package: Optional[str] = None
    version: Optional[str] = None
    kind: str = "shared_object"  # shared_object | python_package
    source: Optional[str] = None  # dpkg | apk | dist-info | soname


@dataclass
class K8sInfo:
    namespace: Optional[str] = None
    pod: Optional[str] = None
    node: Optional[str] = None
    pod_uid: Optional[str] = None
    container: Optional[str] = None


@dataclass
class CloudInfo:
    provider: Optional[str] = None  # aws | gcp | azure | None
    resource_id: Optional[str] = None


@dataclass
class RuntimeEvent:
    event_type: str
    sensor_id: str = ""
    host: str = ""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=utc_now_iso)
    schema_version: str = SCHEMA_VERSION
    container_id: Optional[str] = None
    k8s: Optional[K8sInfo] = None
    process: Optional[ProcessInfo] = None
    network: Optional[NetworkInfo] = None
    file: Optional[FileInfo] = None
    library: Optional[LibraryInfo] = None
    cloud: Optional[CloudInfo] = None
    severity_hint: str = "info"
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.event_type not in EVENT_TYPES:
            raise ValueError(f"unknown event_type: {self.event_type!r}")

    def add_tag(self, tag: str) -> None:
        if tag not in self.tags:
            self.tags.append(tag)

    def raise_severity(self, severity: str) -> None:
        if SEVERITIES.index(severity) > SEVERITIES.index(self.severity_hint):
            self.severity_hint = severity

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuntimeEvent":
        """Inverse of to_dict (used by tests and as a backend reference)."""
        sub = {
            "k8s": K8sInfo,
            "process": ProcessInfo,
            "network": NetworkInfo,
            "file": FileInfo,
            "library": LibraryInfo,
            "cloud": CloudInfo,
        }
        known = {f.name for f in fields(cls)}
        kwargs: Dict[str, Any] = {}
        for key, value in data.items():
            if key not in known:
                continue
            if key in sub and value is not None:
                sub_known = {f.name for f in fields(sub[key])}
                value = sub[key](**{k: v for k, v in value.items() if k in sub_known})
            kwargs[key] = value
        return cls(**kwargs)


def validate_event_dict(data: Dict[str, Any]) -> List[str]:
    """Light-weight structural validation. Returns a list of problems."""
    errors: List[str] = []
    for key in ("event_id", "timestamp", "sensor_id", "host", "event_type", "schema_version"):
        if not isinstance(data.get(key), str) or not data.get(key):
            errors.append(f"{key}: required non-empty string")
    et = data.get("event_type")
    if et not in EVENT_TYPES:
        errors.append(f"event_type: must be one of {EVENT_TYPES}")
    if data.get("severity_hint") not in SEVERITIES:
        errors.append(f"severity_hint: must be one of {SEVERITIES}")
    if not isinstance(data.get("tags"), list):
        errors.append("tags: must be a list")
    required_section = {
        "process_exec": "process",
        "privilege_change": "process",
        "network_connect": "network",
        "network_accept": "network",
        "file_access": "file",
        "library_loaded": "library",
    }.get(et)
    if required_section and not isinstance(data.get(required_section), dict):
        errors.append(f"{required_section}: required for event_type {et}")
    net = data.get("network")
    if isinstance(net, dict) and net.get("direction") not in DIRECTIONS:
        errors.append(f"network.direction: must be one of {DIRECTIONS}")
    fil = data.get("file")
    if isinstance(fil, dict) and fil.get("operation") not in FILE_OPERATIONS:
        errors.append(f"file.operation: must be one of {FILE_OPERATIONS}")
    return errors
