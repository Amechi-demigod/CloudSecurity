"""Request bodies of the network discovery API and of the collector batch upload."""
from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]
Hhmm = Annotated[str, StringConstraints(pattern=r"^([01]\d|2[0-3]):[0-5]\d$")]
Id32 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def clean(s: str | None, n: int) -> str:
    """Sanitised, length-capped text from a device (control characters removed)."""
    return _CTRL.sub("", s or "").strip()[:n]


class Lenient(BaseModel):
    """Collector payloads: unknown keys are ignored (a newer collector must not break an older server)."""
    model_config = ConfigDict(extra="ignore")


# ----------------------------------------------------------------------------- console
class PortIn(BaseModel):
    port: int = Field(ge=1, le=65535)
    proto: Literal["tcp", "udp"] = "tcp"


class CredentialIn(BaseModel):
    """Write-only secrets: they are encrypted and never returned."""
    name: Name
    version: Literal["v3", "v2c"]
    username: Annotated[str, StringConstraints(max_length=128)] = ""
    level: Literal["authPriv", "authNoPriv", ""] = ""
    auth_proto: Literal["SHA", "SHA256", "SHA512", ""] = ""
    priv_proto: Literal["AES128", "AES256", "none", ""] = ""
    auth_password: Annotated[str, StringConstraints(max_length=256)] = ""
    priv_password: Annotated[str, StringConstraints(max_length=256)] = ""
    community: Annotated[str, StringConstraints(max_length=128)] = ""


class ScanIn(BaseModel):
    name: Name
    collector_id: Id32
    targets: list[Annotated[str, StringConstraints(max_length=64)]] = Field(max_length=200)
    exclude: list[Annotated[str, StringConstraints(max_length=64)]] = Field(default_factory=list, max_length=200)
    target_notes: dict[str, Annotated[str, StringConstraints(max_length=128)]] = Field(default_factory=dict)
    port_check: bool = True
    concurrency: Literal[20, 64] = 20
    credential_ids: list[Id32] = Field(default_factory=list, max_length=16)
    schedule: Literal["daily", "weekly", "manual"] = "daily"
    schedule_time: Hhmm = "02:00"
    schedule_weekday: int = Field(0, ge=0, le=6)
    enabled: bool = True
    run_now: bool = False


class ScanPatch(BaseModel):
    name: Name | None = None
    collector_id: Id32 | None = None
    targets: list[Annotated[str, StringConstraints(max_length=64)]] | None = Field(None, max_length=200)
    exclude: list[Annotated[str, StringConstraints(max_length=64)]] | None = Field(None, max_length=200)
    target_notes: dict[str, str] | None = None
    port_check: bool | None = None
    concurrency: Literal[20, 64] | None = None
    credential_ids: list[Id32] | None = Field(None, max_length=20)
    schedule: Literal["daily", "weekly", "manual"] | None = None
    schedule_time: Hhmm | None = None
    schedule_weekday: int | None = Field(None, ge=0, le=6)
    enabled: bool | None = None


class TestIn(BaseModel):
    """Test one address with unsaved wizard settings."""
    collector_id: Id32
    address: Annotated[str, StringConstraints(max_length=45)]
    credential_ids: list[Id32] = Field(default_factory=list, max_length=20)
    port_check: bool = True


class SuggestionsRefresh(BaseModel):
    collector_id: Id32


class AddAssetsIn(BaseModel):
    device_ids: list[Id32] = Field(min_length=1, max_length=500)


# ----------------------------------------------------------------------------- collector batches
class SnmpIn(Lenient):
    version: Literal["v3", "v2c"]
    credential_id: str = ""
    sys_name: str = ""
    sys_descr: str = ""
    sys_object_id: str = ""
    sys_location: str = ""
    sys_contact: str = ""
    uptime_s: int | None = None


class InterfaceIn(Lenient):
    index: int = Field(ge=0, le=2**31 - 1)
    name: str = ""
    descr: str = ""
    mac: str = ""
    oper_up: bool = False
    speed_mbps: int | None = Field(None, ge=0, le=10_000_000)


class FdbIn(Lenient):
    mac: str
    port_name: str = ""
    vlan: int | None = Field(None, ge=0, le=4095)


class OpenPortIn(Lenient):
    port: int = Field(ge=1, le=65535)
    proto: Literal["tcp", "udp"] = "tcp"
    service: str | None = None
    banner: str | None = None


class DeviceIn(Lenient):
    ip: str
    mac: str | None = None
    mac_vendor: str | None = None
    hostname: str | None = None
    alive_via: list[Literal["icmp", "arp", "tcp", "snmp"]] = Field(default_factory=list, max_length=3)
    snmp: SnmpIn | None = None
    default_community: Literal["public", "private"] | None = None
    vendor: str | None = None
    model: str | None = None
    firmware: str | None = None
    serial: str | None = None
    device_type: str | None = None
    interfaces: list[InterfaceIn] | None = Field(None, max_length=2048)
    fdb: list[FdbIn] | None = Field(None, max_length=20000)
    open_ports: list[OpenPortIn] = Field(default_factory=list, max_length=64)

    @field_validator("alive_via", mode="before")
    @classmethod
    def _alive(cls, v):
        return [x for x in (v or []) if x in ("icmp", "arp", "tcp", "snmp")]


class SummaryIn(Lenient):
    addresses: int = 0
    alive: int = 0
    snmp: int = 0
    duration_s: float = 0
    errors: list[str] = Field(default_factory=list, max_length=50)


class NetBatchIn(Lenient):
    scan_id: str = Field(max_length=64)
    seq: int = Field(ge=0, le=1_000_000)
    final: bool = False
    devices: list[DeviceIn] = Field(default_factory=list, max_length=500)
    summary: SummaryIn | None = None
