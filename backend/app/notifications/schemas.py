"""API schemas for notification channels, rules and the delivery log."""
from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..schemas import UTCDateTime
from .events import SEVERITIES
from .rules import zone

ChannelType = Literal["teams", "slack", "email", "webhook"]
Sev = Literal["info", "low", "medium", "high", "critical"]
_HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_SHORT = Field(default_factory=list, max_length=200)


class ChannelIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    type: ChannelType
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    # Write-only. Never returned by the API.
    secrets: dict[str, str] = Field(default_factory=dict)


class ChannelUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=128)
    enabled: bool | None = None
    config: dict[str, Any] | None = None
    # Only the secret fields given are replaced; omitted ones are kept.
    secrets: dict[str, str] | None = None


class ChannelOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    type: str
    enabled: bool
    config: dict[str, Any]
    secret_hints: dict[str, str]
    created_by: str | None = None
    created_at: UTCDateTime
    updated_at: UTCDateTime
    last_test_at: UTCDateTime | None = None
    last_test_status: str | None = None


class RuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    enabled: bool = True
    sources: list[str] = _SHORT
    event_types: list[str] = _SHORT
    min_severity: Sev = "high"
    subscription_ids: list[str] = _SHORT
    asset_ids: list[str] = _SHORT
    asset_types: list[str] = _SHORT
    tags: dict[str, str] = Field(default_factory=dict)
    rule_ids: list[str] = _SHORT
    mitre_techniques: list[str] = _SHORT
    include_status_changes: bool = False
    channel_ids: list[str] = Field(min_length=1, max_length=20)
    throttle_minutes: int = Field(60, ge=0, le=7 * 24 * 60)
    mode: Literal["immediate", "digest"] = "immediate"
    digest_hour: int = Field(8, ge=0, le=23)
    timezone: str = "UTC"
    quiet_start: str | None = None
    quiet_end: str | None = None
    quiet_bypass_severity: Sev | None = None

    @field_validator("sources", "event_types", "subscription_ids", "asset_ids", "asset_types", "rule_ids",
                     "mitre_techniques")
    @classmethod
    def _clean_list(cls, v: list[str]) -> list[str]:
        out = []
        for item in v:
            s = str(item).strip()
            if s and len(s) <= 512 and s not in out:
                out.append(s)
        return out

    @field_validator("mitre_techniques")
    @classmethod
    def _techniques(cls, v: list[str]) -> list[str]:
        for t in v:
            if not re.match(r"^T\d{4}(\.\d{3})?$", t.upper()):
                raise ValueError(f"invalid MITRE technique id {t!r} (expected e.g. T1059 or T1059.004)")
        return [t.upper() for t in v]

    @field_validator("quiet_start", "quiet_end")
    @classmethod
    def _hhmm(cls, v: str | None) -> str | None:
        if v in (None, ""):
            return None
        if not _HHMM.match(v):
            raise ValueError("expected HH:MM (24h)")
        return v

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v: str) -> str:
        v = (v or "UTC").strip()
        if zone(v).key != v and v != "UTC":
            raise ValueError(f"unknown time zone {v!r}")
        return v

    @field_validator("tags")
    @classmethod
    def _tags(cls, v: dict[str, str]) -> dict[str, str]:
        if len(v) > 50:
            raise ValueError("at most 50 tags")
        return {str(k).strip(): str(val).strip() for k, val in v.items() if str(k).strip()}


class RuleOut(RuleIn):
    model_config = ConfigDict(from_attributes=True)

    id: str
    channel_ids: list[str]
    last_digest_at: UTCDateTime | None = None
    created_by: str | None = None
    created_at: UTCDateTime
    updated_at: UTCDateTime


class DeliveryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: UTCDateTime
    channel_id: str | None
    channel_name: str
    channel_type: str
    rule_id: str | None
    rule_name: str
    event_id: str | None
    kind: str
    severity: str
    title: str
    status: str
    attempts: int
    next_attempt_at: UTCDateTime
    last_attempt_at: UTCDateTime | None
    sent_at: UTCDateTime | None
    response_status: int | None
    last_error: str | None
    link: str | None = None


class ChannelTestResult(BaseModel):
    ok: bool
    delivery: DeliveryOut


SEVERITY_VALUES = list(SEVERITIES)
