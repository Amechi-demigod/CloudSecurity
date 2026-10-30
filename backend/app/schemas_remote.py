"""Pydantic schemas for attended remote sessions (/api/devices/{id}/remote-sessions,
/api/remote-sessions/*). The relay's WebSocket protocol is described in
app/api/remote_relay.py."""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints

from .schemas import ORM, UTCDateTime

RemoteMode = Literal["view", "control"]


class RemoteSessionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: RemoteMode = "view"
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=500)]


class RemoteSessionOut(ORM):
    id: str
    device_id: str
    mode: str
    reason: str
    state: str
    end_reason: str | None
    error_code: str | None
    requested_by_email: str
    requested_by_name: str
    created_at: UTCDateTime
    agent_connected_at: UTCDateTime | None
    consented_at: UTCDateTime | None
    started_at: UTCDateTime | None
    ended_at: UTCDateTime | None
    ended_by_email: str | None
    duration_seconds: int | None = None
    bytes_to_viewer: int = 0
    bytes_to_agent: int = 0


class RemoteAvailabilityOut(BaseModel):
    available: bool
    reason: str | None = None
    # The modes the signed-in user may start on this device.
    modes: list[RemoteMode]
    open_session_id: str | None = None
