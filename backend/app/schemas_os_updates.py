"""Agent input for the missing-OS-updates report (POST /api/agent/os-updates,
docs/PATCHING.md): the result of a Windows Update Agent search, strictly
validated and size-limited like every other agent document."""
from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Literal

from pydantic import Field, StringConstraints

from .schemas_devices import Str1k, Str255, Strict

# Windows Update classifications (the UpdateClassification category), normalised by the agent.
Classification = Literal["security", "critical", "definition", "feature_pack", "service_pack", "tool",
                         "update_rollup", "update", "driver", "upgrade", "other"]
SECURITY_CLASSIFICATIONS = ("security", "critical")
UPDATE_SOURCES = ("wsus", "wufb", "microsoft_update", "windows_update", "unknown")
MAX_UPDATES = 1000

KbId = Annotated[str, StringConstraints(pattern=r"^KB[0-9]{4,10}$")]
CveId = Annotated[str, StringConstraints(pattern=r"^CVE-[0-9]{4}-[0-9]{4,8}$")]
UpdateGuid = Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F-]{1,64}$", to_lower=True)] | Literal[""]
State = Annotated[str, StringConstraints(pattern=r"^[a-z_]{0,24}$")]


class OsUpdateItem(Strict):
    update_id: UpdateGuid = ""
    kb_ids: list[KbId] = Field(default_factory=list, max_length=16)
    title: Annotated[str, StringConstraints(max_length=512)] = Field(min_length=1)
    classification: Classification = "other"
    # MSRC severity of security updates ("" = not rated).
    msrc_severity: Literal["Critical", "Important", "Moderate", "Low", "Unspecified", ""] = ""
    # LastDeploymentChangeTime: when the update was published to this source.
    release_date: date | None = None
    cve_ids: list[CveId] = Field(default_factory=list, max_length=500)
    reboot_behavior: Literal["never", "always", "can_request", ""] = ""
    size_bytes: int | None = Field(None, ge=0, le=2**42)
    downloaded: bool = False


class OsUpdateReportIn(Strict):
    schema_version: Literal[1] = 1
    scanned_at: datetime
    status: Literal["ok", "failed"]
    error: Str1k = ""
    trigger: Literal["schedule", "command"] = "schedule"
    duration_seconds: int | None = Field(None, ge=0, le=86400)
    source: Literal["wsus", "wufb", "microsoft_update", "windows_update", "unknown"] = "unknown"
    source_detail: Str255 = ""
    service_state: State = ""
    service_start_type: State = ""
    reboot_pending: bool = False
    last_search_success_at: datetime | None = None
    last_install_success_at: datetime | None = None
    # Missing updates; only meaningful when status == "ok" (a failed search keeps the previous list).
    updates: list[OsUpdateItem] = Field(default_factory=list, max_length=MAX_UPDATES)
