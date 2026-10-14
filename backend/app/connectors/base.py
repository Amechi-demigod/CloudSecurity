"""Pluggable connector interface.

A connector discovers cloud resources (and optionally vulnerabilities) and
returns them in a provider-agnostic `CollectionResult`. The ingest service
(`app/services/ingest.py`) then upserts them into the inventory and runs the
posture rules engine. To add AWS/GCP, implement `Connector` and register it in
`app/connectors/__init__.py::REGISTRY`.

Runtime sensors (e.g. a future eBPF agent) do not implement this interface;
they push events to `POST /api/runtime/events` instead.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AssetRecord:
    id: str
    name: str
    type: str
    provider: str = "azure"
    subscription_id: str | None = None
    subscription_name: str | None = None
    resource_group: str | None = None
    region: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    internet_exposed: bool = False
    sensitive_data: bool = False
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class RelationshipRecord:
    source_id: str
    target_id: str
    type: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnerabilityRecord:
    asset_id: str
    cve_id: str
    package: str
    version: str
    cvss: float
    fixed_version: str | None = None
    title: str = ""
    exploit_available: bool = False
    in_use: bool = False


@dataclass
class CollectionResult:
    assets: list[AssetRecord] = field(default_factory=list)
    relationships: list[RelationshipRecord] = field(default_factory=list)
    vulnerabilities: list[VulnerabilityRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class Connector(ABC):
    #: unique key, also used as `source` on stored rows
    name: str = "base"
    provider: str = "unknown"
    description: str = ""

    @abstractmethod
    def is_configured(self) -> bool:
        """True if credentials / settings needed to run are present."""

    @abstractmethod
    def collect(self) -> CollectionResult:
        """Discover resources. MUST be read-only against the cloud provider."""

    def info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "provider": self.provider,
            "description": self.description,
            "configured": self.is_configured(),
        }
