"""Pluggable connector interface.

A connector discovers cloud resources (and optionally vulnerabilities) and
returns them in a provider-agnostic `CollectionResult`. The ingest service
(`app/services/ingest.py`) then upserts them into the inventory and runs the
posture rules engine. Providers (Azure, AWS, GCP) implement `Connector` and are
registered in `app/connectors/__init__.py::build_registry`. Manual "Run scan"
and scheduled scans both go through `app/services/scans.py::start_scan`, which
only runs connectors whose `is_configured()` is true.

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


SENSITIVE_TAG_KEYS = {"data_classification", "data-classification", "dataclassification", "classification",
                      "sensitivity", "data"}
NON_SENSITIVE_VALUES = {"public", "none", "non-sensitive", "nonsensitive", "general"}


def sensitive_from_tags(tags: dict | None) -> tuple[bool, str | None]:
    """(is_sensitive, classification) from tags / labels such as data-classification=PII."""
    for k, v in (tags or {}).items():
        if k.lower() in SENSITIVE_TAG_KEYS and str(v).lower() not in NON_SENSITIVE_VALUES:
            return True, str(v)
    return False, None


class ScopeAccessError(Exception):
    """A connection test call failed for one subscription / account / project."""

    def __init__(self, scope: str, cause: Exception):
        super().__init__(f"{scope}: {type(cause).__name__}")
        self.scope = scope
        self.cause = cause


class Connector(ABC):
    #: unique key, also used as `source` on stored rows
    name: str = "base"
    provider: str = "unknown"
    description: str = ""
    #: shown when a scan is requested while `is_configured()` is false
    setup_hint: str = ""

    @abstractmethod
    def is_configured(self) -> bool:
        """True if credentials / settings needed to run are present."""

    @abstractmethod
    def collect(self) -> CollectionResult:
        """Discover resources. MUST be read-only against the cloud provider."""

    def check_access(self) -> list[dict[str, str]]:
        """Connection test: one minimal read-only call per configured scope, through
        the provider's read-only client wrapper. Returns the scopes reached
        ([{"id", "name"}]) and raises `ScopeAccessError` on the first one that
        fails (app/connectors/access_check.py adds the timeout and the message)."""
        raise NotImplementedError

    def scope(self) -> list[str]:
        """Configured scan targets (subscriptions, accounts, projects...), for the UI."""
        return []

    def info(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "provider": self.provider,
            "description": self.description,
            "configured": self.is_configured(),
            "scope": self.scope(),
            "setup_hint": self.setup_hint,
        }
