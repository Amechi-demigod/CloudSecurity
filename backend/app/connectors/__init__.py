"""Connector registry. Add new providers (AWS, GCP, ...) here."""
from __future__ import annotations

from ..config import Settings
from .azure import AzureConnector
from .base import Connector
from .simulated import SimulatedConnector


def build_registry(settings: Settings) -> dict[str, Connector]:
    return {
        "simulated": SimulatedConnector(seed=settings.seed),
        "azure": AzureConnector(settings),
    }
