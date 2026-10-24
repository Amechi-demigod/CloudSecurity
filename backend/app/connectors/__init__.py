"""Connector registry: every provider the platform can scan.

Each connector exposes `is_configured()`; manual "Run scan" (POST /api/scans)
and scheduled scans run them through `app/services/scans.py::start_scan`.
"""
from __future__ import annotations

from ..config import Settings
from .aws import AwsConnector
from .azure import AzureConnector
from .base import Connector
from .gcp import GcpConnector
from .simulated import SimulatedConnector

#: Real cloud connectors (excludes the simulated demo data source).
CLOUD_CONNECTORS = ("azure", "aws", "gcp")


def build_registry(settings: Settings) -> dict[str, Connector]:
    return {
        "simulated": SimulatedConnector(seed=settings.seed, simulation_mode=settings.simulation_mode,
                                        available=settings.simulated_connector_available),
        "azure": AzureConnector(settings),
        "aws": AwsConnector(settings),
        "gcp": GcpConnector(settings),
    }


def configured_cloud_connectors(settings: Settings) -> list[Connector]:
    """The real cloud connectors that have credentials and scope configured."""
    reg = build_registry(settings)
    return [reg[n] for n in CLOUD_CONNECTORS if reg[n].is_configured()]
