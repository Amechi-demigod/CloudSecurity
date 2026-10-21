"""Agent auto-update as a notification source: an agent rejected a release
(bad signature, hash mismatch, downgrade...), failed to install it, or rolled
back automatically because the new version did not check in.

Imports of the device modules are deferred (loaded while app.models imports).
"""
from __future__ import annotations

import logging
from urllib.parse import quote

from sqlalchemy.orm import Session

from .events import Event, EventSource, emit, register_source

log = logging.getLogger(__name__)

SOURCE = "agent_update"
EVENT_TYPES = ("update_rolled_back", "update_failed", "update_rejected",
               # Automatic rollout and GitHub Releases auto-import (app/services/agent_update_auto.py).
               "rollout_started", "rollout_promoted", "rollout_paused", "release_imported", "release_import_failed")
SEVERITY = {"update_rolled_back": "medium", "update_failed": "low", "update_rejected": "high"}
TITLES = {"update_rolled_back": "Agent update rolled back", "update_failed": "Agent update failed",
          "update_rejected": "Agent update rejected", "rollout_started": "Agent rollout started (Pilot)",
          "rollout_promoted": "Agent rollout promoted to all devices", "rollout_paused": "Agent rollout paused",
          "release_imported": "Agent release imported", "release_import_failed": "Agent release import refused"}


def update_failed(db: Session, device, status: str, from_version: str, to_version: str, detail: str) -> None:
    event_type = f"update_{status}"
    if event_type not in EVENT_TYPES:
        return
    try:
        emit(db, Event(
            source=SOURCE, event_type=event_type, severity=SEVERITY[event_type],
            title=f"{TITLES[event_type]} on {device.hostname} ({from_version} -> {to_version})",
            summary=(detail or "")[:1000], entity_id=device.id,
            group_key=f"{SOURCE}:{device.id}:{to_version}:{status}", rule_id=event_type,
            link_path=f"/devices/{quote(str(device.id), safe='')}",
            attributes={"asset_type": "device", "asset_name": device.hostname, "hostname": device.hostname,
                        "os_family": device.os_family, "from_version": from_version, "to_version": to_version,
                        "status": status},
        ))
    except Exception:  # notifications must never break the agent API
        log.exception("failed to queue agent update notification")


def _fleet_event(db: Session, event_type: str, version: str, summary: str, severity: str) -> None:
    try:
        emit(db, Event(
            source=SOURCE, event_type=event_type, severity=severity, title=f"{TITLES[event_type]}: {version}",
            summary=summary[:1000], entity_id=f"agent-release:{version}"[:64],
            group_key=f"{SOURCE}:{event_type}:{version}", rule_id=event_type, link_path="/devices/updates",
            attributes={"asset_type": "agent_release", "asset_name": version, "to_version": version},
        ))
    except Exception:  # notifications must never break the rollout
        log.exception("failed to queue agent rollout notification")


def rollout_event(db: Session, event_type: str, version: str, summary: str, severity: str = "info") -> None:
    """Automatic rollout: started (Pilot), promoted (everyone), paused (Pilot failures)."""
    _fleet_event(db, event_type, version, summary, severity)


def import_event(db: Session, event_type: str, version: str, summary: str, severity: str = "info") -> None:
    """GitHub Releases auto-import: imported, or refused (signature / hashes / expiry)."""
    _fleet_event(db, event_type, version, summary, severity)


register_source(EventSource(
    SOURCE, "Agent auto-update", EVENT_TYPES,
    "Endpoint agents that rejected a signed release (signature, hash, downgrade), failed to install it, "
    "or rolled back automatically after a failed health check; automatic rollout steps (Pilot, everyone, "
    "paused) and releases auto-imported from GitHub (or refused)."))
