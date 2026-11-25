"""Device tracking as a notification source ("device_tracking", label "Device tracking").

Events are raised by app/tracking/alerts.py in the same transaction as the alert row. The text only ever holds a
city and a country (never an internet address or coordinates). Belongs to the Endpoints & servers module.
"""
from __future__ import annotations

import logging
from urllib.parse import quote

from sqlalchemy.orm import Session

from .events import Event, EventSource, emit, register_source

log = logging.getLogger(__name__)

SOURCE = "device_tracking"
EVENT_TYPES = ("outside_countries", "not_seen", "after_hours", "hardware_changed", "agent_stopped",
               "auto_lost_mode")
SEVERITY = {"outside_countries": "high", "auto_lost_mode": "high", "not_seen": "medium", "after_hours": "medium",
            "hardware_changed": "medium", "agent_stopped": "medium"}


def notify(db: Session, device, kind: str, title: str, summary: str = "", **attrs) -> bool:
    """Queue the notification event; False when the organisation does not have the module (or on any error)."""
    try:
        row = emit(db, Event(
            source=SOURCE, event_type=kind, severity=SEVERITY[kind], title=title[:255], summary=summary[:1000],
            entity_id=device.id, group_key=f"{SOURCE}:{device.id}:{kind}", rule_id=kind,
            link_path=f"/devices/{quote(str(device.id), safe='')}",
            attributes={"asset_type": "device", "asset_name": device.hostname, "hostname": device.hostname,
                        "os_family": device.os_family, **attrs}))
        return row is not None
    except Exception:  # notifications must never break the agent API
        log.exception("failed to queue device tracking notification")
        return False


register_source(EventSource(
    SOURCE, "Device tracking", EVENT_TYPES,
    "Company laptops and desktops: connected from outside the allowed countries, not seen for several days, away "
    "from offices after hours, hardware changed, agent stopped, and automatic lost mode (location from the "
    "internet address, city level)."))
