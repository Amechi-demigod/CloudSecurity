"""Alert notifications & integrations (Teams, Slack, email, signed webhooks).

Public interface for producers:

    from app.notifications import Event, EventSource, emit, register_source

See events.py for the event model and docs/NOTIFICATIONS.md for setup.
"""
from __future__ import annotations

from . import (
    agent_security,  # noqa: F401  (spikes of rejected endpoint-agent requests)
    agent_update_source,  # noqa: F401  (agent auto-update failures and rollbacks)
    approval_source,  # noqa: F401  (two-person approvals of high-risk device actions)
    asset_lifecycle_source,  # noqa: F401  (IT assets: overdue retrievals, warranties, unseen devices)
    builtin,  # noqa: F401  (registers the built-in sources)
    device_source,  # noqa: F401  (endpoint devices: posture issues, connectivity, remote actions)
    host_isolation_source,  # noqa: F401  (host isolation: sign-in suspension and restore)
    remote_session_source,  # noqa: F401  (attended remote desktop sessions)
    server_update_source,  # noqa: F401  (on-prem server updates: failures and automatic rollbacks)
)
from .events import SEVERITIES, Event, EventSource, emit, register_source, sources

__all__ = ["SEVERITIES", "Event", "EventSource", "emit", "register_source", "sources"]
