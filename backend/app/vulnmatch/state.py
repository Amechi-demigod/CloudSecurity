"""Cheap bookkeeping called from request handlers (agent check-in, sensor
package ingest): remember that a device's / asset's inventory changed so the
background worker re-matches it after the debounce period. Never does network
I/O and never raises into the caller."""
from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import VulnMatchState, utcnow

log = logging.getLogger(__name__)

DEVICE = "device"
ASSET = "asset"


def inventory_hash(items: Iterable) -> str:
    return hashlib.sha256(json.dumps(sorted(items), separators=(",", ":"), default=str).encode()).hexdigest()


def get_state(db: Session, target_type: str, target_id: str) -> VulnMatchState | None:
    return db.scalar(select(VulnMatchState).where(VulnMatchState.target_type == target_type,
                                                  VulnMatchState.target_id == target_id))


def inventory_changed(db: Session, target_type: str, target_id: str, digest: str,
                      now: datetime | None = None) -> bool:
    """Record the inventory digest; request a re-match when it changed.
    Returns True if a match was requested."""
    try:
        now = now or utcnow()
        st = get_state(db, target_type, target_id)
        if st is None:
            st = VulnMatchState(target_type=target_type, target_id=target_id, inventory_hash="", checked=[],
                                not_checked=[], os_info={})
            db.add(st)
        if st.inventory_hash == digest and st.matched_at is not None:
            return False
        st.inventory_hash = digest
        st.requested_at = now  # debounced: the worker waits VULN_DEBOUNCE_SECONDS after the last change
        return True
    except Exception:  # bookkeeping must never break a check-in
        log.exception("could not queue vulnerability matching for %s %s", target_type, target_id)
        return False


def device_inventory_digest(device, software) -> str:
    items = [("os", device.os_family, device.os_name, device.os_version, device.os_build, device.architecture)]
    items += [("sw", s.name, s.version, s.publisher, s.identifier) for s in software]
    return inventory_hash(items)
