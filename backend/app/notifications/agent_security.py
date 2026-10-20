"""Rejected endpoint-agent requests as a notification source ("agent_security").

When the agent API is reachable from the internet, a burst of rejected requests
(unknown / revoked device credentials, failed enrollments, rate limits) usually
means someone is probing it. Each backend worker counts rejections in a sliding
window; when AGENT_AUTH_ALERT_THRESHOLD is reached it writes one audit record
(`agent_auth_failure_spike`) and queues one notification event, then stays quiet
for the rest of the window. Notification rules can route the event (source
"agent_security") to Teams / Slack / email like any other source.

Counting is in memory and per process (like the API rate limiters): with N
workers the effective threshold is between THRESHOLD and N x THRESHOLD.
Requests rejected by nginx itself (limit_req, non-agent paths) never reach the
backend; fail2ban covers those (docs/DEPLOY_ONPREM.md).
"""
from __future__ import annotations

import logging
import threading
import time
from collections import Counter, deque

from .events import Event, EventSource, emit, register_source

log = logging.getLogger(__name__)

SOURCE = "agent_security"
SPIKE = "auth_failure_spike"
EVENT_TYPES = (SPIKE,)


class RejectionMonitor:
    def __init__(self) -> None:
        self._events: deque[tuple[float, str, str]] = deque()
        self._lock = threading.Lock()
        self._quiet_until = 0.0

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
            self._quiet_until = 0.0

    def record(self, kind: str, ip: str, *, threshold: int, window: float, now: float | None = None) -> dict | None:
        """Count one rejection; return a summary when the threshold is crossed (at most once per window)."""
        if threshold <= 0:
            return None
        now = time.monotonic() if now is None else now
        with self._lock:
            self._events.append((now, kind, ip))
            while self._events and self._events[0][0] <= now - window:
                self._events.popleft()
            while len(self._events) > max(threshold * 4, 1000):  # bound memory under a flood
                self._events.popleft()
            if len(self._events) < threshold or now < self._quiet_until:
                return None
            self._quiet_until = now + window
            kinds = Counter(k for _, k, _ in self._events)
            ips = Counter(i for _, _, i in self._events)
            return {"count": len(self._events), "window_seconds": int(window), "by_kind": dict(kinds),
                    "top_ips": [{"ip": i, "count": c} for i, c in ips.most_common(5)],
                    "distinct_ips": len(ips)}


monitor = RejectionMonitor()
# The alert is written by a short-lived thread in its own transaction, so the
# rejected request is not slowed down (tests with a single shared in-memory
# SQLite connection switch this off).
ASYNC_ALERTS = True


def rejected(kind: str, ip: str) -> None:
    """Record a rejected agent request (never raises, never slows the request noticeably)."""
    from .. import config

    s = config.settings
    try:
        summary = monitor.record(kind, ip, threshold=s.agent_auth_alert_threshold,
                                 window=s.agent_auth_alert_window_seconds)
        if summary is not None:
            if ASYNC_ALERTS:
                threading.Thread(target=_alert_safe, args=(summary,), name="agent-auth-alert", daemon=True).start()
            else:
                _alert_safe(summary)
    except Exception:  # monitoring must never break the agent API
        log.exception("agent rejection monitoring failed")


def _alert_safe(summary: dict) -> None:
    try:
        _alert(summary)
    except Exception:
        log.exception("failed to record the agent rejection alert")


def _alert(summary: dict) -> None:
    from .. import db as dbmod
    from ..auth import audit

    top = ", ".join(f"{t['ip']} ({t['count']})" for t in summary["top_ips"])
    minutes = max(1, summary["window_seconds"] // 60)
    log.warning("agent API: %d rejected requests in %d min (top sources: %s)", summary["count"], minutes, top)
    session = dbmod.get_session()
    try:
        audit(session, "agent_auth_failure_spike", actor_email="system:agent-api", **summary)
        emit(session, Event(
            source=SOURCE, event_type=SPIKE, severity="high",
            title=f"Spike of rejected endpoint-agent requests ({summary['count']} in {minutes} min)",
            summary=(f"{summary['count']} agent API requests were rejected in the last {minutes} minutes "
                     f"(by reason: {summary['by_kind']}; {summary['distinct_ips']} source address(es); "
                     f"top: {top}). Possible credential guessing or a misconfigured fleet."),
            group_key=f"{SOURCE}:{SPIKE}", rule_id=SPIKE, link_path="/devices",
            attributes={"asset_type": "agent_api", **summary}))
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


register_source(EventSource(
    SOURCE, "Agent API security", EVENT_TYPES,
    "Spikes of rejected endpoint-agent requests (invalid or revoked device credentials, failed enrollments, "
    "rate limits): possible attack on the internet-facing agent endpoint."))
