"""In-memory pairing of the two WebSockets of a remote session (relay process).

Both ends of a session must reach the same process, so the relay runs as ONE
uvicorn worker (the on-prem `relay` service; REMOTE_RELAY_MODE=relay) while the
REST API keeps its gunicorn workers. State shared with the API lives in the
remote_sessions rows (app/services/remote_sessions.py), re-read by each pair's
watchdog every REMOTE_SESSION_RECHECK_SECONDS.

Nothing here logs or stores frame content or keystrokes: only message types,
byte counts and timestamps.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from fastapi import WebSocket
from starlette.concurrency import run_in_threadpool
from starlette.websockets import WebSocketState

from . import config, db
from .auth import org_user
from .models import RemoteSession, utcnow
from .services import remote_sessions as rsvc

log = logging.getLogger("cnapp.remote")

# How long a viewer may be gone (tab reload, network blip) before the session ends.
VIEWER_RECONNECT_GRACE = timedelta(seconds=30)
PING_SECONDS = 20.0

# Messages the relay forwards, by direction. Anything else is dropped.
VIEWER_TO_AGENT = frozenset({"input", "cad", "ack", "select_monitor", "quality", "activity"})
CONTROL_ONLY = frozenset({"input", "cad"})
AGENT_TO_VIEWER = frozenset({"monitors", "protected", "stats", "cursor"})
# End reasons an agent may report; anything else is recorded as "agent_ended".
AGENT_END_REASONS = frozenset({"user_ended", "session_switch", "user_locked", "indicator_closed", "helper_exit",
                               "idle", "max_duration", "server_unreachable", "agent_stopping", "error"})


class TokenBucket:
    """`rate` units per second with bursts of up to `capacity`."""

    def __init__(self, rate: float, capacity: float, clock: Callable[[], float] = time.monotonic):
        self.rate, self.capacity, self.clock = rate, capacity, clock
        self.tokens, self.stamp = capacity, clock()

    def take(self, n: float = 1.0) -> bool:
        now = self.clock()
        self.tokens = min(self.capacity, self.tokens + (now - self.stamp) * self.rate)
        self.stamp = now
        if self.tokens < n:
            return False
        self.tokens -= n
        return True


@dataclass
class End:
    reason: str
    code: int = rsvc.CLOSE_ENDED
    # Callable(db, rs) applying the final state; default: rsvc.end(...).
    apply: Callable | None = None


@dataclass
class Pair:
    session_id: str
    org_id: str
    mode: str
    agent: WebSocket | None = None
    viewer: WebSocket | None = None
    agent_ip: str | None = None
    viewer_ip: str | None = None
    viewer_user_id: str | None = None
    viewer_gone_at: datetime | None = None
    state: str = "requested"
    monitors: str | None = None  # last monitor list (replayed to a reconnecting viewer)
    to_viewer: int = 0  # since the last flush to the database
    to_agent: int = 0
    total_to_viewer: int = 0
    total_to_agent: int = 0
    dropped_input: int = 0
    activity_at: datetime | None = None
    finished: asyncio.Event = field(default_factory=asyncio.Event)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    send_locks: dict[int, asyncio.Lock] = field(default_factory=dict)
    watchdog: asyncio.Task | None = None


async def _threaded(fn, *args):
    return await run_in_threadpool(fn, *args)


def _session(org_id: str):
    return db.get_session(org_id)


class Hub:
    def __init__(self) -> None:
        self.pairs: dict[str, Pair] = {}

    # ------------------------------------------------------------------ sending
    async def send_text(self, pair: Pair, ws: WebSocket | None, msg: dict | str) -> None:
        if ws is None or ws.application_state != WebSocketState.CONNECTED:
            return
        data = msg if isinstance(msg, str) else json.dumps(msg, separators=(",", ":"))
        lock = pair.send_locks.setdefault(id(ws), asyncio.Lock())
        try:
            async with lock:
                await ws.send_text(data)
        except Exception:  # the peer went away; its receive loop finishes the pair
            log.debug("send to a closed remote-session socket", exc_info=True)

    async def send_bytes(self, pair: Pair, ws: WebSocket | None, data: bytes) -> bool:
        if ws is None or ws.application_state != WebSocketState.CONNECTED:
            return False
        lock = pair.send_locks.setdefault(id(ws), asyncio.Lock())
        try:
            async with lock:
                await ws.send_bytes(data)
            return True
        except Exception:
            return False

    async def state_to_viewer(self, pair: Pair, **extra) -> None:
        await self.send_text(pair, pair.viewer, {"t": "state", "state": pair.state, "mode": pair.mode, **extra})

    # ------------------------------------------------------------------ pairing
    def get_or_create(self, session_id: str, org_id: str, mode: str, state: str) -> Pair:
        pair = self.pairs.get(session_id)
        if pair is None or pair.finished.is_set():
            pair = Pair(session_id=session_id, org_id=org_id, mode=mode, state=state)
            self.pairs[session_id] = pair
            pair.watchdog = asyncio.create_task(self._watchdog(pair), name=f"remote-watchdog-{session_id[:8]}")
        return pair

    async def finish(self, pair: Pair, end: End) -> None:
        """End the session once: record it, tell both ends, close both sockets."""
        async with pair.lock:
            if pair.finished.is_set():
                return
            pair.finished.set()
        try:
            await _threaded(self._record_end, pair, end)
        except Exception:
            log.exception("recording the end of remote session %s failed", pair.session_id)
        pair.state = "ended"
        await self.send_text(pair, pair.agent, {"t": "end", "reason": end.reason})
        await self.state_to_viewer(pair, reason=end.reason)
        for ws in (pair.agent, pair.viewer):
            if ws is not None and ws.application_state == WebSocketState.CONNECTED:
                try:
                    await ws.close(end.code, end.reason[:100])
                except Exception:  # already closed by the peer
                    log.debug("closing a remote-session socket failed", exc_info=True)
        if self.pairs.get(pair.session_id) is pair:
            del self.pairs[pair.session_id]
        if pair.watchdog and pair.watchdog is not asyncio.current_task():
            pair.watchdog.cancel()
        log.info("remote session %s finished: %s (to viewer %d B, to agent %d B, dropped input %d)",
                 pair.session_id, end.reason, pair.total_to_viewer, pair.total_to_agent, pair.dropped_input)

    def _record_end(self, pair: Pair, end: End) -> None:
        with _session(pair.org_id) as s:
            rs = s.get(RemoteSession, pair.session_id)
            if rs is None:
                return
            self._flush(rs, pair)
            if end.apply is not None:
                end.apply(s, rs)
            else:
                rsvc.apply_end(s, rs, end.reason, ip=pair.agent_ip)
            s.commit()

    @staticmethod
    def _flush(rs: RemoteSession, pair: Pair) -> None:
        rsvc.heartbeat(None, rs, to_viewer=pair.to_viewer, to_agent=pair.to_agent, activity_at=pair.activity_at)
        pair.total_to_viewer += pair.to_viewer
        pair.total_to_agent += pair.to_agent
        pair.to_viewer = pair.to_agent = 0

    async def shutdown(self, reason: str = "relay_restart") -> None:
        for pair in list(self.pairs.values()):
            await self.finish(pair, End(reason, 1012))

    # ------------------------------------------------------------------ watchdog
    async def _watchdog(self, pair: Pair) -> None:
        interval = config.settings.remote_session_recheck_seconds
        last_ping = time.monotonic()
        try:
            while not pair.finished.is_set():
                try:
                    await asyncio.wait_for(pair.finished.wait(), timeout=interval)
                    return
                except TimeoutError:
                    pass
                if (pair.viewer is None and pair.viewer_gone_at is not None
                        and utcnow() - pair.viewer_gone_at >= VIEWER_RECONNECT_GRACE):
                    await self.finish(pair, End("viewer_disconnected"))
                    return
                reason = await _threaded(self._recheck, pair)
                if reason:
                    code = rsvc.CLOSE_IDLE if reason == "idle" else rsvc.CLOSE_ENDED
                    await self.finish(pair, End(reason, code))
                    return
                if time.monotonic() - last_ping >= PING_SECONDS:
                    last_ping = time.monotonic()
                    await self.send_text(pair, pair.agent, {"t": "ping"})
                    await self.send_text(pair, pair.viewer, {"t": "ping"})
        except asyncio.CancelledError:
            pass
        except Exception:
            log.exception("remote session watchdog %s failed", pair.session_id)
            await self.finish(pair, End("relay_error", 1011))

    def _recheck(self, pair: Pair) -> str | None:
        with _session(pair.org_id) as s:
            rs = s.get(RemoteSession, pair.session_id)
            if rs is None:
                return "deleted"
            if not rsvc.is_open(rs):  # ended elsewhere (API, revoke, sweep): close the sockets
                return rs.end_reason or rs.state
            if rs.state in ("awaiting_consent", "active"):
                self._flush(rs, pair)
            reason = rsvc.check_live(s, rs)
            s.commit()
            return reason

    # ------------------------------------------------------------------ transitions (threaded)
    def agent_message(self, pair: Pair, kind: str, msg: dict) -> End | None:
        """consent / started / ended / error from the agent. Returns an End when
        the message ends the session (its DB state already applied)."""
        with _session(pair.org_id) as s:
            rs = s.get(RemoteSession, pair.session_id)
            if rs is None or not rsvc.is_open(rs):
                return End("ended")
            end = None
            if kind == "consent":
                if msg.get("allow") is True:
                    rsvc.consented(s, rs, ip=pair.agent_ip)
                else:
                    why = "consent_timeout" if msg.get("reason") == "timeout" else "user_denied"
                    rsvc.deny(s, rs, why, ip=pair.agent_ip)
                    end = End(why, apply=lambda _s, _rs: None)
            elif kind == "started":
                rsvc.started(s, rs, ip=pair.agent_ip)
            elif kind == "ended":
                why = msg.get("reason") if msg.get("reason") in AGENT_END_REASONS else "agent_ended"
                self._flush(rs, pair)
                rsvc.end(s, rs, why, by_email=f"device:{rs.device_id}", ip=pair.agent_ip)
                end = End(why, apply=lambda _s, _rs: None)
            elif kind == "error":
                code = str(msg.get("code") or "ERR_AGENT")[:48]
                if code not in rsvc.AGENT_ERRORS:
                    code = "ERR_AGENT"
                if rs.state == "active":
                    self._flush(rs, pair)
                    rsvc.end(s, rs, "agent_error", by_email=f"device:{rs.device_id}", ip=pair.agent_ip)
                else:
                    rsvc.fail(s, rs, code, ip=pair.agent_ip, detail=str(msg.get("detail") or "")[:500])
                end = End("agent_error", apply=lambda _s, _rs: None)
            pair.state = rs.state
            s.commit()
            return end

    def viewer_end(self, pair: Pair) -> End:
        def apply(s, rs):
            user = org_user(s, pair.viewer_user_id) if pair.viewer_user_id else None
            rsvc.end(s, rs, "ended_by_viewer", actor=user, by_email=None if user else "viewer", ip=pair.viewer_ip)
        return End("ended_by_viewer", apply=apply)


hub = Hub()


def relay_enabled() -> bool:
    return config.settings.remote_relay_mode in ("all", "relay") and config.settings.remote_session_enabled
