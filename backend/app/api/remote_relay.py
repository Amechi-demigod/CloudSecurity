"""Remote-session relay: the two WebSockets of an attended remote session.

    agent   wss /api/agent/remote/{session_id}
            Authorization: Bearer <device secret>, X-Remote-Session-Token: <single-use token>
    viewer  wss /api/remote/{session_id}      session cookie, Origin must be this server

Neither side accepts inbound connections: both dial out to this server, which
pairs them in memory (app/remote_hub.py; one relay process) and forwards their
messages. A second connection for either end is refused.

Protocol (version 1)
--------------------
Text frames are JSON objects with a type "t". Binary frames are screen tiles,
agent -> viewer only, each a 16-byte big-endian header + JPEG bytes:

    u8 kind (1 = tile)  u8 monitor  u16 x  u16 y  u16 w  u16 h  u32 frame seq  u16 reserved

agent -> relay   consent {allow, reason?} | started | ended {reason} | error {code, detail?}
                 monitors | protected {on} | stats | cursor        (forwarded to the viewer)
viewer -> relay  end
                 activity | input | cad (View and control only) | ack {seq} | select_monitor {id} | quality
                                                                   (forwarded to the agent)
relay -> both    state {state, mode, reason?} (viewer) | end {reason} (agent) | ping

Close codes: 4000 ended, 4401 bad credential / token, 4403 forbidden (role,
Origin), 4404 no such session (or another organisation's), 4408 idle, 4409 a
second connection or a replayed token, 4410 token expired, 4429 rate limited,
1009 message too large, 1013 relay not served by this process.

Frames and input are never logged or stored: only types, byte counts and times.
"""
from __future__ import annotations

import json
import logging
import re
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from starlette.concurrency import run_in_threadpool

from .. import config, db
from ..auth import client_ip, session_from_connection
from ..models import utcnow
from ..remote_hub import AGENT_TO_VIEWER, CONTROL_ONLY, VIEWER_TO_AGENT, End, Pair, TokenBucket, hub, relay_enabled
from ..services import remote_sessions as rsvc
from .agent import device_from_connection

log = logging.getLogger("cnapp.remote")
# Two routers so the relay process can serve each end on its own listener with
# its own WebSocket message-size cap (app/relay_main.py); `router` has both.
agent_router = APIRouter(tags=["remote-relay"])
viewer_router = APIRouter(tags=["remote-relay"])
router = APIRouter()

SESSION_ID_RE = re.compile(r"^[0-9a-f]{32}$")
TOKEN_HEADER = "x-remote-session-token"  # noqa: S105 (a header name, not a secret)
_EXPLICIT_ORIGIN_RE = re.compile(r"^https?://[a-z0-9.-]+(:[0-9]{1,5})?$")
CLOSE_TOO_BIG = 1009


async def _reject(ws: WebSocket, code: int, reason: str) -> None:
    """Accept, then close with `code`: a close before accepting reaches the
    client as a bare HTTP 403, without the reason."""
    try:
        await ws.accept()
        await ws.close(code, reason[:100])
    except Exception:  # the client already went away
        log.debug("rejecting a remote-session socket failed", exc_info=True)


def _origin_of(url: str) -> str | None:
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{parts.hostname.lower()}{port}"


def allowed_origins(ws: WebSocket) -> set[str]:
    """The server's own origin; outside production also explicit CORS_ORIGINS
    entries (the Vite dev server). A '*' or wildcard entry is never honoured."""
    s = config.settings
    out: set[str] = set()
    host = (ws.headers.get("host") or "").strip().lower()
    if host and re.fullmatch(r"[a-z0-9.-]+(:[0-9]{1,5})?|\[[0-9a-f:]+\](:[0-9]{1,5})?", host):
        if s.is_production:
            out.add(f"https://{host}")
        else:
            out.add(f"{'https' if ws.url.scheme == 'wss' else 'http'}://{host}")
            out.add(f"https://{host}")  # behind a TLS-terminating proxy
    if s.public_base_url:
        o = _origin_of(s.public_base_url)
        if o:
            out.add(o)
    if not s.is_production:
        for o in s.cors_origins:
            o = o.strip().lower().rstrip("/")
            if _EXPLICIT_ORIGIN_RE.match(o):
                out.add(o)
    return out


def origin_ok(ws: WebSocket) -> bool:
    origin = (ws.headers.get("origin") or "").strip().lower().rstrip("/")
    return bool(origin) and origin in allowed_origins(ws)


def _too_big(data: str | bytes, limit: int) -> bool:
    return len(data) > limit


# ----------------------------------------------------------------------------- agent end
def _agent_auth(ws: WebSocket, session_id: str, ip: str):
    with db.get_session() as s:
        device = device_from_connection(ws, ws.headers.get("authorization"), s)
        s.commit()
        rs = rsvc.agent_connect(s, device, session_id, ws.headers.get(TOKEN_HEADER, "").strip(), ip)
        return rs.id, rs.organization_id, rs.mode, rs.state


@agent_router.websocket("/api/agent/remote/{session_id}")
async def agent_socket(ws: WebSocket, session_id: str):
    s = config.settings
    if not relay_enabled():
        return await _reject(ws, rsvc.CLOSE_UNAVAILABLE, "relay not served here")
    if not SESSION_ID_RE.match(session_id):
        return await _reject(ws, rsvc.CLOSE_NOT_FOUND, "session not found")
    ip = client_ip(ws)
    try:
        sid, org_id, mode, state = await run_in_threadpool(_agent_auth, ws, session_id, ip)
    except HTTPException as e:
        return await _reject(ws, rsvc.CLOSE_AUTH if e.status_code == 401 else rsvc.CLOSE_FORBIDDEN, str(e.detail))
    except rsvc.RelayReject as e:
        return await _reject(ws, e.code, e.reason)
    pair = hub.pairs.get(sid)
    if pair is not None and pair.agent is not None:
        return await _reject(ws, rsvc.CLOSE_DUPLICATE, "the device is already connected")
    pair = pair or hub.get_or_create(sid, org_id, mode, state)
    pair.agent, pair.agent_ip, pair.state, pair.mode = ws, ip, state, mode
    if pair.viewer is None and pair.viewer_gone_at is None:
        pair.viewer_gone_at = utcnow()  # nobody is watching yet: the reconnect grace applies
    await ws.accept()
    await hub.state_to_viewer(pair)
    budget = TokenBucket(s.remote_session_agent_max_bytes_per_second, 2 * s.remote_session_agent_max_bytes_per_second)
    try:
        while not pair.finished.is_set():
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") if msg.get("bytes") is not None else msg.get("text")
            if data is None:
                continue
            if _too_big(data, s.remote_session_agent_max_message_bytes):
                await hub.finish(pair, End("protocol_error", CLOSE_TOO_BIG))
                break
            if not budget.take(len(data)):
                await hub.finish(pair, End("agent_rate_limited", rsvc.CLOSE_RATE))
                break
            if isinstance(data, bytes):
                # Frames only once the user allowed the session.
                if pair.state == "active" and await hub.send_bytes(pair, pair.viewer, data):
                    pair.to_viewer += len(data)
                continue
            await _agent_text(pair, data)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        pair.agent = None
        if not pair.finished.is_set():
            await hub.finish(pair, End("agent_disconnected"))


async def _agent_text(pair: Pair, data: str) -> None:
    try:
        m = json.loads(data)
    except ValueError:
        return
    if not isinstance(m, dict) or not isinstance(m.get("t"), str):
        return
    t = m["t"]
    if t in ("consent", "started", "ended", "error"):
        end = await run_in_threadpool(hub.agent_message, pair, t, m)
        if end is not None:
            await hub.finish(pair, end)
        else:
            await hub.state_to_viewer(pair)
    elif t in AGENT_TO_VIEWER:
        if t == "monitors":
            pair.monitors = data
        if pair.state == "active":
            await hub.send_text(pair, pair.viewer, data)
            pair.to_viewer += len(data)


# ----------------------------------------------------------------------------- viewer end
def _viewer_auth(ws: WebSocket, session_id: str):
    with db.get_session() as s:
        sess = session_from_connection(ws, s)
        user = sess.user
        rs = rsvc.viewer_check(s, user, session_id)
        return user.id, sess.id, rs.id, rs.organization_id, rs.mode, rs.state


@viewer_router.websocket("/api/remote/{session_id}")
async def viewer_socket(ws: WebSocket, session_id: str):
    s = config.settings
    if not relay_enabled():
        return await _reject(ws, rsvc.CLOSE_UNAVAILABLE, "relay not served here")
    if not origin_ok(ws):
        return await _reject(ws, rsvc.CLOSE_FORBIDDEN, "origin not allowed")
    if not SESSION_ID_RE.match(session_id):
        return await _reject(ws, rsvc.CLOSE_NOT_FOUND, "session not found")
    try:
        user_id, user_session_id, sid, org_id, mode, state = await run_in_threadpool(_viewer_auth, ws, session_id)
    except HTTPException as e:
        return await _reject(ws, rsvc.CLOSE_AUTH if e.status_code == 401 else rsvc.CLOSE_FORBIDDEN, str(e.detail))
    except rsvc.RelayReject as e:
        return await _reject(ws, e.code, e.reason)
    pair = hub.pairs.get(sid)
    if pair is not None and pair.viewer is not None:
        return await _reject(ws, rsvc.CLOSE_DUPLICATE, "the session is already open in another window")
    pair = pair or hub.get_or_create(sid, org_id, mode, state)
    pair.viewer, pair.viewer_ip, pair.viewer_user_id = ws, client_ip(ws), user_id
    pair.viewer_session_id = user_session_id
    pair.viewer_gone_at = None
    await ws.accept()
    await hub.state_to_viewer(pair)
    if pair.monitors and pair.state == "active":
        await hub.send_text(pair, ws, pair.monitors)
    rate = s.remote_session_viewer_max_msgs_per_second
    budget = TokenBucket(rate, 2 * rate)
    try:
        while not pair.finished.is_set():
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            if msg.get("bytes") is not None:
                await hub.finish(pair, End("protocol_error", 1003, ip=pair.viewer_ip))
                break
            data = msg.get("text")
            if data is None:
                continue
            if _too_big(data, s.remote_session_viewer_max_message_bytes):
                await hub.finish(pair, End("protocol_error", CLOSE_TOO_BIG, ip=pair.viewer_ip))
                break
            if not budget.take():
                await hub.finish(pair, End("viewer_rate_limited", rsvc.CLOSE_RATE, ip=pair.viewer_ip))
                break
            await _viewer_text(pair, data)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        if pair.viewer is ws:
            pair.viewer = None
            pair.viewer_gone_at = utcnow()


async def _viewer_text(pair: Pair, data: str) -> None:
    try:
        m = json.loads(data)
    except ValueError:
        return
    if not isinstance(m, dict) or not isinstance(m.get("t"), str):
        return
    t = m["t"]
    if t == "end":
        await hub.finish(pair, hub.viewer_end(pair))
        return
    if t not in VIEWER_TO_AGENT or pair.state != "active":
        return
    if t in CONTROL_ONLY:
        if pair.mode != "control":
            pair.dropped_input += 1  # the agent drops it too; this is the server-side guard
            return
        pair.activity_at = utcnow()
    elif t in ("select_monitor", "activity"):
        pair.activity_at = utcnow()
        if t == "activity":
            data = '{"t":"activity"}'  # the agent's own idle limit; nothing else of it is forwarded
    await hub.send_text(pair, pair.agent, data)
    pair.to_agent += len(data)


router.include_router(agent_router)
router.include_router(viewer_router)
