// Remote-session relay protocol (version 1), browser side. The server side is
// documented in backend/app/api/remote_relay.py: JSON text messages with a
// type "t", and binary screen tiles (16-byte big-endian header + JPEG).
import { BASE } from "../../api";

export const TILE_HEADER = 16;
export const TILE_LAST = 1;

export interface Tile {
  monitor: number;
  x: number;
  y: number;
  w: number;
  h: number;
  seq: number;
  last: boolean;
  jpeg: Blob;
}

export interface MonitorInfo {
  id: number;
  x: number;
  y: number;
  w: number;
  h: number;
  scale: number;
  primary: boolean;
}

export type ServerMessage =
  | { t: "state"; state: string; mode: "view" | "control"; reason?: string }
  | { t: "monitors"; monitors: MonitorInfo[]; active: number }
  | { t: "protected"; on: boolean }
  | { t: "ping" }
  | { t: "stats"; stats?: Record<string, number> }
  | { t: "error"; code?: string; detail?: string };

/** Close codes the relay uses (app/services/remote_sessions.py). */
export const CLOSE = {
  ended: 4000,
  auth: 4401,
  forbidden: 4403,
  notFound: 4404,
  idle: 4408,
  duplicate: 4409,
  expired: 4410,
  rateLimited: 4429,
  tooBig: 1009,
  unavailable: 1013,
} as const;

export function parseTile(buf: ArrayBuffer): Tile | null {
  if (buf.byteLength <= TILE_HEADER) return null;
  const v = new DataView(buf);
  if (v.getUint8(0) !== 1) return null;
  return {
    monitor: v.getUint8(1),
    x: v.getUint16(2),
    y: v.getUint16(4),
    w: v.getUint16(6),
    h: v.getUint16(8),
    seq: v.getUint32(10),
    last: (v.getUint16(14) & TILE_LAST) !== 0,
    jpeg: new Blob([buf.slice(TILE_HEADER)], { type: "image/jpeg" }),
  };
}

export function parseMessage(text: string): ServerMessage | null {
  try {
    const m = JSON.parse(text);
    return m && typeof m.t === "string" ? (m as ServerMessage) : null;
  } catch {
    return null;
  }
}

/** Same-origin wss:// URL of the viewer socket (the CSP stays `connect-src 'self'`). */
export function viewerUrl(sessionId: string): string {
  const base = BASE ? new URL(BASE, window.location.href) : new URL(window.location.href);
  const scheme = base.protocol === "https:" ? "wss:" : "ws:";
  const path = BASE ? base.pathname.replace(/\/$/, "") : "";
  return `${scheme}//${base.host}${path}/api/remote/${sessionId}`;
}

/** Wheel delta in notches (Windows WHEEL_DELTA units of 120 are applied by the agent). */
export function wheelNotches(delta: number, mode: number): number {
  if (!delta) return 0;
  const lines = mode === 1 ? delta / 3 : mode === 2 ? delta * 3 : delta / 100;
  const n = Math.sign(lines) * Math.max(1, Math.round(Math.abs(lines)));
  return Math.max(-10, Math.min(10, n));
}

export const END_REASON: Record<string, string> = {
  ended_by_viewer: "You ended the session.",
  ended_by_admin: "An admin ended the session.",
  user_ended: "The user ended the session.",
  user_denied: "The user denied the session.",
  consent_timeout: "The user did not answer in time.",
  indicator_closed: "The session indicator on the user's screen was closed.",
  idle: "The session ended after 15 minutes without activity.",
  max_duration: "The session reached its time limit.",
  device_revoked: "The device was revoked.",
  device_lost_mode: "The device was put in lost mode.",
  device_isolated: "Sign-in was suspended on the device.",
  device_wipe: "A remote wipe was requested.",
  requester_access_revoked: "Your access changed (role or account).",
  agent_disconnected: "The device disconnected.",
  viewer_disconnected: "The viewer disconnected.",
  session_switch: "The user switched or disconnected their Windows session.",
  user_locked: "The user locked the screen.",
  relay_restart: "The server restarted.",
  relay_lost: "The server lost the session.",
  agent_stopping: "The agent on the device stopped.",
  helper_exit: "The helper on the device stopped.",
  cancelled: "The request was cancelled.",
  viewer_rate_limited: "The viewer sent too many messages.",
  agent_rate_limited: "The device sent too much data.",
  protocol_error: "The connection sent an invalid message.",
};

export const ERROR_CODE: Record<string, string> = {
  ERR_NO_ATTENDED_USER: "Nobody is signed in to the device, or the screen is locked. Unattended access is not supported.",
  ERR_UNSUPPORTED_PLATFORM: "Remote sessions are available on Windows devices only for now.",
  ERR_DEVICE_TIMEOUT: "The device did not pick up the request in time. Is it online?",
  ERR_TOKEN_EXPIRED: "The device connected too late; please try again.",
  ERR_HELPER: "The helper could not start on the device.",
  ERR_BUSY: "Another remote session is already running on the device.",
  ERR_CONNECT: "The device could not connect to the server.",
};

export function describeEnd(state: string, endReason: string | null, errorCode: string | null): string {
  if (errorCode) return ERROR_CODE[errorCode] ?? `The session could not start (${errorCode}).`;
  if (endReason) return END_REASON[endReason] ?? `The session ended (${endReason.replace(/_/g, " ")}).`;
  return state === "denied" ? END_REASON.user_denied : "The session ended.";
}
