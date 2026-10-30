import { Keyboard, Maximize2, Minimize2, MonitorUp, Power } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type RemoteSession } from "../../api";
import { Breadcrumbs, Button, ErrorNote, Tag } from "../../components/ui";
import { fmtTime } from "../../lib/format";
import { MoveCoalescer, normalise, throttle } from "../../lib/remote/input";
import {
  CLOSE,
  describeEnd,
  parseMessage,
  parseTile,
  viewerUrl,
  wheelNotches,
  type MonitorInfo,
} from "../../lib/remote/protocol";
import { useApi } from "../../lib/useApi";

type Live = { state: string; mode: "view" | "control"; reason?: string };
type Conn = "connecting" | "open" | "reconnecting" | "closed";

const FINAL = new Set(["ended", "denied", "failed"]);
const ACTIVITY_MS = 10_000;

/** Close codes after which reconnecting cannot help. */
const FINAL_CLOSE = new Set<number>([CLOSE.ended, CLOSE.auth, CLOSE.forbidden, CLOSE.notFound, CLOSE.idle,
  CLOSE.duplicate, CLOSE.expired, CLOSE.rateLimited, CLOSE.tooBig, CLOSE.unavailable]);

const CLOSE_TEXT: Record<number, string> = {
  [CLOSE.duplicate]: "This session is already open in another window or tab.",
  [CLOSE.forbidden]: "You are not allowed to view this session.",
  [CLOSE.notFound]: "This session does not exist.",
  [CLOSE.auth]: "Your sign-in expired. Sign in again to continue.",
  [CLOSE.unavailable]: "Remote sessions are not served by this server (relay not running).",
};

function elapsed(fromIso: string | undefined, now: number): string {
  if (!fromIso) return "";
  const s = Math.max(0, Math.floor((now - Date.parse(fromIso)) / 1000));
  return s < 60 ? `${s} s` : `${Math.floor(s / 60)} min ${s % 60} s`;
}

export default function RemoteViewer() {
  const { id = "", sid = "" } = useParams();
  const device = useApi(() => api.device(id), [id]);
  const session = useApi(() => api.remoteSession(sid), [sid], 3000);
  const [live, setLive] = useState<Live | null>(null);
  const [conn, setConn] = useState<Conn>("connecting");
  const [closeText, setCloseText] = useState<string | null>(null);
  const [monitors, setMonitors] = useState<MonitorInfo[]>([]);
  const [active, setActive] = useState(0);
  const [protectedOn, setProtectedOn] = useState(false);
  const [stats, setStats] = useState({ fps: 0, kbps: 0 });
  const [captured, setCaptured] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  const wsRef = useRef<WebSocket | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const activeRef = useRef(0);
  const counters = useRef({ frames: 0, bytes: 0 });
  // What the viewer holds down on the device: released on blur, on unmount
  // and before the socket closes (the helper also releases them when it stops).
  const held = useRef(new Set<string>());
  const heldButtons = useRef(new Set<number>());
  const lastPos = useRef<[number, number] | null>(null);
  const reloadSession = session.reload;

  const send = useCallback((m: Record<string, unknown>) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(m));
  }, []);

  const releaseButtons = useCallback(() => {
    const p = lastPos.current;
    for (const button of heldButtons.current) {
      if (p) send({ t: "input", kind: "button", button, down: false, x: p[0], y: p[1] });
    }
    heldButtons.current.clear();
  }, [send]);

  const releaseHeld = useCallback(() => {
    for (const code of held.current) send({ t: "input", kind: "key", code, down: false });
    held.current.clear();
    releaseButtons();
  }, [send, releaseButtons]);

  // The viewer socket: same-origin wss://, authenticated by the session cookie.
  useEffect(() => {
    let stopped = false;
    let attempts = 0;
    let timer: number | undefined;
    let draw: Promise<void> = Promise.resolve();

    const onTile = (buf: ArrayBuffer) => {
      const t = parseTile(buf);
      if (!t || t.monitor !== activeRef.current) return;
      counters.current.bytes += buf.byteLength;
      draw = draw.then(async () => {
        const canvas = canvasRef.current;
        const ctx = canvas?.getContext("2d");
        if (!ctx) return;
        try {
          const bmp = await createImageBitmap(t.jpeg);
          ctx.drawImage(bmp, t.x, t.y);
          bmp.close();
        } catch {
          /* a corrupt tile: the next frame repaints it */
        }
        if (t.last) {
          counters.current.frames += 1;
          const ws = wsRef.current;
          if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ t: "ack", seq: t.seq }));
        }
      });
    };

    const open = () => {
      const ws = new WebSocket(viewerUrl(sid));
      ws.binaryType = "arraybuffer";
      wsRef.current = ws;
      ws.onopen = () => {
        attempts = 0;
        setConn("open");
      };
      ws.onmessage = (ev) => {
        if (typeof ev.data !== "string") {
          onTile(ev.data as ArrayBuffer);
          return;
        }
        const m = parseMessage(ev.data);
        if (!m) return;
        if (m.t === "state") {
          setLive({ state: m.state, mode: m.mode, reason: m.reason });
          if (FINAL.has(m.state)) reloadSession();
        } else if (m.t === "monitors") {
          setMonitors(m.monitors);
          setActive(m.active);
          activeRef.current = m.active;
          const mon = m.monitors.find((x) => x.id === m.active);
          const canvas = canvasRef.current;
          if (mon && canvas && (canvas.width !== mon.w || canvas.height !== mon.h)) {
            canvas.width = mon.w;
            canvas.height = mon.h;
          }
        } else if (m.t === "protected") {
          setProtectedOn(m.on);
        }
      };
      ws.onclose = (ev) => {
        if (wsRef.current === ws) wsRef.current = null;
        if (stopped) return;
        if (FINAL_CLOSE.has(ev.code) || attempts >= 3) {
          setConn("closed");
          setCloseText(CLOSE_TEXT[ev.code] ?? null);
          reloadSession();
          return;
        }
        attempts += 1;
        setConn("reconnecting");
        timer = window.setTimeout(open, 2000);
      };
    };
    open();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      releaseHeld(); // leaving the page: nothing stays pressed on the device
      wsRef.current?.close(1000, "viewer closed");
      wsRef.current = null;
    };
  }, [sid, reloadSession, releaseHeld]);

  // Frame rate / throughput, and the "waiting for ..." clocks.
  useEffect(() => {
    const t = window.setInterval(() => {
      const c = counters.current;
      setStats({ fps: c.frames, kbps: Math.round((c.bytes * 8) / 1000) });
      counters.current = { frames: 0, bytes: 0 };
      setNow(Date.now());
    }, 1000);
    return () => window.clearInterval(t);
  }, []);

  useEffect(() => {
    const onChange = () => setFullscreen(document.fullscreenElement === wrapRef.current);
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, []);

  const s: RemoteSession | null = session.data;
  const state = live?.state ?? s?.state ?? "requested";
  const mode = live?.mode ?? s?.mode ?? "view";
  const control = mode === "control";
  const connected = state === "active" && conn === "open";
  const mon = monitors.find((m) => m.id === active);

  // Activity heartbeats (the idle limit), also in View only mode.
  const activity = useRef(throttle(() => send({ t: "activity" }), ACTIVITY_MS));

  // Pointer moves: at most one message per animation frame.
  const mover = useRef<MoveCoalescer | null>(null);
  useEffect(() => {
    mover.current = new MoveCoalescer((x, y) => send({ t: "input", kind: "move", x, y }));
    return () => mover.current?.dispose();
  }, [send]);

  const position = useCallback((clientX: number, clientY: number, clamp = false) => {
    const canvas = canvasRef.current;
    if (!canvas) return null;
    return normalise(clientX, clientY, canvas.getBoundingClientRect(), canvas.width, canvas.height, clamp);
  }, []);

  const releaseKeys = useCallback(() => {
    for (const code of held.current) send({ t: "input", kind: "key", code, down: false });
    held.current.clear();
    const kb = (navigator as Navigator & { keyboard?: { unlock?: () => void } }).keyboard;
    kb?.unlock?.();
    setCaptured(false);
  }, [send]);

  // Keyboard capture (View and control only): every key goes to the device
  // until Ctrl+Alt+Shift releases it.
  useEffect(() => {
    if (!captured || !connected || !control) return;
    const down = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.altKey && e.shiftKey) {
        e.preventDefault();
        releaseKeys();
        return;
      }
      e.preventDefault();
      e.stopPropagation();
      mover.current?.flush();
      held.current.add(e.code);
      send({ t: "input", kind: "key", code: e.code, down: true });
      activity.current();
    };
    const up = (e: KeyboardEvent) => {
      e.preventDefault();
      e.stopPropagation();
      held.current.delete(e.code);
      send({ t: "input", kind: "key", code: e.code, down: false });
    };
    const blur = () => {
      releaseKeys();
      releaseButtons();
    };
    window.addEventListener("keydown", down, true);
    window.addEventListener("keyup", up, true);
    window.addEventListener("blur", blur);
    return () => {
      window.removeEventListener("keydown", down, true);
      window.removeEventListener("keyup", up, true);
      window.removeEventListener("blur", blur);
    };
  }, [captured, connected, control, send, releaseKeys, releaseButtons]);

  // Wheel needs a non-passive listener to stop the page from scrolling.
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !connected || !control) return;
    const wheel = (e: WheelEvent) => {
      e.preventDefault();
      const p = position(e.clientX, e.clientY);
      if (!p) return; // the letterbox bars are not the device's screen
      mover.current?.flush();
      send({ t: "input", kind: "wheel", x: p[0], y: p[1], dx: wheelNotches(e.deltaX, e.deltaMode),
        dy: wheelNotches(e.deltaY, e.deltaMode) });
      activity.current();
    };
    canvas.addEventListener("wheel", wheel, { passive: false });
    return () => canvas.removeEventListener("wheel", wheel);
  }, [connected, control, send, position]);

  function onPointerMove(e: ReactPointerEvent<HTMLCanvasElement>) {
    activity.current();
    if (!connected || !control) return;
    // While a button is held (pointer captured) a drag past the image edge stays on it.
    const p = position(e.clientX, e.clientY, heldButtons.current.size > 0);
    if (!p) return;
    lastPos.current = p;
    mover.current?.push(p[0], p[1]);
  }

  function onPointerButton(e: ReactPointerEvent<HTMLCanvasElement>, down: boolean) {
    activity.current();
    if (!connected || !control) return;
    e.preventDefault();
    if (down && !captured) {
      canvasRef.current?.focus();
      setCaptured(true);
      const kb = (navigator as Navigator & { keyboard?: { lock?: () => Promise<void> } }).keyboard;
      if (document.fullscreenElement) kb?.lock?.().catch(() => undefined);
    }
    if (down) {
      // A press in the letterbox bars is not a click on the device; one on the
      // image captures the pointer, so its release arrives even outside it.
      const p = position(e.clientX, e.clientY);
      if (!p) return;
      e.currentTarget.setPointerCapture?.(e.pointerId);
      heldButtons.current.add(e.button);
      lastPos.current = p;
      mover.current?.flush();
      send({ t: "input", kind: "button", button: e.button, down: true, x: p[0], y: p[1] });
      return;
    }
    if (!heldButtons.current.delete(e.button)) return; // its press was not sent
    const p = position(e.clientX, e.clientY, true) ?? lastPos.current;
    if (heldButtons.current.size === 0 && e.currentTarget.hasPointerCapture?.(e.pointerId)) {
      e.currentTarget.releasePointerCapture(e.pointerId);
    }
    if (!p) return;
    lastPos.current = p;
    mover.current?.flush();
    send({ t: "input", kind: "button", button: e.button, down: false, x: p[0], y: p[1] });
  }

  async function endSession() {
    if (wsRef.current?.readyState === WebSocket.OPEN) send({ t: "end" });
    else await api.endRemoteSession(sid).catch(() => undefined);
    window.setTimeout(reloadSession, 500);
  }

  function toggleFullscreen() {
    if (document.fullscreenElement) document.exitFullscreen().catch(() => undefined);
    else wrapRef.current?.requestFullscreen().catch(() => undefined);
  }

  const final = FINAL.has(state) || (conn === "closed" && (!s || FINAL.has(s.state)));
  const hostname = device.data?.hostname ?? "device";
  const quality = conn === "reconnecting" ? "Reconnecting" : !connected ? "—" : protectedOn ? "Paused" : "Live";
  const qualityTone = conn === "reconnecting" || protectedOn ? "bg-sev-high" : connected ? "bg-good" : "bg-ink-3";

  return (
    <div>
      <Breadcrumbs items={[{ label: "Devices", to: "/devices" }, { label: hostname, to: `/devices/${id}` },
        { label: "Remote session" }]} />
      <ErrorNote error={session.error} />
      <div ref={wrapRef} className={`flex flex-col gap-3 ${fullscreen ? "h-screen bg-surface-0 p-3" : ""}`}>
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-line bg-surface-1 px-3 py-2"
          role="toolbar" aria-label="Remote session">
          <span className="text-sm font-semibold text-ink">{hostname}</span>
          <Tag tone={control ? "warn" : "accent"}>{control ? "View and control" : "View only"}</Tag>
          {monitors.length > 1 && (
            <label className="flex items-center gap-1.5 text-xs text-ink-2">
              <MonitorUp aria-hidden className="h-4 w-4" />
              <span className="sr-only">Monitor</span>
              <select className="rounded border border-line bg-surface-2 px-2 py-1 text-xs text-ink" value={active}
                disabled={!connected}
                onChange={(e) => send({ t: "select_monitor", id: Number(e.target.value) })}>
                {monitors.map((m) => (
                  <option key={m.id} value={m.id}>
                    Monitor {m.id + 1}{m.primary ? " (main)" : ""} · {m.w}×{m.h}{m.scale !== 1 ? ` · ${Math.round(m.scale * 100)}%` : ""}
                  </option>
                ))}
              </select>
            </label>
          )}
          {control && (
            <Button onClick={() => send({ t: "cad" })} disabled={!connected}
              title="Send Ctrl+Alt+Del to the device (shows the Windows security screen, which is not shown here)">
              Ctrl+Alt+Del
            </Button>
          )}
          <Button onClick={toggleFullscreen} title={fullscreen ? "Exit full screen" : "Full screen"}>
            <span className="inline-flex items-center gap-1.5">
              {fullscreen ? <Minimize2 aria-hidden className="h-4 w-4" /> : <Maximize2 aria-hidden className="h-4 w-4" />}
              {fullscreen ? "Exit full screen" : "Full screen"}
            </span>
          </Button>
          <span className="ml-auto flex items-center gap-2 text-xs text-ink-3" aria-live="polite">
            <span aria-hidden className={`h-2 w-2 rounded-full ${qualityTone}`} />
            {quality}
            {connected && !protectedOn && <span>· {stats.fps} fps · {stats.kbps} kbit/s</span>}
          </span>
          {!final && (
            <Button variant="danger" onClick={endSession}>
              <span className="inline-flex items-center gap-1.5">
                <Power aria-hidden className="h-4 w-4" /> End session
              </span>
            </Button>
          )}
        </div>

        {control && connected && (
          <p className={`flex items-center gap-2 text-xs ${captured ? "text-accent" : "text-ink-3"}`}>
            <Keyboard aria-hidden className="h-4 w-4" />
            {captured
              ? "Keyboard captured: every key goes to the device. Press Ctrl+Alt+Shift to release it."
              : "Click the screen to send mouse and keyboard input to the device."}
          </p>
        )}

        <div className={`relative overflow-hidden rounded-xl border border-line bg-surface-2 ${fullscreen ? "min-h-0 flex-1" : "aspect-video"}`}>
          <canvas
            ref={canvasRef}
            width={mon?.w ?? 1280}
            height={mon?.h ?? 720}
            tabIndex={control ? 0 : -1}
            aria-label={`Screen of ${hostname}`}
            className={`h-full w-full object-contain ${connected ? "" : "invisible"} ${control && connected ? "cursor-crosshair" : ""} ${captured ? "outline outline-2 outline-accent" : "outline-none"}`}
            onPointerMove={onPointerMove}
            onPointerDown={(e) => onPointerButton(e, true)}
            onPointerUp={(e) => onPointerButton(e, false)}
            onLostPointerCapture={() => releaseButtons()}
            onContextMenu={(e) => e.preventDefault()}
          />
          {!connected && (
            <div className="absolute inset-0 flex items-center justify-center p-6">
              <StatusPanel state={state} conn={conn} closeText={closeText} session={s} now={now} deviceId={id} />
            </div>
          )}
          {connected && protectedOn && (
            <div className="absolute inset-0 flex items-center justify-center bg-surface-0/80 p-6 text-center">
              <div className="max-w-md">
                <p className="text-sm font-semibold text-ink">The user's screen is on a protected prompt</p>
                <p className="mt-1 text-sm text-ink-2">
                  For example a User Account Control prompt or the Windows security screen. These are not shared; the
                  view continues when the prompt closes.
                </p>
              </div>
            </div>
          )}
        </div>
        {s && (
          <p className="text-xs text-ink-3">
            Requested {fmtTime(s.created_at)} by {s.requested_by_email} · Reason: {s.reason}
          </p>
        )}
      </div>
    </div>
  );
}

function StatusPanel({ state, conn, closeText, session, now, deviceId }: {
  state: string;
  conn: Conn;
  closeText: string | null;
  session: RemoteSession | null;
  now: number;
  deviceId: string;
}) {
  if (FINAL.has(state) || (conn === "closed" && session && FINAL.has(session.state))) {
    const st = session?.state ?? state;
    return (
      <div className="max-w-md text-center">
        <p className="text-sm font-semibold text-ink">
          {st === "denied" ? "Session denied" : st === "failed" ? "Session could not start" : "Session ended"}
        </p>
        <p className="mt-1 text-sm text-ink-2">
          {describeEnd(st, session?.end_reason ?? null, session?.error_code ?? null)}
        </p>
        <Link to={`/devices/${deviceId}?tab=History`} className="mt-3 inline-block text-sm text-accent hover:underline">
          Back to the device
        </Link>
      </div>
    );
  }
  if (conn === "closed") {
    return (
      <div className="max-w-md text-center">
        <p className="text-sm font-semibold text-ink">Disconnected</p>
        <p className="mt-1 text-sm text-ink-2">{closeText ?? "The connection to the server was lost."}</p>
      </div>
    );
  }
  if (conn === "reconnecting") {
    return <p className="text-sm text-ink-2">Connection lost; reconnecting…</p>;
  }
  if (state === "awaiting_consent") {
    return (
      <div className="max-w-md text-center">
        <span aria-hidden className="mx-auto mb-3 block h-6 w-6 animate-spin rounded-full border-2 border-line border-t-accent" />
        <p className="text-sm font-semibold text-ink">Waiting for the user to allow the session</p>
        <p className="mt-1 text-sm text-ink-2">
          A prompt with your name and reason is on their screen. Nothing is shared until they click Allow; it is denied
          automatically after about a minute.
        </p>
        <p className="mt-2 text-xs text-ink-3">Waiting {elapsed(session?.agent_connected_at ?? undefined, now)}</p>
      </div>
    );
  }
  if (state === "active") {
    return <p className="text-sm text-ink-2">Connecting to the screen…</p>;
  }
  return (
    <div className="max-w-md text-center">
      <span aria-hidden className="mx-auto mb-3 block h-6 w-6 animate-spin rounded-full border-2 border-line border-t-accent" />
      <p className="text-sm font-semibold text-ink">Waiting for the device</p>
      <p className="mt-1 text-sm text-ink-2">
        The request is picked up on the device's next poll for commands, which can take up to about 60 seconds.
      </p>
      <p className="mt-2 text-xs text-ink-3">Waiting {elapsed(session?.created_at, now)}</p>
    </div>
  );
}
