// Viewer input helpers: pointer moves are merged into at most one message per
// animation frame (well under the relay's 120 messages/s per viewer), while
// buttons, wheel and keys are sent at once - after any pending move, so the
// order the user produced is kept.

type Schedule = (cb: () => void) => number;
type Cancel = (handle: number) => void;

export class MoveCoalescer {
  private pending: { x: number; y: number } | null = null;
  private handle: number | null = null;
  private readonly send: (x: number, y: number) => void;
  private readonly schedule: Schedule;
  private readonly cancel: Cancel;

  constructor(
    send: (x: number, y: number) => void,
    schedule: Schedule = (cb) => requestAnimationFrame(cb),
    cancel: Cancel = (h) => cancelAnimationFrame(h),
  ) {
    this.send = send;
    this.schedule = schedule;
    this.cancel = cancel;
  }

  /** Record the latest position; it is sent on the next animation frame. */
  push(x: number, y: number): void {
    this.pending = { x, y };
    if (this.handle === null) this.handle = this.schedule(() => this.flush());
  }

  /** Send the pending move now (before a button, wheel or key event). */
  flush(): void {
    if (this.handle !== null) {
      this.cancel(this.handle);
      this.handle = null;
    }
    const p = this.pending;
    this.pending = null;
    if (p) this.send(p.x, p.y);
  }

  dispose(): void {
    if (this.handle !== null) this.cancel(this.handle);
    this.handle = null;
    this.pending = null;
  }
}

/** At most one call per `ms` (activity heartbeats for the idle limit). */
export function throttle(fn: () => void, ms: number): () => void {
  let last = 0;
  return () => {
    const now = Date.now();
    if (now - last >= ms) {
      last = now;
      fn();
    }
  };
}

/** Normalised (0..1) position of a pointer event inside an element showing `w` x `h` pixels with object-fit: contain. */
export function normalise(clientX: number, clientY: number, rect: DOMRect, w: number, h: number): [number, number] | null {
  if (!w || !h || !rect.width || !rect.height) return null;
  const scale = Math.min(rect.width / w, rect.height / h);
  const dw = w * scale;
  const dh = h * scale;
  const ox = rect.left + (rect.width - dw) / 2;
  const oy = rect.top + (rect.height - dh) / 2;
  const x = (clientX - ox) / dw;
  const y = (clientY - oy) / dh;
  if (x < 0 || y < 0 || x > 1 || y > 1) return null;
  return [x, y];
}
