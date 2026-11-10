// Client-side mirror of the server's scan target rules (backend/app/network/validate.py): used for instant feedback only,
// the server validates again. IPv4 CIDRs and inclusive a-b ranges.

export const MAX_TARGET = 65_536;
export const MAX_SCAN = 262_144;

const ip2n = (s: string): number | null => {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s.trim());
  if (!m) return null;
  const p = m.slice(1).map(Number);
  if (p.some((x) => x > 255)) return null;
  return ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3];
};

export type Interval = [number, number];

/** [first, last] address of a CIDR / range / single address, or an error message. */
export function parseTarget(item: string): Interval | string {
  const s = item.trim();
  if (!s) return "empty";
  if (s.includes(":")) return "IPv6 is not supported yet";
  let lo: number | null;
  let hi: number | null;
  const range = /^([\d.]+)\s*-\s*([\d.]+)$/.exec(s);
  if (range) {
    lo = ip2n(range[1]);
    hi = ip2n(range[2]);
    if (lo === null || hi === null) return `${s} is not a valid range`;
    if (hi < lo) return `${s}: the range ends before it starts`;
  } else if (s.includes("/")) {
    const [a, b] = s.split("/");
    const base = ip2n(a);
    const bits = Number(b);
    if (base === null || !/^\d{1,2}$/.test(b) || bits > 32) return `${s} is not a valid CIDR`;
    const size = 2 ** (32 - bits);
    lo = Math.floor(base / size) * size;
    hi = lo + size - 1;
  } else {
    lo = hi = ip2n(s);
    if (lo === null) return `${s} is not a valid IPv4 address`;
  }
  const forbidden: Interval[] = [
    [0, 2 ** 24 - 1],
    [127 * 2 ** 24, 128 * 2 ** 24 - 1],
    [169 * 2 ** 24 + 254 * 2 ** 16, 169 * 2 ** 24 + 255 * 2 ** 16 - 1],
    [224 * 2 ** 24, 2 ** 32 - 1],
  ];
  if (forbidden.some(([f, l]) => lo! <= l && hi! >= f)) return `${s} includes addresses that are never scanned (unspecified, loopback, link-local, multicast, reserved)`;
  return [lo!, hi!];
}

export function size(i: Interval): number {
  return i[1] - i[0] + 1;
}

function merge(list: Interval[]): Interval[] {
  const out: Interval[] = [];
  for (const [a, b] of [...list].sort((x, y) => x[0] - y[0])) {
    if (out.length && a <= out[out.length - 1][1] + 1) out[out.length - 1][1] = Math.max(out[out.length - 1][1], b);
    else out.push([a, b]);
  }
  return out;
}

/** Addresses in `targets` minus `exclude` (overlaps counted once), plus the first problem found. */
export function countAddresses(targets: string[], exclude: string[]): { total: number; error: string | null } {
  const t: Interval[] = [];
  const e: Interval[] = [];
  for (const x of targets) {
    const p = parseTarget(x);
    if (typeof p === "string") return { total: 0, error: p };
    if (size(p) > MAX_TARGET) return { total: 0, error: `${x} has ${size(p).toLocaleString()} addresses: a target may not exceed /16 (${MAX_TARGET.toLocaleString()})` };
    t.push(p);
  }
  for (const x of exclude) {
    const p = parseTarget(x);
    if (typeof p === "string") return { total: 0, error: `Exclusion: ${p}` };
    e.push(p);
  }
  let total = 0;
  for (const [lo, hi] of merge(t)) {
    let cur = lo;
    for (const [xl, xh] of merge(e)) {
      if (xh < cur || xl > hi) continue;
      if (xl > cur) total += xl - cur;
      cur = Math.max(cur, xh + 1);
      if (cur > hi) break;
    }
    if (cur <= hi) total += hi - cur + 1;
  }
  if (total > MAX_SCAN) return { total, error: `${total.toLocaleString()} addresses is more than the ${MAX_SCAN.toLocaleString()} allowed per scan: split it into several scans` };
  return { total, error: null };
}

/** Does the dotted IPv4 address sit inside the target (CIDR / range)? */
export function contains(target: string, ip: string): boolean {
  const p = parseTarget(target);
  const n = ip2n(ip);
  return typeof p !== "string" && n !== null && n >= p[0] && n <= p[1];
}

export function splitList(s: string): string[] {
  return s
    .split(/[\s,;]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}
