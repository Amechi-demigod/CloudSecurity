// Shared constants and helpers for the Dashboards page (pages/Dashboard.tsx, pages/dashboards/*).
import type { DashPart, Severity, SevCounts } from "../api";
import { SEV_COLOR, SEVERITIES } from "./format";

/** URL value of each tab (?tab=), its API name and label. */
export const TABS = [
  { key: "overview", label: "Overview" },
  { key: "vulns", label: "Vulnerabilities", badge: "vulnerabilities" },
  { key: "exposure", label: "External exposure", badge: "exposure" },
  { key: "identities", label: "Identities", badge: "identities" },
  { key: "endpoints", label: "Endpoints", badge: "endpoints" },
] as const;
export type TabKey = (typeof TABS)[number]["key"];

/** Categorical colours in fixed order; the last one is "Other". Never cycled. */
export const CAT_COLORS = ["var(--color-cat-1)", "var(--color-cat-2)", "var(--color-cat-3)", "var(--color-cat-4)"];
export const OTHER_COLOR = "var(--color-cat-4)";
export const NEW_COLOR = "var(--color-cat-1)";
export const RESOLVED_COLOR = "var(--color-good)";

export const cap = (s: string) => (s ? s[0].toUpperCase() + s.slice(1) : s);

/** Build "/path?a=b" dropping empty values. */
export function href(path: string, params: Record<string, string | null | undefined> = {}): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v) p.set(k, v);
  const s = p.toString();
  return s ? `${path}?${s}` : path;
}

export interface Segment {
  key: string;
  label: string;
  count: number;
  color: string;
  to?: string;
}

/** Severity counts as composition segments (zero parts dropped). */
export function sevSegments(parts: Partial<SevCounts> | undefined, to?: (s: Severity) => string, only: Severity[] = SEVERITIES): Segment[] {
  return only
    .map((s) => ({ key: s, label: cap(s), count: parts?.[s as keyof SevCounts] ?? 0, color: SEV_COLOR[s], to: to?.(s) }))
    .filter((s) => s.count > 0);
}

/** Categorical parts (asset groups, ports...) as segments; "other" always gets the grey. */
export function catSegments(parts: DashPart[] | undefined, to?: (p: DashPart) => string | undefined): Segment[] {
  let i = 0;
  return (parts ?? [])
    .filter((p) => p.count > 0)
    .map((p) => ({
      key: p.key,
      label: p.label,
      count: p.count,
      color: p.key === "other" ? OTHER_COLOR : CAT_COLORS[Math.min(i++, CAT_COLORS.length - 2)],
      to: to?.(p),
    }));
}

/** "Oct 27" from "2026-10-27" (no timezone shift). */
export function dayLabel(iso: string): string {
  const [y, m, d] = iso.slice(0, 10).split("-").map(Number);
  return new Date(y, m - 1, d).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

export function bucketLabel(b: { start: string; end: string }, bucket: "day" | "week"): string {
  return bucket === "day" ? dayLabel(b.start) : `${dayLabel(b.start)} – ${dayLabel(b.end)}`;
}

export const fmtNum = (n: number | null | undefined, digits = 0) =>
  n === null || n === undefined ? "—" : n.toLocaleString(undefined, { maximumFractionDigits: digits });

export function riskSeverity(score: number): Severity {
  return score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : "low";
}

/** Recessive axes for recharts. */
export const AXIS = { stroke: "var(--color-ink-3)", fontSize: 11, tickLine: false, axisLine: false } as const;
export const GRID = { vertical: false, stroke: "var(--color-line)", strokeDasharray: "3 3" } as const;
