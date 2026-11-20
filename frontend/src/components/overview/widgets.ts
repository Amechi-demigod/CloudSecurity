// The Overview dashboard's widgets and the pure layout logic (order, on/off, width) behind Customize.
// The ids are the whitelist of the backend (app/services/dashboard_layout.py): keep both lists in sync.
import type { ModuleKey } from "../../api";
import type { OverviewLayout } from "../../overviewApi";

export type Width = 6 | 12;

export interface WidgetDef {
  id: string;
  title: string;
  description: string;
  /** Only offered to organisations that have this module. */
  module?: ModuleKey;
  defaultOn: boolean;
  defaultWidth: Width;
}

export const WIDGETS: WidgetDef[] = [
  { id: "summary", title: "Summary", description: "Issues, assets and computers at a glance", defaultOn: true, defaultWidth: 12 },
  { id: "cloudSev", title: "Cloud issues by severity", description: "Split by severity, with the top 3", module: "cloud", defaultOn: true, defaultWidth: 6 },
  { id: "vulnSev", title: "Vulnerabilities by severity", description: "Split by severity, with the top 3", module: "vulnerabilities", defaultOn: true, defaultWidth: 6 },
  { id: "extSev", title: "Internet-facing by severity", description: "Split by severity, with the top 3", module: "external", defaultOn: true, defaultWidth: 6 },
  { id: "attention", title: "Needs your attention", description: "The few things to do today", defaultOn: true, defaultWidth: 6 },
  { id: "trend", title: "New vs fixed", description: "Are you keeping up? Recent weeks", defaultOn: true, defaultWidth: 6 },
  { id: "compliance", title: "Compliance", description: "Progress per framework", defaultOn: true, defaultWidth: 6 },
  { id: "kpis", title: "Key numbers", description: "Open, critical, exposed, threats, time to fix", defaultOn: false, defaultWidth: 12 },
  { id: "risk", title: "Overall risk score", description: "One number for the whole organisation", defaultOn: false, defaultWidth: 6 },
  { id: "top", title: "Riskiest assets", description: "The assets with the most risk", defaultOn: false, defaultWidth: 6 },
  { id: "age", title: "Open issues by age", description: "How long issues stay open", defaultOn: false, defaultWidth: 6 },
  { id: "category", title: "Cloud issues by type", description: "Cloud issues grouped by kind", module: "cloud", defaultOn: false, defaultWidth: 6 },
];

export const WIDGET_MAP: Record<string, WidgetDef> = Object.fromEntries(WIDGETS.map((w) => [w.id, w]));

/** A layout resolved against the widget list: every widget has a place, a state and a width. */
export interface Resolved {
  order: string[];
  on: Record<string, boolean>;
  width: Record<string, Width>;
}

export function defaultLayout(): Resolved {
  return {
    order: WIDGETS.map((w) => w.id),
    on: Object.fromEntries(WIDGETS.map((w) => [w.id, w.defaultOn])),
    width: Object.fromEntries(WIDGETS.map((w) => [w.id, w.defaultWidth])),
  };
}

/** The saved layout (or none) as a full layout: unknown ids dropped, widgets it does not mention get their defaults (at the end). */
export function resolve(saved: OverviewLayout | null | undefined): Resolved {
  const base = defaultLayout();
  if (!saved) return base;
  const known = (id: string) => id in WIDGET_MAP;
  const mentioned = [...new Set(saved.order.filter(known))];
  const hidden = new Set(saved.hidden.filter(known));
  const on = { ...base.on };
  for (const id of mentioned) on[id] = !hidden.has(id);
  for (const id of hidden) on[id] = false;
  const width = { ...base.width };
  for (const [id, w] of Object.entries(saved.widths ?? {})) if (known(id) && (w === 6 || w === 12)) width[id] = w;
  return { order: [...mentioned, ...base.order.filter((id) => !mentioned.includes(id))], on, width };
}

export function toPayload(r: Resolved): OverviewLayout {
  return { order: r.order, hidden: r.order.filter((id) => !r.on[id]), widths: r.width };
}

export const sameLayout = (a: Resolved, b: Resolved) => JSON.stringify(a) === JSON.stringify(b);

/** Move `id` to the place of `target` (drag and drop). */
export function moveTo(r: Resolved, id: string, target: string): Resolved {
  if (id === target) return r;
  const rest = r.order.filter((x) => x !== id);
  const at = rest.indexOf(target);
  const fromIdx = r.order.indexOf(id);
  const targetIdx = r.order.indexOf(target);
  // dragging down lands after the target, dragging up lands before it
  rest.splice(at < 0 ? rest.length : fromIdx < targetIdx ? at + 1 : at, 0, id);
  return { ...r, order: rest };
}

/** Swap `id` with the next visible widget up (-1) or down (+1); `visible` is the list of shown ids in order. */
export function shift(r: Resolved, id: string, dir: -1 | 1, visible: string[]): Resolved {
  const i = visible.indexOf(id);
  const j = i + dir;
  if (i < 0 || j < 0 || j >= visible.length) return r;
  const order = r.order.slice();
  const a = order.indexOf(id);
  const b = order.indexOf(visible[j]);
  order[a] = visible[j];
  order[b] = id;
  return { ...r, order };
}
