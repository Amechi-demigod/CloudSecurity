// Building blocks of the Dashboards page: KPI tiles (value, change chip, composition bar),
// cards, horizontal bar rows, hover tips and the chart tooltip. Colours: severity tokens for
// severity, the fixed categorical tokens (--color-cat-*) for everything else; text always in ink.
import { ChevronRight } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import type { Segment } from "../lib/dash";
import { fmtNum } from "../lib/dash";

/** Hover / focus tip shown above its child (CSS only, so it also works inside links). */
export function Tip({ tip, children, className = "" }: { tip: ReactNode; children: ReactNode; className?: string }) {
  return (
    <span className={`group/tip relative ${className}`}>
      {children}
      <span
        role="tooltip"
        className="pointer-events-none absolute bottom-full left-1/2 z-30 mb-1.5 hidden -translate-x-1/2 whitespace-nowrap rounded-md border border-line bg-surface-1 px-2 py-1 text-xs font-normal text-ink shadow-lg shadow-black/20 group-hover/tip:block group-focus-within/tip:block"
      >
        {tip}
      </span>
    </span>
  );
}

/**
 * ▲ / ▼ N vs the previous period. Green when the change is an improvement, red when it is worse
 * (`better` says which direction is good). Hidden when there is no history to compare with.
 */
export function ChangeChip({ delta, better, unit = "", days }: { delta: number | null | undefined; better: "up" | "down"; unit?: string; days: number }) {
  if (delta === null || delta === undefined) return null;
  const n = Math.round(delta * 10) / 10;
  const abs = fmtNum(Math.abs(n), 1);
  if (n === 0) {
    return (
      <span className="inline-flex shrink-0 items-center rounded-md bg-surface-2 px-1.5 py-px text-[11.5px] font-semibold text-ink-2" title={`No change vs ${days} days ago`}>
        = 0
      </span>
    );
  }
  const up = n > 0;
  const good = up === (better === "up");
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-0.5 rounded-md px-1.5 py-px text-[11.5px] font-semibold ${good ? "bg-good-bg text-good" : "bg-bad-bg text-sev-critical"}`}
      title={`${up ? "Up" : "Down"} ${abs}${unit} vs ${days} days ago (${good ? "better" : "worse"})`}
    >
      <span aria-hidden>{up ? "▲" : "▼"}</span>
      <span className="sr-only">{up ? "up" : "down"}</span>
      {abs}
      {unit}
    </span>
  );
}

/** Thin stacked bar (2px gaps, rounded ends) + a legend naming every part and its count. */
export function Composition({ segments, legend = true }: { segments: Segment[]; legend?: boolean }) {
  const total = segments.reduce((a, s) => a + s.count, 0);
  if (total === 0) return null;
  return (
    <div>
      <div className="mt-3 flex h-2 gap-[2px]">
        {segments.map((s) => (
          <span key={s.key} className="flex min-w-[3px]" style={{ flex: s.count }}>
            <Tip tip={`${s.label}: ${s.count} (${Math.round((100 * s.count) / total)}%)`} className="flex w-full">
              <span className="block h-2 w-full rounded-[3px]" style={{ background: s.color }} />
            </Tip>
          </span>
        ))}
      </div>
      {legend && (
        <ul className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs text-ink-2">
          {segments.map((s) => {
            const body = (
              <>
                <span aria-hidden className="mr-1 inline-block h-2 w-2 rounded-[2px] align-[0px]" style={{ background: s.color }} />
                {s.label} <b className="font-semibold text-ink">{s.count}</b>
              </>
            );
            return (
              <li key={s.key}>
                {s.to ? (
                  <Link to={s.to} className="rounded hover:text-ink hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent" title={`Show ${s.label.toLowerCase()} (${s.count})`}>
                    {body}
                  </Link>
                ) : (
                  body
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

export function KpiTile({
  label,
  value,
  unit,
  to,
  hint,
  delta,
  better = "down",
  deltaUnit,
  days,
  segments,
  footer,
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  to?: string;
  hint?: string;
  delta?: number | null;
  better?: "up" | "down";
  deltaUnit?: string;
  days: number;
  segments?: Segment[];
  footer?: ReactNode;
}) {
  const val = (
    <span className="text-[28px] font-bold leading-none tracking-tight text-ink">
      {value}
      {unit && <span className="ml-1 text-base font-semibold text-ink-2">{unit}</span>}
    </span>
  );
  return (
    <section data-print="card" className="min-w-0 rounded-xl border border-line bg-surface-1 px-4 py-3.5 shadow-sm shadow-black/5">
      <div className="flex items-start justify-between gap-2">
        <h3 className="text-[11.5px] font-semibold uppercase tracking-[0.06em] text-ink-3">{label}</h3>
        <ChangeChip delta={delta} better={better} unit={deltaUnit} days={days} />
      </div>
      <div className="mt-2">
        {to ? (
          <Link to={to} title={hint ?? `Show ${label.toLowerCase()}`} className="group inline-flex items-center gap-1 rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
            {val}
            <ChevronRight aria-hidden className="h-4 w-4 text-ink-3 opacity-0 transition group-hover:opacity-100 group-focus-visible:opacity-100" />
          </Link>
        ) : (
          val
        )}
      </div>
      {segments && segments.length > 0 && <Composition segments={segments} />}
      {footer && <div className="mt-3 text-xs text-ink-2">{footer}</div>}
    </section>
  );
}

export function ViewLink({ to, label = "View all" }: { to: string; label?: string }) {
  return (
    <Link className="inline-flex items-center gap-0.5 whitespace-nowrap text-[12.5px] font-medium text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent" to={to}>
      {label}
      <ChevronRight aria-hidden className="h-3.5 w-3.5" />
    </Link>
  );
}

/** Dashboard card: title, optional subtitle and right-hand slot (legend or link). */
export function DashCard({ title, sub, right, children, className = "" }: { title: string; sub?: ReactNode; right?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section data-print="card" className={`min-w-0 rounded-xl border border-line bg-surface-1 px-4 py-4 shadow-sm shadow-black/5 sm:px-[18px] ${className}`}>
      <header className="mb-3 flex flex-wrap items-start justify-between gap-x-3 gap-y-1">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-ink">{title}</h2>
          {sub && <p className="mt-0.5 text-xs text-ink-3">{sub}</p>}
        </div>
        {right && <div className="flex flex-wrap items-center gap-3">{right}</div>}
      </header>
      {children}
    </section>
  );
}

export function LegendKeys({ items }: { items: { label: string; color: string; dashed?: boolean }[] }) {
  return (
    <ul className="flex flex-wrap gap-x-3.5 gap-y-1 text-xs text-ink-2">
      {items.map((i) => (
        <li key={i.label} className="inline-flex items-center gap-1.5">
          {i.dashed ? (
            <span aria-hidden className="inline-block w-3 border-t-2 border-dashed" style={{ borderColor: i.color }} />
          ) : (
            <span aria-hidden className="inline-block h-2.5 w-2.5 rounded-[3px]" style={{ background: i.color }} />
          )}
          {i.label}
        </li>
      ))}
    </ul>
  );
}

/**
 * Horizontal bar rows: label · track (one value or stacked segments) · total. Each row links to
 * the list behind it; every segment has a hover tip.
 */
export function BarRows({
  rows,
  max,
  labelWidth = "7.5rem",
  suffix = "",
}: {
  rows: { key: string; label: ReactNode; segments: Segment[]; total?: number; to?: string; hint?: string; extra?: ReactNode; valueLabel?: ReactNode }[];
  max?: number;
  labelWidth?: string;
  suffix?: string;
}) {
  const top = max ?? Math.max(1, ...rows.map((r) => r.total ?? r.segments.reduce((a, s) => a + s.count, 0)));
  return (
    <ul className="space-y-0.5">
      {rows.map((r) => {
        const total = r.total ?? r.segments.reduce((a, s) => a + s.count, 0);
        const inner = (
          <>
            <span className="truncate text-[13px] text-ink" style={{ width: labelWidth, flexShrink: 0 }}>
              {r.label}
            </span>
            <span className="flex h-2 min-w-0 flex-1 rounded-full bg-surface-2">
              <span className="flex h-2 gap-[2px]" style={{ width: `${(100 * Math.min(total, top)) / top}%` }}>
                {r.segments
                  .filter((s) => s.count > 0)
                  .map((s) => (
                    <span key={s.key} className="flex min-w-[3px]" style={{ flex: s.count }}>
                      <Tip tip={`${s.label}: ${s.count}${suffix}`} className="flex w-full">
                        <span className="block h-2 w-full rounded-[3px]" style={{ background: s.color }} />
                      </Tip>
                    </span>
                  ))}
              </span>
            </span>
            <span className="w-11 shrink-0 text-right text-[13px] font-semibold text-ink">{r.valueLabel ?? `${fmtNum(total, 1)}${suffix}`}</span>
            {r.extra}
          </>
        );
        const cls = "flex items-center gap-2.5 rounded-lg px-1.5 py-1.5";
        return (
          <li key={r.key}>
            {r.to ? (
              <Link to={r.to} title={r.hint} className={`${cls} transition hover:bg-surface-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent`}>
                {inner}
              </Link>
            ) : (
              <div className={cls}>{inner}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

type TipPayload = { name?: string | number; value?: unknown; color?: string; dataKey?: unknown; payload?: Record<string, unknown> };

/** Recharts tooltip in the page's tokens; values in ink, a swatch carries the series colour. */
export function ChartTip({ active, payload, label, title }: { active?: boolean; payload?: TipPayload[]; label?: string | number; title?: (p: Record<string, unknown>) => ReactNode }) {
  if (!active || !payload?.length) return null;
  const head = title && payload[0].payload ? title(payload[0].payload) : label;
  return (
    <div className="rounded-lg border border-line bg-surface-1 px-3 py-2 text-xs shadow-lg shadow-black/20">
      {head !== undefined && <div className="mb-1 font-semibold text-ink">{head}</div>}
      <ul className="space-y-0.5">
        {payload.map((p) => (
          <li key={String(p.dataKey ?? p.name)} className="flex items-center gap-2 text-ink-2">
            <span aria-hidden className="inline-block h-2 w-2 rounded-[2px]" style={{ background: p.color }} />
            <span className="flex-1">{p.name}</span>
            <b className="font-semibold text-ink">{p.value === null || p.value === undefined ? "no data" : String(p.value)}</b>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Quiet note shown in place of a chart that has nothing to plot yet. */
export function ChartEmpty({ children, height = "h-48" }: { children: ReactNode; height?: string }) {
  return <div className={`flex ${height} items-center justify-center rounded-lg border border-dashed border-line px-6 text-center text-sm text-ink-3`}>{children}</div>;
}
