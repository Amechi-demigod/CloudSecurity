// Overview charts: ring (donut) and the severity panel (segmented bar + top 3). Colour means severity only
// (--color-ov-*); every swatch sits next to its text label and every chart has a text alternative.
import { ChevronRight } from "lucide-react";
import { Link } from "react-router-dom";
import type { Severity } from "../../api";
import { fmtNum } from "../../lib/dash";
import { OV, SEV4, SEV_LABEL, type Part } from "./palette";

const R = 54;
const C = 2 * Math.PI * R;
const GAP = 2;

/** One ring: segments with a 2px gap, the total and its unit in the centre, a count list beside it. */
export function Donut({ title, unit, parts, link }: { title: string; unit: string; parts: Part[]; link: { label: string; to: string } }) {
  const total = parts.reduce((a, p) => a + p.count, 0);
  const shown = parts.filter((p) => p.count > 0);
  const aria = `${title}: ${parts.map((p) => `${fmtNum(p.count)} ${p.label.toLowerCase()}`).join(", ")}`;
  let at = 0;
  return (
    <div className="flex min-w-0 items-center gap-4">
      <svg viewBox="0 0 140 140" className="h-[124px] w-[124px] shrink-0" role="img" aria-label={aria}>
        <title>{aria}</title>
        <g transform="rotate(-90 70 70)" fill="none" strokeWidth="16">
          <circle cx="70" cy="70" r={R} stroke={OV.none} opacity={total === 0 ? 1 : 0} />
          {shown.map((p) => {
            const len = (C * p.count) / total;
            const dash = shown.length === 1 ? len : Math.max(len - GAP, 0.5);
            const off = -at;
            at += len;
            return (
              <circle key={p.label} cx="70" cy="70" r={R} stroke={p.color} strokeDasharray={`${dash} ${C - dash}`} strokeDashoffset={off}>
                <title>{`${fmtNum(p.count)} ${p.label.toLowerCase()}`}</title>
              </circle>
            );
          })}
        </g>
        <text x="70" y="68" textAnchor="middle" className="fill-ink text-[24px] font-bold">
          {fmtNum(total)}
        </text>
        <text x="70" y="86" textAnchor="middle" className="fill-ink-3 text-[11px]">
          {unit}
        </text>
      </svg>
      <div className="min-w-0 flex-1">
        <h3 className="text-[13px] font-semibold text-ink">{title}</h3>
        <ul className="mt-1.5 space-y-1 text-[13px] text-ink-2">
          {parts.map((p) => (
            <li key={p.label} className="flex items-center gap-2">
              <span aria-hidden className="h-2.5 w-2.5 shrink-0 rounded-[3px]" style={{ background: p.color }} />
              <span className="min-w-0 flex-1 truncate">{p.label}</span>
              <b className="font-semibold text-ink">{fmtNum(p.count)}</b>
            </li>
          ))}
        </ul>
        <Link to={link.to} className="mt-2 inline-flex items-center gap-0.5 text-[12.5px] font-medium text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
          {link.label}
          <ChevronRight aria-hidden className="h-3.5 w-3.5" />
        </Link>
      </div>
    </div>
  );
}

export interface TopRow {
  severity: Severity;
  title: string;
  count: number;
  to: string;
}

export function SeverityDot({ severity }: { severity: string }) {
  return <span aria-hidden className="h-2.5 w-2.5 shrink-0 rounded-[3px]" style={{ background: OV[severity as keyof typeof OV] ?? OV.low }} />;
}

/** Thin segmented bar split by severity (% under each segment), legend, then the top 3 table. */
export function SeverityPanel({
  title,
  counts,
  top,
  countHead,
  link,
  emptyText,
}: {
  title: string;
  counts: Partial<Record<Severity, number>>;
  top: TopRow[];
  countHead: string;
  link: { label: string; to: string };
  emptyText: string;
}) {
  const sevs = SEV4;
  const total = sevs.reduce((a, s) => a + (counts[s] ?? 0), 0);
  const segs = sevs.filter((s) => (counts[s] ?? 0) > 0);
  const aria = `${title}: ${sevs.map((s) => `${counts[s] ?? 0} ${SEV_LABEL[s].toLowerCase()}`).join(", ")}`;
  if (total === 0) return <p className="rounded-lg border border-dashed border-line px-4 py-8 text-center text-sm text-ink-3">{emptyText}</p>;
  return (
    <div>
      <div role="img" aria-label={aria}>
        <div className="flex h-2.5 gap-[2px]">
          {segs.map((s) => (
            <span key={s} className="block rounded-[3px]" style={{ flex: counts[s], background: OV[s], minWidth: 4 }} title={`${counts[s]} ${SEV_LABEL[s].toLowerCase()}`} />
          ))}
        </div>
        <div className="mt-1 flex gap-[2px] text-[11px] text-ink-3" aria-hidden>
          {segs.map((s) => {
            const pct = Math.round((100 * (counts[s] ?? 0)) / total);
            return (
              <span key={s} className="overflow-hidden whitespace-nowrap" style={{ flex: counts[s], minWidth: 4 }}>
                {pct >= 7 ? `${pct}%` : ""}
              </span>
            );
          })}
        </div>
      </div>
      <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-2">
        {sevs.map((s) => (
          <li key={s} className="inline-flex items-center gap-1.5">
            <SeverityDot severity={s} />
            {SEV_LABEL[s]} <b className="font-semibold text-ink">{fmtNum(counts[s] ?? 0)}</b>
          </li>
        ))}
      </ul>
      {top.length > 0 && (
        <table className="mt-4 w-full text-[13px]">
          <caption className="pb-1 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-ink-3">Top {top.length}</caption>
          <thead>
            <tr className="text-left text-[11px] uppercase tracking-[0.06em] text-ink-3">
              <th scope="col" className="py-1 pr-2 font-semibold">Severity</th>
              <th scope="col" className="py-1 pr-2 font-semibold">Issue</th>
              <th scope="col" className="py-1 text-right font-semibold">{countHead}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line border-y border-line">
            {top.map((t) => (
              <tr key={`${t.severity}-${t.title}`}>
                <td className="w-24 py-1.5 pr-2 align-top">
                  <span className="inline-flex items-center gap-1.5 text-ink-2">
                    <SeverityDot severity={t.severity} />
                    {SEV_LABEL[t.severity]}
                  </span>
                </td>
                <td className="py-1.5 pr-2 align-top">
                  <Link to={t.to} className="font-medium text-ink hover:text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
                    {t.title}
                  </Link>
                </td>
                <td className="w-20 py-1.5 text-right align-top text-ink-2">
                  {fmtNum(t.count)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <Link to={link.to} className="mt-3 inline-flex items-center gap-0.5 text-[12.5px] font-medium text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
        {link.label}
        <ChevronRight aria-hidden className="h-3.5 w-3.5" />
      </Link>
    </div>
  );
}
