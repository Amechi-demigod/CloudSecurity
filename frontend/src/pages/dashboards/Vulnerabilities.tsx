import { Link } from "react-router-dom";
import { Area, CartesianGrid, ComposedChart, Line, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, type DashCve } from "../../api";
import { BarRows, ChartEmpty, ChartTip, DashCard, KpiTile, LegendKeys, ViewLink } from "../../components/dash";
import { ErrorNote, SeverityBadge, Tag } from "../../components/ui";
import { AXIS, bucketLabel, cap, CAT_COLORS, fmtNum, GRID, href, OTHER_COLOR, sevSegments } from "../../lib/dash";
import { SEV_COLOR } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import type { TabProps } from "../Dashboard";
import { TabSkeleton } from "./Skeleton";

function signals(c: DashCve): string[] {
  return [c.kev && "KEV", c.runtime && "Runtime", c.internet && "Internet", c.endpoint && "Endpoint"].filter(Boolean) as string[];
}

export default function VulnsTab({ range, account }: TabProps) {
  const { data: d, error } = useApi(() => api.dashVulns({ range, account: account || undefined }), [range, account], 60000);
  if (!d) return error ? <ErrorNote error={error} /> : <TabSkeleton />;
  const k = d.kpis;
  const days = d.days;
  const vulns = (p: Record<string, string | undefined> = {}) => href("/vulnerabilities", p);
  const points = d.over_time.points.map((p) => ({ ...p, label: bucketLabel(p, d.over_time.bucket) }));
  const hasPrioritized = points.some((p) => p.prioritized !== null);
  const sevMax = Math.max(1, ...d.by_severity.map((s) => s.vulns));
  const wlMax = Math.max(1, ...d.workloads.map((w) => w.total));
  const nr = d.noise_reduction;

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:col-span-12 xl:grid-cols-4">
        <KpiTile
          label="Critical"
          value={k.critical.value}
          to={vulns({ severity: "critical" })}
          hint="Show open critical vulnerabilities"
          delta={k.critical.delta}
          days={days}
          segments={[
            { key: "fix", label: "Fix available", count: k.critical.fix_available, color: CAT_COLORS[0], to: vulns({ severity: "critical" }) },
            { key: "nofix", label: "No fix yet", count: k.critical.no_fix, color: OTHER_COLOR, to: vulns({ severity: "critical" }) },
          ].filter((s) => s.count > 0)}
        />
        <KpiTile
          label="Known exploited (KEV)"
          value={k.kev.value}
          to={vulns({ kev: "1" })}
          hint="Show vulnerabilities on the CISA KEV list"
          delta={k.kev.delta}
          days={days}
          segments={sevSegments(k.kev.parts, (s) => vulns({ kev: "1", severity: s }))}
        />
        <KpiTile
          label="Loaded at runtime"
          value={k.in_use.value}
          to={vulns({ runtime: "in_use" })}
          hint="Show vulnerabilities in packages loaded at runtime"
          delta={k.in_use.delta}
          days={days}
          segments={sevSegments(k.in_use.parts, (s) => vulns({ runtime: "in_use", severity: s }))}
        />
        <KpiTile
          label="Fix available"
          value={k.fix_available.value === null ? "—" : `${fmtNum(k.fix_available.value)}%`}
          to={vulns()}
          hint="Show open vulnerabilities"
          delta={k.fix_available.delta}
          better="up"
          deltaUnit=" pts"
          days={days}
          segments={[
            { key: "fix", label: "Fixable", count: k.fix_available.fixable, color: CAT_COLORS[0] },
            { key: "nofix", label: "No fix", count: k.fix_available.no_fix, color: OTHER_COLOR },
          ].filter((s) => s.count > 0)}
        />
      </div>

      <DashCard
        title="Critical & high vulnerabilities over time"
        sub="Open at the end of each period"
        right={
          <LegendKeys
            items={[
              { label: "Critical", color: SEV_COLOR.critical },
              { label: "High", color: SEV_COLOR.high },
              ...(hasPrioritized ? [{ label: "Prioritised (runtime + exposed)", color: "var(--color-ink-3)", dashed: true }] : []),
            ]}
          />
        }
        className="lg:col-span-12 xl:col-span-8"
      >
        {d.total === 0 && points.every((p) => p.critical === 0 && p.high === 0) ? (
          <ChartEmpty height="h-56">No critical or high vulnerabilities in the last {days} days.</ChartEmpty>
        ) : (
          <div className="h-56">
            <ResponsiveContainer>
              <ComposedChart data={points} margin={{ top: 4, right: 8, bottom: 0, left: -4 }}>
                <CartesianGrid {...GRID} />
                <XAxis dataKey="label" {...AXIS} minTickGap={24} />
                <YAxis {...AXIS} allowDecimals={false} width={40} />
                <Tooltip cursor={{ stroke: "var(--color-ink-3)", strokeDasharray: "3 3" }} content={<ChartTip />} />
                <Area type="monotone" dataKey="high" name="High" stroke={SEV_COLOR.high} fill={SEV_COLOR.high} fillOpacity={0.12} strokeWidth={2} dot={false} isAnimationActive={false} />
                <Area type="monotone" dataKey="critical" name="Critical" stroke={SEV_COLOR.critical} fill={SEV_COLOR.critical} fillOpacity={0.12} strokeWidth={2} dot={false} isAnimationActive={false} />
                {hasPrioritized && (
                  <Line type="monotone" dataKey="prioritized" name="Prioritised" stroke="var(--color-ink-3)" strokeDasharray="5 4" strokeWidth={2}
                    dot={{ r: 3, strokeWidth: 0, fill: "var(--color-ink-3)" }} connectNulls={false} isAnimationActive={false} />
                )}
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        )}
      </DashCard>

      <DashCard title="By severity" sub="Open vulnerabilities · hover for CVEs and affected assets" className="lg:col-span-6 xl:col-span-4">
        <BarRows
          max={sevMax}
          labelWidth="5rem"
          rows={d.by_severity.map((s) => ({
            key: s.severity,
            label: cap(s.severity),
            total: s.vulns,
            segments: [{ key: s.severity, label: `${s.vulns} vulnerabilities · ${s.cves} CVEs · ${s.assets} assets`, count: s.vulns, color: "var(--color-accent)" }],
            to: vulns({ severity: s.severity }),
            hint: `Show open ${s.severity} vulnerabilities`,
          }))}
        />
        {nr.total > 0 && (
          <p className="mt-3 text-xs text-ink-3">
            Noise reduction: <b className="font-semibold text-ink">{fmtNum(nr.percent, 1)}%</b> of workload vulnerabilities are{" "}
            <Link to={vulns({ runtime: "dormant" })} className="text-accent hover:underline">not loaded at runtime</Link> and are de-prioritised.
          </p>
        )}
      </DashCard>

      <DashCard
        title="Impact by workload type"
        right={<LegendKeys items={[{ label: "Crit", color: SEV_COLOR.critical }, { label: "High", color: SEV_COLOR.high }, { label: "Med", color: SEV_COLOR.medium }, { label: "Low", color: SEV_COLOR.low }]} />}
        className="lg:col-span-6 xl:col-span-5"
      >
        {d.workloads.length === 0 ? (
          <ChartEmpty height="h-40">No open vulnerabilities.</ChartEmpty>
        ) : (
          <BarRows
            max={wlMax}
            labelWidth="8.5rem"
            rows={d.workloads.map((w) => ({
              key: w.key,
              label: w.label,
              total: w.total,
              segments: sevSegments(w),
              to: w.key === "endpoints" ? vulns({ scope: "device" }) : vulns({ scope: "asset" }),
              hint: `Show vulnerabilities on ${w.label.toLowerCase()}`,
            }))}
          />
        )}
      </DashCard>

      <DashCard title="Top CVEs to fix first" sub="Known exploited first, then loaded and exposed, then EPSS" right={<ViewLink to={vulns()} />} className="lg:col-span-12 xl:col-span-7">
        {d.top_cves.length === 0 ? (
          <ChartEmpty height="h-40">No open vulnerabilities.</ChartEmpty>
        ) : (
          <div className="-mx-1 overflow-x-auto">
            <table className="w-full min-w-[560px] text-[13px]">
              <thead>
                <tr className="border-b border-line text-left text-[11px] uppercase tracking-[0.06em] text-ink-3">
                  <th className="px-1 py-1.5 font-semibold">CVE</th>
                  <th className="px-1 py-1.5 font-semibold">Package</th>
                  <th className="px-1 py-1.5 font-semibold">Severity</th>
                  <th className="px-1 py-1.5 text-right font-semibold">EPSS</th>
                  <th className="px-1 py-1.5 font-semibold">Signals</th>
                  <th className="px-1 py-1.5 text-right font-semibold">Assets</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {d.top_cves.map((c) => (
                  <tr key={c.cve_id}>
                    <td className="whitespace-nowrap px-1 py-2">
                      <Link to={vulns({ cve: c.cve_id })} className="font-semibold text-ink hover:text-accent hover:underline">
                        {c.cve_id}
                      </Link>
                    </td>
                    <td className="max-w-[10rem] truncate px-1 py-2 text-ink-3" title={`${c.package} ${c.version}`}>
                      {c.package} {c.version}
                    </td>
                    <td className="px-1 py-2">
                      <SeverityBadge severity={c.severity} />
                    </td>
                    <td className="px-1 py-2 text-right text-ink" title={c.epss === null ? "No EPSS score yet" : "Probability of exploitation in the next 30 days"}>
                      {c.epss === null ? "—" : c.epss.toFixed(2)}
                    </td>
                    <td className="px-1 py-2">
                      <span className="flex flex-wrap gap-1">
                        {signals(c).map((s) => (
                          <Tag key={s} tone={s === "KEV" ? "critical" : "default"}>
                            {s}
                          </Tag>
                        ))}
                      </span>
                    </td>
                    <td className="px-1 py-2 text-right text-ink">{c.assets}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </DashCard>
    </div>
  );
}
