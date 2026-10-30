import { Link, useNavigate } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, type DashOverview, type EndpointStats } from "../../api";
import { BarRows, ChangeChip, ChartEmpty, ChartTip, DashCard, KpiTile, LegendKeys, ViewLink } from "../../components/dash";
import { ErrorNote } from "../../components/ui";
import {
  AXIS,
  bucketLabel,
  dayLabel,
  cap,
  catSegments,
  fmtNum,
  GRID,
  href,
  NEW_COLOR,
  RESOLVED_COLOR,
  sevSegments,
} from "../../lib/dash";
import { SEV_COLOR, SEVERITIES } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import type { TabProps } from "../Dashboard";
import { TabSkeleton } from "./Skeleton";

function RiskCard({ d, days }: { d: DashOverview; days: number }) {
  const r = d.risk_score;
  const score = Math.round(r.value);
  const radius = 62;
  const c = 2 * Math.PI * radius;
  const why =
    r.critical_findings || r.critical_paths
      ? `Driven by ${r.critical_findings} critical finding${r.critical_findings === 1 ? "" : "s"} and ${r.critical_paths} critical attack path${r.critical_paths === 1 ? "" : "s"}.`
      : "No critical findings or critical attack paths.";
  return (
    <DashCard title="Overall risk score" right={<ChangeChip delta={r.delta} better="down" days={days} />} className="h-full">
      <Link to={href("/attack-paths", { view: "confirmed" })} title="Show the confirmed attack paths behind the score" className="block rounded-lg focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
        <svg viewBox="0 0 160 160" className="mx-auto block h-[160px] w-[160px]" role="img" aria-label={`Risk score ${score} of 100, ${r.severity}`}>
          <title>{`Risk score ${score} / 100 (${r.severity})`}</title>
          <circle cx="80" cy="80" r={radius} stroke="var(--color-surface-2)" strokeWidth="16" fill="none" />
          {score > 0 && (
            <circle
              cx="80"
              cy="80"
              r={radius}
              stroke={SEV_COLOR[r.severity]}
              strokeWidth="16"
              fill="none"
              strokeDasharray={`${(score / 100) * c} ${c}`}
              transform="rotate(-90 80 80)"
            />
          )}
          <text x="80" y="82" textAnchor="middle" fontSize="30" fontWeight="700" fill="var(--color-ink)">
            {score}
          </text>
          <text x="80" y="102" textAnchor="middle" fontSize="11" fill="var(--color-ink-3)">
            / 100
          </text>
        </svg>
      </Link>
      <p className="mt-3 text-xs text-ink-2">
        <span className="font-semibold text-ink">{cap(r.severity)}.</span> {why}
      </p>
    </DashCard>
  );
}

/** Why an asset ranks where it does: "2 critical · 1 high · exposed · sensitive data". */
function riskReason(a: DashOverview["top_assets"][number]): string {
  const parts = [
    a.critical > 0 && `${a.critical} critical`,
    a.high > 0 && `${a.high} high`,
    a.internet_exposed && "exposed",
    a.sensitive_data && "sensitive data",
  ].filter(Boolean);
  return parts.length ? parts.join(" · ") : `${a.findings + a.vulnerabilities} open issues`;
}

function MttrFooter({ m }: { m: DashOverview["kpis"]["mttr"] }) {
  const sep = <span className="mx-1.5 text-line">|</span>;
  const d = (v: number | null) => (v === null ? "—" : `${fmtNum(v, 1)} d`);
  return (
    <span title={`SLA targets: critical ${m.sla_days.critical} days, high ${m.sla_days.high} days (${m.resolved} findings resolved in the period)`}>
      Critical <b className="font-semibold text-ink">{d(m.critical)}</b>
      {sep}High <b className="font-semibold text-ink">{d(m.high)}</b>
      {sep}SLA met <b className="font-semibold text-ink">{m.sla_met_pct === null ? "—" : `${fmtNum(m.sla_met_pct)}%`}</b>
    </span>
  );
}

export function EndpointStrip({ e }: { e: EndpointStats }) {
  const items = [
    { label: "Managed devices", value: e.managed, to: "/devices", color: "var(--color-ink)" },
    { label: "Healthy", value: e.healthy, to: href("/devices", { health: "healthy" }), color: "var(--color-good)" },
    { label: "Failing posture checks", value: e.failing, to: "/devices", color: e.failing ? "var(--color-sev-high)" : "var(--color-ink)", hint: "Devices with at least one failing posture check" },
    { label: "Sign-in suspended", value: e.suspended, to: "/devices", color: e.suspended ? "var(--color-sev-medium)" : "var(--color-ink)", hint: "Devices with sign-in suspended (host isolation)" },
    {
      label: "Outdated agent",
      value: e.outdated,
      to: "/devices/updates",
      color: "var(--color-ink-2)",
      hint: e.latest_agent_version ? `Older than agent ${e.latest_agent_version}` : "No agent version to compare with",
    },
  ];
  return (
    <div className="grid grid-cols-2 gap-y-3 sm:grid-cols-3 lg:grid-cols-5">
      {items.map((i, n) => (
        <Link
          key={i.label}
          to={i.to}
          title={i.hint ?? `Show ${i.label.toLowerCase()}`}
          className={`rounded-lg px-4 py-1 transition hover:bg-surface-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent lg:rounded-none lg:border-l lg:border-line lg:hover:bg-transparent ${n === 0 ? "lg:border-l-0 lg:pl-0" : ""}`}
        >
          <span className="block text-xs text-ink-3">{i.label}</span>
          <b className="mt-1 block text-[22px] font-bold" style={{ color: i.color }}>
            {i.value}
          </b>
        </Link>
      ))}
    </div>
  );
}

export default function OverviewTab({ range, account }: TabProps) {
  const navigate = useNavigate();
  const { data: d, error } = useApi(() => api.dashOverview({ range, account: account || undefined }), [range, account], 60000);
  if (!d) return error ? <ErrorNote error={error} /> : <TabSkeleton />;
  const k = d.kpis;
  const days = d.days;
  const sub = account || undefined;
  const findings = (p: Record<string, string | undefined> = {}) => href("/findings", { ...p, subscription: sub });
  // Axis: the bucket's first day; tooltip: the whole bucket ("Oct 1 – Oct 7" for a week).
  const trend = d.issue_trend.points.map((p) => ({ ...p, label: dayLabel(p.start), range: bucketLabel(p, d.issue_trend.bucket) }));
  const trendEmpty = trend.every((p) => p.new === 0 && p.resolved === 0);
  const ageEmpty = d.age.every((a) => a.critical + a.high + a.medium + a.low === 0);
  const catMax = Math.max(1, ...d.categories.map((c) => c.total));

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
      <div className="lg:col-span-4 xl:col-span-3">
        <RiskCard d={d} days={days} />
      </div>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:col-span-8 xl:col-span-9 xl:grid-cols-3">
        <KpiTile
          label="Open issues"
          value={k.open_issues.value}
          to={findings()}
          hint="Show open posture findings"
          delta={k.open_issues.delta}
          days={days}
          segments={sevSegments(k.open_issues.parts, (s) => findings({ severity: s }))}
        />
        <KpiTile
          label="Critical & high"
          value={k.critical_high.value}
          to={findings({ severity: "critical" })}
          hint="Show open critical findings"
          delta={k.critical_high.delta}
          days={days}
          segments={sevSegments(k.critical_high.parts, (s) => findings({ severity: s }), ["critical", "high"])}
        />
        <KpiTile
          label="Mean time to resolve"
          value={k.mttr.value === null ? "—" : fmtNum(k.mttr.value, 1)}
          unit={k.mttr.value === null ? undefined : "days"}
          to={findings({ status: "resolved" })}
          hint={`Show resolved findings (${k.mttr.resolved} resolved in the last ${days} days)`}
          delta={k.mttr.delta}
          deltaUnit=" d"
          days={days}
          footer={k.mttr.resolved === 0 ? `No findings resolved in the last ${days} days.` : <MttrFooter m={k.mttr} />}
        />
        <KpiTile
          label="Internet-exposed assets"
          value={k.exposed_assets.value}
          to={href("/exposure", { subscription: sub })}
          hint="Show internet-exposed assets"
          delta={k.exposed_assets.delta}
          days={days}
          segments={catSegments(k.exposed_assets.parts, (p) => href("/exposure", { type: p.types?.length === 1 ? p.types[0] : undefined, subscription: sub }))}
        />
        <KpiTile
          label="Active runtime threats"
          value={k.runtime_threats.value}
          to="/threats"
          hint="Show active runtime threats"
          delta={k.runtime_threats.delta}
          days={days}
          segments={sevSegments(k.runtime_threats.parts, (s) => href("/threats", { severity: s }))}
        />
        <KpiTile
          label="Attack paths"
          value={k.attack_paths.value}
          to={href("/attack-paths", { view: "confirmed" })}
          hint="Show confirmed attack paths"
          delta={k.attack_paths.delta}
          days={days}
          segments={sevSegments(k.attack_paths.parts, () => href("/attack-paths", { view: "confirmed" }))}
        />
      </div>

      <DashCard
        title="Issue trend: new vs resolved"
        sub={d.issue_trend.bucket === "week" ? "Posture findings per week" : "Posture findings per day"}
        right={<LegendKeys items={[{ label: "New", color: NEW_COLOR }, { label: "Resolved", color: RESOLVED_COLOR }]} />}
        className="lg:col-span-12 xl:col-span-8"
      >
        {trendEmpty ? (
          <ChartEmpty height="h-56">No findings were opened or resolved in the last {days} days.</ChartEmpty>
        ) : (
          <div className="h-56">
            <ResponsiveContainer>
              <BarChart data={trend} barGap={2} barCategoryGap={d.issue_trend.bucket === "week" ? "30%" : "22%"} margin={{ top: 4, right: 4, bottom: 0, left: -4 }}>
                <CartesianGrid {...GRID} />
                <XAxis dataKey="label" {...AXIS} minTickGap={24} />
                <YAxis {...AXIS} allowDecimals={false} width={40} />
                <Tooltip cursor={{ fill: "var(--color-surface-2)" }} content={<ChartTip title={(p) => String(p.range)} />} />
                <Bar dataKey="new" name="New" fill={NEW_COLOR} radius={[2, 2, 0, 0]} maxBarSize={22} isAnimationActive={false} cursor="pointer"
                  onClick={() => navigate(findings())} />
                <Bar dataKey="resolved" name="Resolved" fill={RESOLVED_COLOR} radius={[2, 2, 0, 0]} maxBarSize={22} isAnimationActive={false} cursor="pointer"
                  onClick={() => navigate(findings({ status: "resolved" }))} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </DashCard>

      <DashCard title="Compliance posture" sub="Controls passing, by framework" right={<ViewLink to={findings()} />} className="lg:col-span-6 xl:col-span-4">
        {d.compliance.length === 0 ? (
          <ChartEmpty height="h-40">No frameworks apply yet: connect a cloud account to check its controls.</ChartEmpty>
        ) : (
          <BarRows
            max={100}
            suffix="%"
            rows={d.compliance.map((c) => ({
              key: c.framework,
              label: c.framework,
              total: c.score,
              segments: [{ key: "pass", label: `${c.passing} of ${c.controls} controls passing`, count: c.score, color: "var(--color-cat-1)" }],
              to: findings({ compliance: c.framework }),
              hint: `${c.passing}/${c.controls} controls passing. Show open findings mapped to ${c.framework}`,
              valueLabel: `${fmtNum(c.score)}%`,
              extra: (
                <span className="flex w-14 shrink-0 justify-end">
                  <ChangeChip delta={c.delta} better="up" days={days} />
                </span>
              ),
            }))}
          />
        )}
      </DashCard>

      <DashCard title="Open issues by age" sub="Stacked by severity" right={<ViewLink to={findings()} />} className="lg:col-span-6 xl:col-span-4">
        {ageEmpty ? (
          <ChartEmpty height="h-52">No open findings.</ChartEmpty>
        ) : (
          <div className="h-52">
            <ResponsiveContainer>
              <BarChart data={d.age} barCategoryGap="30%" margin={{ top: 4, right: 4, bottom: 0, left: -4 }}>
                <CartesianGrid {...GRID} />
                <XAxis dataKey="label" {...AXIS} />
                <YAxis {...AXIS} allowDecimals={false} width={40} />
                <Tooltip cursor={{ fill: "var(--color-surface-2)" }} content={<ChartTip title={(p) => `Open for ${String(p.label)}`} />} />
                {[...SEVERITIES].reverse().map((s, i) => (
                  <Bar key={s} dataKey={s} name={cap(s)} stackId="age" fill={SEV_COLOR[s]} stroke="var(--color-surface-1)" strokeWidth={1}
                    radius={i === SEVERITIES.length - 1 ? [3, 3, 0, 0] : 0} isAnimationActive={false} cursor="pointer"
                    onClick={() => navigate(findings({ severity: s }))} />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </DashCard>

      <DashCard title="Findings by category" right={<ViewLink to={findings()} />} className="lg:col-span-6 xl:col-span-4">
        {d.categories.length === 0 ? (
          <ChartEmpty height="h-52">No open findings.</ChartEmpty>
        ) : (
          <BarRows
            max={catMax}
            labelWidth="6.5rem"
            rows={d.categories.map((c) => ({
              key: c.category,
              label: c.category,
              total: c.total,
              segments: sevSegments(c),
              to: findings({ category: c.category }),
              hint: `Show ${c.total} open ${c.category.toLowerCase()} findings`,
            }))}
          />
        )}
      </DashCard>

      <DashCard title="Top risky assets" right={<ViewLink to={href("/inventory", { subscription: sub })} />} className="lg:col-span-6 xl:col-span-4">
        {d.top_assets.length === 0 ? (
          <ChartEmpty height="h-52">No assets with open findings or vulnerabilities.</ChartEmpty>
        ) : (
          <table className="w-full table-fixed text-[13px]">
            <thead>
              <tr className="border-b border-line text-left text-[11px] uppercase tracking-[0.06em] text-ink-3">
                <th className="py-1.5 pr-2 font-semibold">Asset</th>
                <th className="w-[28%] py-1.5 pr-2 font-semibold">Type</th>
                <th className="w-12 py-1.5 text-right font-semibold">Risk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {d.top_assets.map((a) => (
                <tr key={a.id}>
                  <td className="py-1.5 pr-2 align-top">
                    <Link to={href("/vulnerabilities", { asset: a.id })} className="block break-all font-medium text-ink hover:text-accent hover:underline" title={`${a.name}: ${a.findings} open findings, ${a.vulnerabilities} open vulnerabilities`}>
                      {a.name}
                    </Link>
                    <span className="block text-[11.5px] text-ink-3">{riskReason(a)}</span>
                  </td>
                  <td className="py-1.5 pr-2 align-top text-ink-3" title={a.type_label}>{a.type_short}</td>
                  <td className="py-1.5 text-right align-top">
                    <span className="inline-flex items-center gap-1.5 font-semibold text-ink" title={`Risk ${a.risk} of 100`}>
                      <span aria-hidden className="h-2 w-2 rounded-full" style={{ background: SEV_COLOR[a.risk >= 70 ? "critical" : a.risk >= 45 ? "high" : a.risk >= 20 ? "medium" : "low"] }} />
                      {a.risk}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </DashCard>

      <DashCard title="Endpoints" sub={account ? "Devices are not tied to a cloud account: all devices" : undefined} right={<ViewLink to="/devices" label="Open Devices" />} className="lg:col-span-12">
        {d.endpoints.managed === 0 ? (
          <p className="text-sm text-ink-3">
            No endpoints enrolled yet. <Link className="text-accent hover:underline" to="/devices">Enroll Windows and macOS devices</Link> to track their posture.
          </p>
        ) : (
          <EndpointStrip e={d.endpoints} />
        )}
      </DashCard>
    </div>
  );
}
