import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, Cell, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis, Legend } from "recharts";
import { api } from "../api";
import { Card, ErrorNote, PageHeader, SEV_COLOR, SEVERITIES, SeverityBadge, Stat, useApi } from "../components/ui";

const axis = { stroke: "var(--color-ink-3)", fontSize: 11, tickLine: false, axisLine: false } as const;

function RiskGauge({ score }: { score: number }) {
  const sev = score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : "low";
  const r = 52;
  const c = 2 * Math.PI * r;
  return (
    <div className="flex items-center gap-5">
      <svg width="130" height="130" viewBox="0 0 130 130" role="img" aria-label={`Risk score ${score} of 100`}>
        <circle cx="65" cy="65" r={r} stroke="var(--color-surface-2)" strokeWidth="10" fill="none" />
        <circle
          cx="65"
          cy="65"
          r={r}
          stroke={SEV_COLOR[sev]}
          strokeWidth="10"
          fill="none"
          strokeLinecap="round"
          strokeDasharray={`${(score / 100) * c} ${c}`}
          transform="rotate(-90 65 65)"
        />
        <text x="65" y="66" textAnchor="middle" fontSize="30" fontWeight="600" fill="var(--color-ink)">
          {Math.round(score)}
        </text>
        <text x="65" y="86" textAnchor="middle" fontSize="11" fill="var(--color-ink-3)">
          / 100
        </text>
      </svg>
      <div className="space-y-2">
        <SeverityBadge severity={sev} />
        <p className="max-w-[16rem] text-xs text-ink-2">
          Combines open misconfigurations, runtime-prioritized vulnerabilities, active threats and exploitable attack
          paths, normalized by environment size.
        </p>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const { data: d, error } = useApi(api.dashboard, [], 10000);
  if (!d) return <ErrorNote error={error} />;

  const findings = SEVERITIES.map((s) => ({ severity: s, count: d.findings_by_severity[s] ?? 0 }));
  const timeline = d.alerts_over_time.map((b) => ({
    ...b,
    label: new Date(b.hour).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
  }));
  const nr = d.vulnerabilities.noise_reduction;

  return (
    <div>
      <PageHeader title="Security overview" subtitle="Live posture, runtime and risk across all connected cloud accounts." />
      <ErrorNote error={error} />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,2fr)]">
        <Card title="Overall risk score">
          <RiskGauge score={d.risk_score} />
        </Card>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
          <Stat label="Assets" value={d.assets.total} sub={`${d.assets.internet_exposed} internet-exposed`} />
          <Stat label="Open findings" value={d.open_findings} sub={`${d.findings_by_severity.critical ?? 0} critical`} />
          <Stat
            label="Prioritized vulns"
            value={d.vulnerabilities.prioritized}
            sub={`of ${d.vulnerabilities.total} total`}
          />
          <Stat
            label="Noise reduction"
            value={`${nr.percent}%`}
            sub={`${nr.dormant} vulns not loaded at runtime`}
          />
          <Stat label="Active threats" value={d.alerts.open} sub={`${d.alerts.events_24h} runtime events / 24h`} />
          <Stat label="Attack paths" value={d.attack_paths.total} sub={`${d.attack_paths.critical} critical`} />
        </div>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Runtime alerts, last 24h" className="xl:col-span-2">
          <div className="h-60">
            <ResponsiveContainer>
              <BarChart data={timeline} barCategoryGap={2}>
                <CartesianGrid vertical={false} stroke="var(--color-line)" strokeDasharray="2 4" />
                <XAxis dataKey="label" {...axis} interval={3} />
                <YAxis {...axis} allowDecimals={false} width={28} />
                <Tooltip cursor={{ fill: "var(--color-surface-2)" }} labelStyle={{ color: "var(--color-ink)" }} />
                <Legend wrapperStyle={{ fontSize: 12, color: "var(--color-ink-2)" }} iconType="square" />
                {SEVERITIES.map((s, i) => (
                  <Bar
                    key={s}
                    dataKey={s}
                    stackId="a"
                    fill={SEV_COLOR[s]}
                    stroke="var(--color-surface-1)"
                    strokeWidth={1}
                    radius={i === 0 ? [3, 3, 0, 0] : 0}
                    name={s[0].toUpperCase() + s.slice(1)}
                    isAnimationActive={false}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card title="Open findings by severity" actions={<Link className="text-xs text-accent" to="/findings">View all</Link>}>
          <div className="h-60">
            <ResponsiveContainer>
              <BarChart data={findings} layout="vertical" margin={{ right: 36 }}>
                <XAxis type="number" hide />
                <YAxis type="category" dataKey="severity" {...axis} width={70} tickFormatter={(s: string) => s[0].toUpperCase() + s.slice(1)} />
                <Tooltip cursor={{ fill: "var(--color-surface-2)" }} />
                <Bar dataKey="count" name="Findings" radius={[0, 4, 4, 0]} barSize={22} isAnimationActive={false}>
                  {findings.map((f) => (
                    <Cell key={f.severity} fill={SEV_COLOR[f.severity]} />
                  ))}
                  <LabelList dataKey="count" position="right" fill="var(--color-ink)" fontSize={12} />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Top risks" className="xl:col-span-2">
          <ul className="divide-y divide-line/60">
            {d.top_risks.map((r) => (
              <li key={`${r.kind}-${r.id}`} className="flex items-center gap-3 py-2">
                <SeverityBadge severity={r.severity} />
                <span className="w-24 shrink-0 text-[11px] uppercase tracking-wide text-ink-3">
                  {r.kind.replace("_", " ")}
                </span>
                <Link
                  to={r.kind === "attack_path" ? "/attack-paths" : r.kind === "vulnerability" ? "/vulnerabilities" : "/findings"}
                  className="min-w-0 flex-1 truncate text-sm hover:text-accent"
                  title={r.title}
                >
                  {r.title}
                </Link>
                {r.score !== null && <span className="text-xs text-ink-2">risk {r.score.toFixed(0)}</span>}
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Compliance summary">
          <div className="space-y-4">
            {d.compliance.map((c) => (
              <div key={c.framework}>
                <div className="flex justify-between text-sm">
                  <span>{c.framework}</span>
                  <span className="text-ink-2">
                    {c.passing}/{c.controls} controls · <span className="text-ink">{c.score}%</span>
                  </span>
                </div>
                <div className="mt-1.5 h-2 overflow-hidden rounded-full bg-surface-2">
                  <div className="h-full rounded-full bg-accent" style={{ width: `${c.score}%` }} />
                </div>
                {c.failing_controls.length > 0 && (
                  <div className="mt-1 truncate text-[11px] text-ink-3" title={c.failing_controls.join(", ")}>
                    Failing: {c.failing_controls.join(", ")}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
