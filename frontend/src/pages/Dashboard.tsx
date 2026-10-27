import { ChevronRight } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis, Legend } from "recharts";
import { api, type Dashboard } from "../api";
import { Card, ErrorNote, PageHeader, SeverityBadge, Stat } from "../components/ui";
import { SEV_COLOR, SEVERITIES } from "../lib/format";
import { useApi } from "../lib/useApi";

// Every number on this page links to the records behind it: a tile or row opens the matching
// page with its filters set in the URL (see lib/useUrlState.ts).

const q = (path: string, params: Record<string, string>) => `${path}?${new URLSearchParams(params)}`;
const cap = (s: string) => s[0].toUpperCase() + s.slice(1);

function ViewAll({ to, label = "View all" }: { to: string; label?: string }) {
  return (
    <Link className="inline-flex items-center gap-0.5 text-xs font-medium text-accent hover:underline" to={to}>
      {label}
      <ChevronRight aria-hidden className="h-3.5 w-3.5" />
    </Link>
  );
}

function DevicesTile() {
  const { data: s } = useApi(api.deviceSummary, [], 30000);
  if (!s) return null;
  const pct = (v: number | null) => (v === null ? "—" : `${v}%`);
  return (
    <Card title="Devices" className="mt-4" actions={<ViewAll to="/devices" />}>
      {s.total === 0 ? (
        <p className="text-sm text-ink-3">
          No endpoints enrolled yet. <Link className="text-accent" to="/devices">Enroll Windows and macOS devices</Link> to track their
          inventory and security posture.
        </p>
      ) : (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          <Stat label="Enrolled" value={s.total} sub={`${s.by_os.windows ?? 0} Windows · ${s.by_os.macos ?? 0} macOS`} to="/devices" />
          <Stat label="At risk" value={s.by_health.critical} sub={`${s.by_health.warning} with warnings`}
            to={q("/devices", { health: "critical" })} hint="Show devices at risk" />
          <Stat label="Disk encrypted" value={pct(s.encrypted_percent)} sub={`${s.issues.disk_encryption_off ?? 0} unencrypted`}
            to={q("/devices", { issue: "disk_encryption_off" })} hint="Show devices without disk encryption" />
          <Stat label="Firewall on" value={pct(s.firewall_percent)} sub={`${s.issues.firewall_off ?? 0} with firewall off`}
            to={q("/devices", { issue: "firewall_off" })} hint="Show devices with the firewall off" />
          <Stat label="Stale devices" value={s.connectivity.stale + s.connectivity.inactive} sub={`${s.connectivity.inactive} inactive > 7 days`}
            to={q("/devices", { connectivity: "offline" })} hint="Show devices with no check-in for 24 hours or more" />
        </div>
      )}
    </Card>
  );
}

function ExposureTile() {
  const { data: s } = useApi(api.exposureSummary, [], 30000);
  if (!s) return null;
  return (
    <Card title="Cloud exposure" className="mt-4" actions={<ViewAll to="/exposure" />}>
      {s.total === 0 ? (
        <p className="text-sm text-ink-3">No internet-exposed cloud assets found.</p>
      ) : (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          <Stat label="Open to the Internet" value={s.open} sub={`${s.attack_path_entries} attack-path entry points`}
            to={q("/exposure", { level: "open" })} hint="Show assets open to the whole Internet" />
          <Stat label="Restricted" value={s.restricted} sub="public ranges only"
            to={q("/exposure", { level: "restricted" })} hint="Show assets reachable from listed public ranges only" />
          <Stat label="Risky ports open" value={s.risky_ports_open} sub="admin or database ports"
            to="/exposure" hint="Show exposed assets and their open ports" />
          <Stat label="Exposed data stores" value={s.sensitive} sub={`${s.with_private_endpoint} with a private endpoint`}
            to="/exposure" hint="Show exposed assets (data stores are tagged sensitive)" />
        </div>
      )}
    </Card>
  );
}

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

/** Open findings per severity as linked rows (keyboard- and screen-reader-friendly, unlike chart bars). */
function SeverityRows({ counts }: { counts: Record<string, number> }) {
  const max = Math.max(1, ...SEVERITIES.map((s) => counts[s] ?? 0));
  return (
    <ul className="space-y-1">
      {SEVERITIES.map((s) => {
        const n = counts[s] ?? 0;
        return (
          <li key={s}>
            <Link
              to={q("/findings", { severity: s })}
              title={`Show ${n} open ${s} findings`}
              className="group flex items-center gap-3 rounded-lg px-2 py-2 transition hover:bg-surface-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <span className="w-16 shrink-0 text-sm text-ink-2">{cap(s)}</span>
              <span className="h-2.5 flex-1 overflow-hidden rounded-full bg-surface-2">
                <span className="block h-full rounded-full" style={{ width: `${(n / max) * 100}%`, background: SEV_COLOR[s] }} />
              </span>
              <span className="w-8 text-right text-sm font-semibold text-ink">{n}</span>
              <ChevronRight aria-hidden className="h-4 w-4 text-ink-3 group-hover:text-accent" />
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

function riskLink(r: Dashboard["top_risks"][number]): string {
  if (r.kind === "attack_path") return q("/attack-paths", { path: r.id });
  if (r.kind === "finding") return `/findings/${encodeURIComponent(r.id)}`;
  const cve = r.title.split(" ")[0]; // "<CVE id> in <package> on <asset>"
  return q("/vulnerabilities", { cve, asset: r.asset_id });
}

export default function DashboardPage() {
  const navigate = useNavigate();
  const { data: d, error } = useApi(api.dashboard, [], 10000);
  if (!d) return <ErrorNote error={error} />;

  const timeline = d.alerts_over_time.map((b) => ({
    ...b,
    label: new Date(b.hour).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
  }));
  const nr = d.vulnerabilities.noise_reduction;

  return (
    <div>
      <PageHeader title="Security overview" subtitle="Live posture, runtime and risk across all connected cloud accounts. Select any number to see the records behind it." />
      <ErrorNote error={error} />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,2fr)]">
        <Card title="Overall risk score" actions={<ViewAll to={q("/attack-paths", { view: "confirmed" })} label="Top attack paths" />}>
          <RiskGauge score={d.risk_score} />
        </Card>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
          <Stat label="Assets" value={d.assets.total} sub={`${d.assets.internet_exposed} internet-exposed`} to="/inventory" hint="Show the asset inventory" />
          <Stat label="Open findings" value={d.open_findings} sub={`${d.findings_by_severity.critical ?? 0} critical`} to="/findings" />
          <Stat label="Prioritized vulns" value={d.vulnerabilities.prioritized} sub={`of ${d.vulnerabilities.total} total`}
            to="/vulnerabilities" hint="Show vulnerabilities, highest risk first" />
          <Stat label="Noise reduction" value={`${nr.percent}%`} sub={`${nr.dormant} vulns not loaded at runtime`}
            to={q("/vulnerabilities", { runtime: "dormant" })} hint="Show vulnerabilities in packages never loaded at runtime" />
          <Stat label="Active threats" value={d.alerts.open} sub={`${d.alerts.events_24h} runtime events / 24h`} to="/threats" />
          <Stat
            label="Attack paths"
            value={d.attack_paths.total}
            sub={`${d.attack_paths.critical} critical${d.attack_paths.exposure ? `, +${d.attack_paths.exposure} exposure paths` : ""}`}
            to="/attack-paths"
          />
        </div>
      </div>

      <ExposureTile />

      <DevicesTile />

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Runtime alerts, last 24h" className="xl:col-span-2" actions={<ViewAll to="/threats" />}>
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
                    name={cap(s)}
                    isAnimationActive={false}
                    cursor="pointer"
                    onClick={() => navigate(q("/threats", { severity: s, status: "all" }))}
                  />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-2 flex flex-wrap gap-2 text-xs" aria-label="Active alerts by severity">
            {SEVERITIES.map((s) => (
              <Link
                key={s}
                to={q("/threats", { severity: s })}
                className="inline-flex items-center gap-1.5 rounded-full border border-line px-2.5 py-1 text-ink-2 transition hover:border-accent/60 hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <span aria-hidden className="h-2 w-2 rounded-full" style={{ background: SEV_COLOR[s] }} />
                {cap(s)} <span className="font-semibold text-ink">{d.alerts.by_severity[s] ?? 0}</span> active
              </Link>
            ))}
          </div>
        </Card>
        <Card title="Open findings by severity" actions={<ViewAll to="/findings" />}>
          <SeverityRows counts={d.findings_by_severity} />
        </Card>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Top risks" className="xl:col-span-2">
          <ul className="divide-y divide-line/60">
            {d.top_risks.map((r) => (
              <li key={`${r.kind}-${r.id}`}>
                <Link
                  to={riskLink(r)}
                  title={r.title}
                  className="group flex items-center gap-3 rounded-lg px-2 py-2 transition hover:bg-surface-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  <SeverityBadge severity={r.severity} />
                  <span className="w-24 shrink-0 text-[11px] uppercase tracking-wide text-ink-3">{r.kind.replace("_", " ")}</span>
                  <span className="min-w-0 flex-1 truncate text-sm group-hover:text-accent">{r.title}</span>
                  {r.score !== null && <span className="text-xs text-ink-2">risk {r.score.toFixed(0)}</span>}
                  <ChevronRight aria-hidden className="h-4 w-4 shrink-0 text-ink-3 group-hover:text-accent" />
                </Link>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Compliance summary">
          <ul className="space-y-1">
            {d.compliance.map((c) => (
              <li key={c.framework}>
                <Link
                  to={q("/findings", { compliance: c.framework })}
                  title={`Show open findings mapped to ${c.framework}`}
                  className="group block rounded-lg px-2 py-2 transition hover:bg-surface-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  <div className="flex justify-between text-sm">
                    <span className="group-hover:text-accent">{c.framework}</span>
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
                </Link>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </div>
  );
}
