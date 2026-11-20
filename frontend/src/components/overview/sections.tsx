// The Overview's new widgets. Each takes only data the API already provides (see pages/dashboards/Overview.tsx
// for where it is fetched) and links to the page behind it.
import { Link } from "react-router-dom";
import type { DashOverview, DashVulns, Severity } from "../../api";
import type { ExtFindingGroup, ExtHost, ExtOverview } from "../../externalApi";
import { fmtNum, href } from "../../lib/dash";
import { ChartEmpty, DashCard, ViewLink } from "../dash";
import { Donut, SeverityDot, SeverityPanel, type TopRow } from "./charts";
import { OV, SEV4 } from "./palette";

const rank = (s: string) => (SEV4 as string[]).indexOf(s);
const plural = (n: number, one: string, many = `${one}s`) => `${fmtNum(n)} ${n === 1 ? one : many}`;

export interface OverviewData {
  d: DashOverview;
  vulns: DashVulns | null;
  ext: ExtOverview | null;
  extTop: ExtFindingGroup[] | null;
  extHosts: ExtHost[] | null;
  has: { cloud: boolean; endpoints: boolean; vulns: boolean; external: boolean };
  sub?: string;
}

/** Open issues by severity across the modules the organisation has. */
function issueCounts({ d, vulns, ext, has }: OverviewData): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  if (has.cloud) for (const s of SEV4) out[s] += d.kpis.open_issues.parts?.[s] ?? 0;
  if (has.vulns && vulns) for (const r of vulns.by_severity) if (r.severity in out) out[r.severity] += r.vulns;
  if (has.external && ext) for (const s of SEV4) out[s] += ext.by_severity[s] ?? 0;
  return out;
}

export function SummaryWidget(p: OverviewData) {
  const { d, extHosts, has } = p;
  const c = issueCounts(p);
  const issuesTo = has.cloud ? href("/findings", { subscription: p.sub }) : has.vulns ? "/vulnerabilities" : "/attack-surface/findings";
  const rings = [
    <Donut key="issues" title="Issues by severity" unit="open" parts={SEV4.map((s) => ({ label: s[0].toUpperCase() + s.slice(1), count: c[s], color: OV[s] }))} link={{ label: "See all", to: issuesTo }} />,
  ];
  if (has.cloud)
    rings.push(
      <Donut
        key="assets"
        title="Assets"
        unit="assets"
        parts={[
          { label: "Have issues", count: d.assets.with_issues, color: OV.attention },
          { label: "No issues", count: Math.max(d.assets.total - d.assets.with_issues, 0), color: OV.none },
        ]}
        link={{ label: "See all", to: href("/inventory", { subscription: p.sub }) }}
      />,
    );
  if (has.endpoints) {
    const e = d.endpoints;
    rings.push(
      <Donut
        key="computers"
        title="Computers & servers"
        unit="computers"
        parts={[
          { label: "Need attention", count: Math.max(e.managed - e.healthy, 0), color: OV.attention },
          { label: "Healthy", count: e.healthy, color: OV.none },
        ]}
        link={{ label: "See all", to: "/devices" }}
      />,
    );
  } else if (has.external && extHosts) {
    const bad = extHosts.filter((h) => h.active && h.findings > 0).length;
    rings.push(
      <Donut
        key="systems"
        title="Internet-facing systems"
        unit="systems"
        parts={[
          { label: "Have issues", count: bad, color: OV.attention },
          { label: "No issues", count: extHosts.filter((h) => h.active).length - bad, color: OV.none },
        ]}
        link={{ label: "See all", to: "/attack-surface" }}
      />,
    );
  }
  return (
    <DashCard title="Summary">
      <div className="grid grid-cols-1 gap-x-6 gap-y-5 md:grid-cols-2 xl:grid-cols-3">{rings}</div>
    </DashCard>
  );
}

export function CloudSevWidget({ d, sub }: OverviewData) {
  const top: TopRow[] = d.top_issues.map((t) => ({ severity: t.severity, title: t.title, count: t.assets, to: href("/findings", { rule: t.rule_id, subscription: sub }) }));
  return (
    <DashCard title="Cloud issues by severity">
      <SeverityPanel title="Cloud issues by severity" counts={d.kpis.open_issues.parts ?? {}} top={top} countHead="Assets affected" link={{ label: "All cloud issues", to: href("/findings", { subscription: sub }) }} emptyText="No open cloud issues." />
    </DashCard>
  );
}

export function VulnSevWidget({ vulns }: OverviewData) {
  if (!vulns) return <DashCard title="Vulnerabilities by severity"><ChartEmpty height="h-40">Loading…</ChartEmpty></DashCard>;
  const counts = Object.fromEntries(vulns.by_severity.map((r) => [r.severity, r.vulns]));
  const top: TopRow[] = [...vulns.top_cves]
    .sort((a, b) => rank(a.severity) - rank(b.severity) || Number(b.kev) - Number(a.kev) || b.assets - a.assets)
    .slice(0, 3)
    .map((c) => ({ severity: c.severity, title: `${c.package} (${c.cve_id})${c.kev ? ", being exploited" : ""}`, count: c.assets, to: href("/vulnerabilities", { cve: c.cve_id }) }));
  return (
    <DashCard title="Vulnerabilities by severity">
      <SeverityPanel title="Vulnerabilities by severity" counts={counts} top={top} countHead="Computers" link={{ label: "All vulnerabilities", to: "/vulnerabilities" }} emptyText="No open vulnerabilities." />
    </DashCard>
  );
}

export function ExtSevWidget({ ext, extTop }: OverviewData) {
  if (!ext) return <DashCard title="Internet-facing by severity"><ChartEmpty height="h-40">Loading…</ChartEmpty></DashCard>;
  const top: TopRow[] = (extTop ?? [])
    .filter((g) => g.severity !== "info")
    .sort((a, b) => rank(a.severity) - rank(b.severity) || b.affected - a.affected)
    .slice(0, 3)
    .map((g) => ({ severity: g.severity as Severity, title: g.title, count: g.affected, to: href("/attack-surface/findings", { severity: g.severity }) }));
  return (
    <DashCard title="Internet-facing by severity">
      <SeverityPanel title="Internet-facing by severity" counts={ext.by_severity} top={top} countHead="Ports" link={{ label: "All scan results", to: "/attack-surface/findings" }} emptyText="No open internet-facing issues." />
    </DashCard>
  );
}

interface Item {
  severity: Severity;
  title: string;
  sub: string;
  to: string;
}

/** Plain-language to-do items from the numbers the page already has; the most severe first, at most 5. */
function attentionItems({ d, vulns, ext, has, sub }: OverviewData): Item[] {
  const items: Item[] = [];
  if (has.external && ext && ext.failing_findings > 0)
    items.push({ severity: "critical", title: `${plural(ext.failing_findings, "internet-facing issue")} would fail a pre-ASV scan`, sub: "Systems anyone on the internet can reach", to: "/attack-surface/findings" });
  if (has.cloud) {
    const crit = d.kpis.open_issues.parts?.critical ?? 0;
    if (crit > 0) items.push({ severity: "critical", title: `${plural(crit, "critical cloud issue")} to fix`, sub: `${fmtNum(d.kpis.open_issues.value ?? 0)} open in total`, to: href("/findings", { severity: "critical", subscription: sub }) });
    if (d.kpis.attack_paths.value) items.push({ severity: "high", title: `${plural(d.kpis.attack_paths.value, "route")} an attacker could take into your systems`, sub: "Confirmed attack paths", to: href("/attack-paths", { view: "confirmed" }) });
  }
  if (has.vulns && vulns && (vulns.kpis.kev.value ?? 0) > 0)
    items.push({ severity: "critical", title: `${plural(vulns.kpis.kev.value ?? 0, "vulnerability", "vulnerabilities")} being used by attackers now`, sub: "Update the affected software first", to: href("/vulnerabilities", { kev: "1" }) });
  if (has.endpoints) {
    const e = d.endpoints;
    if (e.managed - e.healthy > 0) items.push({ severity: "high", title: `${plural(e.managed - e.healthy, "computer")} need${e.managed - e.healthy === 1 ? "s" : ""} attention`, sub: `of ${fmtNum(e.managed)} computers & servers`, to: "/devices" });
    if (d.kpis.runtime_threats.value) items.push({ severity: "high", title: `${plural(d.kpis.runtime_threats.value, "active threat")} detected on your computers`, sub: "Being looked at now", to: "/threats" });
    if (e.outdated > 0) items.push({ severity: "low", title: `${plural(e.outdated, "device")} running an out-of-date agent`, sub: "Update the Sentrigis agent", to: "/devices/updates" });
  }
  return items.sort((a, b) => rank(a.severity) - rank(b.severity)).slice(0, 5);
}

export function AttentionWidget(p: OverviewData) {
  const items = attentionItems(p);
  return (
    <DashCard title="Needs your attention">
      {items.length === 0 ? (
        <ChartEmpty height="h-40">Nothing needs your attention right now.</ChartEmpty>
      ) : (
        <ul className="divide-y divide-line">
          {items.map((i) => (
            <li key={i.title}>
              <Link to={i.to} className="flex items-start gap-3 rounded-lg py-2.5 hover:bg-surface-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
                <span className="mt-1 flex shrink-0 items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.04em] text-ink-2">
                  <SeverityDot severity={i.severity} />
                  <span className="w-[4.2rem]">{i.severity}</span>
                </span>
                <span className="min-w-0">
                  <span className="block text-[13.5px] font-medium text-ink">{i.title}</span>
                  <span className="block text-xs text-ink-3">{i.sub}</span>
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </DashCard>
  );
}

export function TrendWidget({ d }: OverviewData) {
  const t = d.issue_trend;
  const pts = t.points.slice(-8);
  const max = Math.max(1, ...pts.flatMap((p) => [p.new, p.resolved]));
  const unit = t.bucket === "week" ? "week" : "day";
  const keys = (
    <ul className="flex gap-3.5 text-xs text-ink-2">
      <li className="inline-flex items-center gap-1.5"><span aria-hidden className="h-2.5 w-2.5 rounded-[3px]" style={{ background: "var(--color-ov-neutral)" }} />New</li>
      <li className="inline-flex items-center gap-1.5"><span aria-hidden className="h-2.5 w-2.5 rounded-[3px] bg-accent" />Fixed</li>
    </ul>
  );
  const empty = pts.every((p) => p.new === 0 && p.resolved === 0);
  return (
    <DashCard title="New vs fixed" sub={`Cloud issues, last ${pts.length} ${unit}s`} right={keys}>
      {empty ? (
        <ChartEmpty height="h-40">Nothing was opened or fixed in this period.</ChartEmpty>
      ) : (
        <div className="flex h-40 items-end gap-2 border-b border-line pb-px">
          {pts.map((p) => {
            const label = `${p.start}${unit === "week" ? ` to ${p.end}` : ""}: ${fmtNum(p.new)} new, ${fmtNum(p.resolved)} fixed`;
            return (
              <div key={p.start} className="group relative flex h-full flex-1 items-end justify-center gap-[3px]" tabIndex={0} role="img" aria-label={label}>
                <span className="w-full max-w-[14px] rounded-t-[3px]" style={{ height: `${(100 * p.new) / max}%`, minHeight: p.new ? 2 : 0, background: "var(--color-ov-neutral)" }} />
                <span className="w-full max-w-[14px] rounded-t-[3px] bg-accent" style={{ height: `${(100 * p.resolved) / max}%`, minHeight: p.resolved ? 2 : 0 }} />
                <span role="tooltip" className="pointer-events-none absolute bottom-full left-1/2 z-30 mb-1 hidden -translate-x-1/2 whitespace-nowrap rounded-md border border-line bg-surface-1 px-2 py-1 text-xs text-ink shadow-lg group-hover:block group-focus:block">
                  {label}
                </span>
              </div>
            );
          })}
        </div>
      )}
      {!empty && (
        <div className="mt-1 flex gap-2 text-[11px] text-ink-3" aria-hidden>
          {pts.map((p) => (
            <span key={p.start} className="flex-1 truncate text-center">{p.start.slice(5)}</span>
          ))}
        </div>
      )}
    </DashCard>
  );
}

export function ComplianceWidget({ d, sub }: OverviewData) {
  return (
    <DashCard title="Compliance" right={<ViewLink to="/compliance" label="All" />}>
      {d.compliance.length === 0 ? (
        <ChartEmpty height="h-40">No frameworks apply yet: connect a cloud account to check its controls.</ChartEmpty>
      ) : (
        <ul className="space-y-3">
          {d.compliance.map((c) => (
            <li key={c.framework}>
              <Link to={href("/findings", { compliance: c.framework, subscription: sub })} className="block rounded-lg focus:outline-none focus-visible:ring-2 focus-visible:ring-accent" title={`Show open findings mapped to ${c.framework}`}>
                <span className="flex items-baseline justify-between gap-2 text-[13px]">
                  <span className="font-medium text-ink">{c.framework}</span>
                  <b className="font-semibold text-ink">{fmtNum(c.score)}%</b>
                </span>
                <span className="mt-1 block h-2 overflow-hidden rounded-full bg-surface-2" role="progressbar" aria-label={`${c.framework} controls passing`} aria-valuenow={Math.round(c.score)} aria-valuemin={0} aria-valuemax={100}>
                  <span className="block h-full rounded-full bg-accent" style={{ width: `${Math.min(100, Math.max(c.score, c.score > 0 ? 1 : 0))}%` }} />
                </span>
                <span className="mt-0.5 block text-xs text-ink-3">{c.passing} of {c.controls} controls pass</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </DashCard>
  );
}
