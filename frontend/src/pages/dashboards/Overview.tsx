import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, type DashOverview } from "../../api";
import { useAuth } from "../../auth/context";
import { BarRows, ChangeChip, ChartEmpty, ChartTip, DashCard, KpiTile, ViewLink } from "../../components/dash";
import { CustomizePanel, EditFrame, SaveBar } from "../../components/overview/Customize";
import {
  AttentionWidget,
  CloudSevWidget,
  ComplianceWidget,
  ExtSevWidget,
  SummaryWidget,
  TrendWidget,
  VulnSevWidget,
  type OverviewData,
} from "../../components/overview/sections";
import { WIDGETS, WIDGET_MAP, moveTo, resolve, sameLayout, shift, toPayload, type Resolved } from "../../components/overview/widgets";
import SortHeader from "../../components/SortHeader";
import { ErrorNote } from "../../components/ui";
import { externalApi } from "../../externalApi";
import { AXIS, cap, catSegments, fmtNum, GRID, href, sevSegments } from "../../lib/dash";
import { SEV_COLOR, SEVERITIES } from "../../lib/format";
import { useModules } from "../../lib/modules";
import { useApi } from "../../lib/useApi";
import { useSort } from "../../lib/useSort";
import { overviewApi } from "../../overviewApi";
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


const SPAN: Record<number, string> = { 6: "lg:col-span-6", 12: "lg:col-span-12" };

function KpisWidget({ d, sub, has }: { d: DashOverview; sub?: string; has: OverviewData["has"] }) {
  const k = d.kpis;
  const days = d.days;
  const findings = (p: Record<string, string | undefined> = {}) => href("/findings", { ...p, subscription: sub });
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
      {has.cloud && (
        <>
          <KpiTile label="Open issues" value={k.open_issues.value} to={findings()} hint="Show open posture findings" delta={k.open_issues.delta} days={days} segments={sevSegments(k.open_issues.parts, (s) => findings({ severity: s }))} />
          <KpiTile label="Critical & high" value={k.critical_high.value} to={findings({ severity: "critical" })} hint="Show open critical findings" delta={k.critical_high.delta} days={days} segments={sevSegments(k.critical_high.parts, (s) => findings({ severity: s }), ["critical", "high"])} />
        </>
      )}
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
      {has.cloud && (
        <>
          <KpiTile label="Internet-exposed assets" value={k.exposed_assets.value} to={href("/exposure", { subscription: sub })} hint="Show internet-exposed assets" delta={k.exposed_assets.delta} days={days}
            segments={catSegments(k.exposed_assets.parts, (p) => href("/exposure", { type: p.types?.length === 1 ? p.types[0] : undefined, subscription: sub }))} />
          <KpiTile label="Attack paths" value={k.attack_paths.value} to={href("/attack-paths", { view: "confirmed" })} hint="Show confirmed attack paths" delta={k.attack_paths.delta} days={days} segments={sevSegments(k.attack_paths.parts, () => href("/attack-paths", { view: "confirmed" }))} />
        </>
      )}
      {has.endpoints && (
        <KpiTile label="Active runtime threats" value={k.runtime_threats.value} to="/threats" hint="Show active runtime threats" delta={k.runtime_threats.delta} days={days} segments={sevSegments(k.runtime_threats.parts, (s) => href("/threats", { severity: s }))} />
      )}
    </div>
  );
}

function AgeWidget({ d, sub }: { d: DashOverview; sub?: string }) {
  const navigate = useNavigate();
  const empty = d.age.every((a) => a.critical + a.high + a.medium + a.low === 0);
  return (
    <DashCard title="Open issues by age" sub="Stacked by severity" right={<ViewLink to={href("/findings", { subscription: sub })} />}>
      {empty ? (
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
                <Bar key={s} dataKey={s} name={cap(s)} stackId="age" fill={SEV_COLOR[s]} stroke="var(--color-surface-1)" strokeWidth={1} radius={i === SEVERITIES.length - 1 ? [3, 3, 0, 0] : 0} isAnimationActive={false} cursor="pointer"
                  onClick={() => navigate(href("/findings", { severity: s, subscription: sub }))} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </DashCard>
  );
}

function CategoryWidget({ d, sub }: { d: DashOverview; sub?: string }) {
  const catMax = Math.max(1, ...d.categories.map((c) => c.total));
  return (
    <DashCard title="Cloud issues by type" right={<ViewLink to={href("/findings", { subscription: sub })} />}>
      {d.categories.length === 0 ? (
        <ChartEmpty height="h-52">No open findings.</ChartEmpty>
      ) : (
        <BarRows max={catMax} labelWidth="6.5rem" rows={d.categories.map((c) => ({ key: c.category, label: c.category, total: c.total, segments: sevSegments(c), to: href("/findings", { category: c.category, subscription: sub }), hint: `Show ${c.total} open ${c.category.toLowerCase()} findings` }))} />
      )}
    </DashCard>
  );
}

function TopWidget({ d, sub }: { d: DashOverview; sub?: string }) {
  // "default" keeps the server's order (highest risk first)
  const sortedAssets = useSort(d.top_assets, { default: (a) => d.top_assets.indexOf(a), asset: (a) => a.name, type: (a) => a.type_label, risk: (a) => a.risk }, { key: "default", dir: "asc" }, { risk: "desc" });
  return (
    <DashCard title="Riskiest assets" right={<ViewLink to={href("/inventory", { subscription: sub })} />}>
      {d.top_assets.length === 0 ? (
        <ChartEmpty height="h-52">No assets with open findings or vulnerabilities.</ChartEmpty>
      ) : (
          <table className="w-full table-fixed text-[13px]">
            <thead>
              <tr className="border-b border-line text-left text-[11px] uppercase tracking-[0.06em] text-ink-3">
                <SortHeader sortKey="asset" label="Asset" sort={sortedAssets.sort} onSort={sortedAssets.onSort} className="py-1.5 pr-2 font-semibold" />
                <SortHeader sortKey="type" label="Type" sort={sortedAssets.sort} onSort={sortedAssets.onSort} className="w-[28%] py-1.5 pr-2 font-semibold" />
                <SortHeader sortKey="risk" label="Risk" sort={sortedAssets.sort} onSort={sortedAssets.onSort} className="w-12 py-1.5 text-right font-semibold" />
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {sortedAssets.rows.map((a) => (
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
  );
}

/** Ask before leaving the page (reload, close, or any in-app link) while there are unsaved layout changes. */
function useUnsavedGuard(dirty: boolean) {
  useEffect(() => {
    if (!dirty) return;
    const before = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = "";
    };
    const click = (e: MouseEvent) => {
      const a = (e.target as Element | null)?.closest?.("a[href]") as HTMLAnchorElement | null;
      if (!a || a.target === "_blank" || e.defaultPrevented || e.metaKey || e.ctrlKey) return;
      if (!window.confirm("You have unsaved changes to the Overview. Leave without saving?")) {
        e.preventDefault();
        e.stopPropagation();
      }
    };
    window.addEventListener("beforeunload", before);
    document.addEventListener("click", click, true);
    return () => {
      window.removeEventListener("beforeunload", before);
      document.removeEventListener("click", click, true);
    };
  }, [dirty]);
}

export interface OverviewProps extends TabProps {
  /** Customize mode (admins). Owned by the page so its header can show the button and guard tab changes. */
  editing: boolean;
  onEditingChange: (v: boolean) => void;
  onDirtyChange: (v: boolean) => void;
}

export default function OverviewTab({ range, account, editing, onEditingChange, onDirtyChange }: OverviewProps) {
  const { organization } = useAuth();
  const { has: hasModule } = useModules();
  const has = { cloud: hasModule("cloud"), endpoints: hasModule("endpoints"), vulns: hasModule("vulnerabilities"), external: hasModule("external") };
  const sub = account || undefined;
  const { data: d, error } = useApi(() => api.dashOverview({ range, account: account || undefined }), [range, account], 60000);
  // Optional data of other modules: a failure only leaves that widget without numbers.
  const { data: vulns } = useApi(() => (has.vulns ? api.dashVulns({ range, account: account || undefined }) : Promise.resolve(null)), [range, account, has.vulns], 60000);
  const { data: ext } = useApi(() => (has.external ? externalApi.overview() : Promise.resolve(null)), [has.external], 60000);
  const { data: extTop } = useApi(() => (has.external ? externalApi.findingsGrouped({ status: "open" }) : Promise.resolve(null)), [has.external], 60000);
  const { data: extHosts } = useApi(() => (has.external && !has.endpoints ? externalApi.hosts() : Promise.resolve(null)), [has.external, has.endpoints], 60000);
  const layoutRes = useApi(() => overviewApi.layout());

  const [savedNow, setSavedNow] = useState<Resolved | null>(null); // the layout just saved (until the next fetch)
  const saved = savedNow ?? resolve(layoutRes.data?.layout);
  const [draft, setDraft] = useState<Resolved | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const [dragId, setDragId] = useState<string | null>(null);
  const [live, setLive] = useState("");
  const shown = editing ? (draft ?? saved) : saved;
  const dirty = editing && draft !== null && !sameLayout(draft, saved);
  useUnsavedGuard(dirty);
  const lastDirty = useRef(false);
  useEffect(() => {
    if (lastDirty.current !== dirty) {
      lastDirty.current = dirty;
      onDirtyChange(dirty);
    }
  }, [dirty, onDirtyChange]);
  useEffect(() => () => onDirtyChange(false), [onDirtyChange]);

  const available = (id: string) => {
    const m = WIDGET_MAP[id].module;
    return !m || hasModule(m);
  };
  const widgets = WIDGETS.filter((w) => available(w.id));
  const visible = shown.order.filter((id) => available(id) && shown.on[id]);

  if (!d || (layoutRes.loading && !layoutRes.data && !layoutRes.error)) return error ? <ErrorNote error={error} /> : <TabSkeleton />;

  const data: OverviewData = { d, vulns: vulns ?? null, ext: ext ?? null, extTop: extTop ?? null, extHosts: extHosts ?? null, has, sub };
  const render = (id: string) => {
    switch (id) {
      case "summary": return <SummaryWidget {...data} />;
      case "cloudSev": return <CloudSevWidget {...data} />;
      case "vulnSev": return <VulnSevWidget {...data} />;
      case "extSev": return <ExtSevWidget {...data} />;
      case "attention": return <AttentionWidget {...data} />;
      case "trend": return <TrendWidget {...data} />;
      case "compliance": return <ComplianceWidget {...data} />;
      case "kpis": return <KpisWidget d={d} sub={sub} has={has} />;
      case "risk": return <RiskCard d={d} days={d.days} />;
      case "top": return <TopWidget d={d} sub={sub} />;
      case "age": return <AgeWidget d={d} sub={sub} />;
      case "category": return <CategoryWidget d={d} sub={sub} />;
      default: return null;
    }
  };

  const edit = (f: (r: Resolved) => Resolved) => setDraft(f(draft ?? saved));
  const close = () => {
    setDraft(null);
    setSaveError(null);
    onEditingChange(false);
  };
  const save = async () => {
    if (!draft) return;
    setSaving(true);
    setSaveError(null);
    try {
      const r = await overviewApi.saveLayout(toPayload(draft));
      setSavedNow(resolve(r.layout));
      setDraft(null);
      setNotice(`Overview saved for everyone at ${organization?.name ?? "your organisation"}.`);
      onEditingChange(false);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };
  const move = (id: string, dir: -1 | 1) => {
    edit((r) => shift(r, id, dir, visible));
    const i = visible.indexOf(id) + dir;
    setLive(`${WIDGET_MAP[id].title} moved to position ${Math.min(Math.max(i, 0), visible.length - 1) + 1} of ${visible.length}`);
  };

  return (
    <div>
      {notice && !editing && (
        <p role="status" className="mb-3 rounded-lg border border-line bg-good-bg px-3 py-2 text-[13px] text-ink" data-print="hide">
          {notice}
        </p>
      )}
      {editing && (
        <div data-print="hide">
          <CustomizePanel
            widgets={widgets}
            draft={shown}
            onToggle={(id) => edit((r) => ({ ...r, on: { ...r.on, [id]: !r.on[id] } }))}
            onReset={() => setDraft(resolve(null))}
            onClose={close}
          />
          <p className="sr-only" role="status" aria-live="polite">
            {live}
          </p>
        </div>
      )}
      {visible.length === 0 ? (
        <ChartEmpty height="h-48">Nothing is shown on the Overview. {editing ? "Turn a widget on above." : "An admin can choose widgets with Customize."}</ChartEmpty>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
          {visible.map((id, i) =>
            editing ? (
              <div key={id} className={SPAN[shown.width[id]]}>
                <EditFrame
                  id={id}
                  index={i}
                  count={visible.length}
                  width={shown.width[id]}
                  dragging={dragId === id}
                  onDragStart={() => setDragId(id)}
                  onDragEnd={() => setDragId(null)}
                  onDropOn={() => {
                    if (dragId && dragId !== id) edit((r) => moveTo(r, dragId, id));
                    setDragId(null);
                  }}
                  onMove={(dir) => move(id, dir)}
                  onWidth={() => edit((r) => ({ ...r, width: { ...r.width, [id]: r.width[id] === 12 ? 6 : 12 } }))}
                  onHide={() => edit((r) => ({ ...r, on: { ...r.on, [id]: false } }))}
                >
                  {render(id)}
                </EditFrame>
              </div>
            ) : (
              <div key={id} className={`min-w-0 ${SPAN[shown.width[id]]}`}>
                {render(id)}
              </div>
            ),
          )}
        </div>
      )}
      {dirty && <SaveBar saving={saving} error={saveError} onDiscard={close} onSave={save} />}
    </div>
  );
}
