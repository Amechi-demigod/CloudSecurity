import { Link } from "react-router-dom";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../../api";
import { BarRows, ChartEmpty, ChartTip, DashCard, KpiTile, LegendKeys, ViewLink } from "../../components/dash";
import { ErrorNote, SeverityBadge } from "../../components/ui";
import { AXIS, bucketLabel, catSegments, dayLabel, GRID, href, sevSegments } from "../../lib/dash";
import { useApi } from "../../lib/useApi";
import type { TabProps } from "../Dashboard";
import { TabSkeleton } from "./Skeleton";

const EXPOSED_COLOR = "var(--color-sev-critical)";
const JEWEL_COLOR = "var(--color-cat-3)";

export default function ExposureTab({ range, account }: TabProps) {
  const { data: d, error } = useApi(() => api.dashExposure({ range, account: account || undefined }), [range, account], 60000);
  if (!d) return error ? <ErrorNote error={error} /> : <TabSkeleton />;
  const k = d.kpis;
  const days = d.days;
  const sub = account || undefined;
  const exposure = (p: Record<string, string | undefined> = {}) => href("/exposure", { ...p, subscription: sub });
  const points = d.trend.points.map((p) => ({ ...p, label: bucketLabel(p, d.trend.bucket) }));
  const known = points.filter((p) => p.exposed_assets !== null).length;
  const typeMax = Math.max(1, ...d.by_type.map((t) => t.count));

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:col-span-12 xl:grid-cols-4">
        <KpiTile
          label="Internet-exposed assets"
          value={k.exposed_assets.value}
          to={exposure()}
          hint="Show internet-exposed assets"
          delta={k.exposed_assets.delta}
          days={days}
          segments={catSegments(k.exposed_assets.parts, (p) => exposure({ type: p.types?.length === 1 ? p.types[0] : undefined }))}
        />
        <KpiTile
          label="Open management ports"
          value={k.mgmt_ports.value}
          to={exposure({ port: "22" })}
          hint="Exposed assets with SSH, RDP or WinRM open to the internet"
          delta={k.mgmt_ports.delta}
          days={days}
          segments={catSegments(k.mgmt_ports.parts, (p) => exposure({ port: String(p.port) }))}
        />
        <KpiTile
          label="Exposed data stores"
          value={k.data_stores.value}
          to={exposure()}
          hint="Storage, databases and key vaults reachable from the internet"
          delta={k.data_stores.delta}
          days={days}
          segments={catSegments(k.data_stores.parts, (p) => exposure({ type: p.types?.length === 1 ? p.types[0] : undefined }))}
        />
        <KpiTile
          label="Paths to crown jewels"
          value={k.crown_jewels.value}
          to={href("/attack-paths", { view: "confirmed" })}
          hint="Confirmed attack paths ending at sensitive data"
          delta={k.crown_jewels.delta}
          days={days}
          segments={sevSegments(k.crown_jewels.parts, () => href("/attack-paths", { view: "confirmed" }))}
        />
      </div>

      <DashCard title="Exposed assets by type" right={<ViewLink to={exposure()} />} className="lg:col-span-6">
        {d.by_type.length === 0 ? (
          <ChartEmpty height="h-48">Nothing is reachable from the internet.</ChartEmpty>
        ) : (
          <BarRows
            max={typeMax}
            labelWidth="9rem"
            rows={d.by_type.map((t) => ({
              key: t.type,
              label: t.label,
              total: t.count,
              segments: [{ key: t.type, label: t.label, count: t.count, color: "var(--color-accent)" }],
              to: exposure({ type: t.type }),
              hint: `Show exposed ${t.label.toLowerCase()}`,
            }))}
          />
        )}
      </DashCard>

      <DashCard
        title="Exposure trend"
        sub="From the daily snapshots"
        right={<LegendKeys items={[{ label: "Exposed assets", color: EXPOSED_COLOR }, { label: "Paths to crown jewels", color: JEWEL_COLOR }]} />}
        className="lg:col-span-6"
      >
        {known < 2 ? (
          <ChartEmpty height="h-48">
            The trend fills in from {d.history_since ? dayLabel(d.history_since) : "today"}: one snapshot a day.
            {known === 1 ? ` Today: ${k.exposed_assets.value} exposed assets.` : ""}
          </ChartEmpty>
        ) : (
          <div className="h-48">
            <ResponsiveContainer>
              <LineChart data={points} margin={{ top: 4, right: 8, bottom: 0, left: -4 }}>
                <CartesianGrid {...GRID} />
                <XAxis dataKey="label" {...AXIS} minTickGap={24} />
                <YAxis {...AXIS} allowDecimals={false} width={40} />
                <Tooltip cursor={{ stroke: "var(--color-ink-3)", strokeDasharray: "3 3" }} content={<ChartTip />} />
                <Line type="monotone" dataKey="exposed_assets" name="Exposed assets" stroke={EXPOSED_COLOR} strokeWidth={2} dot={{ r: 3, strokeWidth: 0, fill: EXPOSED_COLOR }} isAnimationActive={false} />
                <Line type="monotone" dataKey="crown_jewel_paths" name="Paths to crown jewels" stroke={JEWEL_COLOR} strokeWidth={2} strokeDasharray="5 4" dot={{ r: 3, strokeWidth: 0, fill: JEWEL_COLOR }} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </DashCard>

      <DashCard
        title="Internet-exposed attack paths, highest risk first"
        sub={d.paths_total > d.paths.length ? `Top ${d.paths.length} of ${d.paths_total}` : undefined}
        right={<ViewLink to="/attack-paths" label="Open Attack paths" />}
        className="lg:col-span-12"
      >
        {d.paths.length === 0 ? (
          <ChartEmpty height="h-32">No attack paths start from the internet.</ChartEmpty>
        ) : (
          <div className="-mx-1 overflow-x-auto">
            <table className="w-full min-w-[640px] text-[13px]">
              <thead>
                <tr className="border-b border-line text-left text-[11px] uppercase tracking-[0.06em] text-ink-3">
                  <th className="px-1 py-1.5 font-semibold">Entry point</th>
                  <th className="px-1 py-1.5 font-semibold">Path</th>
                  <th className="px-1 py-1.5 font-semibold">Target</th>
                  <th className="px-1 py-1.5 font-semibold">Severity</th>
                  <th className="px-1 py-1.5 text-right font-semibold">Steps</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {d.paths.map((p) => (
                  <tr key={p.id}>
                    <td className="max-w-[16rem] px-1 py-2">
                      <Link to={href("/attack-paths", { path: p.id })} className="block truncate font-semibold text-ink hover:text-accent hover:underline" title={p.entry.detail ?? p.entry.name}>
                        {p.entry.name}
                      </Link>
                      {p.entry.detail && <span className="block truncate text-xs text-ink-3">{p.entry.detail.replace(/^Internet-exposed \((.*)\)$/, "$1")}</span>}
                    </td>
                    <td className="max-w-[24rem] truncate px-1 py-2 text-ink-3" title={p.weaknesses.join("\n")}>
                      Internet → {p.steps.map((s) => s.name).join(" → ")}
                    </td>
                    <td className="max-w-[12rem] truncate px-1 py-2 text-ink">{p.target.name}</td>
                    <td className="px-1 py-2">
                      <SeverityBadge severity={p.severity} />
                    </td>
                    <td className="px-1 py-2 text-right text-ink">{p.steps.length}</td>
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
