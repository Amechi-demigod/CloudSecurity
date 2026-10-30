import { Link } from "react-router-dom";
import { api } from "../../api";
import { BarRows, ChartEmpty, DashCard, KpiTile, ViewLink } from "../../components/dash";
import { ErrorNote, SeverityBadge, Tag } from "../../components/ui";
import { catSegments, href, sevSegments } from "../../lib/dash";
import { SEV_COLOR } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import type { TabProps } from "../Dashboard";
import { TabSkeleton } from "./Skeleton";

export default function IdentitiesTab({ range, account }: TabProps) {
  const { data: d, error } = useApi(() => api.dashIdentities({ range, account: account || undefined }), [range, account], 60000);
  if (!d) return error ? <ErrorNote error={error} /> : <TabSkeleton />;
  const k = d.kpis;
  const days = d.days;
  const sub = account || undefined;
  const findings = (p: Record<string, string | undefined> = {}) => href("/findings", { category: "Identity", subscription: sub, ...p });
  const inventory = (type?: string) => href("/inventory", { type, subscription: sub });
  const ruleMax = Math.max(1, ...d.rules.map((r) => r.findings));

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:col-span-12 xl:grid-cols-4">
        <KpiTile
          label="Cloud identities"
          value={k.identities.value}
          to={inventory(k.identities.parts?.length === 1 ? k.identities.parts[0].key : undefined)}
          hint="Show identities in the inventory"
          delta={k.identities.delta}
          days={days}
          segments={catSegments(k.identities.parts, (p) => inventory(p.key))}
        />
        <KpiTile
          label="Privileged identities"
          value={k.privileged.value}
          to={findings()}
          hint="Owner / Contributor / admin at subscription, account or project scope"
          delta={k.privileged.delta}
          days={days}
          segments={catSegments(k.privileged.parts, (p) => inventory(p.key))}
        />
        <KpiTile
          label="Identity findings"
          value={k.findings.value}
          to={findings()}
          hint="Show open identity findings"
          delta={k.findings.delta}
          days={days}
          segments={sevSegments(k.findings.parts, (s) => findings({ severity: s }))}
        />
        <KpiTile
          label="On attack paths"
          value={k.on_paths.value}
          to={href("/attack-paths", { view: "confirmed" })}
          hint="Identities on a confirmed attack path, by the path's severity"
          days={days}
          segments={sevSegments(k.on_paths.parts, () => href("/attack-paths", { view: "confirmed" }))}
        />
      </div>

      <DashCard title="Identity findings by rule" right={<ViewLink to={findings()} />} className="lg:col-span-12 xl:col-span-5">
        {d.rules.length === 0 ? (
          <ChartEmpty height="h-40">No open identity findings.</ChartEmpty>
        ) : (
          <BarRows
            max={ruleMax}
            labelWidth="15rem"
            rows={d.rules.map((r) => ({
              key: r.rule_id,
              label: (
                <span title={`${r.rule_id}: ${r.title}`}>
                  <span aria-hidden className="mr-1.5 inline-block h-2 w-2 rounded-full" style={{ background: SEV_COLOR[r.severity] }} />
                  {r.title}
                </span>
              ),
              total: r.findings,
              segments: [{ key: r.severity, label: `${r.severity} · ${r.identities} identities`, count: r.findings, color: SEV_COLOR[r.severity] }],
              to: findings({ severity: r.severity }),
              hint: `${r.rule_id}: ${r.title}`,
            }))}
          />
        )}
      </DashCard>

      <DashCard title="Identities to review" sub="On attack paths first, then privileged, then by open findings" right={<ViewLink to={inventory()} />} className="lg:col-span-12 xl:col-span-7">
        {d.identities.length === 0 ? (
          <ChartEmpty height="h-40">No cloud identities discovered{account ? " in this account" : ""}.</ChartEmpty>
        ) : (
          <div className="-mx-1 overflow-x-auto">
            <table className="w-full min-w-[560px] text-[13px]">
              <thead>
                <tr className="border-b border-line text-left text-[11px] uppercase tracking-[0.06em] text-ink-3">
                  <th className="px-1 py-1.5 font-semibold">Identity</th>
                  <th className="px-1 py-1.5 font-semibold">Roles</th>
                  <th className="px-1 py-1.5 font-semibold">Attack path</th>
                  <th className="px-1 py-1.5 text-right font-semibold">Findings</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {d.identities.map((i) => (
                  <tr key={i.id}>
                    <td className="max-w-[15rem] px-1 py-2">
                      <Link to={href("/vulnerabilities", { asset: i.id })} className="block truncate font-medium text-ink hover:text-accent hover:underline" title={i.name}>
                        {i.name}
                      </Link>
                      <span className="block truncate text-xs text-ink-3">
                        {i.principal_type ?? i.type_label} · {i.provider.toUpperCase()}
                      </span>
                    </td>
                    <td className="max-w-[16rem] px-1 py-2">
                      <span className="flex flex-wrap items-center gap-1">
                        {i.privileged && <Tag tone="warn">privileged</Tag>}
                        <span className="truncate text-ink-3" title={i.roles.join(", ")}>
                          {i.roles.join(", ") || "—"}
                          {i.scope ? ` (${i.scope})` : ""}
                        </span>
                      </span>
                    </td>
                    <td className="px-1 py-2">{i.attack_path ? <SeverityBadge severity={i.attack_path} /> : <span className="text-ink-3">—</span>}</td>
                    <td className="px-1 py-2 text-right text-ink">{i.findings}</td>
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
