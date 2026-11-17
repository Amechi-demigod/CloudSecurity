import { SearchX } from "lucide-react";
import { useState } from "react";
import { api } from "../api";
import AssetDrawer from "../components/AssetDrawer";
import { Card, Empty, ErrorNote, PageHeader, RiskBar, Select, Table, Tag } from "../components/ui";
import { PROVIDER_LABEL, SCOPE_LABEL, TYPE_LABEL, fmtAgo, fmtTime } from "../lib/format";
import { useApi } from "../lib/useApi";
import { useSort } from "../lib/useSort";
import { useUrlState } from "../lib/useUrlState";

export default function Inventory() {
  // Filters live in the URL (?type=, ?provider=, ?exposed=yes ...) so the dashboard can link to them.
  const [type, setType] = useUrlState("type");
  const [provider, setProvider] = useUrlState("provider");
  const [sub, setSub] = useUrlState("subscription");
  const [exposed, setExposed] = useUrlState("exposed");
  const [source, setSource] = useUrlState("source");
  // Active (default) or Removed: cloud resources that no longer exist, kept for a while as history.
  const [tab, setTab] = useUrlState("tab");
  const removed = tab === "removed";
  const [q, setQ] = useState("");
  // ?asset=<id> opens the drawer (links from device pages: "Cloud VM -> resource").
  const [selectedId, setSelectedId] = useUrlState("asset");
  const selected = selectedId || null;
  const setSelected = (id: string | null) => setSelectedId(id ?? "");

  const { data: facets } = useApi(api.facets, []);
  const { data, error, loading } = useApi(
    () =>
      api.assets({
        type: type || undefined,
        provider: provider || undefined,
        subscription_id: sub || undefined,
        source: source || undefined,
        internet_exposed: exposed === "" ? undefined : exposed === "yes",
        q: q || undefined,
        removed: removed || undefined,
      }),
    [type, provider, sub, exposed, source, q, removed],
  );
  const sorted = useSort(
    data,
    {
      name: (a) => a.name,
      type: (a) => TYPE_LABEL[a.type] ?? a.type,
      subscription: (a) => a.subscription_name,
      region: (a) => a.region,
      last_seen: (a) => Date.parse(a.last_seen),
      removed_at: (a) => (a.removed_at ? Date.parse(a.removed_at) : null),
      findings: (a) => a.open_findings,
      vulns: (a) => a.vulnerabilities,
      risk: (a) => (a.vulnerabilities ? a.max_risk : null),
      alerts: (a) => a.open_alerts,
    },
    removed ? { key: "removed_at", dir: "desc" } : { key: "name", dir: "asc" },
    { findings: "desc", vulns: "desc", risk: "desc", alerts: "desc", last_seen: "desc", removed_at: "desc" },
  );
  const retentionDays = facets?.counts.retention_days ?? 60;
  const deletedOn = (iso: string) => new Date(Date.parse(iso) + retentionDays * 86400000).toLocaleDateString();
  const tabCls = (on: boolean) =>
    `-mb-px border-b-2 px-3 py-2 text-sm font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
      on ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink"
    }`;

  return (
    <div>
      <PageHeader title="Asset inventory" subtitle="Every discovered cloud resource with exposure, data sensitivity and risk context." />
      <ErrorNote error={error} />
      <div role="tablist" aria-label="Inventory" className="mb-3 flex gap-1 border-b border-line">
        <button role="tab" aria-selected={!removed} className={tabCls(!removed)} onClick={() => setTab("")}>
          Active{facets && <span className="ml-1.5 text-xs text-ink-3">{facets.counts.active.toLocaleString()}</span>}
        </button>
        <button role="tab" aria-selected={removed} className={tabCls(removed)} onClick={() => setTab("removed")}>
          Removed{facets && <span className="ml-1.5 text-xs text-ink-3">{facets.counts.removed.toLocaleString()}</span>}
        </button>
      </div>
      {removed && (
        <p className="mb-3 rounded border border-line bg-surface-2 px-3 py-2 text-sm text-ink-2">
          Resources that no longer exist in your cloud. Kept for {retentionDays} days as history, then deleted permanently. They don&apos;t count towards risk, findings or compliance.
        </p>
      )}
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <input
          className="w-56 rounded border border-line bg-surface-2 px-2 py-1 text-sm"
          placeholder="Search name or ID…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <Select
          label="Type"
          value={type}
          onChange={setType}
          options={[{ value: "", label: "All" }, ...(facets?.types ?? []).map((t) => ({ value: t, label: TYPE_LABEL[t] ?? t }))]}
        />
        <Select
          label="Cloud"
          value={provider}
          onChange={(v) => {
            setProvider(v);
            setSub("");
          }}
          options={[{ value: "", label: "All" }, ...(facets?.providers ?? []).map((p) => ({ value: p, label: PROVIDER_LABEL[p] ?? p }))]}
        />
        <Select
          label={provider ? (SCOPE_LABEL[provider] ?? "Scope") : "Subscription / account / project"}
          value={sub}
          onChange={setSub}
          options={[
            { value: "", label: "All" },
            ...(facets?.subscriptions ?? [])
              .filter((s) => !provider || s.provider === provider)
              .map((s) => ({ value: s.id, label: provider ? s.name : `${PROVIDER_LABEL[s.provider] ?? s.provider}: ${s.name}` })),
          ]}
        />
        <Select
          label="Exposure"
          value={exposed}
          onChange={setExposed}
          options={[
            { value: "", label: "All" },
            { value: "yes", label: "Internet-exposed" },
            { value: "no", label: "Internal" },
          ]}
        />
        <Select label="Source" value={source} onChange={setSource} options={["", ...(facets?.sources ?? [])]} />
        <span className="text-xs text-ink-3">{data ? `${data.length} ${removed ? "removed" : "assets"}` : ""}</span>
      </div>
      <Card>
          <Table
            head={removed ? [
              { label: "Resource", sort: "name" },
              { label: "Type", sort: "type" },
              { label: "Subscription / account / project", sort: "subscription" },
              { label: "Last seen", sort: "last_seen" },
              { label: "Removed", sort: "removed_at" },
              "Deleted permanently",
            ] : [
              { label: "Name", sort: "name" },
              { label: "Type", sort: "type" },
              { label: "Subscription / account / project", sort: "subscription" },
              { label: "Region", sort: "region" },
              "Context",
              { label: "Findings", sort: "findings" },
              { label: "Vulns", sort: "vulns" },
              { label: "Max vuln risk", sort: "risk" },
              { label: "Alerts", sort: "alerts" },
            ]}
            sort={sorted.sort}
            onSort={sorted.onSort}
            loading={loading}
            rowCount={data?.length ?? 0}
            empty={
              removed ? (
                <Empty icon={SearchX} title="No removed resources">
                  Resources that disappear from your cloud show up here after two successful scans without them.
                </Empty>
              ) : (
                <Empty icon={SearchX} title="No assets match these filters">
                  Clear a filter, or connect a cloud account under Connectors & scans.
                </Empty>
              )
            }
          >
            {removed && sorted.rows.map((a) => (
              <tr key={a.id} className="cursor-pointer hover:bg-surface-2" onClick={() => setSelected(a.id)}>
                <td className="px-3 py-2 font-medium">{a.name}</td>
                <td className="px-3 py-2 text-ink-2">{TYPE_LABEL[a.type] ?? a.type}</td>
                <td className="px-3 py-2 text-xs text-ink-2">
                  {a.provider !== "azure" && <span className="mr-1 font-medium text-ink-3">{PROVIDER_LABEL[a.provider] ?? a.provider}</span>}
                  {a.subscription_name}
                </td>
                <td className="px-3 py-2 text-xs text-ink-2" title={fmtTime(a.last_seen)}>{fmtAgo(a.last_seen)}</td>
                <td className="px-3 py-2 text-xs text-ink-2" title={a.removed_at ? fmtTime(a.removed_at) : undefined}>{a.removed_at ? fmtAgo(a.removed_at) : "—"}</td>
                <td className="px-3 py-2 text-xs text-ink-2">{a.removed_at ? deletedOn(a.removed_at) : "—"}</td>
              </tr>
            ))}
            {!removed && sorted.rows.map((a) => (
              <tr key={a.id} className="cursor-pointer hover:bg-surface-2" onClick={() => setSelected(a.id)}>
                <td className="px-3 py-2 font-medium">{a.name}</td>
                <td className="px-3 py-2 text-ink-2">{TYPE_LABEL[a.type] ?? a.type}</td>
                <td className="px-3 py-2 text-xs text-ink-2">
                  {a.provider !== "azure" && <span className="mr-1 font-medium text-ink-3">{PROVIDER_LABEL[a.provider] ?? a.provider}</span>}
                  {a.subscription_name}
                  {a.resource_group && <div className="text-ink-3">{a.resource_group}</div>}
                </td>
                <td className="px-3 py-2 text-ink-2">{a.region}</td>
                <td className="space-x-1 px-3 py-2">
                  {a.internet_exposed && <Tag tone="warn">Exposed</Tag>}
                  {a.sensitive_data && <Tag tone="warn">Sensitive</Tag>}
                  {a.source !== "simulated" && <Tag tone="accent">{a.source}</Tag>}
                </td>
                <td className="px-3 py-2">{a.open_findings || <span className="text-ink-3">0</span>}</td>
                <td className="px-3 py-2">{a.vulnerabilities || <span className="text-ink-3">0</span>}</td>
                <td className="px-3 py-2">{a.vulnerabilities ? <RiskBar value={a.max_risk} /> : <span className="text-ink-3">—</span>}</td>
                <td className="px-3 py-2">{a.open_alerts || <span className="text-ink-3">0</span>}</td>
              </tr>
            ))}
          </Table>
      </Card>
      <AssetDrawer assetId={selected} onClose={() => setSelected(null)} onNavigate={setSelected} />
    </div>
  );
}
