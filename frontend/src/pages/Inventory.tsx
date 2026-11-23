import { SearchX } from "lucide-react";
import { useAuth } from "../auth/context";
import { Link } from "react-router-dom";
import { api, qs } from "../api";
import AssetDrawer from "../components/AssetDrawer";
import { ExportMenu } from "../components/ExportMenu";
import { Card, Empty, FilterBar, FilterChips, FilterSearch, FilterSelect, NameCell, NumCell, None, PageHeader, Pill, PillRow, RiskBar, Segments, Table, TextCell, type FilterChip } from "../components/ui";
import { PROVIDER_LABEL, TYPE_LABEL, fmtAgo, fmtTime } from "../lib/format";
import { useApi } from "../lib/useApi";
import { useSort } from "../lib/useSort";
import { useUrlState } from "../lib/useUrlState";
import { PAGE_INFO } from "../lib/pageInfo";

export default function Inventory() {
  const { platformAdmin } = useAuth();
  // Filters live in the URL (?type=, ?provider=, ?exposed=yes ...) so the dashboard can link to them.
  const [type, setType] = useUrlState("type");
  const [provider, setProvider] = useUrlState("provider");
  const [sub, setSub] = useUrlState("subscription");
  const [exposed, setExposed] = useUrlState("exposed");
  const [source, setSource] = useUrlState("source");
  // Active (default) or Removed: cloud resources that no longer exist, kept for a while as history.
  const [tab, setTab] = useUrlState("tab");
  const removed = tab === "removed";
  const [q, setQ] = useUrlState("q");
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
  const clearAll = () => {
    setQ("");
    setType("");
    setProvider("");
    setSub("");
    setExposed("");
    setSource("");
  };
  const subName = (id: string) => facets?.subscriptions.find((x) => x.id === id)?.name ?? id;
  const chips: FilterChip[] = [
    q && { label: "Search", value: q, onRemove: () => setQ("") },
    type && { label: "Type", value: TYPE_LABEL[type] ?? type, onRemove: () => setType("") },
    provider && { label: "Cloud", value: PROVIDER_LABEL[provider] ?? provider, onRemove: () => { setProvider(""); setSub(""); } },
    sub && { label: "Account", value: subName(sub), onRemove: () => setSub("") },
    exposed && { label: "Exposure", value: exposed === "yes" ? "On the internet" : "Internal", onRemove: () => setExposed("") },
    source && { label: "Source", value: source, onRemove: () => setSource("") },
  ].filter((c): c is FilterChip => !!c);
  const filtered = chips.length > 0;
  const retentionDays = facets?.counts.retention_days ?? 60;
  const deletedOn = (iso: string) => new Date(Date.parse(iso) + retentionDays * 86400000).toLocaleDateString();
  const tabCls = (on: boolean) =>
    `-mb-px border-b-2 px-3 py-2 text-sm font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
      on ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink"
    }`;

  return (
    <div>
      <PageHeader title="Cloud resources" info={PAGE_INFO.cloudResources} actions={
          <>
            <ExportMenu
              noun="cloud resources"
              count={data?.length}
              buildUrl={(format) => `/api/assets/export${qs({ type, provider, subscription_id: sub, source, internet_exposed: exposed === "" ? undefined : exposed === "yes", q, removed: removed || undefined, format })}`}
            />
            <Link to="/exposure" className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">On the internet</Link>
          </>
        } subtitle="Everything found in your connected cloud accounts." />
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
      <Card>
        <FilterBar
          count={data ? `${data.length.toLocaleString()} ${removed ? "removed" : "resources"}` : undefined}
          moreActive={[source, exposed === "no" ? exposed : ""].filter(Boolean).length}
          more={
            <>
              <FilterSelect label="Source" value={source} onChange={setSource} options={["", ...(facets?.sources ?? [])]} />
              <FilterSelect label="Cloud" value={provider} onChange={(v) => { setProvider(v); setSub(""); }} options={[{ value: "", label: "All" }, ...(facets?.providers ?? []).map((p) => ({ value: p, label: PROVIDER_LABEL[p] ?? p }))]} />
            </>
          }
        >
          <FilterSearch value={q} onChange={setQ} placeholder="Name or ID" label="Search resources" />
          <FilterSelect label="Type" value={type} onChange={setType} options={[{ value: "", label: "All" }, ...(facets?.types ?? []).map((t) => ({ value: t, label: TYPE_LABEL[t] ?? t }))]} />
          <FilterSelect
            label="Account"
            value={sub}
            onChange={setSub}
            options={[
              { value: "", label: "All" },
              ...(facets?.subscriptions ?? [])
                .filter((x) => !provider || x.provider === provider)
                .map((x) => ({ value: x.id, label: provider ? x.name : `${PROVIDER_LABEL[x.provider] ?? x.provider}: ${x.name}` })),
            ]}
          />
          <Segments
            label="Exposure"
            value={exposed}
            onChange={setExposed}
            options={[
              { value: "", label: "All" },
              { value: "yes", label: "On the internet" },
              { value: "no", label: "Internal" },
            ]}
          />
        </FilterBar>
        <FilterChips chips={chips} onClearAll={clearAll} />
          <Table
            tableId="inventory"
            head={removed ? [
              { label: "Resource", sort: "name", w: 280 },
              { label: "Account", sort: "subscription", w: 260 },
              { label: "Last seen", sort: "last_seen", w: 120 },
              { label: "Removed", sort: "removed_at", w: 120 },
              { label: "Deleted on", w: 130 },
            ] : [
              { label: "Resource", sort: "name", w: 280 },
              { label: "Account", sort: "subscription", w: 280 },
              { label: "Region", sort: "region", w: 120 },
              { label: "Flags", w: 150 },
              { label: "Issues", sort: "findings", w: 80, align: "right" },
              { label: "Vulns", sort: "vulns", w: 80, align: "right" },
              { label: "Worst vuln", sort: "risk", w: 120 },
              { label: "Alerts", sort: "alerts", w: 80, align: "right" },
            ]}
            sort={sorted.sort}
            onSort={sorted.onSort}
            loading={loading}
            rowCount={data?.length ?? 0}
            noun="resources"
            pageSize={50}
            filtered={filtered}
            onClearFilters={clearAll}
            error={data ? null : error}
            empty={
              removed ? (
                <Empty icon={SearchX} title="No removed resources">
                  Resources that disappear from your cloud show up here after two successful scans without them.
                </Empty>
              ) : (
                <Empty icon={SearchX} title="No assets match these filters">
                  Clear a filter, or connect a cloud account under Connections.
                </Empty>
              )
            }
          >
            {sorted.rows.map((a) => {
              const account = [a.provider !== "azure" ? PROVIDER_LABEL[a.provider] ?? a.provider : "", a.subscription_name].filter(Boolean).join(" · ");
              return (
                <tr key={a.id} className="cursor-pointer hover:bg-surface-2" onClick={() => setSelected(a.id)}>
                  <td className="px-3 py-2">
                    <NameCell name={a.name} sub={TYPE_LABEL[a.type] ?? a.type} onOpen={() => setSelected(a.id)} />
                  </td>
                  <td className="px-3 py-2">
                    <NameCell name={account || "Unknown"} sub={removed ? undefined : a.resource_group} />
                  </td>
                  {removed ? (
                    <>
                      <td className="px-3 py-2"><TextCell muted title={fmtTime(a.last_seen)}>{fmtAgo(a.last_seen)}</TextCell></td>
                      <td className="px-3 py-2">{a.removed_at ? <TextCell muted title={fmtTime(a.removed_at)}>{fmtAgo(a.removed_at)}</TextCell> : <None />}</td>
                      <td className="px-3 py-2">{a.removed_at ? <TextCell muted>{deletedOn(a.removed_at)}</TextCell> : <None />}</td>
                    </>
                  ) : (
                    <>
                      <td className="px-3 py-2">{a.region ? <TextCell>{a.region}</TextCell> : <None />}</td>
                      <td className="px-3 py-2">
                        <PillRow>
                          {a.internet_exposed && <Pill tone="critical" title="Reachable from the internet">Internet</Pill>}
                          {a.sensitive_data && <Pill tone="high" title="Holds sensitive data">Sensitive</Pill>}
                          {platformAdmin && a.source !== "simulated" && <Pill tone="info">{a.source}</Pill>}
                        </PillRow>
                      </td>
                      <td className="px-3 py-2"><NumCell value={a.open_findings} /></td>
                      <td className="px-3 py-2"><NumCell value={a.vulnerabilities} /></td>
                      <td className="px-3 py-2">{a.vulnerabilities ? <RiskBar value={a.max_risk} /> : <None />}</td>
                      <td className="px-3 py-2"><NumCell value={a.open_alerts} /></td>
                    </>
                  )}
                </tr>
              );
            })}
          </Table>
      </Card>
      <AssetDrawer assetId={selected} onClose={() => setSelected(null)} onNavigate={setSelected} />
    </div>
  );
}
