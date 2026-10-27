import { useState } from "react";
import { api } from "../api";
import AssetDrawer from "../components/AssetDrawer";
import { Card, Empty, ErrorNote, PageHeader, RiskBar, Select, Table, Tag } from "../components/ui";
import { PROVIDER_LABEL, SCOPE_LABEL, TYPE_LABEL } from "../lib/format";
import { useApi } from "../lib/useApi";
import { useUrlState } from "../lib/useUrlState";

export default function Inventory() {
  // Filters live in the URL (?type=, ?provider=, ?exposed=yes ...) so the dashboard can link to them.
  const [type, setType] = useUrlState("type");
  const [provider, setProvider] = useUrlState("provider");
  const [sub, setSub] = useUrlState("subscription");
  const [exposed, setExposed] = useUrlState("exposed");
  const [source, setSource] = useUrlState("source");
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

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
      }),
    [type, provider, sub, exposed, source, q],
  );

  return (
    <div>
      <PageHeader title="Asset inventory" subtitle="Every discovered cloud resource with exposure, data sensitivity and risk context." />
      <ErrorNote error={error} />
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
        <span className="text-xs text-ink-3">{data ? `${data.length} assets` : ""}</span>
      </div>
      <Card>
        {loading && !data ? (
          <Empty>Loading…</Empty>
        ) : data && data.length === 0 ? (
          <Empty>No assets match these filters.</Empty>
        ) : (
          <Table head={["Name", "Type", "Subscription / account / project", "Region", "Context", "Findings", "Vulns", "Max vuln risk", "Alerts"]}>
            {data?.map((a) => (
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
        )}
      </Card>
      <AssetDrawer assetId={selected} onClose={() => setSelected(null)} onNavigate={setSelected} />
    </div>
  );
}
