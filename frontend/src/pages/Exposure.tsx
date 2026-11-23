import { Globe } from "lucide-react";
import { Fragment, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type ExposureItem } from "../api";
import AssetDrawer from "../components/AssetDrawer";
import { Card, Empty, FilterBar, FilterChips, FilterSearch, FilterSelect, NameCell, None, PageHeader, Pill, PillRow, SeverityBadge, Stat, Table, Tag, TextCell, type FilterChip } from "../components/ui";
import { PROVIDER_LABEL, TYPE_LABEL } from "../lib/format";
import { useApi } from "../lib/useApi";
import { useSort } from "../lib/useSort";

const PORT_NAME: Record<string, string> = {
  "22": "SSH",
  "3389": "RDP",
  "5985": "WinRM",
  "5986": "WinRM",
  "445": "SMB",
  "1433": "SQL",
  "3306": "MySQL",
  "5432": "PostgreSQL",
  "6379": "Redis",
  "6380": "Redis TLS",
  "3342": "SQL MI",
  "443": "HTTPS",
  "80": "HTTP",
};
const RISKY = new Set(["22", "3389", "5985", "5986", "445", "1433", "3306", "5432", "6379", "27017", "*"]);

function Ports({ ports }: { ports: string[] }) {
  if (!ports.length) return <None />;
  return (
    <PillRow>
      {ports.slice(0, 3).map((p) => (
        <Pill key={p} tone={RISKY.has(p) ? "critical" : "neutral"} title={ports.join(", ")}>
          {p === "*" ? "All ports" : PORT_NAME[p] ? `${p} ${PORT_NAME[p]}` : p}
        </Pill>
      ))}
      {ports.length > 3 && <Pill title={ports.slice(3).join(", ")}>+{ports.length - 3}</Pill>}
    </PillRow>
  );
}

function Detail({ item }: { item: ExposureItem }) {
  return (
    <div className="grid grid-cols-1 gap-4 text-sm lg:grid-cols-2">
      <div>
        <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-3">How it is reached</h3>
        <ul className="space-y-1">
          {item.methods.map((m, i) => (
            <li key={i} className={m.level === "blocked" ? "text-ink-3 line-through" : ""}>
              <Tag tone={m.level === "open" ? "critical" : m.level === "restricted" ? "warn" : "default"}>{m.label}</Tag>{" "}
              {m.detail}
              {m.ports.length > 0 && <span className="text-ink-3"> · ports {m.ports.join(", ")}</span>}
              {m.note && <span className="text-ink-3"> · {m.note}</span>}
            </li>
          ))}
        </ul>
        {item.partial_exposure.length > 0 && (
          <>
            <h3 className="mb-1 mt-3 text-xs font-semibold uppercase tracking-wide text-ink-3">Reachable only from</h3>
            <ul className="space-y-0.5 text-ink-2">
              {item.partial_exposure.map((p, i) => (
                <li key={i}>
                  <span className="font-mono">{p.source}</span>
                  {p.ports && p.ports.length > 0 && <> on {p.ports.join(", ")}</>}
                  {p.rule && <span className="text-ink-3"> (rule {p.rule})</span>}
                </li>
              ))}
            </ul>
          </>
        )}
        <h3 className="mb-1 mt-3 text-xs font-semibold uppercase tracking-wide text-ink-3">Protecting controls</h3>
        <p className="text-ink-2">{item.network_controls.length ? item.network_controls.join(" · ") : "None reported"}</p>
        {item.private_endpoints.length > 0 && (
          <p className="mt-1 text-ink-2">Private endpoints: {item.private_endpoints.join(", ")}</p>
        )}
        {item.public_endpoint && <p className="mt-1 text-ink-2">Public endpoint: {item.public_endpoint}</p>}
        {item.egress && <p className="mt-1 text-ink-3">Egress: {item.egress} (outbound only)</p>}
      </div>
      <div>
        <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-3">
          Linked risk{item.findings.count > 0 ? ` · findings (${item.findings.count})` : ""}
        </h3>
        {item.findings.top.length === 0 && item.vulnerabilities.top.length === 0 && item.attack_paths.length === 0 && (
          <p className="text-ink-3">No open findings, vulnerabilities or attack paths.</p>
        )}
        <ul className="space-y-1">
          {item.findings.top.map((f) => (
            <li key={f.id}>
              <SeverityBadge severity={f.severity} />{" "}
              <Link className="hover:text-accent" to={`/findings/${f.id}`}>
                {f.title}
              </Link>{" "}
              <span className="font-mono text-[11px] text-ink-3">{f.rule_id}</span>
            </li>
          ))}
          {item.vulnerabilities.top.map((v) => (
            <li key={v.id}>
              <SeverityBadge severity={v.severity} />{" "}
              <Link className="hover:text-accent" to="/vulnerabilities">
                {v.cve_id} in {v.package}
              </Link>
            </li>
          ))}
          {item.attack_paths.map((p) => (
            <li key={p.id}>
              <SeverityBadge severity={p.severity} />{" "}
              <Link className="hover:text-accent" to="/attack-paths">
                {p.title}
              </Link>{" "}
              {!p.confirmed && <span className="text-[11px] text-ink-3">(exposure path)</span>}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export default function Exposure() {
  const [params, setParams] = useSearchParams();
  const f = {
    provider: params.get("provider") ?? "",
    subscription: params.get("subscription") ?? "",
    type: params.get("type") ?? "",
    port: params.get("port") ?? "",
    level: params.get("level") ?? "",
  };
  const set = (k: keyof typeof f) => (v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next, { replace: true });
  };
  const [expanded, setExpanded] = useState<string | null>(null);
  const [asset, setAsset] = useState<string | null>(null);
  const { data, error, loading } = useApi(
    () =>
      api.exposure({
        provider: f.provider || undefined,
        subscription: f.subscription || undefined,
        type: f.type || undefined,
        port: f.port || undefined,
        level: f.level || undefined,
      }),
    [f.provider, f.subscription, f.type, f.port, f.level],
  );
  // Risk: confirmed attack paths weigh most, then prioritized vulnerabilities, then findings.
  const sorted = useSort(
    data?.items,
    {
      level: (i) => (i.level === "open" ? 2 : 1) + (i.sensitive_data ? 0.5 : 0),
      name: (i) => i.name,
      ports: (i) => i.effective_ports.length,
      risk: (i) =>
        i.attack_paths.filter((p) => p.confirmed).length * 1000 + i.attack_paths.length * 100 + i.vulnerabilities.prioritized * 10 + i.findings.count,
    },
    { key: "risk", dir: "desc" },
    { level: "desc", ports: "desc", risk: "desc" },
  );
  const s = data?.summary;
  const facets = data?.facets;

  return (
    <div>
      <PageHeader
        title="Exposed to the internet"
        subtitle="Cloud resources anyone on the internet can reach."
      />
      {s && (
        <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
          <Stat label="Open to everyone" selected={f.level === "open"} onSelect={() => set("level")(f.level === "open" ? "" : "open")} value={s.open} sub={`${s.attack_path_entries} start an attack path`} />
          <Stat label="Restricted" selected={f.level === "restricted"} onSelect={() => set("level")(f.level === "restricted" ? "" : "restricted")} value={s.restricted} sub="Reachable only from addresses you allowed" />
          <Stat label="Risky doors open" value={s.risky_ports_open} sub="Remote access or databases" />
          <Stat label="Sensitive data" value={s.sensitive} sub="exposed data stores" />
          <Stat label="With private endpoint" value={s.with_private_endpoint} sub="but still publicly reachable" />
        </div>
      )}
      <Card>
        <FilterBar
          count={data ? `${data.items.length} resources` : undefined}
          moreActive={[f.provider, f.port].filter(Boolean).length}
          more={
            <>
              <FilterSelect label="Cloud" value={f.provider} onChange={set("provider")} options={[{ value: "", label: "All" }, ...(facets?.providers ?? []).map((p) => ({ value: p, label: PROVIDER_LABEL[p] ?? p }))]} />
              <FilterSearch value={f.port} onChange={(v) => set("port")(v.replace(/\D/g, "").slice(0, 5))} placeholder="Port, e.g. 22" label="Filter by port" />
            </>
          }
        >
          <FilterSelect label="Who" value={f.level} onChange={set("level")} options={[{ value: "", label: "All" }, { value: "open", label: "Anyone" }, { value: "restricted", label: "Some addresses" }]} />
          <FilterSelect label="Account" value={f.subscription} onChange={set("subscription")} options={[{ value: "", label: "All" }, ...(facets?.subscriptions ?? []).map((x) => ({ value: x, label: x }))]} />
          <FilterSelect label="Type" value={f.type} onChange={set("type")} options={[{ value: "", label: "All" }, ...(facets?.types ?? []).map((t) => ({ value: t, label: TYPE_LABEL[t] ?? t }))]} />
        </FilterBar>
        <FilterChips
          chips={
            [
              f.level && { label: "Who", value: f.level === "open" ? "Anyone" : "Some addresses", onRemove: () => set("level")("") },
              f.subscription && { label: "Account", value: f.subscription, onRemove: () => set("subscription")("") },
              f.type && { label: "Type", value: TYPE_LABEL[f.type] ?? f.type, onRemove: () => set("type")("") },
              f.provider && { label: "Cloud", value: PROVIDER_LABEL[f.provider] ?? f.provider, onRemove: () => set("provider")("") },
              f.port && { label: "Port", value: f.port, onRemove: () => set("port")("") },
            ].filter((c): c is FilterChip => !!c)
          }
          onClearAll={() => setParams(new URLSearchParams(), { replace: true })}
        />
          <Table
            tableId="exposure"
            head={[
              { label: "Who can reach it", sort: "level", w: 150 },
              { label: "Resource", sort: "name", w: 280 },
              { label: "How", w: 230 },
              { label: "Open ports", sort: "ports", w: 190 },
              { label: "Controls", w: 180 },
              { label: "Risk", sort: "risk", w: 190 },
              { label: "Details", srOnly: true },
            ]}
            sort={sorted.sort}
            onSort={sorted.onSort}
            loading={loading}
            rowCount={data?.items.length ?? 0}
            noun="resources"
            pageSize={50}
            filtered={!!(f.provider || f.subscription || f.type || f.port || f.level)}
            onClearFilters={() => setParams(new URLSearchParams(), { replace: true })}
            error={data ? null : error}
            empty={
              <Empty icon={Globe} title="No internet-exposed assets match these filters">
                Nothing reachable from the Internet with these filters. Clear a filter to see all exposed assets.
              </Empty>
            }
          >
            {sorted.rows.map((i) => (
              <Fragment key={i.id}>
                <tr className="cursor-pointer align-top hover:bg-surface-2" onClick={() => setExpanded(expanded === i.id ? null : i.id)}>
                  <td className="px-3 py-2">
                    <PillRow>
                      <Pill tone={i.level === "open" ? "critical" : "high"}>{i.level === "open" ? "Anyone" : "Some"}</Pill>
                      {i.sensitive_data && <Pill tone="high" title="Holds sensitive data">Sensitive</Pill>}
                    </PillRow>
                  </td>
                  <td className="px-3 py-2">
                    <NameCell
                      name={i.name}
                      sub={[TYPE_LABEL[i.type] ?? i.type, PROVIDER_LABEL[i.provider] ?? i.provider, i.subscription_name].filter(Boolean).join(" · ")}
                      onOpen={() => setAsset(i.id)}
                    />
                  </td>
                  <td className="px-3 py-2">
                    {(() => {
                      const how = i.methods.filter((m) => m.level !== "blocked").map((m) => `${m.label}: ${m.detail}`).join("; ");
                      return how ? <TextCell muted title={how}>{i.methods.find((m) => m.level !== "blocked")?.label}</TextCell> : <None />;
                    })()}
                  </td>
                  <td className="px-3 py-2">
                    <Ports ports={i.effective_ports} />
                  </td>
                  <td className="px-3 py-2">
                    {i.network_controls.length || i.private_endpoints.length ? (
                      <PillRow>
                        {i.network_controls.slice(0, 1).map((c) => <Pill key={c} title={i.network_controls.join(" · ")}>{c.length > 16 ? `${c.slice(0, 15)}…` : c}</Pill>)}
                        {i.private_endpoints.length > 0 && <Pill tone="info">Private link</Pill>}
                      </PillRow>
                    ) : (
                      <Pill tone="high" title="No protecting controls reported">None</Pill>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {(() => {
                      const parts = [i.findings.count ? `${i.findings.count} issues` : "", i.vulnerabilities.count ? `${i.vulnerabilities.count} vulns` : "", i.attack_paths.length ? `${i.attack_paths.length} paths` : ""].filter(Boolean);
                      return parts.length ? (
                        <TextCell title={parts.join(" · ")}>
                          <span className={i.attack_paths.some((p) => p.confirmed) ? "text-sev-critical" : ""}>{parts.join(" · ")}</span>
                        </TextCell>
                      ) : (
                        <None />
                      );
                    })()}
                  </td>
                  <td className="px-3 py-2 text-right text-xs text-ink-3">{expanded === i.id ? "▲" : "▼"}</td>
                </tr>
                {expanded === i.id && (
                  <tr className="bg-surface-0/40">
                    <td colSpan={7} className="px-4 py-3">
                      <Detail item={i} />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </Table>
      </Card>
      <AssetDrawer assetId={asset} onClose={() => setAsset(null)} onNavigate={setAsset} />
    </div>
  );
}
