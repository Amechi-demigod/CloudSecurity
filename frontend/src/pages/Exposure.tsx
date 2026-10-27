import { Globe } from "lucide-react";
import { Fragment, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type ExposureItem } from "../api";
import AssetDrawer from "../components/AssetDrawer";
import { Card, Empty, ErrorNote, PageHeader, Select, SeverityBadge, Stat, Table, Tag } from "../components/ui";
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
  if (!ports.length) return <span className="text-ink-3">—</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {ports.slice(0, 6).map((p) => (
        <Tag key={p} tone={RISKY.has(p) ? "critical" : "default"}>
          {p === "*" ? "all ports" : PORT_NAME[p] ? `${p} ${PORT_NAME[p]}` : p}
        </Tag>
      ))}
      {ports.length > 6 && <span className="text-xs text-ink-3">+{ports.length - 6}</span>}
    </span>
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
        <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-3">Linked risk</h3>
        {item.findings.top.length === 0 && item.vulnerabilities.top.length === 0 && item.attack_paths.length === 0 && (
          <p className="text-ink-3">No open findings, vulnerabilities or attack paths.</p>
        )}
        <ul className="space-y-1">
          {item.findings.top.map((f) => (
            <li key={f.id}>
              <SeverityBadge severity={f.severity} />{" "}
              <Link className="hover:text-accent" to={`/findings?finding=${f.id}`}>
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
        title="Cloud exposure"
        subtitle="Every internet-reachable asset across Azure, AWS and GCP: how it is reached, on which ports, what protects it and the risk linked to it."
      />
      <ErrorNote error={error} />
      {s && (
        <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
          <Stat label="Open to the Internet" value={s.open} sub={`${s.attack_path_entries} attack-path entry points`} />
          <Stat label="Restricted" value={s.restricted} sub="reachable from listed public ranges only" />
          <Stat label="Risky ports open" value={s.risky_ports_open} sub="admin or database ports" />
          <Stat label="Sensitive data" value={s.sensitive} sub="exposed data stores" />
          <Stat label="With private endpoint" value={s.with_private_endpoint} sub="but still publicly reachable" />
        </div>
      )}
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <Select
          label="Cloud"
          value={f.provider}
          onChange={set("provider")}
          options={[{ value: "", label: "All" }, ...(facets?.providers ?? []).map((p) => ({ value: p, label: PROVIDER_LABEL[p] ?? p }))]}
        />
        <Select
          label="Subscription"
          value={f.subscription}
          onChange={set("subscription")}
          options={[{ value: "", label: "All" }, ...(facets?.subscriptions ?? []).map((x) => ({ value: x, label: x }))]}
        />
        <Select
          label="Type"
          value={f.type}
          onChange={set("type")}
          options={[{ value: "", label: "All" }, ...(facets?.types ?? []).map((t) => ({ value: t, label: TYPE_LABEL[t] ?? t }))]}
        />
        <label className="flex items-center gap-1.5 text-xs text-ink-3">
          Port
          <input
            className="w-20 rounded border border-line bg-surface-2 px-2 py-1 text-sm text-ink"
            inputMode="numeric"
            placeholder="e.g. 22"
            value={f.port}
            onChange={(e) => set("port")(e.target.value.replace(/\D/g, "").slice(0, 5))}
          />
        </label>
        <Select
          label="Exposure"
          value={f.level}
          onChange={set("level")}
          options={[
            { value: "", label: "All" },
            { value: "open", label: "Open" },
            { value: "restricted", label: "Restricted" },
          ]}
        />
        <span className="text-xs text-ink-3">{data ? `${data.items.length} assets` : ""}</span>
      </div>
      <Card>
          <Table
            head={[
              { label: "Exposure", sort: "level" },
              { label: "Asset", sort: "name" },
              "How",
              { label: "Ports", sort: "ports" },
              "Controls",
              { label: "Risk", sort: "risk" },
              { label: "Details", srOnly: true },
            ]}
            sort={sorted.sort}
            onSort={sorted.onSort}
            loading={loading}
            rowCount={data?.items.length ?? 0}
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
                    <Tag tone={i.level === "open" ? "critical" : "warn"}>{i.level}</Tag>
                    {i.sensitive_data && (
                      <div className="mt-1">
                        <Tag tone="accent">sensitive</Tag>
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <button
                      className="text-left hover:text-accent"
                      onClick={(e) => {
                        e.stopPropagation();
                        setAsset(i.id);
                      }}
                    >
                      {i.name}
                    </button>
                    <div className="text-[11px] text-ink-3">
                      {TYPE_LABEL[i.type] ?? i.type} · {PROVIDER_LABEL[i.provider] ?? i.provider}
                      {i.subscription_name ? ` · ${i.subscription_name}` : ""}
                    </div>
                  </td>
                  <td className="max-w-md px-3 py-2 text-xs">
                    {i.methods
                      .filter((m) => m.level !== "blocked")
                      .slice(0, 2)
                      .map((m, n) => (
                        <div key={n}>
                          <span className="text-ink-3">{m.label}:</span> {m.detail}
                        </div>
                      ))}
                    {i.exposed_only_via.length > 0 && <div className="text-ink-3">via {i.exposed_only_via.join(", ")}</div>}
                  </td>
                  <td className="px-3 py-2">
                    <Ports ports={i.effective_ports} />
                  </td>
                  <td className="px-3 py-2 text-xs text-ink-2">
                    {i.network_controls.slice(0, 2).join(" · ") || <span className="text-ink-3">none</span>}
                    {i.private_endpoints.length > 0 && <div className="text-ink-3">private endpoint</div>}
                  </td>
                  <td className="px-3 py-2 text-xs">
                    <div>{i.findings.count} findings</div>
                    {i.vulnerabilities.count > 0 && <div>{i.vulnerabilities.count} vulnerabilities</div>}
                    {i.attack_paths.length > 0 && (
                      <div className={i.attack_paths.some((p) => p.confirmed) ? "text-sev-critical" : "text-ink-2"}>
                        {i.attack_paths.length} attack paths
                      </div>
                    )}
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
