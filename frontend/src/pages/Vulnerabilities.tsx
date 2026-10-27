import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth/context";
import AssetDrawer from "../components/AssetDrawer";
import { Button, Card, Empty, ErrorNote, PageHeader, RiskBar, Select, SeverityBadge, Stat, Table, Tag } from "../components/ui";
import { FeedStatus, VulnTable } from "../components/vulns";
import { useApi } from "../lib/useApi";
import { useUrlState } from "../lib/useUrlState";

const VIEWS = ["Vulnerabilities", "By CVE", "By software", "Coverage"] as const;
type View = (typeof VIEWS)[number];

type Filters = Record<string, string | boolean | undefined>;

export default function Vulnerabilities() {
  const [params] = useSearchParams(); // deep links: ?asset=<id> opens the resource, ?cve=<id>, ?device=<id>
  const [view, setView] = useState<View>("Vulnerabilities");
  const [target, setTarget] = useState(params.get("device") ? "device" : params.get("scope") ?? "");
  const [runtime, setRuntime] = useUrlState("runtime", "all");
  const [severity, setSeverity] = useUrlState("severity");
  const [priority, setPriority] = useUrlState("priority");
  const [kevOnly, setKevOnly] = useState(false);
  const [software, setSoftware] = useState("");
  const [status, setStatus] = useState("open");
  const [cve, setCve] = useState(params.get("cve") ?? "");
  const [sort, setSort] = useState("risk");
  const [asset, setAsset] = useState<string | null>(params.get("asset"));
  const deviceId = params.get("device") ?? undefined;
  const analyst = useAuth().can("analyst");
  const [rematchMsg, setRematchMsg] = useState<string | null>(null);

  const filters: Filters = {
    scope: target || undefined,
    in_use: target === "device" || runtime === "all" ? undefined : runtime === "in_use",
    severity: severity || undefined,
    priority: priority || undefined,
    kev: kevOnly ? true : undefined,
    package: software.trim() || undefined,
    status,
    cve_id: cve.trim() || undefined,
    device_id: deviceId,
  };
  const key = JSON.stringify(filters);
  const { data: stats } = useApi(api.vulnStats, []);
  const { data: vstatus, reload: reloadStatus } = useApi(api.vulnStatus, [], 60000);
  const list = useApi(() => (view === "Vulnerabilities" ? api.vulnerabilities({ ...filters, sort }) : Promise.resolve(null)), [key, sort, view]);
  const byCve = useApi(() => (view === "By CVE" ? api.vulnByCve(filters) : Promise.resolve(null)), [key, view]);
  const bySw = useApi(() => (view === "By software" ? api.vulnBySoftware(filters) : Promise.resolve(null)), [key, view]);
  const nr = stats?.noise_reduction;
  const error = list.error || byCve.error || bySw.error;

  async function rematch() {
    try {
      const r = await api.vulnRematch();
      setRematchMsg(`${r.queued} devices / hosts queued for matching${r.worker_running ? "" : " (the background worker is not running in this process)"}.`);
      reloadStatus();
    } catch (e) {
      setRematchMsg(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div>
      <PageHeader
        title="Vulnerabilities"
        subtitle="CVEs on cloud workloads, Linux servers (runtime sensor, matched with OSV.dev) and laptops (installed software matched with NVD by CPE). Workload CVEs are ranked by runtime context; CISA KEV marks vulnerabilities known to be exploited."
        actions={analyst ? <Button onClick={rematch}>Re-match now</Button> : undefined}
      />
      {rematchMsg && <p className="mb-3 text-sm text-ink-2">{rematchMsg}</p>}
      <ErrorNote error={error} />
      {stats && nr && (
        <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-5">
          <Stat
            label="Noise reduction (workloads)"
            value={`${nr.percent}%`}
            sub={`${nr.dormant} of ${nr.total} workload vulns are in packages never loaded at runtime`}
          />
          <Stat label="Loaded at runtime" value={nr.in_use} sub={`${stats.in_use_and_exposed} also internet-exposed`} />
          <Stat
            label="Critical CVSS actually in use"
            value={`${stats.critical_cvss_in_use} / ${stats.critical_cvss_total}`}
            sub="critical-severity CVEs whose package is loaded"
          />
          <Stat label="On laptops" value={stats.devices?.open ?? 0} sub={`${stats.devices?.affected ?? 0} devices affected`} />
          <Stat label="Known exploited (KEV)" value={stats.kev?.cves ?? 0} sub={`${stats.kev?.open ?? 0} open findings`} />
        </div>
      )}

      <div role="tablist" aria-label="Vulnerability views" className="mb-3 flex gap-1 border-b border-line">
        {VIEWS.map((v) => (
          <button
            key={v}
            role="tab"
            aria-selected={view === v}
            onClick={() => setView(v)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm ${view === v ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink"}`}
          >
            {v}
            {v === "Coverage" && vstatus && vstatus.software_not_checked > 0 ? ` (${vstatus.software_not_checked} not checked)` : ""}
          </button>
        ))}
      </div>

      {view !== "Coverage" && (
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <Select
            label="Affected"
            value={target}
            onChange={setTarget}
            options={[
              { value: "", label: "Everything" },
              { value: "asset", label: "Cloud workloads & servers" },
              { value: "device", label: "Laptops (devices)" },
            ]}
          />
          {target !== "device" && (
            <Select
              label="Runtime"
              value={runtime}
              onChange={setRuntime}
              options={[
                { value: "all", label: "All" },
                { value: "in_use", label: "Loaded at runtime" },
                { value: "dormant", label: "Not loaded (deprioritized)" },
              ]}
            />
          )}
          <Select label="Severity" value={severity} onChange={setSeverity} options={["", "critical", "high", "medium", "low"]} />
          {view === "Vulnerabilities" && <Select label="Priority" value={priority} onChange={setPriority} options={["", "critical", "high", "medium", "low"]} />}
          <Select label="Status" value={status} onChange={setStatus} options={["open", "resolved", "all"]} />
          <label className="flex items-center gap-1.5 text-sm text-ink-2">
            <input type="checkbox" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} /> KEV only
          </label>
          <input
            value={software}
            onChange={(e) => setSoftware(e.target.value)}
            placeholder="Software / package"
            aria-label="Filter by software"
            className="w-44 rounded border border-line bg-surface-2 px-2 py-1 text-sm text-ink"
          />
          <input
            value={cve}
            onChange={(e) => setCve(e.target.value)}
            placeholder="CVE-…"
            aria-label="Filter by CVE"
            className="w-36 rounded border border-line bg-surface-2 px-2 py-1 font-mono text-sm text-ink"
          />
          {view === "Vulnerabilities" && (
            <Select
              label="Sort by"
              value={sort}
              onChange={setSort}
              options={[
                { value: "risk", label: "Risk score" },
                { value: "cvss", label: "CVSS only" },
                { value: "epss", label: "EPSS" },
                { value: "recent", label: "Newest" },
              ]}
            />
          )}
          {deviceId && (
            <Link to="/vulnerabilities" className="text-xs text-accent">
              clear device filter
            </Link>
          )}
        </div>
      )}

      {view === "Vulnerabilities" && (
        <Card>
          <p className="mb-2 text-xs text-ink-3">{list.data ? `${list.data.length} vulnerabilities` : "Loading…"}</p>
          {list.data && list.data.length === 0 ? <Empty>No vulnerabilities match these filters.</Empty> : <VulnTable rows={list.data ?? []} onAsset={setAsset} />}
        </Card>
      )}

      {view === "By CVE" && (
        <Card>
          {byCve.data && byCve.data.length === 0 ? (
            <Empty>No vulnerabilities match these filters.</Empty>
          ) : (
            <Table head={["Severity", "CVE", "Software", "Affected", "CVSS / EPSS", "Fixed in", "Max risk"]}>
              {(byCve.data ?? []).map((g) => (
                <tr key={g.cve_id} className="hover:bg-surface-2">
                  <td className="px-3 py-2">
                    <SeverityBadge severity={g.severity} /> {g.kev && <Tag tone="critical">KEV</Tag>}
                  </td>
                  <td className="px-3 py-2">
                    <button className="font-mono text-xs hover:text-accent" onClick={() => { setCve(g.cve_id); setView("Vulnerabilities"); }}>
                      {g.cve_id}
                    </button>
                    <div className="max-w-[18rem] truncate text-[11px] text-ink-3" title={g.title}>{g.title}</div>
                  </td>
                  <td className="px-3 py-2 text-xs">{g.packages.join(", ")}</td>
                  <td className="px-3 py-2 text-xs">
                    {g.device_count > 0 && <div title={g.devices.join(", ")}>{g.device_count} device{g.device_count === 1 ? "" : "s"}</div>}
                    {g.asset_count > 0 && <div title={g.assets.join(", ")}>{g.asset_count} asset{g.asset_count === 1 ? "" : "s"}</div>}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs">
                    {g.cvss.toFixed(1)}
                    {g.epss != null && <span className="text-ink-3"> · {(g.epss * 100).toFixed(1)}%</span>}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs text-ink-2">{g.fixed_versions.slice(-2).join(", ") || "—"}</td>
                  <td className="px-3 py-2"><RiskBar value={g.max_risk} /></td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      )}

      {view === "By software" && (
        <Card>
          {bySw.data && bySw.data.length === 0 ? (
            <Empty>No vulnerabilities match these filters.</Empty>
          ) : (
            <Table head={["Software / package", "Worst", "CVEs", "KEV", "Affected", "Installed versions", "Update to"]}>
              {(bySw.data ?? []).map((g) => (
                <tr key={g.package} className="hover:bg-surface-2">
                  <td className="px-3 py-2">
                    <button className="hover:text-accent" onClick={() => { setSoftware(g.package); setView("Vulnerabilities"); }}>{g.package}</button>
                  </td>
                  <td className="px-3 py-2"><SeverityBadge severity={g.severity} /></td>
                  <td className="px-3 py-2 text-xs">{g.cve_count}</td>
                  <td className="px-3 py-2 text-xs">{g.kev_count > 0 ? <Tag tone="critical">{g.kev_count}</Tag> : "—"}</td>
                  <td className="px-3 py-2 text-xs">
                    {g.device_count > 0 && <div>{g.device_count} device{g.device_count === 1 ? "" : "s"}</div>}
                    {g.asset_count > 0 && <div>{g.asset_count} asset{g.asset_count === 1 ? "" : "s"}</div>}
                  </td>
                  <td className="max-w-[16rem] truncate px-3 py-2 font-mono text-xs text-ink-2" title={g.versions.join(", ")}>{g.versions.join(", ")}</td>
                  <td className="px-3 py-2 font-mono text-xs text-ink-2">{g.fixed_versions.length ? `≥ ${g.fixed_versions[g.fixed_versions.length - 1]}` : "—"}</td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      )}

      {view === "Coverage" && vstatus && (
        <div className="grid gap-4 lg:grid-cols-2">
          <FeedStatus status={vstatus} />
          <Card title={`Software not checked (${vstatus.software_not_checked})`}>
            <p className="mb-2 text-xs text-ink-3">
              Laptop software is only checked when it is in the curated CPE mapping ({vstatus.mapping_rules} products, see
              docs/VULNERABILITIES.md). Unmapped applications are listed here instead of being guessed. {vstatus.software_checked} installs are
              checked.
            </p>
            {vstatus.not_checked_top.length === 0 ? (
              <Empty>Everything reported is checked.</Empty>
            ) : (
              <Table head={["Software", "Devices", "Why"]}>
                {vstatus.not_checked_top.map((n) => (
                  <tr key={n.name}>
                    <td className="px-3 py-1.5 text-sm">{n.name}</td>
                    <td className="px-3 py-1.5 text-xs">{n.devices}</td>
                    <td className="px-3 py-1.5 text-xs text-ink-3">{n.reason}</td>
                  </tr>
                ))}
              </Table>
            )}
          </Card>
        </div>
      )}
      {view !== "Coverage" && vstatus && (
        <p className="mt-3 text-[11px] text-ink-3">
          Sources:{" "}
          {vstatus.feeds.map((f, i) => (
            <span key={f.feed}>
              {i > 0 && " · "}
              {f.feed.toUpperCase()} {f.last_success_at ? `updated ${new Date(f.last_success_at).toLocaleString()}` : "not updated yet"}
              {f.last_error ? " (last refresh failed)" : ""}
            </span>
          ))}
        </p>
      )}
      <AssetDrawer assetId={asset} onClose={() => setAsset(null)} onNavigate={setAsset} />
    </div>
  );
}
