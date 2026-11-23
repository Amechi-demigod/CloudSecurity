import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth/context";
import AssetDrawer from "../components/AssetDrawer";
import { Button, Card, Empty, ErrorNote, FilterBar, FilterChips, FilterSearch, FilterSelect, NameCell, NumCell, None, PageHeader, Pill, PillRow, RiskBar, Stat, Table, TextCell, type FilterChip, type PillTone } from "../components/ui";
import { FeedStatus, VulnTable } from "../components/vulns";
import { useApi } from "../lib/useApi";
import { useSort, useSortState } from "../lib/useSort";
import { useUrlState } from "../lib/useUrlState";
import { PAGE_INFO } from "../lib/pageInfo";

const VIEWS = ["Vulnerabilities", "By CVE", "By software", "Coverage"] as const;
type View = (typeof VIEWS)[number];

const SEV_TONE: Record<string, PillTone> = { critical: "critical", high: "high", medium: "medium", low: "neutral" };

type Filters = Record<string, string | boolean | undefined>;

export default function Vulnerabilities() {
  const [params] = useSearchParams(); // deep links: ?asset=<id> opens the resource, ?cve=<id>, ?device=<id>
  const [view, setView] = useState<View>("Vulnerabilities");
  const [target, setTarget] = useState(params.get("device") ? "device" : params.get("scope") ?? "");
  const [runtime, setRuntime] = useUrlState("runtime", "all");
  const [severity, setSeverity] = useUrlState("severity");
  const [priority, setPriority] = useUrlState("priority");
  const [kevParam, setKevParam] = useUrlState("kev"); // ?kev=1 (dashboard links)
  const kevOnly = kevParam === "1";
  const setKevOnly = (on: boolean) => setKevParam(on ? "1" : "");
  const [software, setSoftware] = useState("");
  const [status, setStatus] = useState("open");
  const [cve, setCve] = useState(params.get("cve") ?? "");
  // The API sorts the whole result of each view (the lists are capped), so the sort goes to it.
  const listSort = useSortState(["risk", "cvss", "epss", "recent", "priority", "cve", "software", "affected", "fixed"], { key: "risk", dir: "desc" }, { risk: "desc", cvss: "desc", epss: "desc", recent: "desc", priority: "desc" });
  const cveSort = useSortState(["severity", "cve", "software", "affected", "cvss", "fixed", "risk"], { key: "severity", dir: "desc" }, { severity: "desc", cvss: "desc", affected: "desc", risk: "desc" }, "csort");
  const swSort = useSortState(["software", "severity", "cves", "kev", "affected", "versions", "fixed"], { key: "severity", dir: "desc" }, { severity: "desc", cves: "desc", kev: "desc", affected: "desc" }, "ssort");
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
  const list = useApi(() => (view === "Vulnerabilities" ? api.vulnerabilities({ ...filters, sort: listSort.sort.key, dir: listSort.sort.dir }) : Promise.resolve(null)), [key, listSort.sort.key, listSort.sort.dir, view]);
  const byCve = useApi(() => (view === "By CVE" ? api.vulnByCve({ ...filters, sort: cveSort.sort.key, dir: cveSort.sort.dir }) : Promise.resolve(null)), [key, cveSort.sort.key, cveSort.sort.dir, view]);
  const bySw = useApi(() => (view === "By software" ? api.vulnBySoftware({ ...filters, sort: swSort.sort.key, dir: swSort.sort.dir }) : Promise.resolve(null)), [key, swSort.sort.key, swSort.sort.dir, view]);
  const ncSort = useSort(vstatus?.not_checked_top, { name: (n) => n.name, devices: (n) => n.devices, reason: (n) => n.reason }, { key: "devices", dir: "desc" }, { devices: "desc" }, "ncsort");
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
        info={PAGE_INFO.vulnerabilities}
        subtitle="Known security flaws in the software you run, worst first."
        actions={analyst ? <Button onClick={rematch}>Re-match now</Button> : undefined}
      />
      {rematchMsg && <p className="mb-3 text-sm text-ink-2">{rematchMsg}</p>}
      <ErrorNote error={error} />
      {stats && nr && (
        <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-5">
          <Stat
            label="Flaws you can ignore for now"
            value={`${nr.percent}%`}
            sub={`${nr.dormant} of ${nr.total} are in software that is never run`}
          />
          <Stat
            label="In use right now"
            value={nr.in_use}
            sub={`${stats.in_use_and_exposed} also reachable from the internet`}
            selected={runtime === "in_use" && target !== "device"}
            onSelect={() => {
              setView("Vulnerabilities");
              setTarget("");
              setRuntime(runtime === "in_use" ? "all" : "in_use");
            }}
          />
          <Stat
            label="Critical and in use"
            value={`${stats.critical_cvss_in_use} / ${stats.critical_cvss_total}`}
            sub="Critical flaws in software that is running"
          />
          <Stat
            label="On computers"
            value={stats.devices?.open ?? 0}
            sub={`${stats.devices?.affected ?? 0} computers affected`}
            selected={target === "device"}
            onSelect={() => {
              setView("Vulnerabilities");
              setTarget(target === "device" ? "" : "device");
            }}
          />
          <Stat
            label="Being exploited now"
            value={stats.kev?.cves ?? 0}
            sub={`${stats.kev?.open ?? 0} open. Fix these first`}
            selected={kevOnly}
            onSelect={() => {
              setView("Vulnerabilities");
              setKevOnly(!kevOnly);
            }}
          />
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
        <>
          <FilterBar
            count={view === "Vulnerabilities" && list.data ? `${list.data.length} vulnerabilities` : undefined}
            moreActive={[runtime !== "all" && target !== "device" ? runtime : "", priority, cve.trim()].filter(Boolean).length}
            more={
              <>
                {target !== "device" && <FilterSelect label="Runtime" value={runtime} onChange={setRuntime} options={[{ value: "all", label: "All" }, { value: "in_use", label: "In use" }, { value: "dormant", label: "Not in use" }]} />}
                {view === "Vulnerabilities" && <FilterSelect label="Priority" value={priority} onChange={setPriority} options={["", "critical", "high", "medium", "low"]} />}
                <FilterSearch value={cve} onChange={setCve} placeholder="CVE-…" label="Filter by CVE" />
                {view === "Vulnerabilities" && (
                  <FilterSelect
                    label="Sort by"
                    value={listSort.sort.key}
                    onChange={(k) => k !== listSort.sort.key && listSort.onSort(k)}
                    options={[
                      { value: "risk", label: "Risk" },
                      { value: "cvss", label: "Severity score only" },
                      { value: "epss", label: "Likely to be exploited" },
                      { value: "recent", label: "Newest" },
                      ...(["risk", "cvss", "epss", "recent"].includes(listSort.sort.key) ? [] : [{ value: listSort.sort.key, label: "Table column" }]),
                    ]}
                  />
                )}
              </>
            }
          >
            <FilterSearch value={software} onChange={setSoftware} placeholder="Software or package" label="Filter by software" />
            <FilterSelect label="Where" value={target} onChange={setTarget} options={[{ value: "", label: "All" }, { value: "asset", label: "Cloud workloads & servers" }, { value: "device", label: "Computers" }]} />
            <FilterSelect label="Severity" value={severity} onChange={setSeverity} options={["", "critical", "high", "medium", "low"]} />
            <FilterSelect label="Status" value={status} onChange={setStatus} options={[{ value: "open", label: "Open" }, { value: "resolved", label: "Fixed" }, { value: "all", label: "All" }]} />
            <label className="inline-flex h-8 items-center gap-1.5 text-sm text-ink-2">
              <input type="checkbox" className="accent-accent" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} /> Being exploited
            </label>
            {deviceId && (
              <Link to="/vulnerabilities" className="text-xs text-accent">
                clear device filter
              </Link>
            )}
          </FilterBar>
          <FilterChips
            chips={
              [
                software.trim() && { label: "Software", value: software, onRemove: () => setSoftware("") },
                target && { label: "Where", value: target === "device" ? "Computers" : "Cloud workloads & servers", onRemove: () => setTarget("") },
                severity && { label: "Severity", value: severity, onRemove: () => setSeverity("") },
                status !== "open" && { label: "Status", value: status === "resolved" ? "Fixed" : "All", onRemove: () => setStatus("open") },
                kevOnly && { label: "Exploited", value: "Being exploited now", onRemove: () => setKevOnly(false) },
                runtime !== "all" && target !== "device" && { label: "Runtime", value: runtime === "in_use" ? "In use" : "Not in use", onRemove: () => setRuntime("all") },
                priority && { label: "Priority", value: priority, onRemove: () => setPriority("") },
                cve.trim() && { label: "CVE", value: cve, onRemove: () => setCve("") },
              ].filter((c): c is FilterChip => !!c)
            }
            onClearAll={() => {
              setSoftware("");
              setTarget("");
              setSeverity("");
              setStatus("open");
              setKevOnly(false);
              setRuntime("all");
              setPriority("");
              setCve("");
            }}
          />
        </>
      )}

      {view === "Vulnerabilities" && (
        <Card>
          {list.data && list.data.length === 0 ? <Empty>No vulnerabilities match these filters.</Empty> : <VulnTable rows={list.data ?? []} onAsset={setAsset} serverSort={listSort} />}
        </Card>
      )}

      {view === "By CVE" && (
        <Card>
          {byCve.data && byCve.data.length === 0 ? (
            <Empty>No vulnerabilities match these filters.</Empty>
          ) : (
            <Table
              tableId="vulnerabilities-1"
              head={[
                { label: "CVE", sort: "cve", w: 300 },
                { label: "Severity", sort: "severity", w: 150 },
                { label: "Software", sort: "software", w: 200 },
                { label: "Affected", sort: "affected", w: 100, align: "right" },
                { label: "Score", sort: "cvss", w: 90, align: "right" },
                { label: "Fixed in", sort: "fixed", w: 140 },
                { label: "Risk", sort: "risk", w: 130 },
              ]}
              sort={cveSort.sort}
              onSort={cveSort.onSort}
              noun="CVEs"
              pageSize={50}
              loading={byCve.loading}
              rowCount={byCve.data?.length ?? 0}
            >
              {(byCve.data ?? []).map((g) => (
                <tr key={g.cve_id} className="hover:bg-surface-2">
                  <td className="px-3 py-2">
                    <div className="min-w-0">
                      <Link className="block truncate font-mono text-sm font-semibold text-ink hover:text-accent hover:underline" to={`/vulnerabilities/${encodeURIComponent(g.cve_id)}`}>
                        {g.cve_id}
                      </Link>
                      <span className="block truncate text-xs text-ink-3" title={g.title}>{g.title}</span>
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <PillRow>
                      <Pill tone={SEV_TONE[g.severity] ?? "neutral"}>{g.severity[0].toUpperCase() + g.severity.slice(1)}</Pill>
                      {g.kev && <Pill tone="critical" title="Being exploited now">Exploited</Pill>}
                    </PillRow>
                  </td>
                  <td className="px-3 py-2"><TextCell>{g.packages.join(", ")}</TextCell></td>
                  <td className="px-3 py-2">
                    <NumCell value={g.device_count + g.asset_count} title={[g.devices.join(", "), g.assets.join(", ")].filter(Boolean).join(" · ") || undefined} />
                  </td>
                  <td className="px-3 py-2">
                    <NumCell value={g.cvss.toFixed(1)} title={g.epss != null ? `${(g.epss * 100).toFixed(0)}% chance of being exploited in the next 30 days` : undefined} />
                  </td>
                  <td className="px-3 py-2">{g.fixed_versions.length ? <TextCell mono>{g.fixed_versions.slice(-2).join(", ")}</TextCell> : <None />}</td>
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
            <Table
              tableId="vulnerabilities-2"
              head={[
                { label: "Software", sort: "software", w: 280 },
                { label: "Worst", sort: "severity", w: 110 },
                { label: "Flaws", sort: "cves", w: 80, align: "right" },
                { label: "Being exploited", sort: "kev", w: 140, align: "right" },
                { label: "Affected", sort: "affected", w: 100, align: "right" },
                { label: "Installed versions", sort: "versions", w: 210 },
                { label: "Update to", sort: "fixed", w: 150 },
              ]}
              sort={swSort.sort}
              onSort={swSort.onSort}
              noun="software"
              pageSize={50}
              loading={bySw.loading}
              rowCount={bySw.data?.length ?? 0}
            >
              {(bySw.data ?? []).map((g) => (
                <tr key={g.package} className="hover:bg-surface-2">
                  <td className="px-3 py-2">
                    <NameCell name={g.package} onOpen={() => { setSoftware(g.package); setView("Vulnerabilities"); }} openLabel={`Show the flaws in ${g.package}`} />
                  </td>
                  <td className="px-3 py-2"><PillRow><Pill tone={SEV_TONE[g.severity] ?? "neutral"}>{g.severity[0].toUpperCase() + g.severity.slice(1)}</Pill></PillRow></td>
                  <td className="px-3 py-2"><NumCell value={g.cve_count} /></td>
                  <td className="px-3 py-2"><NumCell value={g.kev_count} /></td>
                  <td className="px-3 py-2"><NumCell value={g.device_count + g.asset_count} title={`${g.device_count} computers, ${g.asset_count} cloud assets`} /></td>
                  <td className="px-3 py-2"><TextCell mono title={g.versions.join(", ")}>{g.versions.join(", ")}</TextCell></td>
                  <td className="px-3 py-2">{g.fixed_versions.length ? <TextCell mono>{`≥ ${g.fixed_versions[g.fixed_versions.length - 1]}`}</TextCell> : <None />}</td>
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
              <Table
                tableId="vulnerabilities-3"
                head={[{ label: "Software", sort: "name" }, { label: "Devices", sort: "devices" }, { label: "Why", sort: "reason" }]}
                sort={ncSort.sort}
                onSort={ncSort.onSort}
              >
                {ncSort.rows.map((n) => (
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
