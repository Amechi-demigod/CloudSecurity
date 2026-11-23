import { Network } from "lucide-react";
import { statusLabel } from "../../lib/labels";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../auth/context";
import {
  AttentionList,
  Breadcrumbs,
  Button,
  Empty,
  ErrorNote,
  FilterBar,
  FilterChips,
  FilterSearch,
  FilterSelect,
  NumCell,
  None,
  PageHeader,
  Pill,
  PillRow,
  SelectCell,
  Stat,
  Table,
  TextCell,
  type AttentionItem,
  type FilterChip,
  type PillTone,
} from "../../components/ui";
import { errMsg } from "../../lib/assets";
import { fmtAgo, fmtTime, fmtUntil } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { useSort } from "../../lib/useSort";
import { useUrlState } from "../../lib/useUrlState";
import { networkApi, TYPE_LABEL, type NetDeviceRow } from "../../networkApi";
import { PAGE_INFO } from "../../lib/pageInfo";

const STATUS = [
  { value: "", label: "All" },
  { value: "not_in_it_assets", label: "Not in hardware register" },
  { value: "has_vulns", label: "Has vulnerabilities" },
  { value: "has_findings", label: "Has findings" },
  { value: "new_this_week", label: "New this week" },
];
const TYPES = ["", "infrastructure", "switch", "router", "firewall", "access_point", "printer", "ups", "camera", "phone", "server", "workstation", "unknown"];
const TYPE_OPTS = TYPES.map((t) => ({ value: t, label: t === "" ? "All" : t === "infrastructure" ? "Infrastructure" : TYPE_LABEL[t] }));
const SEV_TONE: Record<string, PillTone> = { critical: "critical", high: "high", medium: "medium", low: "neutral" };
const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

function useDebounced<T>(v: T, ms = 300): T {
  const [d, setD] = useState(v);
  useEffect(() => {
    const t = setTimeout(() => setD(v), ms);
    return () => clearTimeout(t);
  }, [v, ms]);
  return d;
}

/** Tabs shared by the Network page and the Network scans page. */
export function NetworkNav({ active, devices, scans }: { active: "devices" | "scans"; devices?: number; scans?: number }) {
  const cls = (on: boolean) =>
    `-mb-px inline-flex items-center gap-2 border-b-2 px-3 py-2 text-sm font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${on ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink"}`;
  const count = (n?: number) => (n == null ? null : <span className="rounded-full bg-surface-2 px-1.5 text-xs tabular-nums text-ink-2">{n}</span>);
  return (
    <nav aria-label="Network sections" className="mb-4 flex gap-1 border-b border-line">
      <Link to="/network-devices" aria-current={active === "devices" ? "page" : undefined} className={cls(active === "devices")}>
        Devices {count(devices)}
      </Link>
      <Link to="/network-scans" aria-current={active === "scans" ? "page" : undefined} className={cls(active === "scans")}>
        Network scans {count(scans)}
      </Link>
    </nav>
  );
}

export default function NetworkDevices() {
  const { can } = useAuth();
  const isAnalyst = can("analyst");
  const isAdmin = can("admin");
  const [q, setQ] = useUrlState("q");
  const dq = useDebounced(q);
  const [type, setType] = useUrlState("type");
  const [status, setStatus] = useUrlState("status");
  const [subnet, setSubnet] = useUrlState("subnet");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [notice, setNotice] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const summary = useApi(networkApi.summary, [], 60000);
  const scans = useApi(networkApi.scans, [], 60000);
  const filters = { q: dq, type, status, subnet };
  const devices = useApi(() => networkApi.devices(filters), [dq, type, status, subnet]);
  // The "Fix first" list is built from every device, whatever the list below is filtered to.
  const all = useApi(() => networkApi.devices({}), [], 60000);
  const s = summary.data;
  const sorted = useSort(
    devices.data,
    {
      device: (d) => d.name, type: (d) => d.type_label, vendor: (d) => `${d.vendor} ${d.model}`.trim(), firmware: (d) => d.firmware,
      ports: (d) => d.open_ports.length, issues: (d) => d.vulns.open * 1000 + d.findings.length, tracked: (d) => d.tracked_label,
      seen: (d) => Date.parse(d.last_seen),
    },
    { key: "seen", dir: "desc" },
    { ports: "desc", issues: "desc", seen: "desc" },
  );
  const rows = sorted.rows;
  const filtered = !!(q || type || status || subnet);
  const clearAll = () => {
    setQ("");
    setType("");
    setStatus("");
    setSubnet("");
  };
  const opt = (list: { value: string; label: string }[], v: string) => list.find((o) => o.value === v)?.label ?? v;
  const chips: FilterChip[] = [
    q && { label: "Search", value: q, onRemove: () => setQ("") },
    type && { label: "Type", value: opt(TYPE_OPTS, type), onRemove: () => setType("") },
    status && { label: "Status", value: opt(STATUS, status), onRemove: () => setStatus("") },
    subnet && { label: "Subnet", value: subnet, onRemove: () => setSubnet("") },
  ].filter((c): c is FilterChip => !!c);

  async function add() {
    setErr(null);
    try {
      const r = await networkApi.addToAssets([...selected]);
      setNotice(`${r.created.length} IT asset${r.created.length === 1 ? "" : "s"} created${r.skipped.length ? `; ${r.skipped.length} skipped` : ""}.`);
      setSelected(new Set());
      devices.reload();
      summary.reload();
    } catch (e) {
      setErr(errMsg(e));
    }
  }

  // Scan now: queue every enabled scan that has a collector (the collector picks each up within about a minute).
  const runnable = (scans.data ?? []).filter((x) => x.enabled && x.collector_id);
  async function scanNow() {
    setErr(null);
    try {
      await Promise.all(runnable.map((x) => networkApi.runScan(x.id)));
      setNotice(`${runnable.length} scan${runnable.length === 1 ? "" : "s"} queued, the collector picks ${runnable.length === 1 ? "it" : "them"} up within about a minute.`);
      scans.reload();
      summary.reload();
    } catch (e) {
      setErr(errMsg(e));
    }
  }

  // Fix first: what the last scan found, worst first. Only what the data says; an item with nothing behind it is left out.
  const list = all.data ?? [];
  const fix: AttentionItem[] = [];
  for (const d of list.filter((x) => x.vulns.kev > 0)) {
    fix.push({
      key: `kev-${d.id}`,
      label: "Critical",
      tone: "critical",
      text: `${d.name}${d.firmware ? ` firmware ${d.firmware}` : ""} has ${d.vulns.kev} ${d.vulns.kev === 1 ? "flaw" : "flaws"} being exploited now.`,
      to: `/network-devices/${d.id}`,
    });
  }
  for (const d of list) {
    for (const f of d.findings.filter((x) => x.severity === "critical" || x.severity === "high")) {
      fix.push({ key: `f-${f.id}`, label: f.severity === "critical" ? "Critical" : "High", tone: SEV_TONE[f.severity] ?? "neutral", text: `${d.name}: ${f.title}`, to: `/network-devices/${d.id}` });
    }
  }
  const fresh = list.filter((d) => d.new_this_week && !d.it_asset_id);
  if (fresh.length > 0) {
    fix.push({
      key: "new",
      label: "Medium",
      tone: "medium",
      text: `${fresh.length} new ${fresh.length === 1 ? "device appeared" : "devices appeared"} this week and ${fresh.length === 1 ? "isn't" : "aren't"} in the hardware register.`,
      onClick: () => setStatus("new_this_week"),
    });
  }
  fix.sort((a, b) => (SEV_ORDER[a.label.toLowerCase()] ?? 9) - (SEV_ORDER[b.label.toLowerCase()] ?? 9));
  const fixTop = fix.slice(0, 5);

  const last = s?.last_scan;
  const nextRun = (scans.data ?? []).filter((x) => x.enabled && x.next_run_at).sort((a, b) => Date.parse(a.next_run_at!) - Date.parse(b.next_run_at!))[0];
  return (
    <div>
      <Breadcrumbs items={[{ label: "Assets" }, { label: "Network" }]} />
      <PageHeader
        title="Network"
        info={PAGE_INFO.network}
        subtitle="Switches, firewalls, printers and other devices found on your networks."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Link to="/network-scans" className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">
              Scan settings
            </Link>
            <a href={networkApi.exportUrl(filters)} className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">
              Export CSV
            </a>
            {isAdmin && (
              <Button variant="primary" disabled={runnable.length === 0} title={runnable.length === 0 ? "No enabled scan with a collector yet" : undefined} onClick={() => void scanNow()}>
                Scan now
              </Button>
            )}
          </div>
        }
      />
      <NetworkNav active="devices" devices={s?.devices} scans={scans.data?.length} />
      {last && (
        <div className="mb-4 rounded-xl border border-line bg-surface-1 px-4 py-3 text-sm">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span className="font-semibold text-ink">Last scan {statusLabel(last.status).toLowerCase()}</span>
            <span className="text-ink-2">
              {last.name} · <span title={fmtTime(last.finished_at ?? last.queued_at)}>{fmtAgo(last.finished_at ?? last.queued_at)}</span>
              {last.summary.duration_s ? ` · took ${Math.max(1, Math.round(last.summary.duration_s / 60))} min` : ""}
            </span>
            {last.summary.addresses != null && (
              <span className="text-ink-2">
                {last.summary.addresses.toLocaleString()} addresses checked{last.devices_seen ? ` · ${last.devices_seen} devices answered` : ""}
              </span>
            )}
            <Link to="/connectors" className="ml-auto text-accent hover:underline">
              Scan history
            </Link>
          </div>
          {nextRun && (
            <div className="mt-1 text-xs text-ink-3">
              Next scan: {fmtUntil(nextRun.next_run_at!)} ({fmtTime(nextRun.next_run_at!)}){nextRun.collector ? ` · from ${nextRun.collector.name}` : ""}
            </div>
          )}
        </div>
      )}
      <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Devices found" onSelect={clearAll} selected={!filtered} value={s?.devices ?? "-"} sub={s ? `${s.with_snmp} identified in detail · ${s.ping_arp_only} only seen on the network` : undefined} />
        <Stat label="Network infrastructure" onSelect={() => setType(type === "infrastructure" ? "" : "infrastructure")} selected={type === "infrastructure"} value={s?.infrastructure ?? "-"} sub="switches, routers, firewalls, access points" />
        <Stat label="Not in hardware register" onSelect={() => setStatus(status === "not_in_it_assets" ? "" : "not_in_it_assets")} selected={status === "not_in_it_assets"} value={s?.not_in_it_assets ?? "-"} sub="no asset record yet" />
        <Stat label="With security flaws" onSelect={() => setStatus(status === "has_vulns" ? "" : "has_vulns")} selected={status === "has_vulns"} value={s?.with_vulns ?? "-"} sub={s ? `${s.kev} being exploited now` : undefined} />
      </div>
      <AttentionList title="Fix first" hint={`${fixTop.length} ${fixTop.length === 1 ? "suggestion" : "suggestions"} from the last scan`} items={fixTop} />
      <div className="rounded-xl border border-line bg-surface-1 p-4">
        <FilterBar
          count={`${rows.length} ${rows.length === 1 ? "device" : "devices"}`}
          moreActive={[status, subnet].filter(Boolean).length}
          more={
            <>
              <FilterSelect label="Status" value={status} onChange={setStatus} options={STATUS} />
              <FilterSelect label="Subnet" value={subnet} onChange={setSubnet} options={[{ value: "", label: "All" }, ...(s?.subnets ?? []).map((x) => ({ value: x, label: x }))]} />
            </>
          }
        >
          <FilterSearch value={q} onChange={setQ} placeholder="Name, IP, MAC, vendor" label="Search devices" />
          <FilterSelect label="Type" value={type} onChange={setType} options={TYPE_OPTS} />
        </FilterBar>
        <FilterChips chips={chips} onClearAll={clearAll} />
        {notice && <p className="mb-2 text-sm text-good">{notice}</p>}
        <ErrorNote error={err} />
        <Table
          tableId="network-devices"
          head={[
            { label: "Device", sort: "device", w: 240 },
            { label: "Type", sort: "type", w: 120 },
            { label: "Vendor / model", sort: "vendor", w: 200 },
            { label: "Firmware", sort: "firmware", w: 110 },
            { label: "Open ports", sort: "ports", w: 150 },
            { label: "Issues", sort: "issues", w: 80, align: "right" },
            { label: "Hardware register", sort: "tracked", w: 150 },
            { label: "Last seen", sort: "seen", w: 120 },
          ]}
          sort={sorted.sort}
          onSort={sorted.onSort}
          loading={devices.loading}
          rowCount={rows.length}
          noun="network devices"
          pageSize={50}
          filtered={filtered}
          onClearFilters={clearAll}
          error={devices.data ? null : devices.error}
          onRetry={devices.reload}
          selection={
            isAnalyst
              ? {
                  ids: rows.map((r) => (r.it_asset_id ? null : r.id)),
                  selected,
                  onChange: setSelected,
                  actions: (
                    <Button variant="primary" onClick={() => void add()}>
                      Add selected to hardware register ({selected.size})
                    </Button>
                  ),
                }
              : undefined
          }
          empty={
            <Empty icon={Network} title="No network devices">
              Nothing matches, or no network scan has run yet. Add a network scan to find your devices.
            </Empty>
          }
        >
          {rows.map((d: NetDeviceRow) => {
            const ports = d.open_ports.map((p) => p.port).join(", ");
            const issues = d.vulns.open + d.findings.length;
            return (
              <tr key={d.id} aria-selected={selected.has(d.id)}>
                {isAnalyst && (
                  <SelectCell
                    label={`Select ${d.name}`}
                    disabled={!!d.it_asset_id}
                    checked={selected.has(d.id)}
                    onChange={(on) =>
                      setSelected((p) => {
                        const n = new Set(p);
                        if (on) n.add(d.id);
                        else n.delete(d.id);
                        return n;
                      })
                    }
                  />
                )}
                <td className="px-3 py-2">
                  <NameCellLink id={d.id} name={d.name} sub={d.ip} />
                </td>
                <td className="px-3 py-2">
                  <TextCell>{d.type_label}</TextCell>
                </td>
                <td className="px-3 py-2">
                  <TextCell title={[d.vendor, d.model].filter(Boolean).join(" ")}>{[d.vendor, d.model].filter(Boolean).join(" ") || <None />}</TextCell>
                </td>
                <td className="px-3 py-2">{d.firmware ? <TextCell>{d.firmware}</TextCell> : <None />}</td>
                <td className="px-3 py-2">{ports ? <TextCell mono>{ports}</TextCell> : <None />}</td>
                <td className="px-3 py-2">
                  <NumCell
                    value={issues}
                    title={[d.vulns.open ? `${d.vulns.open} CVEs${d.vulns.kev ? `, ${d.vulns.kev} being exploited now` : ""}` : "", ...d.findings.map((f) => f.title)].filter(Boolean).join("; ") || undefined}
                  />
                </td>
                <td className="px-3 py-2">
                  <PillRow>
                    {d.it_asset_id ? <Pill tone="good">Registered</Pill> : <Pill tone="medium">Not registered</Pill>}
                    {d.vulns.kev > 0 && <Pill tone="critical">Exploited</Pill>}
                  </PillRow>
                </td>
                <td className="px-3 py-2">
                  <PillRow>
                    <span className="text-ink-2" title={fmtTime(d.last_seen)}>
                      {fmtAgo(d.last_seen)}
                    </span>
                    {d.new_this_week && <Pill tone="info">New</Pill>}
                  </PillRow>
                </td>
              </tr>
            );
          })}
        </Table>
      </div>
    </div>
  );
}

function NameCellLink({ id, name, sub }: { id: string; name: string; sub: string }) {
  return (
    <div className="min-w-0">
      <Link to={`/network-devices/${id}`} title={name} className="block overflow-hidden text-ellipsis whitespace-nowrap rounded font-semibold text-ink hover:text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
        {name}
      </Link>
      <span title={sub} className="block overflow-hidden text-ellipsis whitespace-nowrap font-mono text-xs text-ink-3">
        {sub}
      </span>
    </div>
  );
}
