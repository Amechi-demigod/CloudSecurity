import { Network } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../auth/context";
import { Breadcrumbs, Button, Card, Empty, ErrorNote, PageHeader, Stat, Table, Tag } from "../../components/ui";
import { errMsg } from "../../lib/assets";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { useUrlState } from "../../lib/useUrlState";
import { networkApi, TRACK_TONE, TYPE_LABEL, type NetDeviceRow } from "../../networkApi";

const STATUS = [
  { value: "", label: "All" },
  { value: "not_in_it_assets", label: "Not in IT assets" },
  { value: "has_vulns", label: "Has vulnerabilities" },
  { value: "has_findings", label: "Has findings" },
  { value: "new_this_week", label: "New this week" },
];
const TYPES = ["", "infrastructure", "switch", "router", "firewall", "access_point", "printer", "ups", "camera", "phone", "server", "workstation", "unknown"];
const sel = "rounded border border-line bg-surface-2 px-2 py-1 text-sm text-ink";

function useDebounced<T>(v: T, ms = 300): T {
  const [d, setD] = useState(v);
  useEffect(() => {
    const t = setTimeout(() => setD(v), ms);
    return () => clearTimeout(t);
  }, [v, ms]);
  return d;
}

export function NetworkNav({ active }: { active: "devices" | "scans" }) {
  const cls = (on: boolean) => `rounded border border-line px-3 py-1.5 text-sm font-medium hover:bg-line ${on ? "bg-line text-ink" : "bg-surface-2 text-ink"}`;
  return (
    <>
      <Link to="/network-devices" className={cls(active === "devices")}>
        Network devices
      </Link>
      <Link to="/network-scans" className={cls(active === "scans")}>
        Network scans
      </Link>
    </>
  );
}

export default function NetworkDevices() {
  const isAdmin = useAuth().can("analyst");
  const [q, setQ] = useState("");
  const dq = useDebounced(q);
  const [type, setType] = useUrlState("type");
  const [status, setStatus] = useUrlState("status");
  const [subnet, setSubnet] = useUrlState("subnet");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [notice, setNotice] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const summary = useApi(networkApi.summary, [], 60000);
  const filters = { q: dq, type, status, subnet };
  const devices = useApi(() => networkApi.devices(filters), [dq, type, status, subnet]);
  const s = summary.data;
  const rows = devices.data ?? [];
  const addable = rows.filter((r) => !r.it_asset_id);

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

  const last = s?.last_scan;
  return (
    <div>
      <Breadcrumbs items={[{ label: "Endpoints & assets" }, { label: "Network devices" }]} />
      <PageHeader
        title="Network devices"
        subtitle={
          last
            ? `Last scan ${fmtAgo(last.finished_at ?? last.queued_at)}: ${last.status}${last.summary.addresses ? `, ${last.summary.addresses.toLocaleString()} addresses` : ""}${last.summary.duration_s ? ` in ${Math.round(last.summary.duration_s / 60)} min` : ""}.`
            : "Devices found by network scans. Add a network scan under IT assets > Discovery."
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <NetworkNav active="devices" />
            <a href={networkApi.exportUrl(filters)} className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">
              Export CSV
            </a>
          </div>
        }
      />
      <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Devices found" value={s?.devices ?? "-"} sub={s ? `${s.with_snmp} via SNMP, ${s.ping_arp_only} by ping / ARP` : undefined} />
        <Stat label="Network infrastructure" value={s?.infrastructure ?? "-"} sub="switches, routers, firewalls, access points" to="/network-devices?type=infrastructure" />
        <Stat label="Not in IT assets" value={s?.not_in_it_assets ?? "-"} sub="no asset record yet" to="/network-devices?status=not_in_it_assets" />
        <Stat label="With vulnerabilities" value={s?.with_vulns ?? "-"} sub={s ? `${s.kev} known exploited (KEV)` : undefined} to="/network-devices?status=has_vulns" />
      </div>
      <Card>
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <input type="search" aria-label="Search devices" placeholder="Search name, IP, MAC, vendor…" value={q} onChange={(e) => setQ(e.target.value)} className="w-full rounded border border-line bg-surface-2 px-2.5 py-1 text-sm text-ink placeholder:text-ink-3 sm:w-60" />
          <label className="flex items-center gap-1.5 text-xs text-ink-3">
            Type
            <select className={sel} value={type} onChange={(e) => setType(e.target.value)}>
              {TYPES.map((t) => (
                <option key={t} value={t}>
                  {t === "" ? "All" : t === "infrastructure" ? "Infrastructure" : TYPE_LABEL[t]}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-1.5 text-xs text-ink-3">
            Status
            <select className={sel} value={status} onChange={(e) => setStatus(e.target.value)}>
              {STATUS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-1.5 text-xs text-ink-3">
            Subnet
            <select className={sel} value={subnet} onChange={(e) => setSubnet(e.target.value)}>
              <option value="">All</option>
              {(s?.subnets ?? []).map((x) => (
                <option key={x} value={x}>
                  {x}
                </option>
              ))}
            </select>
          </label>
          {isAdmin && (
            <div className="ml-auto">
              <Button variant="primary" disabled={selected.size === 0} onClick={() => void add()}>
                Add selected to IT assets{selected.size ? ` (${selected.size})` : ""}
              </Button>
            </div>
          )}
        </div>
        {notice && <p className="mb-2 text-sm text-good">{notice}</p>}
        <ErrorNote error={devices.error ?? err} />
        <Table
          head={[
            ...(isAdmin
              ? [
                  {
                    label: (
                      <input
                        type="checkbox"
                        aria-label="Select all"
                        checked={addable.length > 0 && addable.every((r) => selected.has(r.id))}
                        onChange={(e) => setSelected(e.target.checked ? new Set(addable.map((r) => r.id)) : new Set())}
                      />
                    ),
                  },
                ]
              : []),
            "Device",
            "Type",
            "Vendor / model",
            "Firmware",
            "Open ports",
            "Issues",
            "Tracked",
            "Last seen",
          ]}
          loading={devices.loading}
          rowCount={rows.length}
          empty={
            <Empty icon={Network} title="No network devices">
              Nothing matches, or no network scan has run yet. Add a network scan under IT assets &gt; Discovery.
            </Empty>
          }
        >
          {rows.map((d: NetDeviceRow) => (
            <tr key={d.id}>
              {isAdmin && (
                <td className="px-3 py-2">
                  <input
                    type="checkbox"
                    aria-label={`Select ${d.name}`}
                    disabled={!!d.it_asset_id}
                    checked={selected.has(d.id)}
                    onChange={(e) =>
                      setSelected((p) => {
                        const n = new Set(p);
                        if (e.target.checked) n.add(d.id);
                        else n.delete(d.id);
                        return n;
                      })
                    }
                  />
                </td>
              )}
              <td className="px-3 py-2">
                <Link to={`/network-devices/${d.id}`} className="font-medium text-accent hover:underline">
                  {d.name}
                </Link>
                <div className="font-mono text-[11px] text-ink-3">{d.ip}</div>
              </td>
              <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-2">{d.type_label}</td>
              <td className="px-3 py-2 text-xs text-ink-2">
                {d.vendor || <span className="text-ink-3">unknown</span>}
                {d.model && <div className="text-ink-3">{d.model}</div>}
              </td>
              <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-2">{d.firmware || <span className="text-ink-3">-</span>}</td>
              <td className="px-3 py-2 font-mono text-xs text-ink-2">{d.open_ports.length ? d.open_ports.map((p) => p.port).join(" ") : <span className="text-ink-3">-</span>}</td>
              <td className="px-3 py-2">
                <span className="flex flex-wrap gap-1">
                  {d.vulns.open > 0 && (
                    <Tag tone="critical">
                      {d.vulns.open} CVE{d.vulns.open === 1 ? "" : "s"}
                      {d.vulns.kev ? ` · ${d.vulns.kev} KEV` : ""}
                    </Tag>
                  )}
                  {d.findings.slice(0, 3).map((f) => (
                    <Link key={f.id} to={`/findings/${f.id}`} title={f.title}>
                      <Tag tone={f.severity === "high" || f.severity === "critical" ? "warn" : "default"}>{f.rule_id.replace("NET-", "")}</Tag>
                    </Link>
                  ))}
                  {d.findings.length > 3 && <Tag>+{d.findings.length - 3}</Tag>}
                  {d.vulns.open === 0 && d.findings.length === 0 && <span className="text-xs text-ink-3">-</span>}
                </span>
              </td>
              <td className="px-3 py-2">
                <Tag tone={TRACK_TONE[d.tracked]}>{d.tracked_label}</Tag>
              </td>
              <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-2" title={fmtTime(d.last_seen)}>
                {fmtAgo(d.last_seen)}
                {d.new_this_week && (
                  <div>
                    <Tag tone="accent">new</Tag>
                  </div>
                )}
              </td>
            </tr>
          ))}
        </Table>
      </Card>
    </div>
  );
}
