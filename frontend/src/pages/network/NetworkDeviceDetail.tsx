import { FileDown, RefreshCw } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { useAuth } from "../../auth/context";
import { Breadcrumbs, Button, Card, Empty, ErrorNote, SeverityBadge, Table, Tag } from "../../components/ui";
import { errMsg } from "../../lib/assets";
import { fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { networkApi, TRACK_TONE, type NetDeviceDetail } from "../../networkApi";

type Tab = "overview" | "vulnerabilities" | "findings" | "interfaces" | "connected" | "history";

function Cell({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0 bg-surface-1 p-3">
      <dt className="text-[11px] font-medium uppercase tracking-wide text-ink-3">{label}</dt>
      <dd className="mt-1 break-words text-sm font-medium text-ink">{children}</dd>
    </div>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex justify-between gap-4 py-1.5 text-sm">
      <dt className="shrink-0 text-ink-3">{label}</dt>
      <dd className="min-w-0 break-words text-right text-ink">{children}</dd>
    </div>
  );
}

const uptime = (s: number | null) => (s == null ? "-" : `${Math.floor(s / 86400)} d ${Math.floor((s % 86400) / 3600)} h`);

function FixFirst({ d }: { d: NetDeviceDetail }) {
  if (d.fixes.length === 0)
    return <p className="text-sm text-ink-3">{d.vuln_status.reason ?? (d.vuln_status.checked ? "No known vulnerabilities in the firmware." : "Vulnerability check pending.")}</p>;
  return (
    <div className="space-y-4">
      {d.fixes.map((f, i) => (
        <div key={i} className="rounded-lg border border-line bg-surface-2 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.max_severity} />
            <Tag>{f.cve_count} CVE{f.cve_count === 1 ? "" : "s"}</Tag>
            {f.kev_count > 0 && <Tag tone="critical">{f.kev_count} known exploited</Tag>}
          </div>
          <h3 className="mt-2 text-sm font-semibold text-ink">{f.title}</h3>
          <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm text-ink-2 marker:text-ink-3">
            {f.steps.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ol>
          {f.workaround && (
            <div className="mt-3 rounded border border-sev-high/50 bg-sev-high/10 p-2.5 text-sm text-ink">
              <strong>Interim workaround</strong> (published by the vendor): {f.workaround.text}{" "}
              <a className="text-accent hover:underline" href={f.workaround.url} target="_blank" rel="noopener noreferrer">
                {f.workaround.source}
              </a>
            </div>
          )}
          <ul className="mt-3 divide-y divide-line text-sm">
            {f.cves.map((c) => (
              <li key={c.cve_id} className="flex flex-wrap items-center gap-2 py-1.5">
                <Link to={`/vulnerabilities/${c.cve_id}`} className="font-mono text-xs text-accent hover:underline">
                  {c.cve_id}
                </Link>
                <SeverityBadge severity={c.severity} />
                {c.kev && <Tag tone="critical">KEV</Tag>}
                <span className="text-xs text-ink-3">CVSS {c.cvss.toFixed(1)}</span>
              </li>
            ))}
          </ul>
          {f.advisory && (
            <p className="mt-2 text-xs">
              <a className="text-accent hover:underline" href={f.advisory.url} target="_blank" rel="noopener noreferrer">
                {f.advisory.label}
              </a>
            </p>
          )}
        </div>
      ))}
    </div>
  );
}

export default function NetworkDeviceDetail() {
  const { id = "" } = useParams();
  const { can } = useAuth();
  const [tab, setTab] = useState<Tab>("overview");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const { data: d, error, reload } = useApi(() => networkApi.device(id), [id]);
  if (!d) return <ErrorNote error={error} />;

  async function rescan() {
    setErr(null);
    try {
      await networkApi.rescan(d!.id);
      setMsg("Re-scan queued: the collector picks it up within about a minute. Reload to see the result.");
    } catch (e) {
      setErr(errMsg(e));
    }
  }
  async function pdf() {
    try {
      const { blob, filename } = await networkApi.devicePdf(d!.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setErr(errMsg(e));
    }
  }
  async function addAsset() {
    try {
      await networkApi.addToAssets([d!.id]);
      reload();
    } catch (e) {
      setErr(errMsg(e));
    }
  }

  const sub = [d.type_label, [d.vendor, d.model].filter(Boolean).join(" "), d.firmware, d.ip, d.snmp_version ? `identified by SNMP${d.snmp_version}` : `identified by ${d.identified_by}`].filter(Boolean).join(" · ");
  const tabs: { id: Tab; label: string; n?: number }[] = [
    { id: "overview", label: "Overview" },
    { id: "vulnerabilities", label: "Vulnerabilities", n: d.vulnerabilities.length },
    { id: "findings", label: "Findings", n: d.finding_list.length },
    { id: "interfaces", label: "Interfaces", n: d.interfaces.length },
    { id: "connected", label: "Connected devices", n: d.connected.rows.length },
    { id: "history", label: "History", n: d.events.length },
  ];
  const unmanaged = d.connected.rows.filter((r) => r.unmanaged);

  return (
    <div>
      <Breadcrumbs items={[{ label: "Network devices", to: "/network-devices" }, { label: d.name }]} />
      <header className="mb-5">
        <div className="flex flex-wrap items-center gap-2">
          <Tag>{d.type_label}</Tag>
          <Tag tone={TRACK_TONE[d.tracked]}>{d.tracked_label}</Tag>
          {d.vulns.kev > 0 && <Tag tone="critical">{d.vulns.kev} known exploited</Tag>}
          {d.vulns.open > 0 && <Tag tone="warn">{d.vulns.open} vulnerabilities</Tag>}
          {d.end_of_support && new Date(d.end_of_support.date) < new Date() && <Tag tone="critical">firmware end of support</Tag>}
        </div>
        <div className="mt-2 flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h1 className="text-xl font-semibold tracking-tight">{d.name}</h1>
            <p className="mt-1 break-words text-sm text-ink-2">{sub}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {can("analyst") && (
              <Button onClick={() => void pdf()}>
                <span className="inline-flex items-center gap-1.5">
                  <FileDown aria-hidden className="h-4 w-4" />
                  Export (PDF)
                </span>
              </Button>
            )}
            {can("admin") && (
              <Button onClick={() => void rescan()}>
                <span className="inline-flex items-center gap-1.5">
                  <RefreshCw aria-hidden className="h-4 w-4" />
                  Re-scan device
                </span>
              </Button>
            )}
            {d.it_asset_id ? (
              <Link to={`/it-assets/${d.it_asset_id}`} className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">
                Open IT asset record
              </Link>
            ) : (
              can("analyst") && (
                <Button variant="primary" onClick={() => void addAsset()}>
                  Add to IT assets
                </Button>
              )
            )}
          </div>
        </div>
      </header>
      {msg && <p className="mb-3 text-sm text-good">{msg}</p>}
      <ErrorNote error={error ?? err} />

      <dl className="mb-5 grid grid-cols-1 gap-px overflow-hidden rounded-xl border border-line bg-line sm:grid-cols-2 lg:grid-cols-4">
        <Cell label="IP / MAC">
          <span className="font-mono text-xs">{d.ip}</span>
          <div className="font-mono text-xs text-ink-2">{d.mac || "no MAC (routed)"}</div>
        </Cell>
        <Cell label="Serial">{d.serial || "-"}</Cell>
        <Cell label="Uptime">{uptime(d.uptime_s)}</Cell>
        <Cell label="SNMP location">{d.sys_location || "-"}</Cell>
        <Cell label="Interfaces">
          {d.interfaces.length ? `${d.interfaces_up} up / ${d.interfaces_down} down` : "-"}
        </Cell>
        <Cell label="Devices behind it">{d.connected.rows.length ? `${d.connected.total} (${d.connected.unmanaged} unmanaged)` : "-"}</Cell>
        <Cell label="First seen">{fmtTime(d.first_seen)}</Cell>
        <Cell label="Last scan">{d.last_run ? `${fmtTime(d.last_run.finished_at ?? d.last_run.queued_at)} (${d.last_run.status})` : fmtTime(d.last_seen)}</Cell>
      </dl>

      <div role="tablist" aria-label="Device sections" className="mb-4 flex gap-1 overflow-x-auto border-b border-line">
        {tabs.map((t) => (
          <button
            key={t.id}
            role="tab"
            type="button"
            aria-selected={tab === t.id}
            onClick={() => setTab(t.id)}
            className={`-mb-px whitespace-nowrap border-b-2 px-3 py-2 text-sm font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${tab === t.id ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink"}`}
          >
            {t.label}
            {t.n ? <span className="ml-1.5 rounded bg-surface-2 px-1.5 text-[11px] text-ink-2">{t.n}</span> : null}
          </button>
        ))}
      </div>

      {tab === "overview" && (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
          <div className="min-w-0 space-y-4">
            <Card title="Fix first">
              <FixFirst d={d} />
            </Card>
            <Card title={`Findings (${d.finding_list.length})`}>
              {d.finding_list.length === 0 ? (
                <Empty>No open findings on this device.</Empty>
              ) : (
                <ul className="divide-y divide-line">
                  {d.finding_list.map((f) => (
                    <li key={f.id} className="flex items-start gap-2 py-2">
                      <SeverityBadge severity={f.severity} />
                      <div className="min-w-0 text-sm">
                        <Link to={`/findings/${f.id}`} className="break-words hover:text-accent hover:underline">
                          {f.title}
                        </Link>
                        <div className="text-[11px] text-ink-3">{f.rule_id}</div>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
            <Card title="Open ports">
              {d.open_ports.length === 0 ? (
                <p className="text-sm text-ink-3">No open ports found (or the port check was off).</p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {d.open_ports.map((p) => (
                    <span key={`${p.port}/${p.proto}`} className="rounded border border-line px-2 py-0.5 font-mono text-xs text-ink" title={p.service}>
                      {p.port}/{p.proto}
                      {p.service && <span className="ml-1 text-ink-3">{p.service}</span>}
                    </span>
                  ))}
                </div>
              )}
            </Card>
          </div>
          <div className="min-w-0 space-y-4">
            <Card title="Tracking">
              <dl>
                <Fact label="IT asset">{d.it_asset ? <Link className="text-accent hover:underline" to={`/it-assets/${d.it_asset.id}`}>{d.it_asset.asset_tag}</Link> : "Not registered"}</Fact>
                {d.it_asset && <Fact label="Owner">{d.it_asset.assignee_name || d.it_asset.assignee_email || "-"}</Fact>}
                {d.it_asset && <Fact label="Support contract">{d.it_asset.warranty_end ? `until ${d.it_asset.warranty_end}` : d.it_asset.supplier || "not recorded"}</Fact>}
                {d.endpoint && <Fact label="Agent">{<Link className="text-accent hover:underline" to={`/devices/${d.endpoint.id}`}>{d.endpoint.hostname}</Link>}</Fact>}
                <Fact label="Firmware end of support">
                  {d.end_of_support ? (
                    <a className="text-accent hover:underline" href={d.end_of_support.url} target="_blank" rel="noopener noreferrer" title={d.end_of_support.source}>
                      {d.end_of_support.date}
                    </a>
                  ) : (
                    "not known"
                  )}
                </Fact>
              </dl>
            </Card>
            <Card title={`Connected unmanaged devices (${unmanaged.length})`}>
              {unmanaged.length === 0 ? (
                <p className="text-sm text-ink-3">{d.connected.rows.length ? "Everything behind this switch is known." : "No forwarding table (needs a switch read over SNMP)."}</p>
              ) : (
                <ul className="divide-y divide-line text-sm">
                  {unmanaged.slice(0, 8).map((r) => (
                    <li key={r.mac + r.port} className="py-1.5">
                      <span className="font-mono text-xs">{r.mac}</span> <span className="text-ink-3">{r.vendor}</span>
                      <div className="text-[11px] text-ink-3">
                        port {r.port}
                        {r.vlan ? `, VLAN ${r.vlan}` : ""}
                      </div>
                    </li>
                  ))}
                  {unmanaged.length > 8 && <li className="py-1.5 text-xs text-ink-3">and {unmanaged.length - 8} more</li>}
                </ul>
              )}
            </Card>
            <Card title="History">
              <HistoryList d={d} limit={5} />
            </Card>
          </div>
        </div>
      )}

      {tab === "vulnerabilities" && (
        <Card>
          <Table head={["CVE", "Severity", "CVSS", "KEV", "Firmware", "Fixed in"]} rowCount={d.vulnerabilities.length} empty={<Empty>{d.vuln_status.reason ?? "No open vulnerabilities."}</Empty>}>
            {d.vulnerabilities.map((v) => (
              <tr key={v.id}>
                <td className="px-3 py-2">
                  <Link to={`/vulnerabilities/${v.cve_id}`} className="font-mono text-xs text-accent hover:underline">
                    {v.cve_id}
                  </Link>
                  <div className="max-w-md truncate text-[11px] text-ink-3" title={v.title}>
                    {v.title}
                  </div>
                </td>
                <td className="px-3 py-2">
                  <SeverityBadge severity={v.severity} />
                </td>
                <td className="px-3 py-2 text-xs">{v.cvss.toFixed(1)}</td>
                <td className="px-3 py-2">{v.kev ? <Tag tone="critical">KEV</Tag> : <span className="text-ink-3">-</span>}</td>
                <td className="px-3 py-2 text-xs">{v.version}</td>
                <td className="px-3 py-2 text-xs">{v.fixed_version ?? <span className="text-ink-3">not named</span>}</td>
              </tr>
            ))}
          </Table>
        </Card>
      )}

      {tab === "findings" && (
        <Card>
          {d.finding_list.length === 0 ? (
            <Empty>No open findings.</Empty>
          ) : (
            <ul className="divide-y divide-line">
              {d.finding_list.map((f) => (
                <li key={f.id} className="flex items-start gap-2 py-2.5">
                  <SeverityBadge severity={f.severity} />
                  <div className="min-w-0 text-sm">
                    <Link to={`/findings/${f.id}`} className="font-medium hover:text-accent hover:underline">
                      {f.title}
                    </Link>
                    <p className="mt-0.5 text-xs text-ink-2">{f.description}</p>
                    <div className="text-[11px] text-ink-3">
                      {f.rule_id} · first seen {fmtTime(f.first_seen)}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}

      {tab === "interfaces" && (
        <Card>
          <Table head={["Name", "Description", "MAC", "State", "Speed"]} rowCount={d.interfaces.length} empty={<Empty>No interface data: it needs SNMP.</Empty>}>
            {d.interfaces.map((i) => (
              <tr key={i.index}>
                <td className="px-3 py-2 text-sm">{i.name}</td>
                <td className="px-3 py-2 text-xs text-ink-2">{i.descr}</td>
                <td className="px-3 py-2 font-mono text-xs">{i.mac}</td>
                <td className="px-3 py-2">
                  <Tag tone={i.oper_up ? "good" : "default"}>{i.oper_up ? "up" : "down"}</Tag>
                </td>
                <td className="px-3 py-2 text-xs">{i.speed_mbps ? `${i.speed_mbps} Mbps` : "-"}</td>
              </tr>
            ))}
          </Table>
        </Card>
      )}

      {tab === "connected" && (
        <Card>
          <Table head={["MAC", "Vendor", "Port", "VLAN", "Status"]} rowCount={d.connected.rows.length} empty={<Empty>No forwarding table: it needs a switch read over SNMP.</Empty>}>
            {d.connected.rows.map((r) => (
              <tr key={r.mac + r.port}>
                <td className="px-3 py-2 font-mono text-xs">{r.mac}</td>
                <td className="px-3 py-2 text-xs text-ink-2">{r.vendor || "-"}</td>
                <td className="px-3 py-2 text-xs">{r.port}</td>
                <td className="px-3 py-2 text-xs">{r.vlan || "-"}</td>
                <td className="px-3 py-2">
                  {r.device ? (
                    <Link to={`/network-devices/${r.device.id}`} className="text-xs text-accent hover:underline">
                      {r.device.name}
                    </Link>
                  ) : r.unmanaged ? (
                    <Tag tone="warn">unmanaged</Tag>
                  ) : r.uplink ? (
                    <Tag>uplink port</Tag>
                  ) : (
                    <Tag tone="good">{r.endpoint ? "endpoint" : "known"}</Tag>
                  )}
                </td>
              </tr>
            ))}
          </Table>
        </Card>
      )}

      {tab === "history" && (
        <Card>
          <HistoryList d={d} />
        </Card>
      )}
    </div>
  );
}

function HistoryList({ d, limit }: { d: NetDeviceDetail; limit?: number }) {
  const ev = limit ? d.events.slice(0, limit) : d.events;
  if (ev.length === 0) return <p className="text-sm text-ink-3">No history yet.</p>;
  return (
    <ol className="space-y-2 border-l border-line pl-4 text-sm">
      {ev.map((e, i) => (
        <li key={i}>
          <div className="text-ink">{e.detail}</div>
          <div className="text-xs text-ink-3">{fmtTime(e.at)}</div>
        </li>
      ))}
    </ol>
  );
}
