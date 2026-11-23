import { Link } from "react-router-dom";
import { statusLabel } from "../lib/labels";
import type { Vulnerability, VulnStatus } from "../api";
import { fmtAgo, fmtTime, TYPE_LABEL } from "../lib/format";
import { SEV_RANK, useSort, type SortState } from "../lib/useSort";
import { SOURCE_LABEL } from "../lib/vulns";
import { Card, NameCell, NumCell, None, Pill, PillRow, RiskBar, Table, TextCell, type PillTone } from "./ui";

const SEV_TONE: Record<string, PillTone> = { critical: "critical", high: "high", medium: "medium", low: "neutral" };

/** One-word flags: In use, Internet, Data, Exploited. */
function RuntimeContext({ v }: { v: Vulnerability }) {
  const exploited = v.kev ? (
    <Pill tone="critical" title="CISA KEV: on the list of flaws known to be exploited">
      Exploited
    </Pill>
  ) : null;
  if (v.device_id) return <PillRow>{exploited}</PillRow>;
  return (
    <PillRow>
      {v.in_use ? (
        <Pill tone="high" title={v.in_use_source === "sensor" && v.in_use_last_seen ? `Seen by runtime sensor ${new Date(v.in_use_last_seen).toLocaleString()}` : "Software that is running"}>
          In use
        </Pill>
      ) : (
        <Pill title="Software that is not running (lower priority)">Dormant</Pill>
      )}
      {v.internet_exposed && <Pill tone="critical" title="On the internet">Internet</Pill>}
      {v.sensitive_data_access && <Pill tone="high" title="Can reach sensitive data">Data</Pill>}
      {exploited ?? (v.exploit_available && <Pill tone="medium" title="A public exploit exists">Exploit</Pill>)}
    </PillRow>
  );
}

/** Vulnerability rows for cloud assets, sensor hosts and endpoint devices. */
export function VulnTable({
  rows,
  onAsset,
  showTarget = true,
  serverSort,
}: {
  rows: Vulnerability[];
  onAsset?: (assetId: string) => void;
  showTarget?: boolean;
  /** When the API sorts the whole result (the Vulnerabilities page) its sort state is passed in; otherwise the loaded rows sort here. */
  serverSort?: { sort: SortState; onSort: (key: string) => void };
}) {
  const local = useSort(
    serverSort ? [] : rows,
    {
      priority: (v) => SEV_RANK[v.priority] ?? 0,
      cve: (v) => v.cve_id,
      software: (v) => v.package,
      affected: (v) => v.device_name ?? v.asset_name ?? "",
      cvss: (v) => v.cvss,
      risk: (v) => v.risk_score,
      fixed: (v) => v.fixed_version,
    },
    { key: "risk", dir: "desc" },
    { priority: "desc", cvss: "desc", risk: "desc" },
    "vuln_sort",
  );
  const sorted = serverSort ? { ...serverSort, rows } : local;
  const head = [
    { label: "CVE", sort: "cve", w: 300 },
    { label: "Priority", sort: "priority", w: 110 },
    { label: "Software", sort: "software", w: 220 },
    ...(showTarget ? [{ label: "Affected", sort: "affected", w: 220 }] : []),
    { label: "Score", sort: "cvss", w: 80, align: "right" as const },
    { label: "Flags", w: 190 },
    { label: "Risk", sort: "risk", w: 130 },
    { label: "Fix", sort: "fixed", w: 120 },
  ];
  return (
    <Table tableId="vulns" head={head} sort={sorted.sort} onSort={sorted.onSort} noun="vulnerabilities" pageSize={50} rowCount={rows.length}>
      {sorted.rows.map((v) => (
        <tr key={v.id} className={`hover:bg-surface-2 ${v.status === "resolved" ? "opacity-60" : ""}`}>
          <td className="px-3 py-2">
            <div className="min-w-0">
              <Link className="block truncate font-mono text-sm font-semibold text-ink hover:text-accent hover:underline" to={`/vulnerabilities/${encodeURIComponent(v.cve_id)}`} title={`Details and how to fix ${v.cve_id}`}>
                {v.cve_id}
              </Link>
              <span className="block truncate text-xs text-ink-3" title={v.title}>
                {v.title}
              </span>
            </div>
          </td>
          <td className="px-3 py-2">
            <PillRow>
              <Pill tone={SEV_TONE[v.priority] ?? "neutral"}>{v.priority[0].toUpperCase() + v.priority.slice(1)}</Pill>
              {v.status === "resolved" && <Pill tone="good" title={v.resolved_at ? fmtTime(v.resolved_at) : undefined}>{statusLabel("resolved")}</Pill>}
            </PillRow>
          </td>
          <td className="px-3 py-2">
            <NameCell name={v.package} sub={[v.version, v.source ? SOURCE_LABEL[v.source] ?? v.source : ""].filter(Boolean).join(" · ")} />
          </td>
          {showTarget && (
            <td className="px-3 py-2">
              {v.device_id ? (
                <div className="min-w-0">
                  <Link className="block truncate font-semibold text-ink hover:text-accent hover:underline" to={`/devices/${encodeURIComponent(v.device_id)}`}>
                    {v.device_name ?? v.device_id}
                  </Link>
                  <span className="block text-xs text-ink-3">Computer</span>
                </div>
              ) : (
                <NameCell name={v.asset_name ?? v.asset_id ?? ""} sub={TYPE_LABEL[v.asset_type ?? ""] ?? v.asset_type} onOpen={v.asset_id ? () => onAsset?.(v.asset_id as string) : undefined} />
              )}
            </td>
          )}
          <td className="px-3 py-2">
            <NumCell value={v.cvss.toFixed(1)} title={`${v.severity}${v.epss != null ? ` · ${(v.epss * 100).toFixed(0)}% chance of being exploited in the next 30 days` : ""}`} />
          </td>
          <td className="px-3 py-2">
            <RuntimeContext v={v} />
          </td>
          <td className="px-3 py-2">
            <RiskBar value={v.risk_score} />
          </td>
          <td className="px-3 py-2">{v.fixed_version ? <TextCell mono>{v.fixed_version}</TextCell> : <None />}</td>
        </tr>
      ))}
    </Table>
  );
}

/** Data sources and how fresh they are ("feed last updated ..."), with errors. */
export function FeedStatus({ status }: { status: VulnStatus }) {
  return (
    <Card title="Data sources">
      {!status.enabled && <p className="mb-2 text-sm text-sev-high">Vulnerability matching is disabled (VULN_MATCHING_ENABLED=false).</p>}
      <ul className="space-y-2 text-sm">
        {status.feeds.map((f) => (
          <li key={f.feed} className="flex flex-wrap items-baseline justify-between gap-2">
            <span>
              {f.label} <span className="text-[11px] text-ink-3">({f.host})</span>
            </span>
            <span className="text-xs">
              {f.last_success_at ? (
                <span className="text-ink-2" title={fmtTime(f.last_success_at)}>
                  updated {fmtAgo(f.last_success_at)}
                  {f.items != null ? ` · ${f.items.toLocaleString()} entries` : ""}
                </span>
              ) : (
                <span className="text-ink-3">never updated</span>
              )}
              {f.last_error && (
                <span className="ml-2 text-sev-high" title={f.last_error}>
                  last attempt failed{f.last_attempt_at ? ` ${fmtAgo(f.last_attempt_at)}` : ""}
                </span>
              )}
            </span>
          </li>
        ))}
      </ul>
      <p className="mt-3 text-[11px] text-ink-3">
        Devices matched: {status.devices.matched}/{status.devices.total}
        {status.devices.pending ? ` (${status.devices.pending} queued)` : ""} · Linux hosts matched: {status.assets.matched}/{status.assets.total} ·
        re-matched every {status.rematch_interval_hours} h · NVD API key {status.nvd_api_key_configured ? "configured" : "not configured (slower, rate-limited)"}
      </p>
    </Card>
  );
}
