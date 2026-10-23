import { Link } from "react-router-dom";
import type { Vulnerability, VulnStatus } from "../api";
import { fmtAgo, fmtTime, TYPE_LABEL } from "../lib/format";
import { SOURCE_LABEL, cveUrl } from "../lib/vulns";
import { Card, RiskBar, SeverityBadge, Table, Tag } from "./ui";

function RuntimeContext({ v }: { v: Vulnerability }) {
  if (v.device_id) {
    return (
      <span className="space-x-1 whitespace-nowrap">
        <span title="Endpoint software: no runtime sensor on laptops, installed apps are treated as in use for scoring">
          <Tag>Endpoint</Tag>
        </span>
        {v.kev && <Tag tone="critical">KEV</Tag>}
      </span>
    );
  }
  return (
    <span className="space-x-1 whitespace-nowrap">
      {v.in_use ? (
        v.in_use_source === "sensor" ? (
          <span title={v.in_use_last_seen ? `Seen by runtime sensor ${new Date(v.in_use_last_seen).toLocaleString()}` : "Seen by runtime sensor"}>
            <Tag tone="warn">In use (sensor)</Tag>
          </span>
        ) : (
          <Tag tone="warn">In use</Tag>
        )
      ) : (
        <Tag>Not loaded</Tag>
      )}
      {v.internet_exposed && <Tag tone="warn">Exposed</Tag>}
      {v.sensitive_data_access && <Tag tone="warn">Data access</Tag>}
      {v.kev ? <Tag tone="critical">KEV</Tag> : v.exploit_available && <Tag tone="warn">Exploit</Tag>}
    </span>
  );
}

/** Vulnerability rows for cloud assets, sensor hosts and endpoint devices. */
export function VulnTable({
  rows,
  onAsset,
  showTarget = true,
}: {
  rows: Vulnerability[];
  onAsset?: (assetId: string) => void;
  showTarget?: boolean;
}) {
  const head = ["Priority", "CVE", "Software / package", ...(showTarget ? ["Affected"] : []), "CVSS / EPSS", "Context", "Risk score", "Fix"];
  return (
    <Table head={head}>
      {rows.map((v) => (
        <tr key={v.id} className={`hover:bg-surface-2 ${v.status === "resolved" ? "opacity-60" : ""}`}>
          <td className="px-3 py-2">
            <SeverityBadge severity={v.priority} />
            {v.status === "resolved" && (
              <div className="mt-1 text-[11px] text-ink-3" title={v.resolved_at ? fmtTime(v.resolved_at) : undefined}>
                resolved{v.resolved_at ? ` ${fmtAgo(v.resolved_at)}` : ""}
              </div>
            )}
          </td>
          <td className="px-3 py-2">
            <a className="font-mono text-xs hover:text-accent" href={cveUrl(v)} target="_blank" rel="noreferrer">
              {v.cve_id}
            </a>
            <div className="max-w-[16rem] truncate text-[11px] text-ink-3" title={v.title}>
              {v.title}
            </div>
          </td>
          <td className="px-3 py-2 text-xs">
            <div className="font-mono">
              {v.package} <span className="text-ink-3">{v.version}</span>
            </div>
            {v.source && <div className="text-[11px] text-ink-3">{SOURCE_LABEL[v.source] ?? v.source}</div>}
          </td>
          {showTarget && (
            <td className="px-3 py-2">
              {v.device_id ? (
                <>
                  <Link className="hover:text-accent" to={`/devices/${encodeURIComponent(v.device_id)}`}>
                    {v.device_name ?? v.device_id}
                  </Link>
                  <div className="text-[11px] text-ink-3">Device</div>
                </>
              ) : (
                <>
                  <button className="hover:text-accent" onClick={() => v.asset_id && onAsset?.(v.asset_id)}>
                    {v.asset_name ?? v.asset_id}
                  </button>
                  <div className="text-[11px] text-ink-3">{TYPE_LABEL[v.asset_type ?? ""] ?? v.asset_type}</div>
                </>
              )}
            </td>
          )}
          <td className="whitespace-nowrap px-3 py-2 text-xs">
            {v.cvss.toFixed(1)} <span className="text-ink-3">({v.severity})</span>
            {v.epss != null && <div className="text-[11px] text-ink-3" title="FIRST EPSS: probability of exploitation in the next 30 days">EPSS {(v.epss * 100).toFixed(1)}%</div>}
          </td>
          <td className="px-3 py-2">
            <RuntimeContext v={v} />
          </td>
          <td className="px-3 py-2">
            <RiskBar value={v.risk_score} />
          </td>
          <td className="px-3 py-2 font-mono text-xs text-ink-2">{v.fixed_version ?? "—"}</td>
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
