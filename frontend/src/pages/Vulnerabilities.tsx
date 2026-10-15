import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import AssetDrawer from "../components/AssetDrawer";
import { Card, ErrorNote, PageHeader, RiskBar, Select, SeverityBadge, Stat, Table, Tag } from "../components/ui";
import { TYPE_LABEL } from "../lib/format";
import { useApi } from "../lib/useApi";

export default function Vulnerabilities() {
  const [scope, setScope] = useState("in_use");
  const [sort, setSort] = useState("risk");
  const [priority, setPriority] = useState("");
  const [params] = useSearchParams(); // deep link: /vulnerabilities?asset=<id> opens the resource
  const [asset, setAsset] = useState<string | null>(params.get("asset"));

  const { data: stats } = useApi(api.vulnStats, []);
  const { data, error } = useApi(
    () =>
      api.vulnerabilities({
        in_use: scope === "all" ? undefined : scope === "in_use",
        priority: priority || undefined,
        sort,
      }),
    [scope, sort, priority],
  );
  const nr = stats?.noise_reduction;

  return (
    <div>
      <PageHeader
        title="Vulnerabilities with runtime context"
        subtitle="CVEs are ranked by a risk score combining CVSS with runtime signals: is the package actually loaded, is the workload internet-exposed, does it reach sensitive data, is there a public exploit?"
      />
      <ErrorNote error={error} />
      {stats && nr && (
        <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Stat
            label="Noise reduction"
            value={`${nr.percent}%`}
            sub={`${nr.dormant} of ${nr.total} vulns are in packages never loaded at runtime`}
          />
          <Stat label="Loaded at runtime" value={nr.in_use} sub="vulns in packages in use" />
          <Stat label="In use + internet-exposed" value={stats.in_use_and_exposed} sub={`${stats.exploitable_in_use} in use with public exploit`} />
          <Stat
            label="Critical CVSS actually in use"
            value={`${stats.critical_cvss_in_use} / ${stats.critical_cvss_total}`}
            sub="critical-severity CVEs whose package is loaded"
          />
        </div>
      )}
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <Select
          label="Show"
          value={scope}
          onChange={setScope}
          options={[
            { value: "in_use", label: "Loaded at runtime" },
            { value: "dormant", label: "Dormant (deprioritized)" },
            { value: "all", label: "All" },
          ]}
        />
        <Select label="Priority" value={priority} onChange={setPriority} options={["", "critical", "high", "medium", "low"]} />
        <Select
          label="Sort by"
          value={sort}
          onChange={setSort}
          options={[
            { value: "risk", label: "Runtime risk score" },
            { value: "cvss", label: "CVSS only (legacy)" },
          ]}
        />
        <span className="text-xs text-ink-3">{data ? `${data.length} vulnerabilities` : ""}</span>
      </div>
      <Card>
        <Table head={["Priority", "CVE", "Package", "Workload", "CVSS", "Runtime context", "Risk score", "Fix"]}>
          {data?.map((v) => (
            <tr key={v.id} className="hover:bg-surface-2">
              <td className="px-3 py-2">
                <SeverityBadge severity={v.priority} />
              </td>
              <td className="px-3 py-2">
                <a
                  className="font-mono text-xs hover:text-accent"
                  href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  {v.cve_id}
                </a>
                <div className="max-w-[16rem] truncate text-[11px] text-ink-3" title={v.title}>
                  {v.title}
                </div>
              </td>
              <td className="px-3 py-2 font-mono text-xs">
                {v.package}@{v.version}
              </td>
              <td className="px-3 py-2">
                <button className="hover:text-accent" onClick={() => setAsset(v.asset_id)}>
                  {v.asset_name}
                </button>
                <div className="text-[11px] text-ink-3">{TYPE_LABEL[v.asset_type ?? ""] ?? v.asset_type}</div>
              </td>
              <td className="px-3 py-2 text-xs">
                {v.cvss.toFixed(1)} <span className="text-ink-3">({v.severity})</span>
              </td>
              <td className="space-x-1 whitespace-nowrap px-3 py-2">
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
                {v.exploit_available && <Tag tone="warn">Exploit</Tag>}
              </td>
              <td className="px-3 py-2">
                <RiskBar value={v.risk_score} />
              </td>
              <td className="px-3 py-2 font-mono text-xs text-ink-2">{v.fixed_version ?? "—"}</td>
            </tr>
          ))}
        </Table>
      </Card>
      <AssetDrawer assetId={asset} onClose={() => setAsset(null)} onNavigate={setAsset} />
    </div>
  );
}
