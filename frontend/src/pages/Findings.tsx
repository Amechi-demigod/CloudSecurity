import { Fragment, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, type Finding } from "../api";
import { useAuth } from "../auth/context";
import AssetDrawer from "../components/AssetDrawer";
import { Button, Card, Empty, ErrorNote, PageHeader, Select, SeverityBadge, Table, Tag } from "../components/ui";
import { PROVIDER_LABEL, TYPE_LABEL, fmtAgo } from "../lib/format";
import { useApi } from "../lib/useApi";
import { useUrlState } from "../lib/useUrlState";

export default function Findings() {
  // Deep links: /findings?finding=<id> (notifications), ?severity=, ?status=, ?provider=, ?compliance= (dashboard)
  const [params] = useSearchParams();
  const linked = params.get("finding");
  const [severity, setSeverity] = useUrlState("severity");
  const [status, setStatus] = useUrlState("status", linked ? "all" : "open");
  const [source, setSource] = useUrlState("source");
  const [provider, setProvider] = useUrlState("provider");
  const [compliance, setCompliance] = useUrlState("compliance");
  const [expanded, setExpanded] = useState<string | null>(linked);
  const [asset, setAsset] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const canTriage = useAuth().can("analyst");

  const { data, error, reload } = useApi(
    () =>
      api.findings({
        severity: severity || undefined,
        status,
        source: source || undefined,
        provider: provider || undefined,
        compliance: compliance || undefined,
      }),
    [severity, status, source, provider, compliance],
  );

  async function setFindingStatus(f: Finding, s: Finding["status"]) {
    try {
      await api.updateFinding(f.id, s);
      setActionError(null);
      reload();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div>
      <PageHeader
        title="Posture findings (CSPM)"
        subtitle="Misconfigurations detected by the declarative rules engine, mapped to CIS benchmarks."
      />
      <ErrorNote error={error ?? actionError} />
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <Select label="Severity" value={severity} onChange={setSeverity} options={["", "critical", "high", "medium", "low"]} />
        <Select label="Status" value={status} onChange={setStatus} options={["open", "suppressed", "resolved", "all"]} />
        <Select
          label="Cloud"
          value={provider}
          onChange={setProvider}
          options={[{ value: "", label: "All" }, ...["azure", "aws", "gcp"].map((p) => ({ value: p, label: PROVIDER_LABEL[p] }))]}
        />
        <Select label="Source" value={source} onChange={setSource} options={["", "simulated", "azure", "aws", "gcp"]} />
        <input
          className="w-48 rounded border border-line bg-surface-2 px-2 py-1 text-sm"
          placeholder="Compliance, e.g. CIS AWS 2.1"
          value={compliance}
          onChange={(e) => setCompliance(e.target.value)}
        />
        <span className="text-xs text-ink-3">{data ? `${data.length} findings` : ""}</span>
      </div>
      <Card>
        {data && data.length === 0 ? (
          <Empty>No findings match these filters.</Empty>
        ) : (
          <Table head={["Severity", "Finding", "Resource", "Compliance", "Status", "First seen", ""]}>
            {data?.map((f) => (
              <Fragment key={f.id}>
                <tr className="cursor-pointer hover:bg-surface-2" onClick={() => setExpanded(expanded === f.id ? null : f.id)}>
                  <td className="px-3 py-2">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="px-3 py-2">
                    <div>{f.title}</div>
                    <div className="font-mono text-[11px] text-ink-3">{f.rule_id}</div>
                  </td>
                  <td className="px-3 py-2">
                    <button
                      className="hover:text-accent"
                      onClick={(e) => {
                        e.stopPropagation();
                        setAsset(f.asset_id);
                      }}
                    >
                      {f.asset_name}
                    </button>
                    <div className="text-[11px] text-ink-3">{TYPE_LABEL[f.asset_type ?? ""] ?? f.asset_type}</div>
                  </td>
                  <td className="space-x-1 px-3 py-2">
                    {f.compliance.map((c) => (
                      <Tag key={c}>{c}</Tag>
                    ))}
                  </td>
                  <td className="px-3 py-2">
                    <Tag tone={f.status === "open" ? "warn" : f.status === "resolved" ? "good" : "default"}>{f.status}</Tag>
                  </td>
                  <td className="px-3 py-2 text-xs text-ink-2">{fmtAgo(f.first_seen)}</td>
                  <td className="px-3 py-2 text-right text-xs text-ink-3">{expanded === f.id ? "▲" : "▼"}</td>
                </tr>
                {expanded === f.id && (
                  <tr className="bg-surface-0/40">
                    <td colSpan={7} className="px-4 py-3 text-sm">
                      <p className="text-ink-2">{f.description}</p>
                      <p className="mt-2">
                        <span className="text-ink-3">Remediation: </span>
                        {f.remediation}
                      </p>
                      <p className="mt-2 font-mono text-xs text-ink-3">Evidence: {JSON.stringify(f.evidence)}</p>
                      {canTriage ? (
                      <div className="mt-3 flex gap-2">
                        {f.status !== "suppressed" && <Button onClick={() => setFindingStatus(f, "suppressed")}>Suppress</Button>}
                        {f.status !== "resolved" && <Button onClick={() => setFindingStatus(f, "resolved")}>Mark resolved</Button>}
                        {f.status !== "open" && <Button onClick={() => setFindingStatus(f, "open")}>Reopen</Button>}
                      </div>
                      ) : (
                        <p className="mt-3 text-xs text-ink-3">Read-only access: an analyst or admin can suppress or resolve findings.</p>
                      )}
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </Table>
        )}
      </Card>
      <AssetDrawer assetId={asset} onClose={() => setAsset(null)} onNavigate={setAsset} />
    </div>
  );
}
