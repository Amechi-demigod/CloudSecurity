import { ChevronRight, ShieldCheck } from "lucide-react";
import { statusLabel } from "../lib/labels";
import { Fragment, useState } from "react";
import { Link, Navigate, useSearchParams } from "react-router-dom";
import { api, type Finding } from "../api";
import { useAuth } from "../auth/context";
import AssetDrawer from "../components/AssetDrawer";
import { Button, Card, Empty, ErrorNote, FilterBar, FilterChips, FilterSearch, FilterSelect, NameCell, PageHeader, Pill, PillRow, Segments, Table, TextCell, type FilterChip, type PillTone } from "../components/ui";
import { PROVIDER_LABEL, TYPE_LABEL, fmtAgo } from "../lib/format";
import { useApi } from "../lib/useApi";
import { useSortState } from "../lib/useSort";
import { useUrlState } from "../lib/useUrlState";
import { PAGE_INFO } from "../lib/pageInfo";

const SEV_TONE: Record<string, PillTone> = { critical: "critical", high: "high", medium: "medium", low: "neutral" };

export default function Findings() {
  // Deep links: ?severity=, ?status=, ?provider=, ?compliance=, ?category=, ?subscription= (dashboards); ?rule= (compliance); ?finding=<id> redirects below
  const [params] = useSearchParams();
  const linked = params.get("finding");
  const [severity, setSeverity] = useUrlState("severity");
  const [status, setStatus] = useUrlState("status", "open");
  const [source, setSource] = useUrlState("source");
  const [provider, setProvider] = useUrlState("provider");
  const [compliance, setCompliance] = useUrlState("compliance");
  // Set by dashboard links only (no control on this page): finding category and cloud account.
  const [category, setCategory] = useUrlState("category");
  const [subscription, setSubscription] = useUrlState("subscription");
  const [rule, setRule] = useUrlState("rule");
  // Closed findings only: "removed" = closed because the cloud resource no longer exists.
  const [reason, setReason] = useUrlState("reason");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [asset, setAsset] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const { can, platformAdmin } = useAuth();
  const canTriage = can("analyst");

  // The server sorts the whole result (the list is capped), so the sort goes to the API.
  const sorted = useSortState(["severity", "title", "resource", "status", "first_seen"], { key: "severity", dir: "desc" }, { severity: "desc", first_seen: "desc" });
  const { data, error, reload, loading } = useApi(
    () =>
      api.findings({
        severity: severity || undefined,
        status,
        source: source || undefined,
        provider: provider || undefined,
        compliance: compliance || undefined,
        category: category || undefined,
        subscription_id: subscription || undefined,
        rule_id: rule || undefined,
        close_reason: reason === "removed" ? "resource_removed" : undefined,
        sort: sorted.sort.key,
        dir: sorted.sort.dir,
      }),
    [severity, status, source, provider, compliance, category, subscription, rule, reason, sorted.sort.key, sorted.sort.dir],
  );
  const STATUS_OPTS = [{ value: "open", label: "Open" }, { value: "resolved", label: "Fixed" }, { value: "suppressed", label: "Snoozed" }, { value: "all", label: "All" }];
  const clearAll = () => {
    setSeverity("");
    setStatus("open");
    setSource("");
    setProvider("");
    setCompliance("");
    setCategory("");
    setSubscription("");
    setRule("");
    setReason("");
  };
  const chips: FilterChip[] = [
    severity && { label: "Severity", value: severity, onRemove: () => setSeverity("") },
    status !== "open" && { label: "Status", value: STATUS_OPTS.find((o) => o.value === status)?.label ?? status, onRemove: () => setStatus("open") },
    reason && { label: "Reason", value: "Resource removed", onRemove: () => setReason("") },
    provider && { label: "Cloud", value: PROVIDER_LABEL[provider] ?? provider, onRemove: () => setProvider("") },
    source && { label: "Source", value: source, onRemove: () => setSource("") },
    compliance && { label: "Framework", value: compliance, onRemove: () => setCompliance("") },
    category && { label: "Category", value: category, onRemove: () => setCategory("") },
    subscription && { label: "Account", value: subscription, onRemove: () => setSubscription("") },
    rule && { label: "Rule", value: rule, onRemove: () => setRule("") },
  ].filter((c): c is FilterChip => !!c);
  const filtered = chips.some((c) => c.label !== "Status");

  async function setFindingStatus(f: Finding, s: Finding["status"]) {
    try {
      await api.updateFinding(f.id, s);
      setActionError(null);
      reload();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    }
  }

  // Old deep links (notifications): /findings?finding=<id> now opens the finding's own page.
  if (linked) return <Navigate to={`/findings/${encodeURIComponent(linked)}`} replace />;

  return (
    <div>
      <PageHeader
        title="Cloud issues"
        info={PAGE_INFO.cloudIssues}
        actions={
          <Link to="/attack-paths" className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">
            Attack paths
          </Link>
        }
        subtitle="Settings in your cloud accounts that put you at risk."
      />
      <ErrorNote error={actionError} />
      <Card>
        <FilterBar
          count={data ? `${data.length} ${data.length === 1 ? "issue" : "issues"}` : undefined}
          moreActive={[reason, provider, source].filter(Boolean).length}
          more={
            <>
              <FilterSelect
                label="Reason"
                value={reason}
                onChange={(v) => {
                  setReason(v);
                  if (v && status === "open") setStatus("resolved");
                }}
                options={[{ value: "", label: "Any" }, { value: "removed", label: "Resource removed" }]}
              />
              <FilterSelect label="Cloud" value={provider} onChange={setProvider} options={[{ value: "", label: "All" }, ...["azure", "aws", "gcp"].map((p) => ({ value: p, label: PROVIDER_LABEL[p] }))]} />
              <FilterSelect label="Source" value={source} onChange={setSource} options={[{ value: "", label: "All" }, ...(platformAdmin ? [{ value: "simulated", label: "Demo data" }] : []), { value: "azure", label: "Azure" }, { value: "aws", label: "AWS" }, { value: "gcp", label: "Google Cloud" }]} />
            </>
          }
        >
          <Segments label="Status" value={status} onChange={setStatus} options={STATUS_OPTS} />
          <FilterSelect label="Severity" value={severity} onChange={setSeverity} options={["", "critical", "high", "medium", "low"]} />
          <FilterSearch value={compliance} onChange={setCompliance} placeholder="Framework, e.g. CIS AWS 2.1" label="Filter by compliance framework" />
        </FilterBar>
        <FilterChips chips={chips} onClearAll={clearAll} />
          <Table
            tableId="findings"
            head={[
              { label: "Severity", sort: "severity", w: 110 },
              { label: "Issue", sort: "title", w: 360 },
              { label: "Resource", sort: "resource", w: 260 },
              { label: "Compliance", w: 170 },
              { label: "Status", sort: "status", w: 120 },
              { label: "First seen", sort: "first_seen", w: 110 },
              { label: "Details", srOnly: true },
            ]}
            sort={sorted.sort}
            onSort={sorted.onSort}
            loading={loading}
            rowCount={data?.length ?? 0}
            noun="issues"
            pageSize={50}
            filtered={filtered}
            onClearFilters={clearAll}
            error={data ? null : error}
            onRetry={reload}
            empty={
              <Empty icon={ShieldCheck} title={status === "open" && !severity && !provider && !source && !compliance && !category && !subscription && !rule && !reason ? "No open findings" : "No findings match these filters"}>
                {status === "open" ? "Nothing to fix here right now. Run a scan under Settings > Connections to re-check." : "Try another status or clear a filter."}
              </Empty>
            }
          >
            {data?.map((f) => (
              <Fragment key={f.id}>
                <tr className="cursor-pointer hover:bg-surface-2" onClick={() => setExpanded(expanded === f.id ? null : f.id)}>
                  <td className="px-3 py-2">
                    <Pill tone={SEV_TONE[f.severity] ?? "neutral"}>{f.severity[0].toUpperCase() + f.severity.slice(1)}</Pill>
                  </td>
                  <td className="px-3 py-2">
                    <div className="min-w-0" onClick={(e) => e.stopPropagation()}>
                      <Link to={`/findings/${f.id}`} title={f.title} className="block overflow-hidden text-ellipsis whitespace-nowrap font-semibold text-ink hover:text-accent hover:underline">
                        {f.title}
                      </Link>
                      <span className="block truncate font-mono text-xs text-ink-3">{f.rule_id}</span>
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <NameCell name={f.asset_name ?? ""} sub={TYPE_LABEL[f.asset_type ?? ""] ?? f.asset_type} onOpen={() => setAsset(f.asset_id)} />
                  </td>
                  <td className="px-3 py-2">
                    <PillRow>
                      {f.compliance.slice(0, 2).map((c) => (
                        <Pill key={c} title={c}>{c.length > 14 ? `${c.slice(0, 13)}…` : c}</Pill>
                      ))}
                      {f.compliance.length > 2 && <Pill title={f.compliance.slice(2).join(", ")}>+{f.compliance.length - 2}</Pill>}
                    </PillRow>
                  </td>
                  <td className="px-3 py-2">
                    <PillRow>
                      {f.status === "resolved" && f.close_reason === "resource_removed" ? (
                        <Pill title="Closed because the cloud resource no longer exists">Removed</Pill>
                      ) : (
                        <Pill tone={f.status === "open" ? "high" : f.status === "resolved" ? "good" : "neutral"}>{statusLabel(f.status)}</Pill>
                      )}
                    </PillRow>
                  </td>
                  <td className="px-3 py-2">
                    <TextCell muted>{fmtAgo(f.first_seen)}</TextCell>
                  </td>
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
                      <Link to={`/findings/${f.id}`} className="mt-2 inline-flex items-center gap-0.5 text-xs font-medium text-accent hover:underline">
                        Open full details, affected resources and history
                        <ChevronRight aria-hidden className="h-3.5 w-3.5" />
                      </Link>
                      {canTriage ? (
                      <div className="mt-3 flex gap-2">
                        {f.status !== "suppressed" && <Button onClick={() => setFindingStatus(f, "suppressed")}>Snooze</Button>}
                        {f.status !== "resolved" && <Button onClick={() => setFindingStatus(f, "resolved")}>Mark as fixed</Button>}
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
      </Card>
      <AssetDrawer assetId={asset} onClose={() => setAsset(null)} onNavigate={setAsset} />
    </div>
  );
}
