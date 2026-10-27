import { ChevronRight } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type Finding } from "../api";
import { useAuth } from "../auth/context";
import AssetDrawer from "../components/AssetDrawer";
import { Breadcrumbs, Button, Card, Empty, ErrorNote, PageHeader, SeverityBadge, Table, Tag } from "../components/ui";
import { TYPE_LABEL, fmtAgo, fmtTime } from "../lib/format";
import { useApi } from "../lib/useApi";

const STATUS_TONE = { open: "warn", resolved: "good", suppressed: "default" } as const;

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex justify-between gap-4 py-1.5 text-sm">
      <dt className="text-ink-3">{label}</dt>
      <dd className="text-right text-ink">{children}</dd>
    </div>
  );
}

/** A compact list of related findings, each linking to its own detail page. */
function RelatedFindings({ rows, show }: { rows: Finding[]; show: "resource" | "finding" }) {
  const navigate = useNavigate();
  return (
    <Table head={["Severity", show === "resource" ? "Resource" : "Finding", "Status", "First seen", { label: "Open", srOnly: true }]}>
      {rows.map((f) => (
        <tr key={f.id} className="cursor-pointer hover:bg-surface-2" onClick={() => navigate(`/findings/${f.id}`)}>
          <td className="px-3 py-2">
            <SeverityBadge severity={f.severity} />
          </td>
          <td className="px-3 py-2">
            <Link to={`/findings/${f.id}`} className="hover:text-accent" onClick={(e) => e.stopPropagation()}>
              {show === "resource" ? f.asset_name : f.title}
            </Link>
            <div className="text-[11px] text-ink-3">{show === "resource" ? TYPE_LABEL[f.asset_type ?? ""] ?? f.asset_type : f.rule_id}</div>
          </td>
          <td className="px-3 py-2">
            <Tag tone={STATUS_TONE[f.status]}>{f.status}</Tag>
          </td>
          <td className="px-3 py-2 text-xs text-ink-2">{fmtAgo(f.first_seen)}</td>
          <td className="px-3 py-2 text-right">
            <ChevronRight aria-hidden className="ml-auto h-4 w-4 text-ink-3" />
          </td>
        </tr>
      ))}
    </Table>
  );
}

export default function FindingDetail() {
  const { id = "" } = useParams();
  const canTriage = useAuth().can("analyst");
  const [asset, setAsset] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const { data: f, error, reload } = useApi(() => api.finding(id), [id]);
  const sameRule = useApi(() => (f ? api.findings({ rule_id: f.rule_id, status: "all" }) : Promise.resolve(null)), [f?.rule_id]);
  const sameAsset = useApi(() => (f ? api.findings({ asset_id: f.asset_id }) : Promise.resolve(null)), [f?.asset_id]);

  if (!f) return <ErrorNote error={error} />;
  const elsewhere = (sameRule.data ?? []).filter((x) => x.id !== f.id);
  const onAsset = (sameAsset.data ?? []).filter((x) => x.id !== f.id);

  async function setStatus(s: Finding["status"]) {
    try {
      await api.updateFinding(f!.id, s);
      setActionError(null);
      reload();
      sameRule.reload();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div>
      <Breadcrumbs items={[{ label: "Posture findings", to: "/findings" }, { label: f.title }]} />
      <PageHeader
        title={f.title}
        subtitle={`${f.rule_id} · ${f.asset_name ?? f.asset_id}`}
        actions={
          <div className="flex items-center gap-2">
            <SeverityBadge severity={f.severity} />
            <Tag tone={STATUS_TONE[f.status]}>{f.status}</Tag>
          </div>
        }
      />
      <ErrorNote error={error ?? actionError} />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="space-y-4">
          <Card title="What is wrong">
            <p className="text-sm leading-relaxed text-ink-2">{f.description || "No description."}</p>
          </Card>
          <Card title="How to fix it">
            <p className="text-sm leading-relaxed text-ink">{f.remediation || "No remediation guidance for this rule."}</p>
          </Card>
          <Card title="Evidence">
            {Object.keys(f.evidence ?? {}).length === 0 ? (
              <p className="text-sm text-ink-3">The rule recorded no evidence values.</p>
            ) : (
              <pre className="max-h-80 overflow-auto rounded-lg bg-surface-2 p-3 font-mono text-xs leading-relaxed text-ink-2">
                {JSON.stringify(f.evidence, null, 2)}
              </pre>
            )}
          </Card>
        </div>

        <div className="space-y-4">
          <Card title="Resource">
            <dl>
              <Fact label="Name">
                <button className="font-medium text-accent hover:underline" onClick={() => setAsset(f.asset_id)}>
                  {f.asset_name ?? f.asset_id}
                </button>
              </Fact>
              <Fact label="Type">{TYPE_LABEL[f.asset_type ?? ""] ?? f.asset_type ?? "—"}</Fact>
              <Fact label="Source">{f.source}</Fact>
            </dl>
          </Card>
          <Card title="Timeline">
            <dl>
              <Fact label="First seen">{fmtTime(f.first_seen)}</Fact>
              <Fact label="Last seen">{fmtTime(f.last_seen)}</Fact>
              {f.resolved_at && <Fact label="Resolved">{fmtTime(f.resolved_at)}</Fact>}
            </dl>
          </Card>
          <Card title="Compliance">
            {f.compliance.length === 0 ? (
              <p className="text-sm text-ink-3">Not mapped to a compliance control.</p>
            ) : (
              <ul className="flex flex-wrap gap-1.5">
                {f.compliance.map((c) => (
                  <li key={c}>
                    <Link
                      to={`/findings?${new URLSearchParams({ compliance: c })}`}
                      title={`Open findings mapped to ${c}`}
                      className="inline-block rounded border border-line px-2 py-0.5 text-xs text-ink-2 transition hover:border-accent/60 hover:text-ink"
                    >
                      {c}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card title="Triage">
            {canTriage ? (
              <div className="flex flex-wrap gap-2">
                {f.status !== "resolved" && (
                  <Button variant="primary" onClick={() => setStatus("resolved")}>
                    Mark resolved
                  </Button>
                )}
                {f.status !== "suppressed" && <Button onClick={() => setStatus("suppressed")}>Suppress</Button>}
                {f.status !== "open" && <Button onClick={() => setStatus("open")}>Reopen</Button>}
              </div>
            ) : (
              <p className="text-sm text-ink-3">Read-only access: an analyst or admin can suppress or resolve findings.</p>
            )}
            <p className="mt-3 text-xs text-ink-3">
              A resolved finding reopens on the next scan if the misconfiguration is still there. Suppress it to accept the risk.
            </p>
          </Card>
        </div>
      </div>

      <Card title={`Same issue on other resources${sameRule.data ? ` (${elsewhere.length})` : ""}`} className="mt-4">
        {sameRule.data && elsewhere.length === 0 ? (
          <Empty>No other resource has this misconfiguration.</Empty>
        ) : (
          <RelatedFindings rows={elsewhere} show="resource" />
        )}
      </Card>
      <Card title={`Other open findings on ${f.asset_name ?? "this resource"}${sameAsset.data ? ` (${onAsset.length})` : ""}`} className="mt-4">
        {sameAsset.data && onAsset.length === 0 ? <Empty>No other open findings on this resource.</Empty> : <RelatedFindings rows={onAsset} show="finding" />}
      </Card>
      <AssetDrawer assetId={asset} onClose={() => setAsset(null)} onNavigate={setAsset} />
    </div>
  );
}
