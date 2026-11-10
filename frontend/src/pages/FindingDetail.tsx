import { FileDown } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type Finding } from "../api";
import { useAuth } from "../auth/context";
import AssetDrawer from "../components/AssetDrawer";
import { CodeBlock, Tabs } from "../components/FixTabs";
import { Breadcrumbs, Button, Card, Empty, ErrorNote, SeverityBadge, Tag } from "../components/ui";
import { SEV_COLOR, TYPE_LABEL, fmtTime } from "../lib/format";
import { useApi } from "../lib/useApi";

const STATUS_TONE = { open: "warn", resolved: "good", suppressed: "default" } as const;
const CONSOLE_LABEL: Record<string, string> = { azure: "Azure portal", aws: "AWS console", gcp: "Google Cloud console" };
const SECRET_KEY = /secret|password|token|key/i;

/** Evidence as readable `key = value` lines; anything that looks like a secret is masked. */
function evidenceLines(ev: Record<string, unknown>, prefix = ""): string[] {
  const out: string[] = [];
  for (const [k, v] of Object.entries(ev)) {
    const path = prefix ? `${prefix}.${k}` : k;
    if (SECRET_KEY.test(k)) out.push(`${path} = ********`);
    else if (v && typeof v === "object" && !Array.isArray(v)) out.push(...evidenceLines(v as Record<string, unknown>, path));
    else if (Array.isArray(v)) out.push(`${path} = ${v.map((x) => (typeof x === "object" ? JSON.stringify(x) : String(x))).join(", ")}`);
    else out.push(`${path} = ${String(v)}`);
  }
  return out;
}

function Cell({ label, children, tone }: { label: string; children: ReactNode; tone?: string }) {
  return (
    <div className="min-w-0 bg-surface-1 p-3">
      <dt className="text-[11px] font-medium uppercase tracking-wide text-ink-3">{label}</dt>
      <dd className="mt-1 break-words text-sm font-medium text-ink" style={tone ? { color: tone } : undefined}>
        {children}
      </dd>
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

function Chip({ children, tone }: { children: ReactNode; tone: "critical" | "warn" }) {
  return <Tag tone={tone}>{children}</Tag>;
}

/** Compact list used in the narrow right column. */
function MiniList({ rows, show }: { rows: Finding[]; show: "resource" | "finding" }) {
  return (
    <ul className="divide-y divide-line">
      {rows.slice(0, 8).map((f) => (
        <li key={f.id} className="flex items-start gap-2 py-2">
          <SeverityBadge severity={f.severity} />
          <div className="min-w-0 text-sm">
            <Link to={`/findings/${f.id}`} className="break-words hover:text-accent hover:underline">
              {show === "resource" ? f.asset_name : f.title}
            </Link>
            <div className="text-[11px] text-ink-3">{show === "resource" ? TYPE_LABEL[f.asset_type ?? ""] ?? f.asset_type : f.rule_id}</div>
          </div>
        </li>
      ))}
      {rows.length > 8 && <li className="py-2 text-xs text-ink-3">and {rows.length - 8} more</li>}
    </ul>
  );
}

function Steps({ items }: { items: string[] }) {
  return (
    <ol className="list-decimal space-y-1.5 pl-5 text-sm leading-relaxed text-ink-2 marker:text-ink-3">
      {items.map((s, i) => (
        <li key={i}>{s}</li>
      ))}
    </ol>
  );
}

export default function FindingDetail() {
  const { id = "" } = useParams();
  const canTriage = useAuth().can("analyst");
  const navigate = useNavigate();
  const [asset, setAsset] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const { data: f, error, reload } = useApi(() => api.finding(id), [id]);
  const sameRule = useApi(() => (f ? api.findings({ rule_id: f.rule_id, status: "all" }) : Promise.resolve(null)), [f?.rule_id]);
  const sameAsset = useApi(() => (f ? api.findings({ asset_id: f.asset_id }) : Promise.resolve(null)), [f?.asset_id]);

  if (!f) return <ErrorNote error={error} />;
  const g = f.guidance;
  const a = f.asset;
  const elsewhere = (sameRule.data ?? []).filter((x) => x.id !== f.id);
  const onAsset = (sameAsset.data ?? []).filter((x) => x.id !== f.id);
  const sevColor = SEV_COLOR[f.severity] ?? SEV_COLOR.info;
  const account = a?.subscription_name || a?.subscription_id || null;
  const ctx = f.context;
  const why: ReactNode[] = [];
  if (ctx.internet_exposed) why.push(<li key="net">The resource is reachable from the internet, so the weakness can be attacked from outside.</li>);
  if (ctx.sensitive_data) why.push(<li key="data">It holds or processes sensitive data, so a compromise has a larger business impact.</li>);
  for (const p of ctx.attack_paths)
    why.push(
      <li key={p.id}>
        It sits on an attack path:{" "}
        <Link to="/attack-paths" className="text-accent hover:underline">
          {p.title}
        </Link>{" "}
        ({p.severity}).
      </li>,
    );

  let due: ReactNode = "No SLA";
  let dueTone: string | undefined;
  if (f.status === "resolved") due = "Resolved";
  else if (f.sla_due) {
    if (f.overdue_days != null) {
      due = `Overdue by ${f.overdue_days} day${f.overdue_days === 1 ? "" : "s"}`;
      dueTone = "var(--color-sev-critical)";
    } else due = `${new Date(f.sla_due).toLocaleDateString()} (${f.sla_days} day SLA)`;
  }

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

  async function exportReport() {
    setExporting(true);
    try {
      const { blob, filename } = await api.findingReportPdf(f!.id);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setActionError(null);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setExporting(false);
    }
  }

  const evidence = evidenceLines(f.evidence ?? {});
  const consoleLabel = g?.labels?.console ?? CONSOLE_LABEL[a?.provider ?? ""] ?? "Console";
  const isNetwork = a?.source === "network";
  const openAsset = (assetId: string) => (isNetwork ? navigate(`/network-devices/${assetId.replace(/^netdev-/, "")}`) : setAsset(assetId));

  return (
    <div>
      <Breadcrumbs items={[{ label: "Posture findings", to: "/findings" }, { label: f.title }]} />

      <header className="mb-5">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={f.severity} />
          <Tag tone={STATUS_TONE[f.status]}>{f.status}</Tag>
          {ctx.internet_exposed && <Chip tone="critical">Internet exposed</Chip>}
          {ctx.sensitive_data && <Chip tone="warn">Holds sensitive data</Chip>}
        </div>
        <div className="mt-2 flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h1 className="text-xl font-semibold tracking-tight">{f.title}</h1>
            <p className="mt-1 break-words text-sm text-ink-2">
              <span className="font-mono text-xs">{f.rule_id}</span>
              {" · "}
              <button type="button" className="text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent" onClick={() => openAsset(f.asset_id)}>
                {f.asset_name ?? f.asset_id}
              </button>
              {" · "}
              {TYPE_LABEL[f.asset_type ?? ""] ?? f.asset_type ?? "resource"}
              {account && ` · ${account}`}
              {a?.region && ` · ${a.region}`}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {canTriage && (
              <Button onClick={exportReport} disabled={exporting} title="Download this finding as a PDF">
                <span className="inline-flex items-center gap-1.5">
                  <FileDown aria-hidden className="h-4 w-4" />
                  {exporting ? "Preparing..." : "Export report (PDF)"}
                </span>
              </Button>
            )}
            {canTriage && f.status !== "resolved" && (
              <Button variant="primary" onClick={() => setStatus("resolved")}>
                Resolve
              </Button>
            )}
            {canTriage && f.status !== "suppressed" && <Button onClick={() => setStatus("suppressed")}>Suppress</Button>}
            {canTriage && f.status !== "open" && <Button onClick={() => setStatus("open")}>Reopen</Button>}
          </div>
        </div>
      </header>
      <ErrorNote error={error ?? actionError} />

      <dl className="mb-5 grid grid-cols-1 gap-px overflow-hidden rounded-xl border border-line bg-line sm:grid-cols-2 lg:grid-cols-4">
        <Cell label="Severity" tone={sevColor}>
          <span className="capitalize">{f.severity}</span>
        </Cell>
        <Cell label="Risk score">
          {f.risk_score != null ? (
            <>
              {f.risk_score.toFixed(1)} <span className="font-normal text-ink-3">/ 10 CVSS-style</span>
            </>
          ) : (
            "-"
          )}
        </Cell>
        <Cell label="Weakness">{g ? `${g.cwe.id} ${g.cwe.name}` : "-"}</Cell>
        <Cell label="MITRE ATT&CK">{g && g.attack.length ? g.attack.map((t) => `${t.id} ${t.name}`).join(", ") : "-"}</Cell>
        <Cell label="Affected resource">
          <button type="button" className="text-left text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent" onClick={() => openAsset(f.asset_id)}>
            {f.asset_name ?? f.asset_id}
          </button>
        </Cell>
        <Cell label="Account">{account ?? "-"}</Cell>
        <Cell label="First seen">
          {fmtTime(f.first_seen)} <span className="font-normal text-ink-3">({f.days_open} days open)</span>
        </Cell>
        <Cell label="Fix due" tone={dueTone}>
          {due}
        </Cell>
      </dl>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <div className="min-w-0 space-y-4">
          <Card title="Description">
            <p className="text-sm leading-relaxed text-ink-2">{f.description || "No description."}</p>
          </Card>

          {g && (
            <Card title="Business impact">
              <ul className="space-y-2 text-sm leading-relaxed text-ink-2">
                {g.impact.map((i) => (
                  <li key={i.title} className="flex gap-2">
                    <span aria-hidden className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-ink-3" />
                    <span>
                      <strong className="font-semibold text-ink">{i.title}.</strong> {i.text}
                    </span>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          <Card title="Evidence">
            <p className="mb-2 text-xs text-ink-3">
              Collected read-only from {f.source} at {fmtTime(f.last_seen)}
            </p>
            {evidence.length === 0 ? <p className="text-sm text-ink-3">The rule recorded no evidence values.</p> : <CodeBlock code={evidence.join("\n")} label="evidence" />}
          </Card>

          {g && (
            <Card title="How to verify">
              <p className="mb-2 text-xs text-ink-3">Read-only steps: nothing below changes the resource.</p>
              <Steps items={g.verify_steps} />
              <div className="mt-3">
                <CodeBlock code={g.verify_cli} label="verification command" />
              </div>
            </Card>
          )}

          <Card title="How to fix">
            {g ? (
              <>
                <Tabs
                  label="Fix instructions"
                  tabs={[
                    { id: "console", label: consoleLabel, content: <Steps items={g.fix_console} /> },
                    { id: "cli", label: "CLI", content: <CodeBlock code={g.fix_cli} label="CLI fix" /> },
                    { id: "terraform", label: g.labels?.template ?? "Terraform", content: <CodeBlock code={g.fix_terraform} label="Terraform fix" /> },
                  ]}
                />
                <div className="mt-4 rounded-lg border border-accent/40 bg-accent/10 p-3 text-sm text-ink">
                  <strong className="font-semibold">Prevent it coming back.</strong> {g.prevent}
                </div>
                <p className="mt-3 text-xs text-ink-3">Guidance only: review each command before running it. The platform never changes your cloud.</p>
              </>
            ) : (
              <p className="text-sm leading-relaxed text-ink">{f.remediation || "No remediation guidance for this rule."}</p>
            )}
          </Card>

          <Card title="Compliance mapping">
            {f.compliance.length === 0 ? (
              <p className="text-sm text-ink-3">Not mapped to a compliance control.</p>
            ) : (
              <ul className="flex flex-wrap gap-1.5">
                {f.compliance.map((c) => (
                  <li key={c}>
                    <Link
                      to={`/findings?${new URLSearchParams({ compliance: c })}`}
                      title={`Open findings mapped to ${c}`}
                      className="inline-block rounded border border-line px-2 py-0.5 text-xs text-ink-2 transition hover:border-accent/60 hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      {c}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          {g && (
            <Card title="References">
              <ul className="space-y-1.5 text-sm">
                {g.references.map((r) => (
                  <li key={r.url} className="break-words">
                    <a href={r.url} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
                      {r.title}
                    </a>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>

        <div className="min-w-0 space-y-4">
          <Card title="Resource facts">
            <dl>
              <Fact label="Name">
                <button type="button" className="font-medium text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent" onClick={() => openAsset(f.asset_id)}>
                  {f.asset_name ?? f.asset_id}
                </button>
              </Fact>
              <Fact label="Type">{TYPE_LABEL[f.asset_type ?? ""] ?? f.asset_type ?? "-"}</Fact>
              {a?.resource_group && <Fact label="Resource group">{a.resource_group}</Fact>}
              <Fact label="Account">{account ?? "-"}</Fact>
              <Fact label="Region">{a?.region ?? "-"}</Fact>
              <Fact label="Connector">{a?.provider ? `${a.provider} (${a.source})` : f.source}</Fact>
              <Fact label="Tags">
                {a && Object.keys(a.tags).length > 0 ? (
                  <span className="flex flex-wrap justify-end gap-1">
                    {Object.entries(a.tags).map(([k, v]) => (
                      <Tag key={k}>{`${k}=${v}`}</Tag>
                    ))}
                  </span>
                ) : (
                  "None"
                )}
              </Fact>
            </dl>
          </Card>

          {why.length > 0 && (
            <Card title={`Why this is ${f.severity} here`}>
              <ul className="list-disc space-y-1.5 pl-5 text-sm leading-relaxed text-ink-2 marker:text-ink-3">{why}</ul>
            </Card>
          )}

          <Card title={`Same issue elsewhere${sameRule.data ? ` (${elsewhere.length})` : ""}`}>
            {sameRule.data && elsewhere.length === 0 ? <Empty>No other resource has this misconfiguration.</Empty> : <MiniList rows={elsewhere} show="resource" />}
          </Card>

          <Card title={`Other findings on this resource${sameAsset.data ? ` (${onAsset.length})` : ""}`}>
            {sameAsset.data && onAsset.length === 0 ? <Empty>No other open findings on this resource.</Empty> : <MiniList rows={onAsset} show="finding" />}
          </Card>

          <Card title="Timeline">
            <ol className="space-y-2 border-l border-line pl-4 text-sm">
              <li>
                <div className="text-ink">First seen</div>
                <div className="text-xs text-ink-3">{fmtTime(f.first_seen)}</div>
              </li>
              <li>
                <div className="text-ink">Last seen</div>
                <div className="text-xs text-ink-3">{fmtTime(f.last_seen)}</div>
              </li>
              {f.resolved_at && (
                <li>
                  <div className="text-ink">Resolved</div>
                  <div className="text-xs text-ink-3">{fmtTime(f.resolved_at)}</div>
                </li>
              )}
              {f.status === "suppressed" && (
                <li>
                  <div className="text-ink">Suppressed</div>
                  <div className="text-xs text-ink-3">The time of suppression is not recorded.</div>
                </li>
              )}
            </ol>
            <p className="mt-3 text-xs text-ink-3">A resolved finding reopens on the next scan if the misconfiguration is still there. Suppress it to accept the risk.</p>
          </Card>
        </div>
      </div>

      <AssetDrawer assetId={asset} onClose={() => setAsset(null)} onNavigate={setAsset} />
    </div>
  );
}
