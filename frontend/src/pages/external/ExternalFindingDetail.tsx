import { useState } from "react";
import { useParams } from "react-router-dom";
import { useAuth } from "../../auth/context";
import { CodeBlock, Tabs } from "../../components/FixTabs";
import { NotAsvBanner, StatusTag } from "../../components/external";
import { errMsg, inputCls } from "../../lib/externalUi";
import { Breadcrumbs, Button, Card, ErrorNote, Modal, PageHeader, SeverityBadge, Tag } from "../../components/ui";
import { externalApi, type ExtDispute } from "../../externalApi";
import { fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";

export default function ExternalFindingDetail() {
  const { id = "" } = useParams();
  const { can } = useAuth();
  const { data: f, error, reload } = useApi(() => externalApi.finding(id), [id]);
  const [err, setErr] = useState<string | null>(null);
  const [modal, setModal] = useState<"dispute" | "accept" | null>(null);
  const [reason, setReason] = useState("");
  const [kind, setKind] = useState<ExtDispute["kind"]>("false_positive");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  async function run(fn: () => Promise<unknown>, done?: string) {
    setBusy(true);
    setErr(null);
    try {
      await fn();
      if (done) setNote(done);
      setModal(null);
      setReason("");
      reload();
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  if (!f) return <ErrorNote error={error} />;
  const analyst = can("analyst");
  const d = f.detail;
  const fixTabs = Object.entries(d.fix).map(([label, text]) => ({ id: label, label, content: <CodeBlock code={text} label={`${label} fix`} /> }));
  return (
    <div className="space-y-4">
      <Breadcrumbs items={[{ label: "Attack surface", to: "/attack-surface" }, { label: "Findings", to: "/attack-surface/findings" }, { label: f.ref }]} />
      <PageHeader
        title={`${f.ref}: ${f.title}`}
        actions={
          <>
            <a className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line" href={externalApi.findingPdfUrl(f.id)}>Export PDF</a>
            {analyst && f.status !== "resolved" && (
              <Button disabled={busy} onClick={() => void run(async () => { await externalApi.retest(f.id); }, "Re-test started: this host is being scanned again. Refresh in a minute.")}>Re-test now</Button>
            )}
          </>
        }
      />
      <NotAsvBanner />
      <ErrorNote error={err} />
      {note && <p role="status" className="text-sm text-ink-2">{note}</p>}
      <Card>
        <dl className="grid gap-x-6 gap-y-2 p-4 text-sm sm:grid-cols-2 lg:grid-cols-3">
          <div><dt className="text-xs uppercase text-ink-3">Severity</dt><dd><SeverityBadge severity={f.severity} /></dd></div>
          <div><dt className="text-xs uppercase text-ink-3">CVSS 3.1</dt><dd>{f.cvss ? f.cvss.toFixed(1) : "-"} <code className="text-xs text-ink-3">{f.vector}</code></dd></div>
          <div><dt className="text-xs uppercase text-ink-3">CWE</dt><dd>{f.cwe ?? "-"}</dd></div>
          <div><dt className="text-xs uppercase text-ink-3">Affected</dt><dd className="font-mono text-xs">{f.host}{f.ip && f.ip !== f.host ? ` (${f.ip})` : ""}{f.port ? `:${f.port}` : ""}</dd></div>
          <div><dt className="text-xs uppercase text-ink-3">URL</dt><dd className="break-all font-mono text-xs">{f.url ?? "-"}</dd></div>
          <div><dt className="text-xs uppercase text-ink-3">Status</dt><dd><StatusTag status={f.status} /></dd></div>
          <div><dt className="text-xs uppercase text-ink-3">First seen / last seen</dt><dd>{fmtTime(f.first_seen)} / {fmtTime(f.last_seen)}</dd></div>
          <div><dt className="text-xs uppercase text-ink-3">Fix by</dt><dd>{f.fix_due ? `${fmtTime(f.fix_due)} (${f.sla_basis})${f.overdue_days ? `, overdue ${f.overdue_days} days` : ""}` : "-"}</dd></div>
          <div><dt className="text-xs uppercase text-ink-3">Pre-ASV</dt><dd>{f.fail_reason ? <Tag tone="critical">Fails: {f.fail_reason}</Tag> : <Tag tone="good">Does not fail</Tag>}</dd></div>
        </dl>
        {f.status_note && <p className="border-t border-line px-4 py-2 text-sm text-ink-2">{f.status_note}</p>}
      </Card>
      <Card title="Description"><p className="whitespace-pre-line p-4 text-sm text-ink-2">{d.description}</p></Card>
      <Card title="Business impact"><p className="p-4 text-sm text-ink-2">{d.impact}</p></Card>
      <Card title="Evidence (headers and metadata only, never file contents or secrets)"><div className="p-4"><CodeBlock code={JSON.stringify(f.evidence, null, 2)} label="evidence" /></div></Card>
      <Card title="Steps to reproduce"><ol className="list-decimal space-y-1 p-4 pl-8 text-sm text-ink-2">{d.steps.map((s, i) => <li key={i}>{s}</li>)}</ol></Card>
      <Card title="How to fix"><div className="p-4">{fixTabs.length > 0 && <Tabs tabs={fixTabs} label="Fix by server type" />}</div></Card>
      <Card title="Compliance mapping">
        <ul className="space-y-1 p-4 text-sm text-ink-2">{Object.entries(d.compliance).map(([fw, items]) => <li key={fw}><strong className="text-ink">{fw}:</strong> {items.join(", ")}</li>)}</ul>
      </Card>
      {d.references.length > 0 && <Card title="References"><ul className="space-y-1 p-4 text-sm">{d.references.map((r) => <li key={r}><a className="text-accent hover:underline" href={r} target="_blank" rel="noopener noreferrer">{r}</a></li>)}</ul></Card>}
      <Card title="Disputes and decisions">
        <div className="space-y-2 p-4 text-sm">
          {f.disputes.map((x) => (
            <div key={x.id} className="rounded border border-line p-2">
              <Tag tone={x.status === "accepted" ? "good" : x.status === "rejected" ? "critical" : "accent"}>{x.status}</Tag> {x.kind.replace("_", " ")} by {x.submitted_by} on {fmtTime(x.submitted_at)}
              <p className="mt-1 text-ink-2">{x.reason}</p>
              {x.review_note && <p className="mt-1 text-ink-3">Reviewed by {x.reviewed_by}: {x.review_note}</p>}
            </div>
          ))}
          {analyst && f.status !== "resolved" && (
            <div className="flex flex-wrap gap-2">
              <Button onClick={() => setModal("dispute")}>Dispute (false positive / compensating control)</Button>
              {f.status !== "accepted" && <Button onClick={() => setModal("accept")}>Accept risk</Button>}
              {(f.status === "accepted") && <Button onClick={() => void run(() => externalApi.reopen(f.id))}>Re-open</Button>}
            </div>
          )}
          <p className="text-xs text-ink-3">Accepting a risk records your decision but still counts in the pre-ASV result. A dispute that a platform owner accepts is listed as an exception and does not fail the report.</p>
        </div>
      </Card>
      <Modal open={modal === "dispute"} onClose={() => setModal(null)} title="Dispute this finding">
        <div className="space-y-3 text-sm">
          <label className="block">Type
            <select className={inputCls} value={kind} onChange={(e) => setKind(e.target.value as ExtDispute["kind"])}>
              <option value="false_positive">False positive</option><option value="compensating_control">Compensating control</option>
            </select>
          </label>
          <label className="block">Reason<textarea rows={4} className={inputCls} value={reason} onChange={(e) => setReason(e.target.value)} /></label>
          <div className="flex justify-end gap-2"><Button onClick={() => setModal(null)}>Cancel</Button>
            <Button variant="primary" disabled={busy || reason.trim().length < 10} onClick={() => void run(() => externalApi.dispute(f.id, kind, reason), "Dispute submitted for review.")}>Submit</Button></div>
        </div>
      </Modal>
      <Modal open={modal === "accept"} onClose={() => setModal(null)} title="Accept this risk">
        <div className="space-y-3 text-sm">
          <label className="block">Reason<textarea rows={3} className={inputCls} value={reason} onChange={(e) => setReason(e.target.value)} /></label>
          <div className="flex justify-end gap-2"><Button onClick={() => setModal(null)}>Cancel</Button>
            <Button variant="primary" disabled={busy || !reason.trim()} onClick={() => void run(() => externalApi.acceptRisk(f.id, reason))}>Accept risk</Button></div>
        </div>
      </Modal>
    </div>
  );
}
