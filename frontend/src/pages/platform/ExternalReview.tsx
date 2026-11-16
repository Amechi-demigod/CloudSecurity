import { useState } from "react";
import { errMsg, inputCls } from "../../lib/externalUi";
import { Button, Card, Empty, ErrorNote, PageHeader, Tag } from "../../components/ui";
import { externalApi } from "../../externalApi";
import { fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";

/** Platform owners: IP / range approvals and finding disputes of all organisations. Every decision needs a note and is audit logged. */
export default function ExternalReview() {
  const approvals = useApi(externalApi.platformApprovals, []);
  const disputes = useApi(externalApi.platformDisputes, []);
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [err, setErr] = useState<string | null>(null);

  async function decide(id: string, approve: boolean, kind: "approval" | "dispute") {
    setErr(null);
    try {
      if (kind === "approval") await externalApi.decideApproval(id, approve, notes[id] ?? "");
      else await externalApi.decideDispute(id, approve, notes[id] ?? "");
      approvals.reload();
      disputes.reload();
    } catch (e) {
      setErr(errMsg(e));
    }
  }
  const noteBox = (id: string) => (
    <input aria-label="Decision note" className={inputCls} placeholder="Note (required)" value={notes[id] ?? ""} onChange={(e) => setNotes({ ...notes, [id]: e.target.value })} />
  );
  return (
    <div className="space-y-4">
      <PageHeader title="Attack surface review" subtitle="Approve scanning of IP addresses a customer cannot prove another way, and review finding disputes." />
      <ErrorNote error={err ?? approvals.error ?? disputes.error} />
      <Card title="IP and range approvals">
        {approvals.data?.length === 0 ? <Empty title="Nothing waiting">No pending approval requests.</Empty> : (
          <ul className="divide-y divide-line">
            {approvals.data?.map((a) => (
              <li key={a.id} className="space-y-2 p-4 text-sm">
                <div><span className="font-mono">{a.value}</span> <Tag>{a.organization}</Tag> <span className="text-ink-3">requested by {a.attested_by}</span></div>
                <p className="text-ink-2">&ldquo;{a.attestation}&rdquo;</p>
                {noteBox(a.id)}
                <div className="flex gap-2"><Button variant="primary" onClick={() => void decide(a.id, true, "approval")}>Approve</Button><Button variant="danger" onClick={() => void decide(a.id, false, "approval")}>Reject</Button></div>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title="Finding disputes">
        {disputes.data?.length === 0 ? <Empty title="Nothing waiting">No pending disputes.</Empty> : (
          <ul className="divide-y divide-line">
            {disputes.data?.map((d) => (
              <li key={d.id} className="space-y-2 p-4 text-sm">
                <div><strong>{d.ref}</strong> {d.title} <Tag>{d.organization}</Tag> <Tag tone="accent">{d.kind.replace("_", " ")}</Tag> <span className="text-ink-3">{d.host} · CVSS {d.cvss} · {fmtTime(d.submitted_at)} · {d.submitted_by}</span></div>
                {d.fail_reason && <p className="text-xs text-ink-3">Fails the pre-ASV scan because: {d.fail_reason}</p>}
                <p className="text-ink-2">{d.reason}</p>
                {noteBox(d.id)}
                <div className="flex gap-2"><Button variant="primary" onClick={() => void decide(d.id, true, "dispute")}>Accept</Button><Button variant="danger" onClick={() => void decide(d.id, false, "dispute")}>Reject</Button></div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
