import { useState } from "react";
import { externalApi, type ExtOverview } from "../externalApi";
import { errMsg, inputCls } from "../lib/externalUi";
import { fmtTime } from "../lib/format";
import { Button, ErrorNote, Modal, Tag } from "./ui";

/** One small line, shown once per attack-surface page. The full explanation is in the PDF report and the page's info tip. */
export function NotAsvBanner() {
  return (
    <p role="note" className="text-xs text-ink-3">
      A readiness check, not an official PCI ASV report.
    </p>
  );
}

/** The result in plain words (the API's own label is not used, so the wording stays the same everywhere). */
export function ResultBadge({ result }: { result: "pass" | "fail" | null | string; label?: string }) {
  if (result !== "pass" && result !== "fail") return <Tag>Not scanned yet</Tag>;
  return <Tag tone={result === "pass" ? "good" : "critical"}>{result === "pass" ? "Likely to pass" : "Likely to fail a PCI scan"}</Tag>;
}

export function StatusTag({ status }: { status: string }) {
  const tone = status === "open" ? "warn" : status === "resolved" ? "good" : status === "disputed" ? "accent" : "default";
  return <Tag tone={tone as "warn" | "good" | "accent" | "default"}>{status === "accepted" ? "accepted risk" : status}</Tag>;
}

/** Confirm what is in scope. Needed once, before the first report; the text appears in the report (Part 3c). */
export function ScopeModal({ open, onClose, scope, canEdit, onSaved }: {
  open: boolean;
  onClose: () => void;
  scope: ExtOverview["scope"];
  canEdit: boolean;
  onSaved: () => void;
}) {
  const [text, setText] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function save(confirm: boolean) {
    setBusy(true);
    setErr(null);
    try {
      await externalApi.setScope(text ?? scope.text, confirm);
      setText(null);
      onSaved();
      if (confirm) onClose();
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal open={open} onClose={onClose} title="Confirm what's in scope">
      <div className="space-y-2">
        <p className="text-sm text-ink-2">List your in-scope internet-facing systems. It appears in the report (Part 3c) and must be confirmed before a report can be generated.</p>
        <textarea aria-label="Systems in scope" rows={5} className={inputCls} disabled={!canEdit} value={text ?? scope.text} onChange={(e) => setText(e.target.value)} />
        {scope.confirmed_at ? <p className="text-xs text-ink-3">Confirmed by {scope.confirmed_by} on {fmtTime(scope.confirmed_at)}.</p> : <p className="text-xs text-sev-high">Not confirmed yet.</p>}
        <ErrorNote error={err} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Close</Button>
          {canEdit && <Button disabled={busy || text === null} onClick={() => void save(false)}>Save draft</Button>}
          {canEdit && <Button variant="primary" disabled={busy} onClick={() => void save(true)}>Confirm scope</Button>}
        </div>
      </div>
    </Modal>
  );
}

/** Fix-by text from the API's days_left / overdue_days (never from the due date: it lies in the future). */
export function FixBy({ due, daysLeft, overdueDays }: { due: string | null; daysLeft: number | null; overdueDays: number | null }) {
  if (!due) return <span className="text-ink-3">-</span>;
  if (overdueDays) return <span className="font-medium text-sev-critical">Overdue {overdueDays} d</span>;
  if (!daysLeft) return <span className="text-ink-2">Due today</span>;
  return <span className="text-ink-2">In {daysLeft} {daysLeft === 1 ? "day" : "days"}</span>;
}
