import { useEffect, useState } from "react";
import { useAuth } from "../auth/context";
import { CodeBlock } from "./FixTabs";
import { Button, ErrorNote, Modal, SeverityBadge, Tag } from "./ui";
import { reputationApi, type RepFinding, type RepGrade } from "../externalApi";
import { errMsg, inputCls } from "../lib/externalUi";
import { GRADE_WORD, gradeTone } from "../lib/reputation";
import { fmtTime } from "../lib/format";

const TONE_CLS = {
  good: "border-good bg-good/10",
  warn: "border-sev-medium bg-sev-medium/10",
  bad: "border-sev-high bg-sev-high/10",
  none: "border-line bg-surface-2",
};

/** Grade as a letter and a word, so colour is never the only cue. */
export function GradeBadge({ grade, big = false }: { grade: RepGrade | null; big?: boolean }) {
  const word = grade ? GRADE_WORD[grade] : "Not checked";
  return (
    <span
      className={`inline-flex items-center gap-2 rounded-lg border-2 text-ink ${TONE_CLS[gradeTone(grade)]} ${big ? "px-4 py-2" : "px-2 py-1"}`}
      aria-label={grade ? `Grade ${grade}, ${word}` : "Not checked yet"}
    >
      <span aria-hidden className={`font-bold leading-none ${big ? "text-5xl" : "text-xl"}`}>{grade ?? "-"}</span>
      <span aria-hidden className={`font-medium ${big ? "text-base" : "text-xs"}`}>{word}</span>
    </span>
  );
}

/** One finding opened from a domain page: what it means, how to fix it, evidence, accept risk / re-open. */
export function FindingModal({ finding, onClose, onChanged }: { finding: RepFinding | null; onClose: () => void; onChanged: () => void }) {
  const { can } = useAuth();
  const [full, setFull] = useState<RepFinding | null>(null);
  const [reason, setReason] = useState("");
  const [asking, setAsking] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const id = finding?.id ?? null;
  // load the full record (with evidence) when a finding is chosen
  useEffect(() => {
    setFull(null);
    setReason("");
    setAsking(false);
    setErr(null);
    if (!id) return;
    let live = true;
    reputationApi.finding(id).then((r) => live && setFull(r), (e) => live && setErr(errMsg(e)));
    return () => { live = false; };
  }, [id]);
  const f = full ?? finding;
  const analyst = can("analyst");
  const ours = f?.category === "lookalike" || f?.category === "certificate";

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setErr(null);
    try {
      await fn();
      setAsking(false);
      onChanged();
      onClose();
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={!!finding} onClose={onClose} title={f?.title ?? "Finding"} size="lg">
      {f && (
        <div className="space-y-4 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.severity} />
            <Tag tone={f.status === "open" ? "warn" : f.status === "accepted" ? "accent" : "good"}>{f.status === "open" ? "Open" : f.status === "accepted" ? "Accepted" : "Fixed"}</Tag>
            <span className="text-xs text-ink-3">{f.ref} · first seen {fmtTime(f.first_seen)}</span>
          </div>
          {f.description && <p className="text-ink-2">{f.description}</p>}
          {f.fix && (
            <div>
              <h3 className="mb-1 font-semibold text-ink">{ours ? "What to do" : "How to fix"}</h3>
              <p className="text-ink-2">{f.fix}</p>
            </div>
          )}
          {f.status === "accepted" && f.status_note && <p className="rounded border border-line bg-surface-2 p-2 text-ink-2">Accepted by {f.status_by}: {f.status_note}</p>}
          {full?.evidence && Object.keys(full.evidence).length > 0 && (
            <div>
              <h3 className="mb-1 font-semibold text-ink">What we saw</h3>
              <CodeBlock code={JSON.stringify(full.evidence, null, 2)} label="evidence" />
            </div>
          )}
          <ErrorNote error={err} />
          {analyst && f.status !== "resolved" && (
            <div className="border-t border-line pt-3">
              {f.status === "accepted" ? (
                <Button disabled={busy} onClick={() => void act(() => reputationApi.reopen(f.id))}>Re-open</Button>
              ) : asking ? (
                <div className="space-y-2">
                  <label htmlFor="rep-reason" className="block font-medium text-ink-2">{ours ? "Why is this one of yours or expected?" : "Why are you accepting this?"}</label>
                  <textarea id="rep-reason" rows={3} className={inputCls} value={reason} onChange={(e) => setReason(e.target.value)} />
                  <p className="text-xs text-ink-3">Your reason is saved in the audit log. The finding stops counting against the grade.</p>
                  <div className="flex gap-2">
                    <Button variant="primary" disabled={busy || !reason.trim()} onClick={() => void act(() => reputationApi.acceptRisk(f.id, reason))}>{ours ? "Mark as ours" : "Accept risk"}</Button>
                    <Button onClick={() => setAsking(false)}>Cancel</Button>
                  </div>
                </div>
              ) : (
                <Button onClick={() => setAsking(true)}>{ours ? "Mark as ours" : "Accept risk"}</Button>
              )}
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}
