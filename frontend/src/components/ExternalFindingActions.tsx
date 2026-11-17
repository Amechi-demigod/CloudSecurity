import { useState, type ReactNode } from "react";
import { externalApi, type ExtDispute } from "../externalApi";
import { errMsg, inputCls } from "../lib/externalUi";
import { Button, Modal } from "./ui";

type ModalKind = "dispute" | "accept";

/**
 * Analyst actions on one attack-surface finding (re-test, dispute, accept risk, re-open), shared by the
 * finding page and the findings list. `run` wraps any call with busy / error / note handling and calls
 * `onDone` afterwards; `modals` renders the Dispute and Accept risk dialogs for the finding `openFor` chose.
 */
export function useFindingActions(onDone: () => void) {
  const [target, setTarget] = useState<{ id: string; modal: ModalKind } | null>(null);
  const [reason, setReason] = useState("");
  const [kind, setKind] = useState<ExtDispute["kind"]>("false_positive");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  async function run(fn: () => Promise<unknown>, done?: string) {
    setBusy(true);
    setErr(null);
    try {
      await fn();
      if (done) setNote(done);
      setTarget(null);
      setReason("");
      onDone();
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  const close = () => setTarget(null);
  const modals: ReactNode = (
    <>
      <Modal open={target?.modal === "dispute"} onClose={close} title="Dispute this finding">
        <div className="space-y-3 text-sm">
          <label className="block">Type
            <select className={inputCls} value={kind} onChange={(e) => setKind(e.target.value as ExtDispute["kind"])}>
              <option value="false_positive">False positive</option><option value="compensating_control">Compensating control</option>
            </select>
          </label>
          <label className="block">Reason<textarea rows={4} className={inputCls} value={reason} onChange={(e) => setReason(e.target.value)} /></label>
          <div className="flex justify-end gap-2"><Button onClick={close}>Cancel</Button>
            <Button variant="primary" disabled={busy || reason.trim().length < 10} onClick={() => target && void run(() => externalApi.dispute(target.id, kind, reason), "Dispute submitted for review.")}>Submit</Button></div>
        </div>
      </Modal>
      <Modal open={target?.modal === "accept"} onClose={close} title="Accept this risk">
        <div className="space-y-3 text-sm">
          <label className="block">Reason<textarea rows={3} className={inputCls} value={reason} onChange={(e) => setReason(e.target.value)} /></label>
          <div className="flex justify-end gap-2"><Button onClick={close}>Cancel</Button>
            <Button variant="primary" disabled={busy || !reason.trim()} onClick={() => target && void run(() => externalApi.acceptRisk(target.id, reason))}>Accept risk</Button></div>
        </div>
      </Modal>
    </>
  );
  return { run, busy, err, note, setNote, modals, openFor: (id: string, modal: ModalKind) => setTarget({ id, modal }) };
}
