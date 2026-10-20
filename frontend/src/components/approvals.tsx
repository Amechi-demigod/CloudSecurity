import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { ApiError, api, type Approval, type ApprovalSettings, type RiskLevel } from "../api";
import { useAuth } from "../auth/context";
import { fmtAgo, fmtTime } from "../lib/format";
import { Button, Empty, Field, Modal, Table, Tag } from "./ui";

const RISK_TONE: Record<RiskLevel, "good" | "warn" | "critical"> = { low: "good", medium: "warn", high: "critical" };

/** Risk pill (text label, never color alone). */
export function RiskTag({ risk }: { risk: RiskLevel }) {
  return <Tag tone={RISK_TONE[risk] ?? "default"}>{risk} risk</Tag>;
}

const STATUS_TONE: Record<Approval["status"], "default" | "warn" | "good" | "accent" | "critical"> = {
  pending: "accent",
  approved: "warn",
  executed: "good",
  rejected: "warn",
  cancelled: "default",
  expired: "default",
  failed: "critical",
};

export function ApprovalStatus({ approval: a }: { approval: Approval }) {
  return (
    <div>
      <Tag tone={STATUS_TONE[a.status] ?? "default"}>{a.status === "approved" ? "cooling off" : a.status}</Tag>
      <div className="mt-0.5 text-[11px] text-ink-3">
        {a.status === "approved" && a.execute_after && <>self-approved – runs at {fmtTime(a.execute_after)} unless cancelled</>}
        {a.status === "pending" && <>expires {fmtTime(a.expires_at)}</>}
        {a.status !== "pending" && a.status !== "approved" && a.decided_by_email && (
          <>
            {a.status === "cancelled" ? "cancelled" : "decided"} by {a.decided_by_email}
            {a.self_approved && " (self-approved)"}
            {a.decided_at && <> · {fmtAgo(a.decided_at)}</>}
          </>
        )}
        {a.decision_reason && <div>“{a.decision_reason}”</div>}
        {a.executed_at && <div>executed {fmtTime(a.executed_at)}</div>}
      </div>
    </div>
  );
}

function fmtParams(params: Record<string, unknown>): string {
  return Object.entries(params)
    .map(([k, v]) => `${k}=${typeof v === "object" && v !== null ? JSON.stringify(v) : String(v)}`)
    .join(" · ");
}

type Decision = "approve" | "reject" | "cancel";

const DECISION_LABEL: Record<Decision, string> = { approve: "Approve", reject: "Reject", cancel: "Cancel request" };

/** Approve / reject / cancel dialog for one approval request. */
export function DecisionDialog({
  approval: a,
  decision,
  settings,
  onClose,
  onDone,
}: {
  approval: Approval | null;
  decision: Decision;
  settings?: ApprovalSettings | null;
  onClose: () => void;
  onDone: () => void;
}) {
  const [reason, setReason] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function close() {
    setReason("");
    setConfirm("");
    setError(null);
    onClose();
  }

  const approving = decision === "approve";
  const isWipe = a?.action === "wipe_device";
  const needsName = approving && !!a && (isWipe || a.is_own_request);
  const nameOk = !needsName || (!!a && confirm.trim().toLowerCase() === a.hostname.toLowerCase());
  const reasonOk = approving || reason.trim().length >= 3;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!a) return;
    setBusy(true);
    setError(null);
    try {
      if (decision === "approve") {
        await api.approveApproval(a.id, { reason: reason.trim() || undefined, confirm_hostname: needsName ? confirm.trim() : undefined });
      } else if (decision === "reject") {
        await api.rejectApproval(a.id, reason.trim());
      } else {
        await api.cancelApproval(a.id, reason.trim());
      }
      onDone();
      close();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={!!a} onClose={close} title={a ? `${DECISION_LABEL[decision]}: ${a.hostname}` : ""}>
      {a && (
        <form className="space-y-3" onSubmit={submit}>
          <div className="rounded border border-line bg-surface-2 p-3 text-sm">
            <div className="font-medium">{a.summary}</div>
            <div className="mt-1 text-xs text-ink-3">
              Requested by {a.requested_by_email ?? "unknown"} {fmtAgo(a.requested_at)}: “{a.reason}”
            </div>
            {Object.keys(a.params).length > 0 && <div className="mt-1 break-words font-mono text-[11px] text-ink-2">{fmtParams(a.params)}</div>}
          </div>
          {approving && isWipe && (
            <div role="alert" className="rounded border border-sev-critical bg-sev-critical/15 px-3 py-2 text-sm">
              <strong className="text-sev-critical">This erases {a.hostname}.</strong> All data and apps are removed and Windows is reset. It cannot be
              undone and cannot be stopped once the device has started the wipe.
            </div>
          )}
          {approving && a.is_own_request && (
            <p className="rounded border border-sev-high/60 bg-sev-high/10 px-3 py-2 text-sm">
              This is your own request. Approving it yourself starts a cooling-off delay
              {settings ? ` of ${settings.self_approval_cooldown_minutes} minutes` : ""}; any admin can still cancel it until then.
            </p>
          )}
          {decision === "cancel" && <p className="text-sm text-ink-2">The request is withdrawn and nothing is sent to the device.</p>}
          {error && (
            <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
              {error}
            </div>
          )}
          <Field
            label={approving ? "Comment (optional, recorded in the audit log)" : "Reason (recorded in the audit log)"}
            id="apr-reason"
            required={!approving}
            minLength={approving ? undefined : 3}
            maxLength={500}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
          {needsName && (
            <Field label={`Type the device name "${a.hostname}" to confirm`} id="apr-confirm" autoComplete="off" value={confirm}
              onChange={(e) => setConfirm(e.target.value)} />
          )}
          <div className="flex justify-end gap-2 pt-2">
            <Button onClick={close}>Close</Button>
            <Button type="submit" variant={approving && !isWipe ? "primary" : "danger"} disabled={busy || !reasonOk || !nameOk}>
              {busy ? "Working…" : approving && isWipe ? "Approve wipe" : DECISION_LABEL[decision]}
            </Button>
          </div>
        </form>
      )}
    </Modal>
  );
}

/** Table of approval requests; admins get Approve / Reject / Cancel buttons on open requests. */
export function ApprovalList({
  items,
  settings,
  onChanged,
  showDevice = true,
  empty = "No requests.",
}: {
  items: Approval[] | null;
  settings?: ApprovalSettings | null;
  onChanged: () => void;
  showDevice?: boolean;
  empty?: string;
}) {
  const { can } = useAuth();
  const admin = can("admin");
  const [open, setOpen] = useState<{ approval: Approval; decision: Decision } | null>(null);
  if (items && items.length === 0) return <Empty>{empty}</Empty>;
  const head = [...(showDevice ? ["Device"] : []), "Request", "Requested by", "Requested", "Status", ""];
  return (
    <>
      <Table head={head}>
        {(items ?? []).map((a) => {
          const isOpen = a.status === "pending" || a.status === "approved";
          return (
            <tr key={a.id} className="align-top">
              {showDevice && (
                <td className="px-3 py-2">
                  <Link to={`/devices/${a.device_id}`} className="font-medium hover:text-accent">
                    {a.hostname}
                  </Link>
                  <div className="text-[11px] text-ink-3">{a.os_family}</div>
                </td>
              )}
              <td className="max-w-[22rem] px-3 py-2">
                <div className="text-sm">{a.summary}</div>
                <div className="mt-1 flex flex-wrap items-center gap-1">
                  <RiskTag risk={a.risk} />
                  {a.action === "wipe_device" && <Tag tone="critical">remote wipe</Tag>}
                </div>
                {Object.keys(a.params).length > 0 && (
                  <div className="mt-1 break-words font-mono text-[11px] text-ink-3">{fmtParams(a.params)}</div>
                )}
              </td>
              <td className="max-w-[16rem] px-3 py-2 text-xs">
                {a.requested_by_email ?? "—"}
                {a.is_own_request && <span className="text-ink-3"> (you)</span>}
                <div className="text-ink-2">“{a.reason}”</div>
              </td>
              <td className="px-3 py-2 text-xs" title={fmtTime(a.requested_at)}>
                {fmtAgo(a.requested_at)}
              </td>
              <td className="px-3 py-2">
                <ApprovalStatus approval={a} />
              </td>
              <td className="px-3 py-2">
                {admin && isOpen && (
                  <div className="flex flex-wrap gap-1.5">
                    {a.status === "pending" && (
                      <>
                        <Button
                          variant="primary"
                          disabled={!a.can_decide}
                          title={a.can_decide ? undefined : "Waiting for a different admin: you cannot approve your own request"}
                          onClick={() => setOpen({ approval: a, decision: "approve" })}
                        >
                          Approve
                        </Button>
                        <Button onClick={() => setOpen({ approval: a, decision: "reject" })}>Reject</Button>
                      </>
                    )}
                    <Button onClick={() => setOpen({ approval: a, decision: "cancel" })}>Cancel</Button>
                    {a.status === "pending" && !a.can_decide && (
                      <div className="w-full text-[11px] text-ink-3">Waiting for a different admin.</div>
                    )}
                  </div>
                )}
              </td>
            </tr>
          );
        })}
      </Table>
      <DecisionDialog
        approval={open?.approval ?? null}
        decision={open?.decision ?? "approve"}
        settings={settings}
        onClose={() => setOpen(null)}
        onDone={onChanged}
      />
    </>
  );
}
