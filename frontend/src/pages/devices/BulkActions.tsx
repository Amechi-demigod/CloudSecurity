// Devices list: the same endpoint action on several selected devices (USB
// storage block / unblock, stop / disable a service). Devices where it cannot
// run are skipped and listed with the reason.
import { useState, type FormEvent } from "react";
import { ApiError } from "../../api";
import { Button, Field, Modal, Tag } from "../../components/ui";
import { endpointActionsApi, type BulkResult } from "../../endpointActionsApi";

type BulkKind = "block_usb" | "unblock_usb" | "stop_service" | "disable_service";

const KINDS: Record<BulkKind, { label: string; what: string; undo: string; service?: "stop" | "disable"; danger?: boolean }> = {
  block_usb: {
    label: "Block USB storage",
    danger: true,
    what: "On each selected Windows device the agent saves the current values, disables the USB mass-storage driver (USBSTOR) and applies the Removable Disks deny read / write / execute policy. Keyboards, mice, phones and printers keep working.",
    undo: "Unblock USB storage restores each device's previous values exactly.",
  },
  unblock_usb: {
    label: "Unblock USB storage",
    what: "On each selected device the agent restores the values it saved when it blocked USB storage. Devices it did not block are left unchanged.",
    undo: "Block USB storage again.",
  },
  stop_service: {
    label: "Stop a service",
    service: "stop",
    danger: true,
    what: "On each selected device that reports this service, the agent stops it. Its startup type is not changed, so it may start again at the next restart.",
    undo: "Start the service from each device's Services tab.",
  },
  disable_service: {
    label: "Disable a service",
    service: "disable",
    danger: true,
    what: "On each selected device that reports this service, the agent saves its startup type and sets it to Disabled. A running service keeps running until it is stopped or the device restarts.",
    undo: "Restore startup type on each device's Services tab puts back the saved value.",
  },
};

export function BulkActionsBar({ selected, onClear, onDone }: { selected: string[]; onClear: () => void; onDone: () => void }) {
  const [kind, setKind] = useState<BulkKind | null>(null);
  if (selected.length === 0) return null;
  return (
    <div className="mb-3 flex flex-wrap items-center gap-2 rounded border border-accent/40 bg-accent/5 px-3 py-2 text-sm" role="toolbar" aria-label="Bulk actions">
      <span className="font-medium">{selected.length} selected</span>
      {(Object.keys(KINDS) as BulkKind[]).map((k) => (
        <Button key={k} variant={KINDS[k].danger ? "danger" : "default"} onClick={() => setKind(k)}>
          {KINDS[k].label}
        </Button>
      ))}
      <Button onClick={onClear}>Clear selection</Button>
      <BulkDialog kind={kind} deviceIds={selected} onClose={() => setKind(null)} onDone={onDone} />
    </div>
  );
}

function BulkDialog({ kind, deviceIds, onClose, onDone }: { kind: BulkKind | null; deviceIds: string[]; onClose: () => void; onDone: () => void }) {
  const [reason, setReason] = useState("");
  const [service, setService] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<BulkResult | null>(null);
  const k = kind ? KINDS[kind] : null;
  function close() {
    setReason("");
    setService("");
    setError(null);
    setRes(null);
    onClose();
  }
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!kind || !k) return;
    setBusy(true);
    setError(null);
    try {
      const body = k.service
        ? { device_ids: deviceIds, type: "manage_service" as const, params: { service: service.trim(), action: k.service }, reason: reason.trim() }
        : { device_ids: deviceIds, type: kind === "block_usb" ? ("block_usb_storage" as const) : ("unblock_usb_storage" as const), reason: reason.trim() };
      setRes(await endpointActionsApi.bulk(body));
      onDone();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal open={!!k} onClose={close} title={k ? `${k.label} on ${deviceIds.length} device(s)` : ""}>
      {k && res ? (
        <div className="space-y-3">
          <p className="text-sm">
            <strong>{res.queued}</strong> queued, <strong>{res.skipped}</strong> skipped. Results appear on each device's Actions tab.
          </p>
          <ul className="max-h-64 space-y-1 overflow-auto text-xs">
            {res.results.map((r) => (
              <li key={r.device_id} className="flex items-start gap-2">
                <span className="shrink-0">
                  <Tag tone={r.status === "queued" ? "good" : "warn"}>{r.status}</Tag>
                </span>
                <span className="min-w-0">
                  <span className="font-medium">{r.hostname ?? r.device_id}</span>
                  {r.detail && <span className="block text-ink-3">{r.detail}</span>}
                </span>
              </li>
            ))}
          </ul>
          <div className="flex justify-end">
            <Button onClick={close}>Close</Button>
          </div>
        </div>
      ) : k ? (
        <form className="space-y-3" onSubmit={submit}>
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-3">What will happen</h3>
            <p className="mt-1 text-sm text-ink-2">{k.what}</p>
          </div>
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-3">How to undo</h3>
            <p className="mt-1 text-sm text-ink-2">{k.undo}</p>
          </div>
          <p className="text-xs text-ink-3">
            Devices that are not Windows, run an agent older than 1.4.0, do not report the service, or where it is protected are skipped.
          </p>
          {error && (
            <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
              {error}
            </div>
          )}
          {k.service && (
            <Field label="Service name (as in the Services tab, e.g. Spooler)" id="bulk-service" required value={service}
              onChange={(e) => setService(e.target.value)} autoComplete="off" />
          )}
          <Field label="Reason (recorded in the audit log)" id="bulk-reason" required minLength={3} maxLength={500} value={reason}
            onChange={(e) => setReason(e.target.value)} />
          <div className="flex justify-end gap-2 pt-2">
            <Button onClick={close}>Cancel</Button>
            <Button type="submit" variant={k.danger ? "danger" : "primary"} disabled={busy || reason.trim().length < 3 || (!!k.service && !service.trim())}>
              {busy ? "Queuing…" : k.label}
            </Button>
          </div>
        </form>
      ) : null}
    </Modal>
  );
}
