// Lost mode and remote wipe: dialogs and the overview card on the device page.
import { useState, type FormEvent, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { ApiError, api, type DeviceDetail as Device, type WipeMode } from "../../api";
import { Button, Card, Field, Modal, Tag } from "../../components/ui";
import { fmtAgo, fmtTime } from "../../lib/format";

const PHONE_RE = /^[0-9+][0-9 ()./+-]{2,31}$/;
const MESSAGE_MAX = 300;

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : String(e);
}

function Alert({ children }: { children: ReactNode }) {
  return (
    <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
      {children}
    </div>
  );
}

function yesNo(v: unknown): string {
  return v === true ? "Yes" : v === false ? "No" : "Unknown";
}

function nameMatches(device: Device, typed: string) {
  return typed.trim().toLowerCase() === device.hostname.toLowerCase();
}

function LostModeHelp({ os }: { os: Device["os_family"] }) {
  return (
    <div className="space-y-1 text-sm text-ink-2">
      {os === "macos" ? (
        <p>
          On macOS the message and phone number are shown on the lock screen / login window, and the display goes to sleep. The display sleep only
          locks the Mac if the user requires a password after sleep.
        </p>
      ) : (
        <p>
          On Windows the message and phone number are set as the legal notice (caption and text) shown at the sign-in screen, and the signed-in
          session is locked.
        </p>
      )}
      <p className="text-xs text-ink-3">
        Lost mode stays on until an admin exits it here; exiting restores the previous settings. No second approval is needed.
      </p>
    </div>
  );
}

/** Enable lost mode (when off) or exit it (when on). */
export function LostModeDialog({ device, open, onClose, onDone }: { device: Device; open: boolean; onClose: () => void; onDone: () => void }) {
  const enabling = device.lost_mode.status === null;
  const [message, setMessage] = useState("This device has been reported lost. Please contact the IT helpdesk to return it.");
  const [phone, setPhone] = useState("");
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

  const msg = message.trim();
  const msgOk = msg.length >= 1 && msg.length <= MESSAGE_MAX && msg.split("\n").length <= 6;
  const phoneOk = PHONE_RE.test(phone.trim());
  const valid = reason.trim().length >= 3 && (!enabling || (msgOk && phoneOk && nameMatches(device, confirm)));

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (enabling) {
        await api.queueCommand(device.id, {
          type: "enable_lost_mode",
          reason: reason.trim(),
          params: { message: msg, phone: phone.trim() },
          confirm_hostname: confirm.trim(),
        });
      } else {
        await api.queueCommand(device.id, { type: "disable_lost_mode", reason: reason.trim() });
      }
      onDone();
      close();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={close} title={`${enabling ? "Enable lost mode" : "Exit lost mode"}: ${device.hostname}`}>
      <form className="space-y-3" onSubmit={submit}>
        {enabling ? (
          <LostModeHelp os={device.os_family} />
        ) : (
          <p className="text-sm text-ink-2">
            The agent removes the lost-mode message and restores the sign-in / lock-screen settings it replaced. Use this once the device is back.
          </p>
        )}
        {error && <Alert>{error}</Alert>}
        {enabling && (
          <>
            <div>
              <label htmlFor="lm-message" className="mb-1 block text-sm font-medium text-ink-2">
                Message shown on the device
              </label>
              <textarea
                id="lm-message"
                rows={4}
                maxLength={MESSAGE_MAX}
                required
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                aria-describedby="lm-message-hint"
                className="block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40"
              />
              <p id="lm-message-hint" className={`mt-1 text-xs ${msgOk || !msg ? "text-ink-3" : "text-sev-high"}`}>
                {msg.length}/{MESSAGE_MAX} characters, at most 6 lines.
              </p>
            </div>
            <Field label="Contact phone number" id="lm-phone" required maxLength={32} value={phone} placeholder="+234 1 234 5678"
              onChange={(e) => setPhone(e.target.value)} hint="3-32 characters: digits, spaces and + ( ) . / -" />
          </>
        )}
        <Field label="Reason (recorded in the audit log)" id="lm-reason" required minLength={3} maxLength={500} value={reason}
          onChange={(e) => setReason(e.target.value)} placeholder="e.g. ticket INC-1234, user reported lost laptop" />
        {enabling && (
          <Field label={`Type the device name "${device.hostname}" to confirm`} id="lm-confirm" autoComplete="off" value={confirm}
            onChange={(e) => setConfirm(e.target.value)} />
        )}
        <div className="flex justify-end gap-2 pt-2">
          <Button onClick={close}>Cancel</Button>
          <Button type="submit" variant={enabling ? "danger" : "primary"} disabled={busy || !valid}>
            {busy ? "Queuing…" : enabling ? "Enable lost mode" : "Exit lost mode"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function WipeReadiness({ device }: { device: Device }) {
  const w = device.wipe;
  const r = w.readiness;
  const methods = Array.isArray(r.methods) ? (r.methods as unknown[]).map(String).join(", ") : null;
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
      <dt className="text-ink-3">Opted in at install</dt>
      <dd>{w.opted_in ? "Yes" : "No"}</dd>
      <dt className="text-ink-3">WinRE enabled</dt>
      <dd>{yesNo(r.winre_enabled)}</dd>
      <dt className="text-ink-3">MDM bridge available</dt>
      <dd>{yesNo(r.mdm_bridge)}</dd>
      {methods && (
        <>
          <dt className="text-ink-3">Methods</dt>
          <dd className="font-mono">{methods}</dd>
        </>
      )}
      {typeof r.edition === "string" && (
        <>
          <dt className="text-ink-3">Edition</dt>
          <dd>{r.edition}</dd>
        </>
      )}
      <dt className="text-ink-3">Ready</dt>
      <dd>{w.ready ? "Yes" : "No"}</dd>
      {w.readiness_detail && (
        <>
          <dt className="text-ink-3">Detail</dt>
          <dd className="text-ink-2">{w.readiness_detail}</dd>
        </>
      )}
    </dl>
  );
}

const MODES: { value: WipeMode; label: string; help: string }[] = [
  {
    value: "protected",
    label: "Protected (default)",
    help: "doWipeProtectedMethod: keeps trying after a power loss. May leave a device with a broken WinRE unbootable.",
  },
  { value: "standard", label: "Standard", help: "doWipeMethod: can be interrupted by a power cycle." },
];

/** Request a remote wipe (Windows only); creates an approval for a second admin. */
export function WipeDialog({ device, open, onClose, onDone }: { device: Device; open: boolean; onClose: () => void; onDone: () => void }) {
  const [mode, setMode] = useState<WipeMode>("protected");
  const [reason, setReason] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [requested, setRequested] = useState(false);
  const w = device.wipe;

  function close() {
    setReason("");
    setConfirm("");
    setError(null);
    setRequested(false);
    onClose();
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.requestWipe(device.id, { reason: reason.trim(), confirm_hostname: confirm.trim(), mode });
      setRequested(true);
      onDone();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={close} title={`Remote wipe: ${device.hostname}`}>
      {requested ? (
        <div className="space-y-3">
          <p role="status" className="text-sm">
            Wipe requested. Waiting for a second admin&apos;s approval on the{" "}
            <Link to="/approvals" className="text-accent hover:underline">
              Approvals
            </Link>{" "}
            page. Nothing is sent to the device until then.
          </p>
          <div className="flex justify-end">
            <Button onClick={close}>Close</Button>
          </div>
        </div>
      ) : (
        <form className="space-y-3" onSubmit={submit}>
          <div role="alert" className="rounded border border-sev-critical bg-sev-critical/15 px-3 py-2 text-sm">
            <strong className="text-sev-critical">This erases the device.</strong> All data and apps are removed and Windows is reset. It cannot be
            undone.
          </div>
          <div className="rounded border border-line bg-surface-2 p-3">
            <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-ink-3">Readiness reported by the agent</div>
            <WipeReadiness device={device} />
          </div>
          {!w.opted_in && (
            <p className="text-sm text-sev-high">
              This device did not opt in to remote wipe at install time. Reinstall the agent with the MSI property <code>CNAPP_ALLOW_WIPE=1</code> (or
              the &quot;Allow remote wipe&quot; installer option) to enable it.
            </p>
          )}
          {error && <Alert>{error}</Alert>}
          <fieldset className="space-y-2 text-sm">
            <legend className="mb-1 font-medium text-ink-2">Wipe method</legend>
            {MODES.map((m) => (
              <label key={m.value} className="flex items-start gap-2">
                <input type="radio" name="wipe-mode" className="mt-1" checked={mode === m.value} onChange={() => setMode(m.value)} />
                <span>
                  {m.label}
                  <span className="block text-xs text-ink-3">{m.help}</span>
                </span>
              </label>
            ))}
          </fieldset>
          <Field label="Reason (recorded in the audit log)" id="wipe-reason" required minLength={3} maxLength={500} value={reason}
            onChange={(e) => setReason(e.target.value)} placeholder="e.g. INC-1234 laptop stolen, not recovered" />
          <Field label={`Type the device name "${device.hostname}" to confirm`} id="wipe-confirm" autoComplete="off" value={confirm}
            onChange={(e) => setConfirm(e.target.value)} />
          <p className="text-xs text-ink-3">A second admin must approve the request before the wipe command is sent.</p>
          <div className="flex justify-end gap-2 pt-2">
            <Button onClick={close}>Cancel</Button>
            <Button type="submit" variant="danger"
              disabled={busy || !w.opted_in || reason.trim().length < 3 || !nameMatches(device, confirm)}
              title={w.opted_in ? undefined : "The device must opt in at install time"}>
              {busy ? "Requesting…" : "Request wipe"}
            </Button>
          </div>
        </form>
      )}
    </Modal>
  );
}

const LOST_LABEL: Record<NonNullable<Device["lost_mode"]["status"]>, string> = {
  enabling: "Enabling (waiting for the agent)",
  active: "Active",
  disabling: "Exiting (waiting for the agent)",
};

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-3 py-1 text-sm">
      <dt className="w-40 shrink-0 text-ink-3">{label}</dt>
      <dd className="min-w-0 break-words text-ink">{children || "—"}</dd>
    </div>
  );
}

/** Overview card: lost-mode state and remote-wipe support / readiness / status. */
export function LostWipeCard({ device }: { device: Device }) {
  const lm = device.lost_mode;
  const w = device.wipe;
  return (
    <Card title="Lost mode & remote wipe">
      <dl>
        <Row label="Lost mode">
          {lm.status ? <Tag tone="warn">{LOST_LABEL[lm.status]}</Tag> : "Off"}
        </Row>
        {lm.status && (
          <>
            <Row label="Message">
              <span className="whitespace-pre-wrap">{lm.message}</span>
            </Row>
            <Row label="Phone">{lm.phone}</Row>
            <Row label="Since">{lm.since && `${fmtTime(lm.since)} (${fmtAgo(lm.since)})`}</Row>
            <Row label="Requested by">{lm.requested_by}</Row>
            <Row label="Agent reports">{lm.reported_active === null ? "no report yet" : lm.reported_active ? "lost mode on" : "lost mode off"}</Row>
          </>
        )}
        <Row label="Remote wipe">
          {w.supported ? (w.opted_in ? "Supported, opted in" : "Supported, not opted in at install") : `Not supported${w.unsupported_reason ? `: ${w.unsupported_reason}` : ""}`}
        </Row>
        {w.supported && <Row label="Wipe readiness">{w.ready ? "Ready" : "Not ready"}{w.readiness_detail && <span className="text-ink-3"> · {w.readiness_detail}</span>}</Row>}
        {w.status && (
          <Row label="Wipe status">
            <Tag tone={w.status === "failed" ? "critical" : w.status === "expired" ? "default" : "warn"}>{w.status}</Tag>
            {w.status_at && <span className="ml-2 text-xs text-ink-3">{fmtAgo(w.status_at)}</span>}
          </Row>
        )}
      </dl>
      {w.supported && Object.keys(w.readiness).length > 0 && (
        <details className="mt-2 text-xs">
          <summary className="cursor-pointer text-ink-3">Readiness details</summary>
          <div className="mt-2">
            <WipeReadiness device={device} />
          </div>
        </details>
      )}
    </Card>
  );
}
