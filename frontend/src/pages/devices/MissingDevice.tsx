// Missing-device mode: header pill, "Mark missing" / "Mark as recovered" dialogs and the panel on the device page
// (banner, actions, sightings table, last seen). Backend: app/tracking/missing.py, docs/DEVICE_TRACKING.md.
import { useState, type FormEvent, type ReactNode } from "react";
import { ApiError, type DeviceDetail as Device } from "../../api";
import { useAuth } from "../../auth/context";
import { Button, Card, Field, Modal, Tag } from "../../components/ui";
import { fmtAgo } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { fmtInZone } from "../../trackingApi";
import { missingApi, type MissingSighting, type MissingView } from "../../missingApi";

const PHONE_RE = /^[0-9+][0-9 ()./+-]{2,31}$/;
const MESSAGE_MAX = 300;
const DEFAULT_MESSAGE = "This device has been reported lost. Please contact the IT helpdesk to return it.";

const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : String(e));

/** Red pill in the device header. */
export function MissingPill() {
  return <Tag tone="critical">MISSING</Tag>;
}

function place(s: { city: string | null; country: string | null; is_private: boolean; office?: string | null }): string {
  if (s.is_private) return "Private network";
  const p = [s.city, s.country].filter(Boolean).join(", ") || "Not available yet";
  return s.office ? `${p} (${s.office})` : p;
}

/** Mark the device missing: reason, lost-mode message and phone, typed hostname. */
export function MarkMissingDialog({ device, lostModeOn, open, onClose, onDone }: {
  device: Device; lostModeOn: boolean; open: boolean; onClose: () => void; onDone: () => void;
}) {
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState(DEFAULT_MESSAGE);
  const [phone, setPhone] = useState("");
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
  const lostOk = lostModeOn || (msg.length >= 1 && msg.length <= MESSAGE_MAX && msg.split("\n").length <= 6 && PHONE_RE.test(phone.trim()));
  const valid = reason.trim().length >= 3 && confirm.trim().toLowerCase() === device.hostname.toLowerCase() && lostOk;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await missingApi.mark(device.id, {
        reason: reason.trim(),
        confirm_hostname: confirm.trim(),
        ...(lostModeOn ? {} : { message: msg, phone: phone.trim() }),
      });
      onDone();
      close();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={close} title={`Mark as missing: ${device.hostname}`}>
      <form className="space-y-3" onSubmit={submit}>
        <div className="space-y-1 text-sm text-ink-2">
          <p>
            The computer is asked to report every <strong>5 minutes</strong>, and every change of its internet address is recorded as an
            approximate, city-level sighting. {lostModeOn ? "Lost mode is already on." : "Lost mode is turned on with the message below."}
          </p>
          <p className="text-xs text-ink-3">
            Nothing is read from the computer&apos;s camera, screen, GPS or Wi-Fi. You can suspend sign-in or request a remote wipe afterwards. No second
            approval is needed to mark a device missing.
          </p>
        </div>
        {error && (
          <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
            {error}
          </div>
        )}
        <Field label="Reason (recorded in the audit log and shown in the report)" id="missing-reason" required minLength={3} maxLength={500}
          value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. left on a train, ticket INC-1234" />
        {!lostModeOn && (
          <>
            <div>
              <label htmlFor="missing-message" className="mb-1 block text-sm font-medium text-ink-2">
                Message shown on the device
              </label>
              <textarea id="missing-message" rows={3} maxLength={MESSAGE_MAX} required value={message} onChange={(e) => setMessage(e.target.value)}
                className="block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40" />
              <p className="mt-1 text-xs text-ink-3">{msg.length}/{MESSAGE_MAX} characters, at most 6 lines.</p>
            </div>
            <Field label="Contact phone number" id="missing-phone" required maxLength={32} value={phone} placeholder="+234 1 234 5678"
              onChange={(e) => setPhone(e.target.value)} hint="3-32 characters: digits, spaces and + ( ) . / -" />
          </>
        )}
        <Field label={`Type the device name "${device.hostname}" to confirm`} id="missing-confirm" autoComplete="off" value={confirm}
          onChange={(e) => setConfirm(e.target.value)} />
        <div className="flex justify-end gap-2 pt-2">
          <Button onClick={close}>Cancel</Button>
          <Button type="submit" variant="danger" disabled={busy || !valid}>
            {busy ? "Marking…" : "Mark as missing"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

/** Mark the device recovered; asks whether to exit lost mode too. */
export function RecoveredDialog({ device, lostMode, open, onClose, onDone }: {
  device: Device; lostMode: MissingView["lost_mode"]["status"]; open: boolean; onClose: () => void; onDone: () => void;
}) {
  const [exitLost, setExitLost] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await missingApi.recover(device.id, exitLost);
      onDone();
      onClose();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={onClose} title={`Mark as recovered: ${device.hostname}`}>
      <form className="space-y-3" onSubmit={submit}>
        <p className="text-sm text-ink-2">
          The device stops being listed as missing and goes back to its normal check-in interval. The sightings stay available in the report.
        </p>
        {error && (
          <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
            {error}
          </div>
        )}
        {lostMode ? (
          <label className="flex items-start gap-2 text-sm">
            <input type="checkbox" className="mt-1" checked={exitLost} onChange={(e) => setExitLost(e.target.checked)} />
            <span>
              Also exit lost mode
              <span className="block text-xs text-ink-3">The agent removes the lost-mode message and restores the sign-in settings it replaced.</span>
            </span>
          </label>
        ) : (
          <p className="text-xs text-ink-3">Lost mode is not on.</p>
        )}
        <div className="flex justify-end gap-2 pt-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy}>
            {busy ? "Saving…" : "Mark as recovered"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function SightingsTable({ rows, full }: { rows: MissingSighting[]; full: boolean }) {
  if (rows.length === 0) return <p className="text-sm text-ink-3">The computer has not reported since it was marked missing.</p>;
  const newestFirst = [...rows].reverse();
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="text-[11px] uppercase tracking-wide text-ink-3">
          <tr>
            <th className="py-1 pr-3 font-medium">When</th>
            <th className="py-1 pr-3 font-medium">Where (approx.)</th>
            {full && <th className="py-1 pr-3 font-medium">Internet address · provider</th>}
            <th className="py-1 font-medium">Signed in</th>
          </tr>
        </thead>
        <tbody>
          {newestFirst.map((s) => (
            <tr key={`${s.when}-${s.ip ?? s.city}`} className="border-t border-line align-top">
              <td className="whitespace-nowrap py-1.5 pr-3">{fmtInZone(s.when, s.timezone)}</td>
              <td className="py-1.5 pr-3">{place(s)}</td>
              {full && (
                <td className="py-1.5 pr-3">
                  <span className="font-mono text-xs">{s.ip ?? "—"}</span>
                  {s.provider ? <span className="text-ink-3"> · {s.provider}</span> : null}
                </td>
              )}
              <td className="py-1.5">{s.signed_in ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="text-ink-3">{label}</dt>
      <dd className="text-right text-ink">{children}</dd>
    </div>
  );
}

/** The panel shown on the device page while the device is missing. */
export function MissingPanel({ device, onSuspend, onWipe, onChanged }: {
  device: Device; onSuspend?: () => void; onWipe?: () => void; onChanged: () => void;
}) {
  const { can } = useAuth();
  const { data: m, error, reload } = useApi(() => missingApi.get(device.id), [device.id, device.missing], 30000);
  const [recoverOpen, setRecoverOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  if (!m) return error ? <div role="alert" className="mb-4 text-sm text-sev-critical">{error}</div> : null;
  if (!m.missing) return null;
  const full = m.detail === "full";
  const active = device.status === "active";
  const lastSeen = m.last_seen;

  async function download() {
    setBusy(true);
    setErr(null);
    try {
      const { blob, filename } = await missingApi.reportPdf(device.id);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="mb-4 space-y-4" aria-label="Missing device">
      <div role="status" className="rounded-xl border border-sev-critical/60 bg-sev-critical/10 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="text-sm font-semibold text-ink">
              Marked missing {m.since ? fmtAgo(m.since) : ""} by {m.by ?? "an administrator"}
            </p>
            <p className="mt-1 text-sm text-ink-2">{m.reason}</p>
            <p className="mt-1 text-xs text-ink-3">
              The computer reports every 5 minutes while it is missing.{" "}
              {m.lost_mode.status ? "Lost mode is on." : "Lost mode is off."}
            </p>
          </div>
          {active && (
            <div className="flex flex-wrap gap-2" role="toolbar" aria-label="Missing device actions">
              {can("analyst") && <Button onClick={() => void download()} disabled={busy}>{busy ? "Preparing…" : "Download report (PDF)"}</Button>}
              {can("analyst") && onSuspend && device.isolation.status === null && (
                <Button variant="danger" onClick={onSuspend} disabled={!!device.lost_mode.status || !device.isolation.supported}
                  title={device.lost_mode.status ? "Sign-in cannot be suspended while lost mode is on: exit lost mode first" :
                    !device.isolation.supported ? "Not supported by this agent version" : "Block standard interactive sign-in; local admin access keeps working"}>
                  Suspend sign-in
                </Button>
              )}
              {can("admin") && device.os_family === "windows" && onWipe && <Button variant="danger" onClick={onWipe}>Remote wipe</Button>}
              {can("admin") && <Button variant="primary" onClick={() => setRecoverOpen(true)}>Mark as recovered</Button>}
            </div>
          )}
        </div>
        {err && <p role="alert" className="mt-2 text-sm text-sev-critical">{err}</p>}
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <Card title="Sightings since it went missing">
            <SightingsTable rows={m.sightings} full={full} />
            <p className="mt-3 text-xs text-ink-3">
              Offline for more than an hour? You get an alert the moment it connects again. Locations are approximate and come from the
              internet address.
            </p>
          </Card>
        </div>
        <div className="space-y-4">
          <Card title="Last seen">
            {!lastSeen ? (
              <p className="text-sm text-ink-3">Not seen since it was marked missing.</p>
            ) : (
              <dl className="space-y-2 text-sm">
                <Row label="When">{fmtInZone(lastSeen.when, lastSeen.timezone)} ({fmtAgo(lastSeen.when)})</Row>
                <Row label="Where">{place(lastSeen)}</Row>
                {full && <Row label="Internet provider">{lastSeen.provider ?? "—"}</Row>}
                <Row label="Hardware changes">
                  {m.hardware_changes === null ? "Not compared" : m.hardware_changes.length === 0 ? "None" : m.hardware_changes.join(", ")}
                </Row>
              </dl>
            )}
          </Card>
          <Card title="The report includes">
            <ul className="list-disc space-y-1 pl-5 text-sm text-ink-2">
              <li>Device details and serial number</li>
              <li>Owner or signed-in user</li>
              <li>When, why and by whom it was marked missing</li>
              <li>Every sighting: time, area, address and provider</li>
              <li>Actions taken since (lost mode, suspend sign-in, wipe)</li>
              <li>A note that locations are approximate</li>
            </ul>
            {!can("analyst") && <p className="mt-2 text-xs text-ink-3">The report is available to analysts and administrators.</p>}
          </Card>
        </div>
      </div>
      <RecoveredDialog device={device} lostMode={m.lost_mode.status} open={recoverOpen} onClose={() => setRecoverOpen(false)}
        onDone={() => { reload(); onChanged(); }} />
    </section>
  );
}
