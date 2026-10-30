import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError, api, type DeviceDetail, type RemoteMode, type RemoteSession } from "../../api";
import { useAuth } from "../../auth/context";
import { Button, Card, Empty, ErrorNote, Field, Modal, Table, Tag } from "../../components/ui";
import { fmtDuration } from "../../lib/devices";
import { fmtTime } from "../../lib/format";
import { describeEnd } from "../../lib/remote/protocol";
import { useApi } from "../../lib/useApi";

const MODE_LABEL: Record<RemoteMode, string> = { view: "View only", control: "View and control" };

function sessionDuration(seconds: number | null): string {
  if (seconds === null) return "—";
  return seconds < 60 ? `${seconds}s` : fmtDuration(seconds);
}

const STATE_TONE: Record<RemoteSession["state"], "default" | "warn" | "good" | "accent"> = {
  requested: "accent",
  awaiting_consent: "accent",
  active: "good",
  ended: "default",
  denied: "warn",
  failed: "warn",
};

const STATE_LABEL: Record<RemoteSession["state"], string> = {
  requested: "Waiting for device",
  awaiting_consent: "Waiting for user",
  active: "Connected",
  ended: "Ended",
  denied: "Denied",
  failed: "Failed",
};

/** "Remote session" in the device's everyday actions: disabled with the reason when unavailable. */
export function RemoteSessionButton({ device }: { device: DeviceDetail }) {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const avail = useApi(() => api.remoteAvailability(device.id), [device.id, device.lost_mode.status,
    device.isolation.status, device.status], 15000);
  const a = avail.data;
  const windows = device.os_family === "windows";
  if (a?.open_session_id) {
    return (
      <Button onClick={() => navigate(`/devices/${device.id}/remote/${a.open_session_id}`)}
        title="A remote session with this device is open">
        Open remote session
      </Button>
    );
  }
  const reason = !windows
    ? "Remote sessions are available on Windows devices only for now"
    : a && !a.available
      ? a.reason ?? "Not available"
      : null;
  return (
    <>
      <span title={reason ?? "View (or, as an admin, control) the signed-in user's screen after they allow it"}>
        <Button onClick={() => setOpen(true)} disabled={!a || !!reason}>
          Remote session
        </Button>
      </span>
      {a && a.available && (
        <StartRemoteDialog device={device} modes={a.modes} open={open} onClose={() => setOpen(false)}
          onStarted={(s) => navigate(`/devices/${device.id}/remote/${s.id}`)} />
      )}
    </>
  );
}

function StartRemoteDialog({ device, modes, open, onClose, onStarted }: {
  device: DeviceDetail;
  modes: RemoteMode[];
  open: boolean;
  onClose: () => void;
  onStarted: (s: RemoteSession) => void;
}) {
  const [mode, setMode] = useState<RemoteMode>("view");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function close() {
    setReason("");
    setError(null);
    onClose();
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const s = await api.startRemoteSession(device.id, { mode, reason: reason.trim() });
      close();
      onStarted(s);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={close} title={`Remote session: ${device.hostname}`}>
      <form className="space-y-3" onSubmit={submit}>
        <p className="text-sm text-ink-2">
          The signed-in user sees a prompt with your name, the access level and your reason, and nothing is shared until
          they click <strong>Allow</strong>. While connected, a banner stays on their screen and they can end the session
          at any time. Every step is recorded in the audit log; the screen itself is never recorded.
        </p>
        {error && (
          <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
            {error}
          </div>
        )}
        <fieldset className="space-y-1.5">
          <legend className="mb-1 text-xs font-medium text-ink-2">Access</legend>
          {(["view", "control"] as RemoteMode[]).map((m) => {
            const allowed = modes.includes(m);
            return (
              <label key={m} className={`flex items-start gap-2 text-sm ${allowed ? "text-ink" : "text-ink-3"}`}>
                <input type="radio" name="remote-mode" value={m} checked={mode === m} disabled={!allowed}
                  onChange={() => setMode(m)} className="mt-1 accent-accent" />
                <span>
                  {MODE_LABEL[m]}
                  <span className="block text-xs text-ink-3">
                    {m === "view"
                      ? "See the screen; your mouse and keyboard do nothing on the device."
                      : allowed
                        ? "See the screen and use the mouse and keyboard."
                        : "Requires the admin role."}
                  </span>
                </span>
              </label>
            );
          })}
        </fieldset>
        <Field label="Reason (shown to the user and recorded in the audit log)" id="rs-reason" required minLength={3}
          maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)}
          placeholder="e.g. ticket INC-1234, Outlook keeps freezing" />
        <p className="text-xs text-ink-3">
          The device picks the request up on its next poll, usually within a minute.
        </p>
        <div className="flex justify-end gap-2 pt-2">
          <Button onClick={close}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy || reason.trim().length < 3}>
            {busy ? "Requesting…" : "Request session"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

/** Who, when, how long, mode and outcome of every remote session (History tab). */
export function RemoteSessionsCard({ deviceId }: { deviceId: string }) {
  const { can } = useAuth();
  const { data, error } = useApi(() => api.deviceRemoteSessions(deviceId, 100), [deviceId], 15000);
  const navigate = useNavigate();
  return (
    <Card title="Remote sessions" className="mb-4">
      <ErrorNote error={error} />
      {data && data.length === 0 ? (
        <Empty>No remote sessions yet.</Empty>
      ) : (
        <Table head={["Requested", "By", "Mode", "Duration", "Outcome", "Reason"]}>
          {(data ?? []).map((s) => {
            const open = s.state === "requested" || s.state === "awaiting_consent" || s.state === "active";
            return (
              <tr key={s.id}>
                <td className="px-3 py-1.5 text-xs">{fmtTime(s.created_at)}</td>
                <td className="px-3 py-1.5 text-xs text-ink-2">{s.requested_by_name || s.requested_by_email}</td>
                <td className="px-3 py-1.5 text-xs text-ink-2">{MODE_LABEL[s.mode]}</td>
                <td className="px-3 py-1.5 text-xs text-ink-2">
                  {sessionDuration(s.duration_seconds)}
                </td>
                <td className="px-3 py-1.5 text-xs">
                  <Tag tone={STATE_TONE[s.state]}>{STATE_LABEL[s.state]}</Tag>
                  {!open && (
                    <span className="ml-2 text-ink-3">{describeEnd(s.state, s.end_reason, s.error_code)}</span>
                  )}
                  {open && can("analyst") && (
                    <button className="ml-2 text-accent hover:underline"
                      onClick={() => navigate(`/devices/${deviceId}/remote/${s.id}`)}>
                      Open
                    </button>
                  )}
                </td>
                <td className="max-w-xs truncate px-3 py-1.5 text-xs text-ink-3" title={s.reason}>{s.reason}</td>
              </tr>
            );
          })}
        </Table>
      )}
    </Card>
  );
}
