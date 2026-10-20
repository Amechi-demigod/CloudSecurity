import { useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ApiError, api, type CommandType, type DeviceCommand, type DeviceDetail as Device, type Role } from "../../api";
import { useAuth } from "../../auth/context";
import { CheckBadge, ConnectivityTag, HealthBadge, IssueList } from "../../components/devices";
import { Button, Card, Empty, ErrorNote, Field, Modal, PageHeader, Table, Tag } from "../../components/ui";
import { CHECK_LABEL, OS_LABEL, fmtBytes, fmtDuration } from "../../lib/devices";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { AssetRecordLink } from "../assets/AssetRecordLink";

const TABS = ["Overview", "Posture", "Software", "History", "Commands", "Updates"] as const;
type TabName = (typeof TABS)[number];

const ACTIONS: { type: CommandType; label: string; role: Role; help: string; danger?: boolean }[] = [
  { type: "recheck_posture", label: "Re-check posture", role: "analyst", help: "Ask the agent for an immediate full inventory and posture check-in." },
  { type: "collect_logs", label: "Collect logs", role: "analyst", help: "The agent uploads a size-capped bundle of its own logs and a system snapshot (no user files)." },
  { type: "lock_device", label: "Lock device", role: "admin", help: "Locks the signed-in user's session. Unsaved work stays open; the user signs in again to continue.", danger: true },
  { type: "restart_agent", label: "Restart agent", role: "admin", help: "The agent exits and the OS service manager starts it again." },
  { type: "update_check_in_interval", label: "Change check-in interval", role: "admin", help: "How often the agent sends a full inventory/posture report (5 min - 24 h)." },
];

const STATUS_TONE: Record<DeviceCommand["status"], "default" | "warn" | "good" | "accent"> = {
  pending: "accent",
  delivered: "accent",
  succeeded: "good",
  failed: "warn",
  rejected: "warn",
  expired: "default",
  cancelled: "default",
};

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : String(e);
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-3 py-1 text-sm">
      <dt className="w-40 shrink-0 text-ink-3">{label}</dt>
      <dd className="min-w-0 break-words text-ink">{children || "—"}</dd>
    </div>
  );
}

function ActionDialog({ device, action, onClose, onDone }: {
  device: Device;
  action: (typeof ACTIONS)[number] | null;
  onClose: () => void;
  onDone: () => void;
}) {
  const [reason, setReason] = useState("");
  const [minutes, setMinutes] = useState(String(Math.round(device.check_in_interval_seconds / 60)));
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function close() {
    setReason("");
    setConfirm("");
    setError(null);
    onClose();
  }

  const needsConfirm = action?.type === "lock_device";
  const confirmed = !needsConfirm || confirm.trim().toLowerCase() === device.hostname.toLowerCase();

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!action) return;
    setBusy(true);
    setError(null);
    try {
      const params = action.type === "update_check_in_interval" ? { interval_seconds: Math.round(Number(minutes) * 60) } : {};
      await api.queueCommand(device.id, { type: action.type, reason: reason.trim(), params });
      onDone();
      close();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={!!action} onClose={close} title={action ? `${action.label}: ${device.hostname}` : ""}>
      {action && (
        <form className="space-y-3" onSubmit={submit}>
          <p className="text-sm text-ink-2">{action.help}</p>
          <p className="text-xs text-ink-3">
            Queued commands are picked up on the agent's next poll (about a minute while the device is online) and expire after 24 hours.
          </p>
          {error && (
            <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
              {error}
            </div>
          )}
          {action.type === "update_check_in_interval" && (
            <Field label="Check-in interval (minutes)" id="act-minutes" type="number" min={5} max={1440} required value={minutes}
              onChange={(e) => setMinutes(e.target.value)} />
          )}
          <Field label="Reason (recorded in the audit log)" id="act-reason" required minLength={3} maxLength={500} value={reason}
            onChange={(e) => setReason(e.target.value)} placeholder="e.g. ticket INC-1234, user reported lost laptop" />
          {needsConfirm && (
            <Field label={`Type the hostname "${device.hostname}" to confirm`} id="act-confirm" autoComplete="off" value={confirm}
              onChange={(e) => setConfirm(e.target.value)} />
          )}
          <div className="flex justify-end gap-2 pt-2">
            <Button onClick={close}>Cancel</Button>
            <Button type="submit" variant={action.danger ? "danger" : "primary"} disabled={busy || reason.trim().length < 3 || !confirmed}>
              {busy ? "Queuing…" : action.label}
            </Button>
          </div>
        </form>
      )}
    </Modal>
  );
}

function ReasonDialog({ open, title, help, cta, onClose, onSubmit }: {
  open: boolean;
  title: string;
  help: string;
  cta: string;
  onClose: () => void;
  onSubmit: (reason: string) => Promise<void>;
}) {
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
    try {
      await onSubmit(reason.trim());
      close();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal open={open} onClose={close} title={title}>
      <form className="space-y-3" onSubmit={submit}>
        <p className="text-sm text-ink-2">{help}</p>
        {error && (
          <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
            {error}
          </div>
        )}
        <Field label="Reason (recorded in the audit log)" id="rd-reason" required minLength={3} value={reason}
          onChange={(e) => setReason(e.target.value)} />
        <div className="flex justify-end gap-2 pt-2">
          <Button onClick={close}>Cancel</Button>
          <Button type="submit" variant="danger" disabled={busy || reason.trim().length < 3}>
            {busy ? "Working…" : cta}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function PostureCards({ device }: { device: Device }) {
  const entries = Object.entries(device.posture);
  if (entries.length === 0) return <Empty>No posture data yet. It arrives with the first check-in.</Empty>;
  const order = Object.keys(CHECK_LABEL);
  entries.sort(([a], [b]) => (order.indexOf(a) + 1 || 99) - (order.indexOf(b) + 1 || 99));
  return (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
      {entries.map(([name, c]) => {
        const data = Object.entries(c.data ?? {}).filter(([k]) => k !== "accounts" && k !== "pending_titles" && k !== "products" && k !== "profiles");
        const accounts = (c.data?.accounts as string[] | undefined) ?? null;
        const titles = (c.data?.pending_titles as string[] | undefined) ?? null;
        return (
          <section key={name} className="rounded-lg border border-line bg-surface-1 p-3">
            <header className="flex items-center justify-between gap-2">
              <h3 className="text-sm font-semibold">{CHECK_LABEL[name] ?? name}</h3>
              <CheckBadge status={c.status} />
            </header>
            <p className="mt-1 text-sm text-ink-2">{c.detail || "—"}</p>
            {c.error && <p className="mt-1 break-words text-xs text-sev-high">Error: {c.error}</p>}
            {accounts && (
              <ul className="mt-2 flex flex-wrap gap-1">
                {accounts.map((a) => (
                  <li key={a}>
                    <Tag>{a}</Tag>
                  </li>
                ))}
              </ul>
            )}
            {titles && titles.length > 0 && (
              <ul className="mt-2 list-inside list-disc text-xs text-ink-2">
                {titles.map((t) => (
                  <li key={t}>{t}</li>
                ))}
              </ul>
            )}
            {data.length > 0 && (
              <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
                {data.map(([k, v]) => (
                  <div key={k} className="contents">
                    <dt className="text-ink-3">{k.replaceAll("_", " ")}</dt>
                    <dd className="truncate text-ink-2" title={String(v)}>
                      {typeof v === "object" ? JSON.stringify(v) : String(v)}
                    </dd>
                  </div>
                ))}
              </dl>
            )}
          </section>
        );
      })}
    </div>
  );
}

function Overview({ device }: { device: Device }) {
  const inv = device.inventory;
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
      <Card title="Issues">
        <IssueList issues={device.issues} />
      </Card>
      <Card title="Device">
        <dl>
          <Row label="Hostname">{device.hostname}</Row>
          <Row label="Operating system">
            {device.os_name} {device.os_version} {device.os_build && <span className="text-ink-3">(build {device.os_build})</span>}
          </Row>
          <Row label="Hardware">{[device.manufacturer, device.model].filter(Boolean).join(" ")}</Row>
          <Row label="Serial number">{device.serial_number}</Row>
          <Row label="CPU">
            {inv.cpu} {inv.cpu_cores ? <span className="text-ink-3">({inv.cpu_cores} cores)</span> : null}
          </Row>
          <Row label="Memory">{fmtBytes(inv.memory_bytes)}</Row>
          <Row label="Architecture">{device.architecture}</Row>
          <Row label="Uptime">
            {fmtDuration(inv.uptime_seconds)} {inv.last_boot && <span className="text-ink-3">(booted {fmtTime(inv.last_boot)})</span>}
          </Row>
          <Row label="Signed-in users">{(inv.logged_in_users ?? []).join(", ")}</Row>
          <Row label="Time zone">{inv.timezone}</Row>
        </dl>
      </Card>
      <Card title="Storage">
        {(inv.disks ?? []).length === 0 ? (
          <Empty>No disk data.</Empty>
        ) : (
          <ul className="space-y-3">
            {(inv.disks ?? []).map((d) => {
              const used = d.size_bytes && d.free_bytes !== null ? 100 - (100 * d.free_bytes) / d.size_bytes : null;
              return (
                <li key={d.mount}>
                  <div className="flex justify-between text-sm">
                    <span>
                      {d.mount} <span className="text-ink-3">{d.filesystem}</span>
                    </span>
                    <span className="text-ink-2">
                      {fmtBytes(d.free_bytes)} free of {fmtBytes(d.size_bytes)}
                    </span>
                  </div>
                  {used !== null && (
                    <div className="mt-1 h-2 overflow-hidden rounded-full bg-surface-2" aria-hidden>
                      <div className="h-full rounded-full bg-accent" style={{ width: `${used}%` }} />
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </Card>
      <Card title="Network & agent">
        <dl>
          {(inv.network ?? []).map((n) => (
            <Row key={n.name} label={n.name}>
              {n.ips.join(", ")} <span className="text-ink-3">{n.mac}</span>
            </Row>
          ))}
          <Row label="Last public IP">{device.last_ip}</Row>
          <Row label="Agent version">{device.agent_version}</Row>
          <Row label="Enrolled">{fmtTime(device.enrolled_at)}</Row>
          <Row label="Last check-in">{device.last_checkin_at ? `${fmtTime(device.last_checkin_at)} (${fmtAgo(device.last_checkin_at)})` : "never"}</Row>
          <Row label="Check-in interval">{Math.round(device.check_in_interval_seconds / 60)} minutes</Row>
          {device.revoked_at && <Row label="Revoked">{fmtTime(device.revoked_at)}</Row>}
        </dl>
        {Object.keys(device.collection_errors).length > 0 && (
          <details className="mt-3 text-xs">
            <summary className="cursor-pointer text-sev-high">{Object.keys(device.collection_errors).length} collector error(s)</summary>
            <ul className="mt-1 space-y-1 text-ink-2">
              {Object.entries(device.collection_errors).map(([k, v]) => (
                <li key={k}>
                  <span className="text-ink-3">{k}:</span> {v}
                </li>
              ))}
            </ul>
          </details>
        )}
      </Card>
    </div>
  );
}

function SoftwareTab({ id }: { id: string }) {
  const [q, setQ] = useState("");
  const { data, error } = useApi(() => api.deviceSoftware(id, q.trim() || undefined), [id, q]);
  return (
    <Card title={`Installed software${data ? ` (${data.length})` : ""}`} actions={
      <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by name or publisher" aria-label="Filter software"
        className="w-56 rounded border border-line bg-surface-2 px-2 py-1 text-sm text-ink" />
    }>
      <ErrorNote error={error} />
      {data && data.length === 0 ? (
        <Empty>No software reported.</Empty>
      ) : (
        <Table head={["Name", "Version", "Publisher", "Installed", "Source"]}>
          {(data ?? []).map((s, i) => (
            <tr key={`${s.name}-${s.version}-${i}`}>
              <td className="px-3 py-1.5">{s.name}</td>
              <td className="px-3 py-1.5 font-mono text-xs text-ink-2">{s.version || "—"}</td>
              <td className="px-3 py-1.5 text-ink-2">{s.publisher || "—"}</td>
              <td className="px-3 py-1.5 text-xs text-ink-3">{s.install_date || "—"}</td>
              <td className="px-3 py-1.5 text-xs text-ink-3">{s.source}</td>
            </tr>
          ))}
        </Table>
      )}
    </Card>
  );
}

function HistoryTab({ id }: { id: string }) {
  const { data, error } = useApi(() => api.deviceHistory(id, 100), [id]);
  return (
    <Card title="Check-in history">
      <ErrorNote error={error} />
      {data && data.length === 0 ? (
        <Empty>No check-ins yet.</Empty>
      ) : (
        <Table head={["Received", "OS version", "Agent", "Posture", "Issues"]}>
          {(data ?? []).map((h) => {
            const counts = Object.values(h.posture).reduce<Record<string, number>>((acc, c) => {
              acc[c.status] = (acc[c.status] ?? 0) + 1;
              return acc;
            }, {});
            return (
              <tr key={h.id}>
                <td className="px-3 py-1.5 text-xs">{fmtTime(h.received_at)}</td>
                <td className="px-3 py-1.5 text-xs text-ink-2">{h.os_version}</td>
                <td className="px-3 py-1.5 text-xs text-ink-3">{h.agent_version}</td>
                <td className="px-3 py-1.5 text-xs text-ink-2">
                  {counts.pass ?? 0} pass · {counts.fail ?? 0} fail · {counts.unknown ?? 0} unknown
                </td>
                <td className="px-3 py-1.5 text-xs text-ink-2">{h.issues.join(", ") || "none"}</td>
              </tr>
            );
          })}
        </Table>
      )}
    </Card>
  );
}

function CommandsTab({ device, commands, error, reload }: { device: Device; commands: DeviceCommand[] | null; error: string | null; reload: () => void }) {
  const { can } = useAuth();
  const [busy, setBusy] = useState<string | null>(null);
  const [cancelError, setCancelError] = useState<string | null>(null);
  async function cancel(c: DeviceCommand) {
    setBusy(c.id);
    setCancelError(null);
    try {
      await api.cancelCommand(device.id, c.id, "cancelled from the device page");
      reload();
    } catch (e) {
      setCancelError(errMsg(e));
    } finally {
      setBusy(null);
    }
  }
  return (
    <Card title="Remote actions">
      <ErrorNote error={error ?? cancelError} />
      {commands && commands.length === 0 ? (
        <Empty>No remote actions yet.</Empty>
      ) : (
        <Table head={["Requested", "Action", "Status", "Reason", "Output", ""]}>
          {(commands ?? []).map((c) => (
            <tr key={c.id} className="align-top">
              <td className="px-3 py-2 text-xs">
                {fmtTime(c.created_at)}
                <div className="text-ink-3">{c.requested_by_email}</div>
              </td>
              <td className="px-3 py-2 text-sm">
                {ACTIONS.find((a) => a.type === c.type)?.label ?? c.type}
                {c.type === "update_check_in_interval" && (
                  <div className="text-xs text-ink-3">{Math.round(Number(c.params.interval_seconds) / 60)} min</div>
                )}
              </td>
              <td className="px-3 py-2">
                <Tag tone={STATUS_TONE[c.status]}>{c.status}</Tag>
                <div className="mt-0.5 text-[11px] text-ink-3">
                  {c.completed_at ? fmtAgo(c.completed_at) : c.delivered_at ? `delivered ${fmtAgo(c.delivered_at)}` : `expires ${fmtTime(c.expires_at)}`}
                </div>
              </td>
              <td className="max-w-[16rem] px-3 py-2 text-xs text-ink-2">{c.reason}</td>
              <td className="max-w-[24rem] px-3 py-2">
                {c.output && <pre className="max-h-32 overflow-auto whitespace-pre-wrap break-words text-[11px] text-ink-2">{c.output}</pre>}
                {c.log_bundle_id && can("analyst") && (
                  <a className="text-xs text-accent" href={api.logBundleUrl(device.id, c.log_bundle_id)}>
                    Download log bundle
                  </a>
                )}
              </td>
              <td className="px-3 py-2">
                {c.status === "pending" && can(ACTIONS.find((a) => a.type === c.type)?.role ?? "admin") && (
                  <Button onClick={() => cancel(c)} disabled={busy === c.id}>
                    Cancel
                  </Button>
                )}
              </td>
            </tr>
          ))}
        </Table>
      )}
    </Card>
  );
}

const UPDATE_TONE: Record<string, "default" | "warn" | "good" | "accent"> = {
  installed: "good",
  rolled_back: "warn",
  failed: "warn",
  rejected: "warn",
  downloading: "accent",
  verified: "accent",
  installing: "accent",
};

function UpdatesTab({ id, admin }: { id: string; admin: boolean }) {
  const st = useApi(() => api.deviceUpdate(id), [id], 15000);
  const rings = useApi(api.updateRings, []);
  const releases = useApi(api.agentReleases, []);
  const [ring, setRing] = useState("");
  const [pin, setPin] = useState("");
  const [code, setCode] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const s = st.data;

  async function apply(body: { ring_id?: string; clear_ring?: boolean; pinned_release_id?: string; clear_pin?: boolean }) {
    setBusy(true);
    setError(null);
    try {
      await api.setDeviceUpdate(id, { ...body, reason: reason.trim() || "changed from the device page" }, code);
      setCode("");
      st.reload();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card title="Agent version and rollout">
        <ErrorNote error={st.error} />
        {s && (
          <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm md:grid-cols-2">
            <div><dt className="text-ink-3">Running</dt><dd className="font-mono">{s.agent_version || "unknown"}</dd></div>
            <div><dt className="text-ink-3">Target</dt><dd>{s.target_version ?? "none"} <span className="text-xs text-ink-3">({s.target_reason})</span></dd></div>
            <div><dt className="text-ink-3">Ring</dt><dd>{s.ring?.name ?? "—"} <span className="text-xs text-ink-3">({s.ring_assignment})</span></dd></div>
            <div><dt className="text-ink-3">Pinned release</dt><dd>{s.pinned_release?.version ?? "—"}</dd></div>
            <div className="md:col-span-2">
              <dt className="text-ink-3">Last update status</dt>
              <dd>
                {s.status ? <Tag tone={UPDATE_TONE[s.status] ?? "default"}>{s.status.replace("_", " ")}</Tag> : "—"}{" "}
                {s.status_version && <span className="font-mono text-xs">{s.status_version}</span>}{" "}
                {s.status_at && <span className="text-xs text-ink-3">{fmtAgo(s.status_at)}</span>}
                {s.status_detail && <div className="mt-1 text-xs text-ink-3">{s.status_detail}</div>}
              </dd>
            </div>
          </dl>
        )}
      </Card>
      {admin && (
        <Card title="Assign ring / pin version">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <label className="text-sm">
              <span className="mb-1 block font-medium text-ink-2">Ring</span>
              <select aria-label="Ring" value={ring} onChange={(e) => setRing(e.target.value)} className="w-full rounded border border-line bg-surface-2 px-2 py-1.5 text-sm">
                <option value="">— by device group / default —</option>
                {rings.data?.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
              </select>
            </label>
            <label className="text-sm">
              <span className="mb-1 block font-medium text-ink-2">Pin to release (overrides the ring)</span>
              <select aria-label="Pinned release" value={pin} onChange={(e) => setPin(e.target.value)} className="w-full rounded border border-line bg-surface-2 px-2 py-1.5 text-sm">
                <option value="">— no pin —</option>
                {releases.data?.filter((r) => !r.withdrawn_at).map((r) => <option key={r.id} value={r.id}>{r.version}</option>)}
              </select>
            </label>
            <Field label="Reason" id="upd-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
            <Field label="Authenticator code (if you use MFA)" id="upd-mfa" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} />
          </div>
          <ErrorNote error={error} />
          <div className="mt-3 flex flex-wrap gap-2">
            <Button variant="primary" disabled={busy} onClick={() => apply(ring ? { ring_id: ring } : { clear_ring: true })}>Apply ring</Button>
            <Button disabled={busy} onClick={() => apply(pin ? { pinned_release_id: pin } : { clear_pin: true })}>{pin ? "Pin" : "Remove pin"}</Button>
          </div>
          <p className="mt-2 text-xs text-ink-3">
            The agent never installs an older version than it runs unless the release is signed to allow that rollback. Manage releases and rings under{" "}
            <Link to="/devices/updates" className="text-accent hover:underline">Agent updates</Link>.
          </p>
        </Card>
      )}
      <Card title="Update history">
        {s && s.history.length === 0 && <Empty>No updates reported yet.</Empty>}
        {s && s.history.length > 0 && (
          <Table head={["When", "Status", "From", "To", "Detail"]}>
            {s.history.map((h) => (
              <tr key={h.id} className="border-t border-line align-top">
                <td className="py-1.5 pr-3 text-xs" title={fmtTime(h.created_at)}>{fmtAgo(h.created_at)}</td>
                <td className="py-1.5 pr-3"><Tag tone={UPDATE_TONE[h.status] ?? "default"}>{h.status.replace("_", " ")}</Tag></td>
                <td className="py-1.5 pr-3 font-mono text-xs">{h.from_version}</td>
                <td className="py-1.5 pr-3 font-mono text-xs">{h.to_version}</td>
                <td className="py-1.5 text-xs text-ink-2">{h.detail}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}

export default function DeviceDetail() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const { can } = useAuth();
  const [tab, setTab] = useState<TabName>("Overview");
  const [action, setAction] = useState<(typeof ACTIONS)[number] | null>(null);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const { data: device, error, reload } = useApi(() => api.device(id), [id], 30000);
  const cmds = useApi(() => api.deviceCommands(id), [id], 10000);

  if (!device) return <ErrorNote error={error} />;
  const active = device.status === "active";

  return (
    <div>
      <div className="mb-2 text-xs text-ink-3">
        <Link to="/devices" className="hover:text-ink">
          Devices
        </Link>{" "}
        / {device.hostname}
      </div>
      <PageHeader
        title={device.hostname}
        subtitle={`${OS_LABEL[device.os_family] ?? device.os_family} · ${[device.manufacturer, device.model].filter(Boolean).join(" ")}${device.serial_number ? ` · S/N ${device.serial_number}` : ""}`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {active ? <HealthBadge health={device.health} /> : <Tag tone="warn">Revoked</Tag>}
            <ConnectivityTag value={device.connectivity} />
            <AssetRecordLink deviceId={device.id} />
          </div>
        }
      />
      <ErrorNote error={error} />
      {active && can("analyst") && (
        <div className="mb-4 flex flex-wrap gap-2" role="toolbar" aria-label="Remote actions">
          {ACTIONS.filter((a) => can(a.role)).map((a) => (
            <Button key={a.type} variant={a.danger ? "danger" : "default"} onClick={() => setAction(a)} title={a.help}>
              {a.label}
            </Button>
          ))}
          {can("admin") && (
            <Button variant="danger" onClick={() => setRevokeOpen(true)} title="Invalidate the device credential">
              Revoke
            </Button>
          )}
        </div>
      )}
      {!active && can("admin") && (
        <div className="mb-4 flex items-center gap-3 rounded border border-line bg-surface-1 px-3 py-2 text-sm text-ink-2">
          This device's credential was revoked; the agent is rejected until it is re-enrolled with a new token.
          <Button variant="danger" onClick={() => setDeleteOpen(true)}>
            Delete device
          </Button>
        </div>
      )}
      <div role="tablist" aria-label="Device sections" className="mb-4 flex gap-1 border-b border-line">
        {TABS.map((t) => (
          <button
            key={t}
            role="tab"
            aria-selected={tab === t}
            onClick={() => setTab(t)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
              tab === t ? "border-accent text-ink" : "border-transparent text-ink-3 hover:text-ink"
            }`}
          >
            {t}
            {t === "Software" && ` (${device.software_count})`}
            {t === "Commands" && cmds.data && cmds.data.some((c) => c.status === "pending" || c.status === "delivered") && " •"}
          </button>
        ))}
      </div>
      {tab === "Overview" && <Overview device={device} />}
      {tab === "Posture" && <PostureCards device={device} />}
      {tab === "Software" && <SoftwareTab id={device.id} />}
      {tab === "History" && <HistoryTab id={device.id} />}
      {tab === "Updates" && <UpdatesTab id={device.id} admin={can("admin") && active} />}
      {tab === "Commands" && <CommandsTab device={device} commands={cmds.data} error={cmds.error} reload={cmds.reload} />}

      <ActionDialog device={device} action={action} onClose={() => setAction(null)} onDone={() => {
        cmds.reload();
        setTab("Commands");
      }} />
      <ReasonDialog open={revokeOpen} title={`Revoke ${device.hostname}`} cta="Revoke device"
        help="The device credential stops working immediately and pending actions are cancelled. The agent keeps running but is rejected until someone re-enrolls it with a new enrollment token."
        onClose={() => setRevokeOpen(false)}
        onSubmit={async (reason) => {
          await api.revokeDevice(device.id, reason);
          reload();
        }} />
      <ReasonDialog open={deleteOpen} title={`Delete ${device.hostname}`} cta="Delete permanently"
        help="Removes the device with its posture history, software inventory, actions and log bundles. This cannot be undone."
        onClose={() => setDeleteOpen(false)}
        onSubmit={async (reason) => {
          await api.deleteDevice(device.id, reason);
          navigate("/devices");
        }} />
    </div>
  );
}
