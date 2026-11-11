// Built-in endpoint actions on the device page: the Actions tab (USB storage,
// recent actions), the Services tab (per-row stop / start / disable / restore)
// and the uninstall button of the Software tab. Every action opens a
// confirmation that says exactly what will happen and how to undo it
// (docs/DEVICE_MANAGEMENT.md#endpoint-actions).
import { Lock, Usb } from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { ApiError, api, type CommandType, type DeviceCommand, type DeviceDetail as Device, type DeviceSoftware } from "../../api";
import { useAuth } from "../../auth/context";
import { Button, Card, Empty, ErrorNote, Field, Modal, Table, Tag } from "../../components/ui";
import {
  ENDPOINT_ACTION_TYPES,
  START_TYPE_LABEL,
  endpointActionLabel,
  endpointActionsApi,
  type DeviceServiceRow,
  type ServiceAction,
} from "../../endpointActionsApi";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";

const STATUS_TONE: Record<DeviceCommand["status"], "default" | "warn" | "good" | "accent"> = {
  pending: "accent",
  delivered: "accent",
  succeeded: "good",
  failed: "warn",
  rejected: "warn",
  expired: "default",
  cancelled: "default",
};

const SERVICE_STATUS_TONE: Record<string, "default" | "good" | "warn" | "accent"> = {
  running: "good",
  stopped: "default",
  start_pending: "accent",
  stop_pending: "accent",
  paused: "warn",
};

const PRODUCT_CODE_RE = /^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$/;

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : String(e);
}

function isEndpointAction(c: DeviceCommand) {
  return (ENDPOINT_ACTION_TYPES as readonly string[]).includes(c.type);
}

/** Why endpoint actions cannot run on this device (null: they can). */
function actionsBlockedReason(device: Device): string | null {
  const ea = device.endpoint_actions;
  if (!ea) return "Endpoint actions are not available for this device.";
  if (device.status !== "active") return "The device is revoked.";
  return ea.supported ? null : ea.unsupported_reason;
}

export interface PendingAction {
  type: CommandType;
  params: Record<string, unknown>;
  title: string;
  cta: string;
  what: ReactNode;
  undo: ReactNode;
  danger?: boolean;
  /** Type this text to confirm (uninstall: the program name). */
  confirmText?: string;
}

/** Confirmation for one endpoint action: what will happen, how to undo it, a reason. */
export function EndpointActionDialog({ device, action, onClose, onDone }: {
  device: Device;
  action: PendingAction | null;
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
  const confirmed = !action?.confirmText || confirm.trim().toLowerCase() === action.confirmText.toLowerCase();
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!action) return;
    setBusy(true);
    setError(null);
    try {
      await api.queueCommand(device.id, { type: action.type, reason: reason.trim(), params: action.params });
      onDone();
      close();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal open={!!action} onClose={close} title={action ? `${action.title}: ${device.hostname}` : ""}>
      {action && (
        <form className="space-y-3" onSubmit={submit}>
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-3">What will happen</h3>
            <div className="mt-1 space-y-1.5 text-sm text-ink-2">{action.what}</div>
          </div>
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-3">How to undo</h3>
            <div className="mt-1 text-sm text-ink-2">{action.undo}</div>
          </div>
          <p className="text-xs text-ink-3">
            The agent runs it at its next poll (about a minute while the device is online); the request and the result are recorded in the
            audit log and in the device's Commands tab.
          </p>
          {error && (
            <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
              {error}
            </div>
          )}
          <Field label="Reason (recorded in the audit log)" id="ea-reason" required minLength={3} maxLength={500} value={reason}
            onChange={(e) => setReason(e.target.value)} placeholder="e.g. ticket INC-1234" />
          {action.confirmText && (
            <Field label={`Type "${action.confirmText}" to confirm`} id="ea-confirm" autoComplete="off" value={confirm}
              onChange={(e) => setConfirm(e.target.value)} />
          )}
          <div className="flex justify-end gap-2 pt-2">
            <Button onClick={close}>Cancel</Button>
            <Button type="submit" variant={action.danger ? "danger" : "primary"} disabled={busy || reason.trim().length < 3 || !confirmed}>
              {busy ? "Queuing…" : action.cta}
            </Button>
          </div>
        </form>
      )}
    </Modal>
  );
}

/** Status of the most recent command, shown inline next to what it acted on. */
export function InlineStatus({ cmd }: { cmd: DeviceCommand | undefined }) {
  if (!cmd) return null;
  const reboot = cmd.result_data?.reboot_required === true;
  return (
    <div className="mt-1 max-w-[22rem] text-[11px] text-ink-3">
      <Tag tone={STATUS_TONE[cmd.status]}>{cmd.status}</Tag>{" "}
      <span title={fmtTime(cmd.completed_at ?? cmd.created_at)}>{endpointActionLabel(cmd)} · {fmtAgo(cmd.completed_at ?? cmd.created_at)}</span>
      {reboot && <span className="ml-1 text-sev-medium">· restart required</span>}
      {cmd.output && (cmd.status === "failed" || cmd.status === "rejected") && (
        <div className="mt-0.5 line-clamp-2 break-words text-sev-high" title={cmd.output}>
          {cmd.output}
        </div>
      )}
    </div>
  );
}

function latest(commands: DeviceCommand[] | null, match: (c: DeviceCommand) => boolean) {
  return (commands ?? []).find(match); // newest first
}

function inFlight(c: DeviceCommand | undefined) {
  return !!c && (c.status === "pending" || c.status === "delivered");
}

function BlockedNote({ device }: { device: Device }) {
  const reason = actionsBlockedReason(device);
  if (!reason) return null;
  const update = device.endpoint_actions?.agent_update_required;
  return (
    <div className="mb-4 flex items-start gap-2 rounded border border-line bg-surface-1 px-3 py-2 text-sm text-ink-2" role="note">
      {update ? <Tag tone="warn">Agent update required</Tag> : <Tag>Not available</Tag>}
      <span>{reason}</span>
    </div>
  );
}

// ----------------------------------------------------------------------------- Actions tab

function usbActions(blocked: boolean): PendingAction {
  return blocked
    ? {
        type: "unblock_usb_storage",
        params: {},
        title: "Unblock USB storage",
        cta: "Unblock USB storage",
        what: (
          <>
            <p>
              The agent puts back exactly the values it saved when it blocked USB storage: the USBSTOR driver's previous start type and the
              previous Removable Disks deny policy (values that did not exist are removed again).
            </p>
            <p>Newly connected USB drives work again; a drive that is already plugged in may need to be reconnected.</p>
          </>
        ),
        undo: "Block USB storage again.",
      }
    : {
        type: "block_usb_storage",
        params: {},
        title: "Block USB storage",
        cta: "Block USB storage",
        danger: true,
        what: (
          <>
            <p>
              The agent saves the current values, then disables the USB mass-storage driver (<code>USBSTOR</code> Start = 4) and applies the
              Windows policy <em>Removable Disks: Deny read, write and execute access</em>.
            </p>
            <p>
              USB drives, external disks and SD cards can no longer be read or written, including ones already plugged in. Keyboards, mice,
              headsets, printers, phones and docking stations keep working.
            </p>
          </>
        ),
        undo: "Unblock USB storage restores the previous values exactly.",
      };
}

export function ActionsTab({ device, commands, reload, error }: {
  device: Device;
  commands: DeviceCommand[] | null;
  error: string | null;
  reload: () => void;
}) {
  const { can } = useAuth();
  const [pending, setPending] = useState<PendingAction | null>(null);
  const blocked = actionsBlockedReason(device);
  const usb = device.endpoint_actions?.usb_storage;
  const usbCmd = latest(commands, (c) => c.type === "block_usb_storage" || c.type === "unblock_usb_storage");
  const recent = (commands ?? []).filter(isEndpointAction).slice(0, 20);
  const isBlocked = usb?.state === "blocked";
  return (
    <div className="space-y-4">
      <BlockedNote device={device} />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title="USB storage">
          <div className="flex items-start gap-3">
            <Usb aria-hidden className="mt-0.5 h-5 w-5 text-ink-3" />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                {usb?.state === "blocked" ? <Tag tone="warn">Blocked</Tag> : usb?.state === "allowed" ? <Tag tone="good">Allowed</Tag> : <Tag>Unknown</Tag>}
                <span className="text-sm text-ink-2">{usb?.detail || (usb?.state ? "" : "Not reported by this device")}</span>
              </div>
              {usb?.blocked_by_agent && usb.blocked_since && (
                <p className="mt-1 text-xs text-ink-3">Blocked by the CNAPP agent since {fmtTime(usb.blocked_since)}.</p>
              )}
              {isBlocked && usb && !usb.blocked_by_agent && (
                <p className="mt-1 text-xs text-ink-3">
                  Blocked by a setting this agent did not make (for example Group Policy); Unblock will not change it.
                </p>
              )}
              <InlineStatus cmd={usbCmd} />
            </div>
            {can("admin") && (
              <Button
                variant={isBlocked ? "default" : "danger"}
                disabled={!!blocked || inFlight(usbCmd)}
                title={blocked ?? (inFlight(usbCmd) ? "Waiting for the agent" : undefined)}
                onClick={() => setPending(usbActions(isBlocked))}
              >
                {isBlocked ? "Unblock USB storage" : "Block USB storage"}
              </Button>
            )}
          </div>
        </Card>
        <Card title="Services and software">
          <p className="text-sm text-ink-2">
            Stop, start or disable a service from the <strong>Services</strong> tab (its previous startup type is saved so it can be restored
            exactly), and uninstall a program from the <strong>Software</strong> tab (silent MSI or the program's own silent uninstaller only).
          </p>
          <p className="mt-2 text-xs text-ink-3">
            Protected services (this agent, core Windows, networking and security services) cannot be stopped or disabled. The agent never
            uninstalls itself.
          </p>
        </Card>
      </div>
      <Card title="Recent endpoint actions">
        <ErrorNote error={error} />
        {recent.length === 0 ? (
          <Empty>No endpoint actions yet.</Empty>
        ) : (
          <Table head={["Requested", "Action", "Status", "Result"]}>
            {recent.map((c) => (
              <tr key={c.id} className="align-top">
                <td className="px-3 py-2 text-xs">
                  {fmtTime(c.created_at)}
                  <div className="text-ink-3">{c.requested_by_email}</div>
                </td>
                <td className="px-3 py-2 text-sm">
                  {endpointActionLabel(c)}
                  <div className="max-w-[16rem] text-xs text-ink-3">{c.reason}</div>
                </td>
                <td className="px-3 py-2">
                  <Tag tone={STATUS_TONE[c.status]}>{c.status}</Tag>
                  <div className="mt-0.5 text-[11px] text-ink-3">{c.completed_at ? fmtAgo(c.completed_at) : c.delivered_at ? "running" : "queued"}</div>
                </td>
                <td className="max-w-[28rem] px-3 py-2">
                  {c.exit_code !== null && c.exit_code !== undefined && <div className="text-xs text-ink-3">exit code {c.exit_code}</div>}
                  {c.result_data?.reboot_required === true && <Tag tone="warn">Restart required</Tag>}
                  {c.output && <pre className="max-h-24 overflow-auto whitespace-pre-wrap break-words text-[11px] text-ink-2">{c.output}</pre>}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
      <EndpointActionDialog device={device} action={pending} onClose={() => setPending(null)} onDone={reload} />
    </div>
  );
}

// ----------------------------------------------------------------------------- Services tab

function serviceAction(s: DeviceServiceRow, action: ServiceAction): PendingAction {
  const name = `${s.display_name || s.name} (${s.name})`;
  const start = START_TYPE_LABEL[s.start_type] ?? s.start_type;
  switch (action) {
    case "stop":
      return {
        type: "manage_service", params: { service: s.name, action }, title: `Stop ${s.display_name || s.name}`, cta: "Stop service", danger: true,
        what: <p>The agent asks Windows to stop {name} and waits up to a minute for it to stop. Its startup type stays <strong>{start}</strong>, so Windows may start it again at the next restart or when another program needs it.</p>,
        undo: "Start the service again.",
      };
    case "start":
      return {
        type: "manage_service", params: { service: s.name, action }, title: `Start ${s.display_name || s.name}`, cta: "Start service",
        what: <p>The agent asks Windows to start {name} and waits up to a minute for it to run. The startup type is not changed.</p>,
        undo: "Stop the service.",
      };
    case "disable":
      return {
        type: "manage_service", params: { service: s.name, action }, title: `Disable ${s.display_name || s.name}`, cta: "Set to Disabled", danger: true,
        what: (
          <>
            <p>The agent saves the current startup type (<strong>{start}</strong>) on the device, then sets {name} to <strong>Disabled</strong>.</p>
            <p>The service keeps its current state ({s.status.replace("_", " ")}) until it is stopped or the device restarts; after that Windows will not start it. Stop it as well to take effect now.</p>
          </>
        ),
        undo: <>Restore startup type puts back exactly <strong>{start}</strong>.</>,
      };
    case "restore":
      return {
        type: "manage_service", params: { service: s.name, action }, title: `Restore ${s.display_name || s.name}`, cta: "Restore startup type",
        what: <p>The agent sets the startup type of {name} back to the value it saved when the service was disabled. The service is not started; start it afterwards if needed.</p>,
        undo: "Disable the service again.",
      };
  }
}

export function ServicesTab({ device, commands, reload }: { device: Device; commands: DeviceCommand[] | null; reload: () => void }) {
  const { can } = useAuth();
  const [q, setQ] = useState("");
  const [pending, setPending] = useState<PendingAction | null>(null);
  const { data, error, reload: reloadServices } = useApi(() => endpointActionsApi.services(device.id, q.trim() || undefined), [device.id, q], 30000);
  const blocked = actionsBlockedReason(device);
  const protectedSet = new Set((device.endpoint_actions?.protected_services ?? []).map((s) => s.toLowerCase()));
  // Linux servers: the systemd services are listed read-only (the agent never changes a service there).
  const readOnly = device.os_family === "linux";
  const admin = can("admin") && !readOnly;
  return (
    <div>
      {!readOnly && <BlockedNote device={device} />}
      <Card
        title={`${readOnly ? "systemd services" : "Services"}${data ? ` (${data.length})` : ""}`}
        actions={
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by name" aria-label="Filter services"
            className="w-56 rounded border border-line bg-surface-2 px-2 py-1 text-sm text-ink" />
        }
      >
        <ErrorNote error={error} />
        {data && data.length === 0 ? (
          <Empty>
            {device.os_family !== "windows" && device.os_family !== "linux"
              ? "Services are reported by Windows and Linux devices only in this version."
              : q
                ? "No service matches this filter."
                : `No services reported yet: agents ${device.endpoint_actions?.min_agent_version ?? "1.4.0"}+ send them with each check-in.`}
          </Empty>
        ) : (
          <Table head={["Service", "Status", "Startup type", admin ? "Actions" : ""]}>
            {(data ?? []).map((s) => {
              const isProtected = protectedSet.has(s.name.toLowerCase());
              const last = latest(commands, (c) => c.type === "manage_service" && String(c.params.service ?? "").toLowerCase() === s.name.toLowerCase());
              const busy = inFlight(last);
              const why = blocked ?? (busy ? "An action on this service is in progress" : null);
              const protectedWhy = "Protected: this agent, core Windows, networking and security services cannot be stopped or disabled";
              return (
                <tr key={s.name} className="align-top">
                  <td className="px-3 py-1.5">
                    <div className="flex items-center gap-1.5">
                      {s.display_name || s.name}
                      {isProtected && <Lock aria-label="protected" className="h-3.5 w-3.5 text-ink-3" />}
                    </div>
                    <div className="font-mono text-[11px] text-ink-3">{s.name}</div>
                    <InlineStatus cmd={last} />
                  </td>
                  <td className="px-3 py-1.5"><Tag tone={SERVICE_STATUS_TONE[s.status] ?? "default"}>{s.status.replace("_", " ")}</Tag></td>
                  <td className="px-3 py-1.5 text-xs text-ink-2">{START_TYPE_LABEL[s.start_type] ?? s.start_type}</td>
                  <td className="px-3 py-1.5">
                    {admin && (
                      <div className="flex flex-wrap gap-1.5">
                        {s.status === "running" || s.status === "start_pending" ? (
                          <Button variant="danger" disabled={!!why || isProtected} title={isProtected ? protectedWhy : why ?? "Stop the service"}
                            onClick={() => setPending(serviceAction(s, "stop"))}>Stop</Button>
                        ) : (
                          <Button disabled={!!why || s.start_type === "disabled"} title={s.start_type === "disabled" ? "Disabled: restore its startup type first" : why ?? "Start the service"}
                            onClick={() => setPending(serviceAction(s, "start"))}>Start</Button>
                        )}
                        {s.start_type === "disabled" ? (
                          <Button disabled={!!why} title={why ?? "Restore the startup type saved when it was disabled"} onClick={() => setPending(serviceAction(s, "restore"))}>
                            Restore startup type
                          </Button>
                        ) : (
                          <Button variant="danger" disabled={!!why || isProtected} title={isProtected ? protectedWhy : why ?? "Set the startup type to Disabled"}
                            onClick={() => setPending(serviceAction(s, "disable"))}>Disable</Button>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </Table>
        )}
      </Card>
      <EndpointActionDialog device={device} action={pending} onClose={() => setPending(null)} onDone={() => { reload(); reloadServices(); }} />
    </div>
  );
}

// ----------------------------------------------------------------------------- Software tab: uninstall

/** Why a program cannot be uninstalled by the agent (null: it can be tried). */
function uninstallBlockedReason(device: Device, s: DeviceSoftware): string | null {
  const blocked = actionsBlockedReason(device);
  if (blocked) return blocked;
  if (/^cnapp (endpoint )?agent/i.test(s.name)) return "The agent never uninstalls itself";
  if (s.source === "registry_user") return "Per-user install: the agent runs as LocalSystem and cannot remove it; use a script";
  if (s.source !== "registry_hklm64" && s.source !== "registry_hklm32") return "Not a Windows program from the registry inventory";
  return null;
}

function uninstallAction(s: DeviceSoftware): PendingAction {
  const msi = PRODUCT_CODE_RE.test(s.identifier);
  return {
    type: "uninstall_software",
    params: { identifier: s.identifier, source: s.source },
    title: `Uninstall ${s.name}`,
    cta: "Uninstall",
    danger: true,
    confirmText: s.name,
    what: (
      <>
        {msi ? (
          <p>
            The agent runs <code className="break-all">msiexec /x {s.identifier} /qn /norestart</code> silently as LocalSystem.
          </p>
        ) : (
          <p>
            The agent runs the program's own silent uninstaller (its registered <code>QuietUninstallString</code>). If the program has none,
            the agent refuses and nothing changes; use a script instead.
          </p>
        )}
        <p>
          {s.name} {s.version} is removed without prompting the signed-in user, who may lose unsaved work in it. The device is never restarted;
          if the uninstaller needs a restart, the result says so. The software list is refreshed afterwards.
        </p>
      </>
    ),
    undo: "There is no undo: reinstall the program (for example with a script or your software distribution tool).",
  };
}

export function UninstallCell({ device, software, commands, onAsk }: {
  device: Device;
  software: DeviceSoftware;
  commands: DeviceCommand[] | null;
  onAsk: (a: PendingAction) => void;
}) {
  const last = latest(commands, (c) => c.type === "uninstall_software" && c.params.identifier === software.identifier && c.params.source === software.source);
  const why = uninstallBlockedReason(device, software) ?? (inFlight(last) ? "An uninstall is in progress" : null);
  return (
    <div>
      <Button variant="danger" disabled={!!why} title={why ?? "Uninstall silently"} onClick={() => onAsk(uninstallAction(software))}>
        Uninstall
      </Button>
      <InlineStatus cmd={last} />
    </div>
  );
}
