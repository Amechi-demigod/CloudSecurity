import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { ApiError, api, type DeviceDetail as Device, type LibraryScript, type ScriptParam } from "../../api";
import { RiskTag } from "../../components/approvals";
import { Button, Empty, Field, Modal } from "../../components/ui";
import { buildParams, initialParamValues } from "../../lib/scripts";
import { useApi } from "../../lib/useApi";

const INPUT_CLS =
  "block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40";

function ParamInput({ p, value, onChange }: { p: ScriptParam; value: string | boolean; onChange: (v: string | boolean) => void }) {
  const id = `sp-${p.name}`;
  const label = `${p.name}${p.required === false ? " (optional)" : ""}`;
  if (p.type === "bool") {
    return (
      <label className="flex items-start gap-2 text-sm">
        <input type="checkbox" className="mt-1" checked={value === true} onChange={(e) => onChange(e.target.checked)} />
        <span>
          {p.name}
          {p.description && <span className="block text-xs text-ink-3">{p.description}</span>}
        </span>
      </label>
    );
  }
  if (p.type === "enum") {
    return (
      <div>
        <label htmlFor={id} className="mb-1 block text-sm font-medium text-ink-2">
          {label}
        </label>
        <select id={id} className={INPUT_CLS} value={String(value)} onChange={(e) => onChange(e.target.value)}
          aria-describedby={p.description ? `${id}-hint` : undefined}>
          {p.required === false && <option value="">—</option>}
          {(p.values ?? []).map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
        {p.description && <p id={`${id}-hint`} className="mt-1 text-xs text-ink-3">{p.description}</p>}
      </div>
    );
  }
  return (
    <Field
      label={label}
      id={id}
      type={p.type === "int" ? "number" : "text"}
      min={p.min}
      max={p.max}
      step={p.type === "int" ? 1 : undefined}
      maxLength={p.max_length}
      required={p.required !== false}
      value={String(value)}
      onChange={(e) => onChange(e.target.value)}
      hint={[p.description, p.type === "string" && p.pattern ? `Format: ${p.pattern}` : ""].filter(Boolean).join(" · ") || undefined}
    />
  );
}

function ScriptForm({ device, script, onDone }: { device: Device; script: LibraryScript; onDone: (msg: string) => void }) {
  const [values, setValues] = useState(() => initialParamValues(script.parameters));
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const built = buildParams(script.parameters, values);
    if (built.error) {
      setError(built.error);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await api.runScript({ device_id: device.id, script: script.name, parameters: built.params, reason: reason.trim() });
      onDone(
        res.mode === "approval"
          ? "Approval requested: a second admin must approve this run on the Approvals page before it is sent."
          : "Queued: the agent runs it on its next poll. Follow it on the Commands tab.",
      );
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="space-y-3" onSubmit={submit}>
      <div className="rounded border border-line bg-surface-2 p-3 text-sm">
        <div className="flex items-center justify-between gap-2">
          <span className="font-mono">{script.name}</span>
          <RiskTag risk={script.risk} />
        </div>
        <p className="mt-1 text-xs text-ink-2">{script.description}</p>
        <p className="mt-1 text-xs text-ink-3">
          {script.requires_approval ? "Needs approval by a second admin before it runs." : "Low risk: runs without a second approval."} Timeout{" "}
          {script.timeout_seconds}s.
        </p>
      </div>
      {script.parameters.map((p) => (
        <ParamInput key={p.name} p={p} value={values[p.name] ?? ""} onChange={(v) => setValues((s) => ({ ...s, [p.name]: v }))} />
      ))}
      <Field label="Reason (recorded in the audit log)" id="sp-reason" required minLength={3} maxLength={500} value={reason}
        onChange={(e) => setReason(e.target.value)} />
      {error && (
        <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
          {error}
        </div>
      )}
      <div className="flex justify-end pt-2">
        <Button type="submit" variant={script.risk === "low" ? "primary" : "danger"} disabled={busy || reason.trim().length < 3}>
          {busy ? "Submitting…" : script.requires_approval ? "Request approval" : "Run script"}
        </Button>
      </div>
    </form>
  );
}

/** Pick a script from the signed library for this device's platform and run it. */
export function RunScriptDialog({ device, open, onClose, onDone }: { device: Device; open: boolean; onClose: () => void; onDone: () => void }) {
  const lib = useApi(() => (open ? api.scripts() : Promise.resolve(null)), [open]);
  const [name, setName] = useState("");
  const [result, setResult] = useState<string | null>(null);
  const scripts = (lib.data?.scripts ?? []).filter((s) => s.platform === device.os_family);
  const script = scripts.find((s) => s.name === name) ?? null;

  function close() {
    setName("");
    setResult(null);
    onClose();
  }

  return (
    <Modal open={open} onClose={close} title={`Run script: ${device.hostname}`}>
      {result ? (
        <div className="space-y-3">
          <p role="status" className="text-sm">
            {result}
          </p>
          <div className="flex justify-end">
            <Button onClick={close}>Close</Button>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-xs text-ink-3">
            Only scripts from the signed library are available (see <Link to="/devices/scripts" className="text-accent hover:underline">Scripts</Link>).
          </p>
          {lib.error && (
            <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
              {lib.error}
            </div>
          )}
          {lib.data && scripts.length === 0 ? (
            <Empty>No library scripts for this platform.</Empty>
          ) : (
            <div>
              <label htmlFor="sp-script" className="mb-1 block text-sm font-medium text-ink-2">
                Script
              </label>
              <select id="sp-script" className={INPUT_CLS} value={name} onChange={(e) => setName(e.target.value)}>
                <option value="">— choose a script —</option>
                {scripts.map((s) => (
                  <option key={s.name} value={s.name}>
                    {s.name} ({s.risk} risk{s.requires_approval ? ", needs 2nd admin" : ""})
                  </option>
                ))}
              </select>
            </div>
          )}
          {script && (
            <ScriptForm
              key={script.name}
              device={device}
              script={script}
              onDone={(msg) => {
                setResult(msg);
                onDone();
              }}
            />
          )}
        </div>
      )}
    </Modal>
  );
}
