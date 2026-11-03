// Connectors & scans -> Directories -> Microsoft Entra ID + Intune: choose one of the organisation's Azure
// connectors (its app registration is reused, its secret never copied), grant the read-only Microsoft Graph
// application permissions with the copyable script, then Test & save (checks each permission and licence).
import { useMemo, useState, type FormEvent } from "react";
import { directoryApi, type DirectorySource, type EntraConfig, type EntraScope, type SyncRun } from "../directoryApi";
import { entraCliScript, entraPowerShellScript, errMsg, neededPermissions } from "../lib/directory";
import { useApi } from "../lib/useApi";
import { CodeBox, RunResult } from "./directoryShared";
import { Button, ErrorNote, Field, Tag } from "./ui";

type EntraSource = Extract<DirectorySource, { type: "entra" }>;

const PARTS: { scope: EntraScope; label: string; hint: string }[] = [
  { scope: "users", label: "Users", hint: "Enabled / disabled, last sign-in, department, UPN" },
  { scope: "roles", label: "Admin roles", hint: "Privileged directory roles (Global Administrator, ...)" },
  { scope: "devices", label: "Entra devices", hint: "Joined, hybrid joined and registered devices" },
  { scope: "intune", label: "Intune devices", hint: "Compliance, encryption, last check-in, serial, primary user" },
];

export function EntraForm({ source, onDone, onCancel }: { source: EntraSource | null; onDone: (s: DirectorySource) => void; onCancel: () => void }) {
  const info = useApi(directoryApi.azureConnectors, []);
  const c = source?.config;
  const [name, setName] = useState(source?.name ?? "");
  const [connectorId, setConnectorId] = useState<EntraConfig["connector_id"] | "">(c?.connector_id ?? "");
  const [scopes, setScopes] = useState<EntraScope[]>(c?.scopes ?? ["users", "roles", "devices", "intune"]);
  const [staleDays, setStaleDays] = useState(c?.stale_days ?? 90);
  const [intervalHours, setIntervalHours] = useState(c?.interval_hours ?? 6);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState<DirectorySource | null>(source);
  const [run, setRun] = useState<SyncRun | null>(null);
  const [shell, setShell] = useState<"cli" | "ps">("cli");
  const id = source?.id ?? "new";

  const connectors = info.data?.connectors ?? [];
  const chosen = connectors.find((x) => x.id === (connectorId || (connectors.length === 1 ? connectors[0].id : "")));
  const perms = useMemo(() => neededPermissions(info.data?.permissions ?? [], scopes), [info.data, scopes]);
  const script = useMemo(() => {
    const o = { clientId: chosen?.client_id ?? "", tenantId: chosen?.tenant_id ?? "", perms };
    return shell === "cli" ? entraCliScript(o) : entraPowerShellScript(o);
  }, [chosen, perms, shell]);

  function toggle(s: EntraScope, on: boolean) {
    setScopes((prev) => {
      const next = on ? [...prev, s] : prev.filter((x) => x !== s);
      // Admin roles flag users: they need the users part.
      return !next.includes("users") ? next.filter((x) => x !== "roles") : next;
    });
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setErr(null);
    if (!chosen) return setErr("Choose the Azure connector whose app registration reads the directory.");
    if (!chosen.usable) return setErr(chosen.reason);
    if (scopes.length === 0) return setErr("Choose at least one part to read.");
    const config = { connector_id: chosen.id, scopes, stale_days: staleDays, interval_hours: intervalHours };
    setBusy(true);
    setRun(null);
    try {
      const s = saved
        ? await directoryApi.updateSource(saved.id, { name: name.trim(), config })
        : await directoryApi.createSource({ type: "entra", name: name.trim() || "Microsoft Entra ID", config });
      setSaved(s);
      setRun(await directoryApi.test(s.id));
    } catch (ex) {
      setErr(errMsg(ex));
    } finally {
      setBusy(false);
    }
  }

  const label = "mb-1 block text-sm font-medium text-ink-2";
  return (
    <div className="grid grid-cols-1 gap-5 lg:grid-cols-[1fr_1.1fr]">
      <form className="min-w-0 space-y-3" onSubmit={submit} aria-label="Microsoft Entra ID source">
        <Field label="Name" id={`de-${id}-name`} required maxLength={128} placeholder="e.g. Contoso Entra ID" value={name} onChange={(e) => setName(e.target.value)} />
        <fieldset>
          <legend className={label}>Azure connector</legend>
          {info.error && <ErrorNote error={info.error} />}
          {info.data && connectors.length === 0 && (
            <p className="rounded border border-line bg-surface-2 px-3 py-2 text-sm text-ink-2">
              No Azure connector yet. Connect Azure above (Cloud connectors → Azure) with a tenant ID, client ID and client secret: its app
              registration is reused to read the directory, with the Microsoft Graph permissions below added to it.
            </p>
          )}
          <ul className="space-y-1.5">
            {connectors.map((x) => {
              const taken = x.source && x.source.id !== source?.id;
              const disabled = !x.usable || !!taken;
              return (
                <li key={x.id}>
                  <label className={`flex items-start gap-2 rounded border px-3 py-2 text-sm ${chosen?.id === x.id ? "border-accent bg-accent/5" : "border-line"} ${disabled ? "opacity-70" : "cursor-pointer"}`}>
                    <input
                      type="radio"
                      name={`de-${id}-conn`}
                      className="mt-1"
                      disabled={disabled}
                      checked={chosen?.id === x.id}
                      onChange={() => setConnectorId(x.id)}
                    />
                    <span className="min-w-0">
                      <span className="font-medium text-ink">{x.name}</span>
                      <span className="block break-all text-xs text-ink-3">
                        tenant {x.tenant_id || "—"} · app {x.client_id || "—"} · {x.auth_mode.replace("_", " ")}
                      </span>
                      {!x.usable && <span className="mt-0.5 block text-xs text-sev-high">{x.reason}</span>}
                      {taken && <span className="mt-0.5 block text-xs text-ink-2">This tenant is already read by “{x.source!.name}”: one source per tenant.</span>}
                    </span>
                  </label>
                </li>
              );
            })}
          </ul>
          <p className="mt-1 text-xs text-ink-3">Only the connector&apos;s app registration is reused; its client secret stays in the connector settings and is never copied.</p>
        </fieldset>
        <fieldset>
          <legend className={label}>Read</legend>
          <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
            {PARTS.map((p) => (
              <label key={p.scope} className="flex items-start gap-2 text-sm">
                <input
                  type="checkbox"
                  className="mt-1"
                  checked={scopes.includes(p.scope)}
                  disabled={p.scope === "roles" && !scopes.includes("users")}
                  onChange={(e) => toggle(p.scope, e.target.checked)}
                />
                <span>
                  <span className="font-medium text-ink">{p.label}</span>
                  <span className="block text-xs text-ink-3">{p.hint}</span>
                </span>
              </label>
            ))}
          </div>
          <p className="mt-1.5 text-xs text-ink-3">
            Parts your tenant is not licensed for (Intune; last sign-in needs Entra ID P1/P2) are skipped with a note; the rest still syncs.
          </p>
        </fieldset>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Stale after (days)" id={`de-${id}-stale`} type="number" min={7} max={3650} value={staleDays} onChange={(e) => setStaleDays(Number(e.target.value))} />
          <Field label="Sync every (hours)" id={`de-${id}-every`} type="number" min={1} max={168} value={intervalHours} onChange={(e) => setIntervalHours(Number(e.target.value))} />
        </div>
        <ErrorNote error={err} />
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <Button type="submit" variant="primary" disabled={busy || !chosen?.usable}>
            {busy ? "Testing…" : "Test & save"}
          </Button>
          <Button disabled={busy} onClick={() => (saved && !source ? onDone(saved) : onCancel())}>
            {saved && !source ? "Done" : "Cancel"}
          </Button>
          {saved && run && <Button onClick={() => onDone(saved)}>{run.status === "succeeded" ? "Finish" : "Close (keep settings)"}</Button>}
        </div>
        {run && (
          <div className="pt-1">
            <RunResult run={run} error={null} />
            {saved && !source && run.status === "succeeded" && (
              <p className="mt-1.5 text-xs text-ink-3">The source is saved; the first full sync starts on schedule (within a minute) or with Sync now.</p>
            )}
          </div>
        )}
      </form>
      <div className="min-w-0">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-[13px] font-semibold text-ink">Grant read-only Microsoft Graph permissions</h3>
          <div role="tablist" aria-label="Script" className="flex overflow-hidden rounded border border-line text-xs">
            {(["cli", "ps"] as const).map((k) => (
              <button
                key={k}
                type="button"
                role="tab"
                aria-selected={shell === k}
                onClick={() => setShell(k)}
                className={`px-2.5 py-1 ${shell === k ? "bg-accent/15 font-semibold text-accent" : "text-ink-2 hover:bg-surface-2"}`}
              >
                {k === "cli" ? "Azure CLI" : "PowerShell"}
              </button>
            ))}
          </div>
        </div>
        <CodeBox
          testId="entra-permission-script"
          text={script}
          note="Adds application permissions to the connector's app and grants admin consent. All are read-only; nothing is written to the tenant by the platform."
        />
        <table className="mt-1 w-full text-left text-xs">
          <caption className="sr-only">Microsoft Graph permissions</caption>
          <thead>
            <tr className="text-ink-3">
              <th className="py-1 pr-3 font-semibold">Permission</th>
              <th className="py-1 font-semibold">Why</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line/60">
            {perms.map((p) => (
              <tr key={p.name}>
                <td className="whitespace-nowrap py-1.5 pr-3 align-top font-mono text-[11px] text-ink">
                  {p.name} {!p.scope && <Tag>optional</Tag>}
                </td>
                <td className="py-1.5 text-ink-2">{p.why}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
