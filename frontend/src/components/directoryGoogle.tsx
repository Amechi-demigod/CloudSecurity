// Connectors & scans -> Directories -> Google Workspace: a service account with domain-wide delegation
// (read-only scopes) impersonating a Workspace admin. The JSON key is uploaded once, stored encrypted and never
// shown again (only its client email and key id). Test & save checks every scope.
import { useMemo, useState, type ChangeEvent, type FormEvent } from "react";
import { directoryApi, type DirectorySource, type GoogleScope, type SyncRun } from "../directoryApi";
import { errMsg, googleServiceAccountScript } from "../lib/directory";
import { useApi } from "../lib/useApi";
import { CodeBox, CopyValue, RunResult } from "./directoryShared";
import { Button, ErrorNote, Field, Tag } from "./ui";

type GoogleSource = Extract<DirectorySource, { type: "google" }>;

const PARTS: { scope: GoogleScope; label: string; hint: string }[] = [
  { scope: "users", label: "Users", hint: "Suspended / archived, last login, department" },
  { scope: "roles", label: "Admin roles", hint: "Super Admin and other pre-built admin roles" },
  { scope: "endpoints", label: "Endpoints", hint: "Windows / macOS / Linux (endpoint management)" },
  { scope: "chromeos", label: "ChromeOS devices", hint: "Chromebooks: status, last sync, user" },
  { scope: "mobile", label: "Mobile devices", hint: "Android / iOS: status, last sync, user" },
];

interface KeyFacts {
  text: string;
  email: string;
  keyId: string;
  clientId: string;
}

/** Read the public facts of a key file in the browser (the key text is only sent to the server on save). */
function readKey(text: string): KeyFacts | string {
  try {
    const k = JSON.parse(text) as Record<string, unknown>;
    if (k.type !== "service_account" || typeof k.client_email !== "string" || typeof k.private_key !== "string")
      return "This is not a service-account JSON key.";
    return { text, email: k.client_email, keyId: String(k.private_key_id ?? "").slice(0, 8), clientId: String(k.client_id ?? "") };
  } catch {
    return "This file is not JSON.";
  }
}

export function GoogleForm({ source, onDone, onCancel }: { source: GoogleSource | null; onDone: (s: DirectorySource) => void; onCancel: () => void }) {
  const info = useApi(directoryApi.googleScopes, []);
  const c = source?.config;
  const [name, setName] = useState(source?.name ?? "");
  const [adminEmail, setAdminEmail] = useState(c?.admin_email ?? "");
  const [customerId, setCustomerId] = useState(c?.customer_id ?? "my_customer");
  const [scopes, setScopes] = useState<GoogleScope[]>(c?.scopes ?? ["users", "roles", "endpoints", "chromeos", "mobile"]);
  const [staleDays, setStaleDays] = useState(c?.stale_days ?? 90);
  const [intervalHours, setIntervalHours] = useState(c?.interval_hours ?? 6);
  const [key, setKey] = useState<KeyFacts | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState<DirectorySource | null>(source);
  const [run, setRun] = useState<SyncRun | null>(null);
  const id = source?.id ?? "new";
  const stored = saved?.type === "google" ? saved.config : null;
  const clientId = key?.clientId || stored?.client_id || "";

  // Domain-wide delegation scope string: the selected parts (+ group members for admin roles).
  const scopeString = useMemo(() => {
    const parts = new Set<string>(scopes);
    return (info.data?.scopes ?? [])
      .filter((s) => (s.part ? parts.has(s.part) : parts.has("roles")))
      .map((s) => s.scope)
      .join(",");
  }, [info.data, scopes]);

  function toggle(s: GoogleScope, on: boolean) {
    setScopes((prev) => {
      const next = on ? [...prev, s] : prev.filter((x) => x !== s);
      return !next.includes("users") ? next.filter((x) => x !== "roles") : next;
    });
  }

  async function pickFile(e: ChangeEvent<HTMLInputElement>) {
    setErr(null);
    const f = e.target.files?.[0];
    e.target.value = "";
    if (!f) return;
    if (f.size > 16384) return setErr("That file is too large for a service-account key.");
    const r = readKey(await f.text());
    if (typeof r === "string") return setErr(r);
    setKey(r);
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setErr(null);
    if (!key && !saved?.has_credential) return setErr("Upload the service account's JSON key.");
    if (scopes.length === 0) return setErr("Choose at least one part to read.");
    const config = { admin_email: adminEmail.trim(), customer_id: customerId.trim() || "my_customer", scopes, stale_days: staleDays, interval_hours: intervalHours };
    setBusy(true);
    setRun(null);
    try {
      const s = saved
        ? await directoryApi.updateSource(saved.id, { name: name.trim(), config, ...(key ? { google_key: key.text } : {}) })
        : await directoryApi.createSource({ type: "google", name: name.trim() || "Google Workspace", config, google_key: key?.text });
      setSaved(s);
      setKey(null);
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
      <form className="min-w-0 space-y-3" onSubmit={submit} aria-label="Google Workspace source">
        <Field label="Name" id={`dg-${id}-name`} required maxLength={128} placeholder="e.g. Example Workspace" value={name} onChange={(e) => setName(e.target.value)} />
        <Field
          label="Admin to impersonate"
          id={`dg-${id}-admin`}
          type="email"
          required
          maxLength={254}
          spellCheck={false}
          placeholder="it-admin@example.org"
          value={adminEmail}
          onChange={(e) => setAdminEmail(e.target.value)}
          hint="A Workspace admin whose roles can read users, devices and admin roles (e.g. a Super Admin, or a custom read-only admin role). Only read-only scopes are ever requested."
        />
        <div>
          <span className={label}>Service-account key</span>
          <div className="flex flex-wrap items-center gap-2">
            <label className="inline-flex cursor-pointer items-center rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">
              {key || saved?.has_credential ? "Replace key file…" : "Upload JSON key…"}
              <input type="file" accept="application/json,.json" className="sr-only" onChange={(e) => void pickFile(e)} />
            </label>
            {key ? (
              <span className="text-xs text-ink-2">
                Ready to upload: key {key.keyId}… for <span className="font-medium">{key.email}</span>
              </span>
            ) : saved?.has_credential ? (
              <span className="text-xs text-ink-2">
                Stored: <span className="font-medium">{saved.credential_username_hint}</span>
              </span>
            ) : (
              <span className="text-xs text-ink-3">The file from step 1</span>
            )}
          </div>
          <p className="mt-1 text-xs text-ink-3">Stored encrypted on the server and never shown again; only the client email and key id are displayed.</p>
        </div>
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
          <p className="mt-1.5 text-xs text-ink-3">A part whose scope is not delegated, or whose API is off, is skipped with a note; the rest still syncs.</p>
        </fieldset>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Stale after (days)" id={`dg-${id}-stale`} type="number" min={7} max={3650} value={staleDays} onChange={(e) => setStaleDays(Number(e.target.value))} />
          <Field label="Sync every (hours)" id={`dg-${id}-every`} type="number" min={1} max={168} value={intervalHours} onChange={(e) => setIntervalHours(Number(e.target.value))} />
        </div>
        <details className="rounded border border-line px-3 py-2" open={customerId !== "my_customer"}>
          <summary className="cursor-pointer text-sm font-medium text-ink-2">Advanced: customer ID</summary>
          <div className="mt-2">
            <Field
              label="Customer ID"
              id={`dg-${id}-customer`}
              spellCheck={false}
              maxLength={21}
              value={customerId}
              onChange={(e) => setCustomerId(e.target.value)}
              hint="my_customer = the admin's own Workspace account. Otherwise the C0… ID from Admin console → Account → Account settings."
            />
          </div>
        </details>
        <ErrorNote error={err} />
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <Button type="submit" variant="primary" disabled={busy}>
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
            {run.status !== "succeeded" && (
              <p className="mt-1.5 text-xs text-ink-3">Domain-wide delegation changes can take a few minutes (up to 24 h) to apply at Google.</p>
            )}
          </div>
        )}
      </form>
      <div className="min-w-0 space-y-4">
        <div>
          <h3 className="mb-2 text-[13px] font-semibold text-ink">1 · Create the service account and its key</h3>
          <CodeBox testId="google-sa-script" text={googleServiceAccountScript()} note="Google Cloud Shell. The service account gets no Google Cloud roles." />
        </div>
        <div>
          <h3 className="mb-2 text-[13px] font-semibold text-ink">2 · Authorise it in the Admin console (domain-wide delegation)</h3>
          <ol className="mb-2 list-decimal space-y-1 pl-5 text-xs text-ink-2">
            <li>
              Admin console → Security → Access and data control → API controls → <span className="font-medium">Manage domain-wide delegation</span> →{" "}
              <span className="font-medium">Add new</span>.
            </li>
            <li>Paste the client ID and the OAuth scopes below, then Authorise.</li>
          </ol>
          <div className="space-y-2">
            <CopyValue label="Client ID" value={clientId || "Upload the key (or see the gcloud output)"} />
            <CopyValue label="OAuth scopes (comma-separated)" value={scopeString} />
          </div>
        </div>
        <div>
          <h3 className="mb-1 text-[13px] font-semibold text-ink">3 · Upload the key and Test & save</h3>
          <ul className="space-y-1 text-xs text-ink-2">
            {(info.data?.scopes ?? []).map((s) => (
              <li key={s.scope} className="flex flex-wrap items-baseline gap-x-2">
                <code className="font-mono text-[11px] text-ink">{s.scope.replace("https://www.googleapis.com/auth/", "")}</code>
                {!s.part && <Tag>optional</Tag>}
                <span className="text-ink-3">{s.why}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
