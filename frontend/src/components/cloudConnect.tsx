import { Check, Copy, ExternalLink } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { ApiError } from "../api";
import {
  CLOUD_COLOR,
  CLOUD_NAME,
  CLOUD_SHELL,
  CREDENTIAL_FIELDS,
  SETUP_NOTE,
  SETUP_SCRIPT,
  type CredentialField,
} from "../lib/cloudSetup";
import { orgApi, type ConnectorConfig, type Provider } from "../orgApi";
import { Button, Card, ErrorNote, Field } from "./ui";

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : e instanceof Error ? e.message : String(e);
}

/** Coloured provider tile (decorative: the name is always written next to it). */
export function ProviderMark({ provider, size = 18 }: { provider: Provider; size?: number }) {
  return (
    <span
      aria-hidden
      className="inline-block shrink-0 rounded"
      style={{ width: size, height: size, background: CLOUD_COLOR[provider] }}
    />
  );
}

/** The setup script on a dark panel with one Copy button (clipboard, else select the text for Ctrl/⌘+C). */
function ScriptBox({ provider }: { provider: Provider }) {
  const script = SETUP_SCRIPT[provider];
  const pre = useRef<HTMLPreElement>(null);
  const [state, setState] = useState<"idle" | "copied" | "select">("idle");

  useEffect(() => {
    setState("idle");
  }, [provider]);
  useEffect(() => {
    if (state !== "copied") return;
    const t = setTimeout(() => setState("idle"), 2500);
    return () => clearTimeout(t);
  }, [state]);

  function selectAll() {
    const el = pre.current;
    const sel = window.getSelection();
    if (!el || !sel) return;
    const range = document.createRange();
    range.selectNodeContents(el);
    sel.removeAllRanges();
    sel.addRange(range);
    setState("select");
  }

  async function copy() {
    if (!navigator.clipboard?.writeText) return selectAll();
    try {
      await navigator.clipboard.writeText(script);
      setState("copied");
    } catch {
      selectAll();
    }
  }

  return (
    <div>
      <div className="relative">
        <pre
          ref={pre}
          data-testid="setup-script"
          className="overflow-auto whitespace-pre-wrap rounded-xl bg-slate-900 py-3.5 pl-4 pr-24 font-mono text-[12.5px] leading-relaxed text-slate-200 ring-1 ring-inset ring-white/5"
        >
          {script.split("\n").map((line, i) => (
            <span key={i} className={line.startsWith("#") ? "text-slate-400" : undefined}>
              {line}
              {"\n"}
            </span>
          ))}
        </pre>
        <button
          type="button"
          onClick={() => void copy()}
          className="absolute right-2.5 top-2.5 inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs font-semibold text-slate-200 hover:bg-slate-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {state === "copied" ? <Check aria-hidden className="h-3.5 w-3.5" /> : <Copy aria-hidden className="h-3.5 w-3.5" />}
          {state === "copied" ? "Copied" : "Copy"}
        </button>
      </div>
      <p role="status" aria-live="polite" className="mt-2 min-h-4 text-xs text-ink-3">
        {state === "copied"
          ? "Copied to the clipboard."
          : state === "select"
            ? "Your browser blocked the clipboard: the script is selected, press Ctrl+C (⌘C on a Mac)."
            : "Run it as someone who can create identities and grant roles. Nothing is sent to us until you paste the values."}
      </p>
      <p className="mt-1 text-xs text-ink-3">{SETUP_NOTE[provider]}</p>
    </div>
  );
}

function initialValues(provider: Provider, current: ConnectorConfig | undefined) {
  const v: Record<string, string> = {};
  for (const f of CREDENTIAL_FIELDS[provider]) {
    if (f.secret) continue;
    const cur = current?.stored ? current.config?.[f.name] : undefined;
    v[f.name] = Array.isArray(cur) ? cur.join(", ") : (cur ?? "");
  }
  return v;
}

/**
 * Credential form of one provider. "Test & save" tries the credentials (read-only calls on the
 * server) and only stores them if they work; the first save of a provider also starts its first scan.
 */
export function ConnectionForm({
  provider,
  current,
  edit = false,
  onSaved,
  onCancel,
}: {
  provider: Provider;
  current: ConnectorConfig | undefined;
  edit?: boolean;
  onSaved: (saved: ConnectorConfig) => void;
  onCancel?: () => void;
}) {
  const fields = CREDENTIAL_FIELDS[provider];
  const [values, setValues] = useState<Record<string, string>>(() => initialValues(provider, current));
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const advanced = fields.filter((f) => f.advanced);

  useEffect(() => {
    setValues(initialValues(provider, current));
    setSecrets({});
    setErr(null);
  }, [provider, current]);

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const config: Record<string, unknown> = {};
      for (const f of fields) {
        if (f.secret) continue;
        const raw = values[f.name] ?? "";
        config[f.name] = f.list ? raw.split(/[\s,;]+/).filter(Boolean) : raw.trim();
      }
      const sec = Object.fromEntries(Object.entries(secrets).filter(([, v]) => v !== ""));
      const saved = await orgApi.saveConnector(provider, { enabled: true, config, secrets: sec, test: true, start_first_scan: true });
      setSecrets({});
      onSaved(saved);
    } catch (ex) {
      setErr(errMsg(ex));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!window.confirm(`Disconnect ${CLOUD_NAME[provider]}? The stored credentials are deleted; scan results stay.`)) return;
    setBusy(true);
    try {
      const r = await orgApi.deleteConnector(provider);
      onSaved(r);
    } catch (ex) {
      setErr(errMsg(ex));
    } finally {
      setBusy(false);
    }
  }

  function input(f: CredentialField) {
    const id = `${provider}-${f.name}`;
    if (!f.secret)
      return (
        <Field key={f.name} label={f.label} id={id} hint={f.hint} value={values[f.name] ?? ""} spellCheck={false} autoComplete="off"
          onChange={(e) => setValues((v) => ({ ...v, [f.name]: e.target.value }))} />
      );
    const stored = current?.stored ? current.secrets?.[f.name] : null;
    const cls =
      "block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40";
    return (
      <div key={f.name}>
        <label htmlFor={id} className="mb-1 block text-sm font-medium text-ink-2">
          {f.label}
        </label>
        {f.multiline ? (
          <textarea id={id} rows={4} spellCheck={false} value={secrets[f.name] ?? ""} aria-describedby={`${id}-hint`}
            placeholder={stored ? `Stored (${stored}). Paste a new key to replace it.` : '{ "type": "service_account", … }'}
            onChange={(e) => setSecrets((v) => ({ ...v, [f.name]: e.target.value }))}
            className={`${cls} font-mono text-xs`} />
        ) : (
          <input id={id} type="password" autoComplete="new-password" value={secrets[f.name] ?? ""} aria-describedby={`${id}-hint`}
            placeholder={stored ? `Stored (${stored}). Leave empty to keep it.` : ""}
            onChange={(e) => setSecrets((v) => ({ ...v, [f.name]: e.target.value }))}
            className={`${cls} text-sm`} />
        )}
        <p id={`${id}-hint`} className="mt-1 text-xs text-ink-3">
          {f.hint}
        </p>
      </div>
    );
  }

  return (
    <form className="space-y-3" onSubmit={save} aria-label={`${CLOUD_NAME[provider]} credentials`}>
      {current?.from_environment && (
        <p className="text-xs text-ink-2">
          The server&apos;s environment configures {CLOUD_NAME[provider]} today. Values saved here replace it for this organisation.
        </p>
      )}
      {fields.filter((f) => !f.advanced).map(input)}
      {advanced.length > 0 && (
        <details className="rounded border border-line px-3 py-2" open={advanced.some((f) => !!values[f.name])}>
          <summary className="cursor-pointer text-sm font-medium text-ink-2">Advanced</summary>
          <div className="mt-2 space-y-3">{advanced.map(input)}</div>
        </details>
      )}
      <ErrorNote error={err} />
      <div className="flex flex-wrap items-center gap-2 pt-1">
        <Button type="submit" variant="primary" disabled={busy}>
          {busy ? "Testing…" : "Test & save"}
        </Button>
        <Button
          disabled={busy}
          onClick={() => {
            setValues(Object.fromEntries(Object.keys(values).map((k) => [k, ""])));
            setSecrets({});
            setErr(null);
          }}
        >
          Clear
        </Button>
        {onCancel && (
          <Button disabled={busy} onClick={onCancel}>
            Cancel
          </Button>
        )}
        {edit && current?.stored && (
          <span className="ml-auto">
            <Button variant="danger" disabled={busy} onClick={() => void remove()}>
              Disconnect
            </Button>
          </span>
        )}
      </div>
    </form>
  );
}

/** "Connect a cloud account": steps, provider tabs, the setup script and the credential form. */
export function ConnectCloud({
  providers,
  configs,
  initial,
  title = "Connect a cloud account to start scanning",
  onSaved,
  onCancel,
}: {
  providers: Provider[];
  configs: ConnectorConfig[] | null;
  initial?: Provider;
  title?: string;
  onSaved: (saved: ConnectorConfig) => void;
  onCancel?: () => void;
}) {
  const [provider, setProvider] = useState<Provider>(initial && providers.includes(initial) ? initial : providers[0]);
  useEffect(() => {
    if (initial && providers.includes(initial)) setProvider(initial);
  }, [initial, providers]);
  const shell = CLOUD_SHELL[provider];
  const step = (n: number, text: string) => (
    <li className="flex items-center gap-2 text-sm text-ink-2">
      <span className="grid h-[22px] w-[22px] place-items-center rounded-full bg-accent/10 text-xs font-semibold text-accent">{n}</span>
      {text}
    </li>
  );

  return (
    <Card className="mb-4">
      <div className="px-1 py-1">
        <h2 className="text-base font-semibold text-ink">{title}</h2>
        <p className="mt-1 text-sm text-ink-3">
          Takes about 2 minutes. The script creates a <b className="text-ink-2">read-only</b> identity: it can list and read
          configuration, never change anything.
        </p>
        <ol className="mt-3.5 flex flex-wrap items-center gap-2.5" aria-label="Steps">
          {step(1, "Copy the script")}
          <li aria-hidden className="text-ink-3">→</li>
          {step(2, `Run it in ${shell.short}`)}
          <li aria-hidden className="text-ink-3">→</li>
          {step(3, "Paste the values and test")}
        </ol>
        <div role="tablist" aria-label="Cloud provider" className="mb-3.5 mt-4 flex flex-wrap gap-2">
          {providers.map((p) => (
            <button
              key={p}
              type="button"
              role="tab"
              id={`tab-${p}`}
              aria-selected={p === provider}
              aria-controls="connect-panel"
              onClick={() => setProvider(p)}
              className={`flex items-center gap-2 rounded-lg border bg-surface-1 px-4 py-2 text-sm font-semibold transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
                p === provider ? "border-accent text-ink ring-1 ring-accent" : "border-line text-ink-2 hover:bg-surface-2"
              }`}
            >
              <ProviderMark provider={p} />
              {CLOUD_NAME[p]}
            </button>
          ))}
        </div>
        <div id="connect-panel" role="tabpanel" aria-labelledby={`tab-${provider}`} className="grid grid-cols-1 gap-5 lg:grid-cols-[1.25fr_1fr]">
          <div className="min-w-0">
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <h3 className="text-[13px] font-semibold text-ink">Step 1–2 · Run in {shell.name}</h3>
              <a href={shell.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-[13px] text-accent hover:underline">
                Open {provider === "aws" ? "CloudShell" : "Cloud Shell"}
                <ExternalLink aria-hidden className="h-3.5 w-3.5" />
                <span className="sr-only">(opens in a new tab)</span>
              </a>
            </div>
            <ScriptBox provider={provider} />
          </div>
          <div className="min-w-0">
            <h3 className="mb-2 text-[13px] font-semibold text-ink">Step 3 · Paste the values</h3>
            <ConnectionForm
              key={provider}
              provider={provider}
              current={configs?.find((c) => c.provider === provider)}
              onSaved={onSaved}
              onCancel={onCancel}
            />
          </div>
        </div>
      </div>
    </Card>
  );
}
