import { useId, useState, type FormEvent } from "react";
import type { MfaSetup } from "../api";
import { Button } from "./ui";

const inputCls =
  "block w-full rounded-md border border-line bg-surface-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40";

/** One-time code input (TOTP or recovery code). */
export function CodeInput({
  id,
  value,
  onChange,
  allowRecovery = false,
  autoFocus = false,
  invalid = false,
  describedBy,
}: {
  id: string;
  value: string;
  onChange: (v: string) => void;
  allowRecovery?: boolean;
  autoFocus?: boolean;
  invalid?: boolean;
  describedBy?: string;
}) {
  return (
    <div>
      <label htmlFor={id} className="mb-1.5 block text-sm font-medium text-ink-2">
        {allowRecovery ? "Authentication code or recovery code" : "Authentication code"}
      </label>
      <input
        id={id}
        name="one-time-code"
        autoComplete="one-time-code"
        inputMode={allowRecovery ? "text" : "numeric"}
        pattern={allowRecovery ? undefined : "[0-9 ]{6,7}"}
        maxLength={allowRecovery ? 24 : 7}
        spellCheck={false}
        autoFocus={autoFocus}
        required
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-invalid={invalid}
        aria-describedby={describedBy}
        placeholder={allowRecovery ? "123456 or xxxx-xxxx-xxxx-xxxx" : "123456"}
        className={`${inputCls} font-mono tracking-widest`}
      />
    </div>
  );
}

/** QR code + manual key for adding the account to an authenticator app. */
export function TotpSetupDetails({ setup }: { setup: MfaSetup }) {
  const [showKey, setShowKey] = useState(false);
  const grouped = setup.secret.replace(/(.{4})/g, "$1 ").trim();
  return (
    <div className="flex flex-col items-center gap-3 sm:flex-row sm:items-start">
      {/* Rendered by our own backend as an SVG data URI: the secret never goes to a third-party service. */}
      <img
        src={setup.qr_svg}
        alt="QR code to add this account to your authenticator app"
        className="h-44 w-44 shrink-0 rounded-md border border-line bg-white p-1"
      />
      <div className="min-w-0 space-y-2 text-sm text-ink-2">
        <ol className="list-decimal space-y-1 pl-4">
          <li>Open an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password, …).</li>
          <li>Scan the QR code, or enter the setup key manually.</li>
          <li>Enter the {setup.digits}-digit code the app shows.</li>
        </ol>
        <button
          type="button"
          className="text-xs font-medium text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          onClick={() => setShowKey((v) => !v)}
          aria-expanded={showKey}
        >
          {showKey ? "Hide setup key" : "Can't scan? Show the setup key"}
        </button>
        {showKey && (
          <div className="rounded border border-line bg-surface-2 px-2 py-1.5">
            <code className="block break-all font-mono text-xs text-ink" aria-label="Setup key">
              {grouped}
            </code>
            <span className="mt-1 block text-[11px] text-ink-3">Time-based, SHA-1, {setup.digits} digits, {setup.period}s</span>
          </div>
        )}
      </div>
    </div>
  );
}

/** Shows freshly generated recovery codes once, with copy and download. */
export function RecoveryCodes({ codes, email }: { codes: string[]; email?: string }) {
  const [copied, setCopied] = useState(false);
  const text = codes.join("\n");

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }

  function download() {
    const header = `CloudSecurity CNAPP recovery codes${email ? ` for ${email}` : ""}\nGenerated ${new Date().toISOString()}\nEach code works once.\n\n`;
    const url = URL.createObjectURL(new Blob([header + text + "\n"], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "cnapp-recovery-codes.txt";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-3">
      <div role="status" className="rounded-md border border-sev-medium/50 bg-sev-medium/10 px-3 py-2 text-sm text-ink">
        Save these recovery codes somewhere safe. Each one signs you in once if you lose your authenticator.
        They will not be shown again.
      </div>
      <ul className="grid grid-cols-2 gap-x-4 gap-y-1 rounded-md border border-line bg-surface-2 px-4 py-3 font-mono text-sm text-ink" aria-label="Recovery codes">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-2">
        <Button onClick={copy}>{copied ? "Copied" : "Copy"}</Button>
        <Button onClick={download}>Download .txt</Button>
      </div>
    </div>
  );
}

/** Code entry form used by the enrolment flows (forced and self-service). */
export function VerifyCodeForm({
  submitLabel,
  busyLabel,
  onSubmit,
  allowRecovery = false,
  error,
}: {
  submitLabel: string;
  busyLabel: string;
  onSubmit: (code: string) => Promise<void>;
  allowRecovery?: boolean;
  error: string | null;
}) {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const id = useId();
  const errId = useId();

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    try {
      await onSubmit(code.trim());
    } finally {
      setBusy(false);
      setCode("");
    }
  }

  return (
    <form className="space-y-3" onSubmit={submit}>
      {error && (
        <div id={errId} role="alert" className="rounded-md border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm text-ink">
          {error}
        </div>
      )}
      <CodeInput id={id} value={code} onChange={setCode} allowRecovery={allowRecovery} autoFocus invalid={!!error}
        describedBy={error ? errId : undefined} />
      <Button type="submit" variant="primary" disabled={busy || !code.trim()}>
        {busy ? busyLabel : submitLabel}
      </Button>
    </form>
  );
}
