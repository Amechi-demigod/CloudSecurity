// Directory discovery building blocks shared by every directory type (Connectors & scans -> Directories,
// IT assets -> Discovery): copyable script box, stat cell, run result, permission checks, source badges.
import { AlertTriangle, Check, CircleSlash, Copy, Network, RefreshCw, X } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { RECORD_LABEL, type PermissionCheck, type RecordRef, type ScopeStatus, type SyncRun } from "../directoryApi";
import { FINAL, RUN_COLOR, RUN_TEXT, RUN_TEXT_SERVER } from "../lib/directory";
import { ErrorNote, Tag } from "./ui";

export function StatCell({ label, value, sub, valueClass = "text-ink" }: { label: string; value: ReactNode; sub?: ReactNode; valueClass?: string }) {
  return (
    <div className="min-w-0 border-line py-1 sm:border-l sm:px-4 sm:first:border-l-0 sm:first:pl-0">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-ink-3">{label}</div>
      <div className={`mt-0.5 text-lg font-semibold ${valueClass}`}>{value}</div>
      {sub && <div className="text-xs text-ink-3">{sub}</div>}
    </div>
  );
}

/** Directory type mark: AD (network), Entra ID / Google (letter monogram in their brand-ish colour). */
export function DirectoryMark({ size = 18, type = "ad" }: { size?: number; type?: string }) {
  if (type === "entra" || type === "google") {
    const color = type === "entra" ? "#0078d4" : "#34a853";
    return (
      <span
        aria-hidden
        className="inline-grid shrink-0 place-items-center rounded font-bold text-white"
        style={{ width: size, height: size, background: color, fontSize: size * 0.42 }}
      >
        {type === "entra" ? "ID" : "G"}
      </span>
    );
  }
  return (
    <span aria-hidden className="inline-grid shrink-0 place-items-center rounded bg-accent/15 text-accent" style={{ width: size, height: size }}>
      <Network style={{ width: size * 0.62, height: size * 0.62 }} />
    </span>
  );
}

export function CodeBox({ text, note, testId = "directory-precheck" }: { text: string; note?: ReactNode; testId?: string }) {
  const pre = useRef<HTMLPreElement>(null);
  const [state, setState] = useState<"idle" | "copied" | "select">("idle");
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
      await navigator.clipboard.writeText(text);
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
          data-testid={testId}
          className="max-h-96 overflow-auto whitespace-pre-wrap rounded-xl bg-slate-900 py-3.5 pl-4 pr-24 font-mono text-[12px] leading-relaxed text-slate-200 ring-1 ring-inset ring-white/5"
        >
          {text.split("\n").map((line, i) => (
            <span key={i} className={line.trimStart().startsWith("#") ? "text-slate-400" : undefined}>
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
        {state === "copied" ? "Copied to the clipboard." : state === "select" ? "Your browser blocked the clipboard: the script is selected, press Ctrl+C." : note}
      </p>
    </div>
  );
}

/** Copyable one-liner (a client ID, a scope list). */
export function CopyValue({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 2000);
    return () => clearTimeout(t);
  }, [copied]);
  return (
    <div className="min-w-0">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-ink-3">{label}</div>
      <div className="mt-0.5 flex items-start gap-2">
        <code className="min-w-0 flex-1 break-all rounded border border-line bg-surface-2 px-2 py-1 font-mono text-xs text-ink">{value}</code>
        <button
          type="button"
          aria-label={`Copy ${label}`}
          onClick={() => void navigator.clipboard?.writeText(value).then(() => setCopied(true))}
          className="inline-flex shrink-0 items-center gap-1 rounded border border-line px-2 py-1 text-xs text-ink-2 hover:bg-surface-2"
        >
          {copied ? <Check aria-hidden className="h-3.5 w-3.5" /> : <Copy aria-hidden className="h-3.5 w-3.5" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
    </div>
  );
}

const CHECK_ICON: Record<string, { icon: typeof Check; cls: string; text: string }> = {
  ok: { icon: Check, cls: "text-good", text: "OK" },
  missing: { icon: X, cls: "text-sev-high", text: "Missing" },
  missing_permission: { icon: X, cls: "text-sev-high", text: "Missing" },
  unlicensed: { icon: CircleSlash, cls: "text-ink-3", text: "Not licensed" },
  error: { icon: AlertTriangle, cls: "text-sev-high", text: "Error" },
};

/** Test & save result of a cloud directory: one row per permission / licence check. */
export function CheckList({ checks }: { checks: PermissionCheck[] }) {
  return (
    <ul className="divide-y divide-line/60 rounded-lg border border-line text-sm" aria-label="Permission checks">
      {checks.map((c) => {
        const k = CHECK_ICON[c.status] ?? CHECK_ICON.error;
        const Icon = k.icon;
        const warnOnly = c.status !== "ok" && !c.required;
        return (
          <li key={c.id} className="flex items-start gap-2.5 px-3 py-2">
            <Icon aria-hidden className={`mt-0.5 h-4 w-4 shrink-0 ${warnOnly ? "text-sev-medium" : k.cls}`} />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-baseline gap-x-2">
                <span className="font-medium text-ink">{c.label}</span>
                <span className={`text-xs font-semibold ${warnOnly ? "text-sev-medium" : k.cls}`}>{k.text}</span>
                {!c.required && <span className="text-[11px] text-ink-3">optional</span>}
              </div>
              {c.detail && <div className="break-words text-xs text-ink-3">{c.detail}</div>}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

const PART_LABEL: Record<string, string> = {
  users: "Users",
  sign_in: "Last sign-in",
  roles: "Admin roles",
  eligible: "PIM eligible",
  devices: "Entra devices",
  intune: "Intune",
  chromeos: "ChromeOS",
  mobile: "Mobile",
  endpoints: "Endpoints",
};
const PART_STATUS: Record<string, string> = {
  ok: "",
  missing_permission: "no permission",
  unlicensed: "not licensed",
  not_enabled: "not enabled",
  error: "error",
  truncated: "capped",
};

/** Outcome of each part of the last server-side sync, e.g. "Intune · not licensed". */
export function ScopeChips({ status }: { status: Record<string, ScopeStatus> }) {
  // Fixed order (JSON key order is not preserved by every database).
  const order = Object.keys(PART_LABEL);
  const rank = (k: string) => (order.includes(k) ? order.indexOf(k) : order.length);
  const entries = Object.entries(status).sort((a, b) => rank(a[0]) - rank(b[0]));
  if (entries.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1.5" aria-label="Last sync by part">
      {entries.map(([part, s]) => (
        <span key={part} title={s.detail ?? ""}>
          <Tag tone={s.status === "ok" ? "good" : s.status === "unlicensed" ? "default" : "warn"}>
            {PART_LABEL[part] ?? part}
            {s.status === "ok" ? (s.count != null ? ` · ${s.count.toLocaleString()}` : "") : ` · ${PART_STATUS[s.status] ?? s.status}`}
          </Tag>
        </span>
      ))}
    </div>
  );
}

/** Where a computer / user record comes from: one small badge per directory record kind. */
export function SourceBadges({ refs, names }: { refs: RecordRef[]; names?: Record<string, string> }) {
  const kinds = Array.from(new Map(refs.map((r) => [r.kind && r.kind !== "user" ? r.kind : r.type, r])).entries());
  if (kinds.length === 0) return null;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {kinds.map(([k, r]) => (
        <span
          key={k}
          title={names?.[r.source_id] ?? undefined}
          className="rounded border border-line bg-surface-2 px-1.5 py-px text-[10px] font-semibold uppercase tracking-wide text-ink-2"
        >
          {RECORD_LABEL[k] || k}
        </span>
      ))}
    </span>
  );
}

/** Result of a test run: AD (collector bound and read a sample) or cloud (permission checks). */
export function RunResult({ run, error }: { run: SyncRun | null; error: string | null }) {
  if (error) return <ErrorNote error={error} />;
  if (!run) return <p className="text-sm text-ink-3">Queuing the test…</p>;
  if (run.checks.length > 0) {
    const ok = run.status === "succeeded";
    return (
      <div role="status" aria-live="polite" className="space-y-2">
        <p className={`text-sm font-medium ${ok ? "text-good" : "text-sev-high"}`}>
          {ok ? "All required permissions are in place." : "Some required permissions are missing: run the script, then Test & save again."}
        </p>
        <CheckList checks={run.checks} />
      </div>
    );
  }
  const done = FINAL.has(run.status);
  const server = run.device_id == null && run.trigger !== "test";
  return (
    <div role="status" aria-live="polite" className={`rounded-lg border px-3 py-2.5 text-sm ${run.status === "failed" ? "border-sev-high/60 bg-sev-high/10" : run.status === "succeeded" ? "border-good/60 bg-good/10" : "border-line bg-surface-2"}`}>
      <div className="flex items-center gap-2 font-medium text-ink">
        {!done && <RefreshCw aria-hidden className="h-3.5 w-3.5 animate-spin text-accent" />}
        <span className={RUN_COLOR[run.status]}>{(server ? RUN_TEXT_SERVER : RUN_TEXT)[run.status]}</span>
        {run.device_hostname && <span className="text-ink-3">on {run.device_hostname}</span>}
      </div>
      {run.status === "queued" && (
        <p className="mt-1 text-xs text-ink-3">Agents fetch commands about once a minute, so the collector picks the test up within ~1 minute.</p>
      )}
      {run.status === "running" && <p className="mt-1 text-xs text-ink-3">Connected collector is binding and reading a few objects…</p>}
      {run.status === "succeeded" && (
        <div className="mt-1 text-xs text-ink-2">
          Bound{run.server ? ` to ${run.server}` : ""} and read {run.computers_seen} computer(s) and {run.users_seen} user(s).
          {run.sample.length > 0 && <span className="text-ink-3"> Sample: {run.sample.map((s) => s.name).join(", ")}</span>}
        </div>
      )}
      {run.error && <p className="mt-1 break-words text-xs text-ink">{run.error}</p>}
    </div>
  );
}
