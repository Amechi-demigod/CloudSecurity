import { useId, useState, type KeyboardEvent } from "react";
import type { FixLink, FixMethod, FixState } from "../vulnFixesApi";
import { Tag } from "./ui";

/** A command the reader can copy. Display only: nothing here runs on a device. */
export function CodeBlock({ label, code }: { label: string; code: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="mt-2">
      <div className="mb-1 text-xs text-ink-3">{label}</div>
      <div className="flex items-start gap-2 rounded border border-line bg-surface-2 px-3 py-2">
        <code className="min-w-0 flex-1 whitespace-pre-wrap break-all font-mono text-xs text-ink">{code}</code>
        <button
          type="button"
          className="shrink-0 rounded px-1.5 py-0.5 text-xs text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          onClick={() => {
            navigator.clipboard?.writeText(code).then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            }, () => undefined);
          }}
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
    </div>
  );
}

export function LinkList({ links }: { links?: FixLink[] }) {
  if (!links || links.length === 0) return null;
  return (
    <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs">
      {links.map((l) => (
        <li key={l.url}>
          <a className="text-accent hover:underline" href={l.url} target="_blank" rel="noreferrer">
            {l.label}
          </a>
        </li>
      ))}
    </ul>
  );
}

/** "How to fix" tabs (Windows Update | Intune | WSUS / manual, winget | vendor updater ...). WAI-ARIA tabs. */
export function MethodTabs({ methods, label = "How to fix" }: { methods: FixMethod[]; label?: string }) {
  const uid = useId();
  const [sel, setSel] = useState(0);
  if (methods.length === 0) return null;
  const idx = Math.min(sel, methods.length - 1);
  const m = methods[idx];
  const tabId = (i: number) => `${uid}-tab-${i}`;
  const onKey = (e: KeyboardEvent) => {
    const next = { ArrowRight: idx + 1, ArrowLeft: idx - 1, Home: 0, End: methods.length - 1 }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    const n = (next + methods.length) % methods.length;
    setSel(n);
    document.getElementById(tabId(n))?.focus();
  };
  return (
    <div>
      <div role="tablist" aria-label={label} onKeyDown={onKey} className="flex flex-wrap gap-1 border-b border-line">
        {methods.map((x, i) => (
          <button
            key={x.id}
            id={tabId(i)}
            role="tab"
            type="button"
            aria-selected={i === idx}
            aria-controls={`${uid}-panel`}
            tabIndex={i === idx ? 0 : -1}
            onClick={() => setSel(i)}
            className={`-mb-px border-b-2 px-3 py-1.5 text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
              i === idx ? "border-accent font-medium text-ink" : "border-transparent text-ink-3 hover:text-ink"
            }`}
          >
            {x.label}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`${uid}-panel`} aria-labelledby={tabId(idx)} className="pt-3">
        <ol className="list-decimal space-y-1.5 pl-5 text-sm text-ink-2">
          {m.steps.map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ol>
        {m.commands.map((c) => (
          <CodeBlock key={c.code} label={c.label} code={c.code} />
        ))}
        <LinkList links={m.links} />
      </div>
    </div>
  );
}

const STATE_TONE: Record<string, "default" | "warn" | "good" | "accent" | "critical"> = {
  offered: "accent",
  restart_pending: "warn",
  failing: "critical",
  not_offered: "default",
  unknown: "default",
};

/** Where a device is with an OS update (from its Windows Update report). */
export function StateChip({ state }: { state: FixState | null }) {
  if (!state || !state.label) return null;
  return (
    <span title={state.detail}>
      <Tag tone={STATE_TONE[state.code] ?? "default"}>{state.label}</Tag>
    </span>
  );
}

export function PdfLink({ href, children }: { href: string; children: string }) {
  return (
    <a
      href={href}
      className="inline-block rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink transition hover:bg-line focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
    >
      {children}
    </a>
  );
}
