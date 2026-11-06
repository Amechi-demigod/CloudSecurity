import { Check, Copy } from "lucide-react";
import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";

/** A read-only code block: scrolls inside its box (never the page) and offers a copy button. */
export function CodeBlock({ code, label }: { code: string; label: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable (insecure context): the text stays selectable */
    }
  }
  return (
    <div className="relative">
      <pre
        tabIndex={0}
        aria-label={label}
        className="max-w-full overflow-x-auto rounded-lg border border-line bg-surface-2 p-3 pr-12 font-mono text-xs leading-relaxed text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        <code>{code}</code>
      </pre>
      <button
        type="button"
        onClick={copy}
        aria-label={`Copy ${label}`}
        className="absolute right-2 top-2 rounded border border-line bg-surface-1 p-1.5 text-ink-2 hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        {copied ? <Check aria-hidden className="h-3.5 w-3.5 text-good" /> : <Copy aria-hidden className="h-3.5 w-3.5" />}
      </button>
    </div>
  );
}

export interface FixTab {
  id: string;
  label: string;
  content: ReactNode;
}

/** Accessible tabs (role=tablist / tab / tabpanel, roving tabindex, Arrow / Home / End keys). */
export function Tabs({ tabs, label }: { tabs: FixTab[]; label: string }) {
  const [active, setActive] = useState(tabs[0]?.id);
  const uid = useId();
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});

  function onKey(e: KeyboardEvent<HTMLButtonElement>, i: number) {
    let n = -1;
    if (e.key === "ArrowRight") n = (i + 1) % tabs.length;
    else if (e.key === "ArrowLeft") n = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === "Home") n = 0;
    else if (e.key === "End") n = tabs.length - 1;
    if (n < 0) return;
    e.preventDefault();
    setActive(tabs[n].id);
    refs.current[tabs[n].id]?.focus();
  }

  return (
    <div>
      <div role="tablist" aria-label={label} className="mb-3 flex flex-wrap gap-1 border-b border-line">
        {tabs.map((t, i) => {
          const on = t.id === active;
          return (
            <button
              key={t.id}
              ref={(el) => {
                refs.current[t.id] = el;
              }}
              type="button"
              role="tab"
              id={`${uid}-tab-${t.id}`}
              aria-selected={on}
              aria-controls={`${uid}-panel-${t.id}`}
              tabIndex={on ? 0 : -1}
              onClick={() => setActive(t.id)}
              onKeyDown={(e) => onKey(e, i)}
              className={`-mb-px rounded-t border-b-2 px-3 py-1.5 text-sm font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
                on ? "border-accent text-ink" : "border-transparent text-ink-2 hover:text-ink"
              }`}
            >
              {t.label}
            </button>
          );
        })}
      </div>
      {tabs.map((t) => (
        <div
          key={t.id}
          role="tabpanel"
          id={`${uid}-panel-${t.id}`}
          aria-labelledby={`${uid}-tab-${t.id}`}
          hidden={t.id !== active}
          tabIndex={0}
          className="focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {t.content}
        </div>
      ))}
    </div>
  );
}
