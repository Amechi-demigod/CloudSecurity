import { Check, ChevronDown, Search, SlidersHorizontal } from "lucide-react";
import { useId, useState, type ReactNode } from "react";

export type PillTone = "neutral" | "critical" | "high" | "medium" | "good" | "info";

const PILL_TONE: Record<PillTone, string> = {
  neutral: "border-line bg-surface-2 text-ink-2",
  critical: "border-sev-critical/60 bg-sev-critical/10 text-sev-critical",
  high: "border-sev-high/60 bg-sev-high/10 text-sev-high",
  medium: "border-sev-medium/60 bg-sev-medium/10 text-sev-medium",
  good: "border-good/60 bg-good/10 text-good",
  info: "border-accent/50 bg-accent/10 text-accent",
};

const PILL_ICON: Record<PillTone, string> = { neutral: "", critical: "!", high: "!", medium: "~", good: "✓", info: "i" };

/**
 * One-word status pill: 22px high, never wraps, an icon when the colour carries meaning (never colour alone).
 * Use it for state only ("Internet", "Sensitive", "New", "Not registered").
 */
export function Pill({ tone = "neutral", children, title }: { tone?: PillTone; children: ReactNode; title?: string }) {
  const icon = PILL_ICON[tone];
  return (
    <span title={title} className={`inline-flex h-[22px] items-center gap-1 whitespace-nowrap rounded-full border px-2 text-xs font-medium ${PILL_TONE[tone]}`}>
      {icon && (
        <span aria-hidden className="text-[10px] font-bold leading-none">
          {icon}
        </span>
      )}
      {children}
    </span>
  );
}

const CONTROL = "h-8 rounded border border-line bg-surface-2 text-sm text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent";

/** 32px search box for a filter bar. */
export function FilterSearch({ value, onChange, placeholder, label = "Search" }: { value: string; onChange: (v: string) => void; placeholder?: string; label?: string }) {
  return (
    <label className="relative">
      <span className="sr-only">{label}</span>
      <Search aria-hidden className="pointer-events-none absolute left-2 top-2 h-4 w-4 text-ink-3" />
      <input type="search" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder ?? label} className={`${CONTROL} w-56 pl-8 pr-2`} />
    </label>
  );
}

/** 32px select with the filter name inside it ("Type  All"). */
export function FilterSelect({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: (string | { value: string; label: string })[] }) {
  return (
    <label className={`inline-flex items-center gap-1.5 pl-2 text-xs text-ink-3 ${CONTROL}`}>
      <span className="whitespace-nowrap">{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)} className="h-full max-w-[11rem] rounded bg-transparent pr-1 text-sm text-ink focus:outline-none">
        {options.map((o) =>
          typeof o === "string" ? (
            <option key={o} value={o}>
              {o || "All"}
            </option>
          ) : (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ),
        )}
      </select>
    </label>
  );
}

/** Segmented control (All / Open / Fixed ...), 32px high. */
export function Segments<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: { value: T; label: string }[]; label: string }) {
  return (
    <div role="group" aria-label={label} className="inline-flex h-8 overflow-hidden rounded border border-line text-sm">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          aria-pressed={value === o.value}
          onClick={() => onChange(o.value)}
          className={`inline-flex items-center gap-1 px-3 font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${value === o.value ? "bg-accent text-white" : "bg-surface-2 text-ink-2 hover:bg-line"}`}
        >
          {value === o.value && <Check aria-hidden className="h-3.5 w-3.5" />}
          {o.label}
        </button>
      ))}
    </div>
  );
}

/**
 * One compact filter row (32px controls) with the result count on the right. Rarely used filters go in
 * `more`, shown under a "More filters" disclosure (`moreActive` = how many of them are set).
 */
export function FilterBar({ children, more, moreActive = 0, count }: { children?: ReactNode; more?: ReactNode; moreActive?: number; count?: ReactNode }) {
  const [open, setOpen] = useState(moreActive > 0);
  const id = useId();
  return (
    <div className="mb-3">
      <div className="flex flex-wrap items-center gap-2">
        {children}
        {more && (
          <button
            type="button"
            aria-expanded={open}
            aria-controls={id}
            onClick={() => setOpen((o) => !o)}
            className={`inline-flex items-center gap-1.5 ${CONTROL} px-2.5 font-medium text-ink-2 hover:bg-line`}
          >
            <SlidersHorizontal aria-hidden className="h-3.5 w-3.5" />
            More filters{moreActive > 0 ? ` (${moreActive})` : ""}
            <ChevronDown aria-hidden className={`h-3.5 w-3.5 transition ${open ? "rotate-180" : ""}`} />
          </button>
        )}
        {count != null && (
          <span className="ml-auto text-sm text-ink-3" aria-live="polite">
            {count}
          </span>
        )}
      </div>
      {more && open && (
        <div id={id} className="mt-2 flex flex-wrap items-center gap-2 rounded-lg border border-line bg-surface-2/40 p-2">
          {more}
        </div>
      )}
    </div>
  );
}
