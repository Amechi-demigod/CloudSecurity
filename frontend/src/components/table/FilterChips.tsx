import { X } from "lucide-react";

export interface FilterChip {
  /** Filter name, e.g. "Class". */
  label: string;
  /** Chosen value, e.g. "Server". */
  value: string;
  onRemove: () => void;
}

/** "Filtered by" row: one removable chip per active filter and a "Clear all". Renders nothing without chips. */
export function FilterChips({ chips, onClearAll }: { chips: FilterChip[]; onClearAll?: () => void }) {
  if (chips.length === 0) return null;
  return (
    <div className="mb-3 flex flex-wrap items-center gap-2 text-xs" role="group" aria-label="Active filters">
      <span className="text-ink-3">Filtered by</span>
      {chips.map((c) => (
        <span key={`${c.label}:${c.value}`} className="inline-flex items-center gap-1 rounded-full border border-line bg-surface-2 py-0.5 pl-2.5 pr-1 text-ink">
          <span className="text-ink-3">{c.label}:</span> <span className="font-medium">{c.value}</span>
          <button
            type="button"
            onClick={c.onRemove}
            aria-label={`Remove filter ${c.label} ${c.value}`}
            className="flex h-5 w-5 items-center justify-center rounded-full text-ink-3 hover:bg-line hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <X aria-hidden className="h-3 w-3" />
          </button>
        </span>
      ))}
      {onClearAll && (
        <button type="button" onClick={onClearAll} className="rounded px-1 text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
          Clear all
        </button>
      )}
    </div>
  );
}
