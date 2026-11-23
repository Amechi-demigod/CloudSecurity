import type { ReactNode } from "react";
import { isNone } from "./isNone";

/** The grey dash for "none" (screen readers read "None"). */
export function None() {
  return (
    <span aria-label="None" className="text-ink-3">
      –
    </span>
  );
}

/** One-line cell content: never wraps, cut with an ellipsis, the full text in the tooltip. */
export function TextCell({ children, title, mono, muted }: { children: ReactNode; title?: string; mono?: boolean; muted?: boolean }) {
  const full = title ?? (typeof children === "string" || typeof children === "number" ? String(children) : undefined);
  return (
    <span title={full} className={`block max-w-full overflow-hidden text-ellipsis whitespace-nowrap ${mono ? "font-mono text-xs" : ""} ${muted ? "text-ink-3" : ""}`}>
      {children}
    </span>
  );
}

/**
 * Two-line first-column cell: bold name over a muted sub line. With `onOpen` the name is a button that opens
 * the detail drawer.
 */
export function NameCell({ name, sub, onOpen, title, openLabel }: { name: ReactNode; sub?: ReactNode; onOpen?: () => void; title?: string; openLabel?: string }) {
  const full = title ?? (typeof name === "string" ? name : undefined);
  return (
    <div className="min-w-0">
      {onOpen ? (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onOpen();
          }}
          title={full}
          aria-label={openLabel ?? (typeof name === "string" ? `Open details for ${name}` : undefined)}
          className="block max-w-full overflow-hidden text-ellipsis whitespace-nowrap rounded text-left font-semibold text-ink hover:text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {name}
        </button>
      ) : (
        <span title={full} className="block overflow-hidden text-ellipsis whitespace-nowrap font-semibold text-ink">
          {name}
        </span>
      )}
      {sub != null && sub !== "" && (
        <span title={typeof sub === "string" ? sub : undefined} className="block overflow-hidden text-ellipsis whitespace-nowrap text-xs text-ink-3">
          {sub}
        </span>
      )}
    </div>
  );
}

/** Number cell: right-aligned, tabular figures, a grey dash for 0 / empty / "unknown" / "-". Pair it with a column `align: "right"`. */
export function NumCell({ value, title }: { value: number | string | null | undefined; title?: string }) {
  return (
    <span className="block text-right tabular-nums" title={title}>
      {isNone(value) ? <None /> : value}
    </span>
  );
}

/** A group of pills that never wraps (cut off with the cell instead). */
export function PillRow({ children }: { children: ReactNode }) {
  return <span className="flex flex-nowrap items-center gap-1 overflow-hidden whitespace-nowrap [&>*]:shrink-0">{children}</span>;
}
