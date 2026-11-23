import { useState, type ReactNode } from "react";
import { Drawer } from "../ui";

export interface DetailRow {
  label: string;
  value: ReactNode;
  /** Plain text to copy; the Copy button shows only when this is set. */
  copy?: string;
}

/** The full text of a row whose cells were cut short: label / value pairs with a Copy button where useful. */
export function DetailDrawer({ open, onClose, title, sub, rows }: { open: boolean; onClose: () => void; title: ReactNode; sub?: ReactNode; rows: DetailRow[] }) {
  const [copied, setCopied] = useState<string | null>(null);
  const doCopy = (label: string, text: string) => {
    try {
      void navigator.clipboard.writeText(text).catch(() => {});
    } catch {
      /* clipboard unavailable */
    }
    setCopied(label);
    setTimeout(() => setCopied((c) => (c === label ? null : c)), 1500);
  };
  return (
    <Drawer open={open} onClose={onClose} title={title}>
      {sub != null && <p className="-mt-2 mb-4 text-sm text-ink-3">{sub}</p>}
      <dl className="divide-y divide-line/60 text-sm">
        {rows.map((r) => (
          <div key={r.label} className="flex items-start justify-between gap-4 py-2.5">
            <div className="min-w-0">
              <dt className="text-xs text-ink-3">{r.label}</dt>
              <dd className="mt-0.5 break-words text-ink">{r.value ?? <span className="text-ink-3">None</span>}</dd>
            </div>
            {r.copy && (
              <button
                type="button"
                onClick={() => doCopy(r.label, r.copy!)}
                aria-label={`Copy ${r.label}`}
                className="shrink-0 rounded border border-line px-2 py-0.5 text-xs text-ink-2 hover:bg-surface-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                {copied === r.label ? "Copied" : "Copy"}
              </button>
            )}
          </div>
        ))}
      </dl>
    </Drawer>
  );
}
