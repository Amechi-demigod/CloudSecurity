import { MoreHorizontal } from "lucide-react";
import { useEffect, useRef, useState } from "react";

export type MenuItem = { label: string; onSelect: () => void; danger?: boolean; disabled?: boolean };

/** A small "⋯" menu for the secondary actions of a table row. Closes on outside click and Escape. */
export function OverflowMenu({ label, items }: { label: string; items: MenuItem[] }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const click = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    const key = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", click);
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("mousedown", click);
      document.removeEventListener("keydown", key);
    };
  }, [open]);
  if (items.length === 0) return null;
  return (
    <div ref={ref} className="relative inline-block text-left">
      <button
        type="button"
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
        className="rounded border border-line bg-surface-2 p-1.5 text-ink-2 hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        <MoreHorizontal aria-hidden className="h-4 w-4" />
      </button>
      {open && (
        <div role="menu" className="absolute right-0 z-20 mt-1 min-w-[10rem] rounded border border-line bg-surface-1 py-1 shadow-lg">
          {items.map((it) => (
            <button
              key={it.label}
              type="button"
              role="menuitem"
              disabled={it.disabled}
              onClick={() => {
                setOpen(false);
                it.onSelect();
              }}
              className={`block w-full px-3 py-1.5 text-left text-sm hover:bg-surface-2 disabled:opacity-50 ${it.danger ? "text-sev-critical" : "text-ink"}`}
            >
              {it.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
