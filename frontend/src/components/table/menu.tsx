import { ChevronDown } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";
import { Link } from "react-router-dom";

export interface MenuItem {
  label: string;
  /** Goes to another page. */
  to?: string;
  onClick?: () => void;
  hint?: string;
  hidden?: boolean;
}

/** Secondary-actions button ("More") with a small menu. Escape or a click outside closes it. */
export function MoreMenu({ label = "More", items }: { label?: string; items: MenuItem[] }) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const id = useId();
  useEffect(() => {
    if (!open) return;
    const down = (e: MouseEvent) => !root.current?.contains(e.target as Node) && setOpen(false);
    const key = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", down);
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("mousedown", down);
      document.removeEventListener("keydown", key);
    };
  }, [open]);
  const shown = items.filter((i) => !i.hidden);
  if (shown.length === 0) return null;
  const cls = "block w-full rounded px-3 py-1.5 text-left text-sm text-ink hover:bg-surface-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent";
  return (
    <div ref={root} className="relative">
      <button
        type="button"
        aria-haspopup="true"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen((o) => !o)}
        className="inline-flex items-center gap-1.5 rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        {label}
        <ChevronDown aria-hidden className="h-3.5 w-3.5" />
      </button>
      {open && (
        <div id={id} role="group" aria-label={label} className="absolute right-0 z-30 mt-1 w-56 rounded-lg border border-line bg-surface-1 p-1 shadow-xl">
          {shown.map((i) =>
            i.to ? (
              <Link key={i.label} to={i.to} title={i.hint} className={cls} onClick={() => setOpen(false)}>
                {i.label}
              </Link>
            ) : (
              <button
                key={i.label}
                type="button"
                title={i.hint}
                className={cls}
                onClick={() => {
                  setOpen(false);
                  i.onClick?.();
                }}
              >
                {i.label}
              </button>
            ),
          )}
        </div>
      )}
    </div>
  );
}
