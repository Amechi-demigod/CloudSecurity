import { ArrowDown, ArrowUp, ArrowUpDown, ChevronRight, Inbox, type LucideIcon } from "lucide-react";
import { isValidElement, useEffect, useRef, type InputHTMLAttributes, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { SEV_COLOR } from "../lib/format";
import type { SortState } from "../lib/useSort";

const SEV_ICON: Record<string, string> = { critical: "!!", high: "!", medium: "~", low: "-", info: "i" };

/** Severity pill: colored marker + icon + text label (never color alone). */
export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded border border-line bg-surface-2 px-1.5 py-0.5 text-xs font-medium capitalize text-ink">
      <span
        className="inline-flex h-3.5 w-3.5 items-center justify-center rounded-sm text-[9px] font-bold text-black"
        style={{ background: SEV_COLOR[severity] ?? SEV_COLOR.info }}
        aria-hidden
      >
        {SEV_ICON[severity]}
      </span>
      {severity}
    </span>
  );
}

export function Tag({ children, tone = "default" }: { children: ReactNode; tone?: "default" | "warn" | "good" | "accent" | "critical" }) {
  const tones = {
    default: "border-line text-ink-2",
    critical: "border-sev-critical/60 bg-sev-critical/10 text-sev-critical",
    warn: "border-sev-high/60 text-sev-high",
    good: "border-good/60 text-good",
    accent: "border-accent/60 text-accent",
  };
  return <span className={`inline-block rounded border px-1.5 py-0.5 text-[11px] ${tones[tone]}`}>{children}</span>;
}

export function Card({ title, actions, children, className = "" }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-xl border border-line bg-surface-1 shadow-sm shadow-black/10 ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between border-b border-line px-4 py-2.5">
          <h2 className="text-sm font-semibold text-ink">{title}</h2>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

/**
 * A number with a label. With `to`, the whole tile links to the records behind the number
 * (usually a filtered list), with a hover state, a focus ring and a chevron as the cue.
 */
export function Stat({ label, value, sub, to, hint }: { label: string; value: ReactNode; sub?: ReactNode; to?: string; hint?: string }) {
  const body = (
    <>
      <div className="flex items-start justify-between gap-2">
        <div className="text-xs font-medium uppercase tracking-wide text-ink-3">{label}</div>
        {to && (
          <ChevronRight aria-hidden className="h-4 w-4 shrink-0 text-ink-3 transition group-hover:translate-x-0.5 group-hover:text-accent" />
        )}
      </div>
      <div className="mt-1 text-2xl font-semibold tracking-tight text-ink">{value}</div>
      {sub && <div className="mt-0.5 text-xs text-ink-2">{sub}</div>}
    </>
  );
  const base = "block rounded-xl border border-line bg-surface-1 px-4 py-3";
  if (!to) return <div className={base}>{body}</div>;
  return (
    <Link
      to={to}
      title={hint ?? `Show ${label.toLowerCase()}`}
      className={`group ${base} transition hover:border-accent/60 hover:bg-surface-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent`}
    >
      {body}
    </Link>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-ink-2">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Select({ value, onChange, options, label }: { value: string; onChange: (v: string) => void; options: (string | { value: string; label: string })[]; label: string }) {
  return (
    <label className="flex items-center gap-1.5 text-xs text-ink-3">
      {label}
      <select
        className="rounded border border-line bg-surface-2 px-2 py-1 text-sm text-ink"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
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

export function Button({
  children,
  onClick,
  disabled,
  variant = "default",
  title,
  type = "button",
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: "default" | "primary" | "danger";
  title?: string;
  type?: "button" | "submit";
}) {
  const cls = {
    primary: "bg-accent text-white hover:brightness-110",
    danger: "border border-sev-critical/60 bg-sev-critical/10 text-ink hover:bg-sev-critical/20",
    default: "border border-line bg-surface-2 text-ink hover:bg-line",
  }[variant];
  return (
    <button
      type={type}
      title={title}
      className={`rounded px-3 py-1.5 text-sm font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-50 ${cls}`}
      onClick={onClick}
      disabled={disabled}
    >
      {children}
    </button>
  );
}

export function RiskBar({ value }: { value: number }) {
  const sev = value >= 70 ? "critical" : value >= 45 ? "high" : value >= 20 ? "medium" : "low";
  return (
    <div className="flex items-center gap-2" title={`Risk ${value} (${sev})`}>
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-surface-2">
        <div className="h-full rounded-full" style={{ width: `${Math.max(2, value)}%`, background: SEV_COLOR[sev] }} />
      </div>
      <span className="w-9 text-right text-xs text-ink">{value.toFixed(0)}</span>
    </div>
  );
}

/**
 * Empty state: what is missing and, when useful, what to do about it. With only children it keeps
 * the old one-line look; `title` / `action` / `icon` give the fuller version.
 */
export function Empty({ children, title, action, icon: Icon = Inbox }: { children?: ReactNode; title?: ReactNode; action?: ReactNode; icon?: LucideIcon }) {
  if (!title && !action) return <div className="py-8 text-center text-sm text-ink-3">{children}</div>;
  return (
    <div className="flex flex-col items-center px-4 py-10 text-center">
      <span className="flex h-11 w-11 items-center justify-center rounded-full bg-surface-2 text-ink-3">
        <Icon aria-hidden className="h-5 w-5" />
      </span>
      {title && <p className="mt-3 text-sm font-semibold text-ink">{title}</p>}
      {children && <p className="mt-1 max-w-md text-sm text-ink-3">{children}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorNote({ error }: { error: string | null }) {
  if (!error) return null;
  return <div className="mb-3 rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm text-ink">{error}</div>;
}

export function Drawer({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50" onClick={onClose}>
      <aside
        className="h-full w-full max-w-2xl overflow-y-auto border-l border-line bg-surface-1 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="sticky top-0 flex items-center justify-between border-b border-line bg-surface-1 px-5 py-3">
          <div className="min-w-0 text-base font-semibold">{title}</div>
          <button className="text-ink-3 hover:text-ink" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>
        <div className="p-5">{children}</div>
      </aside>
    </div>
  );
}

export type Column = ReactNode | { label: ReactNode; sort?: string; align?: "left" | "right"; srOnly?: boolean };

const isColumnObject = (c: Column): c is { label: ReactNode; sort?: string; align?: "left" | "right"; srOnly?: boolean } =>
  typeof c === "object" && c !== null && !isValidElement(c) && "label" in c;

/**
 * Table shell with consistent styling. The header stays visible while the rows scroll (the table
 * scrolls inside its card once it is taller than the window). Columns given as
 * { label, sort: "key" } are sortable when `sort` / `onSort` are passed (see lib/useSort.ts).
 * `loading` with no rows shows placeholder rows; `empty` is shown when there are no rows.
 */
export function Table({
  head,
  children,
  sort,
  onSort,
  loading,
  empty,
  rowCount,
}: {
  head: Column[];
  children: ReactNode;
  sort?: SortState;
  onSort?: (key: string) => void;
  loading?: boolean;
  empty?: ReactNode;
  rowCount?: number;
}) {
  const noRows = rowCount === 0;
  if (noRows && !loading && empty) return <>{empty}</>;
  return (
    <div className="max-h-[calc(100vh-13rem)] overflow-auto rounded-lg">
      <table className="w-full text-left text-sm">
        <thead className="sticky top-0 z-10 bg-surface-1 shadow-[inset_0_-1px_0_var(--color-line)]">
          <tr className="text-xs uppercase tracking-wide text-ink-3">
            {head.map((h, i) => {
              const col = isColumnObject(h) ? h : { label: h };
              const active = !!sort && !!col.sort && sort.key === col.sort;
              const align = col.align === "right" ? "text-right" : "";
              return (
                <th
                  key={i}
                  scope="col"
                  aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : undefined}
                  className={`px-3 py-2.5 font-medium ${align}`}
                >
                  {col.sort && onSort ? (
                    <button
                      type="button"
                      onClick={() => onSort(col.sort!)}
                      className={`group inline-flex items-center gap-1 rounded uppercase tracking-wide transition hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${active ? "text-ink" : ""}`}
                    >
                      {col.label}
                      {active ? (
                        sort.dir === "asc" ? <ArrowUp aria-hidden className="h-3.5 w-3.5" /> : <ArrowDown aria-hidden className="h-3.5 w-3.5" />
                      ) : (
                        <ArrowUpDown aria-hidden className="h-3.5 w-3.5 opacity-0 transition group-hover:opacity-60 group-focus-visible:opacity-60" />
                      )}
                    </button>
                  ) : col.srOnly ? (
                    <span className="sr-only">{col.label}</span>
                  ) : (
                    col.label
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody className="divide-y divide-line/60">
          {loading && noRows ? <SkeletonRows cols={head.length} /> : children}
        </tbody>
      </table>
    </div>
  );
}

function SkeletonRows({ cols, rows = 6 }: { cols: number; rows?: number }) {
  return (
    <>
      {Array.from({ length: rows }, (_, r) => (
        <tr key={r} aria-hidden>
          {Array.from({ length: cols }, (_, c) => (
            <td key={c} className="px-3 py-3">
              <div className="h-3 animate-pulse rounded bg-surface-2" style={{ width: `${45 + ((r * 7 + c * 13) % 45)}%` }} />
            </td>
          ))}
        </tr>
      ))}
      <tr className="sr-only">
        <td role="status">Loading…</td>
      </tr>
    </>
  );
}

/** Accessible modal dialog: focus moves in on open, Escape / backdrop closes, focus is restored on close. */
export function Modal({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: string; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  const closeRef = useRef(onClose);
  useEffect(() => {
    closeRef.current = onClose;
  }, [onClose]);
  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    const first = ref.current?.querySelector<HTMLElement>("input, select, textarea, button");
    first?.focus();
    const h = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeRef.current();
      if (e.key === "Tab" && ref.current) {
        const items = Array.from(
          ref.current.querySelectorAll<HTMLElement>("input, select, textarea, button, a[href]"),
        ).filter((el) => !el.hasAttribute("disabled"));
        if (items.length === 0) return;
        const [a, z] = [items[0], items[items.length - 1]];
        if (e.shiftKey && document.activeElement === a) {
          e.preventDefault();
          z.focus();
        } else if (!e.shiftKey && document.activeElement === z) {
          e.preventDefault();
          a.focus();
        }
      }
    };
    window.addEventListener("keydown", h);
    return () => {
      window.removeEventListener("keydown", h);
      prev?.focus();
    };
  }, [open]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4" onClick={onClose}>
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="w-full max-w-md rounded-lg border border-line bg-surface-1 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex items-center justify-between border-b border-line px-5 py-3">
          <h2 className="text-base font-semibold">{title}</h2>
          <button className="rounded text-ink-3 hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

/** Labelled text input used by forms. */
export function Field({
  label,
  id,
  hint,
  ...props
}: { label: string; id: string; hint?: string } & InputHTMLAttributes<HTMLInputElement>) {
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-sm font-medium text-ink-2">
        {label}
      </label>
      <input
        id={id}
        {...props}
        aria-describedby={hint ? `${id}-hint` : undefined}
        className="block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40"
      />
      {hint && (
        <p id={`${id}-hint`} className="mt-1 text-xs text-ink-3">
          {hint}
        </p>
      )}
    </div>
  );
}
