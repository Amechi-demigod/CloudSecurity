import { useEffect, useRef, type InputHTMLAttributes, type ReactNode } from "react";
import { SEV_COLOR } from "../lib/format";

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
    <section className={`rounded-lg border border-line bg-surface-1 ${className}`}>
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

export function Stat({ label, value, sub }: { label: string; value: ReactNode; sub?: ReactNode }) {
  return (
    <div className="rounded-lg border border-line bg-surface-1 px-4 py-3">
      <div className="text-xs uppercase tracking-wide text-ink-3">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-ink">{value}</div>
      {sub && <div className="mt-0.5 text-xs text-ink-2">{sub}</div>}
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold">{title}</h1>
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

export function Empty({ children }: { children: ReactNode }) {
  return <div className="py-8 text-center text-sm text-ink-3">{children}</div>;
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

/** Simple sortable-free table shell with consistent styling. */
export function Table({ head, children }: { head: ReactNode[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-line text-xs uppercase tracking-wide text-ink-3">
            {head.map((h, i) => (
              <th key={i} className="px-3 py-2 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-line/60">{children}</tbody>
      </table>
    </div>
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
