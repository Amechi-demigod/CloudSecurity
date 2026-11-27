import { ChevronRight, Info, Inbox, type LucideIcon } from "lucide-react";
import { useEffect, useId, useRef, useState, type InputHTMLAttributes, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { SEV_COLOR } from "../lib/format";
import { registerSaveSlot } from "../lib/saveSlot";

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
export function Stat({
  label,
  value,
  sub,
  to,
  hint,
  onSelect,
  selected,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  to?: string;
  hint?: string;
  /** Makes the box a toggle that filters a list on the same page (`selected` highlights it). */
  onSelect?: () => void;
  selected?: boolean;
}) {
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
  if (onSelect)
    return (
      <button
        type="button"
        onClick={onSelect}
        aria-pressed={!!selected}
        title={hint ?? `Show only ${label.toLowerCase()}`}
        className={`group w-full text-left ${base} transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${selected ? "border-accent bg-accent/10" : "hover:border-accent/60 hover:bg-surface-2"}`}
      >
        {body}
      </button>
    );
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

/** "Section / Item" trail above a detail page's title; the last item is the current page. */
export function Breadcrumbs({ items }: { items: { label: ReactNode; to?: string }[] }) {
  return (
    <nav aria-label="Breadcrumb" className="mb-2">
      <ol className="flex min-w-0 items-center gap-1 text-xs text-ink-3">
        {items.map((it, i) => (
          <li key={i} className="flex min-w-0 items-center gap-1">
            {i > 0 && <ChevronRight aria-hidden className="h-3.5 w-3.5 shrink-0" />}
            {it.to ? (
              <Link to={it.to} className="hover:text-ink">
                {it.label}
              </Link>
            ) : (
              <span aria-current="page" className="truncate text-ink-2">
                {it.label}
              </span>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}

export type PageInfo = { title: string; text: string };

/** Small (i) button after a page title: a tooltip on hover, keyboard focus and tap; Esc closes it. */
export function InfoTip({ info }: { info: PageInfo }) {
  const id = useId();
  const [hover, setHover] = useState(false);
  const [focus, setFocus] = useState(false);
  const [pinned, setPinned] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const open = !dismissed && (hover || focus || pinned);
  return (
    <span className="relative inline-flex align-middle" onMouseEnter={() => { setDismissed(false); setHover(true); }} onMouseLeave={() => { setHover(false); setPinned(false); }}>
      <button
        type="button"
        aria-label={`About this page: ${info.title}`}
        aria-describedby={open ? id : undefined}
        onClick={() => { setDismissed(false); setPinned((p) => !p); }}
        onFocus={() => { setDismissed(false); setFocus(true); }}
        onBlur={() => { setFocus(false); setPinned(false); }}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            setDismissed(true);
            setPinned(false);
          }
        }}
        className="flex h-6 w-6 items-center justify-center rounded-full text-ink-3 transition hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        <Info aria-hidden className="h-4 w-4" />
      </button>
      {open && (
        <span
          role="tooltip"
          id={id}
          className="absolute left-0 top-full z-30 mt-1.5 w-max max-w-[300px] rounded-lg bg-[#0f172a] px-3 py-2 text-left text-xs font-normal normal-case leading-relaxed tracking-normal text-slate-100 shadow-xl ring-1 ring-white/10"
        >
          <span className="mb-0.5 block font-semibold text-white">{info.title}</span>
          {info.text}
        </span>
      )}
    </span>
  );
}

export function PageHeader({ title, subtitle, actions, info }: { title: string; subtitle?: string; actions?: ReactNode; info?: PageInfo }) {
  const slotRef = useRef<HTMLDivElement>(null);
  // SaveBar portals its content into this slot, so unsaved-change controls sit in the title row and scroll with
  // the page (nothing is pinned on screen).
  useEffect(() => (slotRef.current ? registerSaveSlot(slotRef.current) : undefined), []);
  return (
    <div className="mb-5 flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
      <div className="min-w-0">
        <div className="flex items-center gap-1.5">
          <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
          {info && <InfoTip info={info} />}
        </div>
        {subtitle && <p className="mt-1 text-sm text-ink-2">{subtitle}</p>}
      </div>
      <div className="flex flex-wrap items-center justify-end gap-x-3 gap-y-2">
        {actions && <div className="flex items-center gap-2">{actions}</div>}
        <div ref={slotRef} className="contents" />
      </div>
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

const FOCUSABLE = "input, select, textarea, button, a[href], [tabindex]:not([tabindex='-1'])";

/** Side drawer: a modal dialog (role=dialog), focus moves in on open, Tab stays inside, Escape or the backdrop
 * closes and focus returns to whatever opened it. */
export function Drawer({ open, onClose, title, children }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode }) {
  const ref = useRef<HTMLElement>(null);
  const titleId = useId();
  const closeRef = useRef(onClose);
  useEffect(() => {
    closeRef.current = onClose;
  }, [onClose]);
  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.querySelector<HTMLElement>("[data-autofocus]")?.focus();
    if (!ref.current?.contains(document.activeElement)) ref.current?.querySelector<HTMLElement>(FOCUSABLE)?.focus();
    const h = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeRef.current();
      if (e.key === "Tab" && ref.current) {
        const items = Array.from(ref.current.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((el) => !el.hasAttribute("disabled"));
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
    <div className="fixed inset-0 z-40 flex justify-end bg-black/50" onClick={onClose}>
      <aside
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="h-full w-full max-w-2xl overflow-y-auto border-l border-line bg-surface-1 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="sticky top-0 flex items-center justify-between border-b border-line bg-surface-1 px-5 py-3">
          <div id={titleId} className="min-w-0 text-base font-semibold">{title}</div>
          <button className="text-ink-3 hover:text-ink" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>
        <div className="p-5">{children}</div>
      </aside>
    </div>
  );
}

export { Table, SelectCell, type Column, type ColumnObject, type TableSelection } from "./table/Table";
export { DetailDrawer, type DetailRow } from "./table/DetailDrawer";
export { FilterChips, type FilterChip } from "./table/FilterChips";
export { NameCell, NumCell, None, PillRow, TextCell } from "./table/cells";
export { FilterBar, FilterSearch, FilterSelect, Pill, Segments, type PillTone } from "./table/filters";
export { AttentionList, type AttentionItem } from "./table/attention";
export { MoreMenu, type MenuItem } from "./table/menu";

/** Accessible modal dialog: focus moves in on open, Escape / backdrop closes, focus is restored on close.
 * Never taller than the window: the title bar (and its close button) stays put and the body scrolls. */
export function Modal({ open, onClose, title, size = "md", children }: {
  open: boolean;
  onClose: () => void;
  title: string;
  /** md: forms and confirmations; lg: wide content such as scripts. */
  size?: "md" | "lg";
  children: ReactNode;
}) {
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
    // The page behind must not scroll while the dialog is open.
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", h);
      document.body.style.overflow = overflow;
      prev?.focus();
    };
  }, [open]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={`flex max-h-full w-full flex-col rounded-lg border border-line bg-surface-1 shadow-2xl ${size === "lg" ? "max-w-3xl" : "max-w-md"}`}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex shrink-0 items-center justify-between gap-3 border-b border-line px-5 py-3">
          <h2 className="text-base font-semibold">{title}</h2>
          <button className="rounded text-ink-3 hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>
        <div className="min-h-0 overflow-y-auto p-5">{children}</div>
      </div>
    </div>
  );
}

/** Labelled text input used by forms. `error` shows a validation message next to the field. */
export function Field({
  label,
  id,
  hint,
  error,
  ...props
}: { label: string; id: string; hint?: string; error?: string | null } & InputHTMLAttributes<HTMLInputElement>) {
  const described = [error ? `${id}-error` : null, hint ? `${id}-hint` : null].filter(Boolean).join(" ") || undefined;
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-sm font-medium text-ink-2">
        {label}
      </label>
      <input
        id={id}
        {...props}
        aria-invalid={error ? true : undefined}
        aria-describedby={described}
        className={`block w-full rounded border bg-surface-2 px-3 py-1.5 text-sm text-ink focus:outline-none focus:ring-2 ${
          error ? "border-sev-critical focus:border-sev-critical focus:ring-sev-critical/40" : "border-line focus:border-accent focus:ring-accent/40"
        }`}
      />
      {error && (
        <p id={`${id}-error`} className="mt-1 text-xs text-sev-critical">
          {error}
        </p>
      )}
      {hint && (
        <p id={`${id}-hint`} className="mt-1 text-xs text-ink-3">
          {hint}
        </p>
      )}
    </div>
  );
}
