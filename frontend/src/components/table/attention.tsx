import { ChevronRight } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Pill, type PillTone } from "./filters";

export interface AttentionItem {
  key: string;
  /** Severity word shown as a pill ("Critical", "High"); colour is state, the text is always there. */
  label: string;
  tone: PillTone;
  text: ReactNode;
  sub?: ReactNode;
  /** Filters the list on the same page. */
  onClick?: () => void;
  /** Or goes to another page. */
  to?: string;
}

const ROW = "group flex w-full items-center gap-3 px-4 py-2.5 text-left text-sm transition hover:bg-surface-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent";

/** "Needs attention" / "Fix first" card: a short list built from data the page already loads. Renders nothing without items. */
export function AttentionList({ title, hint, items, footer }: { title: string; hint?: string; items: AttentionItem[]; footer?: ReactNode }) {
  if (items.length === 0) return null;
  return (
    <section aria-label={title} className="mb-4 rounded-xl border border-line bg-surface-1">
      <header className="flex flex-wrap items-baseline justify-between gap-2 border-b border-line px-4 py-2.5">
        <h2 className="text-sm font-semibold text-ink">{title}</h2>
        {hint && <span className="text-xs text-ink-3">{hint}</span>}
      </header>
      <ul className="divide-y divide-line/60">
        {items.map((i) => {
          const body = (
            <>
              <span className="w-[72px] shrink-0">
                <Pill tone={i.tone}>{i.label}</Pill>
              </span>
              <span className="min-w-0 flex-1">
                <span className="block text-ink">{i.text}</span>
                {i.sub && <span className="block truncate text-xs text-ink-3">{i.sub}</span>}
              </span>
              <ChevronRight aria-hidden className="h-4 w-4 shrink-0 text-ink-3 group-hover:text-accent" />
            </>
          );
          return (
            <li key={i.key}>
              {i.to ? (
                <Link to={i.to} className={ROW}>
                  {body}
                </Link>
              ) : (
                <button type="button" onClick={i.onClick} className={ROW}>
                  {body}
                </button>
              )}
            </li>
          );
        })}
      </ul>
      {footer && <div className="border-t border-line px-4 py-2 text-xs text-ink-3">{footer}</div>}
    </section>
  );
}
