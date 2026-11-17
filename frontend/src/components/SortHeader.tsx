import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import type { ReactNode } from "react";
import type { SortState } from "../lib/useSort";

/** A sortable <th> for hand-written data tables (the shared Table in ui.tsx does the same for its head). */
export default function SortHeader({
  sortKey,
  label,
  sort,
  onSort,
  className = "",
}: {
  sortKey: string;
  label: ReactNode;
  sort: SortState;
  onSort: (key: string) => void;
  className?: string;
}) {
  const active = sort.key === sortKey;
  return (
    <th scope="col" aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : undefined} className={className}>
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        className={`group inline-flex items-center gap-1 rounded uppercase tracking-wide transition hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${active ? "text-ink" : ""}`}
      >
        {label}
        {active ? (
          sort.dir === "asc" ? <ArrowUp aria-hidden className="h-3.5 w-3.5" /> : <ArrowDown aria-hidden className="h-3.5 w-3.5" />
        ) : (
          <ArrowUpDown aria-hidden className="h-3.5 w-3.5 opacity-0 transition group-hover:opacity-60 group-focus-visible:opacity-60" />
        )}
      </button>
    </th>
  );
}
