import { ArrowDown, ArrowUp, ArrowUpDown, Columns3 } from "lucide-react";
import { Children, isValidElement, useEffect, useId, useRef, useState, type ReactNode } from "react";
import { usePageParam } from "../../lib/urlState";
import type { SortState } from "../../lib/useSort";
import { Button, Empty } from "../ui";
import { MAX_COL, MIN_COL, useTablePrefs, type Density } from "./prefs";

export interface ColumnObject {
  label: ReactNode;
  /** Sort key (with the table's `sort` / `onSort`). */
  sort?: string;
  align?: "left" | "right";
  srOnly?: boolean;
  /** Stable key for saved widths / hidden columns; defaults to `sort`, then the position. */
  key?: string;
  /** Default width in px (richer mode); without it a sensible default is used. */
  w?: number;
}
export type Column = ReactNode | ColumnObject;

const isColumnObject = (c: Column): c is ColumnObject => typeof c === "object" && c !== null && !isValidElement(c) && "label" in c;

export interface TableSelection {
  /** Row ids in row order (null for a row that cannot be selected). Used for "select all on this page". */
  ids: (string | null)[];
  selected: ReadonlySet<string>;
  onChange: (next: Set<string>) => void;
  /** Bulk actions shown in the selection bar. */
  actions?: ReactNode;
}

const SELECT_W = 44;
const STEP = 16;
const ID_OK = /^[a-z0-9-]{1,64}$/;
const clamp = (w: number) => Math.min(MAX_COL, Math.max(MIN_COL, Math.round(w)));

/**
 * Table shell with consistent styling. The header stays visible while the rows scroll (the table
 * scrolls inside its card once it is taller than the window). Columns given as
 * { label, sort: "key" } are sortable when `sort` / `onSort` are passed (see lib/useSort.ts).
 * `loading` with no rows shows placeholder rows; `empty` is shown when there are no rows.
 *
 * Passing `tableId` (a stable id such as "devices") turns on the richer mode: resizable columns (drag the
 * handle, double-click to reset, Left / Right arrows on the focused handle), a Columns menu, comfortable /
 * compact density and a pinned first column, remembered per user (server) with a local cache. Other props:
 * `selection` (checkbox column + selection bar), `pageSize` + `noun` (client-side pager, page in the URL),
 * `error` / `onRetry`, `filtered` / `onClearFilters` (the "no matches" state) and `toolbar` (left of the controls).
 */
export function Table({
  head,
  children,
  sort,
  onSort,
  loading,
  empty,
  rowCount,
  tableId,
  selection,
  toolbar,
  noun = "rows",
  pageSize,
  pageParam = "page",
  error,
  onRetry,
  filtered,
  onClearFilters,
}: {
  head: Column[];
  children: ReactNode;
  sort?: SortState;
  onSort?: (key: string) => void;
  loading?: boolean;
  empty?: ReactNode;
  rowCount?: number;
  tableId?: string;
  selection?: TableSelection;
  toolbar?: ReactNode;
  /** Plural noun for the pager and the "no matches" title ("devices"). */
  noun?: string;
  pageSize?: number;
  pageParam?: string;
  error?: string | null;
  onRetry?: () => void;
  filtered?: boolean;
  onClearFilters?: () => void;
}) {
  const rich = !!tableId && ID_OK.test(tableId);
  const { prefs, save, reset } = useTablePrefs(rich ? tableId : undefined);
  const [live, setLive] = useState<Record<string, number>>({});
  const [activeHandle, setActiveHandle] = useState<string | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const [urlPage, setUrlPage] = usePageParam(pageParam);
  const drag = useRef<{ key: string; x: number; w: number } | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuId = useId();

  useEffect(() => {
    if (!menuOpen) return;
    const down = (e: MouseEvent) => !menuRef.current?.contains(e.target as Node) && setMenuOpen(false);
    const key = (e: KeyboardEvent) => e.key === "Escape" && setMenuOpen(false);
    document.addEventListener("mousedown", down);
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("mousedown", down);
      document.removeEventListener("keydown", key);
    };
  }, [menuOpen]);

  const cols = head.map((h, i) => {
    const c: ColumnObject = isColumnObject(h) ? h : { label: h };
    const key = c.key ?? c.sort ?? `c${i}`;
    return { ...c, key, index: i, defW: c.w ?? (c.srOnly ? 72 : i === 0 ? 240 : 150) };
  });
  const hiddenSet = new Set(rich ? prefs.hidden : []);
  const visible = cols.filter((c) => c.index === 0 || !hiddenSet.has(c.key));
  const widthOf = (c: (typeof cols)[number]) => live[c.key] ?? prefs.widths[c.key] ?? c.defW;
  const selOn = !!selection;

  // Paging (client side): the children are the page's own rows, so the slice is taken here.
  const rows = pageSize ? Children.toArray(children) : null;
  const total = rows ? (rowCount ?? rows.length) : (rowCount ?? 0);
  const pages = pageSize ? Math.max(1, Math.ceil(total / pageSize)) : 1;
  const page = Math.min(urlPage, pages);
  const start = pageSize ? (page - 1) * pageSize : 0;
  const end = pageSize ? Math.min(total, start + pageSize) : 0;
  const shownRows = rows && pageSize ? rows.slice(start, start + pageSize) : children;
  const pageIds = (selection?.ids ?? []).slice(pageSize ? start : 0, pageSize ? start + pageSize : undefined).filter((x): x is string => !!x);

  const noRows = rowCount === 0;
  if (error) {
    return (
      <div role="alert" className="flex flex-col items-center px-4 py-10 text-center">
        <p className="text-sm font-semibold text-ink">Could not load {noun}</p>
        <p className="mt-1 max-w-md text-sm text-ink-3">{error}</p>
        {onRetry && (
          <div className="mt-4">
            <Button onClick={onRetry}>Retry</Button>
          </div>
        )}
      </div>
    );
  }
  if (noRows && !loading && filtered && onClearFilters) {
    return (
      <Empty
        title={`No ${noun} match these filters`}
        action={
          <Button variant="primary" onClick={onClearFilters}>
            Clear filters
          </Button>
        }
      >
        Clear a filter to see more {noun}.
      </Empty>
    );
  }
  if (noRows && !loading && empty) return <>{empty}</>;

  const setWidth = (key: string, w: number) => save({ ...prefs, widths: { ...prefs.widths, [key]: clamp(w) } });
  const startDrag = (e: React.PointerEvent<HTMLButtonElement>, key: string, w: number) => {
    e.preventDefault();
    e.currentTarget.setPointerCapture?.(e.pointerId);
    drag.current = { key, x: e.clientX, w };
    setActiveHandle(key);
  };
  const moveDrag = (e: React.PointerEvent<HTMLButtonElement>) => {
    const d = drag.current;
    if (d) setLive({ [d.key]: clamp(d.w + e.clientX - d.x) });
  };
  const endDrag = (e: React.PointerEvent<HTMLButtonElement>) => {
    const d = drag.current;
    drag.current = null;
    setActiveHandle(null);
    if (d) {
      setLive({});
      setWidth(d.key, d.w + e.clientX - d.x);
    }
  };
  const resetWidth = (key: string) => {
    const widths = { ...prefs.widths };
    delete widths[key];
    save({ ...prefs, widths });
  };
  const setDensity = (density: Density) => save({ ...prefs, density });
  const toggleHidden = (key: string) =>
    save({ ...prefs, hidden: hiddenSet.has(key) ? prefs.hidden.filter((k) => k !== key) : [...prefs.hidden, key] });

  const colCount = visible.length + (selOn ? 1 : 0);
  const sumW = visible.reduce((n, c) => n + widthOf(c), selOn ? SELECT_W : 0);
  const hideCss = rich
    ? cols
        .filter((c) => c.index !== 0 && hiddenSet.has(c.key))
        .map((c) => `.dt-table[data-tid="${tableId}"] > :is(thead, tbody) > tr > :nth-child(${c.index + 1 + (selOn ? 1 : 0)})`)
        .join(",")
    : "";
  const nSel = selection?.selected.size ?? 0;
  const allOnPage = pageIds.length > 0 && pageIds.every((id) => selection?.selected.has(id));
  const someOnPage = pageIds.some((id) => selection?.selected.has(id));
  const showBar = rich || !!toolbar || selOn;

  return (
    <div>
      {showBar &&
        (nSel > 0 && selection ? (
          <div role="region" aria-label="Selection" className="mb-2 flex flex-wrap items-center gap-3 rounded-lg border border-accent/40 bg-row-sel px-3 py-2 text-sm">
            <span className="font-medium text-ink" aria-live="polite">
              {nSel} selected
            </span>
            {selection.actions}
            <button type="button" onClick={() => selection.onChange(new Set())} className="ml-auto rounded px-1 text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
              Clear selection
            </button>
          </div>
        ) : (
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <div className="flex flex-wrap items-center gap-2">{toolbar}</div>
            {rich && (
              <div className="ml-auto flex items-center gap-2">
                <div ref={menuRef} className="relative">
                  <button
                    type="button"
                    aria-haspopup="true"
                    aria-expanded={menuOpen}
                    aria-controls={menuId}
                    onClick={() => setMenuOpen((o) => !o)}
                    className="inline-flex items-center gap-1.5 rounded border border-line bg-surface-2 px-2.5 py-1 text-xs font-medium text-ink hover:bg-line focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    <Columns3 aria-hidden className="h-3.5 w-3.5" />
                    Columns
                  </button>
                  {menuOpen && (
                    <div id={menuId} role="group" aria-label="Show columns" className="absolute right-0 z-30 mt-1 w-56 rounded-lg border border-line bg-surface-1 p-2 shadow-xl">
                      <ul className="max-h-72 overflow-y-auto">
                        {cols
                          .filter((c) => !c.srOnly && typeof c.label !== "object")
                          .map((c) => (
                            <li key={c.key}>
                              <label className={`flex items-center gap-2 rounded px-2 py-1 text-sm ${c.index === 0 ? "text-ink-3" : "cursor-pointer text-ink hover:bg-surface-2"}`}>
                                <input type="checkbox" className="accent-accent" checked={c.index === 0 || !hiddenSet.has(c.key)} disabled={c.index === 0} onChange={() => toggleHidden(c.key)} />
                                {c.label}
                              </label>
                            </li>
                          ))}
                      </ul>
                      <button type="button" onClick={reset} className="mt-1 w-full rounded border-t border-line px-2 pt-2 text-left text-sm text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
                        Reset columns
                      </button>
                    </div>
                  )}
                </div>
                <div role="group" aria-label="Row density" className="inline-flex overflow-hidden rounded border border-line text-xs">
                  {(["comfortable", "compact"] as const).map((d) => (
                    <button
                      key={d}
                      type="button"
                      aria-pressed={prefs.density === d}
                      onClick={() => setDensity(d)}
                      className={`px-2.5 py-1 font-medium capitalize focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${prefs.density === d ? "bg-accent text-white" : "bg-surface-2 text-ink-2 hover:bg-line"}`}
                    >
                      {d}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      {hideCss && <style>{`${hideCss}{display:none}`}</style>}
      <div className="max-h-[calc(100vh-13rem)] overflow-auto rounded-lg">
        <table
          className={`text-left text-sm ${rich ? "dt-table" : "w-full"}`}
          style={rich ? { width: "100%", minWidth: sumW } : undefined}
          data-tid={rich ? tableId : undefined}
          data-density={rich ? prefs.density : undefined}
          data-pin={rich ? "" : undefined}
          data-sel={rich && selOn ? "" : undefined}
          aria-busy={loading ? true : undefined}
        >
          {rich && (
            <colgroup>
              {selOn && <col style={{ width: SELECT_W }} />}
              {visible.map((c) => (
                <col key={c.key} style={{ width: widthOf(c) }} />
              ))}
            </colgroup>
          )}
          <thead className="sticky top-0 z-10 bg-surface-1 shadow-[inset_0_-1px_0_var(--color-line)]">
            <tr className="text-xs uppercase tracking-wide text-ink-3">
              {selection && (
                <th scope="col" className="px-3 py-2.5">
                  <input
                    type="checkbox"
                    aria-label="Select all on this page"
                    className="accent-accent"
                    ref={(el) => {
                      if (el) el.indeterminate = someOnPage && !allOnPage;
                    }}
                    checked={allOnPage}
                    disabled={pageIds.length === 0}
                    onChange={(e) => {
                      const next = new Set(selection.selected);
                      for (const id of pageIds) {
                        if (e.target.checked) next.add(id);
                        else next.delete(id);
                      }
                      selection.onChange(next);
                    }}
                  />
                </th>
              )}
              {visible.map((col) => {
                const active = !!sort && !!col.sort && sort.key === col.sort;
                const align = col.align === "right" ? "text-right" : "";
                const label = typeof col.label === "string" || typeof col.label === "number" ? String(col.label) : undefined;
                return (
                  <th
                    key={col.key}
                    scope="col"
                    aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : undefined}
                    className={`px-3 py-2.5 font-medium ${align} ${rich ? "relative overflow-visible whitespace-nowrap" : ""}`}
                  >
                    <div className={rich ? "overflow-hidden text-ellipsis" : undefined} title={rich ? label : undefined}>
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
                    </div>
                    {rich && (
                      <button
                        type="button"
                        className="dt-handle"
                        data-active={activeHandle === col.key}
                        aria-label={`Resize column ${label ?? col.key}`}
                        title="Drag to resize, double-click to reset"
                        onPointerDown={(e) => startDrag(e, col.key, widthOf(col))}
                        onPointerMove={moveDrag}
                        onPointerUp={endDrag}
                        onPointerCancel={() => {
                          drag.current = null;
                          setActiveHandle(null);
                          setLive({});
                        }}
                        onDoubleClick={() => resetWidth(col.key)}
                        onKeyDown={(e) => {
                          if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
                            e.preventDefault();
                            setWidth(col.key, widthOf(col) + (e.key === "ArrowRight" ? STEP : -STEP));
                          }
                        }}
                      />
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody className={rich ? undefined : "divide-y divide-line/60"}>
            {loading && noRows ? <SkeletonRows cols={colCount} /> : shownRows}
          </tbody>
        </table>
      </div>
      {pageSize && total > 0 && (
        <nav aria-label="Pagination" className="mt-2 flex flex-wrap items-center justify-between gap-2 text-sm text-ink-3">
          <span aria-live="polite">
            Showing {start + 1}–{end} of {total} {noun}
          </span>
          <span className="flex items-center gap-2">
            <Button disabled={page <= 1} onClick={() => setUrlPage(page - 1)}>
              Previous
            </Button>
            <Button disabled={page >= pages} onClick={() => setUrlPage(page + 1)}>
              Next
            </Button>
          </span>
        </nav>
      )}
    </div>
  );
}

/** Checkbox cell for a row of a table that has `selection`. Put it first in the row's cells. */
export function SelectCell({ checked, onChange, label, disabled, title }: { checked: boolean; onChange: (checked: boolean) => void; label: string; disabled?: boolean; title?: string }) {
  return (
    <td className="px-3 py-2" onClick={(e) => e.stopPropagation()}>
      <input type="checkbox" className="accent-accent" aria-label={label} title={title} checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
    </td>
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
