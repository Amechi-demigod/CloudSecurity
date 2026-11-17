import { useMemo } from "react";
import { useUrlState } from "./useUrlState";

export type SortDir = "asc" | "desc";
export interface SortState {
  key: string;
  dir: SortDir;
}
type SortValue = string | number | boolean | null | undefined;

/** Severity / priority words sort by rank (critical first when descending), not alphabetically. */
export const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Status words in a fixed, sensible order (worst / most urgent first when ascending). */
export const rankOf = (order: readonly string[]) => (v: string | null | undefined) => {
  const i = order.indexOf((v ?? "").toLowerCase());
  return i < 0 ? order.length : i;
};

/** A date string as a number so dates sort chronologically (unparseable or missing: null, sorted last). */
export const ts = (v: string | null | undefined): number | null => {
  if (!v) return null;
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : t;
};

/**
 * The sort of a list kept in the URL (?sort=name, ?sort=-risk; `param` names the query key when a page has
 * more than one sorted table). Clicking the active column flips the direction; a new column starts with
 * `firstDir[key]` (default ascending; numbers and dates usually want descending first). `value` is the
 * `sort` query string for an API ("name", "-risk") when the server sorts the whole result.
 */
export function useSortState(
  allowed: readonly string[],
  initial: SortState,
  firstDir: Record<string, SortDir> = {},
  param = "sort",
): { sort: SortState; onSort: (key: string) => void; value: string } {
  const fallback = `${initial.dir === "desc" ? "-" : ""}${initial.key}`;
  const [raw, setRaw] = useUrlState(param, fallback);
  const parsed: SortState = raw.startsWith("-") ? { key: raw.slice(1), dir: "desc" } : { key: raw, dir: "asc" };
  const sort = allowed.includes(parsed.key) ? parsed : initial;
  const onSort = (key: string) => {
    const dir: SortDir = key === sort.key ? (sort.dir === "asc" ? "desc" : "asc") : (firstDir[key] ?? "asc");
    setRaw(`${dir === "desc" ? "-" : ""}${key}`);
  };
  return { sort, onSort, value: `${sort.dir === "desc" ? "-" : ""}${sort.key}` };
}

/**
 * Client-side sorting of a fully loaded list. The sort is kept in the URL (?sort=name, ?sort=-risk) so it
 * survives a reload and can be linked to. `columns` maps a sort key to the value to compare; nulls
 * always sort last. Clicking the active column flips the direction; a new column starts with
 * `firstDir[key]` (default ascending; numbers and dates usually want descending first).
 */
export function useSort<T>(
  rows: T[] | null | undefined,
  columns: Record<string, (row: T) => SortValue>,
  initial: SortState,
  firstDir: Record<string, SortDir> = {},
  param = "sort",
): { rows: T[]; sort: SortState; onSort: (key: string) => void } {
  const { sort, onSort } = useSortState(Object.keys(columns), initial, firstDir, param);

  const sorted = useMemo(() => {
    const get = columns[sort.key];
    if (!rows || !get) return rows ?? [];
    const sign = sort.dir === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => {
      const x = get(a);
      const y = get(b);
      if (x == null || x === "") return y == null || y === "" ? 0 : 1;
      if (y == null || y === "") return -1;
      if (typeof x === "string" && typeof y === "string") return sign * x.localeCompare(y, undefined, { numeric: true, sensitivity: "base" });
      return sign * (Number(x) - Number(y));
    });
    // columns is a fresh object each render; the key and direction identify the ordering
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, sort.key, sort.dir]);

  return { rows: sorted, sort, onSort };
}
