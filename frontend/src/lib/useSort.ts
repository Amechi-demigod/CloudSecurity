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

/**
 * Client-side sorting of a loaded list. The sort is kept in the URL (?sort=name, ?sort=-risk) so it
 * survives a reload and can be linked to. `columns` maps a sort key to the value to compare; nulls
 * always sort last. Clicking the active column flips the direction; a new column starts with
 * `firstDir[key]` (default ascending; numbers and dates usually want descending first).
 */
export function useSort<T>(
  rows: T[] | null | undefined,
  columns: Record<string, (row: T) => SortValue>,
  initial: SortState,
  firstDir: Record<string, SortDir> = {},
): { rows: T[]; sort: SortState; onSort: (key: string) => void } {
  const fallback = `${initial.dir === "desc" ? "-" : ""}${initial.key}`;
  const [raw, setRaw] = useUrlState("sort", fallback);
  const parsed: SortState = raw.startsWith("-") ? { key: raw.slice(1), dir: "desc" } : { key: raw, dir: "asc" };
  const sort = columns[parsed.key] ? parsed : initial;

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

  const onSort = (key: string) => {
    const dir: SortDir = key === sort.key ? (sort.dir === "asc" ? "desc" : "asc") : (firstDir[key] ?? "asc");
    setRaw(`${dir === "desc" ? "-" : ""}${key}`);
  };
  return { rows: sorted, sort, onSort };
}
