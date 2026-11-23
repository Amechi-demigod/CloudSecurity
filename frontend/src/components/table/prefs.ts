import { useCallback, useEffect, useRef, useState } from "react";
import { request } from "../../api";

export type Density = "comfortable" | "compact";
export interface TablePrefs {
  widths: Record<string, number>;
  hidden: string[];
  density: Density;
}

export const MIN_COL = 56;
export const MAX_COL = 1200;
const DEFAULTS: TablePrefs = { widths: {}, hidden: [], density: "comfortable" };
const lsKey = (id: string) => `sentrigis.table.${id}`;

/** Accept only what the server would accept; anything else falls back to the defaults. */
export function normalize(raw: unknown): TablePrefs {
  const r = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const widths: Record<string, number> = {};
  if (r.widths && typeof r.widths === "object") {
    for (const [k, v] of Object.entries(r.widths as Record<string, unknown>)) {
      if (typeof v === "number" && Number.isFinite(v)) widths[k] = Math.min(MAX_COL, Math.max(40, Math.round(v)));
    }
  }
  const hidden = Array.isArray(r.hidden) ? r.hidden.filter((x): x is string => typeof x === "string").slice(0, 50) : [];
  return { widths, hidden, density: r.density === "compact" ? "compact" : "comfortable" };
}

function readLocal(id?: string): TablePrefs {
  if (!id) return DEFAULTS;
  try {
    const v = localStorage.getItem(lsKey(id));
    return v ? normalize(JSON.parse(v)) : DEFAULTS;
  } catch {
    return DEFAULTS;
  }
}

/**
 * A table's widths, hidden columns and density. They are saved per user on the server
 * (`/api/table-prefs/{tableId}`); localStorage is only an immediate cache, so the table never waits for the
 * network and still works (for this browser) when the API fails. Without a `tableId` nothing is stored.
 */
export function useTablePrefs(tableId?: string) {
  const [prefs, setPrefs] = useState<TablePrefs>(() => readLocal(tableId));
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const latest = useRef(prefs);
  latest.current = prefs;

  useEffect(() => {
    setPrefs(readLocal(tableId));
    if (!tableId) return;
    let live = true;
    request<unknown>(`/api/table-prefs/${tableId}`, { skipAuthHandling: true })
      .then((r) => {
        if (!live || !r || typeof r !== "object" || Object.keys(r).length === 0) return;
        const n = normalize(r);
        setPrefs(n);
        try {
          localStorage.setItem(lsKey(tableId), JSON.stringify(n));
        } catch {
          /* storage unavailable: the server copy still applies */
        }
      })
      .catch(() => {
        /* offline or API error: keep the local copy */
      });
    return () => {
      live = false;
    };
  }, [tableId]);

  useEffect(() => () => clearTimeout(timer.current), []);

  const save = useCallback(
    (next: TablePrefs) => {
      setPrefs(next);
      latest.current = next;
      if (!tableId) return;
      try {
        localStorage.setItem(lsKey(tableId), JSON.stringify(next));
      } catch {
        /* ignore */
      }
      clearTimeout(timer.current);
      timer.current = setTimeout(() => {
        request(`/api/table-prefs/${tableId}`, { method: "PUT", body: JSON.stringify(latest.current), skipAuthHandling: true }).catch(() => {
          /* the local copy is kept; the next change tries again */
        });
      }, 600);
    },
    [tableId],
  );

  return { prefs, save, reset: () => save(DEFAULTS) };
}
