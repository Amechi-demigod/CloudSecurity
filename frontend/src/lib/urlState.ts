import { useCallback } from "react";
import { useUrlState } from "./useUrlState";

/**
 * Query-string helpers for list views (search, filters, sort, page), so Back and a refresh keep the view.
 * The default of a key is never written. `readParams` / `patchParams` are pure so they work outside React;
 * `writeParams` uses history.replaceState (no history entry per keystroke), and `usePageParam` is the
 * router-aware equivalent for components (same replace semantics, and the router re-renders on change).
 */
export function readParams(search: string, keys: readonly string[], defaults: Record<string, string> = {}): Record<string, string> {
  const p = new URLSearchParams(search);
  return Object.fromEntries(keys.map((k) => [k, p.get(k) ?? defaults[k] ?? ""]));
}

/** The query string after applying `patch` (a value equal to its default, or empty, removes the key). */
export function patchParams(search: string, patch: Record<string, string | number | null>, defaults: Record<string, string> = {}): string {
  const p = new URLSearchParams(search);
  for (const [k, v] of Object.entries(patch)) {
    const s = v == null ? "" : String(v);
    if (s === "" || s === (defaults[k] ?? "")) p.delete(k);
    else p.set(k, s);
  }
  const out = p.toString();
  return out ? `?${out}` : "";
}

/** Write the patched query string with history.replaceState (outside React; the router does not re-render). */
export function writeParams(patch: Record<string, string | number | null>, defaults: Record<string, string> = {}): void {
  const next = patchParams(window.location.search, patch, defaults);
  window.history.replaceState(window.history.state, "", `${window.location.pathname}${next}${window.location.hash}`);
}

/** A 1-based page number kept in the URL (?page=3). Page 1 is not written. */
export function usePageParam(key = "page"): [number, (n: number) => void] {
  const [raw, setRaw] = useUrlState(key, "1");
  const n = Math.max(1, Math.floor(Number(raw)) || 1);
  const set = useCallback((v: number) => setRaw(String(Math.max(1, v))), [setRaw]);
  return [n, set];
}
