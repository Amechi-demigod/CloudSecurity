import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";

/**
 * A filter value kept in the URL query string (?key=value), so a filtered view can be linked to
 * (dashboard tiles, notifications), bookmarked and survives a reload. The default is never written
 * to the URL; changes replace the history entry instead of adding one per keystroke.
 */
export function useUrlState(key: string, fallback = ""): [string, (v: string) => void] {
  const [params, setParams] = useSearchParams();
  const value = params.get(key) ?? fallback;
  const set = useCallback(
    (v: string) =>
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (v === fallback) next.delete(key);
          else next.set(key, v);
          return next;
        },
        { replace: true },
      ),
    [key, fallback, setParams],
  );
  return [value, set];
}
