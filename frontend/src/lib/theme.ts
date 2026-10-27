import { useCallback, useState } from "react";

/** Light or dark palette (index.css). The choice is per browser; without one, the OS preference is used. */
export type Theme = "light" | "dark";
const KEY = "cnapp-theme";

function stored(): Theme | null {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : null;
  } catch {
    return null;
  }
}

export function initialTheme(): Theme {
  return stored() ?? (window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark");
}

export function applyTheme(t: Theme) {
  document.documentElement.dataset.theme = t;
}

export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() => (document.documentElement.dataset.theme as Theme) || initialTheme());
  const toggle = useCallback(() => {
    setTheme((prev) => {
      const next: Theme = prev === "dark" ? "light" : "dark";
      applyTheme(next);
      try {
        localStorage.setItem(KEY, next);
      } catch {
        /* private mode: the choice lasts for this page only */
      }
      return next;
    });
  }, []);
  return [theme, toggle];
}
