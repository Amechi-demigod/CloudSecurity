export const inputCls =
  "block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40";

export const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e));
