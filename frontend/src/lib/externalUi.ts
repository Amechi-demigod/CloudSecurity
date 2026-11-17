export const inputCls =
  "block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40";

export const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Pre-ASV word for a finding row: Fail / Automatic fail / Pass / Exception, "-" when resolved. */
export function preAsvLabel(f: { status: string; exempt?: boolean; fails: boolean; auto_fail: boolean }): string {
  return f.status === "resolved" ? "-" : f.exempt ? "Exception" : f.fails ? (f.auto_fail ? "Automatic fail" : "Fail") : "Pass";
}
