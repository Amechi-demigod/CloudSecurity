import { mspApi, type ClientOverview } from "../mspApi";

export type ClientStatus = "active" | "suspended" | "waiting";

/** Active, Suspended, or Waiting for first scan (active and never scanned). */
export function clientStatus(c: Pick<ClientOverview, "status" | "last_scan_at">): ClientStatus {
  if (c.status === "suspended") return "suspended";
  return c.last_scan_at ? "active" : "waiting";
}

export const STATUS_LABEL: Record<ClientStatus, string> = { active: "Active", suspended: "Suspended", waiting: "Waiting for first scan" };

/** One line about a client's risk, for the switcher. */
export function riskSummary(c: ClientOverview): string {
  const s = clientStatus(c);
  if (s === "suspended") return "Suspended";
  if (s === "waiting") return "Waiting for first scan";
  const crit = c.open_critical_findings ?? 0;
  const risk = c.risk_score == null ? "Risk not available" : `Risk ${Math.round(c.risk_score)}`;
  return `${risk} · ${crit === 0 ? "no critical issues" : `${crit} critical`}`;
}

/** Enter a client (or go back to the MSP with null), then load the app afresh so every page refetches. */
export async function switchClient(id: string | null): Promise<void> {
  await mspApi.switch(id);
  window.location.assign("/");
}
