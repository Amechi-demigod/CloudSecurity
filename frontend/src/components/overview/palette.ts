// Overview colours: severity marks only (--color-ov-* in index.css, with dark-mode steps) plus the neutral
// "none / healthy" fill. Always drawn next to a text label, never the only signal.
import type { Severity } from "../../api";

export const OV = {
  critical: "var(--color-ov-critical)",
  high: "var(--color-ov-high)",
  medium: "var(--color-ov-medium)",
  low: "var(--color-ov-low)",
  attention: "var(--color-ov-high)",
  none: "var(--color-ov-none)",
} as const;
export const SEV_LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

export interface Part {
  label: string;
  count: number;
  color: string;
}


export const SEV4: Exclude<Severity, "info">[] = ["critical", "high", "medium", "low"];
