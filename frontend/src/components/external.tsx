import { ShieldAlert } from "lucide-react";
import { Tag } from "./ui";

/** Shown on every page of the module: the scan is indicative only. */
export function NotAsvBanner() {
  return (
    <div role="note" className="mb-4 flex items-start gap-2 rounded-lg border border-sev-medium/50 bg-sev-medium/10 px-3 py-2 text-sm text-ink-2">
      <ShieldAlert aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-sev-medium" />
      <span>
        <strong className="text-ink">Pre-ASV, not an ASV scan report or attestation.</strong> This scan helps you prepare for a PCI ASV scan. Only an
        Approved Scanning Vendor can issue an ASV scan report or an Attestation of Scan Compliance.
      </span>
    </div>
  );
}

export function ResultBadge({ result, label }: { result: "pass" | "fail" | null | string; label?: string }) {
  if (result !== "pass" && result !== "fail") return <Tag>Not scanned yet</Tag>;
  return <Tag tone={result === "pass" ? "good" : "critical"}>{label ?? (result === "pass" ? "Likely pass" : "Likely fail")}</Tag>;
}

export function StatusTag({ status }: { status: string }) {
  const tone = status === "open" ? "warn" : status === "resolved" ? "good" : status === "disputed" ? "accent" : "default";
  return <Tag tone={tone as "warn" | "good" | "accent" | "default"}>{status === "accepted" ? "accepted risk" : status}</Tag>;
}

