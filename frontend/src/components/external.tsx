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


/** Fix-by text from the API's days_left / overdue_days (never from the due date: it lies in the future). */
export function FixBy({ due, daysLeft, overdueDays }: { due: string | null; daysLeft: number | null; overdueDays: number | null }) {
  if (!due) return <span className="text-ink-3">-</span>;
  if (overdueDays) return <span className="font-medium text-sev-critical">Overdue {overdueDays} d</span>;
  if (!daysLeft) return <span className="text-ink-2">Due today</span>;
  return <span className="text-ink-2">In {daysLeft} {daysLeft === 1 ? "day" : "days"}</span>;
}
