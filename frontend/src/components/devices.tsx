import type { CheckStatus, Connectivity, DeviceHealth, DeviceIssue } from "../api";
import { SeverityBadge } from "./ui";

const HEALTH_STYLE: Record<DeviceHealth, { cls: string; icon: string; label: string }> = {
  healthy: { cls: "border-good/60 text-good", icon: "✓", label: "Healthy" },
  warning: { cls: "border-sev-medium/60 text-sev-medium", icon: "~", label: "Warning" },
  critical: { cls: "border-sev-critical/60 text-sev-critical", icon: "!", label: "At risk" },
  unknown: { cls: "border-line text-ink-3", icon: "?", label: "No data" },
};

/** Health pill: icon + text, never color alone. */
export function HealthBadge({ health }: { health: DeviceHealth }) {
  const h = HEALTH_STYLE[health];
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-medium ${h.cls}`}>
      <span aria-hidden>{h.icon}</span>
      {h.label}
    </span>
  );
}

const STATUS_STYLE: Record<CheckStatus, { cls: string; icon: string; label: string }> = {
  pass: { cls: "border-good/60 text-good", icon: "✓", label: "Pass" },
  fail: { cls: "border-sev-critical/60 text-sev-critical", icon: "✕", label: "Fail" },
  unknown: { cls: "border-line text-ink-3", icon: "?", label: "Unknown" },
  info: { cls: "border-accent/60 text-accent", icon: "i", label: "Info" },
};

export function CheckBadge({ status }: { status: CheckStatus }) {
  const s = STATUS_STYLE[status] ?? STATUS_STYLE.unknown;
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-medium ${s.cls}`}>
      <span aria-hidden>{s.icon}</span>
      {s.label}
    </span>
  );
}

const CONN_LABEL: Record<Connectivity, string> = { active: "Online", stale: "Stale", inactive: "Inactive", never: "Never" };

export function ConnectivityTag({ value }: { value: Connectivity }) {
  const cls =
    value === "active" ? "text-good" : value === "stale" ? "text-sev-medium" : value === "inactive" ? "text-sev-critical" : "text-ink-3";
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs ${cls}`}>
      <span aria-hidden className="inline-block h-2 w-2 rounded-full bg-current" />
      {CONN_LABEL[value]}
    </span>
  );
}

export function IssueList({ issues, compact = false }: { issues: DeviceIssue[]; compact?: boolean }) {
  if (issues.length === 0) return <span className="text-xs text-ink-3">None</span>;
  if (compact) {
    return (
      <div className="flex flex-wrap gap-1">
        {issues.slice(0, 3).map((i) => (
          <span key={i.code} title={i.detail || i.title} className="rounded border border-line bg-surface-2 px-1.5 py-0.5 text-[11px] text-ink-2">
            {i.title}
          </span>
        ))}
        {issues.length > 3 && <span className="text-[11px] text-ink-3">+{issues.length - 3} more</span>}
      </div>
    );
  }
  return (
    <ul className="space-y-2">
      {issues.map((i) => (
        <li key={i.code} className="flex items-start gap-2">
          <SeverityBadge severity={i.severity} />
          <div className="min-w-0">
            <div className="text-sm">{i.title}</div>
            {i.detail && <div className="text-xs text-ink-3">{i.detail}</div>}
          </div>
        </li>
      ))}
    </ul>
  );
}
