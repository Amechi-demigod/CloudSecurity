import { Bell } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../auth/context";
import { Card, Empty, ErrorNote } from "../../components/ui";
import { fmtAgo } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { trackingApi, type AlertGroup } from "../../trackingApi";

const FILTERS: { value: AlertGroup | ""; label: string }[] = [
  { value: "", label: "All" },
  { value: "outside_countries", label: "Outside countries" },
  { value: "not_seen", label: "Not seen" },
  { value: "hardware", label: "Hardware" },
  { value: "locked", label: "Locked" },
];
const DOT: Record<string, string> = {
  critical: "bg-sev-critical", high: "bg-sev-high", medium: "bg-sev-medium", low: "bg-sev-low",
};
const COLLAPSED = 6;
const EXPANDED = 100;

/** Computers & servers > Map: every tracking alert of the last 7 days across all computers, newest first. */
export default function RecentAlerts() {
  const { can } = useAuth();
  const [group, setGroup] = useState<AlertGroup | "">("");
  const [all, setAll] = useState(false);
  const { data, error, loading } = useApi(
    () => trackingApi.recentAlerts({ group, limit: all ? EXPANDED : COLLAPSED }),
    [group, all],
    60000,
  );
  const chip = "rounded-full border px-3 py-1 text-xs font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-accent";
  const days = data?.days ?? 7;
  return (
    <Card
      title={
        <span className="flex flex-wrap items-baseline justify-between gap-2">
          <span id="recent-alerts-title">Recent alerts</span>
          {data && <span className="text-xs font-normal text-ink-3"><b className="text-ink">{data.count_24h}</b> in the last 24 hours</span>}
        </span>
      }
    >
      <section aria-labelledby="recent-alerts-title">
        <div className="mb-3 flex flex-wrap gap-1.5" role="group" aria-label="Filter alerts by type">
          {FILTERS.map((f) => (
            <button key={f.value || "all"} type="button" aria-pressed={group === f.value} onClick={() => setGroup(f.value)}
              className={`${chip} ${group === f.value ? "border-accent bg-accent/10 text-accent" : "border-line text-ink-2 hover:bg-surface-2"}`}>
              {f.label}
            </button>
          ))}
        </div>
        {!data ? (
          error ? <ErrorNote error={error} /> : <p className="text-sm text-ink-3">{loading ? "Loading…" : ""}</p>
        ) : data.items.length === 0 ? (
          <Empty icon={Bell} title={`No tracking alerts in the last ${days} days.`}>
            {group ? "Nothing of this type. Choose All to see every type." : "Alerts appear here when a computer breaks one of your tracking rules."}
          </Empty>
        ) : (
          <ul className="-mx-4 divide-y divide-line border-t border-line">
            {data.items.map((a) => (
              <li key={a.id}>
                <Link to={`/devices/${encodeURIComponent(a.device_id)}?tab=Location`}
                  className="grid grid-cols-[10px_1fr_auto] items-start gap-3 px-4 py-2.5 text-sm hover:bg-surface-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent">
                  <span aria-hidden="true" className={`mt-1.5 h-2.5 w-2.5 rounded-full ${DOT[a.severity] ?? "bg-ink-3"}`} />
                  <span className="min-w-0">
                    <span className="font-semibold text-ink">{a.hostname}</span>
                    <span className="sr-only"> ({a.severity} severity)</span>{" "}
                    <span className="text-ink">{a.title}</span>
                    <span className="block text-xs text-ink-3">{a.detail_line}</span>
                  </span>
                  <span className="whitespace-nowrap text-xs text-ink-3">{fmtAgo(a.at)}</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
        {data && (
          <div className="mt-3 space-y-2 text-sm">
            {!data.notified && (
              <p className="rounded border border-sev-medium/50 bg-sev-medium/10 px-3 py-2 text-xs text-ink">
                These alerts are not sent anywhere yet.{" "}
                {can("admin") && <Link to="/notifications" className="font-medium text-accent hover:underline">Send them by email, Teams or Slack</Link>}
              </p>
            )}
            {!all && data.total > data.items.length && (
              <button type="button" onClick={() => setAll(true)} className="font-medium text-accent hover:underline">
                Show all alerts from the last {days} days ({data.total})
              </button>
            )}
            {all && data.total > COLLAPSED && (
              <button type="button" onClick={() => setAll(false)} className="font-medium text-accent hover:underline">Show fewer</button>
            )}
          </div>
        )}
      </section>
    </Card>
  );
}
