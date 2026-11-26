import { useState } from "react";
import { ApiError } from "../api";
import { statusLabel } from "../lib/labels";
import { Button, Card, Empty, ErrorNote, FilterBar, FilterChips, FilterSelect, NameCell, NumCell, Pill, PillRow, Table, TextCell, type PillTone } from "../components/ui";
import { fmtAgo, fmtTime } from "../lib/format";
import { useApi } from "../lib/useApi";
import { rankOf, ts, useSort } from "../lib/useSort";
import { useUrlState } from "../lib/useUrlState";
import { notificationsApi, type Delivery } from "../notificationsApi";

const SEV_TONE: Record<string, PillTone> = { critical: "critical", high: "high", medium: "medium", low: "neutral" };

export default function NotificationsLog({ isAdmin, onChange }: { isAdmin: boolean; onChange: () => void }) {
  const [status, setStatus] = useUrlState("status");
  const [kind, setKind] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);
  const { data, error, reload } = useApi(
    () => notificationsApi.deliveries({ status: status || undefined, kind: kind || undefined, limit: 300 }),
    [status, kind],
    10000,
  );
  const statusRank = rankOf(["dead", "skipped", "pending", "sending", "sent"]);
  const sorted = useSort(
    data,
    {
      time: (d) => ts(d.created_at),
      channel: (d) => d.channel_name || "(deleted)",
      notification: (d) => d.title,
      status: (d) => statusRank(d.status),
      attempts: (d) => d.attempts,
    },
    { key: "time", dir: "desc" },
    { time: "desc", attempts: "desc" },
  );

  async function retry(d: Delivery) {
    setActionError(null);
    try {
      await notificationsApi.retryDelivery(d.id);
      reload();
      onChange();
    } catch (e) {
      setActionError(e instanceof ApiError || e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div>
      <ErrorNote error={error ?? actionError} />
      <FilterBar count={data ? `${data.length} sent` : undefined}>
        <FilterSelect label="Status" value={status} onChange={setStatus} options={[{ value: "", label: "All" }, { value: "pending", label: "Waiting" }, { value: "sent", label: "Sent" }, { value: "dead", label: "Failed" }, { value: "skipped", label: "Not sent" }]} />
        <FilterSelect label="Kind" value={kind} onChange={setKind} options={[{ value: "", label: "All" }, { value: "event", label: "Events" }, { value: "digest", label: "Digests" }, { value: "test", label: "Tests" }]} />
      </FilterBar>
      <FilterChips
        chips={[status && { label: "Status", value: status === "dead" ? "Failed" : status === "skipped" ? "Not sent" : status, onRemove: () => setStatus("") }, kind && { label: "Kind", value: kind, onRemove: () => setKind("") }].filter((c): c is { label: string; value: string; onRemove: () => void } => !!c)}
        onClearAll={() => {
          setStatus("");
          setKind("");
        }}
      />
      <Card>
        {data && data.length === 0 ? (
          <Empty>No deliveries yet.</Empty>
        ) : (
          <Table
            tableId="notifications-log"
            head={[
              { label: "Time", sort: "time", w: 110 },
              { label: "Channel", sort: "channel", w: 220 },
              { label: "Notification", sort: "notification", w: 360 },
              { label: "Status", sort: "status", w: 130 },
              { label: "Attempts", sort: "attempts", w: 90, align: "right" },
              { label: "Details", w: 260 },
              ...(isAdmin ? [{ label: "Actions", srOnly: true, w: 90 }] : []),
            ]}
            sort={sorted.sort}
            onSort={sorted.onSort}
            noun="deliveries"
            pageSize={50}
          >
            {sorted.rows.map((d) => (
              <tr key={d.id}>
                <td className="px-3 py-2"><TextCell muted title={fmtTime(d.created_at)}>{fmtAgo(d.created_at)}</TextCell></td>
                <td className="px-3 py-2"><NameCell name={d.channel_name || "(deleted)"} sub={[d.channel_type, d.rule_name].filter(Boolean).join(" · ")} /></td>
                <td className="px-3 py-2">
                  <div className="flex min-w-0 items-center gap-2">
                    <Pill tone={SEV_TONE[d.severity] ?? "neutral"}>{d.severity[0].toUpperCase() + d.severity.slice(1)}</Pill>
                    {d.kind !== "event" && <Pill>{d.kind}</Pill>}
                    <span className="min-w-0 flex-1 truncate" title={d.title}>
                      {d.link ? <a className="hover:text-accent" href={d.link} target="_blank" rel="noreferrer noopener">{d.title}</a> : d.title}
                    </span>
                  </div>
                </td>
                <td className="px-3 py-2">
                  <PillRow>
                    <Pill tone={d.status === "dead" ? "high" : d.status === "skipped" ? "medium" : d.status === "sent" ? "good" : "info"}>{d.status === "dead" ? "Failed" : d.status === "skipped" ? "Not sent" : d.status === "pending" ? "Waiting" : statusLabel(d.status)}</Pill>
                  </PillRow>
                </td>
                <td className="px-3 py-2"><NumCell value={d.attempts} /></td>
                <td className="px-3 py-2">
                  <TextCell muted title={d.last_error ?? undefined}>
                    {d.last_error ?? (d.status === "sent" && d.sent_at ? `Delivered ${fmtAgo(d.sent_at)}` : d.status === "pending" ? `Next attempt ${fmtTime(d.next_attempt_at)}` : "")}
                  </TextCell>
                </td>
                {isAdmin && (
                  <td className="px-3 py-2">
                    {d.status === "dead" && d.kind !== "test" && <Button onClick={() => retry(d)}>Retry</Button>}
                  </td>
                )}
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}
