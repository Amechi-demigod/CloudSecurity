import { useState } from "react";
import { ApiError } from "../api";
import { Button, Card, Empty, ErrorNote, Select, SeverityBadge, Table, Tag } from "../components/ui";
import { fmtAgo, fmtTime } from "../lib/format";
import { useApi } from "../lib/useApi";
import { notificationsApi, type Delivery } from "../notificationsApi";

const STATUS_TONE: Record<Delivery["status"], "default" | "warn" | "good" | "accent"> = {
  pending: "accent",
  sending: "accent",
  sent: "good",
  dead: "warn",
};

export default function NotificationsLog({ isAdmin, onChange }: { isAdmin: boolean; onChange: () => void }) {
  const [status, setStatus] = useState("");
  const [kind, setKind] = useState("");
  const [actionError, setActionError] = useState<string | null>(null);
  const { data, error, reload } = useApi(
    () => notificationsApi.deliveries({ status: status || undefined, kind: kind || undefined, limit: 300 }),
    [status, kind],
    10000,
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
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <Select
          label="Status"
          value={status}
          onChange={setStatus}
          options={[
            { value: "", label: "All" },
            { value: "pending", label: "Pending / retrying" },
            { value: "sent", label: "Sent" },
            { value: "dead", label: "Dead-lettered" },
          ]}
        />
        <Select
          label="Kind"
          value={kind}
          onChange={setKind}
          options={[
            { value: "", label: "All" },
            { value: "event", label: "Events" },
            { value: "digest", label: "Digests" },
            { value: "test", label: "Tests" },
          ]}
        />
        <span className="text-xs text-ink-3">Secrets are redacted from errors. Entries are kept for NOTIFICATIONS_RETENTION_DAYS.</span>
      </div>
      <Card>
        {data && data.length === 0 ? (
          <Empty>No deliveries yet.</Empty>
        ) : (
          <Table head={["Time", "Channel", "Notification", "Status", "Attempts", "Details", ...(isAdmin ? [""] : [])]}>
            {data?.map((d) => (
              <tr key={d.id}>
                <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-2" title={fmtTime(d.created_at)}>
                  {fmtAgo(d.created_at)}
                </td>
                <td className="px-3 py-2 text-sm">
                  {d.channel_name || "(deleted)"}
                  <div className="text-[11px] text-ink-3">
                    {d.channel_type}
                    {d.rule_name && ` · ${d.rule_name}`}
                  </div>
                </td>
                <td className="max-w-[22rem] px-3 py-2">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={d.severity} />
                    {d.kind !== "event" && <Tag>{d.kind}</Tag>}
                  </div>
                  <div className="mt-0.5 truncate text-sm" title={d.title}>
                    {d.link ? (
                      <a className="hover:text-accent" href={d.link} target="_blank" rel="noreferrer noopener">
                        {d.title}
                      </a>
                    ) : (
                      d.title
                    )}
                  </div>
                </td>
                <td className="px-3 py-2">
                  <Tag tone={STATUS_TONE[d.status]}>{d.status === "dead" ? "dead-lettered" : d.status}</Tag>
                </td>
                <td className="px-3 py-2 text-xs text-ink-2">{d.attempts}</td>
                <td className="max-w-[20rem] px-3 py-2 text-xs text-ink-3">
                  {d.status === "sent" && d.sent_at && <span>Delivered {fmtAgo(d.sent_at)}{d.response_status ? ` (HTTP ${d.response_status})` : ""}</span>}
                  {d.status === "pending" && <div>Next attempt {fmtTime(d.next_attempt_at)}</div>}
                  {d.last_error && <div className="break-words text-sev-high">{d.last_error}</div>}
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
