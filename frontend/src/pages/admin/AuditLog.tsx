import { useState } from "react";
import { api } from "../../api";
import { Card, Empty, ErrorNote, PageHeader, Select, Table, Tag } from "../../components/ui";
import { fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";

const ACTIONS = [
  "",
  "login_success",
  "login_failure",
  "login_locked",
  "login_rate_limited",
  "logout",
  "password_changed",
  "password_reset",
  "user_created",
  "user_updated",
  "user_bootstrapped",
  "finding_updated",
  "alert_updated",
  "scan_started",
  "notification_channel_created",
  "notification_channel_updated",
  "notification_channel_deleted",
  "notification_channel_tested",
  "notification_rule_created",
  "notification_rule_updated",
  "notification_rule_deleted",
  "notification_delivery_retried",
];

function tone(action: string): "default" | "warn" | "good" | "accent" {
  if (action.startsWith("login_fail") || action === "login_locked" || action === "login_rate_limited") return "warn";
  if (action === "login_success") return "good";
  if (action.startsWith("user_") || action.startsWith("password_")) return "accent";
  return "default";
}

function detailText(d: Record<string, unknown>): string {
  return Object.entries(d)
    .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(" · ");
}

export default function AuditLog() {
  const [action, setAction] = useState("");
  const { data, error } = useApi(() => api.auditLog({ action: action || undefined, limit: 500 }), [action], 15000);

  return (
    <div>
      <PageHeader title="Audit log" subtitle="Sign-ins, sign-outs, user changes and analyst actions (most recent first)." />
      <ErrorNote error={error} />
      <div className="mb-3">
        <Select label="Action" value={action} onChange={setAction} options={ACTIONS} />
      </div>
      <Card>
        {data && data.length === 0 ? (
          <Empty>No audit entries.</Empty>
        ) : (
          <Table head={["Time", "Action", "Actor", "Target", "IP", "Details"]}>
            {data?.map((e) => (
              <tr key={e.id}>
                <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-2">{fmtTime(e.timestamp)}</td>
                <td className="px-3 py-2">
                  <Tag tone={tone(e.action)}>{e.action}</Tag>
                </td>
                <td className="px-3 py-2 text-sm">{e.actor_email ?? "-"}</td>
                <td className="max-w-[16rem] truncate px-3 py-2 text-xs text-ink-2" title={e.target ?? ""}>
                  {e.target ?? "-"}
                </td>
                <td className="px-3 py-2 font-mono text-xs text-ink-3">{e.ip ?? "-"}</td>
                <td className="px-3 py-2 text-xs text-ink-3">{detailText(e.detail)}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}
