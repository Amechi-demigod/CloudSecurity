import { useState } from "react";
import { api } from "../../api";
import { Card, DetailDrawer, Empty, FilterBar, FilterChips, FilterSelect, NameCell, None, PageHeader, Pill, PillRow, Table, TextCell, type PillTone } from "../../components/ui";
import { fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { useSortState } from "../../lib/useSort";
import { PAGE_INFO } from "../../lib/pageInfo";

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
  "user_deleted",
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

function tone(action: string): PillTone {
  if (action.startsWith("login_fail") || action === "login_locked" || action === "login_rate_limited") return "high";
  if (action === "login_success") return "good";
  if (action.startsWith("user_") || action.startsWith("password_")) return "info";
  return "neutral";
}

const actionLabel = (a: string) => {
  const t = a.replace(/_/g, " ");
  return t[0].toUpperCase() + t.slice(1);
};

function detailText(d: Record<string, unknown>): string {
  return Object.entries(d)
    .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(" · ");
}

export default function AuditLog() {
  const [action, setAction] = useState("");
  // The server sorts the whole log (only the newest 500 are returned), so the sort goes to the API.
  const sorted = useSortState(["time", "action", "actor", "target", "ip"], { key: "time", dir: "desc" }, { time: "desc" });
  const { data, error, loading, reload } = useApi(() => api.auditLog({ action: action || undefined, limit: 500, sort: sorted.sort.key, dir: sorted.sort.dir }), [action, sorted.sort.key, sorted.sort.dir], 15000);

  const [open, setOpen] = useState<NonNullable<typeof data>[number] | null>(null);
  return (
    <div>
      <PageHeader title="Audit log" info={PAGE_INFO.audit} subtitle="Everything people and the system changed in your organisation." />
      <Card>
        <FilterBar count={data ? `${data.length} entries` : undefined}>
          <FilterSelect label="Action" value={action} onChange={setAction} options={ACTIONS.map((a) => ({ value: a, label: a ? actionLabel(a) : "All" }))} />
        </FilterBar>
        <FilterChips chips={action ? [{ label: "Action", value: actionLabel(action), onRemove: () => setAction("") }] : []} onClearAll={() => setAction("")} />
        <Table
          tableId="audit-log"
          head={[
            { label: "Time", sort: "time", w: 160 },
            { label: "Action", sort: "action", w: 260 },
            { label: "Who", sort: "actor", w: 240 },
            { label: "Target", sort: "target", w: 260 },
            { label: "IP", sort: "ip", w: 140 },
          ]}
          sort={sorted.sort}
          onSort={sorted.onSort}
          loading={loading}
          rowCount={data?.length ?? 0}
          noun="entries"
          pageSize={50}
          error={data ? null : error}
          onRetry={reload}
          empty={<Empty>No audit entries.</Empty>}
        >
          {data?.map((e) => (
            <tr key={e.id}>
              <td className="px-3 py-2"><TextCell muted title={fmtTime(e.timestamp)}>{fmtTime(e.timestamp)}</TextCell></td>
              <td className="px-3 py-2">
                <NameCell name={actionLabel(e.action)} onOpen={() => setOpen(e)} openLabel={`Open details for ${e.action}`} />
              </td>
              <td className="px-3 py-2">{e.actor_email ? <TextCell>{e.actor_email}</TextCell> : <None />}</td>
              <td className="px-3 py-2">{e.target ? <TextCell muted>{e.target}</TextCell> : <None />}</td>
              <td className="px-3 py-2">{e.ip ? <TextCell mono>{e.ip}</TextCell> : <None />}</td>
            </tr>
          ))}
        </Table>
      </Card>
      <DetailDrawer
        open={!!open}
        onClose={() => setOpen(null)}
        title={open ? actionLabel(open.action) : ""}
        sub={open ? <PillRow><Pill tone={tone(open.action)}>{open.action}</Pill></PillRow> : undefined}
        rows={
          open
            ? [
                { label: "Time", value: fmtTime(open.timestamp), copy: open.timestamp },
                { label: "Who", value: open.actor_email, copy: open.actor_email ?? undefined },
                { label: "Target", value: open.target, copy: open.target ?? undefined },
                { label: "IP", value: open.ip, copy: open.ip ?? undefined },
                { label: "Details", value: detailText(open.detail) || null, copy: detailText(open.detail) || undefined },
                { label: "Entry ID", value: open.id, copy: String(open.id) },
              ]
            : []
        }
      />
    </div>
  );
}
