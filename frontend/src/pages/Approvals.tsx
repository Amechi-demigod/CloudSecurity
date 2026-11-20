import { Link } from "react-router-dom";
import { useAuth } from "../auth/context";
import { api, type ApprovalSettings } from "../api";
import { ApprovalList } from "../components/approvals";
import { Card, ErrorNote, PageHeader, Stat } from "../components/ui";
import { useApi } from "../lib/useApi";

function SettingsNote({ settings: s }: { settings: ApprovalSettings }) {
  const { platformAdmin } = useAuth();
  return (
    <Card title="How approvals work" className="mb-4">
      <ul className="list-inside list-disc space-y-1 text-sm text-ink-2">
        <li>
          Remote wipes and medium/high-risk scripts need a second admin. Requests expire after <strong>{s.ttl_hours} hours</strong> if nobody
          decides.
        </li>
        <li>
          Self-approval is{" "}
          {s.allow_self_approval ? (
            <strong className="text-sev-high">enabled</strong>
          ) : (
            <strong>disabled</strong>
          )}
          {s.allow_self_approval
            ? `: an admin may approve their own request, which then waits ${s.self_approval_cooldown_minutes} minutes before it runs and can be cancelled meanwhile.`
            : ": a different admin must approve every request."}{" "}
          It is off by default and is changed by Sentrigis.{platformAdmin && <> Operator note: <code>cnapp-ctl approvals self-approval enable</code>.</>}
        </li>
        <li>
          An approved wipe is valid for <strong>{s.wipe_command_ttl_minutes} minutes</strong>; if the device does not pick it up in time it expires
          and must be requested again.
        </li>
      </ul>
    </Card>
  );
}

export default function Approvals() {
  const summary = useApi(api.approvalSummary, [], 30000);
  const open = useApi(() => api.approvals({ status: "open" }), [], 15000);
  const history = useApi(() => api.approvals({ status: "final", limit: 100 }), [], 60000);
  const settings = summary.data?.settings ?? null;
  function reload() {
    summary.reload();
    open.reload();
    history.reload();
  }
  return (
    <div>
      <PageHeader
        title="Approvals"
        subtitle="Risky actions that need a second person to approve."
        actions={
          <>
            <Link to="/admin/users" className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">People</Link>
            <Link to="/admin/organization" className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">Organisation</Link>
          </>
        }
      />
      <ErrorNote error={summary.error} />
      {summary.data && (
        <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Stat label="Waiting for you" value={summary.data.actionable} sub="pending requests you can decide" />
          <Stat label="Pending" value={summary.data.pending} />
          <Stat label="Cooling off" value={summary.data.cooling_off} sub="self-approved, not yet run" />
        </div>
      )}
      {settings && <SettingsNote settings={settings} />}
      <Card title="Open requests" className="mb-4">
        <ErrorNote error={open.error} />
        <ApprovalList items={open.data} settings={settings} onChanged={reload} empty="Nothing is waiting for approval." sortParam="osort" />
      </Card>
      <Card title="History">
        <ErrorNote error={history.error} />
        <ApprovalList items={history.data} settings={settings} onChanged={reload} empty="No decided requests yet." sortParam="hsort" />
      </Card>
    </div>
  );
}
