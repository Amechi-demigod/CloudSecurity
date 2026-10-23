import { useState } from "react";
import { api } from "../api";
import type { ConnectorSchedule, ScanRun, ScanSchedule } from "../api";
import { useAuth } from "../auth/context";
import { Button, Card, ErrorNote, PageHeader, SeverityBadge, Table, Tag } from "../components/ui";
import { fmtAgo, fmtHours, fmtTime, fmtUntil } from "../lib/format";
import { useApi } from "../lib/useApi";

function statusTone(status: ScanRun["status"]) {
  return status === "succeeded" ? "good" : status === "failed" ? "warn" : status === "skipped" ? "default" : "accent";
}

/** "Scheduled every 6 h · last scan 2h ago (succeeded) · next scan in 4h" */
function ScheduleLine({ schedule, c }: { schedule: ScanSchedule; c: ConnectorSchedule | undefined }) {
  if (!c) return null;
  const last = c.last_run;
  return (
    <div className="mt-3 flex flex-wrap items-center gap-x-1.5 gap-y-1 text-xs text-ink-2" data-testid={`schedule-${c.name}`}>
      {c.scheduled ? (
        <span>Scheduled every {fmtHours(schedule.interval_hours)}</span>
      ) : (
        <span className="text-ink-3">
          Not scheduled ({schedule.enabled ? c.not_scheduled_reason : "scheduled scans are off"})
        </span>
      )}
      <span aria-hidden="true">·</span>
      {last ? (
        <span title={fmtTime(last.started_at)}>
          last scan {fmtAgo(last.started_at)} <Tag tone={statusTone(last.status)}>{last.status}</Tag>
          {last.trigger === "scheduled" ? "" : " (manual)"}
        </span>
      ) : (
        <span>no scans yet</span>
      )}
      {c.scheduled && (
        <>
          <span aria-hidden="true">·</span>
          <span title={c.next_run_at ? fmtTime(c.next_run_at) : undefined}>
            {c.running ? "scanning now" : `next scan ${c.next_run_at ? fmtUntil(c.next_run_at) : "due now"}`}
          </span>
        </>
      )}
    </div>
  );
}

/** Admins can override SCAN_SCHEDULE_ENABLED / SCAN_INTERVAL_HOURS (stored in the database, audited). */
function ScheduleSettings({ schedule, onSaved }: { schedule: ScanSchedule; onSaved: () => void }) {
  const [enabled, setEnabled] = useState(schedule.enabled);
  const [hours, setHours] = useState(String(schedule.interval_hours));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const value = Number(hours);
  const valid = hours.trim() !== "" && value >= schedule.min_interval_hours && value <= schedule.max_interval_hours;

  async function save(body: { enabled?: boolean | null; interval_hours?: number | null }) {
    setBusy(true);
    setError(null);
    try {
      const r = await api.updateScanSchedule(body);
      setEnabled(r.enabled);
      setHours(String(r.interval_hours));
      onSaved();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-3 border-t border-line pt-3">
      <ErrorNote error={error} />
      <div className="flex flex-wrap items-end gap-3 text-sm">
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled
        </label>
        <label className="flex items-center gap-2">
          Every
          <input
            type="number"
            min={schedule.min_interval_hours}
            max={schedule.max_interval_hours}
            step={0.25}
            value={hours}
            onChange={(e) => setHours(e.target.value)}
            aria-label="Scan interval in hours"
            className="w-20 rounded border border-line bg-surface-2 px-2 py-1 text-sm text-ink"
          />
          hours
        </label>
        <Button variant="primary" disabled={busy || !valid} onClick={() => save({ enabled, interval_hours: value })}>
          Save
        </Button>
        {(schedule.enabled_overridden || schedule.interval_overridden) && (
          <Button disabled={busy} onClick={() => save({ enabled: null, interval_hours: null })}>
            Reset to defaults
          </Button>
        )}
      </div>
      <p className="mt-2 text-xs text-ink-3">
        Defaults from the server environment: {schedule.default_enabled ? "enabled" : "disabled"}, every{" "}
        {fmtHours(schedule.default_interval_hours)} (<code>SCAN_SCHEDULE_ENABLED</code>, <code>SCAN_INTERVAL_HOURS</code>).
        Allowed interval: {fmtHours(schedule.min_interval_hours)} to {fmtHours(schedule.max_interval_hours)}.
        {schedule.updated_by && schedule.updated_at && ` Last changed by ${schedule.updated_by} ${fmtAgo(schedule.updated_at)}.`}
      </p>
    </div>
  );
}

export default function Connectors() {
  const connectors = useApi(api.connectors, []);
  const scans = useApi(api.scans, [], 3000);
  const schedule = useApi(api.scanSchedule, [], 15000);
  const posture = useApi(api.postureRules, []);
  const detection = useApi(api.detectionRules, []);
  const [scanError, setScanError] = useState<string | null>(null);
  const auth = useAuth();
  const canScan = auth.can("analyst");
  const isAdmin = auth.can("admin");
  const scheduleOf = (name: string) => schedule.data?.connectors.find((x) => x.name === name);
  const running = scans.data?.some((s) => s.status === "running");

  async function runScan(name: string) {
    try {
      setScanError(null);
      await api.startScan(name);
      scans.reload();
      schedule.reload();
    } catch (e) {
      setScanError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div>
      <PageHeader title="Connectors & scans" subtitle="Cloud connectors are strictly read-only. Scan results merge into the same inventory and findings." />
      <ErrorNote error={connectors.error ?? scanError} />
      {schedule.data && (
        <Card
          className="mb-4"
          title="Scheduled scans"
          actions={
            schedule.data.enabled ? (
              <Tag tone="good">Every {fmtHours(schedule.data.interval_hours)}</Tag>
            ) : (
              <Tag>Off</Tag>
            )
          }
        >
          <p className="text-sm text-ink-2">
            Every configured cloud connector is scanned automatically, one scan at a time per connector. The interval
            counts from the start of the previous scheduled scan; manual scans do not move the schedule. A scheduled
            scan that is due while another scan of the same connector is still running is skipped. Failed scans raise
            a &quot;Cloud scans&quot; notification.
          </p>
          {isAdmin && (
            <ScheduleSettings
              key={`${schedule.data.enabled}-${schedule.data.interval_hours}`}
              schedule={schedule.data}
              onSaved={schedule.reload}
            />
          )}
        </Card>
      )}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {connectors.data?.map((c) => (
          <Card key={c.name} title={<span className="capitalize">{c.name}</span>}>
            <p className="text-sm text-ink-2">{c.description}</p>
            <div className="mt-3 flex items-center justify-between">
              {c.configured ? <Tag tone="good">Configured</Tag> : <Tag>Not configured</Tag>}
              {c.name === "azure" && (
                <Button
                  variant="primary"
                  disabled={!canScan || !c.configured || running}
                  onClick={() => runScan(c.name)}
                  title={
                    !canScan
                      ? "Requires the analyst or admin role"
                      : c.configured
                        ? "Run a read-only Azure posture scan"
                        : "Set AZURE_* env vars on the backend"
                  }
                >
                  {running ? "Scanning…" : "Run scan"}
                </Button>
              )}
            </div>
            {schedule.data && <ScheduleLine schedule={schedule.data} c={scheduleOf(c.name)} />}
            {c.name === "azure" && !c.configured && (
              <p className="mt-3 text-xs text-ink-3">
                Deployed on Azure: grant the backend&apos;s managed identity the <b>Reader</b> role on the subscriptions to
                scan and set <code>AZURE_SUBSCRIPTION_IDS</code> (see docs/DEPLOY_AZURE.md). Locally: set{" "}
                <code>AZURE_TENANT_ID</code>, <code>AZURE_CLIENT_ID</code>, <code>AZURE_CLIENT_SECRET</code> and{" "}
                <code>AZURE_SUBSCRIPTION_IDS</code> for a service principal with the <b>Reader</b> role, then restart the backend.
              </p>
            )}
          </Card>
        ))}
        <Card title="Runtime sensor">
          <p className="text-sm text-ink-2">
            Runtime sensors (e.g. a future eBPF agent) push events to <code className="text-ink">POST /api/runtime/events</code>.
            Schema at <code className="text-ink">GET /api/runtime/schema</code>.
          </p>
          <div className="mt-3">
            <Tag tone="accent">Push-based</Tag>
          </div>
        </Card>
      </div>

      <Card title="Scan history" className="mt-4">
        <Table head={["Connector", "Trigger", "Status", "Started", "Assets", "Open findings", "Summary"]}>
          {scans.data?.map((s) => (
            <tr key={s.id}>
              <td className="px-3 py-2 capitalize">{s.connector}</td>
              <td className="px-3 py-2 text-xs text-ink-2">{s.trigger ?? "manual"}</td>
              <td className="px-3 py-2">
                <Tag tone={statusTone(s.status)}>{s.status}</Tag>
              </td>
              <td className="px-3 py-2 text-xs text-ink-2">{fmtTime(s.started_at)}</td>
              <td className="px-3 py-2">{s.assets_found}</td>
              <td className="px-3 py-2">{s.findings_open}</td>
              <td className="px-3 py-2 text-xs text-ink-2">
                {s.message}
                {s.errors.length > 0 && (
                  <details className="mt-1">
                    <summary className="cursor-pointer text-ink-3">{s.errors.length} errors</summary>
                    <ul className="mt-1 list-disc pl-4 font-mono text-[11px]">
                      {s.errors.map((e, i) => (
                        <li key={i}>{e}</li>
                      ))}
                    </ul>
                  </details>
                )}
              </td>
            </tr>
          ))}
          {scans.data?.length === 0 && (
            <tr>
              <td colSpan={7} className="px-3 py-6 text-center text-sm text-ink-3">
                No scans yet.
              </td>
            </tr>
          )}
        </Table>
      </Card>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title={`Posture rules (${posture.data?.length ?? 0})`}>
          <ul className="max-h-96 space-y-1.5 overflow-y-auto text-sm">
            {posture.data?.map((r) => (
              <li key={r.id} className="flex items-center gap-2">
                <SeverityBadge severity={r.severity} />
                <span className="font-mono text-xs text-ink-3">{r.id}</span>
                <span className="truncate">{r.title}</span>
              </li>
            ))}
          </ul>
        </Card>
        <Card title={`Runtime detection rules (${detection.data?.length ?? 0})`}>
          <ul className="max-h-96 space-y-1.5 overflow-y-auto text-sm">
            {detection.data?.map((r) => (
              <li key={r.id} className="flex items-center gap-2">
                <SeverityBadge severity={r.severity} />
                <span className="font-mono text-xs text-ink-3">{r.mitre_technique_id}</span>
                <span className="truncate">{r.title}</span>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </div>
  );
}
