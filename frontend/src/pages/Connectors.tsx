import { useState, type ReactNode } from "react";
import { api } from "../api";
import type { ConnectorSchedule, ScanRun, ScanSchedule } from "../api";
import { useAuth } from "../auth/context";
import { Button, Card, ErrorNote, PageHeader, SeverityBadge, Table, Tag } from "../components/ui";
import { PROVIDER_LABEL, SCOPE_LABEL, fmtAgo, fmtHours, fmtTime, fmtUntil } from "../lib/format";
import { useApi } from "../lib/useApi";

const CLOUD = new Set(["azure", "aws", "gcp"]);

const SETUP: Record<string, ReactNode> = {
  azure: (
    <>
      Deployed on Azure: grant the backend&apos;s managed identity the <b>Reader</b> role on the subscriptions to scan and set{" "}
      <code>AZURE_SUBSCRIPTION_IDS</code> (see docs/DEPLOY_AZURE.md). Locally: set <code>AZURE_TENANT_ID</code>,{" "}
      <code>AZURE_CLIENT_ID</code>, <code>AZURE_CLIENT_SECRET</code> and <code>AZURE_SUBSCRIPTION_IDS</code> for a service
      principal with the <b>Reader</b> role, then restart the backend.
    </>
  ),
  aws: (
    <>
      Create a dedicated IAM user (or use an instance role) with the AWS managed policies <b>SecurityAudit</b> and{" "}
      <b>ViewOnlyAccess</b>, set <code>AWS_ACCESS_KEY_ID</code> / <code>AWS_SECRET_ACCESS_KEY</code> (or{" "}
      <code>AWS_USE_DEFAULT_CREDENTIALS=true</code>) and optionally <code>AWS_ROLE_ARNS</code> + <code>AWS_EXTERNAL_ID</code> for
      other accounts, then restart (on-prem: <code>sudo cnapp-ctl restart</code>). See docs/CONNECT_AWS.md.
    </>
  ),
  gcp: (
    <>
      Create a service account with <b>roles/viewer</b> and <b>roles/iam.securityReviewer</b>, install its key with{" "}
      <code>sudo cnapp-ctl gcp-key install KEY.json</code> (never put it in cnapp.env) and set <code>GCP_PROJECT_IDS</code>{" "}
      or <code>GCP_ORGANIZATION_ID</code>, then restart. See docs/CONNECT_GCP.md.
    </>
  ),
};

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

type Unit = "hours" | "days";

/** Whole hours (1-23) or whole days (1-7, capped by the server maximum), stepped by 1. */
function unitRange(unit: Unit, schedule: ScanSchedule): [number, number] {
  return unit === "days"
    ? [1, Math.max(1, Math.floor(schedule.max_interval_hours / 24))]
    : [Math.max(1, Math.ceil(schedule.min_interval_hours)), Math.min(23, schedule.max_interval_hours)];
}

function fromHours(h: number): { unit: Unit; count: number } {
  return h >= 24 && h % 24 === 0 ? { unit: "days", count: h / 24 } : { unit: "hours", count: Math.min(23, Math.max(1, Math.round(h))) };
}

/** Admins can override SCAN_SCHEDULE_ENABLED / SCAN_INTERVAL_HOURS (stored in the database, audited). */
function ScheduleSettings({ schedule, onSaved }: { schedule: ScanSchedule; onSaved: () => void }) {
  const initial = fromHours(schedule.interval_hours);
  const [enabled, setEnabled] = useState(schedule.enabled);
  const [unit, setUnit] = useState<Unit>(initial.unit);
  const [count, setCount] = useState(initial.count);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [min, max] = unitRange(unit, schedule);
  const clamp = (n: number, u: Unit = unit) => {
    const [lo, hi] = unitRange(u, schedule);
    return Math.min(hi, Math.max(lo, Math.round(n) || lo));
  };
  const hours = unit === "days" ? count * 24 : count;
  const changed = enabled !== schedule.enabled || hours !== schedule.interval_hours;

  async function save(body: { enabled?: boolean | null; interval_hours?: number | null }) {
    setBusy(true);
    setError(null);
    try {
      const r = await api.updateScanSchedule(body);
      const next = fromHours(r.interval_hours);
      setEnabled(r.enabled);
      setUnit(next.unit);
      setCount(next.count);
      onSaved();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const unitLabel = unit === "days" ? (count === 1 ? "day" : "days") : count === 1 ? "hour" : "hours";
  const stepBtn = "grid h-8 w-8 place-items-center rounded border border-line bg-surface-1 text-base text-ink-2 hover:bg-surface-2 disabled:opacity-40";

  return (
    <div className="mt-3 border-t border-line pt-3">
      <ErrorNote error={error} />
      <div className="flex flex-wrap items-center gap-x-5 gap-y-3 text-sm">
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled
        </label>
        <div className="flex items-center gap-2">
          <span className="text-ink-2">Scan every</span>
          <div role="radiogroup" aria-label="Interval unit" className="flex overflow-hidden rounded border border-line">
            {(["hours", "days"] as Unit[]).map((u) => (
              <button
                key={u}
                type="button"
                role="radio"
                aria-checked={unit === u}
                onClick={() => {
                  setUnit(u);
                  setCount((c) => clamp(u === "days" ? Math.max(1, Math.round(c / 24)) : c * (unit === "days" ? 24 : 1), u));
                }}
                className={`px-3 py-1 text-sm capitalize ${unit === u ? "bg-accent/15 font-semibold text-accent" : "text-ink-2 hover:bg-surface-2"}`}
              >
                {u}
              </button>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          <button type="button" className={stepBtn} aria-label={`One ${unit === "days" ? "day" : "hour"} less`} disabled={count <= min}
            onClick={() => setCount((c) => clamp(c - 1))}>
            −
          </button>
          <input
            type="number"
            inputMode="numeric"
            min={min}
            max={max}
            step={1}
            value={count}
            onChange={(e) => setCount(clamp(Number(e.target.value)))}
            aria-label={`Scan interval in ${unit}`}
            className="w-14 rounded border border-line bg-surface-2 px-2 py-1 text-center text-sm text-ink"
          />
          <button type="button" className={stepBtn} aria-label={`One ${unit === "days" ? "day" : "hour"} more`} disabled={count >= max}
            onClick={() => setCount((c) => clamp(c + 1))}>
            +
          </button>
          <span className="ml-1 text-ink-2">{unitLabel}</span>
        </div>
        <Button variant="primary" disabled={busy || !changed} onClick={() => save({ enabled, interval_hours: hours })}>
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
        Choose 1 to {unitRange("hours", schedule)[1]} hours or 1 to {unitRange("days", schedule)[1]} days.
        {schedule.updated_by && schedule.updated_at && ` Last changed by ${schedule.updated_by} ${fmtAgo(schedule.updated_at)}.`}
      </p>
    </div>
  );
}

export default function Connectors() {
  const connectors = useApi(api.connectors, [], 15000);
  const scans = useApi(api.scans, [], 3000);
  const schedule = useApi(api.scanSchedule, [], 15000);
  const posture = useApi(api.postureRules, []);
  const detection = useApi(api.detectionRules, []);
  const [scanError, setScanError] = useState<string | null>(null);
  const auth = useAuth();
  const canScan = auth.can("analyst");
  const isAdmin = auth.can("admin");
  const scheduleOf = (name: string) => schedule.data?.connectors.find((x) => x.name === name);
  const runningFor = (name: string) => scans.data?.some((s) => s.connector === name && s.status === "running");

  async function runScan(name: string) {
    try {
      setScanError(null);
      await api.startScan(name);
      scans.reload();
      schedule.reload();
      connectors.reload();
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
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 2xl:grid-cols-3">
        {connectors.data?.filter((c) => CLOUD.has(c.name)).map((c) => {
          const cloud = CLOUD.has(c.name);
          const running = runningFor(c.name);
          const label = PROVIDER_LABEL[c.name] ?? c.name;
          const scopeLabel = SCOPE_LABEL[c.provider] ?? "Scope";
          const discovered = c.discovered_scopes ?? [];
          return (
            <Card key={c.name} title={cloud ? label : <span className="capitalize">{c.name}</span>}>
              <p className="text-sm text-ink-2">{c.description}</p>
              <div className="mt-3 flex items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-1.5">
                  {c.configured ? <Tag tone="good">Configured</Tag> : <Tag>Not configured</Tag>}
                  {c.auth_mode && <Tag>{c.auth_mode.replace("_", " ")}</Tag>}
                </div>
                {cloud && (
                  <Button
                    variant="primary"
                    disabled={!canScan || !c.configured || running}
                    onClick={() => runScan(c.name)}
                    title={
                      !canScan
                        ? "Requires the analyst or admin role"
                        : c.configured
                          ? `Run a read-only ${label} posture scan`
                          : c.setup_hint
                    }
                  >
                    {running ? "Scanning…" : "Run scan"}
                  </Button>
                )}
              </div>
              {cloud && (
                <dl className="mt-3 grid grid-cols-[7.5rem_1fr] gap-x-2 gap-y-1 text-xs">
                  <dt className="text-ink-3">{scopeLabel}s</dt>
                  <dd className="break-words text-ink-2">
                    {discovered.length > 0
                      ? discovered.map((d) => (d.name && d.name !== d.id ? `${d.name} (${d.id})` : d.id)).join(", ")
                      : c.scope?.length
                        ? c.scope.join(", ")
                        : "—"}
                  </dd>
                  {c.regions && (
                    <>
                      <dt className="text-ink-3">Regions</dt>
                      <dd className="text-ink-2">{c.regions.join(", ")}</dd>
                    </>
                  )}
                  {c.last_scan && c.last_scan.errors.length > 0 && (
                    <>
                      <dt className="text-ink-3">Last scan</dt>
                      <dd className="text-sev-high">{c.last_scan.errors.length} errors (see Scan history)</dd>
                    </>
                  )}
                </dl>
              )}
              {schedule.data && <ScheduleLine schedule={schedule.data} c={scheduleOf(c.name)} />}
              {c.problem && <p className="mt-2 text-xs text-sev-high">{c.problem}</p>}
              {cloud && !c.configured && <p className="mt-3 text-xs text-ink-3">{SETUP[c.name]}</p>}
            </Card>
          );
        })}
      </div>

      <Card title="Scan history" className="mt-4">
        <Table head={["Connector", "Trigger", "Status", "Started", "Assets", "Open findings", "Summary"]}>
          {scans.data?.map((s) => (
            <tr key={s.id}>
              <td className="px-3 py-2">{PROVIDER_LABEL[s.connector] ?? <span className="capitalize">{s.connector}</span>}</td>
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
