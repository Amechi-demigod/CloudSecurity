import { Play } from "lucide-react";
import { useState, type ReactNode } from "react";
import { api } from "../api";
import type { Connector, ConnectorSchedule, ScanRun, ScanSchedule } from "../api";
import { useAuth } from "../auth/context";
import { ConnectCloud, ConnectionForm, ProviderMark } from "../components/cloudConnect";
import { Button, Card, ErrorNote, PageHeader, SeverityBadge, Table, Tag } from "../components/ui";
import { CLOUD_NAME, CLOUD_PROVIDERS, CLOUD_ROLE, CLOUD_SCOPE } from "../lib/cloudSetup";
import { fmtAgo, fmtHours, fmtTime, fmtUntil } from "../lib/format";
import { useApi } from "../lib/useApi";
import { orgApi, type ConnectorConfig, type Provider } from "../orgApi";

const isCloud = (name: string): name is Provider => (CLOUD_PROVIDERS as string[]).includes(name);
const cloudName = (name: string) => (isCloud(name) ? CLOUD_NAME[name] : name === "simulated" ? "Simulated" : name);

const STATUS_TEXT: Record<ScanRun["status"], string> = {
  succeeded: "Succeeded",
  failed: "Failed",
  skipped: "Skipped",
  running: "Running",
};

const STATUS_COLOR: Record<ScanRun["status"], string> = {
  succeeded: "text-good",
  failed: "text-sev-high",
  skipped: "text-ink-3",
  running: "text-accent",
};

/** "1m 48s" between start and finish; null while running. */
function duration(run: ScanRun): string | null {
  if (!run.finished_at) return null;
  const s = Math.max(0, Math.round((new Date(run.finished_at).getTime() - new Date(run.started_at).getTime()) / 1000));
  return s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m`;
}

function trigger(run: ScanRun): string {
  if (run.trigger === "scheduled") return "Scheduled";
  if (run.trigger === "first_scan") return "First scan";
  return run.triggered_by ? `Manual (${run.triggered_by})` : "Manual";
}

function signed(n: number) {
  return n > 0 ? `+${n.toLocaleString()}` : n < 0 ? `−${Math.abs(n).toLocaleString()}` : "no change";
}

/** Subscriptions / accounts / projects: what scans found, else what is configured. */
function scopeCount(c: Connector): number {
  const configured = c.scope.filter((s) => !s.startsWith("organizations/")).length;
  return Math.max(c.discovered_scopes?.length ?? 0, configured);
}

function StatCell({ label, value, sub, valueClass = "text-ink" }: { label: string; value: ReactNode; sub?: ReactNode; valueClass?: string }) {
  return (
    <div className="min-w-0 border-line py-1 sm:border-l sm:px-4 sm:first:border-l-0 sm:first:pl-0">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-ink-3">{label}</div>
      <div className={`mt-0.5 text-lg font-semibold ${valueClass}`}>{value}</div>
      {sub && <div className="text-xs text-ink-3">{sub}</div>}
    </div>
  );
}

/** One connected cloud: status, actions and the last / next scan with what it found. */
function CloudCard({
  c,
  config,
  schedule,
  sched,
  runs,
  canScan,
  isAdmin,
  onScan,
  onSaved,
}: {
  c: Connector;
  config: ConnectorConfig | undefined;
  schedule: ScanSchedule | null;
  sched: ConnectorSchedule | undefined;
  runs: ScanRun[];
  canScan: boolean;
  isAdmin: boolean;
  onScan: () => void;
  onSaved: (saved: ConnectorConfig) => void;
}) {
  const provider = c.name as Provider;
  const [editing, setEditing] = useState(false);
  const last = runs[0] ?? c.last_scan ?? undefined;
  const running = runs.some((r) => r.status === "running") || !!sched?.running;
  const done = runs.filter((r) => r.status === "succeeded");
  const [latest, previous] = done;
  const n = scopeCount(c);
  const [one, many] = CLOUD_SCOPE[provider];
  const errors = last?.errors.length ?? 0;

  let next: { value: ReactNode; sub?: ReactNode } | null = null;
  if (schedule && sched) {
    next = !sched.scheduled
      ? { value: "Off", sub: schedule.enabled ? sched.not_scheduled_reason : "scheduled scans are off" }
      : {
          value: sched.running ? "Scanning now" : sched.next_run_at ? fmtUntil(sched.next_run_at) : "Due now",
          sub: `every ${fmtHours(schedule.interval_hours)}`,
        };
  }

  return (
    <Card className="mb-4">
      <div className="flex flex-wrap items-start justify-between gap-4 px-1">
        <div className="flex min-w-0 items-center gap-3">
          <ProviderMark provider={provider} size={32} />
          <div className="min-w-0">
            <h2 className="text-base font-semibold text-ink">{CLOUD_NAME[provider]}</h2>
            <div className="flex flex-wrap items-center gap-x-1.5 text-[13px] text-ink-3">
              <span aria-hidden className="inline-block h-2 w-2 rounded-full bg-good" />
              <span>
                Connected{n > 0 && ` · ${n} ${n === 1 ? one : many}`} · read-only ({CLOUD_ROLE[provider]})
              </span>
              {config?.from_environment && <Tag>from server environment</Tag>}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {isAdmin && (
            <Button onClick={() => setEditing((v) => !v)} disabled={editing}>
              Edit connection
            </Button>
          )}
          {canScan && (
            <Button variant="primary" disabled={running} onClick={onScan} title={`Run a read-only ${CLOUD_NAME[provider]} posture scan now`}>
              <span className="inline-flex items-center gap-1.5">
                <Play aria-hidden className="h-3.5 w-3.5 fill-current" />
                {running ? "Scanning…" : "Run scan"}
              </span>
            </Button>
          )}
        </div>
      </div>
      <div className="mt-4 grid grid-cols-2 gap-y-3 px-1 sm:grid-cols-4" data-testid={`stats-${provider}`}>
        <StatCell
          label="Last scan"
          value={last ? STATUS_TEXT[last.status] : "Not yet"}
          valueClass={last ? STATUS_COLOR[last.status] : "text-ink-3"}
          sub={last && <span title={fmtTime(last.started_at)}>{[fmtAgo(last.started_at), duration(last)].filter(Boolean).join(" · ")}</span>}
        />
        {next && <StatCell label="Next scan" value={next.value} sub={next.sub} />}
        {latest && (
          <StatCell
            label="Resources"
            value={latest.assets_found.toLocaleString()}
            sub={previous ? `${signed(latest.assets_found - previous.assets_found)} since last scan` : "from the last scan"}
          />
        )}
        {latest && (
          <StatCell
            label="Findings"
            value={latest.findings_open.toLocaleString()}
            sub={previous ? `${signed(latest.findings_open - previous.findings_open)} since last scan` : "open"}
          />
        )}
      </div>
      {errors > 0 && (
        <p className="mt-3 px-1 text-xs text-sev-high">
          The last scan reported {errors} {errors === 1 ? "error" : "errors"} (see Scan history).
        </p>
      )}
      {c.problem && <p className="mt-2 px-1 text-xs text-sev-high">{c.problem}</p>}
      {editing && (
        <div className="mt-4 border-t border-line px-1 pt-4">
          <h3 className="mb-3 text-[13px] font-semibold text-ink">Edit {CLOUD_NAME[provider]} connection</h3>
          <div className="max-w-xl">
            <ConnectionForm
              provider={provider}
              current={config}
              edit
              onCancel={() => setEditing(false)}
              onSaved={(saved) => {
                setEditing(false);
                onSaved(saved);
              }}
            />
          </div>
        </div>
      )}
    </Card>
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
    <div className="mt-3">
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
  const auth = useAuth();
  const canScan = auth.can("analyst");
  const isAdmin = auth.can("admin");
  const connectors = useApi(api.connectors, [], 15000);
  const scans = useApi(api.scans, [], 3000);
  const schedule = useApi(api.scanSchedule, [], 15000);
  const configs = useApi(() => (isAdmin ? orgApi.connectors() : Promise.resolve(null)), [isAdmin]);
  const posture = useApi(api.postureRules, []);
  const detection = useApi(api.detectionRules, []);
  const [scanError, setScanError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [connecting, setConnecting] = useState<Provider | null>(null);

  const clouds = (connectors.data ?? []).filter((c) => isCloud(c.name));
  const connected = clouds.filter((c) => c.configured);
  const unconnected = CLOUD_PROVIDERS.filter((p) => !connected.some((c) => c.name === p));
  const configOf = (p: string) => configs.data?.find((x) => x.provider === p);
  const runsOf = (p: string) => (scans.data ?? []).filter((s) => s.connector === p && s.status !== "skipped");

  function reloadAll() {
    connectors.reload();
    scans.reload();
    schedule.reload();
    configs.reload();
  }

  async function runScan(name: string) {
    try {
      setScanError(null);
      await api.startScan(name);
      reloadAll();
    } catch (e) {
      setScanError(e instanceof Error ? e.message : String(e));
    }
  }

  function saved(c: ConnectorConfig) {
    setConnecting(null);
    const name = CLOUD_NAME[c.provider];
    setNotice(
      !c.stored
        ? `${name} disconnected.`
        : [c.test_message ?? `${name} saved.`, c.first_scan_id ? "The first scan has started." : null].filter(Boolean).join(" "),
    );
    reloadAll();
  }

  const loaded = connectors.data !== null;
  const before = loaded && connected.length === 0;

  return (
    <div>
      <PageHeader title="Connectors & scans" subtitle="Cloud connectors are strictly read-only. Scan results merge into the same inventory and findings." />
      <ErrorNote error={connectors.error ?? scanError} />
      {notice && (
        <div role="status" className="mb-4 flex items-start justify-between gap-3 rounded border border-good/60 bg-good/10 px-3 py-2 text-sm text-ink">
          <span>{notice}</span>
          <button className="text-ink-3 hover:text-ink" onClick={() => setNotice(null)} aria-label="Dismiss">
            ✕
          </button>
        </div>
      )}

      {before &&
        (isAdmin ? (
          <ConnectCloud providers={CLOUD_PROVIDERS} configs={configs.data} onSaved={saved} />
        ) : (
          <Card className="mb-4">
            <h2 className="text-base font-semibold text-ink">No cloud account connected yet</h2>
            <p className="mt-1 text-sm text-ink-3">
              Scans start once an organisation administrator connects Azure, AWS or Google Cloud with a read-only identity.
            </p>
          </Card>
        ))}

      {connected.map((c) => (
        <CloudCard
          key={c.name}
          c={c}
          config={configOf(c.name)}
          schedule={schedule.data}
          sched={schedule.data?.connectors.find((x) => x.name === c.name)}
          runs={runsOf(c.name)}
          canScan={canScan}
          isAdmin={isAdmin}
          onScan={() => void runScan(c.name)}
          onSaved={saved}
        />
      ))}

      {!before && connecting && isAdmin && (
        <ConnectCloud
          providers={unconnected}
          configs={configs.data}
          initial={connecting}
          title="Connect another cloud"
          onSaved={saved}
          onCancel={() => setConnecting(null)}
        />
      )}

      {loaded && !before && (
        <div className="mb-4 grid grid-cols-1 gap-4 xl:grid-cols-12">
          {schedule.data && (
            <Card
              className={isAdmin && unconnected.length > 0 ? "xl:col-span-5" : "xl:col-span-12"}
              title="Scheduled scans"
              actions={schedule.data.enabled ? <Tag tone="good">On</Tag> : <Tag>Off</Tag>}
            >
              <p className="text-sm text-ink-2">
                Every connected cloud is scanned automatically
                {schedule.data.enabled ? `, every ${fmtHours(schedule.data.interval_hours)}` : " when this is on"}. One scan at a
                time per cloud; manual scans do not move the schedule.
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
          {isAdmin && unconnected.length > 0 && (
            <Card className="xl:col-span-7" title="Connect another cloud" actions={<span className="text-xs text-ink-3">optional</span>}>
              <div className="flex flex-wrap gap-2.5">
                {unconnected.map((p) => (
                  <button
                    key={p}
                    type="button"
                    onClick={() => setConnecting(p)}
                    className={`flex items-center gap-2 rounded-lg border bg-surface-1 px-3.5 py-2 text-sm transition hover:bg-surface-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
                      connecting === p ? "border-accent" : "border-line"
                    }`}
                  >
                    <ProviderMark provider={p} />
                    <b className="font-semibold text-ink">{CLOUD_NAME[p]}</b>
                    <span className="text-xs text-ink-3">Not connected</span>
                    <span className="text-accent">Connect →</span>
                  </button>
                ))}
              </div>
              <p className="mt-2.5 text-xs text-ink-3">Opens the same copy-a-script setup for that cloud.</p>
            </Card>
          )}
        </div>
      )}

      <Card title="Scan history" className="mt-4">
        {scans.data?.length === 0 ? (
          <p className="text-sm text-ink-3">
            {before
              ? "No scans yet. Your first scan starts automatically after you connect a cloud account."
              : "No scans yet."}
          </p>
        ) : (
          <Table head={["Started", "Cloud", "Trigger", "Result", "Duration", "Resources", "Findings"]} loading={scans.loading} rowCount={scans.data?.length}>
            {scans.data?.map((s) => (
              <tr key={s.id}>
                <td className="whitespace-nowrap px-3 py-2 text-ink-2" title={fmtTime(s.started_at)}>
                  {new Date(s.started_at).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })}
                </td>
                <td className="px-3 py-2">
                  <span className="inline-flex items-center gap-1.5">
                    {isCloud(s.connector) && <ProviderMark provider={s.connector} size={12} />}
                    {cloudName(s.connector)}
                  </span>
                </td>
                <td className="px-3 py-2 text-ink-2">{trigger(s)}</td>
                <td className="px-3 py-2">
                  <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-ink">
                    <span aria-hidden className={STATUS_COLOR[s.status]}>
                      ●
                    </span>
                    {STATUS_TEXT[s.status]}
                  </span>
                  {(s.status !== "succeeded" || s.errors.length > 0) && s.message && (
                    <div className="mt-1 max-w-md text-xs text-ink-3">{s.message}</div>
                  )}
                  {s.errors.length > 0 && (
                    <details className="mt-1 text-xs">
                      <summary className="cursor-pointer text-ink-3">{s.errors.length} errors</summary>
                      <ul className="mt-1 list-disc pl-4 font-mono text-[11px] text-ink-2">
                        {s.errors.map((e, i) => (
                          <li key={i}>{e}</li>
                        ))}
                      </ul>
                    </details>
                  )}
                </td>
                <td className="px-3 py-2 text-ink-2">{duration(s) ?? "—"}</td>
                <td className="px-3 py-2">{s.status === "succeeded" ? s.assets_found.toLocaleString() : "—"}</td>
                <td className="px-3 py-2">{s.status === "succeeded" ? s.findings_open.toLocaleString() : "—"}</td>
              </tr>
            ))}
          </Table>
        )}
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
