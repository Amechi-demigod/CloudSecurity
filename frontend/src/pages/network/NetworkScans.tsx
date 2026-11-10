import { Network } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../auth/context";
import NetworkScanWizard from "../../components/networkScan";
import { Breadcrumbs, Button, Card, Empty, ErrorNote, PageHeader, Tag } from "../../components/ui";
import { errMsg } from "../../lib/assets";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { networkApi, type NetScan } from "../../networkApi";
import { NetworkNav } from "./NetworkDevices";

const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const TONE = { succeeded: "good", failed: "critical", running: "accent", queued: "default", cancelled: "default" } as const;

function scheduleText(s: NetScan) {
  if (s.schedule === "manual") return "Manual";
  return `${s.schedule === "daily" ? "Daily" : `Weekly (${WEEKDAYS[s.schedule_weekday]})`} at ${s.schedule_time} UTC`;
}

export default function NetworkScans() {
  const isAdmin = useAuth().can("admin");
  const scans = useApi(networkApi.scans, [], 10000);
  const [editing, setEditing] = useState<NetScan | "new" | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  async function act(fn: () => Promise<unknown>, ok: string) {
    setErr(null);
    try {
      await fn();
      setMsg(ok);
      scans.reload();
    } catch (e) {
      setErr(errMsg(e));
    }
  }

  return (
    <div>
      <Breadcrumbs items={[{ label: "Network devices", to: "/network-devices" }, { label: "Network scans" }]} />
      <PageHeader
        title="Network scans"
        subtitle="Scans that find and identify the devices on your networks, run by a dedicated collector. Read-only."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <NetworkNav active="scans" />
            {isAdmin && !editing && (
              <Button variant="primary" onClick={() => setEditing("new")}>
                Add network scan
              </Button>
            )}
          </div>
        }
      />
      <ErrorNote error={scans.error ?? err} />
      {msg && <p className="mb-3 text-sm text-good">{msg}</p>}
      {editing && isAdmin && (
        <Card title={editing === "new" ? "Add network scan" : `Edit ${editing.name}`} className="mb-4">
          <NetworkScanWizard
            scan={editing === "new" ? undefined : editing}
            onCancel={() => setEditing(null)}
            onDone={() => {
              setEditing(null);
              scans.reload();
            }}
          />
        </Card>
      )}
      {scans.data && scans.data.length === 0 && !editing && (
        <Card>
          <Empty icon={Network} title="No network scans yet">
            Add a network scan to discover switches, firewalls, access points and printers.
          </Empty>
        </Card>
      )}
      <div className="space-y-3">
        {(scans.data ?? []).map((s) => (
          <Card key={s.id}>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="text-base font-semibold text-ink">{s.name}</h2>
                  {!s.enabled && <Tag>paused</Tag>}
                  {s.last_status && <Tag tone={TONE[s.last_status as keyof typeof TONE] ?? "default"}>{s.last_status}</Tag>}
                </div>
                <p className="mt-1 text-sm text-ink-2">
                  {s.targets.length} subnet{s.targets.length === 1 ? "" : "s"} · {s.address_count.toLocaleString()} addresses · {scheduleText(s)} · {s.pace === "gentle" ? "Gentle" : "Normal"} pace
                  {s.port_check ? " · port check on" : " · port check off"}
                </p>
                <p className="mt-0.5 break-words font-mono text-xs text-ink-3">{s.targets.join("  ")}</p>
                <p className="mt-1 text-xs text-ink-3">
                  Collector {s.collector ? `${s.collector.name} (${s.collector.state}${s.collector.ip ? `, ${s.collector.ip}` : ""})` : "none"}
                  {s.last_run_at && (
                    <>
                      {" · "}
                      last run <span title={fmtTime(s.last_run_at)}>{fmtAgo(s.last_run_at)}</span>
                      {s.last_summary.devices != null && `: ${s.last_summary.devices} devices`}
                      {s.last_summary.snmp != null && `, ${s.last_summary.snmp} via SNMP`}
                      {s.last_summary.duration_s ? `, ${Math.round(s.last_summary.duration_s / 60)} min` : ""}
                    </>
                  )}
                  {s.next_run_at && s.enabled && <> · next {fmtTime(s.next_run_at)}</>}
                </p>
                {s.last_summary.error && <p className="mt-1 text-xs text-sev-critical">{s.last_summary.error}</p>}
              </div>
              {isAdmin && (
                <div className="flex flex-wrap gap-2">
                  <Button onClick={() => void act(() => networkApi.runScan(s.id), `${s.name}: queued, the collector picks it up within about a minute.`)}>Run now</Button>
                  <Button onClick={() => setEditing(s)}>Edit</Button>
                  <Button
                    variant="danger"
                    onClick={() => {
                      if (window.confirm(`Delete the scan "${s.name}"? Devices already found are kept.`)) void act(() => networkApi.deleteScan(s.id), `${s.name} deleted.`);
                    }}
                  >
                    Delete
                  </Button>
                </div>
              )}
            </div>
          </Card>
        ))}
      </div>
      <p className="mt-4 text-xs text-ink-3">
        <Link to="/network-devices" className="text-accent hover:underline">
          Back to network devices
        </Link>
      </p>
    </div>
  );
}
