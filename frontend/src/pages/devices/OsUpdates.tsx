import { CheckCircle2, Download, RefreshCw } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { ApiError, type DeviceDetail as Device } from "../../api";
import { useAuth } from "../../auth/context";
import { IssueList } from "../../components/devices";
import { Button, Card, Empty, ErrorNote, Select, Table, Tag } from "../../components/ui";
import { fmtBytes } from "../../lib/devices";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { CLASSIFICATION_LABEL, SOURCE_LABEL, catalogUrl, osUpdatesApi, type MissingUpdate } from "../../osUpdatesApi";

/** Issue codes raised from the Windows Update report (app/services/os_updates.py). */
const OS_UPDATE_ISSUES = ["os_critical_updates_missing", "os_security_updates_missing", "os_reboot_pending",
  "windows_update_disabled", "os_update_scan_stale"];

const SEV_TONE: Record<string, "critical" | "warn" | "default"> = { Critical: "critical", Important: "warn" };
const REBOOT_LABEL: Record<string, string> = { never: "No", always: "Yes", can_request: "May" };

function Fact({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <div className="min-w-0 bg-surface-1 px-4 py-2.5" title={hint}>
      <dt className="text-[11px] font-medium uppercase tracking-wide text-ink-3">{label}</dt>
      <dd className="mt-0.5 text-sm text-ink">{children}</dd>
    </div>
  );
}

/** "Check for updates now": queues a read-only Windows Update search (analyst). */
function ScanButton({ deviceId, pending, onDone }: { deviceId: string; pending: boolean; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function scan() {
    setBusy(true);
    setError(null);
    try {
      await osUpdatesApi.scan(deviceId);
      onDone();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <span className="inline-flex items-center gap-2">
      {error && <span role="alert" className="text-xs text-sev-high">{error}</span>}
      <Button onClick={scan} disabled={busy || pending}
        title={pending ? "A check is queued or running; the report arrives when the search finishes" : "Ask the agent to search Windows Update now (read-only: nothing is installed)"}>
        <span className="inline-flex items-center gap-1.5">
          <RefreshCw aria-hidden className={`h-3.5 w-3.5 ${pending ? "animate-spin" : ""}`} />
          {pending ? "Checking…" : "Check for updates now"}
        </span>
      </Button>
    </span>
  );
}

function released(u: MissingUpdate, overdueDays: number) {
  if (!u.release_date) return <span className="text-ink-3">—</span>;
  const overdue = u.security && u.age_days !== null && u.age_days > overdueDays;
  return (
    <span title={u.release_date}>
      {u.release_date}
      {u.age_days !== null && (
        <div className={`text-[11px] ${overdue ? "font-medium text-sev-high" : "text-ink-3"}`}>{u.age_days} days ago</div>
      )}
    </span>
  );
}

function Cves({ u }: { u: MissingUpdate }) {
  const [all, setAll] = useState(false);
  if (u.cve_ids.length === 0) return <span className="text-ink-3">—</span>;
  const known = new Set(u.known_cves);
  const shown = all ? u.cve_ids : u.cve_ids.slice(0, 3);
  return (
    <div className="flex max-w-[16rem] flex-wrap gap-x-2 gap-y-0.5 font-mono text-[11px]">
      {shown.map((c) =>
        known.has(c) ? (
          <Link key={c} to={`/vulnerabilities?cve=${encodeURIComponent(c)}`} className="text-accent hover:underline" title="Open in Vulnerabilities">
            {c}
          </Link>
        ) : (
          <span key={c} className="text-ink-2" title="Not in your vulnerability views">{c}</span>
        ),
      )}
      {u.cve_ids.length > 3 && (
        <button className="text-accent hover:underline" onClick={() => setAll(!all)}>
          {all ? "less" : `+${u.cve_ids.length - 3} more`}
        </button>
      )}
    </div>
  );
}

/** Device detail → "OS updates": the latest read-only Windows Update report (docs/PATCHING.md). */
export function OsUpdatesTab({ device, onChanged }: { device: Device; onChanged?: () => void }) {
  const { can } = useAuth();
  const { data, error, reload } = useApi(() => osUpdatesApi.device(device.id), [device.id], 15000);
  const [scope, setScope] = useState("security");
  if (!data) return <ErrorNote error={error} />;
  const r = data.report;
  const canScan = can("analyst") && device.status === "active" && data.supported;
  const issues = device.issues.filter((i) => OS_UPDATE_ISSUES.includes(i.code));

  if (!data.supported) {
    return (
      <Card title="OS updates">
        <Empty title={data.agent_update_required ? "Agent update required" : "Not available for this device"}
          action={data.agent_update_required && can("admin") ? (
            <Link to="/devices/updates" className="text-sm font-medium text-accent hover:underline">Open Agent updates</Link>
          ) : undefined}>
          {data.unsupported_reason}
        </Empty>
      </Card>
    );
  }

  const rows = (r?.updates ?? []).filter((u) => scope === "all" || u.security);
  const scanBtn = canScan && <ScanButton deviceId={device.id} pending={!!data.pending_scan} onDone={() => { reload(); onChanged?.(); }} />;

  return (
    <div className="space-y-4">
      <Card
        title="Windows Update"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {r && (
              <a className="inline-flex items-center gap-1 rounded border border-line bg-surface-2 px-2.5 py-1 text-sm text-ink hover:bg-line"
                href={osUpdatesApi.exportUrl({ scope: "all", device_id: device.id })}>
                <Download aria-hidden className="h-3.5 w-3.5" /> CSV
              </a>
            )}
            {scanBtn}
          </div>
        }
      >
        <ErrorNote error={error} />
        {data.pending_scan && (
          <p className="mb-3 text-xs text-ink-3">
            Check requested {fmtAgo(data.pending_scan.requested_at)}{data.pending_scan.requested_by ? ` by ${data.pending_scan.requested_by}` : ""}
            {data.pending_scan.status === "delivered" ? " · the agent is searching" : " · waiting for the agent"}. Searches can take several minutes.
          </p>
        )}
        {!r ? (
          <Empty title="No update report yet">
            The agent searches Windows Update a few minutes after it starts and then about every 12 hours, using this device's own update
            source (WSUS, Windows Update for Business or Microsoft Update). Nothing is installed.
          </Empty>
        ) : (
          <>
            {r.scan_status === "failed" && (
              <div role="alert" className="mb-3 rounded border border-sev-high/60 bg-sev-high/10 px-3 py-2 text-sm">
                The last search failed{r.scanned_at ? ` (${fmtAgo(r.scanned_at)})` : ""}: <span className="break-words">{r.scan_error || "unknown error"}</span>
                {r.listed_at ? <span className="text-ink-2"> The list below is from the search {fmtAgo(r.listed_at)}.</span> : null}
              </div>
            )}
            <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-line bg-line sm:grid-cols-3 xl:grid-cols-6">
              <Fact label="Missing updates">
                {r.listed_at ? (
                  <>
                    <span className="font-semibold">{r.missing_count}</span>
                    <span className="text-ink-3"> · {r.security_count} security</span>
                    {r.critical_count > 0 && <span className="text-sev-critical"> · {r.critical_count} critical</span>}
                  </>
                ) : (
                  <span className="text-ink-3">unknown</span>
                )}
              </Fact>
              <Fact label="Oldest security update">{r.oldest_security_days === null ? "—" : `${r.oldest_security_days} days`}</Fact>
              <Fact label="Restart pending" hint="Windows Update, servicing stack or the update agent report a pending restart">
                {r.reboot_pending ? (
                  <span className="text-sev-high">Yes{r.reboot_pending_since ? `, since ${fmtAgo(r.reboot_pending_since)}` : ""}</span>
                ) : (
                  "No"
                )}
              </Fact>
              <Fact label="Update source" hint={r.source_detail || undefined}>
                {SOURCE_LABEL[r.source]}
                {r.source_detail && <div className="truncate text-[11px] text-ink-3">{r.source_detail}</div>}
              </Fact>
              <Fact label="Update service">
                <span className={r.service_start_type === "disabled" ? "text-sev-critical" : undefined}>
                  {r.service_state ? r.service_state.replaceAll("_", " ") : "—"}
                </span>
                {r.service_start_type && <div className="text-[11px] text-ink-3">start: {r.service_start_type.replaceAll("_", " ")}</div>}
              </Fact>
              <Fact label="Last checked" hint={r.scanned_at ? fmtTime(r.scanned_at) : undefined}>
                {r.scanned_at ? fmtAgo(r.scanned_at) : "—"}
                <div className="text-[11px] text-ink-3">
                  {r.scan_trigger === "command" ? "on request" : "scheduled"}
                  {r.scan_duration_seconds !== null ? ` · took ${r.scan_duration_seconds}s` : ""}
                </div>
              </Fact>
            </dl>
            <p className="mt-2 text-xs text-ink-3">
              Last successful search {r.last_success_at ? fmtAgo(r.last_success_at) : "unknown"} · last update installed{" "}
              {r.last_install_success_at ? fmtAgo(r.last_install_success_at) : "unknown"} · issues after {data.thresholds.critical_days} days for
              updates Microsoft rates Critical, {data.thresholds.security_days} days for other security updates.
            </p>
            {issues.length > 0 && (
              <div className="mt-3">
                <IssueList issues={issues} />
              </div>
            )}
          </>
        )}
      </Card>
      {r && !r.listed_at && (
        <Card title="Missing updates">
          <Empty title="Unknown until a search succeeds">
            No Windows Update search on this device has succeeded yet, so the list of missing updates is not known. Fix the error above, then
            check again.
          </Empty>
        </Card>
      )}
      {r && r.listed_at && (
        <Card
          title={`Missing updates (${rows.length})`}
          actions={
            <Select label="Show" value={scope} onChange={setScope}
              options={[{ value: "security", label: "Security & critical" }, { value: "all", label: "All" }]} />
          }
        >
          {rows.length === 0 ? (
            <Empty icon={CheckCircle2} title={scope === "security" ? "No missing security updates" : "Up to date"}>
              {r.missing_count > 0 && scope === "security" ? `${r.missing_count} other update(s) are available; choose "All" to see them.` : "Windows Update reports nothing missing."}
            </Empty>
          ) : (
            <Table head={["Update", "Classification", "Severity", "Released", "CVEs", "Restart", "Size"]}>
              {rows.map((u, i) => (
                <tr key={`${u.update_id}-${i}`} className="align-top">
                  <td className="max-w-[28rem] px-3 py-2">
                    <div className="text-sm">{u.title}</div>
                    <div className="mt-0.5 flex flex-wrap gap-2 text-[11px]">
                      {u.kb_ids.map((kb) => (
                        <a key={kb} href={catalogUrl(kb)} target="_blank" rel="noreferrer noopener" className="font-mono text-accent hover:underline"
                          title="Open in the Microsoft Update Catalog">
                          {kb}
                        </a>
                      ))}
                      {u.downloaded && <span className="text-ink-3">downloaded</span>}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-xs text-ink-2">{CLASSIFICATION_LABEL[u.classification]}</td>
                  <td className="px-3 py-2">{u.msrc_severity ? <Tag tone={SEV_TONE[u.msrc_severity] ?? "default"}>{u.msrc_severity}</Tag> : <span className="text-ink-3">—</span>}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs">
                    {released(u, u.msrc_severity === "Critical" ? data.thresholds.critical_days : data.thresholds.security_days)}
                  </td>
                  <td className="px-3 py-2"><Cves u={u} /></td>
                  <td className="px-3 py-2 text-xs text-ink-2">{REBOOT_LABEL[u.reboot_behavior] ?? "—"}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-3">{u.size_bytes ? fmtBytes(u.size_bytes) : "—"}</td>
                </tr>
              ))}
            </Table>
          )}
          <p className="mt-2 text-xs text-ink-3">
            Read-only report: install updates with your existing tooling (WSUS, Windows Update for Business, Intune). KB links open the Microsoft
            Update Catalog; CVEs link to Vulnerabilities when they also appear there.
          </p>
        </Card>
      )}
    </div>
  );
}
