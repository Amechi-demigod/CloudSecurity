import { Laptop } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type DeviceSummary } from "../../api";
import { useAuth } from "../../auth/context";
import { DeviceClassTag } from "../../components/deviceClass";
import { CLASS_FILTER_OPTIONS, CLASS_LABEL } from "../../lib/deviceClass";
import { ConnectivityTag, HealthBadge, IssueList } from "../../components/devices";
import { Card, Empty, ErrorNote, PageHeader, Select, Stat, Table, Tag } from "../../components/ui";
import { OS_LABEL, osLine } from "../../lib/devices";
import { fmtAgo } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { useSort } from "../../lib/useSort";
import { useUrlState } from "../../lib/useUrlState";
import { BulkActionsBar } from "./BulkActions";

/** Missing OS updates on a Devices row (Windows Update report, docs/PATCHING.md). */
function OsUpdatesCell({ d }: { d: DeviceSummary }) {
  const u = d.os_updates;
  if (!u) return <span className="text-xs text-ink-3">{d.os_family === "windows" || d.os_family === "linux" ? "not reported" : "—"}</span>;
  if (d.os_family === "linux") {
    // Linux servers: security updates pending (apt / dnf, read from the server's own package cache) and reboot required.
    if (!u.listed) {
      return (
        <span className="text-xs text-ink-3" title="The package cache is older than 7 days: the agent never refreshes it, so pending updates are not judged">
          cache too old
        </span>
      );
    }
    const reboot = u.reboot_pending ? " · reboot" : "";
    return u.security > 0 ? (
      <div title={u.cache_age_hours !== undefined ? `Package cache ${u.cache_age_hours} h old` : undefined}>
        <Tag tone={u.critical > 0 ? "critical" : "warn"}>{u.security} security pending</Tag>
        <div className="text-[11px] text-ink-3">{`${u.missing} updates${reboot}`}</div>
      </div>
    ) : (
      <div>
        <Tag tone="good">Up to date</Tag>
        {reboot && <div className="text-[11px] text-ink-3">reboot required</div>}
      </div>
    );
  }
  if (!u.listed) return <span className="text-xs text-sev-high">search failed</span>;
  if (u.missing === 0) return <Tag tone="good">Up to date</Tag>;
  return (
    <div title={u.oldest_security_days !== null ? `Oldest security update released ${u.oldest_security_days} days ago` : undefined}>
      {u.security > 0 ? <Tag tone={u.critical > 0 ? "critical" : "warn"}>{u.security} security</Tag> : <Tag>{u.missing} missing</Tag>}
      <div className="text-[11px] text-ink-3">
        {u.missing} total{u.reboot_pending ? " · restart pending" : ""}
        {u.scan_status === "failed" ? " · last check failed" : ""}
      </div>
    </div>
  );
}

export default function Devices() {
  const navigate = useNavigate();
  const { can } = useAuth();
  const [q, setQ] = useState("");
  // Filters live in the URL (?health=critical, ?issue=firewall_off, ?connectivity=stale ...) for dashboard links.
  const [os, setOs] = useUrlState("os");
  const [health, setHealth] = useUrlState("health");
  const [issue, setIssue] = useUrlState("issue");
  const [connectivity, setConnectivity] = useUrlState("connectivity");
  const [status, setStatus] = useUrlState("status", "active");
  const [deviceClass, setDeviceClass] = useUrlState("class");
  const [virtual, setVirtual] = useUrlState("virtual");
  const [usb, setUsb] = useUrlState("usb");
  // Missing OS updates (Windows Update report): security | any | none | unknown
  const [updates, setUpdates] = useUrlState("updates");
  const [selected, setSelected] = useState<string[]>([]);
  const filters = { q: q.trim() || undefined, os, health, issue, connectivity, status, usb, updates, device_class: deviceClass || undefined, virtual: virtual || undefined };
  const { data, error, loading, reload } = useApi(() => api.devices(filters), [q, os, health, issue, connectivity, status, usb, updates, deviceClass, virtual], 30000);
  const { data: summary } = useApi(api.deviceSummary, [], 30000);
  const filtered = !!(q || os || health || issue || connectivity || usb || updates || deviceClass || virtual) || status !== "active";
  const CLASS_RANK: Record<string, number> = { domain_controller: 3, server: 2, workstation: 1 };
  // Bulk endpoint actions (admins): the selection is limited to the rows shown.
  const bulk = can("admin");
  const shown = new Set((data ?? []).map((d) => d.id));
  const picked = selected.filter((id) => shown.has(id));
  const toggle = (id: string) => setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));
  const HEALTH_RANK: Record<string, number> = { critical: 3, warning: 2, unknown: 1, healthy: 0 };
  const sorted = useSort(
    data,
    {
      name: (d) => d.hostname,
      os: (d) => { const o = osLine(d); return `${o.main} ${o.sub}`; },
      class: (d) => (CLASS_RANK[d.device_class ?? ""] ?? 0) * 2 + (d.is_virtual ? 1 : 0),
      user: (d) => d.logged_in_users.join(", "),
      health: (d) => (d.status === "revoked" ? -1 : HEALTH_RANK[d.health] ?? 0),
      issues: (d) => d.issues.length,
      seen: (d) => (d.last_seen_at ? Date.parse(d.last_seen_at) : null),
      agent: (d) => d.agent_version,
      usb: (d) => (d.usb_storage === "blocked" ? 2 : d.usb_storage === "allowed" ? 1 : 0),
      updates: (d) => (d.os_updates ? d.os_updates.security * 10000 + d.os_updates.missing : null),
    },
    { key: "name", dir: "asc" },
    { health: "desc", issues: "desc", seen: "desc", updates: "desc" },
  );
  const { data: issueTypes } = useApi(api.deviceIssueTypes, []);

  return (
    <div>
      <PageHeader
        title="Devices"
        subtitle="Workstations, servers and domain controllers running the CNAPP endpoint agent: inventory, security posture and remote actions."
        actions={
          <div className="flex items-center gap-2">
            <Link to="/devices/updates" className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">
              Agent updates
            </Link>
            <Link to="/devices/scripts" className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">
              Scripts
            </Link>
            {can("admin") && (
              <Link to="/devices/enrollment" className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-white hover:brightness-110">
                Enroll devices
              </Link>
            )}
          </div>
        }
      />
      {summary && (
        <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
          <Stat label="Devices" value={summary.total} sub={Object.entries(summary.by_os).map(([k, v]) => `${v} ${OS_LABEL[k] ?? k}`).join(" · ") || "none enrolled"} />
          {summary.by_class && (
            <Stat label="Workstations / servers" value={`${summary.by_class.workstation} / ${summary.by_class.server + summary.by_class.domain_controller}`}
              sub={`${summary.by_class.domain_controller} ${CLASS_LABEL.domain_controller.toLowerCase()}${summary.by_class.domain_controller === 1 ? "" : "s"} · ${summary.virtual ?? 0} virtual`} />
          )}
          <Stat label="Healthy" value={summary.by_health.healthy} sub={`${summary.by_health.critical} at risk · ${summary.by_health.warning} warning`} />
          <Stat label="Encrypted" value={summary.encrypted_percent === null ? "—" : `${summary.encrypted_percent}%`} sub={`of ${summary.encryption_known} reporting`} />
          <Stat label="Firewall on" value={summary.firewall_percent === null ? "—" : `${summary.firewall_percent}%`} sub={`of ${summary.firewall_known} reporting`} />
          <Stat label="Stale / inactive" value={summary.connectivity.stale + summary.connectivity.inactive} sub="no check-in for 24h+" />
        </div>
      )}
      <Card>
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-1.5 text-xs text-ink-3">
            Search
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="hostname, serial, model"
              className="w-56 rounded border border-line bg-surface-2 px-2 py-1 text-sm text-ink"
            />
          </label>
          <Select label="OS" value={os} onChange={setOs} options={[{ value: "", label: "All" }, { value: "windows", label: "Windows" }, { value: "macos", label: "macOS" }, { value: "linux", label: "Linux" }]} />
          <Select label="Class" value={deviceClass} onChange={setDeviceClass} options={CLASS_FILTER_OPTIONS} />
          <Select
            label="Virtual"
            value={virtual}
            onChange={setVirtual}
            options={[
              { value: "", label: "All" },
              { value: "true", label: "Virtual machines" },
              { value: "false", label: "Physical" },
            ]}
          />
          <Select
            label="Health"
            value={health}
            onChange={setHealth}
            options={[
              { value: "", label: "All" },
              { value: "critical", label: "At risk" },
              { value: "warning", label: "Warning" },
              { value: "healthy", label: "Healthy" },
              { value: "unknown", label: "No data" },
            ]}
          />
          <Select
            label="Issue"
            value={issue}
            onChange={setIssue}
            options={[{ value: "", label: "All" }, ...(issueTypes ?? []).map((t) => ({ value: t.code, label: t.title }))]}
          />
          <Select
            label="Last seen"
            value={connectivity}
            onChange={setConnectivity}
            options={[
              { value: "", label: "Any" },
              { value: "active", label: "Online (< 24h)" },
              { value: "offline", label: "Offline (> 24h)" },
              { value: "stale", label: "Stale (24h - 7d)" },
              { value: "inactive", label: "Inactive (> 7d)" },
              { value: "never", label: "Never checked in" },
            ]}
          />
          <Select
            label="USB storage"
            value={usb}
            onChange={setUsb}
            options={[
              { value: "", label: "Any" },
              { value: "blocked", label: "Blocked" },
              { value: "allowed", label: "Allowed" },
              { value: "unknown", label: "Not reported" },
            ]}
          />
          <Select
            label="Missing updates (security updates pending on Linux)"
            value={updates}
            onChange={setUpdates}
            options={[
              { value: "", label: "Any" },
              { value: "security", label: "Security updates missing" },
              { value: "any", label: "Any update missing" },
              { value: "none", label: "Up to date" },
              { value: "unknown", label: "Not reported" },
            ]}
          />
          <Select
            label="Status"
            value={status}
            onChange={setStatus}
            options={[
              { value: "active", label: "Enrolled" },
              { value: "revoked", label: "Revoked" },
              { value: "all", label: "All" },
            ]}
          />
        </div>
        <ErrorNote error={error} />
        {bulk && <BulkActionsBar selected={picked} onClear={() => setSelected([])} onDone={reload} />}
          <Table
            head={[
              ...(bulk
                ? [{
                    label: (
                      <input type="checkbox" aria-label="Select all devices shown" className="accent-accent"
                        checked={!!data?.length && picked.length === data.length}
                        onChange={(e) => setSelected(e.target.checked ? (data ?? []).filter((d) => d.status === "active" && d.os_family !== "linux").map((d) => d.id) : [])} />
                    ),
                  }]
                : []),
              { label: "Device", sort: "name" },
              { label: "Class", sort: "class" },
              { label: "OS", sort: "os" },
              { label: "User", sort: "user" },
              { label: "Health", sort: "health" },
              { label: "Issues", sort: "issues" },
              { label: "OS updates", sort: "updates" },
              { label: "Last seen", sort: "seen" },
              { label: "USB storage", sort: "usb" },
              { label: "Agent", sort: "agent" },
            ]}
            sort={sorted.sort}
            onSort={sorted.onSort}
            loading={loading}
            rowCount={data?.length ?? 0}
            empty={
              <Empty
                icon={Laptop}
                title={filtered ? "No devices match these filters" : "No devices enrolled yet"}
                action={
                  can("admin") && !filtered ? (
                    <Link className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-white hover:brightness-110" to="/devices/enrollment">
                      Enroll devices
                    </Link>
                  ) : undefined
                }
              >
                {filtered
                  ? "Clear a filter to see more devices."
                  : "Install the agent on Windows and macOS laptops and on Linux servers to track their inventory and security posture."}
              </Empty>
            }
          >
            {sorted.rows.map((d) => (
              <tr
                key={d.id}
                className="cursor-pointer hover:bg-surface-2"
                onClick={() => navigate(`/devices/${d.id}`)}
              >
                {bulk && (
                  <td className="px-3 py-2" onClick={(e) => e.stopPropagation()}>
                    <input type="checkbox" aria-label={`Select ${d.hostname}`} className="accent-accent" disabled={d.status !== "active" || d.os_family === "linux"}
                      title={d.os_family === "linux" ? "Bulk actions are not available for Linux servers" : undefined}
                      checked={selected.includes(d.id)} onChange={() => toggle(d.id)} />
                  </td>
                )}
                <td className="px-3 py-2">
                  <Link to={`/devices/${d.id}`} className="font-medium hover:text-accent" onClick={(e) => e.stopPropagation()}>
                    {d.hostname}
                  </Link>
                  {d.device_state === "lost" && <span className="ml-2"><Tag tone="warn">Lost</Tag></span>}
                  {d.device_state === "wipe_pending" && <span className="ml-2"><Tag tone="critical">Wipe pending</Tag></span>}
                  {d.device_state === "isolated" && <span className="ml-2"><Tag tone="warn">Sign-in suspended</Tag></span>}
                  {d.device_group && (
                    <span className="ml-2 rounded border border-line px-1.5 py-0.5 text-[10px] text-ink-3">{d.device_group}</span>
                  )}
                  <div className="text-[11px] text-ink-3">
                    {[d.manufacturer, d.model].filter(Boolean).join(" ")} {d.serial_number && `· ${d.serial_number}`}
                  </div>
                </td>
                <td className="px-3 py-2">
                  <DeviceClassTag device={d} />
                </td>
                <td className="px-3 py-2 text-ink-2">
                  {osLine(d).main}
                  <div className="text-[11px] text-ink-3">{osLine(d).sub}</div>
                </td>
                <td className="px-3 py-2 text-xs text-ink-2">{d.logged_in_users.join(", ") || "—"}</td>
                <td className="px-3 py-2">
                  {d.status === "revoked" ? <span className="text-xs text-ink-3">Revoked</span> : <HealthBadge health={d.health} />}
                </td>
                <td className="px-3 py-2">
                  <IssueList issues={d.issues} compact />
                </td>
                <td className="px-3 py-2">
                  <OsUpdatesCell d={d} />
                </td>
                <td className="px-3 py-2">
                  <ConnectivityTag value={d.connectivity} />
                  <div className="text-[11px] text-ink-3">{d.last_seen_at ? fmtAgo(d.last_seen_at) : "—"}</div>
                </td>
                <td className="px-3 py-2">
                  {d.usb_storage === "blocked" ? <Tag tone="warn">Blocked</Tag> : d.usb_storage === "allowed" ? <span className="text-xs text-ink-2">Allowed</span> : <span className="text-xs text-ink-3">—</span>}
                </td>
                <td className="px-3 py-2 text-xs text-ink-3">{d.agent_version || "—"}</td>
              </tr>
            ))}
          </Table>
      </Card>
    </div>
  );
}
