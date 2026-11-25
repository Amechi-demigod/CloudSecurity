import { Laptop } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, qs, type DeviceHealth, type DeviceSummary } from "../../api";
import { useAuth } from "../../auth/context";
import { CLASS_FILTER_OPTIONS, CLASS_LABEL } from "../../lib/deviceClass";
import { ExportMenu } from "../../components/ExportMenu";
import {
  AttentionList,
  Empty,
  FilterBar,
  FilterChips,
  FilterSearch,
  FilterSelect,
  MoreMenu,
  NameCell,
  NumCell,
  PageHeader,
  Pill,
  PillRow,
  SelectCell,
  Stat,
  Table,
  TextCell,
  None,
  type AttentionItem,
  type FilterChip,
  type PillTone,
} from "../../components/ui";
import { OS_LABEL, osLine } from "../../lib/devices";
import { fmtAgo } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { useSortState } from "../../lib/useSort";
import { useUrlState } from "../../lib/useUrlState";
import { BulkActionsBar } from "./BulkActions";
import FleetMap from "./FleetMap";
import { PAGE_INFO } from "../../lib/pageInfo";

const HEALTH_PILL: Record<DeviceHealth, { tone: PillTone; label: string }> = {
  critical: { tone: "critical", label: "At risk" },
  warning: { tone: "medium", label: "Warning" },
  healthy: { tone: "good", label: "Healthy" },
  unknown: { tone: "neutral", label: "No data" },
};
const CONN_PILL = { active: "Online", stale: "Stale", inactive: "Inactive", never: "Never" } as const;
const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const SEV_TONE: Record<string, PillTone> = { critical: "critical", high: "high", medium: "medium", low: "neutral" };

/** Missing OS updates on a row (Windows Update report, docs/PATCHING.md): one pill, the detail in the tooltip. */
function OsUpdatesCell({ d }: { d: DeviceSummary }) {
  const u = d.os_updates;
  if (!u) return d.os_family === "windows" || d.os_family === "linux" ? <TextCell muted>Not reported</TextCell> : <None />;
  const reboot = u.reboot_pending ? " · restart needed" : "";
  if (d.os_family === "linux") {
    // Linux servers: security updates pending (apt / dnf, read from the server's own package cache) and reboot required.
    if (!u.listed) return <Pill title="The package cache is older than 7 days: the agent never refreshes it, so pending updates are not judged">Cache old</Pill>;
    return u.security > 0 ? (
      <Pill tone={u.critical > 0 ? "critical" : "high"} title={`${u.missing} updates${reboot}${u.cache_age_hours !== undefined ? ` · package cache ${u.cache_age_hours} h old` : ""}`}>
        {u.security} security
      </Pill>
    ) : (
      <Pill tone="good" title={u.reboot_pending ? "Up to date, reboot required" : undefined}>
        {u.reboot_pending ? "Reboot" : "Up to date"}
      </Pill>
    );
  }
  if (!u.listed) return <Pill tone="high">Check failed</Pill>;
  if (u.missing === 0) return <Pill tone="good">Up to date</Pill>;
  const detail = `${u.missing} missing${u.oldest_security_days !== null ? ` · oldest security update released ${u.oldest_security_days} days ago` : ""}${reboot}${u.scan_status === "failed" ? " · last check failed" : ""}`;
  return u.security > 0 ? (
    <Pill tone={u.critical > 0 ? "critical" : "high"} title={detail}>
      {u.security} security
    </Pill>
  ) : (
    <Pill tone="medium" title={detail}>
      {u.missing} missing
    </Pill>
  );
}

export default function Devices() {
  const navigate = useNavigate();
  const { can } = useAuth();
  // Search, filters and sort live in the URL (?health=critical, ?issue=firewall_off, ?connectivity=stale ...) for dashboard links.
  const [q, setQ] = useUrlState("q");
  const [os, setOs] = useUrlState("os");
  const [health, setHealth] = useUrlState("health");
  const [issue, setIssue] = useUrlState("issue");
  const [connectivity, setConnectivity] = useUrlState("connectivity");
  const [status, setStatus] = useUrlState("status", "active");
  const [deviceClass, setDeviceClass] = useUrlState("class");
  const [virtual, setVirtual] = useUrlState("virtual");
  const [usb, setUsb] = useUrlState("usb");
  const [missingFilter, setMissingFilter] = useUrlState("missing");
  // Missing OS updates (Windows Update report): security | any | none | unknown
  const [updates, setUpdates] = useUrlState("updates");
  const [selected, setSelected] = useState<string[]>([]);
  // List | Map (device tracking, docs/DEVICE_TRACKING.md#map-view)
  const [view, setView] = useUrlState("view");
  // The server sorts the whole result (the list is capped), so the sort goes to the API.
  const sorted = useSortState(["name", "os", "class", "user", "health", "issues", "seen", "agent", "usb", "updates"], { key: "name", dir: "asc" }, { health: "desc", issues: "desc", seen: "desc", updates: "desc" });
  const filters = { sort: sorted.sort.key, dir: sorted.sort.dir, q: q.trim() || undefined, os, health, issue, connectivity, status, usb, updates, device_class: deviceClass || undefined, virtual: virtual || undefined, missing: missingFilter || undefined };
  const { data, error, loading, reload } = useApi(() => api.devices(filters), [q, os, health, issue, connectivity, status, usb, updates, deviceClass, virtual, missingFilter, sorted.sort.key, sorted.sort.dir], 30000);
  const { data: summary } = useApi(api.deviceSummary, [], 30000);
  const filtered = !!(q || os || health || issue || connectivity || usb || updates || deviceClass || virtual || missingFilter) || status !== "active";
  // Bulk endpoint actions (admins): the selection is limited to the rows shown.
  const bulk = can("admin");
  const shown = new Set((data ?? []).map((d) => d.id));
  const picked = selected.filter((id) => shown.has(id));
  const toggle = (id: string) => setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));
  const { data: issueTypes } = useApi(api.deviceIssueTypes, []);
  // Counts for two more "Needs attention" items. Each is left out when its data is not available (module off, no release imported).
  const { data: updSummary } = useApi(() => api.updateSummary().catch(() => null), [], 60000);
  const { data: releases } = useApi(() => api.agentReleases().catch(() => null), [], 60000);
  const { data: missing } = useApi(() => api.devices({ updates: "security", status: "active" }).catch(() => null), [], 60000);

  const clearAll = () => {
    setQ("");
    setOs("");
    setHealth("");
    setIssue("");
    setConnectivity("");
    setStatus("active");
    setDeviceClass("");
    setVirtual("");
    setUsb("");
    setMissingFilter("");
    setUpdates("");
  };
  const opt = (list: { value: string; label: string }[], v: string) => list.find((o) => o.value === v)?.label ?? v;
  const HEALTH_OPTS = [
    { value: "", label: "All" },
    { value: "critical", label: "At risk" },
    { value: "warning", label: "Warning" },
    { value: "healthy", label: "Healthy" },
    { value: "unknown", label: "No data" },
  ];
  const OS_OPTS = [{ value: "", label: "All" }, { value: "windows", label: "Windows" }, { value: "macos", label: "macOS" }, { value: "linux", label: "Linux" }];
  const SEEN_OPTS = [
    { value: "", label: "Any" },
    { value: "active", label: "Online (< 24h)" },
    { value: "offline", label: "Offline (> 24h)" },
    { value: "stale", label: "Stale (24h - 7d)" },
    { value: "inactive", label: "Inactive (> 7d)" },
    { value: "never", label: "Never checked in" },
  ];
  const VIRTUAL_OPTS = [{ value: "", label: "All" }, { value: "true", label: "Virtual machines" }, { value: "false", label: "Physical" }];
  const ISSUE_OPTS = [{ value: "", label: "All" }, ...(issueTypes ?? []).map((t) => ({ value: t.code, label: t.title }))];
  const USB_OPTS = [{ value: "", label: "Any" }, { value: "blocked", label: "Blocked" }, { value: "allowed", label: "Allowed" }, { value: "unknown", label: "Not reported" }];
  const UPDATE_OPTS = [
    { value: "", label: "Any" },
    { value: "security", label: "Security updates missing" },
    { value: "any", label: "Any update missing" },
    { value: "none", label: "Up to date" },
    { value: "unknown", label: "Not reported" },
  ];
  const MISSING_OPTS = [{ value: "", label: "All" }, { value: "true", label: "Missing" }];
  const STATUS_OPTS = [{ value: "active", label: "Enrolled" }, { value: "revoked", label: "Removed" }, { value: "all", label: "All" }];
  const chips: FilterChip[] = [
    q && { label: "Search", value: q, onRemove: () => setQ("") },
    os && { label: "OS", value: opt(OS_OPTS, os), onRemove: () => setOs("") },
    deviceClass && { label: "Class", value: opt(CLASS_FILTER_OPTIONS, deviceClass), onRemove: () => setDeviceClass("") },
    virtual && { label: "Type", value: opt(VIRTUAL_OPTS, virtual), onRemove: () => setVirtual("") },
    health && { label: "Health", value: opt(HEALTH_OPTS, health), onRemove: () => setHealth("") },
    issue && { label: "Issue", value: opt(ISSUE_OPTS, issue), onRemove: () => setIssue("") },
    connectivity && { label: "Last seen", value: opt(SEEN_OPTS, connectivity), onRemove: () => setConnectivity("") },
    usb && { label: "USB storage", value: opt(USB_OPTS, usb), onRemove: () => setUsb("") },
    updates && { label: "Updates", value: opt(UPDATE_OPTS, updates), onRemove: () => setUpdates("") },
    missingFilter && { label: "Missing", value: opt(MISSING_OPTS, missingFilter), onRemove: () => setMissingFilter("") },
    status !== "active" && { label: "Status", value: opt(STATUS_OPTS, status), onRemove: () => setStatus("active") },
  ].filter((c): c is FilterChip => !!c);
  const moreActive = [deviceClass, virtual, issue, usb, updates, missingFilter, status !== "active" ? status : ""].filter(Boolean).length;

  // "Needs attention": the most common issues across the fleet (summary endpoint), worst first, then offline computers.
  const offline = summary ? summary.connectivity.stale + summary.connectivity.inactive : 0;
  const newestRelease = [...(releases ?? [])].filter((r) => !r.withdrawn_at && !r.expired).sort((a, b) => Date.parse(b.released_at) - Date.parse(a.released_at))[0];
  const olderAgents = newestRelease && updSummary ? Math.max(0, updSummary.devices - (updSummary.versions.find((v) => v.version === newestRelease.version)?.devices ?? 0)) : 0;
  const attention: AttentionItem[] = summary
    ? [
        ...(issueTypes ?? [])
          .filter((t) => (summary.issues[t.code] ?? 0) > 0)
          .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9) || (summary.issues[b.code] ?? 0) - (summary.issues[a.code] ?? 0))
          .slice(0, 4)
          .map((t) => ({
            key: t.code,
            label: t.severity[0].toUpperCase() + t.severity.slice(1),
            tone: SEV_TONE[t.severity] ?? "neutral",
            text: `${summary.issues[t.code]} ${summary.issues[t.code] === 1 ? "computer" : "computers"}: ${t.title}`,
            onClick: () => setIssue(t.code),
          })),
        ...(missing && missing.length > 0
          ? [{ key: "updates", label: "High", tone: "high" as PillTone, text: `${missing.length} ${missing.length === 1 ? "computer is" : "computers are"} missing security updates`, onClick: () => setUpdates("security") }]
          : []),
        ...(olderAgents > 0
          ? [{ key: "agents", label: "Medium", tone: "medium" as PillTone, text: `${olderAgents} ${olderAgents === 1 ? "computer runs" : "computers run"} an older agent (newest is ${newestRelease?.version})`, to: "/devices/updates" }]
          : []),
        ...(offline > 0
          ? [{ key: "offline", label: "Offline", tone: "medium" as PillTone, text: `${offline} ${offline === 1 ? "computer hasn't" : "computers haven't"} checked in for 24h+`, onClick: () => setConnectivity("offline") }]
          : []),
      ]
    : [];

  return (
    <div>
      <PageHeader
        title="Computers & servers"
        info={PAGE_INFO.computers}
        subtitle="Are your laptops, desktops and servers updated and protected?"
        actions={
          <div className="flex items-center gap-2">
            <div role="group" aria-label="View" className="flex overflow-hidden rounded border border-line text-sm">
              {(["", "map"] as const).map((v) => (
                <button key={v || "list"} type="button" aria-pressed={view === v} onClick={() => setView(v)}
                  className={`px-3 py-1.5 ${view === v ? "bg-accent text-white" : "text-ink-2 hover:bg-surface-2"}`}>
                  {v ? "Map" : "List"}
                </button>
              ))}
            </div>
            <MoreMenu
              items={[
                { label: "Agent updates", to: "/devices/updates" },
                { label: "Scripts", to: "/devices/scripts" },
              ]}
            />
            <ExportMenu noun="computers" count={data && data.length < 500 ? data.length : undefined} buildUrl={(format) => `/api/devices/export${qs({ ...filters, format })}`} />
            {can("admin") && (
              <Link to="/devices/enrollment" className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-white hover:brightness-110">
                Enroll devices
              </Link>
            )}
          </div>
        }
      />
      {view === "map" ? <FleetMap /> : <>
      {summary && (
        <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
          <Stat
            label="Computers & servers"
            onSelect={clearAll}
            selected={!filtered}
            hint="Show all active computers and servers"
            value={summary.total}
            sub={
              summary.by_class
                ? `${summary.by_class.workstation} workstations · ${summary.by_class.server + summary.by_class.domain_controller} servers`
                : Object.entries(summary.by_os).map(([k, v]) => `${v} ${OS_LABEL[k] ?? k}`).join(" · ") || "none enrolled"
            }
          />
          <Stat label="Healthy" onSelect={() => setHealth(health === "healthy" ? "" : "healthy")} selected={health === "healthy"} value={summary.by_health.healthy} sub={`${summary.by_health.warning} warning`} />
          <Stat label="At risk" onSelect={() => setHealth(health === "critical" ? "" : "critical")} selected={health === "critical"} value={summary.by_health.critical} sub="need action" />
          <Stat label="Encrypted" value={summary.encrypted_percent === null ? "—" : `${summary.encrypted_percent}%`} sub={`of ${summary.encryption_known} reporting`} />
          <Stat label="Firewall on" value={summary.firewall_percent === null ? "—" : `${summary.firewall_percent}%`} sub={`of ${summary.firewall_known} reporting`} />
          <Stat label="Offline" onSelect={() => setConnectivity(connectivity === "offline" ? "" : "offline")} selected={connectivity === "offline"} value={offline} sub="no check-in for 24h+" />
        </div>
      )}
      <AttentionList title="Needs attention" hint="Click one to filter the list below" items={attention} />
      <div className="rounded-xl border border-line bg-surface-1 p-4">
        <FilterBar
          count={data ? `${data.length} ${data.length === 1 ? "computer" : "computers"}` : undefined}
          moreActive={moreActive}
          more={
            <>
              <FilterSelect label="Class" value={deviceClass} onChange={setDeviceClass} options={CLASS_FILTER_OPTIONS} />
              <FilterSelect label="Type" value={virtual} onChange={setVirtual} options={VIRTUAL_OPTS} />
              <FilterSelect label="Issue" value={issue} onChange={setIssue} options={ISSUE_OPTS} />
              <FilterSelect label="USB storage" value={usb} onChange={setUsb} options={USB_OPTS} />
              <FilterSelect label="Updates" value={updates} onChange={setUpdates} options={UPDATE_OPTS} />
              <FilterSelect label="Missing" value={missingFilter} onChange={setMissingFilter} options={MISSING_OPTS} />
              <FilterSelect label="Status" value={status} onChange={setStatus} options={STATUS_OPTS} />
            </>
          }
        >
          <FilterSearch value={q} onChange={setQ} placeholder="Name, serial, model" label="Search computers" />
          <FilterSelect label="OS" value={os} onChange={setOs} options={OS_OPTS} />
          <FilterSelect label="Health" value={health} onChange={setHealth} options={HEALTH_OPTS} />
          <FilterSelect label="Last seen" value={connectivity} onChange={setConnectivity} options={SEEN_OPTS} />
        </FilterBar>
        <FilterChips chips={chips} onClearAll={clearAll} />
        <Table
          tableId="devices"
          head={[
            { label: "Computer", sort: "name", w: 280 },
            { label: "User", sort: "user", w: 140 },
            { label: "Health", sort: "health", w: 120 },
            { label: "Issues", sort: "issues", w: 80, align: "right" },
            { label: "OS updates", sort: "updates", w: 140 },
            { label: "Last seen", sort: "seen", w: 130 },
            { label: "USB storage", sort: "usb", w: 120 },
            { label: "Agent", sort: "agent", w: 90 },
          ]}
          sort={sorted.sort}
          onSort={sorted.onSort}
          loading={loading}
          rowCount={data?.length ?? 0}
          noun="computers"
          pageSize={50}
          filtered={filtered}
          onClearFilters={clearAll}
          error={data ? null : error}
          onRetry={reload}
          selection={
            bulk
              ? {
                  ids: (data ?? []).map((d) => (d.status === "active" && d.os_family !== "linux" ? d.id : null)),
                  selected: new Set(picked),
                  onChange: (next) => setSelected([...next]),
                  actions: <BulkActionsBar selected={picked} onDone={reload} />,
                }
              : undefined
          }
          empty={
            <Empty
              icon={Laptop}
              title={filtered ? "No computers match these filters" : "No devices enrolled yet"}
              action={
                can("admin") && !filtered ? (
                  <Link className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-white hover:brightness-110" to="/devices/enrollment">
                    Enroll devices
                  </Link>
                ) : undefined
              }
            >
              {filtered ? "Clear a filter to see more computers." : "Install the agent on Windows and macOS laptops and on Linux servers to track their inventory and security posture."}
            </Empty>
          }
        >
          {data?.map((d) => {
            const o = osLine(d);
            const cls = d.device_class ? CLASS_LABEL[d.device_class] : "";
            const sub = [d.os_family === "linux" ? o.main : `${o.main} ${o.sub}`.trim(), cls, d.is_virtual ? "Virtual" : "", d.device_group].filter(Boolean).join(" · ");
            const h = HEALTH_PILL[d.health];
            return (
              <tr key={d.id} className="cursor-pointer hover:bg-surface-2" aria-selected={selected.includes(d.id)} onClick={() => navigate(`/devices/${d.id}`)}>
                {bulk && (
                  <SelectCell
                    label={`Select ${d.hostname}`}
                    disabled={d.status !== "active" || d.os_family === "linux"}
                    title={d.os_family === "linux" ? "Bulk actions are not available for Linux servers" : undefined}
                    checked={selected.includes(d.id)}
                    onChange={() => toggle(d.id)}
                  />
                )}
                <td className="px-3 py-2">
                  <NameCell
                    name={d.hostname}
                    sub={sub || [d.manufacturer, d.model].filter(Boolean).join(" ")}
                    onOpen={() => navigate(`/devices/${d.id}`)}
                    openLabel={`Open ${d.hostname}`}
                  />
                </td>
                <td className="px-3 py-2">{d.logged_in_users.length ? <TextCell muted>{d.logged_in_users.join(", ")}</TextCell> : <None />}</td>
                <td className="px-3 py-2">
                  <PillRow>
                    {d.status === "revoked" ? (
                      <Pill>Removed</Pill>
                    ) : d.missing ? (
                      <Pill tone="critical" title="Marked missing">
                        Missing
                      </Pill>
                    ) : d.device_state === "wipe_pending" ? (
                      <Pill tone="critical">Wiping</Pill>
                    ) : d.device_state === "lost" ? (
                      <Pill tone="high">Lost</Pill>
                    ) : d.device_state === "isolated" ? (
                      <Pill tone="high" title="Sign-in suspended">
                        Suspended
                      </Pill>
                    ) : (
                      <Pill tone={h.tone}>{h.label}</Pill>
                    )}
                  </PillRow>
                </td>
                <td className="px-3 py-2">
                  <NumCell value={d.issues.length} title={d.issues.map((i) => i.title).join(", ") || undefined} />
                </td>
                <td className="px-3 py-2">
                  <OsUpdatesCell d={d} />
                </td>
                <td className="px-3 py-2">
                  <TextCell muted={d.connectivity === "active"} title={`${CONN_PILL[d.connectivity]}${d.last_seen_at ? ` · ${d.last_seen_at}` : ""}`}>
                    {d.last_seen_at ? fmtAgo(d.last_seen_at) : "Never"}
                    {d.connectivity !== "active" && d.last_seen_at ? ` · ${CONN_PILL[d.connectivity]}` : ""}
                  </TextCell>
                </td>
                <td className="px-3 py-2">{d.usb_storage ? <TextCell muted={d.usb_storage === "allowed"}>{d.usb_storage === "blocked" ? "Blocked" : "Allowed"}</TextCell> : <None />}</td>
                <td className="px-3 py-2">{d.agent_version ? <TextCell mono>{d.agent_version}</TextCell> : <None />}</td>
              </tr>
            );
          })}
        </Table>
      </div>
      </>}
    </div>
  );
}
