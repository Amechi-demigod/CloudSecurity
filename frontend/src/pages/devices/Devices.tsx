import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../../api";
import { useAuth } from "../../auth/context";
import { ConnectivityTag, HealthBadge, IssueList } from "../../components/devices";
import { Card, Empty, ErrorNote, PageHeader, Select, Stat, Table } from "../../components/ui";
import { OS_LABEL } from "../../lib/devices";
import { fmtAgo } from "../../lib/format";
import { useApi } from "../../lib/useApi";

export default function Devices() {
  const navigate = useNavigate();
  const { can } = useAuth();
  const [q, setQ] = useState("");
  const [os, setOs] = useState("");
  const [health, setHealth] = useState("");
  const [issue, setIssue] = useState("");
  const [connectivity, setConnectivity] = useState("");
  const [status, setStatus] = useState("active");
  const filters = { q: q.trim() || undefined, os, health, issue, connectivity, status };
  const { data, error, loading } = useApi(() => api.devices(filters), [q, os, health, issue, connectivity, status], 30000);
  const { data: summary } = useApi(api.deviceSummary, [], 30000);
  const { data: issueTypes } = useApi(api.deviceIssueTypes, []);

  return (
    <div>
      <PageHeader
        title="Devices"
        subtitle="Laptops and desktops running the CNAPP endpoint agent: inventory, security posture and remote actions."
        actions={
          can("admin") && (
            <Link to="/devices/enrollment" className="rounded bg-accent px-3 py-1.5 text-sm font-medium text-white hover:brightness-110">
              Enroll devices
            </Link>
          )
        }
      />
      {summary && (
        <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
          <Stat label="Devices" value={summary.total} sub={Object.entries(summary.by_os).map(([k, v]) => `${v} ${OS_LABEL[k] ?? k}`).join(" · ") || "none enrolled"} />
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
          <Select label="OS" value={os} onChange={setOs} options={[{ value: "", label: "All" }, { value: "windows", label: "Windows" }, { value: "macos", label: "macOS" }]} />
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
              { value: "stale", label: "Stale (> 24h)" },
              { value: "inactive", label: "Inactive (> 7d)" },
              { value: "never", label: "Never checked in" },
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
        {data && data.length === 0 ? (
          <Empty>
            {loading ? "Loading…" : "No devices match."}{" "}
            {can("admin") && !loading && (
              <Link className="text-accent" to="/devices/enrollment">
                Enroll a device
              </Link>
            )}
          </Empty>
        ) : (
          <Table head={["Device", "OS", "User", "Health", "Issues", "Last seen", "Agent"]}>
            {(data ?? []).map((d) => (
              <tr
                key={d.id}
                className="cursor-pointer hover:bg-surface-2"
                onClick={() => navigate(`/devices/${d.id}`)}
              >
                <td className="px-3 py-2">
                  <Link to={`/devices/${d.id}`} className="font-medium hover:text-accent" onClick={(e) => e.stopPropagation()}>
                    {d.hostname}
                  </Link>
                  {d.device_group && (
                    <span className="ml-2 rounded border border-line px-1.5 py-0.5 text-[10px] text-ink-3">{d.device_group}</span>
                  )}
                  <div className="text-[11px] text-ink-3">
                    {[d.manufacturer, d.model].filter(Boolean).join(" ")} {d.serial_number && `· ${d.serial_number}`}
                  </div>
                </td>
                <td className="px-3 py-2 text-ink-2">
                  {OS_LABEL[d.os_family] ?? d.os_family}
                  <div className="text-[11px] text-ink-3">{d.os_version}</div>
                </td>
                <td className="px-3 py-2 text-xs text-ink-2">{d.logged_in_users.join(", ") || "—"}</td>
                <td className="px-3 py-2">
                  {d.status === "revoked" ? <span className="text-xs text-ink-3">Revoked</span> : <HealthBadge health={d.health} />}
                </td>
                <td className="px-3 py-2">
                  <IssueList issues={d.issues} compact />
                </td>
                <td className="px-3 py-2">
                  <ConnectivityTag value={d.connectivity} />
                  <div className="text-[11px] text-ink-3">{d.last_seen_at ? fmtAgo(d.last_seen_at) : "—"}</div>
                </td>
                <td className="px-3 py-2 text-xs text-ink-3">{d.agent_version || "—"}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}
