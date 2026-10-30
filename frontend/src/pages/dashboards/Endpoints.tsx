import { Laptop } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../../api";
import { BarRows, ChartEmpty, Composition, DashCard, KpiTile, ViewLink } from "../../components/dash";
import { Empty, ErrorNote } from "../../components/ui";
import { CAT_COLORS, href, OTHER_COLOR, sevSegments } from "../../lib/dash";
import { SEV_COLOR } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import type { TabProps } from "../Dashboard";
import { TabSkeleton } from "./Skeleton";

const OS_LABEL: Record<string, string> = { windows: "Windows", macos: "macOS", linux: "Linux" };

export default function EndpointsTab({ range }: TabProps) {
  // Devices are not tied to a cloud account, so the account filter does not apply here.
  const { data: d, error } = useApi(() => api.dashEndpoints({ range }), [range], 60000);
  if (!d) return error ? <ErrorNote error={error} /> : <TabSkeleton />;
  const k = d.kpis;
  const days = d.days;
  if (d.managed === 0) {
    return (
      <DashCard title="Endpoints">
        <Empty icon={Laptop} title="No endpoints enrolled yet" action={<Link className="text-sm font-medium text-accent hover:underline" to="/devices">Enroll Windows and macOS devices</Link>}>
          Enrolled devices report their posture, software and vulnerabilities here.
        </Empty>
      </DashCard>
    );
  }
  const osParts = Object.entries(d.by_os)
    .sort((a, b) => b[1] - a[1])
    .map(([os, n], i) => ({ key: os, label: OS_LABEL[os] ?? os, count: n, color: CAT_COLORS[Math.min(i, 2)], to: href("/devices", { os }) }));
  const issueMax = Math.max(1, ...d.issues.map((i) => i.devices));
  const vMax = Math.max(1, ...Object.values(d.vulnerabilities.by_severity));
  const verMax = Math.max(1, ...d.agent_versions.map((v) => v.devices));
  const conn = d.connectivity;

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:col-span-12 xl:grid-cols-4">
        <KpiTile label="Managed devices" value={k.managed.value} to="/devices" delta={k.managed.delta} better="up" days={days} segments={osParts} />
        <KpiTile
          label="Failing posture checks"
          value={k.failing.value}
          to="/devices"
          hint="Devices with at least one failing posture check"
          delta={k.failing.delta}
          days={days}
          segments={[
            { key: "critical", label: "At risk", count: d.by_health.critical, color: SEV_COLOR.critical, to: href("/devices", { health: "critical" }) },
            { key: "warning", label: "Warning", count: d.by_health.warning, color: SEV_COLOR.medium, to: href("/devices", { health: "warning" }) },
            { key: "healthy", label: "Healthy", count: d.by_health.healthy, color: "var(--color-good)", to: href("/devices", { health: "healthy" }) },
          ].filter((s) => s.count > 0)}
        />
        <KpiTile label="Sign-in suspended" value={k.suspended.value} to="/devices" hint="Devices with sign-in suspended (host isolation)" delta={k.suspended.delta} days={days}
          footer={`${d.managed - k.suspended.value!} devices allow sign-in`} />
        <KpiTile
          label="Outdated agent"
          value={k.outdated.value}
          to="/devices/updates"
          hint={d.latest_agent_version ? `Older than ${d.latest_agent_version}` : undefined}
          delta={k.outdated.delta}
          days={days}
          segments={[
            { key: "current", label: d.latest_agent_version ? `On ${d.latest_agent_version}+` : "Current", count: d.managed - d.outdated, color: CAT_COLORS[0] },
            { key: "outdated", label: "Outdated", count: d.outdated, color: OTHER_COLOR },
          ].filter((s) => s.count > 0)}
        />
      </div>

      <DashCard title="Failing posture checks" sub="Devices per issue" right={<ViewLink to="/devices" />} className="lg:col-span-6 xl:col-span-5">
        {d.issues.length === 0 ? (
          <ChartEmpty height="h-40">Every device passes its posture checks.</ChartEmpty>
        ) : (
          <BarRows
            max={issueMax}
            labelWidth="12rem"
            rows={d.issues.slice(0, 8).map((i) => ({
              key: i.code,
              label: i.title,
              total: i.devices,
              segments: [{ key: i.code, label: `${i.severity} · ${i.devices} devices`, count: i.devices, color: SEV_COLOR[i.severity] }],
              to: href("/devices", { issue: i.code }),
              hint: `Show devices: ${i.title}`,
            }))}
          />
        )}
      </DashCard>

      <DashCard title="Vulnerabilities on devices" sub={`${d.vulnerabilities.total} open · ${d.vulnerabilities.kev} known exploited`} right={<ViewLink to={href("/vulnerabilities", { scope: "device" })} />} className="lg:col-span-6 xl:col-span-4">
        {d.vulnerabilities.total === 0 ? (
          <ChartEmpty height="h-40">No vulnerabilities found on devices.</ChartEmpty>
        ) : (
          <BarRows
            max={vMax}
            labelWidth="5rem"
            rows={sevSegments(d.vulnerabilities.by_severity).map((s) => ({
              key: s.key,
              label: s.label,
              total: s.count,
              segments: [s],
              to: href("/vulnerabilities", { scope: "device", severity: s.key }),
            }))}
          />
        )}
      </DashCard>

      <DashCard title="Check-in" className="lg:col-span-6 xl:col-span-3">
        <Composition
          segments={[
            { key: "active", label: "Active", count: conn.active, color: "var(--color-good)", to: href("/devices", { connectivity: "active" }) },
            { key: "stale", label: "No check-in 24 h", count: conn.stale, color: SEV_COLOR.medium, to: href("/devices", { connectivity: "stale" }) },
            { key: "inactive", label: "Inactive 7 d", count: conn.inactive, color: SEV_COLOR.high, to: href("/devices", { connectivity: "inactive" }) },
            { key: "never", label: "Never", count: conn.never, color: OTHER_COLOR },
          ].filter((s) => s.count > 0)}
        />
        <h3 className="mt-5 text-xs font-semibold uppercase tracking-[0.06em] text-ink-3">Agent versions</h3>
        <div className="mt-1">
          <BarRows
            max={verMax}
            labelWidth="5rem"
            rows={d.agent_versions.slice(0, 5).map((v, i) => ({
              key: v.version,
              label: v.version,
              total: v.devices,
              segments: [{ key: v.version, label: `${v.devices} devices`, count: v.devices, color: i === 0 ? CAT_COLORS[0] : OTHER_COLOR }],
              to: "/devices/updates",
            }))}
          />
        </div>
      </DashCard>
    </div>
  );
}
