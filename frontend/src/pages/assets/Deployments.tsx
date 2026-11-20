import { Rocket } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { Breadcrumbs, Card, Empty, ErrorNote, PageHeader, Table, Tag } from "../../components/ui";
import { directoryApi, ROUTE_LABEL, type DeployRoute, type Deployment } from "../../directoryApi";
import { DEP_STATE_TONE } from "../../lib/deploy";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { rankOf, ts, useSort } from "../../lib/useSort";

export function ProgressBar({ p }: { p: Deployment["progress"] }) {
  const pct = p.total ? (p.enrolled * 100) / p.total : 0;
  return (
    <div className="min-w-40">
      <div className="mb-1 flex justify-between text-xs">
        <span className="text-ink">
          {p.enrolled.toLocaleString()} of {p.total.toLocaleString()} enrolled
        </span>
        <span className="text-ink-3">{p.pct != null ? `${p.pct}%` : "—"}</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-surface-2" role="progressbar" aria-valuenow={Math.round(pct)} aria-valuemin={0} aria-valuemax={100}>
        <div className="h-full rounded-full bg-good" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

export default function Deployments() {
  const navigate = useNavigate();
  const deps = useApi(directoryApi.deployments, [], 60000);
  const state = rankOf(["active", "expired", "revoked"]);
  const sorted = useSort(
    deps.data,
    {
      deployment: (d) => d.name, routes: (d) => Object.values(d.route_counts).reduce<number>((a, n) => a + (n ?? 0), 0),
      progress: (d) => (d.progress.total ? d.progress.enrolled / d.progress.total : 0), pending: (d) => d.progress.pending,
      state: (d) => state(d.state), created: (d) => ts(d.created_at),
    },
    { key: "created", dir: "desc" },
    { routes: "desc", progress: "desc", pending: "desc", created: "desc" },
  );
  const rows = sorted.rows;
  return (
    <div>
      <Breadcrumbs items={[{ label: "Hardware register", to: "/it-assets" }, { label: "Discovery", to: "/it-assets/discovery" }, { label: "Deployments" }]} />
      <PageHeader
        title="Agent deployments"
        subtitle="Rollouts started from Discovery with Deploy agent: which selected machines have enrolled since (through directory matching, refreshed after every sync and every 30 minutes) and which are still missing."
      />
      <ErrorNote error={deps.error} />
      <Card>
        <Table
          head={[{ label: "Deployment", sort: "deployment" }, { label: "Routes", sort: "routes" }, { label: "Progress", sort: "progress" }, { label: "Pending", sort: "pending" }, { label: "State", sort: "state" }, { label: "Created", sort: "created" }]}
          sort={sorted.sort}
          onSort={sorted.onSort}
          loading={deps.loading}
          rowCount={rows.length}
          empty={
            <Empty
              icon={Rocket}
              title="No deployments yet"
              action={
                <Link className="text-sm font-medium text-accent hover:underline" to="/it-assets/discovery?type=not_managed">
                  Machines without an agent
                </Link>
              }
            >
              Select machines without an agent in Discovery and choose Deploy agent.
            </Empty>
          }
        >
          {rows.map((d) => (
            <tr key={d.id} className="cursor-pointer hover:bg-surface-2" onClick={() => navigate(`/it-assets/discovery/deployments/${d.id}`)}>
              <td className="px-3 py-2">
                <Link to={`/it-assets/discovery/deployments/${d.id}`} className="font-medium text-accent hover:underline" onClick={(e) => e.stopPropagation()}>
                  {d.name}
                </Link>
                {d.device_group && <div className="text-[11px] text-ink-3">group: {d.device_group}</div>}
              </td>
              <td className="px-3 py-2 text-xs">
                <div className="flex flex-wrap gap-1">
                  {Object.entries(d.route_counts).map(([r, n]) => (
                    <Tag key={r}>
                      {ROUTE_LABEL[r as DeployRoute]} {n}
                    </Tag>
                  ))}
                </div>
              </td>
              <td className="px-3 py-2">
                <ProgressBar p={d.progress} />
              </td>
              <td className="px-3 py-2 text-xs text-ink-2">
                {d.progress.pending.toLocaleString()}
                {d.progress.gone > 0 && <div className="text-ink-3">{d.progress.gone} left the directory</div>}
              </td>
              <td className="px-3 py-2">
                <Tag tone={DEP_STATE_TONE[d.state]}>{d.state}</Tag>
                {d.state === "active" && <div className="mt-0.5 text-[11px] text-ink-3">until {fmtTime(d.expires_at)}</div>}
              </td>
              <td className="px-3 py-2 text-xs text-ink-3">
                <span title={fmtTime(d.created_at)}>{fmtAgo(d.created_at)}</span>
                <div>{d.created_by}</div>
              </td>
            </tr>
          ))}
        </Table>
      </Card>
    </div>
  );
}
