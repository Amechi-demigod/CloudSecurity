import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, type AttackPath } from "../api";
import AssetDrawer from "../components/AssetDrawer";
import {
  Card,
  ErrorNote,
  PageHeader,
  SeverityBadge,
  Tag,
} from "../components/ui";
import { TYPE_LABEL } from "../lib/format";
import { useApi } from "../lib/useApi";

const NODE_W = 168;
const NODE_H = 46;
const COL_GAP = 70;
const ROW_GAP = 16;

const TYPE_GLYPH: Record<string, string> = {
  internet: "🌐",
  vm: "VM",
  vmss: "VMSS",
  pod: "POD",
  function_app: "FN",
  identity: "ID",
  storage_account: "ST",
  sql_server: "SQL",
  sql_database: "DB",
  key_vault: "KV",
  aks_cluster: "AKS",
  ec2_instance: "EC2",
  lambda_function: "λ",
  iam_role: "ROLE",
  iam_user: "USER",
  s3_bucket: "S3",
  rds_instance: "RDS",
  gce_instance: "GCE",
  cloud_function: "FN",
  cloud_run_service: "RUN",
  gcp_service_account: "SA",
  gcs_bucket: "GCS",
  cloud_sql_instance: "SQL",
};

type GNode = {
  id: string;
  name: string;
  type: string;
  sensitive_data?: boolean;
  internet_exposed?: boolean;
};
type GEdge = { source: string; target: string; type: string; paths: string[] };

/** Layered left-to-right layout: column = shortest hop distance from the Internet node. */
function layout(nodes: GNode[], edges: GEdge[], paths: AttackPath[]) {
  const depth = new Map<string, number>([["internet", 0]]);
  for (const p of paths) {
    p.steps.forEach((s, i) =>
      depth.set(s.asset_id, Math.min(depth.get(s.asset_id) ?? 99, i + 1)),
    );
  }
  // Push terminal nodes (path targets with no outgoing edge) to the right-most column
  // so every path reads left to right and ends on the data it reaches.
  const maxDepth = Math.max(...depth.values());
  const hasOut = new Set(edges.map((e) => e.source));
  for (const n of nodes) if (!hasOut.has(n.id)) depth.set(n.id, maxDepth);
  const cols = new Map<number, GNode[]>();
  for (const n of nodes) {
    const d = depth.get(n.id) ?? 0;
    cols.set(d, [...(cols.get(d) ?? []), n]);
  }
  const maxRows = Math.max(...[...cols.values()].map((c) => c.length));
  const height = maxRows * (NODE_H + ROW_GAP) + 20;
  const pos = new Map<string, { x: number; y: number }>();
  for (const [d, col] of cols) {
    const offset = (height - col.length * (NODE_H + ROW_GAP)) / 2;
    col.forEach((n, i) =>
      pos.set(n.id, {
        x: 10 + d * (NODE_W + COL_GAP),
        y: offset + i * (NODE_H + ROW_GAP),
      }),
    );
  }
  return {
    pos,
    width: (Math.max(...cols.keys()) + 1) * (NODE_W + COL_GAP),
    height,
  };
}

function Graph({
  nodes,
  edges,
  paths,
  selected,
  onNode,
}: {
  nodes: GNode[];
  edges: GEdge[];
  paths: AttackPath[];
  selected: string | null;
  onNode: (id: string) => void;
}) {
  const { pos, width, height } = useMemo(
    () => layout(nodes, edges, paths),
    [nodes, edges, paths],
  );
  const sel = paths.find((p) => p.id === selected);
  const onPath = new Set(
    sel ? ["internet", ...sel.steps.map((s) => s.asset_id)] : [],
  );
  const confirmedIds = new Set(
    paths.filter((p) => p.confirmed).map((p) => p.id),
  );
  const weakNodes = new Set(
    paths.flatMap((p) => p.steps.filter((s) => s.weak).map((s) => s.asset_id)),
  );
  const hotColor =
    sel && !sel.confirmed
      ? "var(--color-sev-medium)"
      : "var(--color-sev-critical)";
  return (
    <div className="overflow-x-auto">
      <svg
        width={width}
        height={height}
        role="img"
        aria-label="Attack path graph"
      >
        <defs>
          <marker
            id="arrow"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto"
          >
            <path d="M0,0 L10,5 L0,10 z" fill="var(--color-ink-3)" />
          </marker>
          <marker
            id="arrow-hot"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="6"
            markerHeight="6"
            orient="auto"
          >
            <path d="M0,0 L10,5 L0,10 z" fill={hotColor} />
          </marker>
        </defs>
        {edges.map((e) => {
          const a = pos.get(e.source);
          const b = pos.get(e.target);
          if (!a || !b) return null;
          const hot = !!selected && e.paths.includes(selected);
          // edges used only by exposure paths (no confirmed weakness) are dashed
          const exposureOnly = !e.paths.some((id) => confirmedIds.has(id));
          const x1 = a.x + NODE_W,
            y1 = a.y + NODE_H / 2,
            x2 = b.x,
            y2 = b.y + NODE_H / 2;
          const mx = (x1 + x2) / 2;
          return (
            <g key={`${e.source}-${e.target}-${e.type}`}>
              <path
                d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2 - 2},${y2}`}
                fill="none"
                stroke={hot ? hotColor : "var(--color-line)"}
                strokeWidth={hot ? 2.5 : 1.5}
                strokeDasharray={exposureOnly ? "5 4" : undefined}
                markerEnd={hot ? "url(#arrow-hot)" : "url(#arrow)"}
                opacity={selected && !hot ? 0.5 : 1}
              >
                <title>{`${e.type.replace("_", " ")}${exposureOnly ? " (exposure paths only)" : ""}`}</title>
              </path>
            </g>
          );
        })}
        {nodes.map((n) => {
          const p = pos.get(n.id);
          if (!p) return null;
          const dim = selected && !onPath.has(n.id);
          return (
            <g
              key={n.id}
              transform={`translate(${p.x},${p.y})`}
              className="cursor-pointer"
              opacity={dim ? 0.4 : 1}
              onClick={() => n.type !== "internet" && onNode(n.id)}
            >
              <title>{`${n.name} (${TYPE_LABEL[n.type] ?? n.type})`}</title>
              <rect
                width={NODE_W}
                height={NODE_H}
                rx={6}
                fill="var(--color-surface-2)"
                stroke={onPath.has(n.id) ? hotColor : "var(--color-line)"}
                strokeWidth={onPath.has(n.id) ? 2 : 1}
              />
              <text
                x={10}
                y={19}
                fontSize={10}
                fontWeight={700}
                fill="var(--color-ink-3)"
              >
                {TYPE_GLYPH[n.type] ?? n.type.toUpperCase()}
              </text>
              <text x={10} y={35} fontSize={12} fill="var(--color-ink)">
                {n.name.length > 22 ? n.name.slice(0, 21) + "…" : n.name}
              </text>
              {n.sensitive_data && (
                <text
                  x={NODE_W - 8}
                  y={19}
                  fontSize={9}
                  textAnchor="end"
                  fill="var(--color-sev-high)"
                >
                  SENSITIVE
                </text>
              )}
              {weakNodes.has(n.id) && !n.sensitive_data && (
                <text
                  x={NODE_W - 8}
                  y={19}
                  fontSize={9}
                  textAnchor="end"
                  fill="var(--color-sev-critical)"
                >
                  WEAKNESS
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

const EDGE_LABEL: Record<string, string> = {
  contains: "contains",
  connects_to: "connects to",
  uses_identity: "uses identity",
  has_access: "has access to",
};

type View = "all" | "confirmed";

/** What the engine needs before it can report a path; shown when nothing is found. */
function EmptyState({
  view,
  onShowAll,
}: {
  view: View;
  onShowAll: () => void;
}) {
  return (
    <Card>
      <div className="mx-auto max-w-2xl py-4 text-sm text-ink-2">
        <p className="font-medium text-ink">
          {view === "confirmed"
            ? "No confirmed attack paths."
            : "No attack or exposure paths found."}
        </p>
        {view === "confirmed" && (
          <p className="mt-1">
            Exposure paths without a confirmed weakness may still exist.{" "}
            <button className="text-accent hover:underline" onClick={onShowAll}>
              Show all exposure
            </button>
          </p>
        )}
        <p className="mt-3">A path needs all of the following:</p>
        <ol className="mt-1 list-decimal space-y-1 pl-5">
          <li>
            <span className="text-ink">An internet-exposed entry point</span>: a
            VM, scale set or instance with a public IP, a workload behind a
            public load balancer / application gateway, a function app, a public
            AKS API server or a publicly accessible data store.
          </li>
          <li>
            <span className="text-ink">A link to sensitive data</span>: the
            entry point uses a managed identity / role / service account that
            has access (RBAC role, Key Vault access policy, IAM binding) to a
            data store marked sensitive. Key vaults and SQL databases always
            count; storage accounts and buckets count when tagged.
          </li>
          <li>
            <span className="text-ink">A weakness</span> (for a{" "}
            <em>confirmed</em> path): an in-use high-severity vulnerability, a
            high/critical misconfiguration on the entry point or data store, or
            a network rule (NSG, security group, firewall rule) opening
            SSH/RDP/all ports to the internet on the entry point. Without one,
            the chain is listed as an exposure path with a lower score.
          </li>
        </ol>
        <p className="mt-3 rounded border border-line bg-surface-2 px-3 py-2 text-xs">
          Tip: tag storage accounts (and S3 / Cloud Storage buckets) that hold
          sensitive data with{" "}
          <code className="text-ink">data_classification=confidential</code> so
          they become attack-path targets, then run a new scan.
        </p>
      </div>
    </Card>
  );
}

function StatusTag({ path }: { path: AttackPath }) {
  return path.confirmed ? (
    <Tag tone="critical">Confirmed</Tag>
  ) : (
    <span title={path.note ?? undefined}>
      <Tag>Exposure</Tag>
    </span>
  );
}

export default function AttackPaths() {
  const [params, setParams] = useSearchParams(); // deep link: /attack-paths?path=<id>&view=confirmed
  const view: View = params.get("view") === "confirmed" ? "confirmed" : "all";
  const { data, error } = useApi(
    () => api.attackGraph(12, view === "confirmed"),
    [view],
    30000,
  );
  const [selected, setSelected] = useState<string | null>(params.get("path"));
  const [asset, setAsset] = useState<string | null>(null);
  const current =
    (selected && data?.paths.some((p) => p.id === selected)
      ? selected
      : null) ??
    data?.paths[0]?.id ??
    null;
  const path = data?.paths.find((p) => p.id === current);
  const nConfirmed = data?.paths.filter((p) => p.confirmed).length ?? 0;
  const nExposure = (data?.paths.length ?? 0) - nConfirmed;

  const setView = (v: View) => {
    const next = new URLSearchParams(params);
    if (v === "confirmed") next.set("view", "confirmed");
    else next.delete("view");
    setParams(next, { replace: true });
  };

  const toggle = (
    <div
      className="inline-flex overflow-hidden rounded border border-line text-xs"
      role="group"
      aria-label="Path filter"
    >
      {(
        [
          ["confirmed", "Confirmed only"],
          ["all", "All exposure"],
        ] as const
      ).map(([v, label]) => (
        <button
          key={v}
          aria-pressed={view === v}
          className={`px-2.5 py-1 ${view === v ? "bg-accent text-white" : "bg-surface-2 text-ink-2 hover:text-ink"}`}
          onClick={() => setView(v)}
        >
          {label}
        </button>
      ))}
    </div>
  );

  return (
    <div>
      <PageHeader
        title="Attack paths"
        subtitle="Chains from the Internet to sensitive data: exposure → workload → identity → data. Confirmed paths have an exploitable weakness on the way; exposure paths do not (yet)."
        actions={toggle}
      />
      <ErrorNote error={error} />
      {data && data.paths.length === 0 && (
        <EmptyState view={view} onShowAll={() => setView("all")} />
      )}
      {data && data.paths.length > 0 && (
        <>
          <Card
            title="Risk graph (top paths)"
            actions={
              <span className="text-xs text-ink-3">
                {nConfirmed} confirmed
                {view === "all" ? `, ${nExposure} exposure (dashed)` : ""}
              </span>
            }
          >
            <Graph
              nodes={data.nodes}
              edges={data.edges}
              paths={data.paths}
              selected={current}
              onNode={setAsset}
            />
          </Card>
          <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
            <Card title={`Top paths (${data.paths.length})`}>
              <ul className="divide-y divide-line/60">
                {data.paths.map((p) => (
                  <li
                    key={p.id}
                    className={`cursor-pointer px-2 py-2 hover:bg-surface-2 ${p.id === current ? "bg-surface-2" : ""}`}
                    onClick={() => setSelected(p.id)}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={p.severity} />
                      <StatusTag path={p} />
                      <span className="text-xs text-ink-2">
                        score {p.score.toFixed(0)}
                      </span>
                      <span className="text-xs text-ink-3">
                        {p.steps.length} hops
                      </span>
                    </div>
                    <div className="mt-1 truncate text-sm" title={p.title}>
                      {p.title.replace(/ -> /g, " → ")}
                    </div>
                  </li>
                ))}
              </ul>
            </Card>
            <Card title="Path breakdown">
              {path && (
                <>
                  <div className="mb-3 rounded border border-line bg-surface-2 px-3 py-2 text-xs">
                    <div className="flex items-center gap-2">
                      <StatusTag path={path} />
                      <SeverityBadge severity={path.severity} />
                    </div>
                    {path.confirmed ? (
                      <ul className="mt-1.5 list-disc pl-4 text-ink-2">
                        {path.weaknesses.map((w) => (
                          <li key={w}>{w}</li>
                        ))}
                      </ul>
                    ) : (
                      <p className="mt-1.5 text-ink-2">
                        {path.note ?? "No exploitable weakness found yet"}: the
                        chain exists, but no vulnerability or high-risk
                        misconfiguration was found on it. Scored lower and
                        capped at medium severity.
                      </p>
                    )}
                  </div>
                  <ol className="space-y-1">
                    <li className="flex gap-3">
                      <span className="mt-0.5 w-6 text-center">🌐</span>
                      <div className="text-sm text-ink-2">Internet</div>
                    </li>
                    {path.steps.map((s, i) => (
                      <li key={s.asset_id}>
                        <div className="py-0.5 pl-9 text-[11px] text-ink-3">
                          ↓{" "}
                          {i === 0
                            ? "reaches"
                            : (EDGE_LABEL[path.edges[i]?.type] ??
                              path.edges[i]?.type)}
                        </div>
                        <div className="flex gap-3">
                          <span className="mt-0.5 w-6 text-center text-xs font-semibold text-ink-3">
                            {i + 1}
                          </span>
                          <div className="min-w-0">
                            <button
                              className="text-sm font-medium hover:text-accent"
                              onClick={() => setAsset(s.asset_id)}
                            >
                              {s.name}
                            </button>
                            <span className="ml-2 text-xs text-ink-3">
                              {TYPE_LABEL[s.type] ?? s.type}
                            </span>
                            {s.weak && (
                              <span className="ml-2">
                                <Tag tone="critical">weakness</Tag>
                              </span>
                            )}
                            <ul className="mt-1 list-disc pl-4 text-xs text-ink-2">
                              {s.reasons.map((r) => (
                                <li key={r}>{r}</li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      </li>
                    ))}
                  </ol>
                </>
              )}
            </Card>
          </div>
        </>
      )}
      <AssetDrawer
        assetId={asset}
        onClose={() => setAsset(null)}
        onNavigate={setAsset}
      />
    </div>
  );
}
