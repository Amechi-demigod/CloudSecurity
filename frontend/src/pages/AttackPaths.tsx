import { useMemo, useState } from "react";
import { api, type AttackPath } from "../api";
import AssetDrawer from "../components/AssetDrawer";
import { Card, Empty, ErrorNote, PageHeader, SeverityBadge, TYPE_LABEL, useApi } from "../components/ui";

const NODE_W = 168;
const NODE_H = 46;
const COL_GAP = 70;
const ROW_GAP = 16;

const TYPE_GLYPH: Record<string, string> = {
  internet: "🌐",
  vm: "VM",
  pod: "POD",
  function_app: "FN",
  identity: "ID",
  storage_account: "ST",
  sql_server: "SQL",
  sql_database: "DB",
  key_vault: "KV",
  aks_cluster: "AKS",
};

type GNode = { id: string; name: string; type: string; sensitive_data?: boolean; internet_exposed?: boolean };
type GEdge = { source: string; target: string; type: string; paths: string[] };

/** Layered left-to-right layout: column = shortest hop distance from the Internet node. */
function layout(nodes: GNode[], paths: AttackPath[]) {
  const depth = new Map<string, number>([["internet", 0]]);
  for (const p of paths) {
    p.steps.forEach((s, i) => depth.set(s.asset_id, Math.min(depth.get(s.asset_id) ?? 99, i + 1)));
  }
  // Push sensitive-data targets to the right-most column so the story reads left to right.
  const maxDepth = Math.max(...depth.values());
  for (const n of nodes) if (n.sensitive_data && n.type !== "identity") depth.set(n.id, Math.max(depth.get(n.id) ?? 0, maxDepth));
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
    col.forEach((n, i) => pos.set(n.id, { x: 10 + d * (NODE_W + COL_GAP), y: offset + i * (NODE_H + ROW_GAP) }));
  }
  return { pos, width: (Math.max(...cols.keys()) + 1) * (NODE_W + COL_GAP), height };
}

function Graph({ nodes, edges, paths, selected, onNode }: { nodes: GNode[]; edges: GEdge[]; paths: AttackPath[]; selected: string | null; onNode: (id: string) => void }) {
  const { pos, width, height } = useMemo(() => layout(nodes, paths), [nodes, paths]);
  const sel = paths.find((p) => p.id === selected);
  const onPath = new Set(sel ? ["internet", ...sel.steps.map((s) => s.asset_id)] : []);
  return (
    <div className="overflow-x-auto">
      <svg width={width} height={height} role="img" aria-label="Attack path graph">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0,0 L10,5 L0,10 z" fill="var(--color-ink-3)" />
          </marker>
          <marker id="arrow-hot" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M0,0 L10,5 L0,10 z" fill="var(--color-sev-critical)" />
          </marker>
        </defs>
        {edges.map((e) => {
          const a = pos.get(e.source);
          const b = pos.get(e.target);
          if (!a || !b) return null;
          const hot = !!selected && e.paths.includes(selected);
          const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2, x2 = b.x, y2 = b.y + NODE_H / 2;
          const mx = (x1 + x2) / 2;
          return (
            <g key={`${e.source}-${e.target}-${e.type}`}>
              <path
                d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2 - 2},${y2}`}
                fill="none"
                stroke={hot ? "var(--color-sev-critical)" : "var(--color-line)"}
                strokeWidth={hot ? 2.5 : 1.5}
                markerEnd={hot ? "url(#arrow-hot)" : "url(#arrow)"}
                opacity={selected && !hot ? 0.5 : 1}
              >
                <title>{e.type.replace("_", " ")}</title>
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
                stroke={onPath.has(n.id) ? "var(--color-sev-critical)" : "var(--color-line)"}
                strokeWidth={onPath.has(n.id) ? 2 : 1}
              />
              <text x={10} y={19} fontSize={10} fontWeight={700} fill="var(--color-ink-3)">
                {TYPE_GLYPH[n.type] ?? n.type.toUpperCase()}
              </text>
              <text x={10} y={35} fontSize={12} fill="var(--color-ink)">
                {n.name.length > 22 ? n.name.slice(0, 21) + "…" : n.name}
              </text>
              {n.sensitive_data && (
                <text x={NODE_W - 8} y={19} fontSize={9} textAnchor="end" fill="var(--color-sev-high)">
                  SENSITIVE
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

export default function AttackPaths() {
  const { data, error } = useApi(() => api.attackGraph(12), [], 30000);
  const [selected, setSelected] = useState<string | null>(null);
  const [asset, setAsset] = useState<string | null>(null);
  const current = selected ?? data?.paths[0]?.id ?? null;
  const path = data?.paths.find((p) => p.id === current);

  return (
    <div>
      <PageHeader
        title="Attack paths"
        subtitle="Exploitable chains from the Internet to sensitive data: exposure → vulnerable workload (in use at runtime) → identity → data."
      />
      <ErrorNote error={error} />
      {data && data.paths.length === 0 && (
        <Card>
          <Empty>No exploitable attack paths found.</Empty>
        </Card>
      )}
      {data && data.paths.length > 0 && (
        <>
          <Card title="Risk graph (top paths)">
            <Graph nodes={data.nodes} edges={data.edges} paths={data.paths} selected={current} onNode={setAsset} />
          </Card>
          <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
            <Card title={`Top attack paths (${data.paths.length})`}>
              <ul className="divide-y divide-line/60">
                {data.paths.map((p) => (
                  <li
                    key={p.id}
                    className={`cursor-pointer px-2 py-2 hover:bg-surface-2 ${p.id === current ? "bg-surface-2" : ""}`}
                    onClick={() => setSelected(p.id)}
                  >
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={p.severity} />
                      <span className="text-xs text-ink-2">score {p.score.toFixed(0)}</span>
                      <span className="text-xs text-ink-3">{p.steps.length} hops</span>
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
                <ol className="space-y-3">
                  <li className="flex gap-3">
                    <span className="mt-0.5 w-6 text-center">🌐</span>
                    <div className="text-sm text-ink-2">Internet</div>
                  </li>
                  {path.steps.map((s, i) => (
                    <li key={s.asset_id} className="flex gap-3">
                      <span className="mt-0.5 w-6 text-center text-xs font-semibold text-ink-3">{i + 1}</span>
                      <div className="min-w-0">
                        <button className="text-sm font-medium hover:text-accent" onClick={() => setAsset(s.asset_id)}>
                          {s.name}
                        </button>
                        <span className="ml-2 text-xs text-ink-3">{TYPE_LABEL[s.type] ?? s.type}</span>
                        <ul className="mt-1 list-disc pl-4 text-xs text-ink-2">
                          {s.reasons.map((r) => (
                            <li key={r}>{r}</li>
                          ))}
                        </ul>
                      </div>
                    </li>
                  ))}
                </ol>
              )}
            </Card>
          </div>
        </>
      )}
      <AssetDrawer assetId={asset} onClose={() => setAsset(null)} onNavigate={setAsset} />
    </div>
  );
}
