import { api } from "../api";
import { Drawer, ErrorNote, RiskBar, SeverityBadge, Tag, TYPE_LABEL, fmtAgo, useApi } from "./ui";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mt-5">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-ink-3">{title}</h3>
      {children}
    </div>
  );
}

function fmtValue(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

export default function AssetDrawer({ assetId, onClose, onNavigate }: { assetId: string | null; onClose: () => void; onNavigate?: (id: string) => void }) {
  const { data, error } = useApi(() => (assetId ? api.assetDetail(assetId) : Promise.resolve(null)), [assetId]);
  const a = data?.asset;
  return (
    <Drawer open={!!assetId} onClose={onClose} title={a ? a.name : "Loading…"}>
      <ErrorNote error={error} />
      {a && data && (
        <>
          <div className="flex flex-wrap gap-1.5">
            <Tag tone="accent">{TYPE_LABEL[a.type] ?? a.type}</Tag>
            <Tag>{a.provider}</Tag>
            {a.region && <Tag>{a.region}</Tag>}
            <Tag>source: {a.source}</Tag>
            {a.internet_exposed && <Tag tone="warn">Internet-exposed</Tag>}
            {a.sensitive_data && <Tag tone="warn">Sensitive data</Tag>}
          </div>
          <dl className="mt-3 grid grid-cols-[8rem_1fr] gap-x-3 gap-y-1 text-sm">
            <dt className="text-ink-3">Subscription</dt>
            <dd>{a.subscription_name ?? "—"}</dd>
            <dt className="text-ink-3">Resource group</dt>
            <dd>{a.resource_group ?? "—"}</dd>
            <dt className="text-ink-3">Resource ID</dt>
            <dd className="break-all font-mono text-xs text-ink-2">{a.id}</dd>
            <dt className="text-ink-3">Last seen</dt>
            <dd>{fmtAgo(a.last_seen)}</dd>
          </dl>

          {Object.keys(a.tags).length > 0 && (
            <Section title="Tags">
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(a.tags).map(([k, v]) => (
                  <Tag key={k}>
                    {k}={v}
                  </Tag>
                ))}
              </div>
            </Section>
          )}

          <Section title="Configuration">
            <dl className="grid grid-cols-[12rem_1fr] gap-x-3 gap-y-1 text-xs">
              {Object.entries(a.properties)
                .filter(([k]) => k !== "security_rules" && k !== "firewall_rules")
                .map(([k, v]) => (
                  <div key={k} className="contents">
                    <dt className="text-ink-3">{k}</dt>
                    <dd className="break-all font-mono text-ink-2">{fmtValue(v)}</dd>
                  </div>
                ))}
            </dl>
            {Array.isArray(a.properties.security_rules) && (
              <table className="mt-2 w-full text-xs">
                <thead className="text-ink-3">
                  <tr>
                    <th className="text-left font-medium">Rule</th>
                    <th className="text-left font-medium">Dir</th>
                    <th className="text-left font-medium">Access</th>
                    <th className="text-left font-medium">Source</th>
                    <th className="text-left font-medium">Ports</th>
                  </tr>
                </thead>
                <tbody className="font-mono text-ink-2">
                  {(a.properties.security_rules as Record<string, unknown>[]).map((r, i) => (
                    <tr key={i}>
                      <td>{String(r.name)}</td>
                      <td>{String(r.direction)}</td>
                      <td>{String(r.access)}</td>
                      <td>{fmtValue(r.source_prefixes)}</td>
                      <td>{fmtValue(r.port_ranges)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Section>

          <Section title={`Relationships (${data.relationships.length})`}>
            <ul className="space-y-1 text-sm">
              {data.relationships.map((r, i) => (
                <li key={i} className="flex items-center gap-2">
                  <span className="w-28 text-xs text-ink-3">
                    {r.direction === "out" ? r.type.replace("_", " ") + " →" : "← " + r.type.replace("_", " ")}
                  </span>
                  <button className="text-left hover:text-accent" onClick={() => onNavigate?.(r.asset.id)}>
                    {r.asset.name}
                  </button>
                  <span className="text-xs text-ink-3">{TYPE_LABEL[r.asset.type] ?? r.asset.type}</span>
                </li>
              ))}
              {data.relationships.length === 0 && <li className="text-ink-3">None</li>}
            </ul>
          </Section>

          <Section title={`Posture findings (${data.findings.filter((f) => f.status === "open").length} open)`}>
            <ul className="space-y-2">
              {data.findings.map((f) => (
                <li key={f.id} className="rounded border border-line p-2">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={f.severity} />
                    <span className="text-sm">{f.title}</span>
                    {f.status !== "open" && <Tag>{f.status}</Tag>}
                  </div>
                  <div className="mt-1 text-xs text-ink-2">{f.remediation}</div>
                </li>
              ))}
              {data.findings.length === 0 && <li className="text-sm text-ink-3">No findings</li>}
            </ul>
          </Section>

          {data.vulnerabilities.length > 0 && (
            <Section title={`Vulnerabilities (${data.vulnerabilities.length})`}>
              <table className="w-full text-xs">
                <tbody className="divide-y divide-line/60">
                  {data.vulnerabilities.map((v) => (
                    <tr key={v.id}>
                      <td className="py-1 font-mono">{v.cve_id}</td>
                      <td>{v.package}</td>
                      <td>CVSS {v.cvss}</td>
                      <td>{v.in_use ? <Tag tone="warn">in use</Tag> : <Tag>dormant</Tag>}</td>
                      <td>
                        <RiskBar value={v.risk_score} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Section>
          )}

          {data.alerts.length > 0 && (
            <Section title="Runtime alerts">
              <ul className="space-y-1 text-sm">
                {data.alerts.map((al) => (
                  <li key={al.id} className="flex items-center gap-2">
                    <SeverityBadge severity={al.severity} />
                    {al.title}
                    <span className="text-xs text-ink-3">{fmtAgo(al.last_seen)}</span>
                  </li>
                ))}
              </ul>
            </Section>
          )}
        </>
      )}
    </Drawer>
  );
}
