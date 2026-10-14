import { useState } from "react";
import { api } from "../api";
import { Button, Card, ErrorNote, PageHeader, SeverityBadge, Table, Tag, fmtTime, useApi } from "../components/ui";

export default function Connectors() {
  const connectors = useApi(api.connectors, []);
  const scans = useApi(api.scans, [], 3000);
  const posture = useApi(api.postureRules, []);
  const detection = useApi(api.detectionRules, []);
  const [scanError, setScanError] = useState<string | null>(null);
  const running = scans.data?.some((s) => s.status === "running");

  async function runScan(name: string) {
    try {
      setScanError(null);
      await api.startScan(name);
      scans.reload();
    } catch (e) {
      setScanError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div>
      <PageHeader title="Connectors & scans" subtitle="Cloud connectors are strictly read-only. Scan results merge into the same inventory and findings." />
      <ErrorNote error={connectors.error ?? scanError} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {connectors.data?.map((c) => (
          <Card key={c.name} title={<span className="capitalize">{c.name}</span>}>
            <p className="text-sm text-ink-2">{c.description}</p>
            <div className="mt-3 flex items-center justify-between">
              {c.configured ? <Tag tone="good">Configured</Tag> : <Tag>Not configured</Tag>}
              {c.name === "azure" && (
                <Button
                  variant="primary"
                  disabled={!c.configured || running}
                  onClick={() => runScan(c.name)}
                  title={c.configured ? "Run a read-only Azure posture scan" : "Set AZURE_* env vars on the backend"}
                >
                  {running ? "Scanning…" : "Run scan"}
                </Button>
              )}
            </div>
            {c.name === "azure" && !c.configured && (
              <p className="mt-3 text-xs text-ink-3">
                Set <code>AZURE_TENANT_ID</code>, <code>AZURE_CLIENT_ID</code>, <code>AZURE_CLIENT_SECRET</code> and{" "}
                <code>AZURE_SUBSCRIPTION_IDS</code> for a service principal with the <b>Reader</b> role, then restart the backend.
              </p>
            )}
          </Card>
        ))}
        <Card title="Runtime sensor">
          <p className="text-sm text-ink-2">
            Runtime sensors (e.g. a future eBPF agent) push events to <code className="text-ink">POST /api/runtime/events</code>.
            Schema at <code className="text-ink">GET /api/runtime/schema</code>.
          </p>
          <div className="mt-3">
            <Tag tone="accent">Push-based</Tag>
          </div>
        </Card>
      </div>

      <Card title="Scan history" className="mt-4">
        <Table head={["Connector", "Status", "Started", "Assets", "Open findings", "Summary"]}>
          {scans.data?.map((s) => (
            <tr key={s.id}>
              <td className="px-3 py-2 capitalize">{s.connector}</td>
              <td className="px-3 py-2">
                <Tag tone={s.status === "succeeded" ? "good" : s.status === "failed" ? "warn" : "accent"}>{s.status}</Tag>
              </td>
              <td className="px-3 py-2 text-xs text-ink-2">{fmtTime(s.started_at)}</td>
              <td className="px-3 py-2">{s.assets_found}</td>
              <td className="px-3 py-2">{s.findings_open}</td>
              <td className="px-3 py-2 text-xs text-ink-2">
                {s.message}
                {s.errors.length > 0 && (
                  <details className="mt-1">
                    <summary className="cursor-pointer text-ink-3">{s.errors.length} errors</summary>
                    <ul className="mt-1 list-disc pl-4 font-mono text-[11px]">
                      {s.errors.map((e, i) => (
                        <li key={i}>{e}</li>
                      ))}
                    </ul>
                  </details>
                )}
              </td>
            </tr>
          ))}
          {scans.data?.length === 0 && (
            <tr>
              <td colSpan={6} className="px-3 py-6 text-center text-sm text-ink-3">
                No scans yet.
              </td>
            </tr>
          )}
        </Table>
      </Card>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title={`Posture rules (${posture.data?.length ?? 0})`}>
          <ul className="max-h-96 space-y-1.5 overflow-y-auto text-sm">
            {posture.data?.map((r) => (
              <li key={r.id} className="flex items-center gap-2">
                <SeverityBadge severity={r.severity} />
                <span className="font-mono text-xs text-ink-3">{r.id}</span>
                <span className="truncate">{r.title}</span>
              </li>
            ))}
          </ul>
        </Card>
        <Card title={`Runtime detection rules (${detection.data?.length ?? 0})`}>
          <ul className="max-h-96 space-y-1.5 overflow-y-auto text-sm">
            {detection.data?.map((r) => (
              <li key={r.id} className="flex items-center gap-2">
                <SeverityBadge severity={r.severity} />
                <span className="font-mono text-xs text-ink-3">{r.mitre_technique_id}</span>
                <span className="truncate">{r.title}</span>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </div>
  );
}
