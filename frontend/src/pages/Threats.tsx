import { useState } from "react";
import { api, type Alert } from "../api";
import AssetDrawer from "../components/AssetDrawer";
import { Button, Card, Empty, ErrorNote, PageHeader, Select, SeverityBadge, Tag, TYPE_LABEL, fmtAgo, fmtTime, useApi } from "../components/ui";

const EVENT_LABEL: Record<string, string> = {
  process_exec: "exec",
  network_connection: "net",
  file_access: "file",
  privilege_escalation: "privesc",
};

function AlertDetailPanel({ id, onChanged, onAsset }: { id: string; onChanged: () => void; onAsset: (id: string) => void }) {
  const { data: a, error, reload } = useApi(() => api.alert(id), [id], 5000);
  if (!a) return <ErrorNote error={error} />;
  async function set(status: Alert["status"]) {
    await api.updateAlert(id, status);
    reload();
    onChanged();
  }
  return (
    <div>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={a.severity} />
        <h3 className="text-base font-semibold">{a.title}</h3>
        <Tag>{a.status}</Tag>
      </div>
      <p className="mt-2 text-sm text-ink-2">{a.description}</p>
      <dl className="mt-3 grid grid-cols-[9rem_1fr] gap-y-1 text-sm">
        <dt className="text-ink-3">MITRE ATT&amp;CK</dt>
        <dd>
          <a
            className="hover:text-accent"
            href={`https://attack.mitre.org/techniques/${a.mitre_technique_id.replace(".", "/")}/`}
            target="_blank"
            rel="noreferrer"
          >
            {a.mitre_tactic} · <span className="font-mono">{a.mitre_technique_id}</span> {a.mitre_technique_name}
          </a>
        </dd>
        <dt className="text-ink-3">Workload</dt>
        <dd>
          {a.asset ? (
            <button className="hover:text-accent" onClick={() => onAsset(a.asset!.id)}>
              {a.asset.name} <span className="text-xs text-ink-3">({TYPE_LABEL[a.asset.type] ?? a.asset.type})</span>
            </button>
          ) : (
            "—"
          )}
          {a.asset?.internet_exposed && (
            <span className="ml-2">
              <Tag tone="warn">Internet-exposed</Tag>
            </span>
          )}
        </dd>
        <dt className="text-ink-3">Occurrences</dt>
        <dd>
          {a.event_count} · first {fmtTime(a.first_seen)} · last {fmtAgo(a.last_seen)}
        </dd>
      </dl>
      <div className="mt-3 flex gap-2">
        {a.status === "open" && <Button onClick={() => set("acknowledged")}>Acknowledge</Button>}
        {a.status !== "resolved" && <Button onClick={() => set("resolved")}>Resolve</Button>}
        {a.status === "resolved" && <Button onClick={() => set("open")}>Reopen</Button>}
      </div>

      <h4 className="mb-2 mt-5 text-xs font-semibold uppercase tracking-wide text-ink-3">Event timeline</h4>
      <ol className="relative ml-2 border-l border-line">
        {a.timeline.map((e) => (
          <li key={e.id} className="mb-2 ml-4">
            <span
              className={`absolute -left-[5px] mt-1.5 h-2.5 w-2.5 rounded-full border border-surface-1 ${e.triggered ? "bg-sev-critical" : "bg-ink-3"}`}
            />
            <div className="flex items-baseline gap-2 text-xs">
              <span className="text-ink-3">{new Date(e.timestamp).toLocaleTimeString()}</span>
              <Tag>{EVENT_LABEL[e.event_type] ?? e.event_type}</Tag>
              {e.triggered && <span className="text-[11px] font-semibold text-sev-critical">detection</span>}
            </div>
            <div className={`mt-0.5 break-all font-mono text-xs ${e.triggered ? "text-ink" : "text-ink-2"}`}>{e.summary}</div>
          </li>
        ))}
      </ol>
    </div>
  );
}

export default function Threats() {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [asset, setAsset] = useState<string | null>(null);
  const alerts = useApi(() => api.alerts({ status: status || undefined, severity: severity || undefined }), [status, severity], 5000);
  const events = useApi(() => api.events(40), [], 3000);
  const current = selected ?? alerts.data?.[0]?.id ?? null;

  return (
    <div>
      <PageHeader
        title="Runtime threats (CDR)"
        subtitle="Detections from runtime events: process execution, network, file access and privilege changes."
      />
      <ErrorNote error={alerts.error} />
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <Select
          label="Status"
          value={status}
          onChange={setStatus}
          options={[
            { value: "", label: "Active" },
            { value: "open", label: "Open" },
            { value: "acknowledged", label: "Acknowledged" },
            { value: "resolved", label: "Resolved" },
            { value: "all", label: "All" },
          ]}
        />
        <Select label="Severity" value={severity} onChange={setSeverity} options={["", "critical", "high", "medium", "low"]} />
        <span className="text-xs text-ink-3">{alerts.data ? `${alerts.data.length} alerts` : ""}</span>
      </div>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)]">
        <Card title="Alerts">
          {alerts.data && alerts.data.length === 0 && <Empty>No alerts.</Empty>}
          <ul className="max-h-[34rem] divide-y divide-line/60 overflow-y-auto">
            {alerts.data?.map((a) => (
              <li
                key={a.id}
                className={`cursor-pointer px-2 py-2 hover:bg-surface-2 ${current === a.id ? "bg-surface-2" : ""}`}
                onClick={() => setSelected(a.id)}
              >
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={a.severity} />
                  <span className="truncate text-sm">{a.title}</span>
                  {a.event_count > 1 && <span className="text-xs text-ink-3">×{a.event_count}</span>}
                  <span className="ml-auto shrink-0 text-xs text-ink-3">{fmtAgo(a.last_seen)}</span>
                </div>
                <div className="mt-0.5 flex gap-2 text-xs text-ink-3">
                  <span className="truncate">{a.asset_name}</span>
                  <span className="font-mono">{a.mitre_technique_id}</span>
                  {a.status !== "open" && <span>· {a.status}</span>}
                </div>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Alert detail">
          {current ? (
            <AlertDetailPanel id={current} onChanged={alerts.reload} onAsset={setAsset} />
          ) : (
            <Empty>Select an alert.</Empty>
          )}
        </Card>
      </div>
      <Card
        className="mt-4"
        title={
          <span className="flex items-center gap-2">
            <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-good" /> Live runtime event feed
          </span>
        }
      >
        <div className="max-h-80 overflow-y-auto font-mono text-xs">
          {events.data?.map((e) => (
            <div key={e.id} className="flex gap-3 border-b border-line/40 py-1">
              <span className="w-20 shrink-0 text-ink-3">{new Date(e.timestamp).toLocaleTimeString()}</span>
              <span className="w-14 shrink-0 text-ink-2">{EVENT_LABEL[e.event_type] ?? e.event_type}</span>
              <span className="w-32 shrink-0 truncate text-ink-3" title={e.asset_id ?? ""}>
                {e.asset_id?.split("/").pop()}
              </span>
              <span className="break-all text-ink">{e.summary}</span>
            </div>
          ))}
        </div>
      </Card>
      <AssetDrawer assetId={asset} onClose={() => setAsset(null)} onNavigate={setAsset} />
    </div>
  );
}
