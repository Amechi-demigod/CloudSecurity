import { useSearchParams } from "react-router-dom";
import { useAuth } from "../auth/context";
import { PageHeader, Stat } from "../components/ui";
import { fmtAgo } from "../lib/format";
import { useApi } from "../lib/useApi";
import { notificationsApi } from "../notificationsApi";
import NotificationsChannels from "./NotificationsChannels";
import NotificationsLog from "./NotificationsLog";
import NotificationsRules from "./NotificationsRules";

const TABS = [
  { id: "channels", label: "Channels" },
  { id: "rules", label: "Rules" },
  { id: "log", label: "Delivery log" },
] as const;

type TabId = (typeof TABS)[number]["id"];

export default function Notifications() {
  const [params, setParams] = useSearchParams();
  const tab: TabId = (TABS.find((t) => t.id === params.get("tab"))?.id ?? "channels") as TabId;
  const isAdmin = useAuth().can("admin");
  const meta = useApi(notificationsApi.meta, []);
  const status = useApi(notificationsApi.status, [], 10000);
  const s = status.data;

  return (
    <div>
      <PageHeader
        title="Notifications & integrations"
        subtitle={
          isAdmin
            ? "Send runtime alerts, posture findings, vulnerabilities, attack paths and scan results to Teams, Slack, email or signed webhooks."
            : "Read-only: an administrator manages channels and rules."
        }
      />
      {meta.data && !meta.data.public_base_url && (
        <div role="status" className="mb-3 rounded border border-sev-medium/60 bg-sev-medium/10 px-3 py-2 text-sm">
          PUBLIC_BASE_URL is not set on the backend, so messages will not contain links back to this app.
        </div>
      )}
      {meta.data && !meta.data.encryption_configured && (
        <div role="status" className="mb-3 rounded border border-sev-medium/60 bg-sev-medium/10 px-3 py-2 text-sm">
          NOTIFICATIONS_ENCRYPTION_KEY is not set: development uses a derived key; production refuses to save channel secrets.
        </div>
      )}
      {s && (
        <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Stat
            label="Dispatcher"
            value={s.worker_running ? (s.worker_leader ? "Leader" : "Standby") : "Stopped"}
            sub={s.last_tick_at ? `last run ${fmtAgo(s.last_tick_at)} (this replica)` : "only the leader replica sends"}
          />
          <Stat label="Sent (24h)" value={s.sent_24h} />
          <Stat label="Queued" value={s.deliveries.pending + s.deliveries.sending} sub={`${s.event_backlog} events awaiting rule matching`} />
          <Stat label="Dead-lettered" value={s.deliveries.dead} sub="see the delivery log" />
        </div>
      )}
      <div role="tablist" aria-label="Notification settings" className="mb-4 flex gap-1 border-b border-line">
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            className={`-mb-px border-b-2 px-3 py-2 text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
              tab === t.id ? "border-accent text-ink" : "border-transparent text-ink-2 hover:text-ink"
            }`}
            onClick={() => setParams({ tab: t.id }, { replace: true })}
          >
            {t.label}
          </button>
        ))}
      </div>
      {meta.error && <div className="text-sm text-sev-critical">{meta.error}</div>}
      {meta.data && tab === "channels" && <NotificationsChannels meta={meta.data} isAdmin={isAdmin} onChange={status.reload} />}
      {meta.data && tab === "rules" && <NotificationsRules meta={meta.data} isAdmin={isAdmin} />}
      {tab === "log" && <NotificationsLog isAdmin={isAdmin} onChange={status.reload} />}
    </div>
  );
}
