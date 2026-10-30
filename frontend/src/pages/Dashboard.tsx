import { Download } from "lucide-react";
import { api, type DashMeta, type DashRange } from "../api";
import { GettingStarted } from "../components/org";
import { ErrorNote } from "../components/ui";
import { TABS, type TabKey } from "../lib/dash";
import { useApi } from "../lib/useApi";
import { useUrlState } from "../lib/useUrlState";
import EndpointsTab from "./dashboards/Endpoints";
import ExposureTab from "./dashboards/Exposure";
import IdentitiesTab from "./dashboards/Identities";
import OverviewTab from "./dashboards/Overview";
import VulnsTab from "./dashboards/Vulnerabilities";

// The Dashboards page: five tabs over one set of global controls (time range and cloud account),
// all kept in the URL (?tab=vulns&range=90d&account=<id>) so every view can be linked to.
// Each tab loads one /api/dashboards/<tab> response; every number links to the records behind it.

const RANGES: DashRange[] = ["7d", "30d", "90d"];
const HEADINGS: Record<TabKey, { title: string; sub: string }> = {
  overview: { title: "Security overview", sub: "Live posture, runtime and risk across all connected cloud accounts and endpoints" },
  vulns: { title: "Vulnerabilities", sub: "Prioritised by exploitability, runtime use and internet exposure" },
  exposure: { title: "External exposure", sub: "What an attacker on the internet can reach, and the paths into your crown jewels" },
  identities: { title: "Identities", sub: "Cloud identities, their privileges and the paths they open" },
  endpoints: { title: "Endpoints", sub: "Managed devices, their posture and the vulnerabilities on them" },
};

export interface TabProps {
  range: DashRange;
  account: string;
  meta: DashMeta | null;
}

function RangeControl({ value, onChange }: { value: DashRange; onChange: (v: DashRange) => void }) {
  return (
    <div role="radiogroup" aria-label="Time range" className="flex overflow-hidden rounded-lg border border-line bg-surface-1">
      {RANGES.map((r) => (
        <button
          key={r}
          type="button"
          role="radio"
          aria-checked={value === r}
          onClick={() => onChange(r)}
          className={`px-3 py-1.5 text-[12.5px] transition focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent ${
            value === r ? "bg-accent/15 font-semibold text-accent" : "text-ink-2 hover:bg-surface-2"
          }`}
        >
          {r}
        </button>
      ))}
    </div>
  );
}

export default function DashboardPage() {
  const [tabParam, setTab] = useUrlState("tab", "overview");
  const [rangeParam, setRange] = useUrlState("range", "30d");
  const [account, setAccount] = useUrlState("account", "");
  const tab: TabKey = TABS.some((t) => t.key === tabParam) ? (tabParam as TabKey) : "overview";
  const range: DashRange = RANGES.includes(rangeParam as DashRange) ? (rangeParam as DashRange) : "30d";
  const { data: meta, error } = useApi(() => api.dashboards({ range, account: account || undefined }), [range, account], 60000);
  const heading = HEADINGS[tab];
  const accountName = meta?.accounts.find((a) => a.id === account)?.name ?? account;
  const props: TabProps = { range, account, meta };

  return (
    <div className="mx-auto max-w-[1400px]">
      <div data-print="hide">
        <GettingStarted />
      </div>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-[22px] font-semibold tracking-tight">{heading.title}</h1>
          <p className="mt-0.5 text-[13px] text-ink-3">
            {heading.sub}
            {tab !== "endpoints" && account ? ` · ${accountName}` : ""} · last {range.replace("d", " days")}
          </p>
        </div>
        <div data-print="hide" className="flex flex-wrap items-center gap-2">
          <RangeControl value={range} onChange={(v) => setRange(v)} />
          <label className="sr-only" htmlFor="dash-account">
            Cloud account
          </label>
          <select
            id="dash-account"
            value={account}
            onChange={(e) => setAccount(e.target.value)}
            disabled={tab === "endpoints"}
            className="max-w-[14rem] disabled:opacity-50 rounded-lg border border-line bg-surface-1 px-2.5 py-1.5 text-[12.5px] text-ink-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            title={tab === "endpoints" ? "Devices are not tied to a cloud account" : "Limit the dashboards to one subscription, account or project"}
          >
            <option value="">All cloud accounts</option>
            {meta?.accounts.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} ({a.provider.toUpperCase()})
              </option>
            ))}
            {account && meta && !meta.accounts.some((a) => a.id === account) && <option value={account}>{account}</option>}
          </select>
          <button
            type="button"
            onClick={() => window.print()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface-1 px-3 py-1.5 text-[12.5px] text-ink-2 transition hover:bg-surface-2 hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            title="Print this tab or save it as a PDF"
          >
            <Download aria-hidden className="h-3.5 w-3.5" />
            Export PDF
          </button>
        </div>
      </div>

      <nav aria-label="Dashboards" className="mb-[18px] mt-4 overflow-x-auto border-b border-line" data-print="hide">
        <ul role="tablist" className="flex min-w-max gap-1">
          {TABS.map((t) => {
            const on = t.key === tab;
            const badge = "badge" in t && meta ? meta.tabs[t.badge] : null;
            return (
              <li key={t.key} role="presentation">
                <button
                  type="button"
                  role="tab"
                  aria-selected={on}
                  onClick={() => setTab(t.key)}
                  className={`-mb-px flex items-center gap-1.5 border-b-2 px-3.5 py-2.5 text-sm transition focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent ${
                    on ? "border-accent font-semibold text-accent" : "border-transparent font-medium text-ink-3 hover:text-ink"
                  }`}
                >
                  {t.label}
                  {badge !== null && badge !== undefined && (
                    <span className="rounded-full bg-surface-2 px-1.5 text-[11px] font-medium text-ink-2">{badge.toLocaleString()}</span>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </nav>

      <ErrorNote error={error} />
      <div role="tabpanel" aria-label={TABS.find((t) => t.key === tab)?.label}>
        {tab === "overview" && <OverviewTab {...props} />}
        {tab === "vulns" && <VulnsTab {...props} />}
        {tab === "exposure" && <ExposureTab {...props} />}
        {tab === "identities" && <IdentitiesTab {...props} />}
        {tab === "endpoints" && <EndpointsTab {...props} />}
      </div>
      {meta && (
        <p className="mt-5 text-xs text-ink-3">
          Changes compare with {range.replace("d", " days")} ago and are shown once that much history exists
          {meta.history_since ? ` (daily history since ${new Date(`${meta.history_since}T00:00:00`).toLocaleDateString()})` : ""}.
        </p>
      )}
    </div>
  );
}
