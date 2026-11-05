import { Rocket } from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Breadcrumbs, Button, Card, Empty, ErrorNote, Field, PageHeader, Stat, Table, Tag } from "../../components/ui";
import { RouteGuidance } from "../../components/deployGuidance";
import { SourceBadges } from "../../components/directoryShared";
import { directoryApi, ROUTE_LABEL, type DeployMachine, type DeployRoute, type DeploySelection } from "../../directoryApi";
import { errMsg } from "../../lib/assets";
import { EXCLUDED_HINT, ROUTE_HINT } from "../../lib/deploy";
import { useApi } from "../../lib/useApi";

/** Selection handed over from Discovery (router state; never in the URL). */
export interface DeployState {
  selection: DeploySelection;
  label: string;
}

function RoutePicker({ m, value, onChange }: { m: DeployMachine; value: DeployRoute; onChange: (r: DeployRoute) => void }) {
  if (m.allowed_routes.length <= 1) return <span className="text-xs text-ink-2">{ROUTE_LABEL[value]}</span>;
  return (
    <select
      aria-label={`Route for ${m.name}`}
      value={value}
      onChange={(e) => onChange(e.target.value as DeployRoute)}
      className="rounded border border-line bg-surface-2 px-1.5 py-0.5 text-xs text-ink"
    >
      {m.allowed_routes.map((r) => (
        <option key={r} value={r}>
          {ROUTE_LABEL[r]}
        </option>
      ))}
    </select>
  );
}

export default function DeployAgent() {
  const location = useLocation();
  const navigate = useNavigate();
  const state = location.state as DeployState | null;
  const plan = useApi(() => (state ? directoryApi.deployPlan(state.selection) : Promise.resolve(null)), [state]);
  const sources = useApi(directoryApi.sources, []);
  const [overrides, setOverrides] = useState<Record<string, DeployRoute>>({});
  const [name, setName] = useState(`Agent rollout ${new Date().toISOString().slice(0, 10)}`);
  const [days, setDays] = useState("14");
  const [group, setGroup] = useState("");
  const [cliToken, setCliToken] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const sourceNames = Object.fromEntries((sources.data ?? []).map((x) => [x.id, x.name]));

  const p = plan.data;
  // Machines regrouped by their chosen route (suggestion unless overridden).
  const grouped = useMemo(() => {
    const out = new Map<DeployRoute, DeployMachine[]>();
    for (const g of p?.routes ?? [])
      for (const m of g.items) {
        const r = overrides[m.computer_id] ?? (m.route as DeployRoute);
        out.set(r, [...(out.get(r) ?? []), m]);
      }
    return (["gpo", "intune", "rmm", "manual"] as DeployRoute[]).filter((r) => out.has(r)).map((r) => ({ route: r, items: out.get(r)! }));
  }, [p, overrides]);
  const hasManual = grouped.some((g) => g.route === "manual");
  const wantToken = cliToken ?? hasManual;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!state) return;
    setBusy(true);
    setError(null);
    try {
      const dep = await directoryApi.createDeployment({
        ...state.selection,
        name: name.trim(),
        routes: overrides,
        expires_in_days: Number(days),
        device_group: group.trim() || null,
        command_line_token: wantToken,
      });
      navigate(`/it-assets/discovery/deployments/${dep.id}`, { state: { token: dep.token ?? null }, replace: true });
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  const crumbs = (
    <Breadcrumbs items={[{ label: "IT assets", to: "/it-assets" }, { label: "Discovery", to: "/it-assets/discovery" }, { label: "Deploy agent" }]} />
  );
  if (!state) {
    return (
      <div>
        {crumbs}
        <PageHeader title="Deploy agent" />
        <Card>
          <Empty icon={Rocket} title="Nothing selected" action={<Link className="text-sm font-medium text-accent hover:underline" to="/it-assets/discovery?type=not_managed">Open “No agent” machines</Link>}>
            Select computers without an agent in Discovery (or use a whole issue filter), then choose Deploy agent.
          </Empty>
        </Card>
      </div>
    );
  }

  return (
    <div>
      {crumbs}
      <PageHeader
        title="Deploy agent"
        subtitle={`${state.label}. Grouped by the best route for where each machine was found and its OS. Nothing is changed in your directories: you follow the steps in your own tools, and the deployment tracks which machines enroll.`}
      />
      <ErrorNote error={plan.error} />
      {p && (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat label="Selected machines" value={p.total.toLocaleString()} />
            <Stat label="Can get the agent" value={p.deployable.toLocaleString()} />
            <Stat label="Excluded" value={(p.total - p.deployable).toLocaleString()} hint="Already managed, phones / ChromeOS, personal devices, Linux or unknown OS" />
            <Stat label="Routes" value={grouped.length} sub={grouped.map((g) => ROUTE_LABEL[g.route]).join(", ")} />
          </div>

          {grouped.map((g) => {
            const platforms: Record<string, number> = {};
            const ous = new Map<string, { domain: string; ou: string; count: number }>();
            for (const m of g.items) {
              platforms[m.platform] = (platforms[m.platform] ?? 0) + 1;
              const k = `${m.domain}|${m.ou}`;
              ous.set(k, { domain: m.domain, ou: m.ou, count: (ous.get(k)?.count ?? 0) + 1 });
            }
            const facts = { route: g.route, label: ROUTE_LABEL[g.route], count: g.items.length, platforms, ous: [...ous.values()].sort((a, b) => b.count - a.count) };
            return (
              <Card
                key={g.route}
                className="mb-4"
                title={
                  <span className="flex items-center gap-2">
                    {ROUTE_LABEL[g.route]} <Tag tone="accent">{g.items.length}</Tag>
                    {Object.entries(platforms).map(([k, n]) => (
                      <Tag key={k}>
                        {k === "macos" ? "macOS" : k === "windows" ? "Windows" : k} {n}
                      </Tag>
                    ))}
                  </span>
                }
              >
                <p className="mb-3 text-sm text-ink-2">{ROUTE_HINT[g.route]}</p>
                <details className="mb-4">
                  <summary className="cursor-pointer text-sm font-medium text-accent">Machines ({g.items.length}) and route per machine</summary>
                  <div className="mt-2">
                    <Table head={["Machine", "Found in", "OS", "OU / domain", "Route"]}>
                      {g.items.map((m) => (
                        <tr key={m.computer_id}>
                          <td className="px-3 py-1.5 font-medium text-ink">{m.name}</td>
                          <td className="px-3 py-1.5 text-xs">
                            <SourceBadges refs={m.kinds.map((k) => ({ id: m.computer_id, source_id: m.source_ids[0] ?? "", type: "", kind: k }))} names={sourceNames} />
                          </td>
                          <td className="px-3 py-1.5 text-xs text-ink-2">{m.os}</td>
                          <td className="max-w-xs truncate px-3 py-1.5 text-xs text-ink-3" title={m.ou}>
                            {m.ou || m.domain || "—"}
                          </td>
                          <td className="px-3 py-1.5">
                            <RoutePicker
                              m={m}
                              value={overrides[m.computer_id] ?? (m.route as DeployRoute)}
                              onChange={(r) =>
                                setOverrides((o) => {
                                  const next = { ...o };
                                  if (r === m.route) delete next[m.computer_id];
                                  else next[m.computer_id] = r;
                                  return next;
                                })
                              }
                            />
                          </td>
                        </tr>
                      ))}
                    </Table>
                  </div>
                </details>
                <RouteGuidance facts={facts} names={g.items.map((m) => m.name)} serverUrl={p.server_url} />
              </Card>
            );
          })}

          {p.excluded.length > 0 && (
            <Card title="Excluded" className="mb-4">
              <ul className="space-y-3">
                {p.excluded.map((x) => (
                  <li key={x.reason}>
                    <div className="flex items-center gap-2 text-sm font-medium text-ink">
                      {x.label} <Tag>{x.count}</Tag>
                    </div>
                    <p className="text-xs text-ink-3">{EXCLUDED_HINT[x.reason]}</p>
                    <p className="mt-0.5 text-xs text-ink-2">
                      {x.items
                        .slice(0, 12)
                        .map((m) => m.name)
                        .join(", ")}
                      {x.items.length > 12 ? ` and ${x.items.length - 12} more` : ""}
                    </p>
                  </li>
                ))}
              </ul>
            </Card>
          )}

          {p.deployable > 0 ? (
            <Card title="Create the deployment">
              <form className="grid grid-cols-1 gap-3 md:grid-cols-2" onSubmit={submit}>
                <Field label="Name" id="dep-name" required maxLength={128} value={name} onChange={(e) => setName(e.target.value)} />
                <Field
                  label="Tokens expire after (days)"
                  id="dep-days"
                  type="number"
                  min={1}
                  max={90}
                  required
                  value={days}
                  onChange={(e) => setDays(e.target.value)}
                  hint="Installers and tokens of this deployment stop enrolling after this."
                />
                <Field
                  label="Device group (optional)"
                  id="dep-group"
                  maxLength={64}
                  placeholder="e.g. Rollout wave 1"
                  value={group}
                  onChange={(e) => setGroup(e.target.value)}
                  hint="Label applied to devices that enroll with this deployment's installers."
                />
                <label className="flex items-start gap-2 text-sm md:col-span-2">
                  <input type="checkbox" className="mt-1" checked={wantToken} onChange={(e) => setCliToken(e.target.checked)} />
                  <span>
                    Also create a token for command-line installs
                    <span className="block text-xs text-ink-3">
                      Shown once after creation, for the generic installer + <code>CNAPP_TOKEN</code> or <code>cnapp-agent configure</code>. Not needed when you use the
                      pre-configured installers.
                    </span>
                  </span>
                </label>
                <p className="text-xs text-ink-3 md:col-span-2">
                  Enrollment caps follow the batch: the number of machines plus a 10% margin (re-installs on an enrolled machine use none).
                </p>
                <div className="md:col-span-2">
                  <Button type="submit" variant="primary" disabled={busy || !name.trim()}>
                    {busy ? "Creating…" : `Create deployment for ${p.deployable} machine${p.deployable === 1 ? "" : "s"}`}
                  </Button>
                </div>
              </form>
              <ErrorNote error={error} />
            </Card>
          ) : (
            <Card>
              <Empty icon={Rocket} title="None of these machines can get the agent">
                See the reasons above.
              </Empty>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
