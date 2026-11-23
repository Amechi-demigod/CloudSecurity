import { ChevronDown, ChevronRight, ShieldCheck } from "lucide-react";
import { Fragment, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../auth/context";
import { useFindingActions } from "../../components/ExternalFindingActions";
import { FixBy, NotAsvBanner, StatusTag } from "../../components/external";
import { Button, Card, Empty, ErrorNote, FilterBar, FilterChips, FilterSearch, FilterSelect, NumCell, PageHeader, Pill, PillRow, Segments, Table, TextCell, type FilterChip, type PillTone } from "../../components/ui";
import { externalApi, type ExtFinding, type ExtFindingFilter, type ExtFindingGroup } from "../../externalApi";
import { preAsvLabel } from "../../lib/externalUi";
import { fmtAgo } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { useSortState } from "../../lib/useSort";
import { useUrlState } from "../../lib/useUrlState";
import { PAGE_INFO } from "../../lib/pageInfo";

const SEV_TONE: Record<string, PillTone> = { critical: "critical", high: "high", medium: "medium", low: "neutral", info: "neutral" };
const SevPill = ({ severity }: { severity: string }) => <PillRow><Pill tone={SEV_TONE[severity] ?? "neutral"}>{severity[0].toUpperCase() + severity.slice(1)}</Pill></PillRow>;
const hostPort = (host: string, port: number | null) => `${host}${port ? `:${port}` : ""}`;
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

/** The one findings list: the Scan results tab of Attack surface and the Issues > Internet-facing page both show this. */
export function FindingsPanel() {
  const [view, setView] = useUrlState("view", "grouped");
  const [status, setStatus] = useUrlState("status", "open");
  const [severity, setSeverity] = useUrlState("severity");
  const [preAsv, setPreAsv] = useUrlState("pre_asv");
  const [target, setTarget] = useUrlState("target");
  const [host, setHost] = useUrlState("host");
  const [q, setQ] = useUrlState("q");
  const grouped = view !== "all";
  const { data: targets } = useApi(() => externalApi.targets(), []);
  const verified = (targets ?? []).filter((t) => t.verified);
  const filter: ExtFindingFilter = {
    status: status || undefined,
    severity: severity || undefined,
    pre_asv: preAsv || undefined,
    target: target || undefined,
    host: host || undefined,
    q: q.trim() || undefined,
  };
  const filtered = !!(severity || preAsv || target || host || q.trim()) || status !== "open";
  const clearAll = () => {
    setStatus("open");
    setSeverity("");
    setPreAsv("");
    setTarget("");
    setHost("");
    setQ("");
  };
  const chipList: FilterChip[] = [
    status !== "open" && { label: "Status", value: status || "All", onRemove: () => setStatus("open") },
    severity && { label: "Severity", value: severity, onRemove: () => setSeverity("") },
    preAsv && { label: "PCI scan", value: preAsv, onRemove: () => setPreAsv("") },
    target && { label: "Target", value: verified.find((t) => t.id === target)?.value ?? target, onRemove: () => setTarget("") },
    host && { label: "Host", value: host, onRemove: () => setHost("") },
    q.trim() && { label: "Search", value: q, onRemove: () => setQ("") },
  ].filter((c): c is FilterChip => !!c);
  const [count, setCount] = useState("");

  return (
    <div className="space-y-4">
      <FilterBar
        count={count}
        moreActive={[preAsv, target].filter(Boolean).length}
        more={
          <>
            <FilterSelect label="PCI scan" value={preAsv} onChange={setPreAsv} options={[{ value: "", label: "Any" }, { value: "fail", label: "Would fail" }, { value: "pass", label: "Would pass" }, { value: "exception", label: "Exception" }]} />
            <FilterSelect label="Target" value={target} onChange={setTarget} options={[{ value: "", label: "All" }, ...verified.map((t) => ({ value: t.id, label: t.value }))]} />
          </>
        }
      >
        <Segments
          label="View"
          value={view === "all" ? "all" : "grouped"}
          onChange={setView}
          options={[
            { value: "grouped", label: "By finding" },
            { value: "all", label: "All findings" },
          ]}
        />
        <FilterSearch value={q} onChange={setQ} placeholder="Title, ID, host, port" label="Search findings" />
        <FilterSelect label="Severity" value={severity} onChange={setSeverity} options={["", "critical", "high", "medium", "low", "info"]} />
        <FilterSelect label="Status" value={status} onChange={setStatus} options={[{ value: "", label: "All" }, "open", "disputed", "accepted", "resolved"]} />
      </FilterBar>
      <FilterChips chips={chipList} onClearAll={clearAll} />
      {grouped ? (
        <GroupedView filter={filter} filtered={filtered} setCount={setCount} setHost={setHost} />
      ) : (
        <AllView filter={filter} filtered={filtered} setCount={setCount} setHost={setHost} />
      )}
    </div>
  );
}

export default function ExternalFindings() {
  return (
    <div className="space-y-4">
      <PageHeader title="Internet-facing issues" info={PAGE_INFO.internetFacing} subtitle="Weaknesses an attacker could see from the internet. Findings close by themselves when a later scan no longer sees them." />
      <NotAsvBanner />
      <FindingsPanel />
    </div>
  );
}

interface ViewProps {
  filter: ExtFindingFilter;
  filtered: boolean;
  setCount: (s: string) => void;
  setHost: (h: string) => void;
}

const emptyState = (filtered: boolean) => (
  <Empty icon={ShieldCheck} title={filtered ? "No findings match these filters" : "No findings"}>
    {filtered ? "Try another status or clear a filter." : "Nothing matches. Run a scan to re-check."}
  </Empty>
);

function Caret({ open, label, onToggle }: { open: boolean; label: string; onToggle: () => void }) {
  const Icon = open ? ChevronDown : ChevronRight;
  return (
    <button
      type="button"
      aria-expanded={open}
      aria-label={`${open ? "Collapse" : "Expand"} ${label}`}
      onClick={(e) => {
        e.stopPropagation();
        onToggle();
      }}
      className="rounded p-0.5 text-ink-3 hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
    >
      <Icon aria-hidden className="h-4 w-4" />
    </button>
  );
}

// ----------------------------------------------------------------------------- all findings
function AllView({ filter, filtered, setCount, setHost }: ViewProps) {
  const { can } = useAuth();
  const [expanded, setExpanded] = useState<string | null>(null);
  // The server sorts the whole result (the list is capped), so the sort goes to the API.
  const sorted = useSortState(["severity", "title", "host", "cvss", "pre_asv", "status", "first_seen", "fix_by"], { key: "severity", dir: "desc" }, { severity: "desc", cvss: "desc", first_seen: "desc" });
  const { data, error, loading, reload } = useApi(
    () =>
      externalApi.findings({ ...filter, sort: sorted.sort.key, dir: sorted.sort.dir }).then((r) => {
        setCount(`${r.length} findings`);
        return r;
      }),
    [JSON.stringify(filter), sorted.sort.key, sorted.sort.dir],
  );
  const actions = useFindingActions(reload);
  return (
    <>
      <ErrorNote error={error ?? actions.err} />
      {actions.note && (
        <p role="status" className="text-sm text-ink-2">
          {actions.note}
        </p>
      )}
      <Card>
        <Table
          tableId="external-findings-1"
          head={[
            { label: "Severity", sort: "severity", w: 110 },
            { label: "Finding", sort: "title", w: 380 },
            { label: "Host", sort: "host", w: 220 },
            { label: "CVSS", sort: "cvss", w: 80, align: "right" },
            { label: "PCI scan", sort: "pre_asv", w: 120 },
            { label: "Status", sort: "status", w: 120 },
            { label: "First seen", sort: "first_seen", w: 110 },
            { label: "Fix by", sort: "fix_by", w: 130 },
            { label: "Details", srOnly: true },
          ]}
          sort={sorted.sort}
          onSort={sorted.onSort}
          loading={loading}
          rowCount={data?.length ?? 0}
          noun="findings"
          pageSize={50}
          empty={emptyState(filtered)}
        >
          {data?.map((f) => (
            <Fragment key={f.id}>
              <tr className="cursor-pointer hover:bg-surface-2" onClick={() => setExpanded(expanded === f.id ? null : f.id)}>
                <td className="px-3 py-2"><SevPill severity={f.severity} /></td>
                <td className="px-3 py-2">
                  <div className="min-w-0">
                    <Link to={`/attack-surface/findings/${f.id}`} title={f.title} className="block truncate font-semibold text-ink hover:text-accent hover:underline" onClick={(e) => e.stopPropagation()}>
                      {f.title}
                    </Link>
                    <span className="block truncate font-mono text-xs text-ink-3">{f.ref} · {f.check_id}</span>
                  </div>
                </td>
                <td className="px-3 py-2">
                  <button
                    type="button"
                    title="Show only this host"
                    className="font-mono text-xs hover:text-accent"
                    onClick={(e) => {
                      e.stopPropagation();
                      setHost(f.host);
                    }}
                  >
                    {f.host}
                  </button>
                  {f.port ? <div className="text-[11px] text-ink-3">Port {f.port}{f.service ? ` · ${f.service}` : ""}</div> : null}
                </td>
                <td className="px-3 py-2"><NumCell value={f.cvss ? f.cvss.toFixed(1) : null} /></td>
                <td className="px-3 py-2"><TextCell>{preAsvLabel(f)}</TextCell></td>
                <td className="px-3 py-2"><StatusTag status={f.status} /></td>
                <td className="px-3 py-2 text-xs text-ink-2">{fmtAgo(f.first_seen)}</td>
                <td className="px-3 py-2 text-xs"><FixBy due={f.fix_due} daysLeft={f.days_left} overdueDays={f.overdue_days} /></td>
                <td className="px-3 py-2 text-right">
                  <Caret open={expanded === f.id} label={f.ref} onToggle={() => setExpanded(expanded === f.id ? null : f.id)} />
                </td>
              </tr>
              {expanded === f.id && (
                <tr className="bg-surface-0/40">
                  <td colSpan={9} className="px-4 py-3 text-sm">
                    <ExpandedFinding f={f} canAct={can("analyst")} actions={actions} />
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </Table>
      </Card>
      {actions.modals}
    </>
  );
}

function ExpandedFinding({ f, canAct, actions }: { f: ExtFinding; canAct: boolean; actions: ReturnType<typeof useFindingActions> }) {
  // The list rows carry no description or fix text: the detail is fetched when the row opens.
  const { data: d, error } = useApi(() => externalApi.finding(f.id), [f.id, f.status]);
  const fix = d ? Object.values(d.detail.fix)[0] : null;
  return (
    <div className="space-y-2">
      <ErrorNote error={error} />
      {!d && !error && <p className="text-ink-3">Loading details...</p>}
      {d && (
        <>
          <p><span className="text-ink-3">What we saw: </span><span className="text-ink-2">{d.detail.description}</span></p>
          {fix && <p><span className="text-ink-3">How to fix: </span>{fix}</p>}
          <p className="break-all font-mono text-xs text-ink-3">Evidence: {JSON.stringify(d.evidence)}</p>
          {(d.fail_reason || d.special_note) && (
            <p>
              <span className="text-ink-3">Why it fails pre-ASV: </span>
              {d.fail_reason ?? "Does not fail"}
              {d.special_note ? ` (${d.special_note.replace(/_/g, " ")})` : ""}
            </p>
          )}
          {d.fix_due && (
            <p>
              <span className="text-ink-3">Fix by: </span>
              {new Date(d.fix_due).toLocaleDateString()} ({d.sla_basis}){d.overdue_days ? `, overdue ${d.overdue_days} days` : ""}
            </p>
          )}
          {d.status_note && <p className="text-ink-2">{d.status_note}</p>}
        </>
      )}
      <Link to={`/attack-surface/findings/${f.id}`} className="inline-flex items-center gap-0.5 text-xs font-medium text-accent hover:underline">
        Open full details, steps to reproduce, compliance mapping and history
        <ChevronRight aria-hidden className="h-3.5 w-3.5" />
      </Link>
      {canAct ? (
        f.status !== "resolved" && (
          <div className="flex flex-wrap gap-2 pt-1">
            <Button disabled={actions.busy} onClick={() => void actions.run(async () => { await externalApi.retest(f.id); }, "Re-test started: this host is being scanned again. Refresh in a minute.")}>Re-test now</Button>
            <Button onClick={() => actions.openFor(f.id, "dispute")}>Dispute</Button>
            {f.status !== "accepted" && <Button onClick={() => actions.openFor(f.id, "accept")}>Accept risk</Button>}
            {f.status === "accepted" && <Button onClick={() => void actions.run(() => externalApi.reopen(f.id))}>Re-open</Button>}
          </div>
        )
      ) : (
        <p className="pt-1 text-xs text-ink-3">Read-only access: an analyst or admin can re-test, dispute or accept the risk of findings.</p>
      )}
    </div>
  );
}

// ----------------------------------------------------------------------------- by finding
function statusSummary(g: ExtFindingGroup) {
  const parts = (["open", "disputed", "accepted", "resolved"] as const).filter((s) => g.status_counts[s] > 0);
  if (parts.length === 1) return <StatusTag status={parts[0]} />;
  return <span className="text-xs text-ink-2">{parts.map((s) => `${g.status_counts[s]} ${s === "accepted" ? "accepted risk" : s}`).join(" · ")}</span>;
}

const groupPreAsv = (g: ExtFindingGroup) =>
  g.pre_asv === null ? "-" : g.pre_asv === "fail" ? (g.auto_fail ? "Automatic fail" : "Fail") : g.pre_asv === "exception" ? "Exception" : "Pass";

function GroupedView({ filter, filtered, setCount, setHost }: ViewProps) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const sorted = useSortState(["severity", "title", "affected", "cvss", "pre_asv", "fix_by"], { key: "severity", dir: "desc" }, { severity: "desc", affected: "desc", cvss: "desc" });
  const { data, error, loading } = useApi(
    () =>
      externalApi.findingsGrouped({ ...filter, sort: sorted.sort.key, dir: sorted.sort.dir }).then((r) => {
        setCount(`${plural(r.reduce((n, g) => n + g.affected, 0), "finding")} across ${plural(r.length, "check")}`);
        return r;
      }),
    [JSON.stringify(filter), sorted.sort.key, sorted.sort.dir],
  );
  return (
    <>
      <ErrorNote error={error} />
      <Card>
        <Table
          tableId="external-findings-2"
          head={[
            { label: "Severity", sort: "severity", w: 110 },
            { label: "Finding", sort: "title", w: 380 },
            { label: "Affected", sort: "affected", w: 100, align: "right" },
            { label: "CVSS", sort: "cvss", w: 80, align: "right" },
            { label: "PCI scan", sort: "pre_asv", w: 130 },
            { label: "Status", w: 150 },
            { label: "Fix by", sort: "fix_by", w: 130 },
            { label: "Details", srOnly: true },
          ]}
          sort={sorted.sort}
          onSort={sorted.onSort}
          loading={loading}
          rowCount={data?.length ?? 0}
          noun="findings"
          pageSize={50}
          empty={emptyState(filtered)}
        >
          {data?.map((g) => (
            <Fragment key={g.check_id}>
              <tr className="cursor-pointer hover:bg-surface-2" onClick={() => setExpanded(expanded === g.check_id ? null : g.check_id)}>
                <td className="px-3 py-2"><SevPill severity={g.severity} /></td>
                <td className="px-3 py-2">
                  <div className="min-w-0">
                    <span title={g.title} className="block truncate font-semibold text-ink">{g.title}</span>
                    <span className="block truncate font-mono text-xs text-ink-3">{g.check_id}</span>
                  </div>
                </td>
                <td className="px-3 py-2"><NumCell value={g.affected} title={`${plural(g.affected, "host:port")} on ${plural(g.hosts, "host")}`} /></td>
                <td className="px-3 py-2"><NumCell value={g.cvss ? g.cvss.toFixed(1) : null} /></td>
                <td className="px-3 py-2"><TextCell>{groupPreAsv(g)}</TextCell></td>
                <td className="px-3 py-2">{statusSummary(g)}</td>
                <td className="px-3 py-2 text-xs"><FixBy due={g.fix_due} daysLeft={g.days_left} overdueDays={g.overdue_days} /></td>
                <td className="px-3 py-2 text-right">
                  <Caret open={expanded === g.check_id} label={g.title} onToggle={() => setExpanded(expanded === g.check_id ? null : g.check_id)} />
                </td>
              </tr>
              {expanded === g.check_id && (
                <tr className="bg-surface-0/40">
                  <td colSpan={8} className="px-4 py-3">
                    <table className="w-full text-left text-sm">
                      <thead>
                        <tr className="text-xs uppercase tracking-wide text-ink-3">
                          <th scope="col" className="px-2 py-1 font-medium">ID</th>
                          <th scope="col" className="px-2 py-1 font-medium">Host:port</th>
                          <th scope="col" className="px-2 py-1 font-medium">Status</th>
                          <th scope="col" className="px-2 py-1 font-medium">PCI scan</th>
                          <th scope="col" className="px-2 py-1 font-medium">Fix by</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-line">
                        {g.findings.map((m) => (
                          <tr key={m.id}>
                            <td className="px-2 py-1 font-mono text-xs">
                              <Link className="text-accent hover:underline" to={`/attack-surface/findings/${m.id}`}>{m.ref}</Link>
                            </td>
                            <td className="px-2 py-1">
                              <button type="button" title="Show only this host" className="font-mono text-xs hover:text-accent" onClick={() => setHost(m.host)}>
                                {hostPort(m.host, m.port)}
                              </button>
                            </td>
                            <td className="px-2 py-1"><StatusTag status={m.status} /></td>
                            <td className="px-2 py-1 text-xs">{preAsvLabel(m)}</td>
                            <td className="px-2 py-1 text-xs"><FixBy due={m.fix_due} daysLeft={m.days_left} overdueDays={m.overdue_days} /></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </Table>
      </Card>
    </>
  );
}
