import { Network, ShieldAlert } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../auth/context";
import { Breadcrumbs, Button, Card, Empty, ErrorNote, PageHeader, Select, Stat, Table, Tag } from "../../components/ui";
import { SourceBadges } from "../../components/directoryShared";
import {
  directoryApi,
  ISSUE_HINT,
  ISSUE_LABEL,
  ISSUE_TONE,
  ISSUE_TYPES,
  ISSUES_BY_TYPE,
  USER_ISSUES,
  type ComputerStatus,
  type DirComputer,
  type DirUser,
  type Issue,
  type IssueType,
} from "../../directoryApi";
import { errMsg } from "../../lib/assets";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { useUrlState } from "../../lib/useUrlState";
import { CLASS_FILTER_OPTIONS, CLASS_LABEL } from "../../lib/deviceClass";

const PAGE = 100;
// issues: computer issues; users: user issues; people: directory users.
type View = "issues" | "computers" | "users" | "people";
const COMPUTER_ISSUES = ISSUE_TYPES.filter((t) => !USER_ISSUES.includes(t));

const COMPUTER_STATUS: { value: ComputerStatus; label: string }[] = [
  { value: "all", label: "All present" },
  { value: "not_in_assets", label: "Not in IT assets" },
  { value: "matched", label: "Matched to an agent" },
  { value: "unmatched", label: "No agent match" },
  { value: "ambiguous", label: "Ambiguous match" },
  { value: "missing", label: "Missing from directory" },
];

const MATCH_LABEL: Record<string, string> = {
  directory_sid: "computer SID",
  directory_guid: "object GUID",
  entra_device_id: "Entra device ID",
  serial: "serial number",
  fqdn: "FQDN",
  hostname_domain: "host name + domain",
  hostname: "host name only",
};

const COMPLIANCE: Record<string, { label: string; tone: "good" | "warn" | "default" }> = {
  compliant: { label: "compliant", tone: "good" },
  noncompliant: { label: "non-compliant", tone: "warn" },
  ingraceperiod: { label: "grace period", tone: "default" },
};

function When({ at, unknown }: { at: string | null; unknown?: string }) {
  if (!at) return <span className="text-ink-3" title={unknown}>{unknown ? "unknown" : "never"}</span>;
  return <span title={fmtTime(at)}>{fmtAgo(at)}</span>;
}

function Pager({ offset, total, onChange }: { offset: number; total: number; onChange: (o: number) => void }) {
  if (total <= PAGE) return <p className="mt-2 px-1 text-xs text-ink-3">{total.toLocaleString()} total</p>;
  return (
    <div className="mt-3 flex items-center justify-between gap-2 px-1 text-xs text-ink-3">
      <span>
        {(offset + 1).toLocaleString()}–{Math.min(offset + PAGE, total).toLocaleString()} of {total.toLocaleString()}
      </span>
      <div className="flex gap-2">
        <Button disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - PAGE))}>
          Previous
        </Button>
        <Button disabled={offset + PAGE >= total} onClick={() => onChange(offset + PAGE)}>
          Next
        </Button>
      </div>
    </div>
  );
}

function Search({ value, onChange, label }: { value: string; onChange: (v: string) => void; label: string }) {
  return (
    <input
      type="search"
      aria-label={label}
      placeholder={label}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="w-60 rounded border border-line bg-surface-2 px-2.5 py-1 text-sm text-ink placeholder:text-ink-3"
    />
  );
}

function Check({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return <input type="checkbox" aria-label={label} checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} onClick={(e) => e.stopPropagation()} />;
}

/** Debounced copy of a value (search boxes). */
function useDebounced<T>(v: T, ms = 300): T {
  const [d, setD] = useState(v);
  useEffect(() => {
    const t = setTimeout(() => setD(v), ms);
    return () => clearTimeout(t);
  }, [v, ms]);
  return d;
}

function AssetCell({ assetId, canAdd, busy, onAdd }: { assetId: string | null; canAdd: boolean; busy: boolean; onAdd: () => void }) {
  if (assetId)
    return (
      <Link to={`/it-assets/${assetId}`} className="text-accent hover:underline">
        IT asset
      </Link>
    );
  if (!canAdd) return <span className="text-ink-3">—</span>;
  return (
    <button type="button" disabled={busy} onClick={onAdd} className="whitespace-nowrap text-accent hover:underline disabled:opacity-50">
      Add to IT assets
    </button>
  );
}

function PrivilegedBadge({ roles }: { roles?: string[] }) {
  return (
    <span
      title={roles && roles.length ? roles.join(", ") : "Holds a privileged admin role"}
      className="inline-flex items-center gap-1 rounded border border-sev-critical/50 bg-sev-critical/10 px-1.5 py-px text-[10px] font-semibold uppercase tracking-wide text-sev-critical"
    >
      <ShieldAlert aria-hidden className="h-3 w-3" />
      Privileged
    </span>
  );
}

export default function Discovery() {
  const { can } = useAuth();
  const isAdmin = can("admin");
  const [type, setType] = useUrlState("type");
  const [viewParam, setView] = useUrlState("view", "issues");
  const view: View = type && USER_ISSUES.includes(type as IssueType) ? "users" : (viewParam as View);
  const [q, setQ] = useState("");
  const dq = useDebounced(q);
  const [sourceId, setSourceId] = useUrlState("source");
  const [domain, setDomain] = useState("");
  const dDomain = useDebounced(domain);
  const [compStatus, setCompStatus] = useUrlState("status", "not_in_assets");
  const [compClass, setCompClass] = useUrlState("class");
  const [userFilter, setUserFilter] = useUrlState("users", "all");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionErr, setActionErr] = useState<string | null>(null);

  const summary = useApi(directoryApi.summary, [], 60000);
  const sources = useApi(directoryApi.sources, []);
  const issueType = view === "users" ? (USER_ISSUES.includes(type as IssueType) ? type : "") : COMPUTER_ISSUES.includes(type as IssueType) ? type : "";
  const issueFilters = {
    type: issueType as IssueType | "",
    kind: view === "users" ? ("user" as const) : ("machine" as const),
    q: dq,
    domain: dDomain,
    source_id: sourceId,
    limit: PAGE,
    offset,
  };
  const issues = useApi(
    () => (view === "computers" || view === "people" ? Promise.resolve(null) : directoryApi.issues(issueFilters)),
    [view, issueType, dq, dDomain, sourceId, offset],
  );
  const computers = useApi(
    () =>
      view !== "computers"
        ? Promise.resolve(null)
        : directoryApi.computers({ q: dq, domain: dDomain, source_id: sourceId, status: compStatus as ComputerStatus, device_class: compClass || undefined, limit: PAGE, offset }),
    [view, dq, dDomain, sourceId, compStatus, compClass, offset],
  );
  const people = useApi(
    () =>
      view !== "people"
        ? Promise.resolve(null)
        : directoryApi.users({
            q: dq,
            source_id: sourceId,
            privileged: userFilter === "privileged" ? true : undefined,
            enabled: userFilter === "disabled" ? false : undefined,
            limit: PAGE,
            offset,
          }),
    [view, dq, sourceId, userFilter, offset],
  );

  useEffect(() => {
    setOffset(0);
    setSelected(new Set());
  }, [view, issueType, dq, dDomain, sourceId, compStatus, compClass, userFilter]);

  const s = summary.data;
  const counts = issues.data?.counts ?? s?.counts;
  const sourceNames = Object.fromEntries((sources.data ?? []).map((x) => [x.id, x.name]));

  async function add(ids: string[]) {
    if (ids.length === 0) return;
    setBusy(true);
    setActionErr(null);
    try {
      const r = await directoryApi.addToAssets(ids);
      setNotice(
        `${r.created} IT asset${r.created === 1 ? "" : "s"} created (in stock, source: directory)` +
          (r.skipped ? `; ${r.skipped} already in IT assets` : "") +
          ".",
      );
      setSelected(new Set());
      issues.reload();
      computers.reload();
    } catch (e) {
      setActionErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  function toggle(id: string, on: boolean) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });
  }

  const header = (
    <>
      <Breadcrumbs items={[{ label: "IT assets", to: "/it-assets" }, { label: "Discovery" }]} />
      <PageHeader
        title="Discovery"
        subtitle="Computers, devices and users from your directories, matched against agent devices and IT assets. Each physical machine is one row, whichever directories know it. Directory computers become IT assets only when you add them."
        actions={
          s && s.sources > 0 ? (
            <div className="flex flex-wrap items-center gap-2">
              <Link to="/connectors#directories" className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">
                Directory sources
              </Link>
              {(view === "issues" || view === "users") && (
                <a
                  href={directoryApi.issuesExportUrl(issueFilters)}
                  className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line"
                >
                  Export CSV
                </a>
              )}
            </div>
          ) : undefined
        }
      />
    </>
  );

  if (s && s.sources === 0) {
    return (
      <div>
        {header}
        <Card>
          <Empty
            icon={Network}
            title="No directory connected"
            action={
              <Link className="text-sm font-medium text-accent hover:underline" to="/connectors#directories">
                Connect a directory
              </Link>
            }
          >
            Discovery compares the computers and users in Active Directory, Microsoft Entra ID + Intune or Google Workspace with your agents: machines without an
            agent, stale and disabled accounts, non-compliant devices, admins at risk.
          </Empty>
        </Card>
      </div>
    );
  }

  const domains = Array.from(new Set((sources.data ?? []).flatMap((x) => (x.type === "ad" ? [x.config.domain] : []))));
  const sourceOptions = [{ value: "", label: "All" }, ...(sources.data ?? []).map((x) => ({ value: x.id, label: x.name }))];
  const issueRows = issues.data?.items ?? [];
  const compRows = computers.data?.items ?? [];
  const peopleRows = people.data?.items ?? [];
  const addableIssues = issueRows.filter((r) => r.kind === "computer" && r.computer_id && !r.it_asset_id);
  const addableComps = compRows.filter((r) => !r.in_it_assets && !r.missing_since);
  const addable: string[] = view === "computers" ? addableComps.map((r) => r.id) : addableIssues.map((r) => r.computer_id!);
  const allSelected = addable.length > 0 && addable.every((id) => selected.has(id));
  const cov = s?.coverage;
  // KPI tiles: the issue types the configured directory types can produce.
  const relevant = new Set((s?.source_types ?? ["ad"]).flatMap((t) => ISSUES_BY_TYPE[t] ?? []));
  const kpiTypes = ISSUE_TYPES.filter((t) => relevant.has(t) || (counts?.[t] ?? 0) > 0);
  const canSelect = isAdmin && (view === "issues" || view === "computers");

  const tabs: { key: View; label: string }[] = [
    { key: "issues", label: "Computer issues" },
    { key: "computers", label: "Directory computers" },
    { key: "users", label: "User issues" },
    { key: "people", label: "Directory users" },
  ];

  const filters: ReactNode = (
    <div className="mb-3 flex flex-wrap items-center gap-3">
      <div role="tablist" aria-label="Discovery view" className="flex overflow-hidden rounded border border-line">
        {tabs.map((t) => (
          <button
            key={t.key}
            type="button"
            role="tab"
            aria-selected={view === t.key}
            onClick={() => {
              setType("");
              setView(t.key);
            }}
            className={`px-3 py-1 text-sm ${view === t.key ? "bg-accent/15 font-semibold text-accent" : "text-ink-2 hover:bg-surface-2"}`}
          >
            {t.label}
          </button>
        ))}
      </div>
      {view === "computers" ? (
        <>
          <Select label="Show" value={compStatus} onChange={setCompStatus} options={COMPUTER_STATUS} />
          <Select label="Class" value={compClass} onChange={setCompClass} options={CLASS_FILTER_OPTIONS} />
        </>
      ) : view === "people" ? (
        <Select
          label="Show"
          value={userFilter}
          onChange={setUserFilter}
          options={[
            { value: "all", label: "All users" },
            { value: "privileged", label: "Privileged" },
            { value: "disabled", label: "Disabled" },
          ]}
        />
      ) : (
        <Select
          label="Issue"
          value={issueType}
          onChange={setType}
          options={[{ value: "", label: "All" }, ...(view === "users" ? USER_ISSUES : COMPUTER_ISSUES).map((t) => ({ value: t, label: ISSUE_LABEL[t] }))]}
        />
      )}
      {sourceOptions.length > 2 && <Select label="Source" value={sourceId} onChange={setSourceId} options={sourceOptions} />}
      {view !== "people" && domains.length > 0 && (
        <label className="flex items-center gap-1.5 text-xs text-ink-3">
          Domain
          <input
            list="discovery-domains"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="any"
            aria-label="Domain"
            className="w-44 rounded border border-line bg-surface-2 px-2 py-1 text-sm text-ink placeholder:text-ink-3"
          />
          <datalist id="discovery-domains">
            {domains.map((d) => (
              <option key={d} value={d} />
            ))}
          </datalist>
        </label>
      )}
      <Search value={q} onChange={setQ} label={view === "users" || view === "people" ? "Search users" : "Search name, OU, OS"} />
      {canSelect && (
        <div className="ml-auto">
          <Button variant="primary" disabled={busy || selected.size === 0} onClick={() => void add(Array.from(selected))}>
            Add {selected.size > 0 ? selected.size : ""} to IT assets
          </Button>
        </div>
      )}
    </div>
  );

  const selectAllCell = canSelect ? (
    <Check
      label="Select all on this page"
      checked={allSelected}
      disabled={addable.length === 0}
      onChange={(on) => setSelected(on ? new Set([...selected, ...addable]) : new Set([...selected].filter((x) => !addable.includes(x))))}
    />
  ) : null;

  return (
    <div>
      {header}
      <ErrorNote error={summary.error ?? actionErr} />
      {notice && (
        <div role="status" className="mb-4 flex items-start justify-between gap-3 rounded border border-good/60 bg-good/10 px-3 py-2 text-sm text-ink">
          <span>{notice}</span>
          <button className="text-ink-3 hover:text-ink" onClick={() => setNotice(null)} aria-label="Dismiss">
            ✕
          </button>
        </div>
      )}

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
        <Stat
          label="Agent coverage"
          value={cov?.pct != null ? `${cov.pct}%` : "—"}
          sub={cov ? `${cov.managed.toLocaleString()} of ${cov.directory_computers.toLocaleString()} machines` : undefined}
          to="/it-assets/discovery?view=computers&status=unmatched"
          hint="Physical machines the agent belongs on (enabled, Windows / macOS / Linux, not personal), each counted once across directories, with an active agent"
        />
        {kpiTypes.map((t) => (
          <Stat
            key={t}
            label={ISSUE_LABEL[t]}
            value={counts ? (counts[t] ?? 0).toLocaleString() : "—"}
            to={`/it-assets/discovery?type=${t}`}
            hint={ISSUE_HINT[t]}
          />
        ))}
      </div>

      <Card>
        {filters}
        <ErrorNote error={issues.error ?? computers.error ?? people.error} />
        {view === "people" ? (
          <>
            <Table
              head={["User", "Department / domain", "Source", "Last sign-in", "Status", "Admin roles"]}
              loading={people.loading}
              rowCount={peopleRows.length}
              empty={<Empty icon={Network} title="No directory users match">Change the filter, or run a sync from Connectors &amp; scans.</Empty>}
            >
              {peopleRows.map((u: DirUser) => (
                <tr key={u.id}>
                  <td className="px-3 py-2">
                    <div className="font-medium text-ink">{u.display_name || u.user_principal_name || u.sam_account_name}</div>
                    <div className="text-[11px] text-ink-3">{u.user_principal_name || u.mail || u.sam_account_name}</div>
                  </td>
                  <td className="max-w-xs px-3 py-2 text-xs">
                    <div className="text-ink-2">{u.department || "—"}</div>
                    <div className="truncate text-ink-3">{u.domain}</div>
                  </td>
                  <td className="px-3 py-2 text-xs">
                    <SourceBadges refs={[{ id: u.id, source_id: u.source_id, type: u.source_type, kind: u.source_type }]} names={sourceNames} />
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-2">
                    <When at={u.last_logon_at} unknown={u.sign_in_known ? undefined : "Last sign-in is not available (Entra ID P1/P2 and AuditLog.Read.All needed)"} />
                  </td>
                  <td className="px-3 py-2 text-xs">{u.enabled ? <span className="text-ink-2">enabled</span> : <Tag tone="warn">disabled</Tag>}</td>
                  <td className="px-3 py-2 text-xs">
                    {u.privileged ? (
                      <div className="space-y-1">
                        <PrivilegedBadge roles={u.privileged_roles} />
                        <ul className="space-y-0.5">
                          {u.privileged_roles.map((r) =>
                            r.startsWith("Eligible: ") ? (
                              <li key={r} className="text-ink-3">
                                <Tag>eligible (PIM)</Tag> {r.replace("Eligible: ", "").replace(/ \(PIM(, via group)?\)$/, (_m, g) => (g ? " (via group)" : ""))}
                              </li>
                            ) : (
                              <li key={r} className="text-ink-2">
                                <Tag tone="critical">active</Tag> {r}
                              </li>
                            ),
                          )}
                        </ul>
                      </div>
                    ) : (
                      <span className="text-ink-3">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </Table>
            <Pager offset={offset} total={people.data?.total ?? 0} onChange={setOffset} />
          </>
        ) : view === "computers" ? (
          <>
            <Table
              head={[...(selectAllCell ? [{ label: selectAllCell }] : []), "Computer / device", "Sources", "OS", "Last activity", "Agent match", "IT asset"]}
              loading={computers.loading}
              rowCount={compRows.length}
              empty={<Empty icon={Network} title="No directory computers match">Change the filter, or run a sync from Connectors &amp; scans.</Empty>}
            >
              {compRows.map((c: DirComputer) => (
                <tr key={c.id}>
                  {selectAllCell && (
                    <td className="px-3 py-2">
                      <Check label={`Select ${c.name}`} checked={selected.has(c.id)} disabled={c.in_it_assets || !!c.missing_since} onChange={(on) => toggle(c.id, on)} />
                    </td>
                  )}
                  <td className="px-3 py-2">
                    <div className="font-medium text-ink">{c.name}</div>
                    <div className="text-[11px] text-ink-3">{c.dns_hostname || c.serial_number || c.primary_user}</div>
                    {!c.enabled && <Tag>disabled</Tag>} {c.missing_since && <Tag tone="warn">missing since {fmtAgo(c.missing_since)}</Tag>}{" "}
                    {c.compliance && COMPLIANCE[c.compliance.toLowerCase()] && (
                      <Tag tone={COMPLIANCE[c.compliance.toLowerCase()].tone}>{COMPLIANCE[c.compliance.toLowerCase()].label}</Tag>
                    )}{" "}
                    {c.encrypted === false && <Tag tone="warn">not encrypted</Tag>} {!c.agent_expected && <Tag>no agent expected</Tag>}
                  </td>
                  <td className="max-w-xs px-3 py-2 text-xs">
                    <SourceBadges refs={c.sources} names={sourceNames} />
                    {(c.domain || c.ou) && (
                      <div className="mt-0.5 truncate text-ink-3" title={c.ou}>
                        {c.domain} {c.ou}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2 text-xs text-ink-2">
                    {c.os}
                    {c.os_version && <div className="text-ink-3">{c.os_version}</div>}
                    {c.device_class && c.device_class !== "workstation" && (
                      <div className="mt-0.5">
                        <Tag tone={c.device_class === "domain_controller" ? "critical" : "accent"}>{CLASS_LABEL[c.device_class]}</Tag>
                      </div>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-2">
                    <When at={c.last_logon_at} />
                  </td>
                  <td className="px-3 py-2 text-xs">
                    {c.match_status === "matched" && c.device_id ? (
                      <>
                        <Link to={`/devices/${c.device_id}`} className="text-accent hover:underline">
                          {c.device_hostname ?? "device"}
                        </Link>
                        <div className="text-ink-3">
                          by {MATCH_LABEL[c.match_method ?? ""] ?? c.match_method} ({c.match_confidence}%)
                        </div>
                      </>
                    ) : c.match_status === "ambiguous" ? (
                      <Tag tone="warn">ambiguous ({MATCH_LABEL[c.match_method ?? ""] ?? c.match_method})</Tag>
                    ) : (
                      <span className="text-ink-3">no agent</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-xs">
                    <AssetCell assetId={c.it_asset_id} canAdd={isAdmin && !c.missing_since} busy={busy} onAdd={() => void add([c.id])} />
                  </td>
                </tr>
              ))}
            </Table>
            <Pager offset={offset} total={computers.data?.total ?? 0} onChange={setOffset} />
          </>
        ) : (
          <>
            <Table
              head={[
                ...(selectAllCell ? [{ label: selectAllCell }] : []),
                view === "users" ? "User" : "Computer / device",
                "Sources",
                ...(view === "users" ? [] : ["OS"]),
                "Last activity",
                "Issue",
                view === "users" ? "Device" : "Agent device",
                ...(view === "users" ? [] : ["IT asset"]),
              ]}
              loading={issues.loading}
              rowCount={issueRows.length}
              empty={
                <Empty icon={Network} title={issueType ? `No “${ISSUE_LABEL[issueType as IssueType]}” issues` : "No discovery issues"}>
                  {s?.last_sync_at ? "Nothing to review for this filter." : "Issues appear after the first directory sync."}
                </Empty>
              }
            >
              {issueRows.map((r: Issue) => (
                <tr key={r.id}>
                  {selectAllCell && (
                    <td className="px-3 py-2">
                      {r.kind === "computer" && r.computer_id && (
                        <Check label={`Select ${r.name}`} checked={selected.has(r.computer_id)} disabled={!!r.it_asset_id} onChange={(on) => toggle(r.computer_id!, on)} />
                      )}
                    </td>
                  )}
                  <td className="px-3 py-2">
                    <div className="font-medium text-ink">{r.name}</div>
                    <div className="flex flex-wrap items-center gap-1 text-[11px] text-ink-3">
                      {r.kind === "device" ? "agent device" : r.kind === "user" ? "directory user" : "directory computer"}
                      {r.privileged && <PrivilegedBadge />}
                    </div>
                  </td>
                  <td className="max-w-xs px-3 py-2 text-xs">
                    {r.sources.length > 0 ? <SourceBadges refs={r.sources} names={sourceNames} /> : <span className="text-ink-3">agent</span>}
                    {(r.domain || r.ou) && (
                      <div className="mt-0.5 truncate text-ink-3" title={r.ou}>
                        {r.domain} {r.ou}
                      </div>
                    )}
                  </td>
                  {view !== "users" && <td className="px-3 py-2 text-xs text-ink-2">{r.os}</td>}
                  <td className="whitespace-nowrap px-3 py-2 text-xs text-ink-2">
                    <When at={r.last_logon_at} />
                  </td>
                  <td className="max-w-sm px-3 py-2 text-xs">
                    <Tag tone={ISSUE_TONE[r.type]}>{ISSUE_LABEL[r.type]}</Tag>
                    <div className="mt-0.5 text-ink-3">{r.detail}</div>
                  </td>
                  <td className="px-3 py-2 text-xs">
                    {r.device_id ? (
                      <Link to={`/devices/${r.device_id}`} className="text-accent hover:underline">
                        {r.device_hostname ?? "device"}
                      </Link>
                    ) : (
                      <span className="text-ink-3">—</span>
                    )}
                  </td>
                  {view !== "users" && (
                    <td className="px-3 py-2 text-xs">
                      {r.kind === "computer" && r.computer_id ? (
                        <AssetCell assetId={r.it_asset_id} canAdd={isAdmin} busy={busy} onAdd={() => void add([r.computer_id!])} />
                      ) : (
                        <span className="text-ink-3">—</span>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </Table>
            <Pager offset={offset} total={issues.data?.total ?? 0} onChange={setOffset} />
          </>
        )}
      </Card>
    </div>
  );
}
