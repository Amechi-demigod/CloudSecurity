import { Package } from "lucide-react";
import { useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { assetsApi, type AssetBrief, type ImportResult } from "../../assetsApi";
import { useAuth } from "../../auth/context";
import { AssetFormModal, AssetStatusBadge, FormError } from "../../components/assets";
import { Button, Card, Empty, FilterBar, FilterChips, FilterSearch, FilterSelect, Modal, MoreMenu, NameCell, None, PageHeader, Pill, PillRow, Stat, Table, TextCell, type FilterChip } from "../../components/ui";
import { STATUS_LABEL, STATUS_ORDER, TYPE_LABEL, errMsg, fmtDate, fmtMoney, namedByHost, ownerLabel } from "../../lib/assets";
import { fmtAgo } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { rankOf, useSort } from "../../lib/useSort";
import { PAGE_INFO } from "../../lib/pageInfo";

function BriefList({ items, render, empty }: { items: AssetBrief[]; render: (a: AssetBrief) => string; empty: string }) {
  if (items.length === 0) return <p className="text-sm text-ink-3">{empty}</p>;
  return (
    <ul className="space-y-1 text-sm">
      {items.map((a) => (
        <li key={a.id} className="flex justify-between gap-2">
          <Link to={`/it-assets/${a.id}`} className="truncate font-medium hover:text-accent">
            {a.display_name} <span className="text-ink-3">{namedByHost(a) ? a.asset_tag : a.model}</span>
          </Link>
          <span className="shrink-0 text-xs text-ink-2">{render(a)}</span>
        </li>
      ))}
    </ul>
  );
}

function ImportDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function close() {
    setFile(null);
    setResult(null);
    setError(null);
    onClose();
  }

  async function run(dryRun: boolean) {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const r = await assetsApi.importCsv(file, dryRun);
      setResult(r);
      if (!dryRun && r.errors.length === 0) onDone();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={close} title="Import assets from CSV">
      <div className="space-y-3 text-sm">
        <p className="text-ink-2">
          UTF-8 CSV with a header row. <code>asset_tag</code> is required; rows are matched by tag (new tags are created, existing ones
          updated). Empty cells leave existing values unchanged. Use an export as a template; custom fields are <code>custom.&lt;key&gt;</code>{" "}
          columns. The file is imported only if every row is valid.
        </p>
        <input
          ref={fileRef}
          type="file"
          accept=".csv,text/csv"
          aria-label="CSV file"
          onChange={(e) => {
            setFile(e.target.files?.[0] ?? null);
            setResult(null);
          }}
          className="block w-full text-sm text-ink-2 file:mr-3 file:rounded file:border file:border-line file:bg-surface-2 file:px-3 file:py-1 file:text-ink"
        />
        <FormError error={error} />
        {result && (
          <div className={`rounded border px-3 py-2 ${result.errors.length ? "border-sev-critical/60 bg-sev-critical/10" : "border-good/60 bg-good/10"}`} role="status">
            {result.errors.length > 0 ? (
              <>
                <p className="font-medium">{result.message ?? `${result.errors.length} row(s) have errors; nothing was imported.`}</p>
                <ul className="mt-1 max-h-48 list-inside list-disc overflow-y-auto text-xs">
                  {result.errors.map((e) => (
                    <li key={`${e.row}-${e.asset_tag}`}>
                      Row {e.row}
                      {e.asset_tag && ` (${e.asset_tag})`}: {e.error}
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <p>
                {result.dry_run ? "Check passed: would create" : "Imported: created"} {result.created}, updated {result.updated}, unchanged {result.unchanged} of{" "}
                {result.rows} row(s).
              </p>
            )}
          </div>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={close}>Close</Button>
          <Button onClick={() => run(true)} disabled={!file || busy}>
            Check file
          </Button>
          <Button variant="primary" onClick={() => run(false)} disabled={!file || busy}>
            {busy ? "Working…" : "Import"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

export default function Assets() {
  const navigate = useNavigate();
  const { can } = useAuth();
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("active");
  const [type, setType] = useState("");
  const [location, setLocation] = useState("");
  const [agent, setAgent] = useState("");
  const [flag, setFlag] = useState("");
  const [adding, setAdding] = useState(false);
  const [importing, setImporting] = useState(false);
  const filters = { q: q.trim() || undefined, status, type, location, agent, flag };
  const list = useApi(() => assetsApi.list(filters), [q, status, type, location, agent, flag], 60000);
  const summary = useApi(assetsApi.summary, [], 60000);
  const sorted = useSort(
    list.data,
    {
      name: (a) => a.display_name.toLowerCase(),
      type: (a) => TYPE_LABEL[a.asset_type] ?? a.asset_type,
      status: (a) => rankOf(STATUS_ORDER)(a.status),
      owner: (a) => ownerLabel(a).toLowerCase(),
      site: (a) => a.location,
      warranty: (a) => (a.warranty_end ? Date.parse(a.warranty_end) : null),
      agent: (a) => (a.device_id ? 1 : 0),
    },
    { key: "name", dir: "asc" },
  );
  const clearAll = () => {
    setQ("");
    setStatus("active");
    setType("");
    setLocation("");
    setAgent("");
    setFlag("");
  };
  const chips: FilterChip[] = [
    q.trim() && { label: "Search", value: q, onRemove: () => setQ("") },
    type && { label: "Type", value: TYPE_LABEL[type] ?? type, onRemove: () => setType("") },
    status !== "active" && { label: "Status", value: STATUS_LABEL[status as keyof typeof STATUS_LABEL] ?? (status || "All"), onRemove: () => setStatus("active") },
    location && { label: "Site", value: location, onRemove: () => setLocation("") },
    agent && { label: "Agent", value: agent === "yes" ? "Enrolled" : "No agent", onRemove: () => setAgent("") },
    flag && { label: "Flag", value: flag.replace(/_/g, " "), onRemove: () => setFlag("") },
  ].filter((c): c is FilterChip => !!c);
  const { data: settings } = useApi(assetsApi.settings, []);
  const s = summary.data;
  const reload = () => {
    list.reload();
    summary.reload();
  };

  return (
    <div>
      <PageHeader
        title="Hardware register"
        info={PAGE_INFO.hardware}
        subtitle="Everything your company owns: who has it and when the warranty ends."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <MoreMenu
              items={[
                { label: "Discovery", to: "/it-assets/discovery" },
                { label: "Offboarding", to: "/it-assets/offboarding" },
                { label: "Settings", to: "/it-assets/settings", hidden: !can("admin") },
                { label: "Import CSV", onClick: () => setImporting(true), hidden: !can("analyst") },
              ]}
            />
            <a href={assetsApi.exportUrl(filters)} className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">
              Export CSV
            </a>
            {can("analyst") && (
              <Button variant="primary" onClick={() => setAdding(true)}>
                Add hardware
              </Button>
            )}
          </div>
        }
      />
      {s && (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            <Stat label="Assets in use" selected={status === "active" && !flag} onSelect={() => { setStatus("active"); setFlag(""); }} value={s.active} sub={`${s.total} total · ${s.with_agent} with agent`} />
            <Stat label="Assigned" selected={status === "assigned" && !flag} onSelect={() => { setStatus("assigned"); setFlag(""); }} value={s.by_status.assigned} sub={`${s.by_status.in_stock} in stock · ${s.by_status.in_repair} in repair`} />
            <Stat
              label="Total value"
              value={Object.keys(s.value_by_currency).length ? fmtMoney(s.value_by_currency[s.default_currency] ?? 0, s.default_currency) : "—"}
              sub={Object.entries(s.value_by_currency).filter(([c]) => c !== s.default_currency).map(([c, v]) => fmtMoney(v, c)).join(" · ") || "excl. disposed, lost, stolen"}
            />
            <Stat label="Overdue retrievals" selected={flag === "retrieval_overdue"} onSelect={() => { setStatus(""); setFlag(flag === "retrieval_overdue" ? "" : "retrieval_overdue"); }} value={s.retrieval_overdue} sub={`${s.by_status.retrieval_pending} pending`} />
            <Stat label="Warranty expiring" selected={flag === "warranty_expiring"} onSelect={() => { setStatus("active"); setFlag(flag === "warranty_expiring" ? "" : "warranty_expiring"); }} value={s.warranty_expiring} sub={`within ${s.warranty_warning_days} days`} />
            <Stat label="Idle devices" selected={flag === "idle"} onSelect={() => { setStatus("active"); setFlag(flag === "idle" ? "" : "idle"); }} value={s.idle} sub={`agent not seen ${s.idle_days}+ days`} />
          </div>
          <div className="mb-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
            <Card title="By status">
              <ul className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
                {STATUS_ORDER.map((st) => (
                  <li key={st} className="flex justify-between">
                    <button className="text-left text-ink-2 hover:text-accent" onClick={() => setStatus(st)}>
                      {STATUS_LABEL[st]}
                    </button>
                    <span className="font-medium">{s.by_status[st]}</span>
                  </li>
                ))}
              </ul>
              <p className="mt-3 text-xs text-ink-3">
                By type:{" "}
                {Object.entries(s.by_type)
                  .map(([t, n]) => `${n} ${TYPE_LABEL[t] ?? t}`)
                  .join(" · ") || "none"}
              </p>
            </Card>
            <Card title="Overdue retrievals" actions={s.retrieval_overdue > 0 && <button className="text-xs text-accent" onClick={() => { setStatus(""); setFlag("retrieval_overdue"); }}>Show all</button>}>
              <BriefList items={s.retrieval_overdue_assets} empty="Nothing overdue." render={(a) => `${ownerLabel(a) || "no owner"} · due ${fmtDate(a.retrieval_due)}`} />
            </Card>
            <Card title="Warranty expiring soon" actions={s.warranty_expiring > 0 && <button className="text-xs text-accent" onClick={() => { setStatus("active"); setFlag("warranty_expiring"); }}>Show all</button>}>
              <BriefList items={s.warranty_expiring_assets} empty={`No warranty ends in the next ${s.warranty_warning_days} days.`} render={(a) => fmtDate(a.warranty_end)} />
            </Card>
          </div>
        </>
      )}
      <Card>
        <FilterBar
          count={list.data ? `${list.data.length} ${list.data.length === 1 ? "asset" : "assets"}` : undefined}
          moreActive={[agent, flag].filter(Boolean).length}
          more={
            <>
              <FilterSelect label="Agent" value={agent} onChange={setAgent} options={[{ value: "", label: "Any" }, { value: "yes", label: "Enrolled" }, { value: "no", label: "No agent" }]} />
              <FilterSelect label="Flag" value={flag} onChange={setFlag} options={[{ value: "", label: "None" }, { value: "retrieval_overdue", label: "Retrieval overdue" }, { value: "warranty_expiring", label: "Warranty expiring" }, { value: "idle", label: "Idle device" }]} />
            </>
          }
        >
          <FilterSearch value={q} onChange={setQ} placeholder="Name, tag, serial, owner" label="Search hardware" />
          <FilterSelect label="Type" value={type} onChange={setType} options={[{ value: "", label: "All" }, ...Object.entries(TYPE_LABEL).map(([value, label]) => ({ value, label }))]} />
          <FilterSelect label="Status" value={status} onChange={setStatus} options={[{ value: "active", label: "In use" }, { value: "", label: "All" }, ...STATUS_ORDER.map((v) => ({ value: v, label: STATUS_LABEL[v] }))]} />
          <FilterSelect label="Site" value={location} onChange={setLocation} options={[{ value: "", label: "All" }, ...(settings?.locations ?? []).map((l) => ({ value: l, label: l }))]} />
        </FilterBar>
        <FilterChips chips={chips} onClearAll={clearAll} />
          <Table
            tableId="assets"
            head={[
              { label: "Asset", sort: "name", w: 260 },
              { label: "Type", sort: "type", w: 110 },
              { label: "Status", sort: "status", w: 150 },
              { label: "Owner", sort: "owner", w: 190 },
              { label: "Site", sort: "site", w: 130 },
              { label: "Warranty", sort: "warranty", w: 130 },
              { label: "Agent", sort: "agent", w: 130 },
            ]}
            sort={sorted.sort}
            onSort={sorted.onSort}
            loading={list.loading}
            rowCount={list.data?.length ?? 0}
            noun="assets"
            pageSize={50}
            filtered={chips.length > 0}
            onClearFilters={clearAll}
            error={list.data ? null : list.error}
            onRetry={list.reload}
            empty={
              <Empty icon={Package} title="No assets match">
                Clear a filter, or add assets by hand or by CSV import. Devices with the agent appear here automatically.
              </Empty>
            }
          >
            {sorted.rows.map((a) => (
              <tr key={a.id} className="cursor-pointer hover:bg-surface-2" onClick={() => navigate(`/it-assets/${a.id}`)}>
                <td className="px-3 py-2">
                  <NameCell
                    name={a.display_name}
                    sub={[a.manufacturer, a.model].filter(Boolean).join(" ") + (a.serial_number ? ` · ${a.serial_number}` : "") || (namedByHost(a) ? a.asset_tag : "")}
                    onOpen={() => navigate(`/it-assets/${a.id}`)}
                  />
                </td>
                <td className="px-3 py-2">
                  <TextCell>{TYPE_LABEL[a.asset_type] ?? a.asset_type}</TextCell>
                </td>
                <td className="px-3 py-2">
                  <PillRow>
                    <AssetStatusBadge status={a.status} />
                    {a.retrieval_overdue && <Pill tone="high" title={`Retrieval due ${fmtDate(a.retrieval_due)}`}>Overdue</Pill>}
                  </PillRow>
                </td>
                <td className="px-3 py-2">
                  {ownerLabel(a) ? <NameCell name={ownerLabel(a)} sub={a.assignee_department || a.owner_directory?.department} /> : <None />}
                </td>
                <td className="px-3 py-2">{a.location ? <TextCell>{a.location}</TextCell> : <None />}</td>
                <td className="px-3 py-2">
                  {a.warranty_end ? <TextCell title={fmtDate(a.warranty_end)}><span className={a.warranty_expiring ? "text-sev-high" : ""}>{fmtDate(a.warranty_end)}</span></TextCell> : <None />}
                </td>
                <td className="px-3 py-2">
                  {a.device_id ? (
                    <PillRow>
                      <Pill tone={a.idle ? "high" : "good"} title={`${a.device_hostname ?? ""} · ${a.device_last_seen_at ? fmtAgo(a.device_last_seen_at) : "never seen"}`}>
                        {a.idle ? "Idle" : "Enrolled"}
                      </Pill>
                    </PillRow>
                  ) : (
                    <None />
                  )}
                </td>
              </tr>
            ))}
          </Table>
      </Card>
      {adding && (
        <AssetFormModal open asset={null} settings={settings} onClose={() => setAdding(false)} onSaved={(a) => navigate(`/it-assets/${a.id}`)} />
      )}
      <ImportDialog open={importing} onClose={() => setImporting(false)} onDone={reload} />
    </div>
  );
}
