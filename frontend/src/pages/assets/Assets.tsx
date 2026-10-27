import { Package } from "lucide-react";
import { useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { assetsApi, type AssetBrief, type ImportResult } from "../../assetsApi";
import { useAuth } from "../../auth/context";
import { AssetFormModal, AssetStatusBadge, FormError } from "../../components/assets";
import { Button, Card, Empty, ErrorNote, Modal, PageHeader, Select, Stat, Table, Tag } from "../../components/ui";
import { STATUS_LABEL, STATUS_ORDER, TYPE_LABEL, errMsg, fmtDate, fmtMoney } from "../../lib/assets";
import { fmtAgo } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { useSort } from "../../lib/useSort";

function BriefList({ items, render, empty }: { items: AssetBrief[]; render: (a: AssetBrief) => string; empty: string }) {
  if (items.length === 0) return <p className="text-sm text-ink-3">{empty}</p>;
  return (
    <ul className="space-y-1 text-sm">
      {items.map((a) => (
        <li key={a.id} className="flex justify-between gap-2">
          <Link to={`/it-assets/${a.id}`} className="truncate font-medium hover:text-accent">
            {a.asset_tag} <span className="text-ink-3">{a.device_hostname ?? a.model}</span>
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
      tag: (a) => a.asset_tag,
      type: (a) => TYPE_LABEL[a.asset_type] ?? a.asset_type,
      status: (a) => STATUS_LABEL[a.status] ?? a.status,
      owner: (a) => a.assignee_name || a.assignee_email,
      site: (a) => a.location,
      warranty: (a) => (a.warranty_end ? Date.parse(a.warranty_end) : null),
    },
    { key: "tag", dir: "asc" },
  );
  const { data: settings } = useApi(assetsApi.settings, []);
  const s = summary.data;
  const reload = () => {
    list.reload();
    summary.reload();
  };

  return (
    <div>
      <PageHeader
        title="IT assets"
        subtitle="Hardware lifecycle: who has what, custody history, leavers' retrievals, warranties and disposal. Agent devices get a record automatically."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Link to="/it-assets/offboarding" className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">
              Offboarding
            </Link>
            {can("admin") && (
              <Link to="/it-assets/settings" className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">
                Settings
              </Link>
            )}
            <a href={assetsApi.exportUrl(filters)} className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">
              Export CSV
            </a>
            {can("analyst") && (
              <>
                <Button onClick={() => setImporting(true)}>Import CSV</Button>
                <Button variant="primary" onClick={() => setAdding(true)}>
                  Add asset
                </Button>
              </>
            )}
          </div>
        }
      />
      {s && (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            <Stat label="Assets in use" value={s.active} sub={`${s.total} total · ${s.with_agent} with agent`} />
            <Stat label="Assigned" value={s.by_status.assigned} sub={`${s.by_status.in_stock} in stock · ${s.by_status.in_repair} in repair`} />
            <Stat
              label="Total value"
              value={Object.keys(s.value_by_currency).length ? fmtMoney(s.value_by_currency[s.default_currency] ?? 0, s.default_currency) : "—"}
              sub={Object.entries(s.value_by_currency).filter(([c]) => c !== s.default_currency).map(([c, v]) => fmtMoney(v, c)).join(" · ") || "excl. disposed, lost, stolen"}
            />
            <Stat label="Overdue retrievals" value={s.retrieval_overdue} sub={`${s.by_status.retrieval_pending} pending`} />
            <Stat label="Warranty expiring" value={s.warranty_expiring} sub={`within ${s.warranty_warning_days} days`} />
            <Stat label="Idle devices" value={s.idle} sub={`agent not seen ${s.idle_days}+ days`} />
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
              <BriefList items={s.retrieval_overdue_assets} empty="Nothing overdue." render={(a) => `${a.assignee_name || a.assignee_email} · due ${fmtDate(a.retrieval_due)}`} />
            </Card>
            <Card title="Warranty expiring soon" actions={s.warranty_expiring > 0 && <button className="text-xs text-accent" onClick={() => { setStatus("active"); setFlag("warranty_expiring"); }}>Show all</button>}>
              <BriefList items={s.warranty_expiring_assets} empty={`No warranty ends in the next ${s.warranty_warning_days} days.`} render={(a) => fmtDate(a.warranty_end)} />
            </Card>
          </div>
        </>
      )}
      <Card>
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-1.5 text-xs text-ink-3">
            Search
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="tag, serial, model, owner, hostname"
              className="w-64 rounded border border-line bg-surface-2 px-2 py-1 text-sm text-ink"
            />
          </label>
          <Select
            label="Status"
            value={status}
            onChange={setStatus}
            options={[{ value: "active", label: "In use (not disposed/lost)" }, { value: "", label: "All" }, ...STATUS_ORDER.map((v) => ({ value: v, label: STATUS_LABEL[v] }))]}
          />
          <Select label="Type" value={type} onChange={setType} options={[{ value: "", label: "All" }, ...Object.entries(TYPE_LABEL).map(([value, label]) => ({ value, label }))]} />
          <Select label="Site" value={location} onChange={setLocation} options={[{ value: "", label: "All" }, ...(settings?.locations ?? []).map((l) => ({ value: l, label: l }))]} />
          <Select label="Agent" value={agent} onChange={setAgent} options={[{ value: "", label: "Any" }, { value: "yes", label: "Enrolled" }, { value: "no", label: "No agent" }]} />
          <Select
            label="Flag"
            value={flag}
            onChange={setFlag}
            options={[
              { value: "", label: "None" },
              { value: "retrieval_overdue", label: "Retrieval overdue" },
              { value: "warranty_expiring", label: "Warranty expiring" },
              { value: "idle", label: "Idle device" },
            ]}
          />
        </div>
        <ErrorNote error={list.error} />
          <Table
            head={[
              { label: "Asset", sort: "tag" },
              { label: "Type", sort: "type" },
              { label: "Status", sort: "status" },
              { label: "Owner", sort: "owner" },
              { label: "Site", sort: "site" },
              { label: "Warranty", sort: "warranty" },
              "Agent",
            ]}
            sort={sorted.sort}
            onSort={sorted.onSort}
            loading={list.loading}
            rowCount={list.data?.length ?? 0}
            empty={
              <Empty icon={Package} title="No assets match">
                Clear a filter, or add assets by hand or by CSV import. Devices with the agent appear here automatically.
              </Empty>
            }
          >
            {sorted.rows.map((a) => (
              <tr key={a.id} className="cursor-pointer hover:bg-surface-2" onClick={() => navigate(`/it-assets/${a.id}`)}>
                <td className="px-3 py-2">
                  <Link to={`/it-assets/${a.id}`} className="font-medium hover:text-accent" onClick={(e) => e.stopPropagation()}>
                    {a.asset_tag}
                  </Link>
                  <div className="text-[11px] text-ink-3">
                    {[a.manufacturer, a.model].filter(Boolean).join(" ")} {a.serial_number && `· ${a.serial_number}`}
                  </div>
                </td>
                <td className="px-3 py-2 text-ink-2">{TYPE_LABEL[a.asset_type] ?? a.asset_type}</td>
                <td className="px-3 py-2">
                  <AssetStatusBadge status={a.status} />
                  {a.retrieval_overdue && (
                    <div className="mt-0.5">
                      <Tag tone="warn">overdue {fmtDate(a.retrieval_due)}</Tag>
                    </div>
                  )}
                </td>
                <td className="px-3 py-2 text-xs">
                  {a.assignee_email ? (
                    <>
                      <div className="text-ink">{a.assignee_name || a.assignee_email}</div>
                      <div className="text-ink-3">{a.assignee_department}</div>
                    </>
                  ) : (
                    <span className="text-ink-3">—</span>
                  )}
                </td>
                <td className="px-3 py-2 text-xs text-ink-2">{a.location || "—"}</td>
                <td className="px-3 py-2 text-xs">
                  <span className={a.warranty_expiring ? "text-sev-high" : "text-ink-2"}>{fmtDate(a.warranty_end)}</span>
                </td>
                <td className="px-3 py-2 text-xs">
                  {a.device_id ? (
                    <>
                      <span className="text-ink-2">{a.device_hostname}</span>
                      <div className={a.idle ? "text-sev-high" : "text-ink-3"}>
                        {a.device_last_seen_at ? fmtAgo(a.device_last_seen_at) : "never seen"}
                        {a.idle && " · idle"}
                      </div>
                    </>
                  ) : (
                    <span className="text-ink-3">—</span>
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
