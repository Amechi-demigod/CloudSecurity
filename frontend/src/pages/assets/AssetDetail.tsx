import { useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { assetsApi, type AssetEvent, type ItAsset } from "../../assetsApi";
import { useAuth } from "../../auth/context";
import { AssetFormModal, AssetStatusBadge, FormError, SelectField, TextArea } from "../../components/assets";
import { Button, Card, Empty, ErrorNote, Field, Modal, PageHeader, Tag } from "../../components/ui";
import { DISPOSAL_LABEL, EVENT_LABEL, STATUS_LABEL, TYPE_LABEL, errMsg, fmtDate, fmtMoney, todayIso } from "../../lib/assets";
import { fmtBytes } from "../../lib/devices";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";

type Action = "assign" | "return" | "status" | "dispose" | "delete" | null;

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex gap-3 py-1 text-sm">
      <dt className="w-40 shrink-0 text-ink-3">{label}</dt>
      <dd className="min-w-0 break-words text-ink">{children || "—"}</dd>
    </div>
  );
}

function ActionDialog({ asset, action, onClose, onDone }: { asset: ItAsset; action: Action; onClose: () => void; onDone: (a: ItAsset | null) => void }) {
  const [f, setF] = useState<Record<string, string>>({
    assignee_email: "",
    assignee_name: "",
    assignee_department: "",
    notes: "",
    status: "in_repair",
    retrieval_due: "",
    return_status: "",
    location: asset.location,
    method: "recycled",
    disposal_date: todayIso(),
    vendor: "",
    reason: "",
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: string) => (v: string) => setF((x) => ({ ...x, [k]: v }));
  const inp = (k: string) => ({ value: f[k], onChange: (e: { target: { value: string } }) => set(k)(e.target.value) });

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      let r: ItAsset | null = null;
      if (action === "assign")
        r = await assetsApi.assign(asset.id, { assignee_email: f.assignee_email.trim(), assignee_name: f.assignee_name.trim(), assignee_department: f.assignee_department.trim(), notes: f.notes });
      if (action === "return") r = await assetsApi.returnAsset(asset.id, { notes: f.notes, status: f.return_status || undefined, location: f.location });
      if (action === "status") r = await assetsApi.setStatus(asset.id, { status: f.status, notes: f.notes, retrieval_due: f.retrieval_due || undefined });
      if (action === "dispose") r = await assetsApi.dispose(asset.id, { method: f.method, disposal_date: f.disposal_date, vendor: f.vendor.trim(), notes: f.notes });
      if (action === "delete") await assetsApi.remove(asset.id, f.reason.trim());
      onDone(r);
      onClose();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  const titles: Record<string, string> = {
    assign: asset.assignee_email ? "Reassign" : "Assign",
    return: "Record return",
    status: "Change status",
    dispose: "Dispose of asset",
    delete: "Delete asset record",
  };
  if (!action) return null;
  return (
    <Modal open onClose={onClose} title={`${titles[action]}: ${asset.asset_tag}`}>
      <form className="space-y-3" onSubmit={submit}>
        <FormError error={error} />
        {action === "assign" && (
          <>
            <Field label="Owner email" id="ad-email" type="email" required maxLength={320} {...inp("assignee_email")} />
            <Field label="Owner name" id="ad-name" maxLength={128} {...inp("assignee_name")} />
            <Field label="Department" id="ad-dept" maxLength={128} {...inp("assignee_department")} />
          </>
        )}
        {action === "return" && (
          <>
            <SelectField label="Goes to" id="ad-rs" value={f.return_status} onChange={set("return_status")}>
              <option value="">{asset.status === "retrieval_pending" ? "Retrieved (default)" : "In stock (default)"}</option>
              <option value="in_stock">In stock</option>
              <option value="retrieved">Retrieved (awaiting check / wipe)</option>
              <option value="in_repair">In repair</option>
            </SelectField>
            <Field label="Location / site" id="ad-loc" maxLength={128} {...inp("location")} />
          </>
        )}
        {action === "status" && (
          <>
            <SelectField label="New status" id="ad-st" value={f.status} onChange={set("status")}>
              {(["in_stock", "in_repair", "retrieval_pending", "retrieved", "lost", "stolen"] as const)
                .filter((s) => s !== asset.status || s === "retrieval_pending")
                .map((s) => (
                  <option key={s} value={s}>
                    {STATUS_LABEL[s]}
                  </option>
                ))}
            </SelectField>
            {f.status === "retrieval_pending" && <Field label="Retrieval due" id="ad-due" type="date" {...inp("retrieval_due")} hint="Default: today + the configured number of days." />}
            {(f.status === "lost" || f.status === "stolen") && <p className="text-xs text-sev-high">Raises a high-severity notification (source asset_lifecycle).</p>}
          </>
        )}
        {action === "dispose" && (
          <>
            <SelectField label="Method" id="ad-m" value={f.method} onChange={set("method")}>
              {Object.entries(DISPOSAL_LABEL).map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
            </SelectField>
            <Field label="Disposal date" id="ad-dd" type="date" required max={todayIso()} {...inp("disposal_date")} />
            <Field label="Vendor" id="ad-vendor" maxLength={128} {...inp("vendor")} />
            <p className="text-xs text-ink-3">Upload the wipe / destruction certificate under Certificates afterwards. Disposal is final.</p>
          </>
        )}
        {action === "delete" ? (
          <>
            <p className="text-sm text-ink-2">Removes the record, its custody history and certificates. For real assets prefer Dispose, which keeps the history.</p>
            <Field label="Reason (audit log)" id="ad-reason" required minLength={3} maxLength={500} {...inp("reason")} />
          </>
        ) : (
          <TextArea label="Notes (custody timeline)" id="ad-notes" value={f.notes} onChange={set("notes")} maxLength={action === "dispose" ? 4000 : 1000} />
        )}
        <div className="flex justify-end gap-2 pt-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant={action === "delete" || action === "dispose" ? "danger" : "primary"} disabled={busy || (action === "delete" && f.reason.trim().length < 3)}>
            {busy ? "Saving…" : titles[action]}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function Timeline({ events }: { events: AssetEvent[] | null }) {
  if (!events) return <Empty>Loading…</Empty>;
  if (events.length === 0) return <Empty>No history.</Empty>;
  return (
    <ol className="relative space-y-4 border-l border-line pl-5">
      {events.map((e) => {
        const changes = e.detail.changes as Record<string, [unknown, unknown]> | undefined;
        return (
          <li key={e.id} className="relative">
            <span className="absolute -left-[25px] top-1.5 h-2.5 w-2.5 rounded-full border border-accent bg-surface-1" aria-hidden />
            <div className="flex flex-wrap items-baseline gap-x-2 text-sm">
              <span className="font-medium">{EVENT_LABEL[e.event_type] ?? e.event_type}</span>
              {e.from_status !== e.to_status && e.to_status && (
                <span className="text-xs text-ink-2">
                  {e.from_status ? `${STATUS_LABEL[e.from_status as keyof typeof STATUS_LABEL] ?? e.from_status} → ` : ""}
                  {STATUS_LABEL[e.to_status as keyof typeof STATUS_LABEL] ?? e.to_status}
                </span>
              )}
              <span className="text-xs text-ink-3" title={fmtTime(e.at)}>
                {fmtTime(e.at)} · {e.actor_email ?? "system"}
              </span>
            </div>
            {e.from_assignee !== e.to_assignee && (e.from_assignee || e.to_assignee) && (
              <div className="text-xs text-ink-2">
                Owner: {e.from_assignee ?? "none"} → {e.to_assignee ?? "none"}
              </div>
            )}
            {changes && (
              <div className="text-xs text-ink-3">
                {Object.entries(changes)
                  .map(([k, [a, b]]) => `${k.replaceAll("_", " ")}: ${typeof a === "object" ? JSON.stringify(a) : a || "—"} → ${typeof b === "object" ? JSON.stringify(b) : b || "—"}`)
                  .join("; ")}
              </div>
            )}
            {e.notes && <p className="mt-0.5 whitespace-pre-wrap text-sm text-ink-2">{e.notes}</p>}
          </li>
        );
      })}
    </ol>
  );
}

function Certificates({ asset, canUpload, canDownload, canDelete, onChange }: { asset: ItAsset; canUpload: boolean; canDownload: boolean; canDelete: boolean; onChange: () => void }) {
  const { data, error, reload } = useApi(() => assetsApi.certificates(asset.id), [asset.id]);
  const [busy, setBusy] = useState(false);
  const [upErr, setUpErr] = useState<string | null>(null);
  async function upload(file: File | undefined) {
    if (!file) return;
    setBusy(true);
    setUpErr(null);
    try {
      await assetsApi.uploadCertificate(asset.id, file);
      reload();
      onChange();
    } catch (e) {
      setUpErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }
  async function remove(id: string) {
    const reason = window.prompt("Reason for deleting this certificate (audit log)?");
    if (!reason || reason.trim().length < 3) return;
    try {
      await assetsApi.deleteCertificate(asset.id, id, reason.trim());
      reload();
      onChange();
    } catch (e) {
      setUpErr(errMsg(e));
    }
  }
  return (
    <Card
      title="Wipe / destruction certificates"
      actions={
        canUpload && (
          <label className={`cursor-pointer rounded border border-line bg-surface-2 px-3 py-1 text-sm hover:bg-line ${busy ? "opacity-50" : ""}`}>
            {busy ? "Uploading…" : "Upload"}
            <input type="file" className="sr-only" accept="application/pdf,image/png,image/jpeg" disabled={busy} onChange={(e) => upload(e.target.files?.[0])} />
          </label>
        )
      }
    >
      <ErrorNote error={error ?? upErr} />
      <p className="mb-2 text-xs text-ink-3">PDF, PNG or JPEG, up to 5 MB by default. Stored in the database (included in backups).</p>
      {data && data.length === 0 ? (
        <Empty>No certificates.</Empty>
      ) : (
        <ul className="divide-y divide-line/60 text-sm">
          {(data ?? []).map((c) => (
            <li key={c.id} className="flex items-center justify-between gap-2 py-1.5">
              <div className="min-w-0">
                {canDownload ? (
                  <a href={assetsApi.certificateUrl(asset.id, c.id)} className="font-medium hover:text-accent">
                    {c.filename}
                  </a>
                ) : (
                  <span className="font-medium">{c.filename}</span>
                )}
                <div className="truncate text-[11px] text-ink-3" title={c.sha256}>
                  {fmtBytes(c.size_bytes)} · {c.uploaded_by} · {fmtTime(c.uploaded_at)} · sha256 {c.sha256.slice(0, 12)}…
                </div>
              </div>
              {canDelete && (
                <button className="text-xs text-sev-critical hover:underline" onClick={() => remove(c.id)}>
                  Delete
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export default function AssetDetail() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const { can } = useAuth();
  const { data: asset, error, reload } = useApi(() => assetsApi.get(id), [id]);
  const ev = useApi(() => assetsApi.events(id), [id]);
  const { data: settings } = useApi(assetsApi.settings, []);
  const [action, setAction] = useState<Action>(null);
  const [editing, setEditing] = useState(false);
  const refresh = () => {
    reload();
    ev.reload();
  };

  if (!asset) {
    return (
      <div>
        <ErrorNote error={error} />
        {!error && <Empty>Loading…</Empty>}
      </div>
    );
  }
  const disposed = asset.status === "disposed";
  const analyst = can("analyst");
  const labelFor = (k: string) => settings?.custom_fields.find((f) => f.key === k)?.label ?? k;

  return (
    <div>
      <div className="mb-1 text-xs text-ink-3">
        <Link to="/it-assets" className="hover:text-ink">
          IT assets
        </Link>{" "}
        / {asset.asset_tag}
      </div>
      <PageHeader
        title={asset.asset_tag}
        subtitle={`${TYPE_LABEL[asset.asset_type] ?? asset.asset_type} · ${[asset.manufacturer, asset.model].filter(Boolean).join(" ") || "no model"}${asset.serial_number ? ` · S/N ${asset.serial_number}` : ""}`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <AssetStatusBadge status={asset.status} />
            {asset.retrieval_overdue && <Tag tone="warn">Retrieval overdue</Tag>}
            {asset.warranty_expiring && <Tag tone="warn">Warranty expiring</Tag>}
            {asset.idle && <Tag tone="warn">Idle device</Tag>}
          </div>
        }
      />
      {analyst && (
        <div className="mb-4 flex flex-wrap gap-2" role="toolbar" aria-label="Asset actions">
          {!disposed && <Button onClick={() => setEditing(true)}>Edit</Button>}
          {["in_stock", "assigned", "in_repair", "retrieved"].includes(asset.status) && (
            <Button variant="primary" onClick={() => setAction("assign")}>
              {asset.assignee_email ? "Reassign" : "Assign"}
            </Button>
          )}
          {["assigned", "retrieval_pending", "lost", "stolen"].includes(asset.status) || (asset.status === "in_repair" && asset.assignee_email) ? (
            <Button onClick={() => setAction("return")}>Record return</Button>
          ) : null}
          {!disposed && <Button onClick={() => setAction("status")}>Change status</Button>}
          {!disposed && !["assigned", "retrieval_pending"].includes(asset.status) && (
            <Button variant="danger" onClick={() => setAction("dispose")}>
              Dispose
            </Button>
          )}
          {can("admin") && (
            <Button variant="danger" onClick={() => setAction("delete")}>
              Delete record
            </Button>
          )}
        </div>
      )}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title="Asset">
          <dl>
            <Row label="Status">{STATUS_LABEL[asset.status]}</Row>
            <Row label="Owner">
              {asset.assignee_email && (
                <>
                  {asset.assignee_name || asset.assignee_email} <span className="text-ink-3">{asset.assignee_name && asset.assignee_email}</span>
                  {asset.assigned_at && <div className="text-xs text-ink-3">since {fmtTime(asset.assigned_at)}</div>}
                </>
              )}
            </Row>
            <Row label="Department">{asset.assignee_department}</Row>
            <Row label="Location / site">{asset.location}</Row>
            {asset.status === "retrieval_pending" && (
              <Row label="Retrieval due">
                {fmtDate(asset.retrieval_due)}{" "}
                {asset.offboarding_id && (
                  <Link className="text-xs text-accent" to={`/it-assets/offboarding?id=${asset.offboarding_id}`}>
                    offboarding
                  </Link>
                )}
              </Row>
            )}
            <Row label="Source">{asset.source === "agent" ? "Agent enrollment" : asset.source === "import" ? "CSV import" : "Added manually"}</Row>
            {Object.entries(asset.custom_fields).map(([k, v]) => (
              <Row key={k} label={labelFor(k)}>
                {v}
              </Row>
            ))}
            {asset.notes && (
              <Row label="Notes">
                <span className="whitespace-pre-wrap">{asset.notes}</span>
              </Row>
            )}
          </dl>
        </Card>
        <Card title="Purchase & warranty">
          <dl>
            <Row label="Purchase date">{asset.purchase_date && fmtDate(asset.purchase_date)}</Row>
            <Row label="Supplier">{asset.supplier}</Row>
            <Row label="Purchase cost">{asset.purchase_cost !== null && fmtMoney(asset.purchase_cost, asset.currency)}</Row>
            <Row label="Warranty end">{asset.warranty_end && fmtDate(asset.warranty_end)}</Row>
            <Row label="Expected refresh">{asset.refresh_date && fmtDate(asset.refresh_date)}</Row>
            {disposed && (
              <>
                <Row label="Disposed">
                  {DISPOSAL_LABEL[asset.disposal_method ?? ""] ?? asset.disposal_method} on {fmtDate(asset.disposal_date)}
                </Row>
                <Row label="Disposal vendor">{asset.disposal_vendor}</Row>
                {asset.disposal_notes && <Row label="Disposal notes">{asset.disposal_notes}</Row>}
              </>
            )}
          </dl>
        </Card>
        <Card title="Agent device">
          {asset.device_id ? (
            <dl>
              <Row label="Device">
                <Link to={`/devices/${asset.device_id}`} className="text-accent hover:underline">
                  {asset.device_hostname ?? asset.device_id}
                </Link>
              </Row>
              <Row label="Last seen">
                {asset.device_last_seen_at ? `${fmtTime(asset.device_last_seen_at)} (${fmtAgo(asset.device_last_seen_at)})` : "never"}
                {asset.idle && <span className="ml-2 text-xs text-sev-high">idle candidate: reassign or retrieve</span>}
              </Row>
            </dl>
          ) : (
            <p className="text-sm text-ink-3">
              No endpoint agent. When this device is enrolled with the same serial number, the agent device is linked automatically.
            </p>
          )}
        </Card>
        <Certificates asset={asset} canUpload={analyst} canDownload={analyst} canDelete={can("admin")} onChange={ev.reload} />
        <Card title="Chain of custody" className="xl:col-span-2">
          <ErrorNote error={ev.error} />
          <Timeline events={ev.data} />
        </Card>
      </div>
      {editing && (
        <AssetFormModal open asset={asset} settings={settings} onClose={() => setEditing(false)} onSaved={refresh} />
      )}
      {action && (
        <ActionDialog
          asset={asset}
          action={action}
          onClose={() => setAction(null)}
          onDone={() => (action === "delete" ? navigate("/it-assets") : refresh())}
        />
      )}
    </div>
  );
}
