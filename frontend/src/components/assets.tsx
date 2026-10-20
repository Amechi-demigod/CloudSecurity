import { useState, type FormEvent, type ReactNode } from "react";
import { assetsApi, type AssetInput, type AssetSettings, type AssetStatus, type ItAsset } from "../assetsApi";
import { STATUS_LABEL, TYPE_LABEL, errMsg } from "../lib/assets";
import { Button, Field, Modal } from "./ui";

const STATUS_STYLE: Record<AssetStatus, { cls: string; icon: string }> = {
  in_stock: { cls: "border-line text-ink-2", icon: "□" },
  assigned: { cls: "border-good/60 text-good", icon: "●" },
  in_repair: { cls: "border-sev-medium/60 text-sev-medium", icon: "~" },
  retrieval_pending: { cls: "border-sev-high/60 text-sev-high", icon: "↩" },
  retrieved: { cls: "border-accent/60 text-accent", icon: "✓" },
  lost: { cls: "border-sev-critical/60 text-sev-critical", icon: "?" },
  stolen: { cls: "border-sev-critical/60 text-sev-critical", icon: "!" },
  disposed: { cls: "border-line text-ink-3", icon: "✕" },
};

/** Lifecycle status pill: icon + text (never color alone). */
export function AssetStatusBadge({ status }: { status: AssetStatus }) {
  const s = STATUS_STYLE[status] ?? STATUS_STYLE.in_stock;
  return (
    <span className={`inline-flex items-center gap-1 whitespace-nowrap rounded border px-1.5 py-0.5 text-xs font-medium ${s.cls}`}>
      <span aria-hidden>{s.icon}</span>
      {STATUS_LABEL[status] ?? status}
    </span>
  );
}

export function FormError({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
      {error}
    </div>
  );
}

const inputCls =
  "block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40";

export function SelectField({ label, id, value, onChange, children }: { label: string; id: string; value: string; onChange: (v: string) => void; children: ReactNode }) {
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-sm font-medium text-ink-2">
        {label}
      </label>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value)} className={inputCls}>
        {children}
      </select>
    </div>
  );
}

export function TextArea({ label, id, value, onChange, maxLength = 4000, placeholder }: { label: string; id: string; value: string; onChange: (v: string) => void; maxLength?: number; placeholder?: string }) {
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-sm font-medium text-ink-2">
        {label}
      </label>
      <textarea id={id} rows={3} value={value} maxLength={maxLength} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} className={inputCls} />
    </div>
  );
}

type FormState = Record<string, string>;

function initial(asset: ItAsset | null, settings: AssetSettings | null): FormState {
  const s: FormState = {
    asset_tag: asset?.asset_tag ?? "",
    serial_number: asset?.serial_number ?? "",
    asset_type: asset?.asset_type ?? "laptop",
    manufacturer: asset?.manufacturer ?? "",
    model: asset?.model ?? "",
    location: asset?.location ?? "",
    purchase_date: asset?.purchase_date ?? "",
    supplier: asset?.supplier ?? "",
    purchase_cost: asset?.purchase_cost != null ? String(asset.purchase_cost) : "",
    currency: asset?.currency ?? settings?.default_currency ?? "NGN",
    warranty_end: asset?.warranty_end ?? "",
    refresh_date: asset?.refresh_date ?? "",
    notes: asset?.notes ?? "",
    assignee_name: "",
    assignee_email: "",
    assignee_department: asset?.assignee_department ?? "",
  };
  for (const f of settings?.custom_fields ?? []) s[`custom.${f.key}`] = asset?.custom_fields[f.key] ?? "";
  return s;
}

/** Create or edit an asset record (analyst / admin). */
export function AssetFormModal({ open, asset, settings, onClose, onSaved }: {
  open: boolean;
  asset: ItAsset | null;
  settings: AssetSettings | null;
  onClose: () => void;
  onSaved: (a: ItAsset) => void;
}) {
  const [form, setForm] = useState<FormState>(() => initial(asset, settings));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: string) => (v: string) => setForm((f) => ({ ...f, [k]: v }));
  const input = (k: string) => ({ value: form[k] ?? "", onChange: (e: { target: { value: string } }) => set(k)(e.target.value) });

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const custom: Record<string, string> = {};
    for (const f of settings?.custom_fields ?? []) {
      const v = (form[`custom.${f.key}`] ?? "").trim();
      if (v) custom[f.key] = v;
    }
    const nullable = (v: string) => (v.trim() ? v.trim() : null);
    const body: AssetInput = {
      asset_tag: form.asset_tag.trim(),
      serial_number: form.serial_number,
      asset_type: form.asset_type,
      manufacturer: form.manufacturer,
      model: form.model,
      location: form.location,
      purchase_date: nullable(form.purchase_date),
      supplier: form.supplier,
      purchase_cost: nullable(form.purchase_cost),
      currency: form.currency.trim().toUpperCase(),
      warranty_end: nullable(form.warranty_end),
      refresh_date: nullable(form.refresh_date),
      notes: form.notes,
      custom_fields: custom,
      assignee_department: form.assignee_department,
    };
    try {
      let saved: ItAsset;
      if (asset) {
        saved = await assetsApi.update(asset.id, body);
      } else {
        const email = form.assignee_email.trim();
        saved = await assetsApi.create({
          ...body,
          status: email ? "assigned" : "in_stock",
          assignee_email: email,
          assignee_name: form.assignee_name.trim(),
        });
      }
      onSaved(saved);
      onClose();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={onClose} title={asset ? `Edit ${asset.asset_tag}` : "Add asset"}>
      <form className="max-h-[70vh] space-y-3 overflow-y-auto pr-1" onSubmit={submit}>
        <FormError error={error} />
        <div className="grid grid-cols-2 gap-3">
          <Field label="Asset tag" id="af-tag" required maxLength={64} {...input("asset_tag")} placeholder="WK-LAP-0001" />
          <SelectField label="Type" id="af-type" value={form.asset_type} onChange={set("asset_type")}>
            {(settings?.types ?? Object.keys(TYPE_LABEL)).map((t) => (
              <option key={t} value={t}>
                {TYPE_LABEL[t] ?? t}
              </option>
            ))}
          </SelectField>
          <Field label="Manufacturer" id="af-make" maxLength={128} {...input("manufacturer")} />
          <Field label="Model" id="af-model" maxLength={128} {...input("model")} />
          <Field label="Serial number" id="af-serial" maxLength={128} {...input("serial_number")}
            hint={asset?.device_id ? "Filled from the agent inventory when empty." : undefined} />
          <div>
            <Field label="Location / site" id="af-loc" maxLength={128} list="af-locations" {...input("location")} />
            <datalist id="af-locations">
              {(settings?.locations ?? []).map((l) => (
                <option key={l} value={l} />
              ))}
            </datalist>
          </div>
          <Field label="Purchase date" id="af-pdate" type="date" {...input("purchase_date")} />
          <Field label="Supplier" id="af-supplier" maxLength={128} {...input("supplier")} />
          <Field label="Purchase cost" id="af-cost" type="number" min={0} step="0.01" {...input("purchase_cost")} />
          <Field label="Currency" id="af-cur" maxLength={3} pattern="[A-Za-z]{3}" {...input("currency")} />
          <Field label="Warranty end" id="af-warranty" type="date" {...input("warranty_end")} />
          <Field label="Expected refresh" id="af-refresh" type="date" {...input("refresh_date")} />
        </div>
        {!asset && (
          <div className="grid grid-cols-2 gap-3 rounded border border-line p-3">
            <p className="col-span-2 text-xs text-ink-3">Optional: assign it straight away.</p>
            <Field label="Owner email" id="af-email" type="email" maxLength={320} {...input("assignee_email")} />
            <Field label="Owner name" id="af-name" maxLength={128} {...input("assignee_name")} />
            <Field label="Department" id="af-dept" maxLength={128} {...input("assignee_department")} />
          </div>
        )}
        {(settings?.custom_fields ?? []).length > 0 && (
          <div className="grid grid-cols-2 gap-3">
            {settings!.custom_fields.map((f) => (
              <Field key={f.key} label={f.label} id={`af-c-${f.key}`} maxLength={500} {...input(`custom.${f.key}`)} />
            ))}
          </div>
        )}
        <TextArea label="Notes" id="af-notes" value={form.notes} onChange={set("notes")} />
        <div className="flex justify-end gap-2 pt-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy || !form.asset_tag.trim()}>
            {busy ? "Saving…" : asset ? "Save" : "Add asset"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
