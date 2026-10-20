import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { assetsApi, type AssetSettings as Settings } from "../../assetsApi";
import { FormError, TextArea } from "../../components/assets";
import { Button, Card, ErrorNote, Field, PageHeader } from "../../components/ui";
import { errMsg } from "../../lib/assets";
import { useApi } from "../../lib/useApi";

function Form({ initial, onSaved }: { initial: Settings; onSaved: (s: Settings) => void }) {
  const [currency, setCurrency] = useState(initial.default_currency);
  const [locations, setLocations] = useState(initial.locations.join("\n"));
  const [fields, setFields] = useState(initial.custom_fields.map((f) => `${f.key}=${f.label}`).join("\n"));
  const [idle, setIdle] = useState(String(initial.idle_days));
  const [warranty, setWarranty] = useState(String(initial.warranty_warning_days));
  const [due, setDue] = useState(String(initial.retrieval_due_days));
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      const custom = fields
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)
        .map((l) => {
          const [key, ...rest] = l.split("=");
          return { key: key.trim(), label: (rest.join("=") || key).trim() };
        });
      const s = await assetsApi.saveSettings({
        default_currency: currency.trim().toUpperCase(),
        locations: locations.split("\n").map((l) => l.trim()).filter(Boolean),
        custom_fields: custom,
        idle_days: Number(idle),
        warranty_warning_days: Number(warranty),
        retrieval_due_days: Number(due),
      });
      onSaved(s);
      setSaved(true);
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="max-w-2xl space-y-4" onSubmit={submit}>
      <FormError error={error} />
      {saved && (
        <div role="status" className="rounded border border-good/60 bg-good/10 px-3 py-2 text-sm">
          Settings saved.
        </div>
      )}
      <Card title="Defaults & thresholds">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Default currency (ISO 4217)" id="st-cur" maxLength={3} pattern="[A-Za-z]{3}" required value={currency} onChange={(e) => setCurrency(e.target.value)} />
          <Field label="Idle after (days unseen)" id="st-idle" type="number" min={1} max={3650} required value={idle} onChange={(e) => setIdle(e.target.value)} />
          <Field label="Warranty warning (days)" id="st-war" type="number" min={1} max={3650} required value={warranty} onChange={(e) => setWarranty(e.target.value)} />
          <Field label="Retrieval due after leave date (days)" id="st-due" type="number" min={0} max={365} required value={due} onChange={(e) => setDue(e.target.value)} />
        </div>
      </Card>
      <Card title="Sites / locations">
        <TextArea label="One per line (suggested in the asset form; free text is still allowed)" id="st-locs" value={locations} onChange={setLocations} maxLength={64000} />
      </Card>
      <Card title="Custom fields">
        <TextArea
          label="One per line as key=Label (key: lower-case letters, digits, _)"
          id="st-fields"
          value={fields}
          onChange={setFields}
          placeholder={"cost_centre=Cost centre\npo_number=PO number"}
          maxLength={10000}
        />
        <p className="mt-1 text-xs text-ink-3">Removing a field hides it; values already stored on assets are kept. CSV columns are named custom.&lt;key&gt;.</p>
      </Card>
      <div className="flex justify-end">
        <Button type="submit" variant="primary" disabled={busy}>
          {busy ? "Saving…" : "Save settings"}
        </Button>
      </div>
    </form>
  );
}

export default function AssetSettings() {
  const { data, error, reload } = useApi(assetsApi.settings, []);
  return (
    <div>
      <div className="mb-1 text-xs text-ink-3">
        <Link to="/it-assets" className="hover:text-ink">
          IT assets
        </Link>{" "}
        / Settings
      </div>
      <PageHeader title="IT asset settings" subtitle="Admin only. Every change is recorded in the audit log." />
      <ErrorNote error={error} />
      {data && <Form initial={data} onSaved={reload} />}
    </div>
  );
}
