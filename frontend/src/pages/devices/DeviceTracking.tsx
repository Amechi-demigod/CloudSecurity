import { useMemo, useState } from "react";
import { SaveBar } from "../../components/SaveBar";
import { Switch } from "../../components/Switch";
import { Button, Card, Empty, ErrorNote, Field, Modal, PageHeader, Table } from "../../components/ui";
import TrackingAlerts from "./TrackingAlerts";
import { useApi } from "../../lib/useApi";
import { trackingApi, timeZones, type Country, type TrackingOffice } from "../../trackingApi";

function OfficeDialog({ office, open, onClose, onSaved, zones }: {
  office: TrackingOffice | null; open: boolean; onClose: () => void; onSaved: () => void; zones: string[];
}) {
  const [name, setName] = useState(office?.name ?? "");
  const [nets, setNets] = useState((office?.networks ?? []).join("\n"));
  const [tz, setTz] = useState(office?.timezone ?? "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const networks = nets.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
      if (office) await trackingApi.updateOffice(office.id, { name, networks, ...(tz ? { timezone: tz } : { clear_timezone: true }) });
      else await trackingApi.createOffice({ name, networks, timezone: tz || null });
      onSaved();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!office) return;
    setBusy(true);
    try {
      await trackingApi.deleteOffice(office.id);
      onSaved();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={onClose} title={office ? `Edit ${office.name}` : "Add office"}>
      <div className="space-y-3">
        <Field id="office-name" label="Office name" value={name} onChange={(e) => setName(e.target.value)} maxLength={128} />
        <div>
          <label htmlFor="office-nets" className="mb-1 block text-sm font-medium text-ink-2">Internet addresses or ranges</label>
          <textarea id="office-nets" rows={4} value={nets} onChange={(e) => setNets(e.target.value)}
            placeholder={"203.0.113.10\n198.51.100.0/24"}
            className="block w-full rounded border border-line bg-surface-2 px-3 py-1.5 font-mono text-sm text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40" />
          <p className="mt-1 text-xs text-ink-3">The public address of the office network, one per line (up to 50). Ranges like 198.51.100.0/24 work too.</p>
        </div>
        <div>
          <label htmlFor="office-tz" className="mb-1 block text-sm font-medium text-ink-2">Time zone (optional)</label>
          <select id="office-tz" value={tz} onChange={(e) => setTz(e.target.value)}
            className="block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink">
            <option value="">Same as the organisation</option>
            {zones.map((z) => <option key={z} value={z}>{z}</option>)}
          </select>
        </div>
        {error && <p role="alert" className="text-sm text-sev-critical">{error}</p>}
        <div className="flex justify-between gap-2">
          <div>{office && <Button variant="danger" onClick={remove} disabled={busy}>Delete office</Button>}</div>
          <div className="flex gap-2">
            <Button onClick={onClose} disabled={busy}>Cancel</Button>
            <Button variant="primary" onClick={save} disabled={busy || !name.trim()}>{busy ? "Saving…" : "Save office"}</Button>
          </div>
        </div>
      </div>
    </Modal>
  );
}

function CountryPicker({ countries, value, onChange }: { countries: Country[]; value: string[]; onChange: (v: string[]) => void }) {
  const [q, setQ] = useState("");
  const shown = countries.filter((c) => c.name.toLowerCase().includes(q.toLowerCase()) || c.code.toLowerCase() === q.toLowerCase());
  const byCode = useMemo(() => new Map(countries.map((c) => [c.code, c.name])), [countries]);
  const toggle = (code: string) => onChange(value.includes(code) ? value.filter((c) => c !== code) : [...value, code].sort());
  return (
    <div>
      <div className="mb-2 flex flex-wrap gap-1.5">
        {value.length === 0 && <span className="text-sm text-ink-3">No country rule: computers may be anywhere.</span>}
        {value.map((c) => (
          <button key={c} type="button" onClick={() => toggle(c)} aria-label={`Remove ${byCode.get(c) ?? c}`}
            className="rounded-full border border-line bg-surface-2 px-2 py-0.5 text-xs text-ink hover:bg-line">
            {byCode.get(c) ?? c} ×
          </button>
        ))}
      </div>
      <Field id="country-search" label="Add a country" placeholder="Search countries" value={q} onChange={(e) => setQ(e.target.value)} />
      <ul className="mt-2 max-h-48 overflow-y-auto rounded border border-line bg-surface-2 text-sm" aria-label="Countries">
        {shown.map((c) => (
          <li key={c.code}>
            <label className="flex cursor-pointer items-center gap-2 px-3 py-1 hover:bg-line">
              <input type="checkbox" checked={value.includes(c.code)} onChange={() => toggle(c.code)} />
              {c.name} <span className="text-xs text-ink-3">{c.code}</span>
            </label>
          </li>
        ))}
        {shown.length === 0 && <li className="px-3 py-2 text-ink-3">No match.</li>}
      </ul>
    </div>
  );
}

export default function DeviceTracking() {
  const settings = useApi(() => trackingApi.settings(), []);
  const offices = useApi(() => trackingApi.offices(), []);
  const countries = useApi(() => trackingApi.countries(), []);
  const zones = useMemo(() => timeZones(), []);
  const [draft, setDraft] = useState<{ enabled?: boolean; timezone?: string; allowed_countries?: string[] }>({});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dialog, setDialog] = useState<{ office: TrackingOffice | null } | null>(null);

  const s = settings.data;
  if (!s) return <ErrorNote error={settings.error} />;
  const enabled = draft.enabled ?? s.enabled;
  const timezone = draft.timezone ?? s.timezone;
  const allowed = draft.allowed_countries ?? s.allowed_countries;
  const changes = (draft.enabled !== undefined && draft.enabled !== s.enabled ? 1 : 0)
    + (draft.timezone !== undefined && draft.timezone !== s.timezone ? 1 : 0)
    + (draft.allowed_countries !== undefined && draft.allowed_countries.join() !== s.allowed_countries.join() ? 1 : 0);

  async function save() {
    setSaving(true);
    setError(null);
    try {
      await trackingApi.saveSettings(draft);
      setDraft({});
      settings.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="max-w-4xl">
      <PageHeader title="Device tracking"
        subtitle="See roughly where company laptops and desktops are, from their internet address. Windows and macOS only; servers are never tracked." />
      <ErrorNote error={error} />
      <Card title="Tracking" className="mb-4">
        <div className="flex items-center justify-between gap-4">
          <div>
            <div className="text-sm font-medium text-ink">Tracking on</div>
            <div className="text-xs text-ink-3">Off by default. History is kept {s.retention_days} days.</div>
          </div>
          <Switch on={enabled} label="Tracking on" onChange={(v) => setDraft((d) => ({ ...d, enabled: v }))} />
        </div>
        <div role="note" className="mt-3 rounded border border-warn/50 bg-warn/10 px-3 py-2 text-sm text-ink">
          Tell your staff: company laptops report their location while tracking is on. History is kept {s.retention_days} days.
        </div>
        {!s.database_available && (
          <p className="mt-3 text-sm text-ink-3">The location database has not been downloaded yet, so places show as &ldquo;Not available yet&rdquo;.</p>
        )}
      </Card>

      <Card title="Office networks" className="mb-4"
        actions={<Button onClick={() => setDialog({ office: null })}>Add office</Button>}>
        {offices.data && offices.data.length === 0 ? (
          <Empty>No offices yet. Add the internet addresses of your offices to see when a computer is at one.</Empty>
        ) : (
          <Table tableId="device-tracking-offices" head={["Office", "Internet addresses", "Computers there now", ""]}>
            {(offices.data ?? []).map((o) => (
              <tr key={o.id}>
                <td className="px-3 py-1.5 font-medium">{o.name}</td>
                <td className="px-3 py-1.5 font-mono text-xs text-ink-2">{o.networks.join(", ") || "—"}</td>
                <td className="px-3 py-1.5">{o.devices_now}</td>
                <td className="px-3 py-1.5 text-right"><Button onClick={() => setDialog({ office: o })}>Edit</Button></td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Card title="Allowed places" className="mb-4">
        <p className="mb-3 text-sm text-ink-3">Countries where your computers are expected to be. Leave empty for no rule.</p>
        <CountryPicker countries={countries.data ?? []} value={allowed} onChange={(v) => setDraft((d) => ({ ...d, allowed_countries: v }))} />
      </Card>

      <Card title="Time zone" className="mb-4">
        <label htmlFor="org-tz" className="mb-1 block text-sm text-ink-3">Times for your organisation are shown in this time zone. Each office can have its own.</label>
        <select id="org-tz" value={timezone} onChange={(e) => setDraft((d) => ({ ...d, timezone: e.target.value }))}
          className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink">
          {[...new Set([timezone, ...zones])].map((z) => <option key={z} value={z}>{z}</option>)}
        </select>
      </Card>

      <TrackingAlerts s={s} onSaved={() => settings.reload()} />

      <p className="mb-4 text-xs text-ink-3">
        IP geolocation by <a className="text-accent hover:underline" href="https://db-ip.com" target="_blank" rel="noopener noreferrer">DB-IP</a>.
        Map data &copy; OpenStreetMap contributors.
      </p>

      <SaveBar count={changes} saving={saving} onSave={save} onDiscard={() => setDraft({})} />
      {dialog && (
        <OfficeDialog key={dialog.office?.id ?? "new"} office={dialog.office} open zones={zones}
          onClose={() => setDialog(null)} onSaved={() => offices.reload()} />
      )}
    </div>
  );
}
