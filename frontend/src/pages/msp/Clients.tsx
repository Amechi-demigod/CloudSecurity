import { Users } from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";
import { ApiError, type ModuleKey } from "../../api";
import { useAuth } from "../../auth/context";
import { InvitationStateTag, InviteResult } from "../../components/org";
import { SaveBar } from "../../components/SaveBar";
import { Switch } from "../../components/Switch";
import {
  Button, Card, Drawer, Empty, ErrorNote, Field, FilterBar, FilterSearch, Modal, NameCell, NumCell, PageHeader, Pill, PillRow, RiskBar, Stat, Table, TextCell, type PillTone,
} from "../../components/ui";
import { fmtAgo, fmtTime } from "../../lib/format";
import { clientStatus, riskSummary, STATUS_LABEL, switchClient, type ClientStatus } from "../../lib/msp";
import { MODULES, MODULE_KEYS } from "../../lib/modules";
import { useApi } from "../../lib/useApi";
import { ts, useSort } from "../../lib/useSort";
import { mspApi, type ClientRow } from "../../mspApi";
import type { IssuedInvitation } from "../../orgApi";

const NEEDS_ATTENTION = 60;
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const STATUS_TONE: Record<ClientStatus, PillTone> = { active: "good", suspended: "critical", waiting: "neutral" };

const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : String(e));

function ModulePills({ modules }: { modules: ModuleKey[] }) {
  if (modules.length === 0) return <TextCell muted>None</TextCell>;
  return (
    <PillRow>
      {modules.map((m) => (
        <Pill key={m} tone="info">{MODULES[m].label}</Pill>
      ))}
    </PillRow>
  );
}

/** One-line module descriptions for the checkbox cards (the long ones live in MODULES for the locked pages). */
const MODULE_BLURB: Record<ModuleKey, string> = {
  cloud: "Risky settings, exposure and attack paths in Azure, AWS and Google Cloud.",
  endpoints: "Keep computers and servers updated and protected, and see threats on them.",
  vulnerabilities: "Known flaws in the software they run and what to fix first.",
  assets: "Hardware register, directories and network devices in one place.",
  external: "Scan their internet-facing domains from outside, with a PCI practice report.",
};

function ModuleCards({ value, onChange, disabled }: { value: ModuleKey[]; onChange: (v: ModuleKey[]) => void; disabled?: boolean }) {
  return (
    <fieldset disabled={disabled}>
      <legend className="mb-1 block text-sm font-medium text-ink-2">Modules</legend>
      <div className="grid gap-2 sm:grid-cols-2">
        {MODULE_KEYS.map((m) => {
          const on = value.includes(m);
          return (
            <label key={m} className={`flex cursor-pointer items-start gap-2 rounded-lg border p-3 text-sm transition focus-within:ring-2 focus-within:ring-accent ${on ? "border-accent bg-accent/10" : "border-line bg-surface-2 hover:border-accent/60"}`}>
              <input type="checkbox" className="mt-0.5" checked={on} onChange={(e) => onChange(e.target.checked ? [...value, m] : value.filter((x) => x !== m))} />
              <span>
                <span className="block font-medium text-ink">{MODULES[m].label}</span>
                <span className="block text-xs text-ink-3">{MODULE_BLURB[m]}</span>
              </span>
            </label>
          );
        })}
      </div>
      <p className="mt-2 text-xs text-ink-3">You can change modules at any time from the client's settings.</p>
    </fieldset>
  );
}

function AddClientDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (i: IssuedInvitation | null) => void }) {
  const [name, setName] = useState("");
  const [contact, setContact] = useState("");
  const [adminEmail, setAdminEmail] = useState("");
  const [modules, setModules] = useState<ModuleKey[]>([]);
  const [errors, setErrors] = useState<{ name?: string; contact?: string; admin?: string }>({});
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  function close() {
    setName("");
    setContact("");
    setAdminEmail("");
    setModules([]);
    setErrors({});
    setErr(null);
    onClose();
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    const next: typeof errors = {};
    if (!name.trim()) next.name = "Enter the client's name.";
    if (!contact.trim()) next.contact = "Enter a contact email.";
    else if (!EMAIL.test(contact.trim())) next.contact = "Enter a valid email address, like name@company.com.";
    if (adminEmail.trim() && !EMAIL.test(adminEmail.trim())) next.admin = "Enter a valid email address, like name@company.com.";
    setErrors(next);
    if (Object.keys(next).length) return;
    setBusy(true);
    setErr(null);
    try {
      const r = await mspApi.createClient({ name: name.trim(), contact_email: contact.trim(), modules, admin_email: adminEmail.trim() || undefined });
      onCreated(r.invitation);
      close();
    } catch (ex) {
      setErr(errMsg(ex));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={close} title="Add client" size="lg">
      <form className="space-y-4" onSubmit={submit} noValidate>
        <ErrorNote error={err} />
        <Field label="Client name" id="ac-name" required maxLength={128} value={name} error={errors.name} onChange={(e) => setName(e.target.value)} />
        <Field label="Contact email" id="ac-contact" type="email" required autoComplete="off" value={contact} error={errors.contact} onChange={(e) => setContact(e.target.value)} />
        <Field label="Client's first admin (optional)" id="ac-admin" type="email" autoComplete="off" value={adminEmail} error={errors.admin}
          hint="We email them an invitation. You can also run everything yourself and invite them later."
          onChange={(e) => setAdminEmail(e.target.value)} />
        <ModuleCards value={modules} onChange={setModules} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={close}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy}>{busy ? "Creating…" : "Create client"}</Button>
        </div>
      </form>
    </Modal>
  );
}

function SuspendDialog({ client, onClose, onDone }: { client: ClientRow | null; onClose: () => void; onDone: () => void }) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!client) return;
    setBusy(true);
    setErr(null);
    try {
      await mspApi.suspend(client.id, reason.trim());
      setReason("");
      onDone();
    } catch (ex) {
      setErr(errMsg(ex));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal open={!!client} onClose={onClose} title={client ? `Suspend ${client.name}` : "Suspend client"}>
      <form className="space-y-3" onSubmit={submit}>
        <p className="text-sm text-ink-2">Their users are signed out and their agents are refused until you reactivate them. Nothing is deleted.</p>
        <ErrorNote error={err} />
        <Field label="Reason (optional)" id="sc-reason" maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="danger" disabled={busy}>{busy ? "Suspending…" : "Suspend client"}</Button>
        </div>
      </form>
    </Modal>
  );
}

/** Manage one client (MSP admins): details, modules, suspension and its admin invitations. */
function ClientDrawer({ row, onClose, onChanged }: { row: ClientRow | null; onClose: () => void; onChanged: () => void }) {
  const client = row?.record ?? null;
  const id = row?.id ?? null;
  const { data: invitations, error: invErr, reload: reloadInv } = useApi(() => (id ? mspApi.invitations(id) : Promise.resolve(null)), [id]);
  const [issued, setIssued] = useState<IssuedInvitation | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [suspending, setSuspending] = useState(false);
  const [email, setEmail] = useState("");
  const [emailErr, setEmailErr] = useState<string | null>(null);

  async function act(fn: () => Promise<unknown>) {
    setErr(null);
    setBusy(true);
    try {
      const r = await fn();
      if (r && typeof r === "object" && "invitation" in r && "emailed" in r) setIssued(r as IssuedInvitation);
      onChanged();
      reloadInv();
    } catch (ex) {
      setErr(errMsg(ex));
      throw ex;
    } finally {
      setBusy(false);
    }
  }
  const quiet = (fn: () => Promise<unknown>) => act(fn).catch(() => undefined);

  return (
    <Drawer open={!!row} onClose={() => { setIssued(null); setErr(null); onClose(); }} title={row ? row.name : "Client"}>
      <ErrorNote error={err ?? invErr} />
      {issued && <InviteResult issued={issued} onDismiss={() => setIssued(null)} />}
      {row && client && (
        <div className="space-y-6 text-sm">
          <DetailsForm key={client.id + client.name + client.contact_email} client={client} busy={busy} onSave={(patch) => quiet(() => mspApi.updateClient(client.id, patch))} />
          <ModulesEditor key={client.id + client.modules.join()} modules={client.modules} busy={busy} onSave={(m) => quiet(() => mspApi.setModules(client.id, m))} />
          <section>
            <h3 className="mb-2 font-semibold">Status</h3>
            {client.status === "active" ? (
              <div className="flex items-center gap-3">
                <Pill tone="good">Active</Pill>
                <Button variant="danger" disabled={busy} onClick={() => setSuspending(true)}>Suspend</Button>
              </div>
            ) : (
              <div className="space-y-2">
                <div className="flex items-center gap-3">
                  <Pill tone="critical">Suspended</Pill>
                  {client.can_reactivate && <Button disabled={busy} onClick={() => void quiet(() => mspApi.activate(client.id))}>Reactivate</Button>}
                </div>
                {client.suspended_at && <p className="text-ink-3">Suspended {fmtTime(client.suspended_at)}{client.suspended_reason ? `: ${client.suspended_reason}` : ""}</p>}
                {!client.can_reactivate && <p className="text-ink-2">Suspended by Sentrigis. Contact Sentrigis to have it reactivated.</p>}
              </div>
            )}
          </section>
          {client.status === "active" && (
            <section>
              <h3 className="mb-2 font-semibold">Client admins</h3>
              {invitations && invitations.length > 0 ? (
                <ul className="space-y-2">
                  {invitations.map((i) => (
                    <li key={i.id} className="flex flex-wrap items-center justify-between gap-2">
                      <span>{i.email}</span>
                      <span className="flex items-center gap-2">
                        <InvitationStateTag state={i.state} />
                        {(i.state === "pending" || i.state === "expired") && (
                          <Button disabled={busy} onClick={() => void quiet(() => mspApi.resend(client.id, i.id))}>Resend invitation</Button>
                        )}
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-ink-3">No invitations yet. You can work in this client yourself and invite their admin later.</p>
              )}
              <form
                className="mt-3 flex flex-wrap items-start gap-2"
                noValidate
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!EMAIL.test(email.trim())) return setEmailErr("Enter a valid email address, like name@company.com.");
                  setEmailErr(null);
                  void quiet(async () => {
                    const r = await mspApi.invite(client.id, email.trim());
                    setEmail("");
                    return r;
                  });
                }}
              >
                <div className="min-w-48 flex-1">
                  <Field label="Invite a client admin" id="ci-email" type="email" autoComplete="off" value={email} error={emailErr} onChange={(e) => setEmail(e.target.value)} />
                </div>
                <div className="pt-[26px]"><Button type="submit" disabled={busy || !email.trim()}>Invite</Button></div>
              </form>
            </section>
          )}
        </div>
      )}
      {row && !client && <p className="text-sm text-ink-3">Loading…</p>}
      <SuspendDialog client={suspending ? row : null} onClose={() => setSuspending(false)} onDone={() => { setSuspending(false); onChanged(); }} />
    </Drawer>
  );
}

function DetailsForm({ client, busy, onSave }: { client: { name: string; contact_email: string | null }; busy: boolean; onSave: (p: { name?: string; contact_email?: string }) => Promise<unknown> }) {
  const [name, setName] = useState(client.name);
  const [contact, setContact] = useState(client.contact_email ?? "");
  const [errors, setErrors] = useState<{ name?: string; contact?: string }>({});
  const dirty = name.trim() !== client.name || contact.trim() !== (client.contact_email ?? "");
  return (
    <form
      className="space-y-3"
      noValidate
      onSubmit={(e) => {
        e.preventDefault();
        const next: typeof errors = {};
        if (!name.trim()) next.name = "Enter the client's name.";
        if (!EMAIL.test(contact.trim())) next.contact = "Enter a valid email address, like name@company.com.";
        setErrors(next);
        if (Object.keys(next).length) return;
        void onSave({ name: name.trim(), contact_email: contact.trim() });
      }}
    >
      <h3 className="font-semibold">Details</h3>
      <Field label="Client name" id="cd-name" maxLength={128} value={name} error={errors.name} onChange={(e) => setName(e.target.value)} />
      <Field label="Contact email" id="cd-contact" type="email" autoComplete="off" value={contact} error={errors.contact} onChange={(e) => setContact(e.target.value)} />
      <Button type="submit" disabled={busy || !dirty}>Save details</Button>
    </form>
  );
}

/** Modules of a client: switches are pending until "Save changes" (same pattern as the platform console). */
function ModulesEditor({ modules, busy, onSave }: { modules: ModuleKey[]; busy: boolean; onSave: (m: ModuleKey[]) => Promise<unknown> }) {
  const [pending, setPending] = useState<Partial<Record<ModuleKey, boolean>>>({});
  const has = (m: ModuleKey) => (m in pending ? pending[m]! : modules.includes(m));
  const changes = (Object.entries(pending) as [ModuleKey, boolean][]).filter(([m, v]) => v !== modules.includes(m));
  const turningOff = changes.filter(([, v]) => !v).map(([m]) => m);
  return (
    <section>
      <h3 className="mb-2 font-semibold">Modules</h3>
      <ul className="space-y-3">
        {MODULE_KEYS.map((m) => (
          <li key={m} className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="font-medium">{MODULES[m].label}</div>
              <p className="text-xs text-ink-3">{MODULE_BLURB[m]}</p>
              {turningOff.includes(m) && (
                <p role="alert" className="mt-1 text-xs text-sev-high">Turning off {MODULES[m].label} hides those pages and their data for this client. Nothing is deleted.</p>
              )}
            </div>
            <Switch on={has(m)} label={MODULES[m].label} disabled={busy} onChange={(next) => setPending({ ...pending, [m]: next })} />
          </li>
        ))}
      </ul>
      <SaveBar
        placement="inline"
        count={changes.length}
        saving={busy}
        onDiscard={() => setPending({})}
        onSave={() => void onSave(MODULE_KEYS.filter(has)).then(() => setPending({}))}
      />
    </section>
  );
}

export default function Clients() {
  const { can } = useAuth();
  const admin = can("admin");
  const { data: rows, error, loading, reload } = useApi(mspApi.rows, []);
  const { data: info, reload: reloadInfo } = useApi(mspApi.msp, []);
  const [q, setQ] = useState("");
  const [adding, setAdding] = useState(false);
  const [issued, setIssued] = useState<IssuedInvitation | null>(null);
  const [managing, setManaging] = useState<string | null>(null);
  const [opening, setOpening] = useState<string | null>(null);
  const [openErr, setOpenErr] = useState<string | null>(null);

  const all = useMemo(() => rows ?? [], [rows]);
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return needle ? all.filter((c) => c.name.toLowerCase().includes(needle)) : all;
  }, [all, q]);
  const active = all.filter((c) => c.status === "active");
  const suspended = all.length - active.length;
  const attention = active.filter((c) => (c.risk_score ?? 0) > NEEDS_ATTENTION).length;
  const withCritical = active.filter((c) => (c.open_critical_findings ?? 0) > 0);
  const critical = withCritical.reduce((n, c) => n + (c.open_critical_findings ?? 0), 0);
  const devices = active.reduce((n, c) => n + (c.devices ?? 0), 0);

  const sorted = useSort(
    filtered,
    {
      client: (c) => c.name.toLowerCase(),
      risk: (c) => c.risk_score,
      critical: (c) => c.open_critical_findings,
      devices: (c) => c.devices,
      scan: (c) => ts(c.last_scan_at),
      status: (c) => ["active", "waiting", "suspended"].indexOf(clientStatus(c)),
    },
    { key: "client", dir: "asc" },
    { risk: "desc", critical: "desc", devices: "desc", scan: "desc" },
  );

  const limitReached = !!info && info.max_clients != null && info.clients >= info.max_clients;
  const refresh = () => {
    void reload();
    void reloadInfo();
  };
  const managed = all.find((c) => c.id === managing) ?? null;

  function open(id: string) {
    setOpening(id);
    setOpenErr(null);
    switchClient(id).catch((e) => {
      setOpenErr(errMsg(e));
      setOpening(null);
    });
  }

  return (
    <div>
      <PageHeader
        title="Clients"
        subtitle="Every organisation you manage. Open one to work inside it."
        actions={
          admin && (
            <Button variant="primary" onClick={() => setAdding(true)} disabled={limitReached} title={limitReached ? "Client limit reached. Ask Sentrigis to raise it." : undefined}>
              Add client
            </Button>
          )
        }
      />
      {limitReached && admin && <p className="mb-3 text-xs text-ink-3">You have reached your limit of {info?.max_clients} clients. Ask Sentrigis to raise it.</p>}
      <ErrorNote error={openErr} />
      {issued && <InviteResult issued={issued} onDismiss={() => setIssued(null)} />}
      <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Clients" value={rows ? all.length : "–"} sub={rows ? `${active.length} active · ${suspended} suspended` : undefined} />
        <Stat label="Need attention" value={rows ? attention : "–"} sub={`Risk score above ${NEEDS_ATTENTION}`} />
        <Stat label="Critical issues" value={rows ? critical : "–"} sub={rows ? `Across ${withCritical.length} ${withCritical.length === 1 ? "client" : "clients"}` : undefined} />
        <Stat label="Devices managed" value={rows ? devices : "–"} />
      </div>
      <Card>
        <FilterBar count={rows ? `${filtered.length} ${filtered.length === 1 ? "client" : "clients"}` : undefined}>
          <FilterSearch value={q} onChange={setQ} placeholder="Search clients" label="Search clients" />
        </FilterBar>
        <Table
          tableId="msp-clients"
          head={[
            { label: "Client", sort: "client", w: 240 },
            { label: "Modules", w: 300, key: "modules" },
            { label: "Risk score", sort: "risk", w: 150 },
            { label: "Critical", sort: "critical", w: 90, align: "right" },
            { label: "Devices", sort: "devices", w: 90, align: "right" },
            { label: "Last scan", sort: "scan", w: 130 },
            { label: "Status", sort: "status", w: 190 },
            { label: "Open", srOnly: true, w: 100, key: "open" },
          ]}
          sort={sorted.sort}
          onSort={sorted.onSort}
          loading={loading}
          rowCount={filtered.length}
          noun="clients"
          pageSize={50}
          filtered={q.trim() !== ""}
          onClearFilters={() => setQ("")}
          error={rows ? null : error}
          onRetry={() => void reload()}
          empty={
            <Empty icon={Users} title="No clients yet" action={admin ? <Button variant="primary" onClick={() => setAdding(true)}>Add client</Button> : undefined}>
              {admin ? "Add your first client to start managing their security from here." : "Your administrators have not added any clients yet."}
            </Empty>
          }
        >
          {sorted.rows.map((c) => {
            const st = clientStatus(c);
            const numbers = st === "active";
            return (
              <tr key={c.id} className="hover:bg-surface-2">
                <td className="px-3 py-2">
                  <NameCell name={c.name} sub={c.record?.contact_email ?? undefined} onOpen={admin ? () => setManaging(c.id) : undefined} openLabel={`Manage ${c.name}`} />
                </td>
                <td className="px-3 py-2"><ModulePills modules={c.modules} /></td>
                <td className="px-3 py-2">{numbers && c.risk_score != null ? <RiskBar value={c.risk_score} /> : <NumCell value={null} />}</td>
                <td className="px-3 py-2"><NumCell value={numbers ? c.open_critical_findings : null} /></td>
                <td className="px-3 py-2"><NumCell value={numbers ? c.devices : null} /></td>
                <td className="px-3 py-2"><TextCell muted title={c.last_scan_at ? fmtTime(c.last_scan_at) : undefined}>{c.last_scan_at ? fmtAgo(c.last_scan_at) : "Never"}</TextCell></td>
                <td className="px-3 py-2">
                  <PillRow>
                    <Pill tone={STATUS_TONE[st]} title={st === "suspended" ? (c.record?.can_reactivate === false ? "Suspended by Sentrigis" : undefined) : riskSummary(c)}>{STATUS_LABEL[st]}</Pill>
                  </PillRow>
                </td>
                <td className="px-3 py-2">
                  <Button variant="primary" disabled={st === "suspended" || opening !== null} onClick={() => open(c.id)} title={st === "suspended" ? "Reactivate this client to open it" : undefined}>
                    {opening === c.id ? "Opening…" : <>Open<span className="sr-only"> {c.name}</span></>}
                  </Button>
                </td>
              </tr>
            );
          })}
        </Table>
      </Card>
      <AddClientDialog open={adding} onClose={() => setAdding(false)} onCreated={(i) => { setIssued(i); refresh(); }} />
      {admin && <ClientDrawer row={managed} onClose={() => setManaging(null)} onChanged={refresh} />}
    </div>
  );
}
