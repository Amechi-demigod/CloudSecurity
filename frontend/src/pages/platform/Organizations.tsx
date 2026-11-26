import { useMemo, useState, type FormEvent } from "react";
import { ApiError, type ModuleKey, type Role } from "../../api";
import { ROLE_LABEL, useAuth } from "../../auth/context";
import { InvitationStateTag, InviteResult } from "../../components/org";
import { Switch } from "../../components/Switch";
import { SaveBar } from "../../components/SaveBar";
import { Button, Card, Drawer, ErrorNote, Field, Modal, NameCell, NumCell, PageHeader, Pill, PillRow, Table, Tag, TextCell } from "../../components/ui";
import { fmtAgo, fmtTime } from "../../lib/format";
import { MODULES, MODULE_KEYS } from "../../lib/modules";
import { useApi } from "../../lib/useApi";
import { ts, useSort } from "../../lib/useSort";
import { orgApi, type IssuedInvitation, type PlatformOrg } from "../../orgApi";

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : String(e);
}

/** Product modules of an organisation as chips (the platform owner's at-a-glance view). */
function ModuleChips({ modules }: { modules: ModuleKey[] }) {
  if (modules.length === 0) return <TextCell muted>None</TextCell>;
  return (
    <PillRow>
      {modules.map((m) => (
        <Pill key={m} tone="info">
          {MODULES[m].label}
        </Pill>
      ))}
    </PillRow>
  );
}

/** The product modules of an organisation. Switches are pending until "Save changes". */
function ModulesSection({ orgId, modules, busy, onSave }: { orgId: string; modules: ModuleKey[]; busy: boolean; onSave: (changes: [ModuleKey, boolean][]) => Promise<void> }) {
  const [pending, setPending] = useState<Partial<Record<ModuleKey, boolean>>>({});
  const has = (m: ModuleKey) => (m in pending ? pending[m]! : modules.includes(m));
  const changes = (Object.entries(pending) as [ModuleKey, boolean][]).filter(([m, v]) => v !== modules.includes(m));
  const turningOff = changes.filter(([, v]) => !v).map(([m]) => m);
  const noData = has("vulnerabilities") && !has("cloud") && !has("endpoints");
  return (
    <section key={orgId}>
      <h3 className="mb-2 font-semibold">Modules</h3>
      <ul className="space-y-3">
        {MODULE_KEYS.map((m) => (
          <li key={m}>
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div id={`mod-${m}`} className="font-medium">{MODULES[m].label}</div>
                <p className="text-xs text-ink-3">{MODULES[m].description}</p>
                {m === "vulnerabilities" && noData && (
                  <p className="mt-1 text-xs text-sev-high">Needs Cloud security or Endpoints &amp; servers to have data.</p>
                )}
                {turningOff.includes(m) && (
                  <p role="alert" className="mt-1 text-xs text-sev-high">
                    Turning off {MODULES[m].label} hides those pages and their data for that customer. Nothing is deleted.
                  </p>
                )}
              </div>
              <Switch on={has(m)} label={MODULES[m].label} disabled={busy} onChange={(next) => setPending({ ...pending, [m]: next })} />
            </div>
          </li>
        ))}
      </ul>
      <SaveBar
        placement="inline"
        count={changes.length}
        saving={busy}
        onDiscard={() => setPending({})}
        onSave={() => void onSave(changes).then(() => setPending({}))}
      />
    </section>
  );
}

/** Who manages this organisation (a customer's MSP), or how many clients an MSP may have. Pending until saved. */
function PartnershipSection({ org, msps, busy, onSavePartner, onSaveMax }: {
  org: PlatformOrg;
  msps: PlatformOrg[];
  busy: boolean;
  onSavePartner: (id: string | null) => Promise<unknown>;
  onSaveMax: (n: number | null) => Promise<unknown>;
}) {
  const [partner, setPartner] = useState(org.partner_org_id ?? "");
  const [max, setMax] = useState(org.max_clients == null ? "" : String(org.max_clients));
  if (org.kind === "msp") {
    const bad = max.trim() !== "" && !/^\d{1,6}$/.test(max.trim());
    const next = max.trim() === "" ? null : Number(max.trim());
    const changed = !bad && next !== org.max_clients;
    return (
      <section>
        <h3 className="mb-2 font-semibold">Partner account</h3>
        <p className="mb-2 text-xs text-ink-3">This organisation is an MSP and manages {org.clients} {org.clients === 1 ? "client" : "clients"}.</p>
        <Field label="Maximum clients" id="pm-max" inputMode="numeric" value={max} placeholder="No limit" disabled={busy}
          error={bad ? "Enter a whole number, or leave it empty for no limit." : null} onChange={(e) => setMax(e.target.value)} />
        <SaveBar placement="inline" count={changed ? 1 : 0} saving={busy} onDiscard={() => setMax(org.max_clients == null ? "" : String(org.max_clients))}
          onSave={() => void onSaveMax(next)} />
      </section>
    );
  }
  const changed = partner !== (org.partner_org_id ?? "");
  const current = msps.find((m) => m.id === org.partner_org_id);
  return (
    <section>
      <h3 className="mb-2 font-semibold">Managed by</h3>
      <label htmlFor="pm-partner" className="sr-only">MSP partner</label>
      <select id="pm-partner" value={partner} disabled={busy} onChange={(e) => setPartner(e.target.value)}
        className="block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink">
        <option value="">Nobody (managed by its own team)</option>
        {msps.map((m) => (
          <option key={m.id} value={m.id}>{m.name}</option>
        ))}
      </select>
      <p className="mt-1 text-xs text-ink-3">
        {current ? `${current.name}'s staff can open this organisation and work in it.` : "An MSP's staff can open it and work in it. The organisation's own users never see this."}
        {partner === "" && org.partner_org_id && " Removing the partner ends the MSP's access at once."}
      </p>
      <SaveBar placement="inline" count={changed ? 1 : 0} saving={busy} onDiscard={() => setPartner(org.partner_org_id ?? "")}
        onSave={() => void onSavePartner(partner || null)} />
    </section>
  );
}

function CreateOrgDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (i: IssuedInvitation) => void }) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [contact, setContact] = useState("");
  const [adminEmail, setAdminEmail] = useState("");
  const [plan, setPlan] = useState("");
  const [modules, setModules] = useState<ModuleKey[]>([]);
  const [kind, setKind] = useState<"customer" | "msp">("customer");
  const [maxClients, setMaxClients] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const maxBad = kind === "msp" && maxClients.trim() !== "" && !/^\d{1,6}$/.test(maxClients.trim());

  function close() {
    setKind("customer");
    setMaxClients("");
    setName("");
    setSlug("");
    setContact("");
    setAdminEmail("");
    setPlan("");
    setModules([]);
    setErr(null);
    onClose();
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const r = await orgApi.createOrg({
        name: name.trim(),
        slug: slug.trim() || undefined,
        contact_email: contact.trim() || undefined,
        plan: plan.trim() || undefined,
        admin_email: adminEmail.trim(),
        modules,
        kind,
        max_clients: kind === "msp" && maxClients.trim() ? Number(maxClients.trim()) : undefined,
      });
      onCreated(r.invitation);
      close();
    } catch (ex) {
      setErr(errMsg(ex));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={close} title="New organisation">
      <form className="space-y-3" onSubmit={submit}>
        <ErrorNote error={err} />
        <div>
          <label htmlFor="no-kind" className="mb-1 block text-sm font-medium text-ink-2">Kind</label>
          <select id="no-kind" value={kind} onChange={(e) => setKind(e.target.value as "customer" | "msp")}
            className="block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink">
            <option value="customer">Customer</option>
            <option value="msp">MSP (partner)</option>
          </select>
          {kind === "msp" && <p className="mt-1 text-xs text-ink-3">An MSP creates and manages its own client organisations.</p>}
        </div>
        {kind === "msp" && (
          <Field label="Maximum clients (optional)" id="no-max" inputMode="numeric" value={maxClients} placeholder="No limit"
            error={maxBad ? "Enter a whole number, or leave it empty for no limit." : null} onChange={(e) => setMaxClients(e.target.value)} />
        )}
        <Field label="Name" id="no-name" required maxLength={128} value={name} onChange={(e) => setName(e.target.value)} />
        <Field label="Short name (optional)" id="no-slug" maxLength={64} placeholder="derived from the name" value={slug}
          hint="Lowercase letters, digits and -; unique on the platform." onChange={(e) => setSlug(e.target.value)} />
        <Field label="Contact email (optional)" id="no-contact" type="email" value={contact} onChange={(e) => setContact(e.target.value)} />
        <Field label="Plan (optional)" id="no-plan" maxLength={32} value={plan} onChange={(e) => setPlan(e.target.value)} />
        <Field label="First administrator's email" id="no-admin" type="email" required value={adminEmail}
          hint="They receive a single-use invitation to set their password, then invite their team."
          onChange={(e) => setAdminEmail(e.target.value)} />
        <fieldset>
          <legend className="mb-1 block text-sm font-medium text-ink-2">Modules</legend>
          <div className="space-y-1.5">
            {MODULE_KEYS.map((m) => (
              <label key={m} className="flex items-start gap-2 text-sm">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={modules.includes(m)}
                  onChange={(e) => setModules(e.target.checked ? [...modules, m] : modules.filter((x) => x !== m))}
                />
                <span>
                  {MODULES[m].label}
                  <span className="block text-xs text-ink-3">{MODULES[m].description}</span>
                </span>
              </label>
            ))}
          </div>
          <p className="mt-1 text-xs text-ink-3">Switch on what they have bought. You can change this at any time.</p>
        </fieldset>
        <div className="flex justify-end gap-2 pt-2">
          <Button onClick={close}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy || maxBad || !name.trim() || !adminEmail.trim()}>
            {busy ? "Creating…" : "Create and invite"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function OrgDrawer({ orgId, msps, onClose, onChanged }: { orgId: string | null; msps: PlatformOrg[]; onClose: () => void; onChanged: () => void }) {
  const { data: org, error, reload } = useApi(() => (orgId ? orgApi.platformOrg(orgId) : Promise.resolve(null)), [orgId]);
  const [err, setErr] = useState<string | null>(null);
  const [issued, setIssued] = useState<IssuedInvitation | null>(null);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("admin");
  const [busy, setBusy] = useState(false);
  const { organization, refresh } = useAuth();

  async function act(fn: () => Promise<unknown>) {
    setErr(null);
    setBusy(true);
    try {
      const r = await fn();
      // The platform owner's own organisation: the sidebar's locks follow the change.
      if (orgId && orgId === organization?.id) await refresh();
      if (r && typeof r === "object" && "invitation" in r && "emailed" in r) setIssued(r as IssuedInvitation);
      reload();
      onChanged();
    } catch (ex) {
      setErr(errMsg(ex));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Drawer open={!!orgId} onClose={() => { setIssued(null); onClose(); }} title={org ? org.name : "Organisation"}>
      <ErrorNote error={error ?? err} />
      {issued && <InviteResult issued={issued} onDismiss={() => setIssued(null)} />}
      {org && (
        <div className="space-y-5 text-sm">
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1">
            <dt className="text-ink-3">Short name</dt>
            <dd><code>{org.slug}</code></dd>
            <dt className="text-ink-3">Status</dt>
            <dd>{org.status === "active" ? <Tag tone="good">Active</Tag> : <Tag tone="critical">Suspended</Tag>}</dd>
            {org.suspended_reason && (
              <>
                <dt className="text-ink-3">Reason</dt>
                <dd>{org.suspended_reason}</dd>
              </>
            )}
            <dt className="text-ink-3">Contact</dt>
            <dd>{org.contact_email ?? "—"}</dd>
            <dt className="text-ink-3">Plan</dt>
            <dd>{org.plan ?? "—"}</dd>
            <dt className="text-ink-3">Created</dt>
            <dd>{fmtTime(org.created_at)}{org.created_by ? ` by ${org.created_by}` : ""}</dd>
            <dt className="text-ink-3">Usage</dt>
            <dd>
              {org.usage.users} users · {org.usage.devices} devices · {org.usage.assets} assets · {org.usage.scans} scans
            </dd>
          </dl>
          {!org.is_default && (
            <div className="flex gap-2">
              {org.status === "active" ? (
                <Button
                  variant="danger"
                  disabled={busy}
                  onClick={() => {
                    const reason = window.prompt(`Suspend ${org.name}? Its users are signed out, agents and sensors are refused. Reason:`);
                    if (reason !== null) void act(() => orgApi.suspendOrg(org.id, reason));
                  }}
                >
                  Suspend
                </Button>
              ) : (
                <Button disabled={busy} onClick={() => void act(() => orgApi.activateOrg(org.id))}>
                  Reactivate
                </Button>
              )}
            </div>
          )}
          {!org.is_default && (
            <PartnershipSection key={`${org.id}-${org.kind}-${org.partner_org_id}-${org.max_clients}`} org={org} msps={msps} busy={busy}
              onSavePartner={(id) => act(() => orgApi.setOrgPartner(org.id, id))}
              onSaveMax={(n) => act(() => orgApi.setOrgMaxClients(org.id, n))} />
          )}
          <ModulesSection key={org.id} orgId={org.id} modules={org.modules} busy={busy}
            onSave={async (changes) => { await act(async () => { for (const [m, enabled] of changes) await orgApi.setOrgModule(org.id, m, enabled); }); }} />
          <section>
            <h3 className="mb-2 font-semibold">Members</h3>
            {org.members.length ? (
              <ul className="space-y-1">
                {org.members.map((m) => (
                  <li key={m.id} className="flex justify-between gap-2">
                    <span>{m.email}{!m.is_active && <span className="ml-2 text-xs text-ink-3">(deactivated)</span>}</span>
                    <span className="text-ink-3">{ROLE_LABEL[m.role]} · {m.last_login_at ? fmtAgo(m.last_login_at) : "never signed in"}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-ink-3">Nobody has accepted an invitation yet.</p>
            )}
          </section>
          <section>
            <h3 className="mb-2 font-semibold">Invitations</h3>
            {org.invitations.length ? (
              <ul className="space-y-2">
                {org.invitations.map((i) => (
                  <li key={i.id} className="flex flex-wrap items-center justify-between gap-2">
                    <span>
                      {i.email} <span className="text-ink-3">({ROLE_LABEL[i.role]})</span>
                    </span>
                    <span className="flex items-center gap-2">
                      <InvitationStateTag state={i.state} />
                      {(i.state === "pending" || i.state === "expired") && org.status === "active" && (
                        <Button disabled={busy} onClick={() => void act(() => orgApi.platformResend(org.id, i.id))}>
                          Resend
                        </Button>
                      )}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-ink-3">None.</p>
            )}
            {org.status === "active" && (
              <form
                className="mt-3 flex flex-wrap items-end gap-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  void act(async () => {
                    const r = await orgApi.platformInvite(org.id, email.trim(), role);
                    setEmail("");
                    return r;
                  });
                }}
              >
                <div className="min-w-48 flex-1">
                  <Field label="Invite someone" id="pi-email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
                </div>
                <select aria-label="Role" value={role} onChange={(e) => setRole(e.target.value as Role)}
                  className="rounded border border-line bg-surface-2 px-2 py-1.5 text-sm text-ink">
                  {(["admin", "analyst", "viewer"] as Role[]).map((r) => (
                    <option key={r} value={r}>{ROLE_LABEL[r]}</option>
                  ))}
                </select>
                <Button type="submit" disabled={busy || !email.trim()}>Invite</Button>
              </form>
            )}
          </section>
        </div>
      )}
    </Drawer>
  );
}

export default function Organizations() {
  const { data: orgs, error, reload } = useApi(orgApi.platformOrgs, []);
  const { data: mail } = useApi(orgApi.platformMail, []);
  const [creating, setCreating] = useState(false);
  const [issued, setIssued] = useState<IssuedInvitation | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const msps = useMemo(() => (orgs ?? []).filter((o) => o.kind === "msp"), [orgs]);
  const mspName = useMemo(() => new Map((orgs ?? []).filter((o) => o.kind === "msp").map((o) => [o.id, o.name])), [orgs]);
  const sorted = useSort(
    orgs,
    {
      organisation: (o) => o.name,
      status: (o) => (o.status === "active" ? 0 : 1),
      modules: (o) => o.modules.length,
      clients: (o) => o.clients,
      users: (o) => o.usage.users,
      devices: (o) => o.usage.devices,
      assets: (o) => o.usage.assets,
      invitations: (o) => o.pending_invitations,
      created: (o) => ts(o.created_at),
    },
    { key: "organisation", dir: "asc" },
    { modules: "desc", clients: "desc", users: "desc", devices: "desc", assets: "desc", invitations: "desc", created: "desc" },
  );

  return (
    <div>
      <PageHeader
        title="Organisations"
        subtitle="Every customer and partner on the platform. Each only sees its own data."
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            New organisation
          </Button>
        }
      />
      <ErrorNote error={error} />
      {mail && !mail.configured && (
        <p className="mb-3 text-xs text-ink-3">
          Platform email isn't set up yet, so invitation links are shown here for you to send.
        </p>
      )}
      {issued && <InviteResult issued={issued} onDismiss={() => setIssued(null)} />}
      <Card>
        <Table
          tableId="organizations"
          head={[
            { label: "Organisation", sort: "organisation", w: 250 },
            { label: "Status", sort: "status", w: 110 },
            { label: "Modules", sort: "modules", w: 330 },
            { label: "Clients", sort: "clients", w: 90, align: "right" },
            { label: "People", sort: "users", w: 90, align: "right" },
            { label: "Computers", sort: "devices", w: 110, align: "right" },
            { label: "Cloud resources", sort: "assets", w: 140, align: "right" },
            { label: "Invites", sort: "invitations", w: 90, align: "right" },
            { label: "Created", sort: "created", w: 130 },
          ]}
          sort={sorted.sort}
          onSort={sorted.onSort}
          noun="organisations"
          pageSize={50}
        >
          {sorted.rows.map((o: PlatformOrg) => (
            <tr key={o.id} className="cursor-pointer hover:bg-surface-2" onClick={() => setOpen(o.id)}>
              <td className="px-3 py-2">
                <NameCell name={o.name} sub={`${o.slug}${o.kind === "msp" ? " · MSP (partner)" : ""}${o.is_default ? " · default" : ""}${o.plan ? ` · ${o.plan}` : ""}${o.partner_org_id ? ` · managed by ${mspName.get(o.partner_org_id) ?? "an MSP"}` : ""}`} onOpen={() => setOpen(o.id)} />
              </td>
              <td className="px-3 py-2"><PillRow>{o.status === "active" ? <Pill tone="good">Active</Pill> : <Pill tone="critical">Suspended</Pill>}</PillRow></td>
              <td className="px-3 py-2"><ModuleChips modules={o.modules} /></td>
              <td className="px-3 py-2"><NumCell value={o.kind === "msp" ? o.clients : null} title={o.max_clients != null ? `Limit ${o.max_clients}` : undefined} /></td>
              <td className="px-3 py-2"><NumCell value={o.usage.users} /></td>
              <td className="px-3 py-2"><NumCell value={o.usage.devices} /></td>
              <td className="px-3 py-2"><NumCell value={o.usage.assets} /></td>
              <td className="px-3 py-2"><NumCell value={o.pending_invitations} /></td>
              <td className="px-3 py-2"><TextCell muted title={fmtTime(o.created_at)}>{fmtTime(o.created_at).split(",")[0]}</TextCell></td>
            </tr>
          ))}
        </Table>
      </Card>
      <CreateOrgDialog open={creating} onClose={() => setCreating(false)} onCreated={(i) => { setIssued(i); reload(); }} />
      <OrgDrawer orgId={open} msps={msps} onClose={() => setOpen(null)} onChanged={reload} />
    </div>
  );
}
