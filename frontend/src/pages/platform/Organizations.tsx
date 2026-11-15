import { useState, type FormEvent } from "react";
import { ApiError, type ModuleKey, type Role } from "../../api";
import { ROLE_LABEL, useAuth } from "../../auth/context";
import { InvitationStateTag, InviteResult } from "../../components/org";
import { Button, Card, Drawer, ErrorNote, Field, Modal, PageHeader, Table, Tag } from "../../components/ui";
import { fmtAgo, fmtTime } from "../../lib/format";
import { MODULES, MODULE_KEYS } from "../../lib/modules";
import { useApi } from "../../lib/useApi";
import { orgApi, type IssuedInvitation, type PlatformOrg } from "../../orgApi";

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : String(e);
}

/** Product modules of an organisation as chips (the platform owner's at-a-glance view). */
function ModuleChips({ modules }: { modules: ModuleKey[] }) {
  if (modules.length === 0) return <span className="text-xs text-ink-3">None</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {modules.map((m) => (
        <Tag key={m} tone="accent">
          {MODULES[m].label}
        </Tag>
      ))}
    </span>
  );
}

function ModuleSwitch({ on, label, disabled, onChange }: { on: boolean; label: string; disabled?: boolean; onChange: (next: boolean) => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!on)}
      className={`relative h-5 w-9 shrink-0 rounded-full transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-50 ${
        on ? "bg-accent" : "bg-line"
      }`}
    >
      <span aria-hidden className={`absolute left-0.5 top-0.5 h-4 w-4 rounded-full bg-white shadow transition-transform ${on ? "translate-x-4" : ""}`} />
    </button>
  );
}

/** The four product modules of an organisation. Turning one on applies at once; turning one off asks first. */
function ModulesSection({ orgId, modules, busy, onSet }: { orgId: string; modules: ModuleKey[]; busy: boolean; onSet: (m: ModuleKey, enabled: boolean) => void }) {
  const [confirming, setConfirming] = useState<ModuleKey | null>(null);
  const has = (m: ModuleKey) => modules.includes(m);
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
              </div>
              <ModuleSwitch
                on={has(m)}
                label={MODULES[m].label}
                disabled={busy}
                onChange={(next) => {
                  if (next) {
                    setConfirming(null);
                    onSet(m, true);
                  } else {
                    setConfirming(m);
                  }
                }}
              />
            </div>
            {confirming === m && (
              <div role="alert" className="mt-2 rounded border border-sev-high/60 bg-sev-high/10 p-3 text-xs">
                <p className="font-medium text-ink">Turn off {MODULES[m].label}?</p>
                <p className="mt-1 text-ink-2">{MODULES[m].stops}</p>
                <p className="mt-1 text-ink-2">Their data is kept. Turning the module back on shows it again.</p>
                <div className="mt-2 flex gap-2">
                  <Button
                    variant="danger"
                    disabled={busy}
                    onClick={() => {
                      setConfirming(null);
                      onSet(m, false);
                    }}
                  >
                    Turn off
                  </Button>
                  <Button onClick={() => setConfirming(null)}>Keep on</Button>
                </div>
              </div>
            )}
          </li>
        ))}
      </ul>
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
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  function close() {
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
          <Button type="submit" variant="primary" disabled={busy || !name.trim() || !adminEmail.trim()}>
            {busy ? "Creating…" : "Create and invite"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function OrgDrawer({ orgId, onClose, onChanged }: { orgId: string | null; onClose: () => void; onChanged: () => void }) {
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
          <ModulesSection orgId={org.id} modules={org.modules} busy={busy} onSet={(m, enabled) => void act(() => orgApi.setOrgModule(org.id, m, enabled))} />
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

  return (
    <div>
      <PageHeader
        title="Organisations"
        subtitle="Platform console: every organisation on this platform. Each one only ever sees its own data."
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            New organisation
          </Button>
        }
      />
      <ErrorNote error={error} />
      {mail && !mail.configured && (
        <p className="mb-3 text-xs text-ink-3">
          Platform email is not configured (PLATFORM_SMTP_*): invitation links are shown here for you to send.
        </p>
      )}
      {issued && <InviteResult issued={issued} onDismiss={() => setIssued(null)} />}
      <Card>
        <Table head={["Organisation", "Status", "Modules", "Users", "Devices", "Assets", "Pending invitations", "Created"]}>
          {orgs?.map((o: PlatformOrg) => (
            <tr key={o.id} className="cursor-pointer hover:bg-surface-2" onClick={() => setOpen(o.id)}>
              <td className="px-3 py-2">
                <button className="text-left font-medium text-ink hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  onClick={(e) => { e.stopPropagation(); setOpen(o.id); }}>
                  {o.name}
                </button>
                <div className="text-xs text-ink-3">
                  {o.slug}
                  {o.is_default && " · default"}
                  {o.plan && ` · ${o.plan}`}
                </div>
              </td>
              <td className="px-3 py-2">{o.status === "active" ? <Tag tone="good">Active</Tag> : <Tag tone="critical">Suspended</Tag>}</td>
              <td className="px-3 py-2"><ModuleChips modules={o.modules} /></td>
              <td className="px-3 py-2">{o.usage.users}</td>
              <td className="px-3 py-2">{o.usage.devices}</td>
              <td className="px-3 py-2">{o.usage.assets}</td>
              <td className="px-3 py-2">{o.pending_invitations || "—"}</td>
              <td className="px-3 py-2 text-xs text-ink-2">{fmtTime(o.created_at)}</td>
            </tr>
          ))}
        </Table>
      </Card>
      <CreateOrgDialog open={creating} onClose={() => setCreating(false)} onCreated={(i) => { setIssued(i); reload(); }} />
      <OrgDrawer orgId={open} onClose={() => setOpen(null)} onChanged={reload} />
    </div>
  );
}
