import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { ApiError, type Role } from "../../api";
import { ROLE_LABEL, useAuth } from "../../auth/context";
import { CopyField, InvitationStateTag, InviteResult } from "../../components/org";
import { Button, Card, ErrorNote, Field, PageHeader, Stat, Table, Tag } from "../../components/ui";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { orgApi, type ConnectorConfig, type IssuedInvitation, type Provider } from "../../orgApi";

const ROLES: Role[] = ["viewer", "analyst", "admin"];

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : String(e);
}

function Profile() {
  const { refresh } = useAuth();
  const { data: org, error, reload } = useApi(orgApi.organization, []);
  const { data: usage } = useApi(orgApi.usage, []);
  const [name, setName] = useState("");
  const [contact, setContact] = useState("");
  const [logo, setLogo] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!org) return;
    setName(org.name);
    setContact(org.contact_email ?? "");
    setLogo(org.logo_url ?? "");
  }, [org]);

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    setMsg(null);
    try {
      await orgApi.updateOrganization({ name: name.trim(), contact_email: contact.trim(), logo_url: logo.trim() });
      setMsg("Saved.");
      reload();
      await refresh();
    } catch (ex) {
      setErr(errMsg(ex));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Profile">
      <ErrorNote error={error ?? err} />
      {msg && <div role="status" className="mb-3 text-sm text-good">{msg}</div>}
      {org && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <form className="space-y-3" onSubmit={save}>
            <Field label="Organisation name" id="org-name" required maxLength={128} value={name} onChange={(e) => setName(e.target.value)} />
            <Field label="Contact email" id="org-contact" type="email" maxLength={320} value={contact}
              hint="Who the platform operator contacts about this organisation." onChange={(e) => setContact(e.target.value)} />
            <Field label="Logo URL (optional)" id="org-logo" type="url" maxLength={1024} placeholder="https://…" value={logo}
              hint="Stored for branding; not displayed yet (the console only loads its own images)." onChange={(e) => setLogo(e.target.value)} />
            <div className="flex items-center gap-3">
              <Button type="submit" variant="primary" disabled={busy || !name.trim()}>
                {busy ? "Saving…" : "Save"}
              </Button>
              <span className="text-xs text-ink-3">
                Short name <code>{org.slug}</code>
                {org.is_default && " · default organisation"}
              </span>
            </div>
          </form>
          {usage && (
            <div className="grid grid-cols-2 gap-3 self-start">
              <Stat label="Users" value={usage.users} />
              <Stat label="Active devices" value={usage.devices} />
              <Stat label="Cloud assets" value={usage.assets} />
              <Stat label="Scans" value={usage.scans} />
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

function Invitations() {
  const { data: invitations, error, reload } = useApi(orgApi.invitations, []);
  const { data: mail } = useApi(orgApi.mailStatus, []);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [issued, setIssued] = useState<IssuedInvitation | null>(null);

  async function act(fn: () => Promise<IssuedInvitation | unknown>) {
    setErr(null);
    setBusy(true);
    try {
      const r = await fn();
      if (r && typeof r === "object" && "invitation" in r) setIssued(r as IssuedInvitation);
      reload();
    } catch (ex) {
      setErr(errMsg(ex));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card
      title="Invite people"
      actions={
        <Link to="/admin/users" className="text-sm text-accent hover:underline">
          Manage users
        </Link>
      }
    >
      <p className="mb-3 text-sm text-ink-2">
        Sign-up is by invitation only. The invited person gets a single-use link to choose their password
        {mail && !mail.configured && " (email is not configured on this platform: you will get the link to send yourself)"}.
      </p>
      <ErrorNote error={error ?? err} />
      {issued && <InviteResult issued={issued} onDismiss={() => setIssued(null)} />}
      <form
        className="mb-4 flex flex-wrap items-end gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          void act(async () => {
            const r = await orgApi.invite(email.trim(), role);
            setEmail("");
            return r;
          });
        }}
      >
        <div className="min-w-64 flex-1">
          <Field label="Email" id="inv-email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div>
          <label htmlFor="inv-role" className="mb-1 block text-sm font-medium text-ink-2">
            Role
          </label>
          <select id="inv-role" value={role} onChange={(e) => setRole(e.target.value as Role)}
            className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {ROLE_LABEL[r]}
              </option>
            ))}
          </select>
        </div>
        <Button type="submit" variant="primary" disabled={busy || !email.trim()}>
          Send invitation
        </Button>
      </form>
      {!!invitations?.length && (
        <Table head={["Email", "Role", "Status", "Invited", "Expires", "Actions"]}>
          {invitations.map((i) => (
            <tr key={i.id}>
              <td className="px-3 py-2">
                <div className="text-ink">{i.email}</div>
                {i.invited_by && <div className="text-xs text-ink-3">by {i.invited_by}</div>}
              </td>
              <td className="px-3 py-2">{ROLE_LABEL[i.role]}</td>
              <td className="px-3 py-2">
                <InvitationStateTag state={i.state} />
              </td>
              <td className="px-3 py-2 text-xs text-ink-2">{fmtAgo(i.created_at)}</td>
              <td className="px-3 py-2 text-xs text-ink-2">{i.state === "pending" || i.state === "expired" ? fmtTime(i.expires_at) : "—"}</td>
              <td className="px-3 py-2">
                {(i.state === "pending" || i.state === "expired") && (
                  <div className="flex gap-2">
                    <Button disabled={busy} title="New link (the previous one stops working)" onClick={() => void act(() => orgApi.resendInvitation(i.id))}>
                      Resend
                    </Button>
                    <Button variant="danger" disabled={busy} onClick={() => void act(() => orgApi.revokeInvitation(i.id))}>
                      Revoke
                    </Button>
                  </div>
                )}
              </td>
            </tr>
          ))}
        </Table>
      )}
    </Card>
  );
}

function IngestTokens() {
  const { data: tokens, error, reload } = useApi(orgApi.ingestTokens, []);
  const [name, setName] = useState("");
  const [created, setCreated] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function create(e: FormEvent) {
    e.preventDefault();
    setErr(null);
    try {
      const t = await orgApi.createIngestToken(name.trim());
      setCreated(t.token);
      setName("");
      reload();
    } catch (ex) {
      setErr(errMsg(ex));
    }
  }

  return (
    <Card title="Runtime sensor tokens">
      <p className="mb-3 text-sm text-ink-2">
        Your Linux runtime sensors send events and package inventory with one of these tokens (<code>SENSOR_API_TOKEN</code>); the data
        lands in this organisation only.
      </p>
      <ErrorNote error={error ?? err} />
      {created && (
        <div role="status" className="mb-3 space-y-2 rounded border border-good/60 bg-good/10 px-3 py-2 text-sm">
          <div>New token (shown once; store it in your sensor configuration):</div>
          <CopyField value={created} label="Sensor token" />
        </div>
      )}
      <form className="mb-4 flex flex-wrap items-end gap-3" onSubmit={create}>
        <div className="min-w-64 flex-1">
          <Field label="Name" id="tok-name" required maxLength={128} placeholder="e.g. production Kubernetes" value={name}
            onChange={(e) => setName(e.target.value)} />
        </div>
        <Button type="submit" variant="primary" disabled={!name.trim()}>
          Create token
        </Button>
      </form>
      {!!tokens?.length && (
        <Table head={["Name", "Token", "Created", "Last used", "Status", ""]}>
          {tokens.map((t) => (
            <tr key={t.id}>
              <td className="px-3 py-2 text-ink">{t.name}</td>
              <td className="px-3 py-2 font-mono text-xs">{t.token_prefix}…</td>
              <td className="px-3 py-2 text-xs text-ink-2">{fmtTime(t.created_at)}</td>
              <td className="px-3 py-2 text-xs text-ink-2">{t.last_used_at ? fmtAgo(t.last_used_at) : "Never"}</td>
              <td className="px-3 py-2">{t.revoked_at ? <Tag>Revoked</Tag> : <Tag tone="good">Active</Tag>}</td>
              <td className="px-3 py-2">
                {!t.revoked_at && (
                  <Button
                    variant="danger"
                    onClick={() => {
                      if (window.confirm(`Revoke "${t.name}"? Sensors using it are refused immediately.`))
                        void orgApi.revokeIngestToken(t.id).then(reload, (ex) => setErr(errMsg(ex)));
                    }}
                  >
                    Revoke
                  </Button>
                )}
              </td>
            </tr>
          ))}
        </Table>
      )}
    </Card>
  );
}

const PROVIDERS: { provider: Provider; label: string; doc: string; fields: { name: string; label: string; list?: boolean; hint?: string }[]; secrets: { name: string; label: string; multiline?: boolean }[] }[] = [
  {
    provider: "azure",
    label: "Azure",
    doc: "App registration with the built-in Reader role on each subscription.",
    fields: [
      { name: "tenant_id", label: "Tenant ID" },
      { name: "client_id", label: "Client (application) ID" },
      { name: "subscription_ids", label: "Subscription IDs", list: true, hint: "Comma-separated." },
    ],
    secrets: [{ name: "client_secret", label: "Client secret" }],
  },
  {
    provider: "aws",
    label: "AWS",
    doc: "Read-only IAM user (SecurityAudit + ViewOnlyAccess), optionally assuming a role in each account.",
    fields: [
      { name: "access_key_id", label: "Access key ID" },
      { name: "role_arns", label: "Role ARNs (cross-account)", list: true, hint: "Comma-separated; empty: the key's own account." },
      { name: "external_id", label: "External ID" },
      { name: "regions", label: "Regions", list: true, hint: "Comma-separated; empty: every enabled region." },
      { name: "home_region", label: "Home region", hint: "Default us-east-1." },
    ],
    secrets: [{ name: "secret_access_key", label: "Secret access key" }],
  },
  {
    provider: "gcp",
    label: "GCP",
    doc: "Service account with roles/viewer and roles/iam.securityReviewer.",
    fields: [
      { name: "project_ids", label: "Project IDs", list: true, hint: "Comma-separated." },
      { name: "organization_id", label: "Organization ID (numeric)", hint: "Discover every project under it." },
    ],
    secrets: [{ name: "credentials_json", label: "Service-account key (JSON)", multiline: true }],
  },
];

function ConnectorForm({ spec, current, onSaved }: { spec: (typeof PROVIDERS)[number]; current: ConnectorConfig | undefined; onSaved: () => void }) {
  const [values, setValues] = useState<Record<string, string>>({});
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [enabled, setEnabled] = useState(true);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    const v: Record<string, string> = {};
    for (const f of spec.fields) {
      const cur = current?.config?.[f.name];
      v[f.name] = Array.isArray(cur) ? cur.join(", ") : (cur ?? "");
    }
    setValues(v);
    setSecrets({});
    setEnabled(current?.stored ? current.enabled : true);
  }, [current, spec]);

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    setMsg(null);
    try {
      const config: Record<string, unknown> = {};
      for (const f of spec.fields) {
        const raw = values[f.name] ?? "";
        config[f.name] = f.list ? raw.split(/[\s,;]+/).filter(Boolean) : raw.trim();
      }
      const sec = Object.fromEntries(Object.entries(secrets).filter(([, v]) => v !== ""));
      await orgApi.saveConnector(spec.provider, { enabled, config, secrets: sec });
      setMsg("Saved. Run a scan from Connectors & scans.");
      onSaved();
    } catch (ex) {
      setErr(errMsg(ex));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!window.confirm(`Remove the stored ${spec.label} settings and secrets?`)) return;
    try {
      await orgApi.deleteConnector(spec.provider);
      onSaved();
    } catch (ex) {
      setErr(errMsg(ex));
    }
  }

  return (
    <form className="space-y-3" onSubmit={save}>
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold">{spec.label}</h3>
        {current?.stored ? (current.enabled ? <Tag tone="good">Configured</Tag> : <Tag>Disabled</Tag>) : current?.from_environment ? (
          <Tag tone="accent">From server environment</Tag>
        ) : (
          <Tag>Not configured</Tag>
        )}
      </div>
      <p className="text-xs text-ink-3">{spec.doc}</p>
      {current?.from_environment && (
        <p className="text-xs text-ink-2">The server's environment configures this provider. Settings saved here replace it for your organisation.</p>
      )}
      <ErrorNote error={err} />
      {msg && <div role="status" className="text-sm text-good">{msg}</div>}
      {spec.fields.map((f) => (
        <Field key={f.name} label={f.label} id={`${spec.provider}-${f.name}`} hint={f.hint} value={values[f.name] ?? ""}
          onChange={(e) => setValues((v) => ({ ...v, [f.name]: e.target.value }))} />
      ))}
      {spec.secrets.map((s) => {
        const hint = current?.secrets?.[s.name];
        const id = `${spec.provider}-${s.name}`;
        return (
          <div key={s.name}>
            <label htmlFor={id} className="mb-1 block text-sm font-medium text-ink-2">
              {s.label}
            </label>
            {s.multiline ? (
              <textarea id={id} rows={4} spellCheck={false} value={secrets[s.name] ?? ""}
                placeholder={hint ? `Stored (${hint}). Paste a new key to replace it.` : "Paste the key file contents"}
                onChange={(e) => setSecrets((v) => ({ ...v, [s.name]: e.target.value }))}
                className="block w-full rounded border border-line bg-surface-2 px-3 py-1.5 font-mono text-xs text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40" />
            ) : (
              <input id={id} type="password" autoComplete="new-password" value={secrets[s.name] ?? ""}
                placeholder={hint ? `Stored (${hint}). Type to replace.` : ""}
                onChange={(e) => setSecrets((v) => ({ ...v, [s.name]: e.target.value }))}
                className="block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40" />
            )}
            <p className="mt-1 text-xs text-ink-3">Encrypted at rest and never shown again.</p>
          </div>
        );
      })}
      <label className="flex items-center gap-2 text-sm text-ink-2">
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        Enabled
      </label>
      <div className="flex gap-2">
        <Button type="submit" variant="primary" disabled={busy}>
          {busy ? "Saving…" : "Save"}
        </Button>
        {current?.stored && (
          <Button variant="danger" onClick={() => void remove()}>
            Remove
          </Button>
        )}
      </div>
    </form>
  );
}

function Connectors() {
  const { data, error, reload } = useApi(orgApi.connectors, []);
  return (
    <Card title="Cloud connectors">
      <p className="mb-3 text-sm text-ink-2">
        Read-only credentials your organisation's scans use. Scans and the schedule are on{" "}
        <Link to="/connectors" className="text-accent hover:underline">
          Connectors &amp; scans
        </Link>
        .
      </p>
      <ErrorNote error={error} />
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        {PROVIDERS.map((p) => (
          <div key={p.provider} className="rounded-lg border border-line p-4">
            <ConnectorForm spec={p} current={data?.find((c) => c.provider === p.provider)} onSaved={reload} />
          </div>
        ))}
      </div>
    </Card>
  );
}

export default function OrganizationPage() {
  const { organization } = useAuth();
  return (
    <div className="space-y-4">
      <PageHeader title="Organisation" subtitle={`Settings of ${organization?.name ?? "your organisation"}. Everything here applies to this organisation only.`} />
      <Profile />
      <Invitations />
      <IngestTokens />
      <Connectors />
    </div>
  );
}
