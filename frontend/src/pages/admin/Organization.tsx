import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { ApiError, type Role } from "../../api";
import { ROLE_LABEL, useAuth } from "../../auth/context";
import { InvitationStateTag, InviteResult } from "../../components/org";
import { Button, Card, ErrorNote, Field, PageHeader, Stat, Table } from "../../components/ui";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { orgApi, type IssuedInvitation } from "../../orgApi";

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

export default function OrganizationPage() {
  const { organization } = useAuth();
  return (
    <div className="space-y-4">
      <PageHeader
        title="Organisation"
        subtitle={`Settings of ${organization?.name ?? "your organisation"}. Everything here applies to this organisation only. Cloud accounts are connected on Connectors & scans.`}
      />
      <Profile />
      <Invitations />
    </div>
  );
}
