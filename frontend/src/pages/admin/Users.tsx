import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { ApiError, api, type Role, type User } from "../../api";
import { ROLE_LABEL, useAuth } from "../../auth/context";
import { Button, Card, ErrorNote, Field, Modal, NameCell, PageHeader, Pill, PillRow, Table, TextCell } from "../../components/ui";
import { fmtAgo, fmtTime } from "../../lib/format";
import { PAGE_INFO } from "../../lib/pageInfo";
import { useApi } from "../../lib/useApi";
import { rankOf, ts, useSort } from "../../lib/useSort";

const ROLES: Role[] = ["viewer", "analyst", "admin"];
const MIN_PASSWORD = 12;

const ROLE_HELP: Record<Role, string> = {
  viewer: "Read-only access to all dashboards and data.",
  analyst: "Viewer, plus suppress/resolve findings and alerts and run scans.",
  admin: "Everything, including user management, the audit log and connector settings.",
};

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : String(e);
}

function CreateUserDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function close() {
    setEmail("");
    setName("");
    setRole("viewer");
    setPassword("");
    setError(null);
    onClose();
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (password.length < MIN_PASSWORD) return setError(`Password must be at least ${MIN_PASSWORD} characters.`);
    setBusy(true);
    setError(null);
    try {
      await api.createUser({ email: email.trim(), name: name.trim(), role, password });
      onCreated();
      close();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={close} title="Add user">
      <form className="space-y-3" onSubmit={submit}>
        {error && (
          <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
            {error}
          </div>
        )}
        <Field label="Email" id="nu-email" type="email" autoComplete="off" required value={email}
          onChange={(e) => setEmail(e.target.value)} />
        <Field label="Name" id="nu-name" autoComplete="off" value={name} onChange={(e) => setName(e.target.value)} />
        <div>
          <label htmlFor="nu-role" className="mb-1 block text-sm font-medium text-ink-2">
            Role
          </label>
          <select id="nu-role" value={role} onChange={(e) => setRole(e.target.value as Role)}
            className="block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40">
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {ROLE_LABEL[r]}
              </option>
            ))}
          </select>
          <p className="mt-1 text-xs text-ink-3">{ROLE_HELP[role]}</p>
        </div>
        <Field label="Initial password" id="nu-password" type="password" autoComplete="new-password" required
          minLength={MIN_PASSWORD} hint={`At least ${MIN_PASSWORD} characters. Share it securely; the user can change it after signing in.`}
          value={password} onChange={(e) => setPassword(e.target.value)} />
        <div className="flex justify-end gap-2 pt-2">
          <Button onClick={close}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy || !email || !password}>
            {busy ? "Creating…" : "Create user"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function ResetPasswordDialog({ user, onClose, onDone }: { user: User | null; onClose: () => void; onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function close() {
    setPassword("");
    setError(null);
    onClose();
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!user) return;
    if (password.length < MIN_PASSWORD) return setError(`Password must be at least ${MIN_PASSWORD} characters.`);
    setBusy(true);
    try {
      await api.resetPassword(user.id, password);
      onDone();
      close();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={!!user} onClose={close} title={`Reset password${user ? ` for ${user.email}` : ""}`}>
      <form className="space-y-3" onSubmit={submit}>
        <p className="text-sm text-ink-2">
          Sets a new password, unlocks the account and signs the user out of all sessions.
        </p>
        {error && (
          <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
            {error}
          </div>
        )}
        <Field label="New password" id="rp-password" type="password" autoComplete="new-password" required
          minLength={MIN_PASSWORD} hint={`At least ${MIN_PASSWORD} characters.`}
          value={password} onChange={(e) => setPassword(e.target.value)} />
        <div className="flex justify-end gap-2 pt-2">
          <Button onClick={close}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy || !password}>
            {busy ? "Saving…" : "Reset password"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function DeleteUserDialog({ user, onClose, onDeleted }: { user: User | null; onClose: () => void; onDeleted: (email: string) => void }) {
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const matches = !!user && confirm.trim().toLowerCase() === user.email.toLowerCase();

  function close() {
    setConfirm("");
    setError(null);
    onClose();
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!user || !matches) return;
    setBusy(true);
    setError(null);
    try {
      await api.deleteUser(user.id);
      onDeleted(user.email);
      close();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={!!user} onClose={close} title="Delete user">
      {user && (
        <form className="space-y-3" onSubmit={submit}>
          <div className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
            Permanently deletes <span className="font-medium">{user.email}</span>: the account, its organisation
            membership, sessions, two-step verification and Microsoft sign-in links, and pending invitations for this
            address. This cannot be undone.
          </div>
          <p className="text-sm text-ink-2">
            The audit log and other history keep the email address. The address can be invited again later.
          </p>
          {error && (
            <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
              {error}
            </div>
          )}
          <Field label={`Type the email "${user.email}" to confirm`} id="du-confirm" autoComplete="off" value={confirm}
            onChange={(e) => setConfirm(e.target.value)} />
          <div className="flex justify-end gap-2 pt-2">
            <Button onClick={close}>Cancel</Button>
            <Button type="submit" variant="danger" disabled={busy || !matches}>
              {busy ? "Deleting…" : "Delete user"}
            </Button>
          </div>
        </form>
      )}
    </Modal>
  );
}

export default function Users() {
  const { user: me } = useAuth();
  const { data: users, error, reload } = useApi(api.users, []);
  const [actionError, setActionError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [resetting, setResetting] = useState<User | null>(null);
  const [deleting, setDeleting] = useState<User | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function update(u: User, patch: Partial<Pick<User, "role" | "is_active">>) {
    setActionError(null);
    setNotice(null);
    try {
      await api.updateUser(u.id, patch);
      reload();
    } catch (e) {
      setActionError(errMsg(e));
    }
  }

  async function resetMfa(u: User) {
    setActionError(null);
    setNotice(null);
    try {
      await api.resetMfa(u.id);
      setNotice(`Two-step verification reset for ${u.email}.`);
      reload();
    } catch (e) {
      setActionError(errMsg(e));
    }
  }

  const locked = (u: User) => !!u.locked_until && new Date(u.locked_until).getTime() > Date.now();
  const roleRank = rankOf(["admin", "analyst", "viewer"]);
  const sorted = useSort(
    users,
    {
      user: (u) => u.name || u.email,
      role: (u) => roleRank(u.role),
      status: (u) => (!u.is_active ? 2 : locked(u) ? 1 : 0),
      signin: (u) => [...u.auth_sources].sort().join(", ") + (u.mfa_enabled ? " MFA on" : " MFA off"),
      last_login: (u) => ts(u.last_login_at),
      created: (u) => ts(u.created_at),
    },
    { key: "user", dir: "asc" },
    { last_login: "desc", created: "desc" },
  );

  return (
    <div>
      <PageHeader
        title="People"
        info={PAGE_INFO.people}
        subtitle="Who can sign in, and what they can do."
        actions={
          <>
            <Link to="/approvals" className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">Approvals</Link>
            <Link to="/admin/organization" className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">Organisation</Link>
            <Button variant="primary" onClick={() => setCreating(true)}>
              Add user
            </Button>
          </>
        }
      />
      <ErrorNote error={error ?? actionError} />
      {notice && (
        <div role="status" className="mb-3 rounded border border-good/60 bg-good/10 px-3 py-2 text-sm">
          {notice}
        </div>
      )}
      <Card>
        <Table
          tableId="users"
          head={[
            { label: "Person", sort: "user", w: 320 },
            { label: "Role", sort: "role", w: 130 },
            { label: "Status", sort: "status", w: 120 },
            { label: "Sign-in", sort: "signin", w: 200 },
            { label: "Last sign-in", sort: "last_login", w: 130 },
            { label: "Added", sort: "created", w: 130 },
            { label: "Actions", srOnly: true, w: 330 },
          ]}
          sort={sorted.sort}
          onSort={sorted.onSort}
          noun="people"
          pageSize={50}
        >
          {sorted.rows.map((u) => {
            const isMe = u.id === me?.id;
            return (
              <tr key={u.id}>
                <td className="px-3 py-2">
                  <NameCell name={`${u.name || u.email}${isMe ? " (you)" : ""}`} sub={u.name ? u.email : undefined} />
                </td>
                <td className="px-3 py-2">
                  <label className="sr-only" htmlFor={`role-${u.id}`}>
                    Role for {u.email}
                  </label>
                  <select
                    id={`role-${u.id}`}
                    value={u.role}
                    disabled={isMe}
                    title={isMe ? "You cannot change your own role" : undefined}
                    onChange={(e) => update(u, { role: e.target.value as Role })}
                    className="rounded border border-line bg-surface-2 px-2 py-1 text-sm text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-60"
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {ROLE_LABEL[r]}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="px-3 py-2">
                  <PillRow>
                    {!u.is_active ? <Pill>Deactivated</Pill> : locked(u) ? <Pill tone="high" title={`Locked until ${fmtTime(u.locked_until!)}`}>Locked</Pill> : <Pill tone="good">Active</Pill>}
                  </PillRow>
                </td>
                <td className="px-3 py-2">
                  <PillRow>
                    {u.auth_sources.includes("entra") && <Pill tone="info">Microsoft</Pill>}
                    {u.auth_sources.includes("password") && <Pill>Password</Pill>}
                    {u.mfa_enabled ? <Pill tone="good" title="Two-step verification is on">MFA</Pill> : <Pill tone="medium" title="Two-step verification is off">No MFA</Pill>}
                  </PillRow>
                </td>
                <td className="px-3 py-2"><TextCell muted>{u.last_login_at ? fmtAgo(u.last_login_at) : "Never"}</TextCell></td>
                <td className="px-3 py-2"><TextCell muted title={fmtTime(u.created_at)}>{fmtTime(u.created_at).split(",")[0]}</TextCell></td>
                <td className="px-3 py-2">
                  <div className="flex flex-wrap gap-2">
                    <Button onClick={() => setResetting(u)}>Reset password</Button>
                    {u.mfa_enabled && (
                      <Button
                        title="Remove the user's authenticator and recovery codes (lost device)"
                        onClick={() => {
                          if (window.confirm(`Reset two-step verification for ${u.email}? They are signed out and must set it up again if their role requires it.`)) resetMfa(u);
                        }}
                      >
                        Reset MFA
                      </Button>
                    )}
                    {u.is_active ? (
                      <Button
                        variant="danger"
                        disabled={isMe}
                        title={isMe ? "You cannot deactivate yourself" : "Sign the user out and block sign-in"}
                        onClick={() => {
                          if (window.confirm(`Deactivate ${u.email}? They will be signed out immediately.`)) update(u, { is_active: false });
                        }}
                      >
                        Deactivate
                      </Button>
                    ) : (
                      <>
                        <Button onClick={() => update(u, { is_active: true })}>Reactivate</Button>
                        <Button
                          variant="danger"
                          title="Permanently delete this deactivated account"
                          onClick={() => {
                            setActionError(null);
                            setNotice(null);
                            setDeleting(u);
                          }}
                        >
                          Delete
                        </Button>
                      </>
                    )}
                  </div>
                </td>
              </tr>
            );
          })}
        </Table>
      </Card>
      <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-3">
        {ROLES.map((r) => (
          <div key={r} className="rounded-lg border border-line bg-surface-1 px-4 py-3">
            <div className="text-sm font-semibold">{ROLE_LABEL[r]}</div>
            <p className="mt-1 text-xs text-ink-2">{ROLE_HELP[r]}</p>
          </div>
        ))}
      </div>
      <CreateUserDialog open={creating} onClose={() => setCreating(false)} onCreated={() => { setNotice("User created."); reload(); }} />
      <DeleteUserDialog
        user={deleting}
        onClose={() => setDeleting(null)}
        onDeleted={(email) => {
          setNotice(`Deleted ${email}. The audit log keeps its history.`);
          reload();
        }}
      />
      <ResetPasswordDialog
        user={resetting}
        onClose={() => setResetting(null)}
        onDone={() => {
          setNotice(`Password reset for ${resetting?.email}.`);
          reload();
        }}
      />
    </div>
  );
}
