import { useState, type FormEvent } from "react";
import { ApiError, api, type Role, type User } from "../../api";
import { ROLE_LABEL, useAuth } from "../../auth/context";
import { Button, Card, ErrorNote, Field, Modal, PageHeader, Table, Tag } from "../../components/ui";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";

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

export default function Users() {
  const { user: me } = useAuth();
  const { data: users, error, reload } = useApi(api.users, []);
  const [actionError, setActionError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [resetting, setResetting] = useState<User | null>(null);
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

  const locked = (u: User) => !!u.locked_until && new Date(u.locked_until).getTime() > Date.now();

  return (
    <div>
      <PageHeader
        title="Users"
        subtitle="Manage who can sign in and what they can do. All changes are recorded in the audit log."
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            Add user
          </Button>
        }
      />
      <ErrorNote error={error ?? actionError} />
      {notice && (
        <div role="status" className="mb-3 rounded border border-good/60 bg-good/10 px-3 py-2 text-sm">
          {notice}
        </div>
      )}
      <Card>
        <Table head={["User", "Role", "Status", "Last sign-in", "Created", "Actions"]}>
          {users?.map((u) => {
            const isMe = u.id === me?.id;
            return (
              <tr key={u.id}>
                <td className="px-3 py-2">
                  <div className="font-medium text-ink">
                    {u.name || u.email}
                    {isMe && <span className="ml-2 text-xs text-ink-3">(you)</span>}
                  </div>
                  <div className="text-xs text-ink-3">{u.email}</div>
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
                  {!u.is_active ? (
                    <Tag>Deactivated</Tag>
                  ) : locked(u) ? (
                    <span title={`Locked until ${fmtTime(u.locked_until!)}`}>
                      <Tag tone="warn">Locked</Tag>
                    </span>
                  ) : (
                    <Tag tone="good">Active</Tag>
                  )}
                </td>
                <td className="px-3 py-2 text-xs text-ink-2">{u.last_login_at ? fmtAgo(u.last_login_at) : "Never"}</td>
                <td className="px-3 py-2 text-xs text-ink-2">{fmtTime(u.created_at)}</td>
                <td className="px-3 py-2">
                  <div className="flex flex-wrap gap-2">
                    <Button onClick={() => setResetting(u)}>Reset password</Button>
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
                      <Button onClick={() => update(u, { is_active: true })}>Reactivate</Button>
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
