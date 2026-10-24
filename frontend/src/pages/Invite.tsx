import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError } from "../api";
import { ROLE_LABEL, useAuth } from "../auth/context";
import { Button, Field } from "../components/ui";
import { isSignInRequired, orgApi, type InvitationInfo } from "../orgApi";

const MIN_PASSWORD = 12;

/** Accept an invitation: /invite#token=cnv_... (the token stays in the fragment, never sent in a URL). */
export default function Invite() {
  const navigate = useNavigate();
  const { completeLogin } = useAuth();
  const [token] = useState(() => new URLSearchParams(window.location.hash.replace(/^#/, "")).get("token") ?? "");
  const [info, setInfo] = useState<InvitationInfo | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Keep the one-time token out of the history once read.
    if (window.location.hash) window.history.replaceState(null, "", window.location.pathname);
    if (!token) {
      setLoadError("This invitation link is incomplete. Open the link from your invitation email again.");
      return;
    }
    orgApi.lookupInvitation(token).then(setInfo, (e) =>
      setLoadError(e instanceof ApiError ? e.message : "Could not check the invitation. Try again later."),
    );
  }, [token]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (password.length < MIN_PASSWORD) return setError(`Choose a password of at least ${MIN_PASSWORD} characters.`);
    if (password !== confirm) return setError("The passwords do not match.");
    setBusy(true);
    try {
      const r = await orgApi.acceptInvitation(token, name.trim(), password);
      if (isSignInRequired(r)) {
        navigate("/login", { replace: true, state: { email: r.email, notice: "Account created. Sign in to set up two-step verification." } });
      } else {
        completeLogin(r);
        navigate("/", { replace: true });
      }
    } catch (ex) {
      setError(ex instanceof ApiError ? ex.message : String(ex));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-full items-center justify-center bg-surface-0 px-4 py-10">
      <main className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center text-center">
          <img src="/shield.svg" alt="" className="mb-3 h-8 w-8" />
          <h1 className="text-xl font-semibold text-ink">CloudSecurity</h1>
        </div>
        <div className="rounded-xl border border-line bg-surface-1 p-6 shadow-2xl">
          {loadError && (
            <div className="space-y-3">
              <h2 className="text-base font-semibold text-ink">Invitation unavailable</h2>
              <p role="alert" className="text-sm text-ink-2">
                {loadError} Ask the person who invited you for a new invitation.
              </p>
              <Link to="/login" className="text-sm text-accent hover:underline">
                Go to sign-in
              </Link>
            </div>
          )}
          {!loadError && !info && <p className="text-sm text-ink-3">Checking your invitation…</p>}
          {info && (
            <form className="space-y-4" onSubmit={submit}>
              <div>
                <h2 className="text-base font-semibold text-ink">Join {info.organization}</h2>
                <p className="mt-1 text-sm text-ink-3">
                  You were invited as {ROLE_LABEL[info.role]} with <span className="text-ink-2">{info.email}</span>. Choose your password to
                  create your account.
                </p>
              </div>
              {error && (
                <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
                  {error}
                </div>
              )}
              <Field label="Your name" id="inv-name" autoComplete="name" maxLength={128} value={name} onChange={(e) => setName(e.target.value)} />
              <Field label="Password" id="inv-password" type="password" autoComplete="new-password" required minLength={MIN_PASSWORD}
                hint={`At least ${MIN_PASSWORD} characters.`} value={password} onChange={(e) => setPassword(e.target.value)} />
              <Field label="Repeat password" id="inv-confirm" type="password" autoComplete="new-password" required value={confirm}
                onChange={(e) => setConfirm(e.target.value)} />
              <Button type="submit" variant="primary" disabled={busy || !password || !confirm}>
                {busy ? "Creating your account…" : "Create account"}
              </Button>
              <p className="text-xs text-ink-3">The link works once and expires {new Date(info.expires_at).toLocaleString()}.</p>
            </form>
          )}
        </div>
      </main>
    </div>
  );
}
