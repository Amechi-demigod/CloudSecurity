import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { ApiError, api, isMfaChallenge, type AuthProviders, type LoginComplete, type MfaSetup } from "../api";
import { useAuth } from "../auth/context";
import { RecoveryCodes, TotpSetupDetails, VerifyCodeForm } from "../components/mfa";
import { Button } from "../components/ui";

interface FromState {
  from?: string;
}

function safeRedirect(from: string | undefined | null): string {
  // Only same-app paths; never protocol-relative or absolute URLs.
  if (!from || !from.startsWith("/") || from.startsWith("//") || from.startsWith("/\\") || from.startsWith("/login")) return "/";
  return from;
}

type Step =
  | { kind: "password" }
  | { kind: "verify"; token: string }
  | { kind: "enroll"; token: string; setup: MfaSetup | null }
  | { kind: "codes"; session: LoginComplete };

const SSO_ERRORS: Record<string, string> = {
  not_provisioned: "Your Microsoft account has no access to CloudSecurity yet. Ask an administrator to add you.",
  no_role_assigned: "Your Microsoft account is not assigned a CloudSecurity role. Ask your Entra ID administrator.",
  inactive: "This account is deactivated. Contact an administrator.",
  idp_error: "Microsoft sign-in was cancelled or refused.",
  rate_limited: "Too many sign-in attempts. Please wait a few minutes and try again.",
  idp_unavailable: "Microsoft sign-in is unavailable right now. Try again later.",
};

function ssoErrorMessage(code: string): string {
  return SSO_ERRORS[code] ?? "Microsoft sign-in failed. Please try again.";
}

/** Second step handed over by the SSO callback in the URL fragment (never sent to servers). */
function stepFromHash(hash: string): { step: Step; next: string | null } | null {
  const p = new URLSearchParams(hash.replace(/^#/, ""));
  const token = p.get("mfa_token");
  if (!token) return null;
  const step: Step = p.get("purpose") === "enroll" ? { kind: "enroll", token, setup: null } : { kind: "verify", token };
  return { step, next: p.get("next") };
}

export default function Login() {
  const { user, login, completeLogin, sessionExpired } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [initial] = useState(() => stepFromHash(location.hash));
  const from = safeRedirect(initial?.next ?? (location.state as FromState | null)?.from);
  const [step, setStep] = useState<Step>(initial?.step ?? { kind: "password" });
  const [providers, setProviders] = useState<AuthProviders | null>(null);
  const [breakGlass, setBreakGlass] = useState(false);
  const ssoError = new URLSearchParams(location.search).get("sso_error");

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const emailRef = useRef<HTMLInputElement>(null);
  const errorId = useId();
  const noticeId = useId();

  useEffect(() => {
    emailRef.current?.focus();
    // Drop the one-time token from the address bar / history.
    if (window.location.hash) window.history.replaceState(null, "", window.location.pathname + window.location.search);
  }, []);

  useEffect(() => {
    let cancelled = false;
    api
      .providers()
      .then((p) => !cancelled && setProviders(p))
      .catch(() => !cancelled && setProviders({ password: true, entra: false, entra_label: "Microsoft" }));
    return () => {
      cancelled = true;
    };
  }, []);

  if (user) return <Navigate to={from} replace />;

  function restart(message: string | null) {
    setStep({ kind: "password" });
    setPassword("");
    setError(message);
  }

  function secondStepError(err: unknown): string | null {
    if (err instanceof ApiError && err.status === 401 && /sign in again/i.test(err.message)) {
      restart("Your sign-in expired or was locked after too many attempts. Please sign in again.");
      return null;
    }
    if (err instanceof ApiError && err.status === 429) return "Too many attempts. Please wait a few minutes and try again.";
    if (err instanceof ApiError && (err.status === 400 || err.status === 401)) return "That code is not valid. Try the current code.";
    return "Could not reach the server. Check your connection and try again.";
  }

  async function verify(code: string) {
    if (step.kind !== "verify") return;
    setError(null);
    try {
      completeLogin(await api.loginMfa(step.token, code));
      navigate(from, { replace: true });
    } catch (err) {
      setError(secondStepError(err));
    }
  }

  async function startEnrolment() {
    if (step.kind !== "enroll") return;
    setError(null);
    try {
      setStep({ ...step, setup: await api.enrollStart(step.token) });
    } catch (err) {
      setError(secondStepError(err));
    }
  }

  async function confirmEnrolment(code: string) {
    if (step.kind !== "enroll") return;
    setError(null);
    try {
      setStep({ kind: "codes", session: await api.enrollConfirm(step.token, code) });
    } catch (err) {
      setError(secondStepError(err));
    }
  }

  function finishEnrolment() {
    if (step.kind !== "codes") return;
    completeLogin(step.session);
    navigate(from, { replace: true });
  }

  const microsoftHref = `/api/auth/sso/entra/login?next=${encodeURIComponent(from)}`;
  const showPasswordForm = !providers || providers.password || breakGlass;

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (submitting) return;
    setError(null);
    setSubmitting(true);
    try {
      const r = await login(email.trim(), password);
      setPassword("");
      if (isMfaChallenge(r)) {
        setStep(r.purpose === "enroll" ? { kind: "enroll", token: r.mfa_token, setup: null } : { kind: "verify", token: r.mfa_token });
        return;
      }
      navigate(from, { replace: true });
    } catch (err) {
      setPassword("");
      if (err instanceof ApiError && err.status === 403) {
        setError(err.message);
      } else if (err instanceof ApiError && err.status === 429) {
        setError("Too many sign-in attempts. Please wait a few minutes and try again.");
      } else if (err instanceof ApiError && err.status === 401) {
        setError("Invalid email or password.");
      } else {
        setError("Could not reach the server. Check your connection and try again.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  const describedBy = [error ? errorId : null, sessionExpired ? noticeId : null].filter(Boolean).join(" ") || undefined;

  return (
    <div className="relative flex min-h-full items-center justify-center overflow-hidden bg-surface-0 px-4 py-10">
      {/* Subtle grid + glow backdrop */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.35]"
        style={{
          backgroundImage:
            "linear-gradient(var(--color-line) 1px, transparent 1px), linear-gradient(90deg, var(--color-line) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
          maskImage: "radial-gradient(ellipse at center, black 20%, transparent 70%)",
          WebkitMaskImage: "radial-gradient(ellipse at center, black 20%, transparent 70%)",
        }}
      />
      <div
        aria-hidden
        className="pointer-events-none absolute left-1/2 top-1/3 h-72 w-72 -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent/20 blur-3xl"
      />

      <main className="relative w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center text-center">
          <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-xl border border-line bg-surface-1 shadow-lg">
            <img src="/shield.svg" alt="" className="h-7 w-7" />
          </div>
          <h1 className="text-xl font-semibold text-ink">CloudSecurity</h1>
          <p className="mt-1 text-sm text-ink-3">Runtime-first CNAPP</p>
        </div>

        <div className="rounded-xl border border-line bg-surface-1/95 p-6 shadow-2xl backdrop-blur">
          {step.kind === "password" && (
            <>
              <h2 className="text-base font-semibold text-ink">Sign in to your account</h2>
              <p className="mt-1 text-sm text-ink-3">
                {providers?.entra ? "Use your work account or the credentials provided by your administrator." : "Use the credentials provided by your administrator."}
              </p>
            </>
          )}
          {step.kind === "verify" && (
            <>
              <h2 className="text-base font-semibold text-ink">Two-step verification</h2>
              <p className="mt-1 text-sm text-ink-3">Enter the 6-digit code from your authenticator app, or one of your recovery codes.</p>
            </>
          )}
          {step.kind === "enroll" && (
            <>
              <h2 className="text-base font-semibold text-ink">Set up two-step verification</h2>
              <p className="mt-1 text-sm text-ink-3">Your role requires an authenticator app. Set it up now to finish signing in.</p>
            </>
          )}
          {step.kind === "codes" && (
            <>
              <h2 className="text-base font-semibold text-ink">Two-step verification is on</h2>
              <p className="mt-1 text-sm text-ink-3">One last thing: keep your recovery codes.</p>
            </>
          )}

          {ssoError && step.kind === "password" && !error && (
            <div role="alert" className="mt-4 rounded-md border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm text-ink">
              {ssoErrorMessage(ssoError)}
            </div>
          )}
          {sessionExpired && !error && step.kind === "password" && (
            <div
              id={noticeId}
              role="status"
              className="mt-4 rounded-md border border-sev-medium/50 bg-sev-medium/10 px-3 py-2 text-sm text-ink"
            >
              Your session has expired. Please sign in again.
            </div>
          )}
          {error && (
            <div
              id={errorId}
              role="alert"
              className="mt-4 rounded-md border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm text-ink"
            >
              {error}
            </div>
          )}

          {step.kind === "verify" && (
            <div className="mt-5">
              <VerifyCodeForm allowRecovery submitLabel="Verify" busyLabel="Verifying…" onSubmit={verify} error={null} />
              <button type="button" onClick={() => restart(null)}
                className="mt-4 text-xs font-medium text-ink-3 hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
                ← Back to sign in
              </button>
            </div>
          )}

          {step.kind === "enroll" && (
            <div className="mt-5 space-y-4">
              {step.setup ? (
                <>
                  <TotpSetupDetails setup={step.setup} />
                  <VerifyCodeForm submitLabel="Verify and sign in" busyLabel="Verifying…" onSubmit={confirmEnrolment} error={null} />
                </>
              ) : (
                <Button variant="primary" onClick={startEnrolment}>
                  Set up authenticator app
                </Button>
              )}
              <button type="button" onClick={() => restart(null)}
                className="block text-xs font-medium text-ink-3 hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
                ← Cancel
              </button>
            </div>
          )}

          {step.kind === "codes" && (
            <div className="mt-5 space-y-4">
              <RecoveryCodes codes={step.session.recovery_codes ?? []} email={step.session.user.email} />
              <Button variant="primary" onClick={finishEnrolment}>
                I have saved my codes, continue
              </Button>
            </div>
          )}

          {step.kind === "password" && providers?.entra && (
            <div className="mt-5">
              <a
                href={microsoftHref}
                className="flex w-full items-center justify-center gap-2 rounded-md border border-line bg-surface-2 px-3 py-2 text-sm font-semibold text-ink transition hover:bg-line focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <svg aria-hidden width="16" height="16" viewBox="0 0 21 21">
                  <rect x="1" y="1" width="9" height="9" fill="#f25022" />
                  <rect x="11" y="1" width="9" height="9" fill="#7fba00" />
                  <rect x="1" y="11" width="9" height="9" fill="#00a4ef" />
                  <rect x="11" y="11" width="9" height="9" fill="#ffb900" />
                </svg>
                Sign in with {providers.entra_label}
              </a>
              {showPasswordForm && (
                <div className="my-4 flex items-center gap-3 text-xs text-ink-3" aria-hidden>
                  <span className="h-px flex-1 bg-line" />
                  or
                  <span className="h-px flex-1 bg-line" />
                </div>
              )}
            </div>
          )}

          {step.kind === "password" && !showPasswordForm && (
            <button type="button" onClick={() => setBreakGlass(true)}
              className="mt-4 text-xs font-medium text-ink-3 hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
              Emergency administrator sign-in
            </button>
          )}

          {step.kind === "password" && showPasswordForm && (
            <form className={providers?.entra ? "space-y-4" : "mt-5 space-y-4"} onSubmit={onSubmit}>
              <div>
                <label htmlFor="login-email" className="mb-1.5 block text-sm font-medium text-ink-2">
                  Email
                </label>
                <input
                  ref={emailRef}
                  id="login-email"
                  name="email"
                  type="email"
                  autoComplete="username"
                  inputMode="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  aria-invalid={!!error}
                  aria-describedby={describedBy}
                  className="block w-full rounded-md border border-line bg-surface-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40"
                  placeholder="you@company.com"
                />
              </div>

              <div>
                <label htmlFor="login-password" className="mb-1.5 block text-sm font-medium text-ink-2">
                  Password
                </label>
                <div className="relative">
                  <input
                    id="login-password"
                    name="password"
                    type={showPassword ? "text" : "password"}
                    autoComplete="current-password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    aria-invalid={!!error}
                    aria-describedby={describedBy}
                    className="block w-full rounded-md border border-line bg-surface-2 py-2 pl-3 pr-16 text-sm text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((v) => !v)}
                    aria-pressed={showPassword}
                    aria-controls="login-password"
                    aria-label={showPassword ? "Hide password" : "Show password"}
                    className="absolute inset-y-0 right-0 my-1 mr-1 rounded px-2 text-xs font-medium text-ink-3 hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    {showPassword ? "Hide" : "Show"}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={submitting || !email || !password}
                aria-busy={submitting}
                className="flex w-full items-center justify-center gap-2 rounded-md bg-accent px-3 py-2 text-sm font-semibold text-white transition hover:brightness-110 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface-1 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {submitting && (
                  <span
                    aria-hidden
                    className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white"
                  />
                )}
                {submitting ? "Signing in…" : "Sign in"}
              </button>
            </form>
          )}
        </div>

        <p className="mt-6 text-center text-xs text-ink-3">
          Access is restricted to authorized users. Sign-in activity is audited.
        </p>
      </main>
    </div>
  );
}
