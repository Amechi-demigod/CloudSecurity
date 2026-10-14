import { useEffect, useId, useRef, useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { ApiError } from "../api";
import { useAuth } from "../auth/context";

interface FromState {
  from?: string;
}

function safeRedirect(from: string | undefined): string {
  // Only same-app paths; never protocol-relative or absolute URLs.
  if (!from || !from.startsWith("/") || from.startsWith("//") || from.startsWith("/login")) return "/";
  return from;
}

export default function Login() {
  const { user, login, sessionExpired } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const from = safeRedirect((location.state as FromState | null)?.from);

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
  }, []);

  if (user) return <Navigate to={from} replace />;

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (submitting) return;
    setError(null);
    setSubmitting(true);
    try {
      await login(email.trim(), password);
      navigate(from, { replace: true });
    } catch (err) {
      setPassword("");
      if (err instanceof ApiError && err.status === 429) {
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
          <h2 className="text-base font-semibold text-ink">Sign in to your account</h2>
          <p className="mt-1 text-sm text-ink-3">Use the credentials provided by your administrator.</p>

          {sessionExpired && !error && (
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

          <form className="mt-5 space-y-4" onSubmit={onSubmit}>
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
        </div>

        <p className="mt-6 text-center text-xs text-ink-3">
          Access is restricted to authorized users. Sign-in activity is audited.
        </p>
      </main>
    </div>
  );
}
