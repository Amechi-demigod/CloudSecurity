import { Check } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import type { Role } from "../api";
import { useAuth } from "../auth/context";
import { useApi } from "../lib/useApi";
import { orgApi, type InvitationState, type IssuedInvitation, type OnboardingStepKey } from "../orgApi";
import { Button, Card, ErrorNote, Tag } from "./ui";

// Where each checklist step is done, and the role that page needs (others are told to ask an admin).
const ONBOARDING_STEPS: Record<OnboardingStepKey, { title: string; hint: string; to: string; label: string; role: Role }> = {
  mfa: { title: "Secure your account", hint: "Turn on multi-factor authentication", to: "/account/security", label: "Set up MFA", role: "viewer" },
  team: { title: "Invite your team", hint: "Add at least one teammate", to: "/admin/organization", label: "Invite people", role: "admin" },
  cloud: { title: "Connect a cloud account", hint: "Enter read-only Azure, AWS or GCP credentials", to: "/admin/organization", label: "Add credentials", role: "admin" },
  agent: { title: "Install the endpoint agent", hint: "Enroll your first device", to: "/devices/enrollment", label: "Enroll a device", role: "admin" },
  scan: { title: "Run your first scan", hint: "Scan a connected cloud account", to: "/connectors", label: "Run a scan", role: "analyst" },
  alerts: { title: "Set up alerts", hint: "Add a Teams, Slack, email or webhook channel", to: "/notifications?tab=channels", label: "Add a channel", role: "analyst" },
};

/**
 * "Getting started" checklist for a new organisation, shown on the landing page until every step
 * is done or an admin dismisses it. Never shown in the default (platform operator's) organisation.
 */
export function GettingStarted() {
  const { organization, can } = useAuth();
  const skip = !organization || organization.is_default;
  const { data, error, reload } = useApi(() => (skip ? Promise.resolve(null) : orgApi.onboarding()), [skip], 60000);
  const [busy, setBusy] = useState(false);
  const [dismissError, setDismissError] = useState<string | null>(null);
  if (skip || error || !data || data.is_default || data.dismissed || data.completed >= data.total) return null;

  async function dismiss() {
    setBusy(true);
    setDismissError(null);
    try {
      await orgApi.dismissOnboarding();
      await reload();
    } catch (e) {
      setDismissError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card
      className="mb-5"
      title={
        <span className="flex items-center gap-2">
          Getting started
          <Tag tone="accent">
            {data.completed} of {data.total}
          </Tag>
        </span>
      }
      actions={
        can("admin") && (
          <Button disabled={busy} onClick={() => void dismiss()} title="Hide this checklist for everyone in the organisation">
            Dismiss
          </Button>
        )
      }
    >
      <ErrorNote error={dismissError} />
      <div
        role="progressbar"
        aria-label="Setup progress"
        aria-valuemin={0}
        aria-valuemax={data.total}
        aria-valuenow={data.completed}
        className="mb-3 h-1.5 overflow-hidden rounded-full bg-surface-2"
      >
        <div className="h-full rounded-full bg-accent transition-all" style={{ width: `${(data.completed / data.total) * 100}%` }} />
      </div>
      <ol className="divide-y divide-line">
        {data.steps.map(({ key, done }) => {
          const step = ONBOARDING_STEPS[key];
          return (
            <li key={key} className="flex flex-wrap items-center justify-between gap-2 py-2">
              <div className="flex min-w-0 items-center gap-2.5">
                <span
                  aria-hidden
                  className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full border ${
                    done ? "border-good bg-good text-white" : "border-line bg-surface-2"
                  }`}
                >
                  {done && <Check className="h-3.5 w-3.5" />}
                </span>
                <div className="min-w-0">
                  <div className={`text-sm font-medium ${done ? "text-ink-3 line-through" : "text-ink"}`}>
                    {step.title}
                    <span className="sr-only">{done ? " (done)" : " (to do)"}</span>
                  </div>
                  {!done && <div className="text-xs text-ink-3">{step.hint}</div>}
                </div>
              </div>
              {!done &&
                (can(step.role) ? (
                  <Link
                    to={step.to}
                    className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    {step.label}
                  </Link>
                ) : (
                  <span className="text-xs text-ink-3">Ask an administrator</span>
                ))}
            </li>
          );
        })}
      </ol>
    </Card>
  );
}

export function InvitationStateTag({ state }: { state: InvitationState }) {
  const tone = state === "pending" ? "accent" : state === "accepted" ? "good" : state === "expired" ? "warn" : "default";
  return <Tag tone={tone}>{state[0].toUpperCase() + state.slice(1)}</Tag>;
}

/** Copy-to-clipboard for a one-time value (invitation link, token). */
export function CopyField({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-stretch gap-2">
      <input
        readOnly
        aria-label={label}
        value={value}
        onFocus={(e) => e.currentTarget.select()}
        className="min-w-0 flex-1 rounded border border-line bg-surface-2 px-2 py-1.5 font-mono text-xs text-ink"
      />
      <Button
        onClick={() => {
          void navigator.clipboard?.writeText(value).then(() => setCopied(true));
        }}
      >
        {copied ? "Copied" : "Copy"}
      </Button>
    </div>
  );
}

/** Result of sending an invitation: emailed, or the link to pass on. */
export function InviteResult({ issued, onDismiss }: { issued: IssuedInvitation; onDismiss: () => void }) {
  return (
    <div role="status" className="mb-3 space-y-2 rounded border border-good/60 bg-good/10 px-3 py-2 text-sm">
      <div className="flex items-start justify-between gap-3">
        <span>
          {issued.emailed
            ? `Invitation emailed to ${issued.invitation.email}.`
            : `Invitation created for ${issued.invitation.email}. ${
                issued.email_error ? `The email could not be sent (${issued.email_error}). ` : "Email is not configured on this platform. "
              }Send them this link yourself: it works once and expires ${new Date(issued.invitation.expires_at).toLocaleString()}.`}
        </span>
        <button className="text-ink-3 hover:text-ink" onClick={onDismiss} aria-label="Dismiss">
          ✕
        </button>
      </div>
      {issued.invite_url && <CopyField value={issued.invite_url} label="Invitation link" />}
    </div>
  );
}
