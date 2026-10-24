import { useState } from "react";
import type { InvitationState, IssuedInvitation } from "../orgApi";
import { Button, Tag } from "./ui";

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
