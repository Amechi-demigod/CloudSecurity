import { useState, type FormEvent } from "react";
import { ApiError, api, type MfaSetup, type MfaStatus } from "../api";
import { useAuth } from "../auth/context";
import { CodeInput, RecoveryCodes, TotpSetupDetails, VerifyCodeForm } from "../components/mfa";
import { Button, Card, ErrorNote, Field, Modal, PageHeader, Tag } from "../components/ui";
import { fmtTime } from "../lib/format";
import { useApi } from "../lib/useApi";

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : String(e);
}

/** Password (if the account has one) + current code, for disable / regenerate. */
function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  danger,
  status,
  onClose,
  onConfirm,
}: {
  open: boolean;
  title: string;
  description: string;
  confirmLabel: string;
  danger?: boolean;
  status: MfaStatus;
  onClose: () => void;
  onConfirm: (password: string | null, code: string) => Promise<void>;
}) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function close() {
    setPassword("");
    setCode("");
    setError(null);
    onClose();
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onConfirm(status.has_password ? password : null, code.trim());
      setPassword("");
      setCode("");
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={close} title={title}>
      <form className="space-y-3" onSubmit={submit}>
        <p className="text-sm text-ink-2">{description}</p>
        {error && (
          <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
            {error}
          </div>
        )}
        {status.has_password && (
          <Field label="Current password" id="mfa-confirm-password" type="password" autoComplete="current-password"
            required value={password} onChange={(e) => setPassword(e.target.value)} />
        )}
        <CodeInput id="mfa-confirm-code" value={code} onChange={setCode} allowRecovery />
        <div className="flex justify-end gap-2 pt-2">
          <Button onClick={close}>Cancel</Button>
          <Button type="submit" variant={danger ? "danger" : "primary"}
            disabled={busy || !code.trim() || (status.has_password && !password)}>
            {busy ? "Working…" : confirmLabel}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

export default function Security() {
  const { user } = useAuth();
  const { data: status, error, reload } = useApi(api.mfaStatus, []);
  const [setup, setSetup] = useState<MfaSetup | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [dialog, setDialog] = useState<"disable" | "regenerate" | null>(null);

  async function startSetup() {
    setActionError(null);
    setNotice(null);
    setCodes(null);
    try {
      setSetup(await api.mfaSetup());
    } catch (e) {
      setActionError(errMsg(e));
    }
  }

  async function enable(code: string) {
    setVerifyError(null);
    try {
      const r = await api.mfaEnable(code);
      setSetup(null);
      setCodes(r.recovery_codes);
      setNotice("Two-step verification is on. You will be asked for a code at every sign-in.");
      reload();
    } catch (e) {
      setVerifyError(e instanceof ApiError && e.status === 400 ? "That code is not valid. Try the current code." : errMsg(e));
    }
  }

  return (
    <div className="max-w-3xl">
      <PageHeader title="Security" subtitle="Protect your account with two-step verification (an authenticator app)." />
      <ErrorNote error={error ?? actionError} />
      {notice && (
        <div role="status" className="mb-3 rounded border border-good/60 bg-good/10 px-3 py-2 text-sm">
          {notice}
        </div>
      )}

      {status && status.sso_user && !status.has_password && (
        <Card className="mb-4">
          <p className="text-sm text-ink-2">
            You sign in with Microsoft. Multi-factor authentication for that sign-in is managed by your organization in
            Microsoft Entra ID. The authenticator below is only needed if your administrator requires it here as well.
          </p>
        </Card>
      )}

      {status && (
        <Card
          title={
            <span className="flex items-center gap-2">
              Authenticator app
              {status.enabled ? <Tag tone="good">On</Tag> : <Tag tone={status.required ? "warn" : "default"}>Off</Tag>}
              {status.required && <Tag tone="accent">Required for your role</Tag>}
            </span>
          }
        >
          {codes ? (
            <div className="space-y-4">
              <RecoveryCodes codes={codes} email={user?.email} />
              <Button variant="primary" onClick={() => setCodes(null)}>
                Done
              </Button>
            </div>
          ) : status.enabled ? (
            <div className="space-y-4">
              <dl className="grid grid-cols-1 gap-2 text-sm sm:grid-cols-2">
                <div>
                  <dt className="text-xs text-ink-3">Enabled</dt>
                  <dd className="text-ink">{status.enabled_at ? fmtTime(status.enabled_at) : "—"}</dd>
                </div>
                <div>
                  <dt className="text-xs text-ink-3">Recovery codes left</dt>
                  <dd className={status.recovery_codes_remaining <= 2 ? "text-sev-high" : "text-ink"}>
                    {status.recovery_codes_remaining} of 10
                  </dd>
                </div>
              </dl>
              <div className="flex flex-wrap gap-2">
                <Button onClick={() => setDialog("regenerate")}>Generate new recovery codes</Button>
                <Button variant="danger" disabled={status.required}
                  title={status.required ? "Your role requires two-step verification" : undefined}
                  onClick={() => setDialog("disable")}>
                  Turn off
                </Button>
              </div>
            </div>
          ) : setup ? (
            <div className="space-y-4">
              <TotpSetupDetails setup={setup} wide />
              <VerifyCodeForm submitLabel="Verify and turn on" busyLabel="Verifying…" onSubmit={enable} error={verifyError} />
              <Button onClick={() => setSetup(null)}>Cancel</Button>
            </div>
          ) : (
            <div className="space-y-3">
              <p className="text-sm text-ink-2">
                After your password, you will also enter a 6-digit code from an authenticator app on your phone. You get
                10 one-time recovery codes in case you lose the device.
              </p>
              <Button variant="primary" onClick={startSetup}>
                Set up authenticator app
              </Button>
            </div>
          )}
        </Card>
      )}

      {status && (
        <>
          <ConfirmDialog
            open={dialog === "disable"}
            title="Turn off two-step verification"
            description="Your authenticator and recovery codes will stop working, and your other sessions are signed out."
            confirmLabel="Turn off"
            danger
            status={status}
            onClose={() => setDialog(null)}
            onConfirm={async (pw, code) => {
              await api.mfaDisable(pw, code);
              setDialog(null);
              setNotice("Two-step verification is off.");
              reload();
            }}
          />
          <ConfirmDialog
            open={dialog === "regenerate"}
            title="Generate new recovery codes"
            description="Your current recovery codes stop working and 10 new ones are shown once."
            confirmLabel="Generate"
            status={status}
            onClose={() => setDialog(null)}
            onConfirm={async (pw, code) => {
              const r = await api.regenerateRecoveryCodes(pw, code);
              setDialog(null);
              setNotice(null);
              setCodes(r.recovery_codes);
              reload();
            }}
          />
        </>
      )}
    </div>
  );
}
