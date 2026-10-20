import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { ApiError, api, type EnrollmentToken, type InstallerPlatform } from "../../api";
import { Button, Card, Empty, ErrorNote, Field, Modal, PageHeader, Table, Tag } from "../../components/ui";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : String(e);
}

function CopyBlock({ label, text }: { label: string; text: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }
  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <span className="text-xs font-medium text-ink-2">{label}</span>
        <button type="button" onClick={copy} className="text-xs text-accent hover:underline">
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto whitespace-pre rounded border border-line bg-surface-0 p-3 font-mono text-xs text-ink">{text}</pre>
    </div>
  );
}

function CreateTokenDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: (token: string) => void }) {
  const [name, setName] = useState("");
  const [multi, setMulti] = useState(false);
  const [maxUses, setMaxUses] = useState("25");
  const [hours, setHours] = useState("24");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function close() {
    setName("");
    setMulti(false);
    setError(null);
    onClose();
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const t = await api.createEnrollmentToken({
        name: name.trim(),
        max_uses: multi ? (maxUses.trim() ? Number(maxUses) : null) : 1,
        expires_in_hours: Number(hours),
      });
      onCreated(t.token);
      close();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={close} title="Create enrollment token">
      <form className="space-y-3" onSubmit={submit}>
        {error && (
          <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
            {error}
          </div>
        )}
        <Field label="Name" id="et-name" required maxLength={128} placeholder="e.g. Finance laptops, Oct 2026" value={name}
          onChange={(e) => setName(e.target.value)} />
        <fieldset className="space-y-1 text-sm">
          <legend className="mb-1 font-medium text-ink-2">Uses</legend>
          <label className="flex items-center gap-2">
            <input type="radio" name="et-uses" checked={!multi} onChange={() => setMulti(false)} /> Single device
          </label>
          <label className="flex items-center gap-2">
            <input type="radio" name="et-uses" checked={multi} onChange={() => setMulti(true)} /> Multiple devices
          </label>
        </fieldset>
        {multi && (
          <Field label="Maximum devices (empty = unlimited until expiry)" id="et-max" type="number" min={1} value={maxUses}
            onChange={(e) => setMaxUses(e.target.value)} />
        )}
        <Field label="Expires after (hours)" id="et-hours" type="number" min={1} max={2160} required value={hours}
          onChange={(e) => setHours(e.target.value)} hint="Keep tokens short-lived; anyone holding a valid token can enroll a device." />
        <div className="flex justify-end gap-2 pt-2">
          <Button onClick={close}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy || !name.trim()}>
            {busy ? "Creating…" : "Create token"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function InstallerDownload({ onCreated }: { onCreated: () => void }) {
  const { data: info, error: infoError } = useApi(api.installerInfo, []);
  const [platform, setPlatform] = useState<InstallerPlatform>("windows-msi");
  const [days, setDays] = useState("30");
  const [maxDevices, setMaxDevices] = useState("500");
  const [group, setGroup] = useState("");
  const [name, setName] = useState("");
  const [includeCa, setIncludeCa] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<{ filename: string; sha256: string | null } | null>(null);

  const ca = includeCa ?? info?.include_ca_default ?? false;
  const plat = info?.platforms[platform];

  async function download(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setDone(null);
    try {
      const { blob, filename, sha256 } = await api.downloadInstaller({
        platform,
        name: name.trim() || null,
        expires_in_days: Number(days),
        max_devices: Number(maxDevices),
        device_group: group.trim() || null,
        include_ca: ca,
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
      setDone({ filename, sha256 });
      onCreated();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card title="Download installer (recommended)" className="mb-4">
      <p className="mb-3 text-sm text-ink-2">
        One pre-configured file for all your devices: it carries this server&apos;s address, a dedicated enrollment token
        {info?.ca_configured ? " and the server's CA certificate" : ""}. Install it silently with Group Policy, Intune, SCCM or
        Jamf, or double-click it. Each device enrolls itself on first start; no per-device token.
      </p>
      <ErrorNote error={infoError} />
      {info?.server_error && (
        <div role="alert" className="mb-3 rounded border border-sev-high/60 bg-sev-high/10 px-3 py-2 text-sm">{info.server_error}</div>
      )}
      <form className="grid grid-cols-1 gap-3 md:grid-cols-2" onSubmit={download}>
        <fieldset className="space-y-1 text-sm md:col-span-2">
          <legend className="mb-1 font-medium text-ink-2">Platform</legend>
          {(["windows-msi", "macos-pkg"] as InstallerPlatform[]).map((p) => (
            <label key={p} className="mr-6 inline-flex items-center gap-2">
              <input type="radio" name="inst-platform" checked={platform === p} onChange={() => setPlatform(p)} />
              {info?.platforms[p]?.label ?? p}
              {info && !info.platforms[p]?.available && <Tag tone="warn">not bundled</Tag>}
            </label>
          ))}
        </fieldset>
        <Field label="Expires after (days)" id="inst-days" type="number" min={1} max={365} required value={days}
          onChange={(e) => setDays(e.target.value)} hint="The installer stops enrolling new devices after this." />
        <Field label="Maximum devices" id="inst-max" type="number" min={1} max={100000} required value={maxDevices}
          onChange={(e) => setMaxDevices(e.target.value)} hint="Each device uses one enrollment; re-installs do not." />
        <Field label="Device group (optional)" id="inst-group" maxLength={64} placeholder="e.g. Lagos office" value={group}
          onChange={(e) => setGroup(e.target.value)} hint="Label applied to every device enrolled with this installer." />
        <Field label="Name (optional)" id="inst-name" maxLength={128} placeholder="shown under Enrollment tokens" value={name}
          onChange={(e) => setName(e.target.value)} />
        <label className="flex items-start gap-2 text-sm md:col-span-2">
          <input type="checkbox" className="mt-1" checked={ca} disabled={!info?.ca_configured && !ca}
            onChange={(e) => setIncludeCa(e.target.checked)} />
          <span>
            Include the server&apos;s CA certificate
            <span className="block text-xs text-ink-3">
              {info?.ca_configured
                ? "Needed while the server uses its built-in/internal CA. Untick once it has a publicly trusted certificate (or your CA is deployed by GPO/MDM)."
                : "No private CA is configured on the server: the certificate must be publicly trusted (or already trusted by the devices)."}
            </span>
          </span>
        </label>
        <div className="md:col-span-2 flex flex-wrap items-center gap-3">
          <Button type="submit" variant="primary" disabled={busy || !plat?.available || !!info?.server_error}>
            {busy ? "Building…" : `Download ${plat?.filename ?? "installer"}`}
          </Button>
          {info?.server_url && <span className="text-xs text-ink-3">Agents will connect to <code>{info.server_url}</code>
            {plat?.version && <> · agent {plat.version}</>}</span>}
        </div>
        {plat && !plat.available && <p className="text-xs text-ink-3 md:col-span-2">{plat.reason}</p>}
      </form>
      <ErrorNote error={error} />
      {done && (
        <div className="mt-3 rounded border border-accent/60 p-3 text-sm">
          <p className="mb-2">
            Saved <code>{done.filename}</code>
            {done.sha256 && <> (SHA-256 <code className="break-all">{done.sha256}</code>)</>}. The token inside it is not shown
            again: keep the file like a password and revoke it below when the rollout is finished.
          </p>
          {platform === "windows-msi" ? (
            <CopyBlock label="Silent install (GPO startup script, Intune, SCCM)" text={`msiexec /i ${done.filename} /qn /l*v %TEMP%\\cnapp-agent-install.log`} />
          ) : (
            <CopyBlock label="Silent install (Jamf / Kandji / Intune / Terminal)" text={`sudo installer -pkg ${done.filename} -target /`} />
          )}
        </div>
      )}
    </Card>
  );
}

const PLATFORM_LABEL: Record<InstallerPlatform, string> = { "windows-msi": "Windows MSI", "macos-pkg": "macOS pkg" };

const STATE_TONE: Record<EnrollmentToken["state"], "good" | "default" | "warn"> = {
  active: "good",
  expired: "default",
  exhausted: "default",
  revoked: "warn",
};

export default function Enrollment() {
  const { data: tokens, error, reload } = useApi(api.enrollmentTokens, []);
  const [createOpen, setCreateOpen] = useState(false);
  const [newToken, setNewToken] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  async function revoke(t: EnrollmentToken) {
    setActionError(null);
    try {
      await api.revokeEnrollmentToken(t.id);
      reload();
    } catch (e) {
      setActionError(errMsg(e));
    }
  }

  return (
    <div>
      <div className="mb-2 text-xs text-ink-3">
        <Link to="/devices" className="hover:text-ink">
          Devices
        </Link>{" "}
        / Enrollment
      </div>
      <PageHeader
        title="Enroll devices"
        subtitle="Download one pre-configured installer for all your devices. Tokens for manual (command-line) installs are managed below."
        actions={<Button onClick={() => setCreateOpen(true)}>Create token</Button>}
      />
      <ErrorNote error={error ?? actionError} />

      {newToken && (
        <Card title="New enrollment token" className="mb-4 border-accent/60" actions={<Button onClick={() => setNewToken(null)}>Done</Button>}>
          <p className="mb-2 text-sm text-ink-2">
            Copy it now: it is shown only once. Treat it like a password until it expires or is used up.
          </p>
          <CopyBlock label="Token" text={newToken} />
          <p className="mt-2 text-xs text-ink-3">
            For a manual command-line install, pass it to the agent&apos;s <code>enroll</code> command (see <code>docs/DEVICE_MANAGEMENT.md</code>).
            For most rollouts the pre-configured installer below is simpler.
          </p>
        </Card>
      )}

      <InstallerDownload onCreated={reload} />

      <Card title="Enrollment tokens" className="mb-4">
        {tokens && tokens.length === 0 ? (
          <Empty>No tokens yet.</Empty>
        ) : (
          <Table head={["Name", "Token", "State", "Uses", "Expires", "Created", ""]}>
            {(tokens ?? []).map((t) => (
              <tr key={t.id}>
                <td className="px-3 py-2">
                  {t.name}
                  {t.package_platform && (
                    <div className="mt-0.5">
                      <Tag tone="accent">installer · {PLATFORM_LABEL[t.package_platform]}</Tag>
                    </div>
                  )}
                  {t.device_group && <div className="text-[11px] text-ink-3">group: {t.device_group}</div>}
                </td>
                <td className="px-3 py-2 font-mono text-xs text-ink-3">{t.token_prefix}…</td>
                <td className="px-3 py-2">
                  <Tag tone={STATE_TONE[t.state]}>{t.state}</Tag>
                </td>
                <td className="px-3 py-2 text-xs text-ink-2">
                  {t.use_count} / {t.max_uses ?? "∞"}
                  {t.last_used_at && <div className="text-ink-3">last {fmtAgo(t.last_used_at)}</div>}
                </td>
                <td className="px-3 py-2 text-xs text-ink-2">{fmtTime(t.expires_at)}</td>
                <td className="px-3 py-2 text-xs text-ink-3">
                  {fmtTime(t.created_at)}
                  <div>{t.created_by}</div>
                </td>
                <td className="px-3 py-2">
                  {t.state === "active" && (
                    <Button variant="danger" onClick={() => revoke(t)}>
                      Revoke
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <CreateTokenDialog open={createOpen} onClose={() => setCreateOpen(false)} onCreated={(t) => {
        setNewToken(t);
        reload();
      }} />
    </div>
  );
}
