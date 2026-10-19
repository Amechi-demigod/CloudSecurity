import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { ApiError, api, type EnrollmentToken, type InstallerPlatform } from "../../api";
import { Button, Card, Empty, ErrorNote, Field, Modal, PageHeader, Table, Tag } from "../../components/ui";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";

const PLACEHOLDER = "<ENROLLMENT_TOKEN>";

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

function trimSlash(s: string) {
  return s.replace(/\/+$/, "");
}

function InstallCommands({ token, downloadUrl }: { token: string; downloadUrl: string | null }) {
  const server = window.location.origin;
  const base = downloadUrl ? trimSlash(downloadUrl) : null;
  const winDownload = base
    ? `.\\install.ps1 -Server ${server} -Token ${token} \`\n  -DownloadUrl ${base}/cnapp-agent-windows-amd64.exe -Sha256 <SHA-256 from SHA256SUMS>`
    : `.\\install.ps1 -Server ${server} -Token ${token} -BinaryPath .\\cnapp-agent-windows-amd64.exe`;
  const winManual = `$env:CNAPP_ENROLL_TOKEN = '${token}'
.\\cnapp-agent-windows-amd64.exe enroll --server ${server}
.\\cnapp-agent-windows-amd64.exe install
Remove-Item Env:CNAPP_ENROLL_TOKEN`;
  const macDownload = base ? `curl -fLO ${base}/cnapp-agent-darwin-arm64   # Intel Macs: cnapp-agent-darwin-amd64\n` : "";
  const mac = `${macDownload}chmod +x cnapp-agent-darwin-arm64
xattr -d com.apple.quarantine cnapp-agent-darwin-arm64 2>/dev/null
echo '${token}' | sudo ./cnapp-agent-darwin-arm64 enroll --server ${server} --token-stdin
sudo ./cnapp-agent-darwin-arm64 install`;
  const macPkg = `sudo installer -pkg cnapp-agent-macos-universal.pkg -target /
echo '${token}' | sudo /usr/local/cnapp-agent/bin/cnapp-agent enroll --server ${server} --token-stdin
sudo /usr/local/cnapp-agent/bin/cnapp-agent install`;
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
      <div className="space-y-3">
        <h3 className="text-sm font-semibold">Windows 10 / 11</h3>
        <p className="text-xs text-ink-3">
          Run in an elevated PowerShell (Run as administrator) in the folder containing the agent and <code>install.ps1</code>. Use the
          <code> windows-arm64</code> build on ARM devices.
        </p>
        <CopyBlock label="Installer script (recommended)" text={winDownload} />
        <CopyBlock label="Or directly with the agent binary" text={winManual} />
      </div>
      <div className="space-y-3">
        <h3 className="text-sm font-semibold">macOS</h3>
        <p className="text-xs text-ink-3">
          Run in Terminal with an administrator account. Use <code>darwin-amd64</code> on Intel Macs.
        </p>
        <CopyBlock label="Agent binary" text={mac} />
        <CopyBlock label="Or the installer package" text={macPkg} />
      </div>
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
  const { data: info } = useApi(api.enrollmentInfo, []);
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
        subtitle="Download one pre-configured installer for all devices, or create a token for manual installs."
        actions={<Button onClick={() => setCreateOpen(true)}>Create token</Button>}
      />
      <ErrorNote error={error ?? actionError} />

      {newToken && (
        <Card title="New enrollment token" className="mb-4 border-accent/60" actions={<Button onClick={() => setNewToken(null)}>Done</Button>}>
          <p className="mb-2 text-sm text-ink-2">
            Copy it now: it is shown only once. Treat it like a password until it expires or is used up.
          </p>
          <CopyBlock label="Token" text={newToken} />
          <div className="mt-4">
            <InstallCommands token={newToken} downloadUrl={info?.agent_download_url ?? null} />
          </div>
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

      <Card title="Install commands" className="mb-4">
        <p className="mb-3 text-sm text-ink-2">
          Templates with a placeholder token. Create a token above to get commands with the token filled in.
        </p>
        <InstallCommands token={PLACEHOLDER} downloadUrl={info?.agent_download_url ?? null} />
      </Card>

      <Card title="Agent downloads">
        {info?.agent_download_url ? (
          <p className="text-sm text-ink-2">
            Agent builds:{" "}
            <a className="text-accent" href={info.agent_download_url} target="_blank" rel="noreferrer">
              {info.agent_download_url}
            </a>{" "}
            (verify against <code>SHA256SUMS</code>).
          </p>
        ) : (
          <p className="text-sm text-ink-2">
            Build artifacts are produced by CI (<code>cnapp-agent-binaries</code>: Windows amd64/arm64, macOS amd64/arm64, the
            installer scripts and <code>SHA256SUMS</code>; <code>cnapp-agent-macos-pkg</code>: a universal macOS package). Sign them and
            publish them on an internal share or release page, then set <code>AGENT_DOWNLOAD_URL</code> on the backend to show the
            link here. See <code>docs/DEVICE_MANAGEMENT.md</code>.
          </p>
        )}
      </Card>

      <CreateTokenDialog open={createOpen} onClose={() => setCreateOpen(false)} onCreated={(t) => {
        setNewToken(t);
        reload();
      }} />
    </div>
  );
}
