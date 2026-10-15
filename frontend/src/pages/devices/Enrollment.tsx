import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { ApiError, api, type EnrollmentToken } from "../../api";
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
        subtitle="Create an enrollment token, then run the install command on each Windows or Mac device."
        actions={<Button variant="primary" onClick={() => setCreateOpen(true)}>Create token</Button>}
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

      <Card title="Enrollment tokens" className="mb-4">
        {tokens && tokens.length === 0 ? (
          <Empty>No tokens yet.</Empty>
        ) : (
          <Table head={["Name", "Token", "State", "Uses", "Expires", "Created", ""]}>
            {(tokens ?? []).map((t) => (
              <tr key={t.id}>
                <td className="px-3 py-2">{t.name}</td>
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
