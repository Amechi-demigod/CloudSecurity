import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { ApiError, api, uploadScriptBundle, type ScriptBundle, type ScriptRun } from "../../api";
import { useAuth } from "../../auth/context";
import { ApprovalList, RiskTag } from "../../components/approvals";
import { Button, Card, Empty, ErrorNote, PageHeader, Table, Tag } from "../../components/ui";
import { OS_LABEL } from "../../lib/devices";
import { fmtAgo, fmtTime } from "../../lib/format";
import { describeParam } from "../../lib/scripts";
import { useApi } from "../../lib/useApi";

const RUN_TONE: Record<ScriptRun["status"], "default" | "warn" | "good" | "accent"> = {
  pending: "accent",
  delivered: "accent",
  succeeded: "good",
  failed: "warn",
  rejected: "warn",
  expired: "default",
  cancelled: "default",
};

function BundleInfo({ bundle, trustedKeys }: { bundle: ScriptBundle | null; trustedKeys: string[] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm md:grid-cols-2">
      {bundle ? (
        <>
          <div>
            <dt className="text-ink-3">Library version</dt>
            <dd className="font-mono">
              {bundle.version} {bundle.expired && <Tag tone="warn">expired</Tag>}
            </dd>
          </div>
          <div>
            <dt className="text-ink-3">Signed by</dt>
            <dd className="break-all font-mono text-xs">{bundle.key_id}</dd>
          </div>
          <div>
            <dt className="text-ink-3">Released / expires</dt>
            <dd className="text-xs">
              {fmtTime(bundle.released_at)} → {fmtTime(bundle.expires_at)}
            </dd>
          </div>
          <div>
            <dt className="text-ink-3">Imported</dt>
            <dd className="text-xs">
              {fmtAgo(bundle.imported_at)} by {bundle.imported_by}
            </dd>
          </div>
          {bundle.notes && (
            <div className="md:col-span-2">
              <dt className="text-ink-3">Notes</dt>
              <dd className="text-xs text-ink-2">{bundle.notes}</dd>
            </div>
          )}
        </>
      ) : (
        <div className="md:col-span-2 text-ink-2">No script library imported yet.</div>
      )}
      <div className="md:col-span-2">
        <dt className="text-ink-3">Trusted signing keys</dt>
        <dd className="font-mono text-xs">
          {trustedKeys.length ? trustedKeys.map((k) => <div key={k} className="break-all">{k}</div>) : <span className="text-sev-high">none configured: imports are refused</span>}
        </dd>
      </div>
    </dl>
  );
}

function ImportBundle({ onDone }: { onDone: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function upload(e: FormEvent) {
    e.preventDefault();
    if (!file) return;
    setBusy(true);
    setError(null);
    setMsg(null);
    try {
      const b = await uploadScriptBundle(file);
      setMsg(`Imported script library ${b.version} (${b.scripts.length} scripts).`);
      setFile(null);
      onDone();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="mt-4 border-t border-line pt-4">
      <form onSubmit={upload} className="flex flex-wrap items-end gap-3">
        <label className="text-sm">
          <span className="mb-1 block font-medium text-ink-2">Import signed bundle (.tar.gz)</span>
          <input type="file" accept=".gz,.tgz,application/gzip" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm" />
        </label>
        <Button type="submit" variant="primary" disabled={!file || busy}>
          {busy ? "Verifying…" : "Import"}
        </Button>
      </form>
      {msg && <p className="mt-2 text-sm text-good" role="status">{msg}</p>}
      {error && (
        <div role="alert" className="mt-2 rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
          {error}
        </div>
      )}
    </div>
  );
}

function RunsTable({ runs }: { runs: ScriptRun[] }) {
  if (runs.length === 0) return <Empty>No scripts have been run yet.</Empty>;
  return (
    <Table head={["Requested", "Device", "Script", "Parameters", "Status", "Exit", "Output"]}>
      {runs.map((r) => (
        <tr key={r.id} className="align-top">
          <td className="px-3 py-2 text-xs">
            <span title={fmtTime(r.created_at)}>{fmtAgo(r.created_at)}</span>
            <div className="text-ink-3">by {r.requested_by_email ?? "—"}</div>
            {r.approved_by_email && <div className="text-ink-3">approved by {r.approved_by_email}</div>}
            {r.reason && <div className="text-ink-2">“{r.reason}”</div>}
          </td>
          <td className="px-3 py-2">
            <Link to={`/devices/${r.device_id}`} className="hover:text-accent">
              {r.hostname}
            </Link>
          </td>
          <td className="px-3 py-2 font-mono text-xs">
            {r.script}
            <div className="text-ink-3">v{r.bundle_version}</div>
          </td>
          <td className="max-w-[14rem] break-words px-3 py-2 font-mono text-[11px] text-ink-2">
            {Object.entries(r.parameters).map(([k, v]) => `${k}=${String(v)}`).join(" ") || "—"}
          </td>
          <td className="px-3 py-2">
            <Tag tone={RUN_TONE[r.status] ?? "default"}>{r.status}</Tag>
            {r.completed_at && <div className="mt-0.5 text-[11px] text-ink-3">{fmtAgo(r.completed_at)}</div>}
          </td>
          <td className="px-3 py-2 font-mono text-xs">{r.exit_code ?? "—"}</td>
          <td className="max-w-[24rem] px-3 py-2">
            {r.output ? (
              <details>
                <summary className="cursor-pointer text-xs text-accent">Show output</summary>
                <pre className="mt-1 max-h-64 overflow-auto whitespace-pre-wrap break-words text-[11px] text-ink-2">{r.output}</pre>
              </details>
            ) : (
              <span className="text-xs text-ink-3">—</span>
            )}
          </td>
        </tr>
      ))}
    </Table>
  );
}

export default function Scripts() {
  const { can } = useAuth();
  const admin = can("admin");
  const lib = useApi(api.scripts, []);
  const pending = useApi(api.scriptPendingApprovals, [], 30000);
  const runs = useApi(() => api.scriptRuns({ limit: 100 }), [], 30000);

  return (
    <div>
      <PageHeader
        title="Scripts"
        subtitle="Reviewed maintenance scripts that admins can run on devices."
        actions={
          <Link to="/devices" className="text-sm text-accent hover:underline">
            Back to devices
          </Link>
        }
      />
      <p className="mb-4 rounded border border-line bg-surface-1 px-3 py-2 text-sm text-ink-2">
        Scripts come only from the signed library built from the repository (<code>device-scripts/</code>, changed through reviewed pull requests and
        released with a <code>scripts-vX.Y.Z</code> tag). There are no free-form commands: the agent refuses anything that is not in a library signed by a
        trusted key. Low-risk scripts run straight away; medium and high-risk scripts need a second admin on the{" "}
        {admin ? <Link to="/approvals" className="text-accent hover:underline">Approvals</Link> : "Approvals"} page. Run a script from a device&apos;s page.
      </p>

      <Card title="Library" className="mb-4">
        <ErrorNote error={lib.error} />
        {lib.data && <BundleInfo bundle={lib.data.bundle} trustedKeys={lib.data.trusted_keys} />}
        {lib.data && lib.data.scripts.length > 0 && (
          <div className="mt-4">
            <Table head={["Script", "Platform", "Risk", "Parameters", "Timeout"]}>
              {lib.data.scripts.map((s) => (
                <tr key={`${s.platform}-${s.name}`} className="align-top">
                  <td className="px-3 py-2">
                    <div className="font-mono text-sm">{s.name}</div>
                    <div className="text-xs text-ink-3">{s.description}</div>
                  </td>
                  <td className="px-3 py-2 text-xs">
                    {OS_LABEL[s.platform] ?? s.platform}
                    <div className="text-ink-3">{s.interpreter}</div>
                  </td>
                  <td className="px-3 py-2">
                    <RiskTag risk={s.risk} />
                    {s.requires_approval && <div className="mt-1 text-[11px] text-ink-3">needs 2nd admin</div>}
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px] text-ink-2">
                    {s.parameters.length ? s.parameters.map((p) => <div key={p.name}>{describeParam(p)}</div>) : "—"}
                  </td>
                  <td className="px-3 py-2 text-xs">{s.timeout_seconds}s</td>
                </tr>
              ))}
            </Table>
          </div>
        )}
        {admin && <ImportBundle onDone={lib.reload} />}
      </Card>

      <Card title="Script runs waiting for approval" className="mb-4">
        <ErrorNote error={pending.error} />
        <ApprovalList items={pending.data} onChanged={() => { pending.reload(); runs.reload(); }} empty="No script runs are waiting for approval." />
      </Card>

      <Card title="Run history">
        <ErrorNote error={runs.error} />
        {runs.data && <RunsTable runs={runs.data} />}
      </Card>
    </div>
  );
}
