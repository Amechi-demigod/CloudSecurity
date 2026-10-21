import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { ApiError, api, uploadAgentRelease, type AgentRelease, type UpdateRing } from "../../api";
import { useAuth } from "../../auth/context";
import { Button, Card, Empty, ErrorNote, PageHeader, Stat, Table, Tag } from "../../components/ui";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { summarizeUpdateNow, updatesApi } from "../../updatesApi";
import UpdateAutomationCard from "./UpdateAutomation";

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : String(e);
}

function shortKey(k: string) {
  return k.replace(/^ed25519:/, "");
}

function releaseState(r: AgentRelease) {
  if (r.withdrawn_at) return <Tag tone="warn">withdrawn</Tag>;
  if (r.expired) return <Tag tone="warn">expired</Tag>;
  return <Tag tone="good">active</Tag>;
}

/** One editable row of the ring table (admins). */
function RingRow({
  ring,
  releases,
  progress,
  admin,
  onSaved,
}: {
  ring: UpdateRing;
  releases: AgentRelease[];
  progress?: { devices: number; on_target: number; updating: number; failed: number };
  admin: boolean;
  onSaved: () => void;
}) {
  const [target, setTarget] = useState(ring.target_release_id ?? "");
  const [percent, setPercent] = useState(String(ring.rollout_percent));
  const [groups, setGroups] = useState(ring.device_groups.join(", "));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dirty =
    target !== (ring.target_release_id ?? "") || percent !== String(ring.rollout_percent) || groups !== ring.device_groups.join(", ");

  async function save(extra: { paused?: boolean } = {}) {
    setBusy(true);
    setError(null);
    try {
      const pct = Number(percent);
      await api.updateRing(
        ring.id,
        {
          reason: extra.paused === undefined ? "rollout change from the console" : extra.paused ? "rollout paused" : "rollout resumed",
          ...(target ? { target_release_id: target } : { clear_target: ring.target_release_id !== null }),
          rollout_percent: Number.isFinite(pct) ? Math.max(0, Math.min(100, Math.round(pct))) : ring.rollout_percent,
          device_groups: ring.is_default ? undefined : groups.split(",").map((g) => g.trim()).filter(Boolean),
          ...extra,
        },
      );
      onSaved();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  const [notice, setNotice] = useState<string | null>(null);
  async function updateNow() {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      setNotice(summarizeUpdateNow(await updatesApi.updateNow({ ring_id: ring.id })));
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  const active = releases.filter((r) => !r.withdrawn_at && !r.expired);
  return (
    <tr className="border-t border-line align-top">
      <td className="py-2 pr-3">
        <div className="font-medium">{ring.name}</div>
        <div className="text-xs text-ink-3">{ring.description}</div>
        {error && <div className="mt-1 text-xs text-sev-high" role="alert">{error}</div>}
      </td>
      <td className="py-2 pr-3 text-xs">
        {ring.is_default ? (
          <span className="text-ink-3">all other devices</span>
        ) : admin ? (
          <input
            aria-label={`Device groups of ${ring.name}`}
            value={groups}
            onChange={(e) => setGroups(e.target.value)}
            className="w-36 rounded border border-line bg-surface-2 px-2 py-1 text-xs"
          />
        ) : (
          ring.device_groups.join(", ") || "—"
        )}
        {ring.explicit_devices > 0 && <div className="mt-1 text-ink-3">+{ring.explicit_devices} assigned</div>}
      </td>
      <td className="py-2 pr-3">
        {admin ? (
          <select
            aria-label={`Target release of ${ring.name}`}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="rounded border border-line bg-surface-2 px-2 py-1 text-sm"
          >
            <option value="">— none —</option>
            {active.map((r) => (
              <option key={r.id} value={r.id}>
                {r.version}
              </option>
            ))}
          </select>
        ) : (
          ring.target_version ?? "—"
        )}
      </td>
      <td className="py-2 pr-3">
        {admin ? (
          <input
            aria-label={`Rollout percentage of ${ring.name}`}
            type="number"
            min={0}
            max={100}
            value={percent}
            onChange={(e) => setPercent(e.target.value)}
            className="w-20 rounded border border-line bg-surface-2 px-2 py-1 text-sm"
          />
        ) : (
          `${ring.rollout_percent}%`
        )}
      </td>
      <td className="py-2 pr-3 text-xs">
        {progress ? (
          <>
            {progress.on_target}/{progress.devices} on target
            {progress.updating > 0 && <div>{progress.updating} updating</div>}
            {progress.failed > 0 && <div className="text-sev-high">{progress.failed} failed / rolled back</div>}
          </>
        ) : (
          "—"
        )}
      </td>
      <td className="py-2">
        <div className="flex flex-wrap gap-2">
          {ring.paused ? <Tag tone="warn">paused</Tag> : <Tag tone="good">active</Tag>}
          {admin && (
            <>
              <Button disabled={busy || !dirty} variant="primary" onClick={() => save()}>
                Save
              </Button>
              <Button disabled={busy} onClick={() => save({ paused: !ring.paused })}>
                {ring.paused ? "Resume" : "Pause"}
              </Button>
              {ring.target_release_id && !ring.paused && (
                <Button disabled={busy} onClick={updateNow} title="Devices in this ring check in now and start the target release without the random delay">
                  Update now
                </Button>
              )}
            </>
          )}
        </div>
        {notice && <div className="mt-1 text-xs text-ink-2" role="status">{notice}</div>}
      </td>
    </tr>
  );
}

export default function AgentUpdates() {
  const { can } = useAuth();
  const admin = can("admin");
  const summary = useApi(api.updateSummary, [], 30000);
  const rings = useApi(api.updateRings, [], 30000);
  const releases = useApi(api.agentReleases, [], 60000);
  const keys = useApi(api.updateKeys, []);
  const [file, setFile] = useState<File | null>(null);
  const [uploadMsg, setUploadMsg] = useState<string | null>(null);
  const [uploadErr, setUploadErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function reload() {
    summary.reload();
    rings.reload();
    releases.reload();
  }

  async function upload(e: FormEvent) {
    e.preventDefault();
    if (!file) return;
    setBusy(true);
    setUploadErr(null);
    setUploadMsg(null);
    try {
      const r = await uploadAgentRelease(file);
      setUploadMsg(`Imported ${r.version}, signed by ${shortKey(r.key_id)} (${r.artifacts.length} platform binaries).`);
      setFile(null);
      reload();
    } catch (err) {
      setUploadErr(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  async function withdraw(r: AgentRelease) {
    const reason = window.prompt(`Withdraw ${r.version}? It will no longer be offered to devices. Reason:`);
    if (!reason || reason.trim().length < 3) return;
    try {
      await api.withdrawRelease(r.id, reason.trim());
      reload();
    } catch (err) {
      setUploadErr(errMsg(err));
    }
  }

  const progress = new Map((summary.data?.rings ?? []).map((r) => [r.ring_id, r]));
  return (
    <div>
      <PageHeader
        title="Agent updates"
        subtitle="Signed endpoint-agent releases and their rollout. Agents only install releases signed by a release key compiled into them; this server just chooses which one."
        actions={
          <Link to="/devices" className="text-sm text-accent hover:underline">
            Back to devices
          </Link>
        }
      />
      <UpdateAutomationCard admin={admin} onChanged={reload} />
      {summary.data && (
        <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
          <Stat label="Devices" value={summary.data.devices} sub={`${summary.data.versions.length} agent version(s)`} />
          <Stat
            label="Latest version"
            value={summary.data.versions[0]?.version ?? "—"}
            sub={summary.data.versions[0] ? `${summary.data.versions[0].devices} device(s)` : undefined}
          />
          <Stat label="Updating" value={(summary.data.statuses.downloading ?? 0) + (summary.data.statuses.verified ?? 0) + (summary.data.statuses.installing ?? 0)} />
          <Stat
            label="Failed / rolled back"
            value={(summary.data.statuses.failed ?? 0) + (summary.data.statuses.rolled_back ?? 0) + (summary.data.statuses.rejected ?? 0)}
            sub="last reported status"
          />
        </div>
      )}

      <Card title="Rollout rings" className="mb-4">
        <ErrorNote error={rings.error} />
        <p className="mb-2 text-xs text-ink-3">
          A device belongs to the ring it is assigned to on its device page, else the first ring listing its device group, else “All devices”. A pin on the
          device page overrides its ring. Devices that fail an update roll back automatically and are not offered that release again.
        </p>
        {rings.data && releases.data && (
          <Table head={["Ring", "Device groups", "Target release", "Rollout %", "Progress", ""]}>
            {rings.data.map((r) => (
              <RingRow key={`${r.id}-${r.updated_at}`} ring={r} releases={releases.data ?? []} progress={progress.get(r.id)} admin={admin} onSaved={reload} />
            ))}
          </Table>
        )}
      </Card>

      <Card title="Fleet versions" className="mb-4">
        {summary.data && summary.data.versions.length > 0 ? (
          <Table head={["Agent version", "Devices"]}>
            {summary.data.versions.map((v) => (
              <tr key={v.version} className="border-t border-line">
                <td className="py-1.5 pr-3 font-mono text-sm">{v.version}</td>
                <td className="py-1.5">{v.devices}</td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty>No enrolled devices.</Empty>
        )}
      </Card>

      <Card title="Releases" className="mb-4">
        <ErrorNote error={releases.error} />
        {admin && (
          <form onSubmit={upload} className="mb-4 flex flex-wrap items-end gap-3">
            <label className="text-sm">
              <span className="mb-1 block font-medium text-ink-2">Signed release bundle (.tar.gz)</span>
              <input type="file" accept=".gz,.tgz,application/gzip" onChange={(e) => setFile(e.target.files?.[0] ?? null)} className="text-sm" />
            </label>
            <Button type="submit" variant="primary" disabled={!file || busy}>
              {busy ? "Verifying…" : "Import release"}
            </Button>
            <span className="text-xs text-ink-3">
              Or on the server: <code>sudo cnapp-ctl agent-release import BUNDLE.tar.gz</code>
            </span>
          </form>
        )}
        {uploadMsg && <p className="mb-2 text-sm text-good" role="status">{uploadMsg}</p>}
        <ErrorNote error={uploadErr} />
        {releases.data && releases.data.length === 0 && <Empty>No releases imported yet. See docs/AGENT_UPDATES.md for the release process.</Empty>}
        {releases.data && releases.data.length > 0 && (
          <Table head={["Version", "State", "Signed by", "Released", "Expires", "Platforms", "Running", ""]}>
            {releases.data.map((r) => (
              <tr key={r.id} className="border-t border-line align-top">
                <td className="py-1.5 pr-3">
                  <div className="font-mono text-sm">{r.version}</div>
                  {r.notes && <div className="text-xs text-ink-3">{r.notes}</div>}
                  {r.rollback_allowed_from.length > 0 && <div className="text-xs text-ink-3">signed rollback from {r.rollback_allowed_from.join(", ")}</div>}
                </td>
                <td className="py-1.5 pr-3">{releaseState(r)}</td>
                <td className="py-1.5 pr-3 font-mono text-xs" title={r.key_id}>
                  {shortKey(r.key_id)}
                </td>
                <td className="py-1.5 pr-3 text-xs" title={fmtTime(r.released_at)}>
                  {fmtAgo(r.released_at)}
                  <div className="text-ink-3">imported by {r.imported_by}</div>
                </td>
                <td className="py-1.5 pr-3 text-xs">{fmtTime(r.expires_at)}</td>
                <td className="py-1.5 pr-3 text-xs">
                  {r.artifacts.map((a) => (
                    <div key={`${a.os}/${a.arch}`} title={`sha256 ${a.sha256}`}>
                      {a.os}/{a.arch} · {(a.size_bytes / 1048576).toFixed(1)} MB
                    </div>
                  ))}
                </td>
                <td className="py-1.5 pr-3">{r.devices_running}</td>
                <td className="py-1.5">
                  {admin && !r.withdrawn_at && (
                    <Button variant="danger" onClick={() => withdraw(r)}>
                      Withdraw
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Card title="Trusted release-signing keys (server copy)">
        <ErrorNote error={keys.error ?? keys.data?.error ?? null} />
        {keys.data && keys.data.keys.length === 0 && (
          <Empty>No release keys configured: imports are refused. Create one with scripts/agent-release-keygen.</Empty>
        )}
        <ul className="space-y-1 text-sm">
          {keys.data?.keys.map((k) => (
            <li key={k.key_id} className="font-mono text-xs">
              {k.key_id} <span className="text-ink-3">({k.source})</span>
            </li>
          ))}
        </ul>
        <p className="mt-2 text-xs text-ink-3">
          Agents verify signatures with the keys compiled into them; this list only lets the server refuse bundles they would reject.
        </p>
      </Card>
    </div>
  );
}
