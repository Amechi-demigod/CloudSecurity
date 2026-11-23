import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { ApiError, api, uploadAgentRelease, type AgentRelease, type DeviceSummary, type UpdateRing } from "../../api";
import { useAuth } from "../../auth/context";
import { OverflowMenu } from "../../components/OverflowMenu";
import { Button, Card, Empty, ErrorNote, Modal, PageHeader, Stat, Table, Tag } from "../../components/ui";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { ts, useSort } from "../../lib/useSort";
import { summarizeUpdateNow, updatesApi } from "../../updatesApi";
import UpdateAutomationCard from "./UpdateAutomation";
import { PAGE_INFO } from "../../lib/pageInfo";

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

type Draft = { target: string; percent: string; groups: string };
const draftOf = (r: UpdateRing): Draft => ({ target: r.target_release_id ?? "", percent: String(r.rollout_percent), groups: r.device_groups.join(", ") });
const isDirty = (r: UpdateRing, d: Draft | undefined) => !!d && (d.target !== (r.target_release_id ?? "") || d.percent !== String(r.rollout_percent) || d.groups !== r.device_groups.join(", "));

type Progress = { devices: number; on_target: number; updating: number; failed: number };

function GroupStatus({ ring, p }: { ring: UpdateRing; p?: Progress }) {
  if (ring.paused) return <Tag tone="warn">Paused</Tag>;
  if (!ring.target_release_id) return <Tag>No version chosen</Tag>;
  if (p && p.failed > 0) return <Tag tone="critical">{p.failed} failed</Tag>;
  if (p && p.devices > 0 && p.on_target >= p.devices) return <Tag tone="good">All updated</Tag>;
  if (p && p.devices === 0) return <Tag>No devices</Tag>;
  return <Tag tone="accent">Updating</Tag>;
}

function ProgressBar({ p }: { p?: Progress }) {
  if (!p) return <span className="text-ink-3">—</span>;
  const pct = p.devices ? Math.round((p.on_target / p.devices) * 100) : 0;
  return (
    <div className="min-w-[8rem]">
      <div className="text-xs text-ink-2">{p.on_target} of {p.devices}</div>
      <div className="mt-1 h-1.5 w-full overflow-hidden rounded bg-line" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label="Devices updated">
        <div className="h-full bg-accent" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

/** One row of the update-groups table. Edits are kept by the table (one save bar), never saved from here. */
function RingRow({ ring, releases, progress, admin, draft, editing, busy, onEdit, onDraft, onPause, onResume, onUpdateNow }: {
  ring: UpdateRing;
  releases: AgentRelease[];
  progress?: Progress;
  admin: boolean;
  draft: Draft;
  editing: boolean;
  busy: boolean;
  onEdit: () => void;
  onDraft: (d: Draft) => void;
  onPause: () => void;
  onResume: () => void;
  onUpdateNow: () => void;
}) {
  const active = releases.filter((r) => !r.withdrawn_at && !r.expired);
  const dirty = isDirty(ring, draft);
  const canNow = !!ring.target_release_id && !ring.paused;
  return (
    <tr className={`border-t border-line align-top ${dirty ? "bg-accent/5" : ""}`}>
      <td className="py-2 pr-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium">{ring.name}</span>
          <GroupStatus ring={ring} p={progress} />
          {dirty && <Tag tone="accent">Unsaved</Tag>}
        </div>
        <div className="text-xs text-ink-3">{ring.description}</div>
        {editing && !ring.is_default && (
          <label className="mt-2 block text-xs text-ink-3">
            Device groups
            <input aria-label={`Device groups of ${ring.name}`} value={draft.groups} onChange={(e) => onDraft({ ...draft, groups: e.target.value })}
              className="mt-0.5 block w-48 rounded border border-line bg-surface-2 px-2 py-1 text-sm text-ink" />
          </label>
        )}
        {ring.explicit_devices > 0 && <div className="text-xs text-ink-3">+{ring.explicit_devices} assigned by hand</div>}
      </td>
      <td className="py-2 pr-3 text-sm">{progress?.devices ?? "—"}</td>
      <td className="py-2 pr-3 text-sm">
        {editing ? (
          <select aria-label={`Version for ${ring.name}`} value={draft.target} onChange={(e) => onDraft({ ...draft, target: e.target.value })}
            className="rounded border border-line bg-surface-2 px-2 py-1 text-sm">
            <option value="">— none —</option>
            {active.map((r) => <option key={r.id} value={r.id}>{r.version}</option>)}
          </select>
        ) : (
          <span className="font-mono text-xs">{ring.target_version ?? "—"}</span>
        )}
        <div className="mt-1 text-xs text-ink-3">
          {editing ? (
            <label>
              Share of devices (%){" "}
              <input aria-label={`Share of devices in ${ring.name} (percent)`} type="number" min={0} max={100} value={draft.percent} onChange={(e) => onDraft({ ...draft, percent: e.target.value })}
                className="ml-1 w-16 rounded border border-line bg-surface-2 px-2 py-0.5 text-sm text-ink" />
            </label>
          ) : (
            ring.rollout_percent < 100 && `${ring.rollout_percent}% of devices`
          )}
        </div>
      </td>
      <td className="py-2 pr-3"><ProgressBar p={progress} /></td>
      <td className="py-2 text-right">
        {admin && (
          <div className="flex items-center justify-end gap-2">
            <Button disabled={busy || !canNow} onClick={onUpdateNow} title={canNow ? "Devices in this group check in now and start the new version without the random delay" : ring.paused ? "This group is paused" : "Choose a version first"}>
              Update now
            </Button>
            <OverflowMenu
              label={`More actions for ${ring.name}`}
              items={[
                { label: editing ? "Done editing" : "Edit…", onSelect: onEdit },
                ring.paused ? { label: "Resume", onSelect: onResume, disabled: busy } : { label: "Pause…", onSelect: onPause, disabled: busy },
              ]}
            />
          </div>
        )}
      </td>
    </tr>
  );
}

/** The update-groups table (the API calls them rings) with one save bar for all pending edits. */
function UpdateGroups({ rings, releases, progress, admin, onSaved }: {
  rings: UpdateRing[];
  releases: AgentRelease[];
  progress: Map<string, Progress>;
  admin: boolean;
  onSaved: () => void;
}) {
  const [drafts, setDrafts] = useState<Record<string, Draft>>({});
  const [editing, setEditing] = useState<Set<string>>(new Set());
  const [pausing, setPausing] = useState<UpdateRing | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const ordered = [...rings].sort((a, b) => a.position - b.position);
  const dirtyRings = ordered.filter((r) => isDirty(r, drafts[r.id]));
  const flash = (m: string) => {
    setToast(m);
    window.setTimeout(() => setToast(null), 4000);
  };

  async function save() {
    setBusy(true);
    setError(null);
    try {
      for (const ring of dirtyRings) {
        const d = drafts[ring.id];
        const pct = Number(d.percent);
        await api.updateRing(ring.id, {
          reason: "update group changed from the console",
          ...(d.target ? { target_release_id: d.target } : { clear_target: ring.target_release_id !== null }),
          rollout_percent: Number.isFinite(pct) ? Math.max(0, Math.min(100, Math.round(pct))) : ring.rollout_percent,
          device_groups: ring.is_default ? undefined : d.groups.split(",").map((g) => g.trim()).filter(Boolean),
        });
      }
      setDrafts({});
      setEditing(new Set());
      flash(`Rings saved: ${dirtyRings.length} update group${dirtyRings.length === 1 ? "" : "s"} changed.`);
      onSaved();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }
  async function setPaused(ring: UpdateRing, paused: boolean) {
    setBusy(true);
    setError(null);
    try {
      await api.updateRing(ring.id, { reason: paused ? "rollout paused" : "rollout resumed", paused });
      flash(`${ring.name} ${paused ? "paused" : "resumed"}.`);
      onSaved();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }
  async function updateNow(ring: UpdateRing) {
    setBusy(true);
    setError(null);
    try {
      flash(summarizeUpdateNow(await updatesApi.updateNow({ ring_id: ring.id })));
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <ErrorNote error={error} />
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="text-xs uppercase tracking-wide text-ink-3">
              <th scope="col" className="py-1.5 pr-3 font-medium">Group</th>
              <th scope="col" className="py-1.5 pr-3 font-medium">Devices</th>
              <th scope="col" className="py-1.5 pr-3 font-medium">Version</th>
              <th scope="col" className="py-1.5 pr-3 font-medium">Progress</th>
              <th scope="col" className="py-1.5 font-medium"><span className="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {ordered.map((r) => (
              <RingRow
                key={r.id}
                ring={r}
                releases={releases}
                progress={progress.get(r.id)}
                admin={admin}
                draft={drafts[r.id] ?? draftOf(r)}
                editing={editing.has(r.id)}
                busy={busy}
                onEdit={() => setEditing((prev) => { const n = new Set(prev); if (n.has(r.id)) n.delete(r.id); else n.add(r.id); return n; })}
                onDraft={(d) => setDrafts((prev) => ({ ...prev, [r.id]: d }))}
                onPause={() => setPausing(r)}
                onResume={() => void setPaused(r, false)}
                onUpdateNow={() => void updateNow(r)}
              />
            ))}
          </tbody>
        </table>
      </div>
      {dirtyRings.length > 0 && (
        <div role="region" aria-label="Unsaved changes" className="sticky bottom-3 z-10 mt-3 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-accent/50 bg-surface-1 px-4 py-2 shadow-lg">
          <span className="text-sm text-ink">{dirtyRings.length} unsaved change{dirtyRings.length === 1 ? "" : "s"}</span>
          <span className="flex gap-2">
            <Button disabled={busy} onClick={() => { setDrafts({}); setEditing(new Set()); }}>Discard</Button>
            <Button variant="primary" disabled={busy} onClick={() => void save()}>{busy ? "Saving…" : "Save changes"}</Button>
          </span>
        </div>
      )}
      {toast && <div role="status" className="fixed bottom-6 right-6 z-50 rounded-lg border border-line bg-surface-1 px-4 py-2 text-sm text-ink shadow-xl">{toast}</div>}
      <Modal open={!!pausing} onClose={() => setPausing(null)} title={`Pause ${pausing?.name ?? ""}?`}>
        <p className="text-sm text-ink-2">Devices in this group stop being offered new versions until you resume it. Devices already updating finish.</p>
        <div className="mt-4 flex justify-end gap-2">
          <Button onClick={() => setPausing(null)}>Cancel</Button>
          <Button variant="primary" onClick={() => { const r = pausing; setPausing(null); if (r) void setPaused(r, true); }}>Pause</Button>
        </div>
      </Modal>
    </>
  );
}

/** Devices that have not checked in (same rule as the Devices page's "Offline" filter: stale or inactive). */
function OfflineBanner({ devices }: { devices: DeviceSummary[] }) {
  if (devices.length === 0) return null;
  const since = (d: DeviceSummary) => (d.last_seen_at ? fmtAgo(d.last_seen_at).replace(" ago", "") : "a long time");
  const cls = "mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-sev-medium/50 bg-sev-medium/10 px-4 py-3 text-sm text-ink";
  if (devices.length === 1) {
    const d = devices[0];
    return (
      <div role="note" className={cls}>
        <span><strong>{d.hostname}</strong> hasn&apos;t checked in for {since(d)}, so it can&apos;t update until it&apos;s back online.</span>
        <Link to="/devices?connectivity=offline" className="text-accent hover:underline">View device ›</Link>
      </div>
    );
  }
  const top = devices.slice(0, 3);
  return (
    <div role="note" className={cls}>
      <span>
        <strong>{devices.length} devices</strong> can&apos;t update until they come back online. Longest offline: {top.map((d) => `${d.hostname} (${since(d)})`).join(", ")}.
      </span>
      <Link to="/devices?connectivity=offline" className="text-accent hover:underline">View all {devices.length} offline devices ›</Link>
    </div>
  );
}

export default function AgentUpdates() {
  const { can, platformAdmin } = useAuth();
  const admin = can("admin");
  // Devices that are not checking in: the Devices page's "Offline" filter (stale or inactive, see device_stale_hours), longest offline first.
  const offline = useApi(() => api.devices({ connectivity: "offline", sort: "seen", dir: "asc" }), [], 60000);
  const summary = useApi(api.updateSummary, [], 30000);
  const rings = useApi(api.updateRings, [], 30000);
  const releases = useApi(api.agentReleases, [], 60000);
  const keys = useApi(() => (platformAdmin ? api.updateKeys() : Promise.resolve(null)), [platformAdmin]);
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
      setUploadMsg(`Imported ${r.version} (${r.artifacts.length} platform binaries).`);
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
  // "Newest version" is the newest imported release, not the newest one seen on a device.
  const newest = [...(releases.data ?? [])].filter((r) => !r.withdrawn_at).sort((a, b) => (ts(b.released_at) ?? 0) - (ts(a.released_at) ?? 0))[0];
  const onNewest = newest ? (summary.data?.versions.find((v) => v.version === newest.version)?.devices ?? 0) : 0;
  const offlineList = offline.data ?? [];
  const verSort = useSort(summary.data?.versions, { version: (v) => v.version, devices: (v) => v.devices }, { key: "devices", dir: "desc" }, { devices: "desc" }, "ver_sort");
  const relSort = useSort(
    releases.data,
    {
      version: (r) => r.version,
      state: (r) => (r.withdrawn_at ? 2 : Date.parse(r.expires_at) <= Date.now() ? 1 : 0),
      signed: (r) => shortKey(r.key_id),
      released: (r) => ts(r.released_at),
      expires: (r) => ts(r.expires_at),
      platforms: (r) => r.artifacts.length,
      running: (r) => r.devices_running,
    },
    { key: "released", dir: "desc" },
    { released: "desc", expires: "desc", running: "desc", platforms: "desc" },
    "rel_sort",
  );
  return (
    <div>
      <PageHeader
        title="Agents & updates"
        info={PAGE_INFO.agents}
        subtitle="Keep the Sentrigis agent up to date on every device."
        actions={
          <Link to="/devices" className="text-sm text-accent hover:underline">
            Back to Computers &amp; servers
          </Link>
        }
      />
      {summary.data && (
        <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-3">
          <Stat label="Newest version" value={newest?.version ?? "—"} sub={newest ? "Latest release imported" : "No release imported yet"} />
          <Stat label={newest ? `Devices on ${newest.version}` : "Devices on the newest version"} value={newest ? `${onNewest} of ${summary.data.devices}` : "—"}
            sub={newest && summary.data.devices > onNewest ? `${summary.data.devices - onNewest} still updating or waiting` : undefined} to="/devices" />
          <Stat label="Not checking in" value={offlineList.length}
            sub={offlineList.length > 0 ? `${offlineList.slice(0, 2).map((d) => d.hostname).join(", ")}${offlineList.length > 2 ? "…" : ""}: can't update until they reconnect` : "Every device is reporting"}
            to={offlineList.length > 0 ? "/devices?connectivity=offline" : undefined} />
        </div>
      )}
      <OfflineBanner devices={offlineList} />
      <UpdateAutomationCard admin={admin} onChanged={reload} />
      <Card title="Update groups" className="mb-4">
        <ErrorNote error={rings.error} />
        <p className="mb-2 text-sm text-ink-2">New versions reach the groups in this order, top to bottom.</p>
        <details className="mb-3 text-xs text-ink-3">
          <summary className="cursor-pointer text-sm font-medium text-ink-2">How update groups work</summary>
          <p className="mt-2">
            A device belongs to the group it is assigned to on its device page, else the first group listing its device group, else “All devices”. A pin on the
            device page overrides its group. Devices that fail an update roll back automatically and are not offered that version again.
          </p>
        </details>
        {rings.data && releases.data && (
          <UpdateGroups rings={rings.data} releases={releases.data} progress={progress} admin={admin} onSaved={reload} />
        )}
      </Card>

      <Card title="Versions on your devices" className="mb-4">
        {summary.data && summary.data.versions.length > 0 ? (
          <Table
            tableId="agent-updates-1"
            head={[{ label: "Agent version", sort: "version" }, { label: "Devices", sort: "devices" }]}
            sort={verSort.sort}
            onSort={verSort.onSort}
          >
            {verSort.rows.map((v) => (
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

      <Card title="Imported releases" className="mb-4">
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
            {platformAdmin && (
              <span className="text-xs text-ink-3">
                Or on the server: <code>sudo cnapp-ctl agent-release import BUNDLE.tar.gz</code>
              </span>
            )}
          </form>
        )}
        {uploadMsg && <p className="mb-2 text-sm text-good" role="status">{uploadMsg}</p>}
        <ErrorNote error={uploadErr} />
        {releases.data && releases.data.length === 0 && <Empty>No releases imported yet.</Empty>}
        {releases.data && releases.data.length > 0 && (
          <Table
            tableId="agent-updates-2"
            head={[
              { label: "Version", sort: "version" },
              { label: "State", sort: "state" },
              ...(platformAdmin ? [{ label: "Signed by", sort: "signed" }] : []),
              { label: "Released", sort: "released" },
              { label: "Expires", sort: "expires" },
              { label: "Platforms", sort: "platforms" },
              { label: "Running", sort: "running" },
              "",
            ]}
            sort={relSort.sort}
            onSort={relSort.onSort}
          >
            {relSort.rows.map((r) => (
              <tr key={r.id} className="border-t border-line align-top">
                <td className="py-1.5 pr-3">
                  <div className="font-mono text-sm">{r.version}</div>
                  {r.notes && <div className="text-xs text-ink-3">{r.notes}</div>}
                  {r.rollback_allowed_from.length > 0 && <div className="text-xs text-ink-3">signed rollback from {r.rollback_allowed_from.join(", ")}</div>}
                </td>
                <td className="py-1.5 pr-3">{releaseState(r)}</td>
                {platformAdmin && (
                  <td className="py-1.5 pr-3 font-mono text-xs" title={r.key_id}>
                    {shortKey(r.key_id)}
                  </td>
                )}
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

      {platformAdmin && <Card title="Trusted release-signing keys (server copy)">
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
      </Card>}
    </div>
  );
}
