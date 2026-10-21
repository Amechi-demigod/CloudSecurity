import { useState } from "react";
import { ApiError } from "../../api";
import { Button, Card, ErrorNote, Tag } from "../../components/ui";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { fmtIn, summarizeUpdateNow, updatesApi, type PendingUpdate, type UpdateAutomation as Automation } from "../../updatesApi";

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : String(e);
}

const STAGE: Record<string, { label: string; tone: "default" | "warn" | "good" | "accent" }> = {
  pilot: { label: "Pilot soaking", tone: "accent" },
  all: { label: "all devices", tone: "good" },
  paused: { label: "paused", tone: "warn" },
};

/** Human description of a device's pending update (device page, Updates tab). */
export function PendingUpdateView({ p }: { p: PendingUpdate }) {
  switch (p.state) {
    case "waiting_checkin":
      return (
        <span>
          Waiting for the next check-in
          {p.next_checkin_by ? ` (≤ ${Math.ceil(p.check_in_interval_seconds / 60)} min, ${fmtIn(p.next_checkin_by)})` : ""}. {p.message}.
        </span>
      );
    case "offered":
      return (
        <span>
          Update offered {p.offered_at ? <span title={fmtTime(p.offered_at)}>{fmtAgo(p.offered_at)}</span> : ""}
          {p.starts_by ? <>, starts {fmtIn(p.starts_by)} <span className="text-ink-3">(by {fmtTime(p.starts_by)})</span></> : ""}.
          <div className="text-xs text-ink-3">{p.message}</div>
        </span>
      );
    case "update_now_requested":
      return <span>{p.message}.</span>;
    case "updating":
      return <span>{p.message}</span>;
    case "up_to_date":
      return <span className="text-good">Up to date ({p.message}).</span>;
    case "blocked":
      return <span className="text-sev-high">Not offered: {p.message}.</span>;
    case "no_target":
      return <span className="text-ink-3">No update targeted ({p.message}).</span>;
    default:
      return <span className="text-ink-3">{p.message || "—"}</span>;
  }
}

/** "Update now" for one device (analysts and admins). */
export function UpdateNowButton({ deviceId, pending, onDone }: { deviceId: string; pending?: PendingUpdate; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  if (!pending?.can_update_now) return null;
  async function go() {
    setBusy(true);
    setError(null);
    setMsg(null);
    try {
      const r = await updatesApi.updateNow({ device_id: deviceId });
      setMsg(
        r.queued[0]?.command === "recheck_posture"
          ? "Queued. This agent version has no check_for_update yet: it re-checks posture, then starts the update without delay."
          : "Queued. The agent checks in at its next command poll (about a minute) and starts the update right away.",
      );
      onDone();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="mt-2">
      <Button variant="primary" disabled={busy} onClick={go}>
        {busy ? "Queuing…" : "Update now"}
      </Button>
      <span className="ml-2 text-xs text-ink-3">Checks in immediately and skips the random start delay. The agent still verifies the signed release.</span>
      {msg && <div className="mt-1 text-xs text-good" role="status">{msg}</div>}
      <ErrorNote error={error} />
    </div>
  );
}

function RolloutStatus({ a, admin, onChanged }: { a: Automation; admin: boolean; onChanged: () => void }) {
  const [error, setError] = useState<string | null>(null);
  const r = a.rollout;
  if (a.mode !== "automatic") return null;
  if (!r.version) return <p className="text-sm text-ink-3">No release imported yet: the next imported release goes to the Pilot ring right away.</p>;
  async function promote() {
    const reason = window.prompt(`Give ${r.version} to all devices now? Reason:`, r.stage === "paused" ? "failure understood, safe to continue" : "pilot looks good");
    if (!reason || reason.trim().length < 3) return;
    setError(null);
    try {
      await updatesApi.promote(reason.trim());
      onChanged();
    } catch (e) {
      setError(errMsg(e));
    }
  }
  const stage = STAGE[r.stage ?? ""] ?? { label: r.stage ?? "—", tone: "default" as const };
  return (
    <div className="text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span>
          Rolling out <span className="font-mono">{r.version}</span>
        </span>
        <Tag tone={stage.tone}>{stage.label}</Tag>
        {r.stage_at && <span className="text-xs text-ink-3" title={fmtTime(r.stage_at)}>since {fmtAgo(r.stage_at)}</span>}
      </div>
      {r.stage === "pilot" && (
        <p className="mt-1 text-xs text-ink-2">
          {r.pilot_ring ?? "Pilot"} ring ({r.pilot_devices} device{r.pilot_devices === 1 ? "" : "s"}) has it now; everyone else{" "}
          {r.promote_at ? <>gets it {fmtIn(r.promote_at)} ({fmtTime(r.promote_at)})</> : "after the soak period"} unless a {r.pilot_ring ?? "Pilot"} device
          fails to update.
          {r.pilot_devices === 0 && " Tip: assign one or two devices to the Pilot ring on their device page (Updates tab)."}
        </p>
      )}
      {r.stage === "paused" && <p className="mt-1 text-xs text-sev-high">Paused: {r.paused_reason}. Publish a fixed release, or promote anyway.</p>}
      {r.stage === "all" && <p className="mt-1 text-xs text-ink-2">Every ring targets {r.version}; devices pick it up at their next check-in.</p>}
      {admin && (r.stage === "pilot" || r.stage === "paused") && (
        <div className="mt-2">
          <Button onClick={promote}>{r.stage === "paused" ? "Promote anyway" : "Promote to all devices now"}</Button>
        </div>
      )}
      <ErrorNote error={error} />
    </div>
  );
}

function AutoImport({ a, admin, onChanged }: { a: Automation; admin: boolean; onChanged: () => void }) {
  const ai = a.auto_import;
  const [repo, setRepo] = useState(ai.repo);
  const [intervalMin, setIntervalMin] = useState(String(ai.interval_minutes));
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function save(body: Parameters<typeof updatesApi.setAutomation>[0]) {
    setBusy(true);
    setError(null);
    try {
      await updatesApi.setAutomation({ reason: "auto-import settings changed from the console", ...body });
      onChanged();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }
  async function checkNow() {
    setBusy(true);
    setError(null);
    setMsg(null);
    try {
      const r = await updatesApi.checkGithub();
      setMsg(`${r.status}: ${r.message}`);
      onChanged();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }
  const tone = ai.status === "ok" ? "good" : ai.status ? "warn" : "default";
  return (
    <div className="text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">Import new releases from GitHub automatically</span>
        <Tag tone={ai.enabled ? "good" : "default"}>{ai.enabled ? `on, every ${ai.interval_minutes} min` : "off"}</Tag>
        {admin && (
          <Button disabled={busy} onClick={() => save({ auto_import_enabled: !ai.enabled })}>
            {ai.enabled ? "Turn off" : "Turn on"}
          </Button>
        )}
        {admin && (
          <Button disabled={busy} onClick={checkNow}>
            {busy ? "Checking…" : "Check now"}
          </Button>
        )}
      </div>
      <p className="mt-1 text-xs text-ink-3">
        Polls github.com/{ai.repo} for new <code>agent-v*</code> releases and imports <code>cnapp-agent-update.tar.gz</code> with the same checks as an
        upload: signature against the trusted release keys, size and SHA-256 of every binary, expiry. Unsigned or tampered bundles are refused and
        notified. Uses HTTPS_PROXY / NO_PROXY from the server environment; without internet access it only logs.
      </p>
      {ai.checked_at && (
        <p className="mt-1 text-xs">
          Last check <span title={fmtTime(ai.checked_at)}>{fmtAgo(ai.checked_at)}</span>: <Tag tone={tone}>{ai.status ?? "—"}</Tag>{" "}
          <span className="text-ink-2">{ai.message}</span>
        </p>
      )}
      {admin && (
        <div className="mt-2 flex flex-wrap items-end gap-2">
          <label className="text-xs">
            <span className="mb-1 block text-ink-3">Repository (OWNER/NAME)</span>
            <input aria-label="Release repository" value={repo} onChange={(e) => setRepo(e.target.value)}
              className="w-64 rounded border border-line bg-surface-2 px-2 py-1 text-sm" />
          </label>
          <label className="text-xs">
            <span className="mb-1 block text-ink-3">Check every (minutes)</span>
            <input aria-label="Auto-import interval" type="number" min={15} max={10080} value={intervalMin} onChange={(e) => setIntervalMin(e.target.value)}
              className="w-24 rounded border border-line bg-surface-2 px-2 py-1 text-sm" />
          </label>
          <Button disabled={busy || (repo === ai.repo && intervalMin === String(ai.interval_minutes))}
            onClick={() => save({ auto_import_repo: repo.trim(), auto_import_interval_minutes: Math.round(Number(intervalMin)) })}>
            Save
          </Button>
        </div>
      )}
      {msg && <p className="mt-1 text-xs text-ink-2" role="status">{msg}</p>}
      <ErrorNote error={error} />
    </div>
  );
}

/** Update mode (automatic / manual), automatic rollout status, auto-import, fleet "update now". */
export default function UpdateAutomationCard({ admin, onChanged }: { admin: boolean; onChanged: () => void }) {
  const auto = useApi(updatesApi.automation, [], 30000);
  const [soak, setSoak] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const a = auto.data;

  function changed() {
    auto.reload();
    onChanged();
  }
  async function setMode(mode: "automatic" | "manual") {
    if (!a || a.mode === mode) return;
    setBusy(true);
    setError(null);
    try {
      await updatesApi.setAutomation({ mode, reason: `update mode set to ${mode} from the console` });
      changed();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }
  async function saveSoak() {
    if (soak === null) return;
    setBusy(true);
    setError(null);
    try {
      await updatesApi.setAutomation({ soak_hours: Math.max(0, Math.round(Number(soak))), reason: "soak period changed from the console" });
      setSoak(null);
      changed();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }
  async function updateAllNow() {
    if (!window.confirm("Make every device with a pending update check in now and start it without the random delay?")) return;
    setBusy(true);
    setError(null);
    setMsg(null);
    try {
      setMsg(summarizeUpdateNow(await updatesApi.updateNow({ all: true })));
      changed();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card
      title="Update mode"
      className="mb-4"
      actions={
        admin && a ? (
          <Button disabled={busy} onClick={updateAllNow}>
            Update all now
          </Button>
        ) : undefined
      }
    >
      <ErrorNote error={auto.error} />
      {a && (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-3" role="radiogroup" aria-label="Update mode">
            {(["automatic", "manual"] as const).map((m) => (
              <label key={m} className={`flex max-w-md cursor-pointer gap-2 rounded border px-3 py-2 text-sm ${a.mode === m ? "border-accent" : "border-line"}`}>
                <input type="radio" name="update-mode" checked={a.mode === m} disabled={!admin || busy} onChange={() => setMode(m)} />
                <span>
                  <span className="font-medium">{m === "automatic" ? "Automatic (recommended)" : "Manual"}</span>
                  <span className="block text-xs text-ink-3">
                    {m === "automatic"
                      ? `Each new release goes to the Pilot ring at once and to all other devices after ${a.soak_hours} h, unless a Pilot device fails to update (then the rollout pauses and you are notified).`
                      : "You choose each ring's target release, percentage and pause below (advanced)."}
                  </span>
                </span>
              </label>
            ))}
          </div>
          {a.mode === "automatic" && admin && (
            <div className="flex flex-wrap items-end gap-2 text-xs">
              <label>
                <span className="mb-1 block text-ink-3">Soak period before everyone gets it (hours)</span>
                <input aria-label="Soak period in hours" type="number" min={0} max={720} value={soak ?? String(a.soak_hours)}
                  onChange={(e) => setSoak(e.target.value)} className="w-24 rounded border border-line bg-surface-2 px-2 py-1 text-sm" />
              </label>
              <Button disabled={busy || soak === null || soak === String(a.soak_hours)} onClick={saveSoak}>
                Save
              </Button>
            </div>
          )}
          <RolloutStatus a={a} admin={admin} onChanged={changed} />
          <AutoImport key={`${a.auto_import.repo}-${a.auto_import.interval_minutes}`} a={a} admin={admin} onChanged={changed} />
          <p className="text-xs text-ink-3">
            Agents get offers at their regular check-in (every 15 min by default) and start after a random delay of up to {a.jitter_seconds} s (grows with
            fleet size). <span className="font-medium">Update now</span> (here, per ring below, or on a device page) skips both.
          </p>
          {msg && <p className="text-sm text-good" role="status">{msg}</p>}
          <ErrorNote error={error} />
        </div>
      )}
    </Card>
  );
}
