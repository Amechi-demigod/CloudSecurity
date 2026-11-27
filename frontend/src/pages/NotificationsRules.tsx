import { Check } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { ApiError, type Severity } from "../api";
import { SaveBar } from "../components/SaveBar";
import { Switch } from "../components/Switch";
import { Button, Card, Empty, ErrorNote, Field, Modal, NameCell, Pill, PillRow, Table, Tag, TextCell, type PillTone } from "../components/ui";
import { useApi } from "../lib/useApi";
import { SEV_RANK, useSort } from "../lib/useSort";
import { Link } from "react-router-dom";
import { notificationsApi, type Channel, type NotificationMeta, type Rule, type RuleInput, type RuleTestResult } from "../notificationsApi";

const EMPTY: RuleInput = {
  name: "",
  enabled: true,
  sources: [],
  event_types: [],
  min_severity: "high",
  subscription_ids: [],
  asset_ids: [],
  asset_types: [],
  tags: {},
  rule_ids: [],
  mitre_techniques: [],
  include_status_changes: false,
  channel_ids: [],
  throttle_minutes: 60,
  mode: "immediate",
  digest_hour: 8,
  timezone: "UTC",
  quiet_start: null,
  quiet_end: null,
  quiet_bypass_severity: null,
};

const tagsToText = (t: Record<string, string>) => Object.entries(t).map(([k, v]) => `${k}=${v}`).join(", ");
// Event types a rule can narrow down to: only for a single selected source with
// several kinds of events (e.g. endpoint devices: firewall off, stale, ...).
// `status_changed` has its own checkbox.
const humanize = (t: string) => (t.charAt(0).toUpperCase() + t.slice(1)).replace(/_/g, " ");
function selectableEventTypes(meta: NotificationMeta, sources: string[]): string[] {
  if (sources.length !== 1) return [];
  const types = (meta.sources.find((x) => x.name === sources[0])?.event_types ?? []).filter((t) => t !== "status_changed");
  return types.length > 1 ? types : [];
}

function errMsg(e: unknown) {
  return e instanceof ApiError || e instanceof Error ? e.message : String(e);
}

/** One line per channel for the result of "Send a test alert". */
function describeTest(r: RuleTestResult): { ok: boolean; text: string } {
  const parts = r.results.map((x) => (x.ok ? `${x.channel_name}: sent` : `${x.channel_name}: not sent (${x.error ?? x.status})`));
  return { ok: r.ok, text: `Test alert: ${parts.join("; ")}.` };
}

// --- the rule wizard --------------------------------------------------------------

const AREA_LABELS: Record<string, string> = {
  device: "Device health",
  device_tracking: "Device tracking",
  host_isolation: "Suspend sign-in",
  endpoint_action: "Actions on devices",
  remote_session: "Remote sessions",
  device_approvals: "Approvals",
  runtime_alert: "Threats detected",
  posture_finding: "Misconfigurations",
  vulnerability: "Vulnerabilities",
  attack_path: "Attack paths",
  scan: "Scan problems",
  external_finding: "Attack surface",
  reputation_finding: "Reputation",
  asset_lifecycle: "Asset lifecycle",
  directory_source: "Directory sync",
  agent_update: "Agent updates",
  server_update: "Server updates",
  agent_security: "Agent security",
};

const AREA_GROUPS: { title: string; sources: string[] }[] = [
  { title: "Computers & servers", sources: ["device", "device_tracking", "host_isolation", "endpoint_action", "remote_session", "device_approvals"] },
  { title: "Cloud", sources: ["runtime_alert", "posture_finding", "vulnerability", "attack_path", "scan"] },
  { title: "Internet-facing", sources: ["external_finding", "reputation_finding"] },
  { title: "Assets & platform", sources: ["asset_lifecycle", "directory_source", "agent_update", "server_update", "agent_security"] },
];
const LAST_GROUP = AREA_GROUPS.length - 1;

type Level = "medium" | "high" | "critical";
const LEVELS: { value: Level; label: string }[] = [
  { value: "medium", label: "Medium and above" },
  { value: "high", label: "High and above" },
  { value: "critical", label: "Critical only" },
];
const LEVEL_LABEL: Record<string, string> = { medium: "Medium and above", high: "High and above", critical: "Critical only" };
const RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

// Example alerts per area and severity, taken from what the backend sources really raise
// (backend/app/notifications/*). Only critical, high and medium are shown.
const EXAMPLES: Record<string, Partial<Record<Level, string[]>>> = {
  device: { high: ["Disk encryption is off", "Firewall is off"], medium: ["Antivirus signatures are outdated", "OS updates pending"] },
  device_tracking: { high: ["Connected from outside the allowed countries"], medium: ["Device not seen for several days", "Hardware changed"] },
  host_isolation: { critical: ["Suspend sign-in blocked - no local admin would remain"], high: ["Sign-in suspended", "Suspend sign-in failed"], medium: ["Suspend sign-in requested"] },
  endpoint_action: { medium: ["An action failed on a device"] },
  remote_session: { medium: ["Remote session started"] },
  device_approvals: { critical: ["Remote wipe needs a second admin's approval"], high: ["High-risk action rejected"], medium: ["Medium-risk action approved"] },
  runtime_alert: { critical: ["A critical detection rule fired on a workload"], high: ["A high detection rule fired on a workload"], medium: ["A medium detection rule fired on a workload"] },
  posture_finding: { critical: ["Critical misconfiguration on a resource"], high: ["High misconfiguration on a resource"], medium: ["Medium misconfiguration on a resource"] },
  vulnerability: { critical: ["Critical vulnerable package in a workload"], high: ["High vulnerable package in a workload"], medium: ["Medium vulnerable package in a workload"] },
  attack_path: { critical: ["New attack path from the internet to sensitive data"], high: ["New high-risk attack path"], medium: ["New medium-risk attack path"] },
  scan: { high: ["Cloud scan failed"] },
  external_finding: { critical: ["Critical external finding on a host"], high: ["High external finding on a host"] },
  reputation_finding: { critical: ["Critical reputation finding on a domain"], high: ["High reputation finding on a domain"], medium: ["Medium reputation finding on a domain"] },
  asset_lifecycle: { high: ["Asset marked lost or stolen"], medium: ["Asset not retrieved (days overdue)"] },
  directory_source: { high: ["Directory sync failed", "Directory collector offline"] },
  agent_update: { high: ["Agent update rejected (signature or hash)"], medium: ["Agent update rolled back"] },
  server_update: { high: ["Server update failed", "Server update rolled back"] },
  agent_security: { high: ["Spike of rejected agent requests"] },
};

const SEV_LABEL: Record<Level, string> = { critical: "Critical", high: "High", medium: "Medium" };

function areaLabel(meta: NotificationMeta, name: string): string {
  return AREA_LABELS[name] ?? meta.sources.find((s) => s.name === name)?.label ?? name;
}

/** The areas the organisation has, in the groups of the mock-up; unknown sources go under "Assets & platform". */
function groupAreas(meta: NotificationMeta): { title: string; sources: string[] }[] {
  const have = meta.sources.map((s) => s.name);
  const known = new Set(AREA_GROUPS.flatMap((g) => g.sources));
  const groups = AREA_GROUPS.map((g, i) => ({
    title: g.title,
    sources: [...g.sources.filter((s) => have.includes(s)), ...(i === LAST_GROUP ? have.filter((s) => !known.has(s)) : [])],
  }));
  return groups.filter((g) => g.sources.length > 0);
}

function autoName(meta: NotificationMeta, sources: string[], level: string): string {
  if (sources.length === 0) return "";
  const groups = groupAreas(meta);
  const group = groups.find((g) => g.sources.every((s) => sources.includes(s)) && sources.every((s) => g.sources.includes(s)));
  const first = groups.flatMap((g) => g.sources).find((s) => sources.includes(s)) ?? sources[0];
  const what = sources.length > 1 && group ? group.title : areaLabel(meta, first);
  return `${what} – ${LEVEL_LABEL[level] ?? LEVEL_LABEL.high}`;
}

function ChoicePill({ on, onClick, children }: { on: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      aria-pressed={on}
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-sm transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
        on ? "border-accent bg-accent/15 font-medium text-ink" : "border-line bg-surface-2 text-ink-2 hover:bg-line"
      }`}
    >
      {on && <Check aria-hidden className="h-3.5 w-3.5 text-accent" />}
      {children}
    </button>
  );
}

function Seg({ label, options, value, onChange }: { label: string; options: { value: string; label: string }[]; value: string | null; onChange: (v: string) => void }) {
  return (
    <div role="group" aria-label={label} className="inline-flex flex-wrap overflow-hidden rounded border border-line text-sm">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          aria-pressed={value === o.value}
          onClick={() => onChange(o.value)}
          className={`inline-flex items-center gap-1 px-3 py-1.5 font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent ${
            value === o.value ? "bg-accent text-white" : "bg-surface-2 text-ink-2 hover:bg-line"
          }`}
        >
          {value === o.value && <Check aria-hidden className="h-3.5 w-3.5" />}
          {o.label}
        </button>
      ))}
    </div>
  );
}

const STEPS = ["Where and when", "What", "How serious"];

function RuleDialog({
  meta,
  channels,
  rule,
  onClose,
  onSaved,
}: {
  meta: NotificationMeta;
  channels: Channel[];
  rule: Rule | null;
  onClose: () => void;
  onSaved: (msg: string) => void;
}) {
  // Everything the wizard does not show (filters, throttle, quiet hours, ...) stays in `r` and is sent back unchanged.
  const [r, setR] = useState<RuleInput>(() => (rule ? { ...EMPTY, ...rule } : { ...EMPTY, min_severity: "high" }));
  const [step, setStep] = useState(0);
  const [reached, setReached] = useState(rule ? 2 : 0);
  const [nameTouched, setNameTouched] = useState(!!rule);
  const [savedId, setSavedId] = useState<string | null>(rule?.id ?? null);
  const [dirtySaved, setDirtySaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testNote, setTestNote] = useState<{ ok: boolean; text: string } | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const moved = useRef(false);
  const groups = groupAreas(meta);
  const legacy = r.min_severity === "low" || r.min_severity === "info";
  const level: Level | null = legacy ? null : (r.min_severity as Level);

  useEffect(() => {
    if (moved.current) headingRef.current?.focus();
    moved.current = true;
  }, [step]);

  const go = (n: number) => {
    setStep(n);
    setReached((x) => Math.max(x, n));
  };
  const edit = (patch: Partial<RuleInput>) => setR((p) => ({ ...p, ...patch }));
  const withName = (next: RuleInput): RuleInput => (nameTouched ? next : { ...next, name: autoName(meta, next.sources, next.min_severity) });
  const toggleChannel = (id: string) => edit({ channel_ids: r.channel_ids.includes(id) ? r.channel_ids.filter((x) => x !== id) : [...r.channel_ids, id] });
  const setSources = (sources: string[]) =>
    setR((p) => {
      // Event types only apply to a single source: drop ones the new selection does not offer.
      const allowed = selectableEventTypes(meta, sources);
      return withName({ ...p, sources, event_types: p.event_types.filter((t) => allowed.includes(t)) });
    });
  const toggleSource = (s: string) => setSources(r.sources.includes(s) ? r.sources.filter((x) => x !== s) : [...r.sources, s]);
  const setLevel = (v: string) => setR((p) => withName({ ...p, min_severity: v as Severity }));

  const examples = LEVELS.slice()
    .reverse()
    .map((l) => {
      const lists = r.sources.map((s) => EXAMPLES[s]?.[l.value] ?? []).filter((x) => x.length > 0);
      // One picked area with examples: show up to two of its. Several: the first one of the first two.
      const names = lists.length === 1 ? lists[0].slice(0, 2) : lists.slice(0, 2).map((x) => x[0]);
      return { level: l.value, names, sent: (RANK[l.value] ?? 0) >= (RANK[r.min_severity] ?? 0) };
    });

  const areaLabels = groups.flatMap((g) => g.sources).filter((s) => r.sources.includes(s)).map((s) => areaLabel(meta, s));
  const areaSummary = areaLabels.length <= 2 ? areaLabels.join(" and ") : `${areaLabels.length} areas`;
  const chNames = r.channel_ids.map((id) => channels.find((c) => c.id === id)?.name).filter(Boolean) as string[];
  const levelText = r.min_severity === "critical" ? "critical" : `${r.min_severity === "high" ? "high" : "medium"} and above`;
  const summary = `Sends ${legacy ? "low and above" : levelText} alerts from ${areaSummary || "no area yet"} to ${chNames.join(", ") || "no channel yet"}, ${
    r.mode === "digest" ? "as one email each morning" : "as they happen"
  }.`;

  function body(): RuleInput {
    const out: RuleInput = { ...r, name: r.name.trim() };
    if (r.mode === "digest") {
      // The time zone is not asked for: the organisation's one, else UTC (same as the recommended rules).
      const keepZone = !!rule && (rule.mode === "digest" || !!rule.quiet_start);
      out.timezone = keepZone ? rule.timezone : meta.default_timezone || "UTC";
      out.digest_hour = rule?.mode === "digest" ? rule.digest_hour : 8;
    }
    return out;
  }

  async function save(): Promise<Rule> {
    const b = body();
    const saved = savedId ? await notificationsApi.updateRule(savedId, b) : await notificationsApi.createRule(b);
    setSavedId(saved.id);
    setDirtySaved(true);
    return saved;
  }

  // Enter in the form: steps 1-2 go to the next step, step 3 never saves by keyboard alone.
  function onFormSubmit(e: FormEvent) {
    e.preventDefault();
    if (step === 0 && step1Ok) go(1);
    else if (step === 1 && step2Ok) go(2);
  }

  async function create() {
    if (step !== 2) return;
    setBusy(true);
    setError(null);
    try {
      const saved = await save();
      setDirtySaved(false);
      onSaved(`Rule "${saved.name}" saved.`);
      onClose();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  async function test() {
    setTesting(true);
    setTestNote(null);
    setError(null);
    try {
      const id = savedId ?? (await save()).id;
      setTestNote(describeTest(await notificationsApi.testRule(id)));
    } catch (err) {
      setTestNote({ ok: false, text: errMsg(err) });
    } finally {
      setTesting(false);
    }
  }

  function close() {
    // A rule saved only to send a test still exists: refresh the list behind the dialog.
    if (dirtySaved) onSaved(`Rule "${r.name.trim()}" saved.`);
    onClose();
  }

  const step1Ok = r.channel_ids.length > 0;
  const step2Ok = r.sources.length > 0;
  const canGo = (n: number) => n <= reached && (n < 1 || step1Ok) && (n < 2 || step2Ok);

  return (
    <Modal open onClose={close} title={rule ? `Edit rule: ${rule.name}` : "New notification rule"} size="lg">
      <form className="space-y-4" onSubmit={onFormSubmit}>
        <ol className="flex flex-wrap gap-x-4 gap-y-1 text-sm" aria-label="Steps">
          {STEPS.map((s, i) => (
            <li key={s} aria-current={i === step ? "step" : undefined}>
              <button
                type="button"
                disabled={i === step || !canGo(i)}
                onClick={() => go(i)}
                className={`inline-flex items-center gap-2 rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${i === step ? "font-semibold text-ink" : "text-ink-2 enabled:hover:text-ink"}`}
              >
                <span
                  aria-hidden
                  className={`inline-flex h-5 w-5 items-center justify-center rounded-full text-xs ${i === step ? "bg-accent text-white" : i <= reached ? "bg-accent/25 text-ink" : "border border-line"}`}
                >
                  {i + 1}
                </span>
                {s}
              </button>
            </li>
          ))}
        </ol>
        {error && (
          <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
            {error}
          </div>
        )}

        {step === 0 && (
          <div className="space-y-4">
            <h3 ref={headingRef} tabIndex={-1} className="text-base font-semibold focus:outline-none">
              Where and when
            </h3>
            <fieldset>
              <legend className="mb-1.5 text-sm font-medium text-ink-2">Send to</legend>
              <div className="flex flex-wrap items-center gap-2">
                {channels.map((c) => (
                  <ChoicePill key={c.id} on={r.channel_ids.includes(c.id)} onClick={() => toggleChannel(c.id)}>
                    {c.name} <span className="text-xs text-ink-3">({c.type})</span>
                    {!c.enabled && <span className="text-xs text-ink-3">· disabled</span>}
                  </ChoicePill>
                ))}
                <Link to="/notifications?tab=channels" className="text-sm text-accent hover:underline">
                  + Add a channel
                </Link>
              </div>
              {!step1Ok && <p className="mt-1.5 text-xs text-ink-3">Pick at least one.</p>}
            </fieldset>
            <div>
              <div className="mb-1.5 text-sm font-medium text-ink-2">Delivery</div>
              <Seg
                label="Delivery"
                value={r.mode === "digest" ? "digest" : "immediate"}
                onChange={(v) => edit({ mode: v as RuleInput["mode"] })}
                options={[
                  { value: "immediate", label: "Immediately" },
                  { value: "digest", label: "Daily" },
                ]}
              />
              <p className="mt-1.5 text-xs text-ink-3">
                Immediately: an email or message for each alert as it happens. Daily: one email each morning listing the day's alerts.
              </p>
            </div>
          </div>
        )}

        {step === 1 && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <h3 ref={headingRef} tabIndex={-1} className="text-base font-semibold focus:outline-none">
                What
              </h3>
              <span className="text-sm text-ink-2" aria-live="polite">
                {r.sources.length} selected
              </span>
            </div>
            {groups.map((g) => {
              const all = g.sources.every((s) => r.sources.includes(s));
              return (
                <fieldset key={g.title}>
                  <legend className="mb-1.5 flex w-full items-center justify-between gap-3">
                    <span className="text-xs font-semibold uppercase tracking-wide text-ink-3">{g.title}</span>
                    <button
                      type="button"
                      className="text-xs text-accent hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                      onClick={() => setSources(all ? r.sources.filter((s) => !g.sources.includes(s)) : [...new Set([...r.sources, ...g.sources])])}
                    >
                      {all ? "Clear" : "Select all"}
                    </button>
                  </legend>
                  <div className="flex flex-wrap gap-2">
                    {g.sources.map((s) => (
                      <ChoicePill key={s} on={r.sources.includes(s)} onClick={() => toggleSource(s)}>
                        {areaLabel(meta, s)}
                      </ChoicePill>
                    ))}
                  </div>
                </fieldset>
              );
            })}
            {!step2Ok && <p className="text-xs text-ink-3">Pick at least one.</p>}
          </div>
        )}

        {step === 2 && (
          <div className="space-y-4">
            <h3 ref={headingRef} tabIndex={-1} className="text-base font-semibold focus:outline-none">
              How serious
            </h3>
            <div>
              <Seg label="How serious" value={level} onChange={setLevel} options={LEVELS} />
              {legacy && <p className="mt-1.5 text-xs text-sev-medium">This rule currently also sends Low alerts. It keeps doing so unless you pick a level.</p>}
            </div>
            <div>
              <div className="mb-1.5 text-sm font-medium text-ink-2">Examples from what you picked:</div>
              <ul className="divide-y divide-line rounded border border-line text-sm">
                {examples.map((x) => (
                  <li key={x.level} className="flex items-center gap-3 px-3 py-2">
                    <span className="w-16 shrink-0">
                      <Pill tone={SEV_TONE[x.level]}>{SEV_LABEL[x.level]}</Pill>
                    </span>
                    <span className={`min-w-0 flex-1 ${x.names.length ? "" : "text-ink-3"}`}>{x.names.length ? x.names.join("; ") : "No examples in the areas you picked"}</span>
                    <span className={`shrink-0 text-xs font-medium ${x.sent ? "text-good" : "text-ink-3"}`}>{x.sent ? "Sent" : "Not sent"}</span>
                  </li>
                ))}
              </ul>
            </div>
            <Field
              label="Rule name"
              id="rule-name"
              required
              maxLength={128}
              value={r.name}
              onChange={(e) => {
                setNameTouched(true);
                edit({ name: e.target.value });
              }}
            />
            <p className="text-sm text-ink-2">{summary}</p>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={r.enabled} onChange={(e) => edit({ enabled: e.target.checked })} /> Turn the rule on now
            </label>
            {testNote && (
              <div role="status" className={`rounded border px-3 py-2 text-sm ${testNote.ok ? "border-good/60 bg-good/10" : "border-sev-critical/60 bg-sev-critical/10"}`}>
                {testNote.text}
              </div>
            )}
          </div>
        )}

        <div className="flex flex-wrap items-center justify-end gap-2 pt-1">
          {step === 2 && (
            <Button
              disabled={busy || testing || !r.name.trim() || !step1Ok || !step2Ok}
              onClick={() => void test()}
              title={savedId ? "Sends a sample alert through the saved rule" : "Saves the rule, then sends a sample alert"}
            >
              {testing ? "Sending…" : "Send a test alert"}
            </Button>
          )}
          <div className="flex-1" />
          {step > 0 && <Button onClick={() => go(step - 1)}>Back</Button>}
          <Button onClick={close}>Cancel</Button>
          {step < 2 ? (
            <Button key="next" variant="primary" disabled={step === 0 ? !step1Ok : !step2Ok} onClick={() => go(step + 1)}>
              Next
            </Button>
          ) : (
            <Button key="save" variant="primary" onClick={() => void create()} disabled={busy || !r.name.trim() || !step1Ok || !step2Ok}>
              {busy ? "Saving…" : rule ? "Save changes" : "Create rule"}
            </Button>
          )}
        </div>
      </form>
    </Modal>
  );
}

function RecommendedDialog({ channels, onClose, onDone }: { channels: Channel[]; onClose: () => void; onDone: (msg: string) => void }) {
  const [picked, setPicked] = useState<string[]>(() => channels.filter((c) => c.enabled).slice(0, 1).map((c) => c.id));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function create() {
    setBusy(true);
    setError(null);
    try {
      const res = await notificationsApi.createRecommended(picked);
      const made = res.created.map((r) => `"${r.name}"`).join(" and ");
      const skipped = res.skipped.map((n) => `"${n}"`).join(" and ");
      onDone(
        [made ? `Created ${made}.` : "", skipped ? `${skipped} already ${res.skipped.length === 1 ? "exists" : "exist"}, so nothing was added for ${res.skipped.length === 1 ? "it" : "them"}.` : ""]
          .filter(Boolean)
          .join(" "),
      );
      onClose();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open onClose={onClose} title="Use recommended rules">
      {channels.length === 0 ? (
        <div className="space-y-3 text-sm">
          <p>You need somewhere to send alerts first. Add an email, Teams or Slack channel, then come back.</p>
          <div className="flex justify-end gap-2">
            <Button onClick={onClose}>Cancel</Button>
            <Link to="/notifications?tab=channels" className="inline-flex items-center rounded bg-accent px-3 py-1.5 text-sm font-medium text-white hover:opacity-90">
              Go to Channels
            </Link>
          </div>
        </div>
      ) : (
        <div className="space-y-3 text-sm">
          {error && (
            <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2">
              {error}
            </div>
          )}
          <p>This adds two rules, both covering every area your organisation has:</p>
          <ul className="list-disc space-y-1 pl-5 text-ink-2">
            <li>
              <b className="text-ink">High alerts – straight away:</b> High and Critical alerts, sent as they happen.
            </li>
            <li>
              <b className="text-ink">Daily summary:</b> Medium and above, in one message each morning at 08:00.
            </li>
          </ul>
          <fieldset className="space-y-1">
            <legend className="mb-1 font-medium text-ink-2">Send them to</legend>
            {channels.map((c) => (
              <label key={c.id} className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={picked.includes(c.id)}
                  onChange={() => setPicked((p) => (p.includes(c.id) ? p.filter((x) => x !== c.id) : [...p, c.id]))}
                />
                {c.name} <span className="text-xs text-ink-3">({c.type})</span>
                {!c.enabled && <Tag>disabled</Tag>}
              </label>
            ))}
          </fieldset>
          <p className="text-xs text-ink-3">Rules that already exist with these names are left as they are.</p>
          <div className="flex justify-end gap-2">
            <Button onClick={onClose}>Cancel</Button>
            <Button variant="primary" disabled={busy || picked.length === 0} onClick={() => void create()}>
              {busy ? "Adding…" : "Add the two rules"}
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );
}

const SEV_TONE: Record<string, PillTone> = { critical: "critical", high: "high", medium: "medium", low: "neutral" };

function describe(r: Rule, meta: NotificationMeta): string {
  const parts = [r.sources.length ? r.sources.map((s) => areaLabel(meta, s)).join(", ") : "Needs an area"];
  if (r.event_types.length) parts.push(r.event_types.map(humanize).join(", "));
  if (r.subscription_ids.length) parts.push(`${r.subscription_ids.length} subscription(s)`);
  if (r.asset_types.length) parts.push(r.asset_types.join("/"));
  if (Object.keys(r.tags).length) parts.push(`tags ${tagsToText(r.tags)}`);
  if (r.rule_ids.length || r.mitre_techniques.length) parts.push("specific detections");
  if (r.include_status_changes) parts.push("+ status changes");
  return parts.join(" · ");
}

export default function NotificationsRules({ meta, isAdmin }: { meta: NotificationMeta; isAdmin: boolean }) {
  const rules = useApi(notificationsApi.rules, []);
  const channels = useApi(notificationsApi.channels, []);
  const [editing, setEditing] = useState<Rule | "new" | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [pending, setPending] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [recommending, setRecommending] = useState(false);
  const isOn = (r: Rule) => (r.id in pending ? pending[r.id] : r.enabled);
  const changed = (rules.data ?? []).filter((r) => r.id in pending && pending[r.id] !== r.enabled);
  async function saveSwitches() {
    setSaving(true);
    setActionError(null);
    try {
      for (const r of changed) await notificationsApi.updateRule(r.id, { ...r, enabled: pending[r.id] });
      setNotice(`${changed.length} ${changed.length === 1 ? "rule" : "rules"} updated.`);
      setPending({});
      rules.reload();
    } catch (e) {
      setActionError(errMsg(e));
    } finally {
      setSaving(false);
    }
  }
  const chName = (id: string) => channels.data?.find((c) => c.id === id)?.name ?? "(deleted)";
  const sorted = useSort(
    rules.data,
    {
      rule: (r) => r.name,
      matches: (r) => describe(r, meta),
      severity: (r) => SEV_RANK[r.min_severity] ?? 0,
      channels: (r) => r.channel_ids.map(chName).join(", "),
      delivery: (r) => (r.mode === "digest" ? 1 : 0) * 100 + (r.mode === "digest" ? r.digest_hour : 0),
      status: (r) => (r.enabled ? 0 : 1),
    },
    { key: "rule", dir: "asc" },
    { severity: "desc" },
  );

  async function act(fn: () => Promise<unknown>, msg: string) {
    setActionError(null);
    try {
      await fn();
      setNotice(msg);
      rules.reload();
    } catch (e) {
      setActionError(errMsg(e));
    }
  }

  return (
    <div>
      <ErrorNote error={rules.error ?? channels.error ?? actionError} />
      {notice && (
        <div role="status" className="mb-3 rounded border border-good/60 bg-good/10 px-3 py-2 text-sm">
          {notice}
        </div>
      )}
      <Card
        title="Rules"
        actions={
          isAdmin && (
            <div className="flex gap-2">
              <Button onClick={() => setRecommending(true)} disabled={!channels.data}>
                Use recommended rules
              </Button>
              <Button variant="primary" onClick={() => setEditing("new")} disabled={!channels.data?.length}>
                New rule
              </Button>
            </div>
          )
        }
      >
        {rules.data && rules.data.length === 0 ? (
          <Empty>No rules yet. Nothing is sent until you add one.{isAdmin ? " \"Use recommended rules\" sets up a good starting point." : ""}</Empty>
        ) : (
          <Table
            tableId="notifications-rules"
            head={[
              { label: "Rule", sort: "rule", w: 300 },
              { label: "Matches", sort: "matches", w: 240 },
              { label: "From severity", sort: "severity", w: 140 },
              { label: "Channels", sort: "channels", w: 220 },
              { label: "Delivery", sort: "delivery", w: 140 },
              { label: "On", sort: "status", w: 80 },
              ...(isAdmin ? [{ label: "Actions", srOnly: true, w: 300 }] : []),
            ]}
            sort={sorted.sort}
            onSort={sorted.onSort}
            noun="rules"
          >
            {sorted.rows.map((r) => (
              <tr key={r.id}>
                <td className="px-3 py-2"><NameCell name={r.name} onOpen={isAdmin ? () => setEditing(r) : undefined} openLabel={`Edit ${r.name}`} /></td>
                <td className="px-3 py-2"><TextCell muted title={describe(r, meta)}>{describe(r, meta)}</TextCell></td>
                <td className="px-3 py-2">
                  <PillRow><Pill tone={SEV_TONE[r.min_severity] ?? "neutral"}>{r.min_severity[0].toUpperCase() + r.min_severity.slice(1)}</Pill></PillRow>
                </td>
                <td className="px-3 py-2">
                  {r.channel_ids.length ? <TextCell muted title={r.channel_ids.map(chName).join(", ")}>{r.channel_ids.map(chName).join(", ")}</TextCell> : <PillRow><Pill tone="high">None</Pill></PillRow>}
                </td>
                <td className="px-3 py-2">
                  <TextCell title={[r.throttle_minutes > 0 && r.mode !== "digest" ? `At most 1 per group every ${r.throttle_minutes} min` : "", r.quiet_start ? `Quiet ${r.quiet_start}-${r.quiet_end} ${r.timezone}` : ""].filter(Boolean).join(" · ") || undefined}>
                    {r.mode === "digest" ? `Daily ${String(r.digest_hour).padStart(2, "0")}:00` : "Right away"}
                  </TextCell>
                </td>
                <td className="px-3 py-2">
                  {isAdmin ? (
                    <Switch on={isOn(r)} label={`${r.name} on or off`} disabled={saving} onChange={(v) => setPending({ ...pending, [r.id]: v })} />
                  ) : (
                    <PillRow>{r.enabled ? <Pill tone="good">On</Pill> : <Pill>Off</Pill>}</PillRow>
                  )}
                </td>
                {isAdmin && (
                  <td className="px-3 py-2">
                    <div className="flex gap-2">
                      <Button
                        disabled={testing === r.id || r.channel_ids.length === 0}
                        onClick={async () => {
                          setTesting(r.id);
                          setActionError(null);
                          setNotice(null);
                          try {
                            const res = describeTest(await notificationsApi.testRule(r.id));
                            if (res.ok) setNotice(res.text);
                            else setActionError(res.text);
                          } catch (e) {
                            setActionError(errMsg(e));
                          } finally {
                            setTesting(null);
                          }
                        }}
                      >
                        {testing === r.id ? "Sending…" : "Send a test alert"}
                      </Button>
                      <Button onClick={() => setEditing(r)}>Edit</Button>
                      <Button
                        variant="danger"
                        onClick={() => {
                          if (window.confirm(`Delete rule "${r.name}"?`)) act(() => notificationsApi.deleteRule(r.id), `Rule "${r.name}" deleted.`);
                        }}
                      >
                        Delete
                      </Button>
                    </div>
                  </td>
                )}
              </tr>
            ))}
          </Table>
        )}
      </Card>
      <SaveBar count={changed.length} saving={saving} onDiscard={() => setPending({})} onSave={() => void saveSwitches()} />
      {recommending && channels.data && (
        <RecommendedDialog
          channels={channels.data}
          onClose={() => setRecommending(false)}
          onDone={(m) => {
            setNotice(m);
            rules.reload();
          }}
        />
      )}
      {editing && channels.data && (
        <RuleDialog
          meta={meta}
          channels={channels.data}
          rule={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={(m) => {
            setNotice(m);
            rules.reload();
          }}
        />
      )}
    </div>
  );
}
