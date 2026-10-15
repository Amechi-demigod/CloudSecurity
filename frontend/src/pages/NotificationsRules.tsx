import { useState, type FormEvent, type ReactNode } from "react";
import { ApiError, type Severity } from "../api";
import { Button, Card, Empty, ErrorNote, Field, Modal, SeverityBadge, Table, Tag } from "../components/ui";
import { useApi } from "../lib/useApi";
import { notificationsApi, type Channel, type NotificationMeta, type Rule, type RuleInput } from "../notificationsApi";

const inputCls =
  "block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40";

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

const list = (s: string) => s.split(/[,;\n]+/).map((x) => x.trim()).filter(Boolean);
const tagsToText = (t: Record<string, string>) => Object.entries(t).map(([k, v]) => `${k}=${v}`).join(", ");
function textToTags(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of list(s)) {
    const [k, ...rest] = part.split("=");
    if (k.trim()) out[k.trim()] = rest.join("=").trim() || "*";
  }
  return out;
}

function errMsg(e: unknown) {
  return e instanceof ApiError || e instanceof Error ? e.message : String(e);
}

function Group({ title, children }: { title: string; children: ReactNode }) {
  return (
    <fieldset className="space-y-2 rounded border border-line p-3">
      <legend className="px-1 text-xs font-semibold uppercase tracking-wide text-ink-3">{title}</legend>
      {children}
    </fieldset>
  );
}

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
  const [r, setR] = useState<RuleInput>(() => (rule ? { ...EMPTY, ...rule } : { ...EMPTY, channel_ids: channels.slice(0, 1).map((c) => c.id) }));
  const [text, setText] = useState({
    subscription_ids: (rule?.subscription_ids ?? []).join(", "),
    asset_types: (rule?.asset_types ?? []).join(", "),
    asset_ids: (rule?.asset_ids ?? []).join(", "),
    rule_ids: (rule?.rule_ids ?? []).join(", "),
    mitre_techniques: (rule?.mitre_techniques ?? []).join(", "),
    tags: tagsToText(rule?.tags ?? {}),
  });
  const [quiet, setQuiet] = useState(!!rule?.quiet_start);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = <K extends keyof RuleInput>(k: K, v: RuleInput[K]) => setR((prev) => ({ ...prev, [k]: v }));
  const toggle = (k: "sources" | "channel_ids", v: string) =>
    set(k, r[k].includes(v) ? r[k].filter((x) => x !== v) : [...r[k], v]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const body: RuleInput = {
      ...r,
      name: r.name.trim(),
      subscription_ids: list(text.subscription_ids),
      asset_types: list(text.asset_types),
      asset_ids: list(text.asset_ids),
      rule_ids: list(text.rule_ids),
      mitre_techniques: list(text.mitre_techniques),
      tags: textToTags(text.tags),
      quiet_start: quiet ? r.quiet_start || "22:00" : null,
      quiet_end: quiet ? r.quiet_end || "07:00" : null,
      quiet_bypass_severity: quiet ? r.quiet_bypass_severity : null,
    };
    try {
      if (rule) await notificationsApi.updateRule(rule.id, body);
      else await notificationsApi.createRule(body);
      onSaved(`Rule "${body.name}" saved.`);
      onClose();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  const textField = (k: keyof typeof text, label: string, hint: string, placeholder = "") => (
    <Field label={label} id={`rule-${k}`} hint={hint} placeholder={placeholder} value={text[k]} onChange={(e) => setText({ ...text, [k]: e.target.value })} />
  );

  return (
    <Modal open onClose={onClose} title={rule ? `Edit rule: ${rule.name}` : "New notification rule"}>
      <form className="max-h-[75vh] space-y-3 overflow-y-auto pr-1" onSubmit={submit}>
        {error && (
          <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
            {error}
          </div>
        )}
        <Field label="Name" id="rule-name" required maxLength={128} value={r.name} onChange={(e) => set("name", e.target.value)} />
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={r.enabled} onChange={(e) => set("enabled", e.target.checked)} /> Enabled
        </label>
        <Group title="When">
          <div className="text-sm text-ink-2">Sources (none selected = all)</div>
          <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
            {meta.sources.map((s) => (
              <label key={s.name} className="flex items-center gap-2 text-sm" title={s.description}>
                <input type="checkbox" checked={r.sources.includes(s.name)} onChange={() => toggle("sources", s.name)} />
                {s.label}
              </label>
            ))}
          </div>
          <div>
            <label htmlFor="rule-sev" className="mb-1 block text-sm font-medium text-ink-2">
              Minimum severity
            </label>
            <select id="rule-sev" className={inputCls} value={r.min_severity} onChange={(e) => set("min_severity", e.target.value as Severity)}>
              {meta.severities.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={r.include_status_changes} onChange={(e) => set("include_status_changes", e.target.checked)} />
            Also notify when an alert or finding changes status (acknowledged, resolved, …)
          </label>
        </Group>
        <Group title="Only for (optional filters)">
          {textField("subscription_ids", "Subscriptions", "Comma-separated subscription IDs.")}
          {textField("asset_types", "Resource types", "e.g. vm, pod, storage_account")}
          {textField("tags", "Tags", "key=value pairs; key=* matches any value.", "env=prod, team=payments")}
          {textField("rule_ids", "Detection / posture rule IDs", "Wildcards allowed, e.g. CDR-00*")}
          {textField("mitre_techniques", "MITRE ATT&CK techniques", "T1059 also matches sub-techniques such as T1059.004")}
          {textField("asset_ids", "Specific resource IDs", "Full resource IDs (rarely needed).")}
        </Group>
        <Group title="Send to">
          {channels.length === 0 && <p className="text-sm text-sev-medium">Create a channel first.</p>}
          {channels.map((c) => (
            <label key={c.id} className="flex items-center gap-2 text-sm">
              <input type="checkbox" checked={r.channel_ids.includes(c.id)} onChange={() => toggle("channel_ids", c.id)} />
              {c.name} <span className="text-xs text-ink-3">({c.type})</span>
              {!c.enabled && <Tag>disabled</Tag>}
            </label>
          ))}
        </Group>
        <Group title="Noise control">
          <Field
            label="Throttle (minutes)"
            id="rule-throttle"
            type="number"
            min={0}
            max={10080}
            hint="The same alert group (e.g. one detection on one resource) is sent at most once per window; 0 sends every event. Suppressed repeats are counted in the next message."
            value={r.throttle_minutes}
            onChange={(e) => set("throttle_minutes", Number(e.target.value))}
          />
          <div>
            <label htmlFor="rule-mode" className="mb-1 block text-sm font-medium text-ink-2">
              Delivery
            </label>
            <select id="rule-mode" className={inputCls} value={r.mode} onChange={(e) => set("mode", e.target.value as RuleInput["mode"])}>
              <option value="immediate">Immediately</option>
              <option value="digest">Daily digest (good for low severity)</option>
            </select>
          </div>
          {r.mode === "digest" && (
            <Field label="Digest hour (0-23, rule time zone)" id="rule-digest-hour" type="number" min={0} max={23}
              value={r.digest_hour} onChange={(e) => set("digest_hour", Number(e.target.value))} />
          )}
          <Field label="Time zone" id="rule-tz" hint="IANA name, e.g. Europe/London, Africa/Lagos. Used for quiet hours and the digest hour."
            value={r.timezone} onChange={(e) => set("timezone", e.target.value)} />
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={quiet} onChange={(e) => setQuiet(e.target.checked)} /> Quiet hours (hold messages until the window ends)
          </label>
          {quiet && (
            <div className="grid grid-cols-3 gap-2">
              <Field label="From" id="rule-qs" type="time" value={r.quiet_start ?? "22:00"} onChange={(e) => set("quiet_start", e.target.value)} />
              <Field label="Until" id="rule-qe" type="time" value={r.quiet_end ?? "07:00"} onChange={(e) => set("quiet_end", e.target.value)} />
              <div>
                <label htmlFor="rule-qb" className="mb-1 block text-sm font-medium text-ink-2">
                  Always send
                </label>
                <select id="rule-qb" className={inputCls} value={r.quiet_bypass_severity ?? ""}
                  onChange={(e) => set("quiet_bypass_severity", (e.target.value || null) as Severity | null)}>
                  <option value="">nothing</option>
                  <option value="critical">critical</option>
                  <option value="high">high and above</option>
                </select>
              </div>
            </div>
          )}
        </Group>
        <div className="flex justify-end gap-2 pt-1">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy || !r.name.trim() || r.channel_ids.length === 0}>
            {busy ? "Saving…" : "Save rule"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function describe(r: Rule, meta: NotificationMeta): string {
  const parts = [r.sources.length ? r.sources.map((s) => meta.sources.find((x) => x.name === s)?.label ?? s).join(", ") : "All sources"];
  if (r.subscription_ids.length) parts.push(`${r.subscription_ids.length} subscription(s)`);
  if (r.asset_types.length) parts.push(r.asset_types.join("/"));
  if (Object.keys(r.tags).length) parts.push(`tags ${tagsToText(r.tags)}`);
  if (r.rule_ids.length) parts.push(`rules ${r.rule_ids.join(", ")}`);
  if (r.mitre_techniques.length) parts.push(r.mitre_techniques.join(", "));
  if (r.include_status_changes) parts.push("+ status changes");
  return parts.join(" · ");
}

export default function NotificationsRules({ meta, isAdmin }: { meta: NotificationMeta; isAdmin: boolean }) {
  const rules = useApi(notificationsApi.rules, []);
  const channels = useApi(notificationsApi.channels, []);
  const [editing, setEditing] = useState<Rule | "new" | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const chName = (id: string) => channels.data?.find((c) => c.id === id)?.name ?? "(deleted)";

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
        title="Routing rules"
        actions={
          isAdmin && (
            <Button variant="primary" onClick={() => setEditing("new")} disabled={!channels.data?.length}>
              New rule
            </Button>
          )
        }
      >
        {rules.data && rules.data.length === 0 ? (
          <Empty>No rules: nothing is sent until a rule routes events to a channel.</Empty>
        ) : (
          <Table head={["Rule", "Matches", "Min. severity", "Channels", "Delivery", "Status", ...(isAdmin ? [""] : [])]}>
            {rules.data?.map((r) => (
              <tr key={r.id}>
                <td className="px-3 py-2 font-medium">{r.name}</td>
                <td className="max-w-[22rem] px-3 py-2 text-xs text-ink-2">{describe(r, meta)}</td>
                <td className="px-3 py-2">
                  <SeverityBadge severity={r.min_severity} />
                </td>
                <td className="px-3 py-2 text-xs">{r.channel_ids.length ? r.channel_ids.map(chName).join(", ") : <Tag tone="warn">none</Tag>}</td>
                <td className="px-3 py-2 text-xs text-ink-2">
                  {r.mode === "digest" ? `Daily digest at ${String(r.digest_hour).padStart(2, "0")}:00` : "Immediate"}
                  {r.throttle_minutes > 0 && r.mode !== "digest" && <div>≤ 1 per group / {r.throttle_minutes} min</div>}
                  {r.quiet_start && <div>Quiet {r.quiet_start}–{r.quiet_end} {r.timezone}</div>}
                </td>
                <td className="px-3 py-2">{r.enabled ? <Tag tone="good">Enabled</Tag> : <Tag>Disabled</Tag>}</td>
                {isAdmin && (
                  <td className="px-3 py-2">
                    <div className="flex gap-2">
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
