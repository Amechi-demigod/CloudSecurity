import { ChevronDown, ChevronRight, Download, FileText, Mail, Printer, ShieldCheck } from "lucide-react";
import { Fragment, useEffect, useMemo, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { ApiError } from "../api";
import { useAuth } from "../auth/context";
import {
  CHECK_KIND_LABEL,
  complianceApi,
  STATUS_HINT,
  STATUS_LABEL,
  WEEKDAYS,
  type CheckResult,
  type Control,
  type ControlStatus,
  type Schedule,
  type ScheduleBody,
  type Scope,
} from "../complianceApi";
import { ChartEmpty, ChartTip, LegendKeys } from "../components/dash";
import { Button, Card, Empty, ErrorNote, Field, Modal, PageHeader, Select, Stat, Tag } from "../components/ui";
import { AXIS, GRID } from "../lib/dash";
import { fmtAgo, fmtTime } from "../lib/format";
import { useApi } from "../lib/useApi";
import { useUrlState } from "../lib/useUrlState";

const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : String(e));
const pct = (v: number | null | undefined) => (v == null ? "—" : `${v}%`);

const STATUS_CLASS: Record<ControlStatus, string> = {
  pass: "border-good/60 bg-good/10 text-good",
  fail: "border-sev-critical/60 bg-sev-critical/10 text-sev-critical",
  partial: "border-sev-medium/60 bg-sev-medium/10 text-sev-medium",
  no_data: "border-line text-ink-3",
  manual: "border-line bg-surface-2 text-ink-2",
};
const CHECK_CLASS: Record<CheckResult["status"], string> = {
  pass: "text-good",
  fail: "text-sev-critical",
  no_data: "text-ink-3",
  out_of_scope: "text-ink-3",
};
const CHECK_LABEL: Record<CheckResult["status"], string> = { pass: "pass", fail: "fail", no_data: "no data", out_of_scope: "out of scope" };
const SCORE_COLOR = "var(--color-cat-1)";
const COVERAGE_COLOR = "var(--color-cat-2)";

function StatusPill({ status }: { status: ControlStatus }) {
  return (
    <span title={STATUS_HINT[status]} className={`inline-block whitespace-nowrap rounded border px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${STATUS_CLASS[status]}`}>
      {STATUS_LABEL[status]}
    </span>
  );
}

function evidenceText(c: Control) {
  if (c.checks.length === 0) return "Not assessed automatically";
  const by: Record<string, number> = {};
  for (const ch of c.checks) by[ch.status] = (by[ch.status] ?? 0) + 1;
  return (
    `${c.checks.length} check${c.checks.length === 1 ? "" : "s"}: ` +
    (["fail", "pass", "no_data", "out_of_scope"] as const)
      .filter((k) => by[k])
      .map((k) => `${by[k]} ${CHECK_LABEL[k]}`)
      .join(", ")
  );
}

function CheckRow({ ch }: { ch: CheckResult }) {
  return (
    <li className="rounded border border-line bg-surface-0 p-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`text-xs font-semibold uppercase ${CHECK_CLASS[ch.status]}`}>{CHECK_LABEL[ch.status]}</span>
        <span className="text-sm text-ink">{ch.title}</span>
        <Tag>{CHECK_KIND_LABEL[ch.kind]}</Tag>
        <code className="text-[11px] text-ink-3">{ch.id}</code>
        <span className="ml-auto text-xs text-ink-3">
          {ch.status === "fail" ? `${ch.failing.toLocaleString()} failing` : ""}
          {ch.total != null && ch.status !== "no_data" && ch.status !== "out_of_scope" ? ` of ${ch.total.toLocaleString()} evaluated` : ""}
          {ch.link && (ch.status === "pass" || ch.status === "fail") && (
            <Link to={ch.link} className="ml-2 text-accent hover:underline">
              View
            </Link>
          )}
        </span>
      </div>
      {ch.detail && <div className="mt-0.5 text-xs text-ink-3">{ch.detail}</div>}
      {ch.items.length > 0 && (
        <ul className="mt-1.5 space-y-0.5 text-xs">
          {ch.items.map((it, i) => (
            <li key={i} className="flex flex-wrap gap-x-2">
              <Link to={it.link} className="text-accent hover:underline">
                {it.label}
              </Link>
              {it.detail && <span className="text-ink-3">{it.detail}</span>}
              {it.since && <span className="text-ink-3">· open {fmtAgo(it.since)}</span>}
            </li>
          ))}
          {ch.failing > ch.items.length && <li className="text-ink-3">… and {(ch.failing - ch.items.length).toLocaleString()} more</li>}
        </ul>
      )}
    </li>
  );
}

const EMPTY_FORM: ScheduleBody = {
  name: "Monthly compliance report",
  enabled: true,
  frameworks: [],
  frequency: "monthly",
  day: 1,
  hour: 6,
  recipients: [],
  account: null,
  device_group: null,
};

function ScheduleDialog({
  open,
  onClose,
  onSaved,
  initial,
  frameworks,
}: {
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
  initial: Schedule | null;
  frameworks: { id: string; name: string }[];
}) {
  const [form, setForm] = useState<ScheduleBody>(EMPTY_FORM);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const members = useApi(() => (open ? complianceApi.recipients() : Promise.resolve(null)), [open]);

  useEffect(() => {
    if (!open) return;
    setError(null);
    setForm(initial ? { ...initial } : { ...EMPTY_FORM, frameworks: frameworks.slice(0, 1).map((f) => f.id) });
  }, [open, initial, frameworks]);

  const set = <K extends keyof ScheduleBody>(k: K, v: ScheduleBody[K]) => setForm((f) => ({ ...f, [k]: v }));
  const toggle = (k: "frameworks" | "recipients", v: string, on: boolean) =>
    setForm((f) => ({ ...f, [k]: on ? [...f[k], v] : f[k].filter((x) => x !== v) }));

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (initial) await complianceApi.updateSchedule(initial.id, form);
      else await complianceApi.createSchedule(form);
      onSaved();
      onClose();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={onClose} title={initial ? "Edit scheduled report" : "Schedule a compliance report"}>
      <form className="space-y-3" onSubmit={submit}>
        <ErrorNote error={error} />
        <Field label="Name" id="cs-name" required maxLength={128} value={form.name} onChange={(e) => set("name", e.target.value)} />
        <fieldset className="text-sm">
          <legend className="mb-1 font-medium text-ink-2">Frameworks</legend>
          <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
            {frameworks.map((f) => (
              <label key={f.id} className="flex items-center gap-2">
                <input type="checkbox" checked={form.frameworks.includes(f.id)} onChange={(e) => toggle("frameworks", f.id, e.target.checked)} />
                {f.name}
              </label>
            ))}
          </div>
        </fieldset>
        <div className="grid grid-cols-3 gap-2">
          <label className="text-sm">
            <span className="mb-1 block font-medium text-ink-2">Frequency</span>
            <select
              className="w-full rounded border border-line bg-surface-2 px-2 py-1.5 text-sm"
              value={form.frequency}
              onChange={(e) => {
                const f = e.target.value as ScheduleBody["frequency"];
                setForm((x) => ({ ...x, frequency: f, day: f === "weekly" ? 0 : 1 }));
              }}
            >
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block font-medium text-ink-2">{form.frequency === "weekly" ? "Day" : "Day of month"}</span>
            <select className="w-full rounded border border-line bg-surface-2 px-2 py-1.5 text-sm" value={form.day} onChange={(e) => set("day", Number(e.target.value))}>
              {form.frequency === "weekly"
                ? WEEKDAYS.map((d, i) => (
                    <option key={d} value={i}>
                      {d}
                    </option>
                  ))
                : Array.from({ length: 28 }, (_, i) => (
                    <option key={i + 1} value={i + 1}>
                      {i + 1}
                    </option>
                  ))}
            </select>
          </label>
          <label className="text-sm">
            <span className="mb-1 block font-medium text-ink-2">Hour (UTC)</span>
            <select className="w-full rounded border border-line bg-surface-2 px-2 py-1.5 text-sm" value={form.hour} onChange={(e) => set("hour", Number(e.target.value))}>
              {Array.from({ length: 24 }, (_, i) => (
                <option key={i} value={i}>
                  {String(i).padStart(2, "0")}:00
                </option>
              ))}
            </select>
          </label>
        </div>
        <fieldset className="text-sm">
          <legend className="mb-1 font-medium text-ink-2">Recipients</legend>
          <p className="mb-1 text-xs text-ink-3">Members of this organisation only. Invite someone under Users first to add them.</p>
          <div className="max-h-40 space-y-1 overflow-auto rounded border border-line p-2">
            {(members.data?.emails ?? []).map((m) => (
              <label key={m} className="flex items-center gap-2">
                <input type="checkbox" checked={form.recipients.includes(m)} onChange={(e) => toggle("recipients", m, e.target.checked)} />
                {m}
              </label>
            ))}
            {members.data && members.data.emails.length === 0 && <span className="text-ink-3">No active members.</span>}
          </div>
        </fieldset>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} /> Enabled
        </label>
        <div className="flex justify-end gap-2 pt-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy || !form.name.trim() || form.frameworks.length === 0 || form.recipients.length === 0}>
            {busy ? "Saving…" : "Save"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function ScheduledReports({ frameworks, isAdmin }: { frameworks: { id: string; name: string }[]; isAdmin: boolean }) {
  const { data, error, reload } = useApi(complianceApi.schedules, []);
  const [editing, setEditing] = useState<Schedule | null>(null);
  const [open, setOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionErr, setActionErr] = useState<string | null>(null);
  const names = Object.fromEntries(frameworks.map((f) => [f.id, f.name]));

  async function act(fn: () => Promise<unknown>, ok?: string) {
    setActionErr(null);
    setNotice(null);
    try {
      await fn();
      if (ok) setNotice(ok);
      reload();
    } catch (e) {
      setActionErr(errMsg(e));
    }
  }

  const when = (s: Schedule) =>
    s.frequency === "weekly" ? `Weekly, ${WEEKDAYS[s.day]} ${String(s.hour).padStart(2, "0")}:00 UTC` : `Monthly, day ${s.day} ${String(s.hour).padStart(2, "0")}:00 UTC`;

  return (
    <Card
      title="Scheduled reports"
      className="mb-4"
      actions={
        isAdmin ? (
          <Button
            onClick={() => {
              setEditing(null);
              setOpen(true);
            }}
            disabled={!!data && data.items.length >= data.max_schedules}
          >
            Schedule a report
          </Button>
        ) : undefined
      }
    >
      <p className="mb-3 text-sm text-ink-2">
        The PDF report is emailed to members of this organisation, weekly or monthly.
        {data && !data.mail_configured && <span className="text-sev-high"> No platform mail server is configured yet: reports cannot be sent until it is.</span>}
      </p>
      <ErrorNote error={error ?? actionErr} />
      {notice && <div role="status" className="mb-3 rounded border border-good/60 bg-good/10 px-3 py-2 text-sm">{notice}</div>}
      {data && data.items.length === 0 ? (
        <Empty icon={Mail} title="No scheduled reports">
          {isAdmin ? "Schedule one to email the PDF to your team." : "An admin can schedule an emailed PDF report."}
        </Empty>
      ) : (
        <ul className="divide-y divide-line">
          {(data?.items ?? []).map((s) => (
            <li key={s.id} className="flex flex-wrap items-start justify-between gap-3 py-2.5">
              <div className="min-w-0">
                <div className="font-medium text-ink">
                  {s.name} {!s.enabled && <Tag>paused</Tag>}
                </div>
                <div className="text-xs text-ink-2">
                  {s.frameworks.map((f) => names[f] ?? f).join(", ")} · {when(s)} · {s.recipients.length} recipient{s.recipients.length === 1 ? "" : "s"}
                </div>
                <div className="text-xs text-ink-3">
                  {s.enabled && s.next_run_at && <>Next {fmtTime(s.next_run_at)}. </>}
                  {s.last_run_at && (
                    <>
                      Last {fmtAgo(s.last_run_at)}:{" "}
                      <span className={s.last_status === "sent" ? "text-good" : "text-sev-high"}>{s.last_status}</span>
                      {s.last_error && <span title={s.last_error}> ({s.last_error.slice(0, 120)})</span>}
                    </>
                  )}
                </div>
              </div>
              {isAdmin && (
                <div className="flex gap-2">
                  <Button onClick={() => void act(async () => {
                    const r = await complianceApi.sendNow(s.id);
                    if (r.status === "failed") throw new Error(r.errors.join("; ") || "sending failed");
                  }, "Report sent.")}>Send now</Button>
                  <Button
                    onClick={() => {
                      setEditing(s);
                      setOpen(true);
                    }}
                  >
                    Edit
                  </Button>
                  <Button variant="danger" onClick={() => void act(() => complianceApi.deleteSchedule(s.id))}>
                    Delete
                  </Button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      <ScheduleDialog open={open} onClose={() => setOpen(false)} onSaved={reload} initial={editing} frameworks={frameworks} />
    </Card>
  );
}

export default function Compliance() {
  const { can } = useAuth();
  const isAdmin = can("admin");
  const [fw, setFw] = useUrlState("framework", "cis");
  const [account, setAccount] = useUrlState("account");
  const [group, setGroup] = useUrlState("group");
  const [statusFilter, setStatusFilter] = useUrlState("status");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<Set<string>>(new Set());
  const scope: Scope = account ? { account } : group ? { device_group: group } : {};

  const overview = useApi(() => complianceApi.frameworks(scope), [account, group]);
  const posture = useApi(() => complianceApi.posture(fw, scope), [fw, account, group]);
  const trend = useApi(() => complianceApi.trend(fw, scope), [fw, account, group]);
  const frameworks = overview.data?.frameworks ?? [];
  const p = posture.data;
  const s = p?.summary;

  useEffect(() => setOpen(new Set()), [fw, account, group]);

  const groups = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (p?.groups ?? [])
      .map((g) => ({
        ...g,
        controls: g.controls.filter(
          (c) => (!statusFilter || c.status === statusFilter) && (!needle || c.id.toLowerCase().includes(needle) || c.title.toLowerCase().includes(needle)),
        ),
      }))
      .filter((g) => g.controls.length > 0);
  }, [p, statusFilter, q]);

  const points = (trend.data?.points ?? []).map((pt) => ({ ...pt, label: pt.day.slice(5) }));
  const scopes = overview.data?.scopes;
  const toggle = (id: string) =>
    setOpen((prev) => {
      const n = new Set(prev);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  return (
    <div className="mx-auto max-w-[1400px]">
      <PageHeader
        title="Compliance"
        subtitle="Framework controls mapped to the platform's own checks: cloud posture, endpoint agents, vulnerabilities and directories."
        actions={
          <div data-print="hide" className="flex flex-wrap items-center gap-2">
            <a href={complianceApi.csvUrl(fw, scope)} className="inline-flex items-center gap-1.5 rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">
              <FileText aria-hidden className="h-3.5 w-3.5" />
              Export CSV
            </a>
            <a href={complianceApi.pdfUrl([fw], scope)} className="inline-flex items-center gap-1.5 rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line" title="The same PDF report the scheduled emails attach">
              <Download aria-hidden className="h-3.5 w-3.5" />
              PDF report
            </a>
            <button
              type="button"
              onClick={() => window.print()}
              className="inline-flex items-center gap-1.5 rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line"
              title="Print this page or save it as a PDF"
            >
              <Printer aria-hidden className="h-3.5 w-3.5" />
              Export PDF
            </button>
          </div>
        }
      />

      <div role="note" className="mb-4 rounded border border-sev-medium/50 bg-sev-medium/10 px-3 py-2 text-sm text-ink">
        <strong>Evidence to support an assessment, not an audit opinion.</strong> Scores only cover controls the platform can check automatically; no
        framework can be certified from this page. Control titles are short paraphrases; refer to the publisher&apos;s text.
      </div>

      <ErrorNote error={overview.error ?? posture.error} />

      <div role="tablist" aria-label="Framework" className="mb-4 grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-5" data-print="hide">
        {frameworks.map((f) => (
          <button
            key={f.id}
            type="button"
            role="tab"
            aria-selected={fw === f.id}
            onClick={() => setFw(f.id)}
            className={`rounded-lg border px-3 py-2 text-left transition ${fw === f.id ? "border-accent bg-accent/10" : "border-line bg-surface-1 hover:bg-surface-2"}`}
          >
            <div className="text-sm font-semibold text-ink">{f.short_name}</div>
            <div className="text-[11px] text-ink-3">{f.version}</div>
            <div className="mt-1 flex items-baseline gap-2">
              <span className="text-lg font-semibold text-ink">{pct(f.summary.score)}</span>
              <span className="text-[11px] text-ink-3">coverage {pct(f.summary.coverage)}</span>
            </div>
          </button>
        ))}
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-3" data-print="hide">
        <Select
          label="Cloud account"
          value={account}
          onChange={(v) => {
            setGroup("");
            setAccount(v);
          }}
          options={[{ value: "", label: "All" }, ...(scopes?.accounts ?? []).map((a) => ({ value: a.id, label: `${a.name} (${a.provider.toUpperCase()})` }))]}
        />
        <Select
          label="Device group"
          value={group}
          onChange={(v) => {
            setAccount("");
            setGroup(v);
          }}
          options={[{ value: "", label: "All" }, ...(scopes?.device_groups ?? []).map((g) => ({ value: g, label: g }))]}
        />
        {(account || group) && <span className="text-xs text-ink-3">{account ? "Endpoint and directory checks are out of scope for one cloud account." : "Cloud and directory checks are out of scope for one device group."}</span>}
      </div>

      {p && (
        <h2 className="mb-2 text-base font-semibold text-ink">
          {p.framework.name} <span className="text-sm font-normal text-ink-3">· {p.scope.label} · {fmtTime(p.generated_at)}</span>
        </h2>
      )}

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
        <Stat label="Score" value={pct(s?.score)} hint="Controls without failing automated evidence / controls assessed automatically" />
        <Stat label="Automated coverage" value={pct(s?.coverage)} sub={s ? `${s.assessed} of ${s.total} controls` : undefined} hint="Controls assessed automatically / all controls" />
        {(["fail", "pass", "partial", "no_data", "manual"] as ControlStatus[]).map((k) => (
          <Stat key={k} label={STATUS_LABEL[k]} value={s ? s[k].toLocaleString() : "—"} hint={STATUS_HINT[k]} />
        ))}
      </div>

      <Card title="Trend" className="mb-4" actions={<LegendKeys items={[{ label: "Score", color: SCORE_COLOR }, { label: "Automated coverage", color: COVERAGE_COLOR, dashed: true }]} />}>
        {points.length < 2 ? (
          <ChartEmpty height="h-40">The trend fills in from today: one snapshot a day.{s?.score != null ? ` Today's score: ${s.score}%.` : ""}</ChartEmpty>
        ) : (
          <div className="h-40">
            <ResponsiveContainer>
              <LineChart data={points} margin={{ top: 4, right: 8, bottom: 0, left: -4 }}>
                <CartesianGrid {...GRID} />
                <XAxis dataKey="label" {...AXIS} minTickGap={24} />
                <YAxis {...AXIS} domain={[0, 100]} width={48} unit="%" />
                <Tooltip cursor={{ stroke: "var(--color-ink-3)", strokeDasharray: "3 3" }} content={<ChartTip />} />
                <Line type="monotone" dataKey="score" name="Score" stroke={SCORE_COLOR} strokeWidth={2} dot={false} isAnimationActive={false} connectNulls />
                <Line type="monotone" dataKey="coverage" name="Automated coverage" stroke={COVERAGE_COLOR} strokeWidth={2} strokeDasharray="5 4" dot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </Card>

      <Card title="Controls" className="mb-4">
        {p?.framework.notice && <p className="mb-3 text-xs text-ink-3">{p.framework.notice}</p>}
        <div className="mb-3 flex flex-wrap items-center gap-3" data-print="hide">
          <Select
            label="Status"
            value={statusFilter}
            onChange={setStatusFilter}
            options={[{ value: "", label: "All" }, ...(["fail", "partial", "pass", "no_data", "manual"] as ControlStatus[]).map((k) => ({ value: k, label: STATUS_LABEL[k] }))]}
          />
          <input
            type="search"
            aria-label="Search controls"
            placeholder="Search control or title"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            className="w-60 rounded border border-line bg-surface-2 px-2.5 py-1 text-sm text-ink placeholder:text-ink-3"
          />
        </div>
        {posture.loading && !p ? (
          <p className="text-sm text-ink-3">Loading…</p>
        ) : groups.length === 0 ? (
          <Empty icon={ShieldCheck} title="No controls match">Change the status filter or the search.</Empty>
        ) : (
          <div className="overflow-x-auto" data-print="flow">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="text-xs uppercase tracking-wide text-ink-3">
                  <th className="w-8 px-2 py-2" />
                  <th className="px-2 py-2">Control</th>
                  <th className="px-2 py-2">Title (paraphrased)</th>
                  <th className="px-2 py-2">Status</th>
                  <th className="px-2 py-2">Evidence</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((g) => (
                  <Fragment key={g.id}>
                    <tr className="bg-surface-2/60">
                      <td colSpan={5} className="px-2 py-1.5 text-xs font-semibold text-ink-2">
                        {/* CIS groups have slug ids ("azure"): the title alone */}
                        {g.id === g.id.toLowerCase() && /[a-z]/.test(g.id) ? g.title : `${g.id} · ${g.title}`}
                      </td>
                    </tr>
                    {g.controls.map((c) => {
                      const expanded = open.has(c.id);
                      return (
                        <Fragment key={c.id}>
                          <tr className="border-t border-line hover:bg-surface-2/40" data-print="card">
                            <td className="px-2 py-2">
                              {c.checks.length > 0 && (
                                <button type="button" aria-label={`${expanded ? "Hide" : "Show"} evidence for ${c.id}`} aria-expanded={expanded} onClick={() => toggle(c.id)} className="text-ink-3 hover:text-ink">
                                  {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                                </button>
                              )}
                            </td>
                            <td className="whitespace-nowrap px-2 py-2 font-mono text-xs text-ink">{c.id}</td>
                            <td className="px-2 py-2 text-ink">
                              {c.title}
                              {c.note && <div className="text-[11px] text-ink-3">{c.note}</div>}
                            </td>
                            <td className="px-2 py-2">
                              <StatusPill status={c.status} />
                            </td>
                            <td className="px-2 py-2 text-xs text-ink-2">
                              {evidenceText(c)}
                              {c.coverage === "partial" && <div className="text-ink-3">covers part of the control</div>}
                            </td>
                          </tr>
                          {expanded && (
                            <tr>
                              <td />
                              <td colSpan={4} className="px-2 pb-3">
                                <ul className="space-y-1.5">
                                  {c.checks.map((ch) => (
                                    <CheckRow key={ch.id} ch={ch} />
                                  ))}
                                </ul>
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      );
                    })}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div data-print="hide">
        <ScheduledReports frameworks={frameworks.map((f) => ({ id: f.id, name: f.name }))} isAdmin={isAdmin} />
      </div>
    </div>
  );
}
