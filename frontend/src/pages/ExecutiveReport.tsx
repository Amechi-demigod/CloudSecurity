import { Download, Mail, Printer, Trash2 } from "lucide-react";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { ApiError } from "../api";
import { useAuth } from "../auth/context";
import { Button, Card, Empty, ErrorNote, Field, Modal, PageHeader, Pill, type PillTone } from "../components/ui";
import { SaveBar } from "../components/SaveBar";
import { Switch } from "../components/Switch";
import { Segments } from "../components/table/filters";
import {
  executiveApi,
  PERIODS,
  PERIOD_NAME,
  WEEKDAYS,
  type ExecutiveReport,
  type Recipient,
  type ReportPeriod,
  type Subscription,
  type SubscriptionBody,
} from "../executiveApi";
import { fmtAgo, fmtTime } from "../lib/format";
import { useApi } from "../lib/useApi";
import { useUrlState } from "../lib/useUrlState";

const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : String(e));
const SEV_TONE: Record<string, PillTone> = { critical: "critical", high: "high", medium: "medium", low: "neutral" };
const DIR_CLASS = { better: "text-good", worse: "text-sev-critical", same: "text-ink-2", unknown: "text-ink-2" };
const pct = (v: number | null) => (v == null ? "not measured" : `${v}%`);

function Section({ n, title, explain, children }: { n: number; title: string; explain?: string; children: ReactNode }) {
  return (
    <section className="mb-5" data-print="card">
      <h2 className="mb-2 border-b border-line pb-1 text-base font-semibold text-ink">
        {n}. {title}
      </h2>
      {children}
      {explain && <p className="mt-2 text-xs text-ink-3">{explain}</p>}
    </section>
  );
}

function Bullets({ items }: { items: string[] }) {
  return (
    <ul className="list-disc space-y-1 pl-5 text-sm text-ink">
      {items.map((s) => (
        <li key={s}>{s}</li>
      ))}
    </ul>
  );
}

function ReportView({ r }: { r: ExecutiveReport }) {
  const counter = { n: 0 };
  const next = () => ++counter.n;
  return (
    <div>
      <div className="mb-5 rounded-lg border border-line bg-surface-1 p-4" data-print="card">
        <div className="text-xs font-semibold uppercase tracking-wide text-ink-3">{r.period.name} report · {r.organization}</div>
        <p className={`mt-1 text-xl font-semibold ${DIR_CLASS[r.headline.direction]}`}>{r.headline.text}</p>
        <p className="mt-2 text-xs text-ink-3">{r.headline.explain}</p>
        <p className="mt-2 text-xs text-ink-3">Period covered: {r.period.label}. Generated {fmtTime(r.generated_at)}.</p>
      </div>

      <Section n={next()} title="The top risks to act on">
        {r.top_risks.length === 0 ? (
          <p className="text-sm text-ink-2">No serious risks are open. Keep the current routine going.</p>
        ) : (
          <ol className="space-y-3">
            {r.top_risks.map((t, i) => (
              <li key={t.title} className="rounded border border-line bg-surface-1 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-semibold text-ink">
                    {i + 1}. {t.title}
                  </span>
                  <Pill tone={SEV_TONE[t.severity] ?? "neutral"}>{t.severity}</Pill>
                </div>
                <p className="mt-1 text-sm text-ink-2"><span className="font-medium">Why it matters:</span> {t.why}</p>
                <p className="mt-0.5 text-sm text-ink-2"><span className="font-medium">Who should act:</span> {t.who}</p>
              </li>
            ))}
          </ol>
        )}
      </Section>

      <Section n={next()} title={`What changed since ${r.changes.compared_with}`} explain={r.changes.explain}>
        {r.changes.improved.length > 0 && (
          <>
            <div className="mb-1 text-sm font-semibold text-good">Better</div>
            <Bullets items={r.changes.improved} />
          </>
        )}
        {r.changes.worse.length > 0 && (
          <>
            <div className="mb-1 mt-2 text-sm font-semibold text-sev-critical">Worse</div>
            <Bullets items={r.changes.worse} />
          </>
        )}
        {r.changes.notes.length > 0 && <div className="mt-2"><Bullets items={r.changes.notes} /></div>}
        {!r.changes.comparison_available && (
          <p className="mt-2 text-xs text-ink-3">A full comparison with {r.changes.compared_with} is not available yet; it fills in as daily history builds up.</p>
        )}
      </Section>

      <Section n={next()} title="What we can see (coverage)" explain={r.coverage.explain}>
        {r.coverage.lines.length ? <Bullets items={r.coverage.lines} /> : <p className="text-sm text-ink-2">No areas are being checked yet.</p>}
      </Section>

      {r.compliance && (
        <Section n={next()} title="Compliance at a glance" explain={r.compliance.explain}>
          <Bullets
            items={r.compliance.frameworks.map(
              (f) => `${f.name}: score ${pct(f.score)}, automatic coverage ${pct(f.coverage)}, ${f.failing} requirement${f.failing === 1 ? "" : "s"} failing.`,
            )}
          />
          <p role="note" className="mt-2 rounded border border-sev-medium/50 bg-sev-medium/10 px-3 py-2 text-xs text-ink">{r.compliance.disclaimer}</p>
        </Section>
      )}

      {r.exposure && (
        <Section n={next()} title="Internet exposure and reputation" explain={r.exposure.explain}>
          <Bullets
            items={[
              ...r.exposure.lines,
              ...(r.exposure.domains.length
                ? r.exposure.domains.map((d) => `${d.domain}: grade ${d.grade ?? "-"} (${d.meaning})${d.open_issues ? `, ${d.open_issues} open issue${d.open_issues === 1 ? "" : "s"}` : ""}.`)
                : ["No domain has been graded yet."]),
            ]}
          />
        </Section>
      )}

      {r.overdue && (
        <Section n={next()} title="Overdue fixes" explain={r.overdue.explain}>
          <Bullets items={r.overdue.lines} />
        </Section>
      )}

      <Section n={next()} title="Recommended next steps">
        <ol className="list-decimal space-y-1 pl-5 text-sm text-ink">
          {r.next_steps.map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ol>
      </Section>
      <p className="text-xs text-ink-3">
        {r.organization} · Period {r.period.label} · Generated {fmtTime(r.generated_at)} · {r.brand}
      </p>
    </div>
  );
}

// ----------------------------------------------------------------------------- scheduled reports
const hourOptions = Array.from({ length: 24 }, (_, i) => ({ v: i, label: `${String(i).padStart(2, "0")}:00 UTC` }));
const when = (s: Pick<Subscription, "frequency" | "day" | "hour">) => {
  const t = `${String(s.hour).padStart(2, "0")}:00 UTC`;
  if (s.frequency === "daily") return `Every day at ${t}`;
  if (s.frequency === "weekly") return `Every ${WEEKDAYS[s.day]} at ${t}`;
  return `${s.frequency === "monthly" ? "Monthly" : "Quarterly"}, day ${s.day} at ${t}`;
};

function NewReportDialog({ open, onClose, onSaved }: { open: boolean; onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState<SubscriptionBody>({ name: "Board report", enabled: true, frequency: "monthly", day: 1, hour: 6 });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (open) setError(null);
  }, [open]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await executiveApi.create(form);
      onSaved();
      onClose();
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={onClose} title="Schedule an executive report">
      <form className="space-y-3" onSubmit={submit}>
        <ErrorNote error={error} />
        <Field label="Name" id="er-name" required maxLength={128} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        <FrequencyPicker value={form} onChange={(v) => setForm({ ...form, ...v })} />
        <p className="text-xs text-ink-3">You add the people who receive it after the report is created.</p>
        <div className="flex justify-end gap-2 pt-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy || !form.name.trim()}>
            {busy ? "Saving…" : "Create"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

type Slot = Pick<SubscriptionBody, "frequency" | "day" | "hour">;

function FrequencyPicker({ value, onChange }: { value: Slot; onChange: (v: Slot) => void }) {
  const cls = "w-full rounded border border-line bg-surface-2 px-2 py-1.5 text-sm";
  return (
    <div className="grid grid-cols-3 gap-2">
      <label className="text-sm">
        <span className="mb-1 block font-medium text-ink-2">How often</span>
        <select
          className={cls}
          value={value.frequency}
          onChange={(e) => {
            const f = e.target.value as ReportPeriod;
            onChange({ ...value, frequency: f, day: f === "weekly" ? 0 : 1 });
          }}
        >
          {(["daily", "weekly", "monthly", "quarterly"] as ReportPeriod[]).map((f) => (
            <option key={f} value={f}>{PERIOD_NAME[f]}</option>
          ))}
        </select>
      </label>
      <label className="text-sm">
        <span className="mb-1 block font-medium text-ink-2">{value.frequency === "weekly" ? "Day" : value.frequency === "daily" ? "Day" : "Day of month"}</span>
        <select className={cls} disabled={value.frequency === "daily"} value={value.day} onChange={(e) => onChange({ ...value, day: Number(e.target.value) })}>
          {value.frequency === "daily" && <option value={value.day}>Every day</option>}
          {value.frequency === "weekly" && WEEKDAYS.map((d, i) => <option key={d} value={i}>{d}</option>)}
          {(value.frequency === "monthly" || value.frequency === "quarterly") && Array.from({ length: 28 }, (_, i) => <option key={i + 1} value={i + 1}>{i + 1}</option>)}
        </select>
      </label>
      <label className="text-sm">
        <span className="mb-1 block font-medium text-ink-2">Time</span>
        <select className={cls} value={value.hour} onChange={(e) => onChange({ ...value, hour: Number(e.target.value) })}>
          {hourOptions.map((h) => <option key={h.v} value={h.v}>{h.label}</option>)}
        </select>
      </label>
    </div>
  );
}

const STATE_LABEL: Record<Recipient["state"], string> = { active: "Receives it", unsubscribed: "Unsubscribed", not_admin: "No longer an admin" };

function Recipients({ sub, admins, max, onChanged }: { sub: Subscription; admins: { id: string; name: string; email: string }[]; max: number; onChanged: () => void }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [title, setTitle] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const optedIn = new Map(sub.recipients.filter((r) => r.kind === "admin").map((r) => [r.user_id, r]));
  const externals = sub.recipients.filter((r) => r.kind === "external");

  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      onChanged();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mt-3 grid gap-4 md:grid-cols-2">
      <fieldset>
        <legend className="mb-1 text-sm font-medium text-ink-2">Administrators</legend>
        <p className="mb-1 text-xs text-ink-3">Each administrator can opt in to receive this report.</p>
        <div className="space-y-1 rounded border border-line p-2 text-sm">
          {admins.map((a) => {
            const rec = optedIn.get(a.id);
            return (
              <label key={a.id} className="flex items-center gap-2">
                <input
                  type="checkbox"
                  disabled={busy}
                  checked={!!rec}
                  onChange={(e) => void run(() => (e.target.checked ? executiveApi.addRecipient(sub.id, { kind: "admin", user_id: a.id }) : executiveApi.removeRecipient(sub.id, rec!.id)))}
                />
                <span>{a.name || a.email}</span>
                <span className="text-xs text-ink-3">{a.email}</span>
              </label>
            );
          })}
        </div>
      </fieldset>
      <div>
        <div className="mb-1 text-sm font-medium text-ink-2">Other people (no console account needed)</div>
        <p className="mb-1 text-xs text-ink-3">For example your CEO or a director. They get the PDF by email and a link to stop receiving it; the link never signs them in.</p>
        <ul className="mb-2 space-y-1 text-sm">
          {externals.map((r) => (
            <li key={r.id} className="flex items-center justify-between gap-2 rounded border border-line px-2 py-1">
              <span>
                {r.name}
                {r.job_title ? `, ${r.job_title}` : ""} <span className="text-xs text-ink-3">{r.email}</span>
                {r.state !== "active" && <span className="ml-2 text-xs text-sev-high">{STATE_LABEL[r.state]}</span>}
              </span>
              <button type="button" aria-label={`Remove ${r.name}`} disabled={busy} className="text-ink-3 hover:text-sev-critical" onClick={() => void run(() => executiveApi.removeRecipient(sub.id, r.id))}>
                <Trash2 aria-hidden className="h-4 w-4" />
              </button>
            </li>
          ))}
          {externals.length === 0 && <li className="text-xs text-ink-3">Nobody added yet.</li>}
        </ul>
        <ErrorNote error={error} />
        <form
          className="grid grid-cols-1 gap-2 sm:grid-cols-3"
          onSubmit={(e) => {
            e.preventDefault();
            void run(async () => {
              await executiveApi.addRecipient(sub.id, { kind: "external", name, email, job_title: title || undefined });
              setName("");
              setEmail("");
              setTitle("");
            });
          }}
        >
          <Field label="Name" id={`rn-${sub.id}`} required maxLength={120} value={name} onChange={(e) => setName(e.target.value)} />
          <Field label="Email" id={`re-${sub.id}`} type="email" required maxLength={320} value={email} onChange={(e) => setEmail(e.target.value)} />
          <Field label="Job title (optional)" id={`rt-${sub.id}`} maxLength={120} value={title} onChange={(e) => setTitle(e.target.value)} />
          <div className="sm:col-span-3">
            <Button type="submit" disabled={busy || sub.recipients.length >= max}>Add person</Button>
          </div>
        </form>
      </div>
    </div>
  );
}

type Pending = Partial<SubscriptionBody>;

function ScheduledReports() {
  const { data, error, reload } = useApi(executiveApi.subscriptions, []);
  const [pending, setPending] = useState<Record<string, Pending>>({});
  const [saving, setSaving] = useState(false);
  const [open, setOpen] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionErr, setActionErr] = useState<string | null>(null);

  const count = Object.values(pending).reduce((n, p) => n + Object.keys(p).length, 0);
  const view = (s: Subscription): Subscription => ({ ...s, ...pending[s.id] });
  const setField = (s: Subscription, patch: Pending) =>
    setPending((p) => {
      const merged = { ...p[s.id], ...patch };
      for (const k of Object.keys(merged) as (keyof Pending)[]) if (merged[k] === s[k]) delete merged[k];
      const next = { ...p };
      if (Object.keys(merged).length) next[s.id] = merged;
      else delete next[s.id];
      return next;
    });

  async function save() {
    setSaving(true);
    setActionErr(null);
    try {
      for (const [id, body] of Object.entries(pending)) await executiveApi.update(id, body);
      setPending({});
      setNotice("Changes saved.");
      reload();
    } catch (e) {
      setActionErr(errMsg(e));
    } finally {
      setSaving(false);
    }
  }

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

  return (
    <Card
      title="Scheduled reports"
      className="mb-4"
      actions={<Button onClick={() => setOpen(true)} disabled={!!data && data.items.length >= data.max_subscriptions}>Schedule a report</Button>}
    >
      <p className="mb-3 text-sm text-ink-2">
        The report is emailed as a PDF to the people you choose, every day, week, month or quarter. You can set up several, for example a weekly one for IT and a quarterly one for the board.
        {data && !data.mail_configured && <span className="text-sev-high"> No platform mail server is configured yet: reports cannot be sent until it is.</span>}
      </p>
      <ErrorNote error={error ?? actionErr} />
      {notice && <div role="status" className="mb-3 rounded border border-good/60 bg-good/10 px-3 py-2 text-sm">{notice}</div>}
      {data && data.items.length === 0 ? (
        <Empty icon={Mail} title="No scheduled reports">Schedule one to email the report to your leadership team.</Empty>
      ) : (
        <div className="space-y-4">
          {(data?.items ?? []).map((raw) => {
            const s = view(raw);
            return (
              <div key={raw.id} className="rounded-lg border border-line bg-surface-1 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="text-sm font-semibold text-ink">{raw.name}</div>
                    <div className="text-xs text-ink-3">
                      {when(s)} · {raw.last_run_at ? `last sent ${fmtAgo(raw.last_run_at)}` : "never sent"}
                      {raw.last_status && raw.last_status !== "sent" && <span className="text-sev-high" title={raw.last_error ?? undefined}> · last send {raw.last_status}</span>}
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-3">
                    <label className="flex items-center gap-2 text-sm">
                      <Switch on={s.enabled} label={`Send "${raw.name}" on schedule`} onChange={(v) => setField(raw, { enabled: v })} />
                      {s.enabled ? "On" : "Paused"}
                    </label>
                    <Button
                      onClick={() => void act(async () => {
                        const r = await executiveApi.sendNow(raw.id);
                        if (r.status === "failed") throw new Error(r.errors.join("; ") || "sending failed");
                      }, "Report sent.")}
                    >
                      Send now
                    </Button>
                    <Button variant="danger" onClick={() => { if (window.confirm(`Delete "${raw.name}" and its recipient list?`)) void act(() => executiveApi.remove(raw.id)); }}>Delete</Button>
                  </div>
                </div>
                <div className="mt-3 max-w-xl">
                  <FrequencyPicker value={s} onChange={(v) => setField(raw, v)} />
                </div>
                <Recipients sub={raw} admins={data?.admins ?? []} max={data?.max_recipients ?? 25} onChanged={reload} />
              </div>
            );
          })}
        </div>
      )}
      <SaveBar count={count} saving={saving} onSave={() => void save()} onDiscard={() => setPending({})} note="Schedule changes apply when you save." />
      <NewReportDialog open={open} onClose={() => setOpen(false)} onSaved={reload} />
    </Card>
  );
}

// ----------------------------------------------------------------------------- page
export default function ExecutiveReportPage() {
  const { can } = useAuth();
  const [period, setPeriod] = useUrlState("period", "monthly");
  const p = (PERIODS.some((x) => x.value === period) ? period : "monthly") as ReportPeriod;
  const report = useApi(() => executiveApi.report(p), [p]);
  const data = report.data;

  return (
    <div className="mx-auto max-w-[1100px]">
      <PageHeader
        title="Executive report"
        subtitle="A five-minute summary of your whole environment, in plain words."
        actions={
          <div data-print="hide" className="flex flex-wrap items-center gap-2">
            <Segments label="Period" value={p} onChange={setPeriod} options={PERIODS} />
            <a href={executiveApi.pdfUrl(p)} className="inline-flex items-center gap-1.5 rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line" title="The same PDF the scheduled emails attach">
              <Download aria-hidden className="h-3.5 w-3.5" />
              Download PDF
            </a>
            <button type="button" onClick={() => window.print()} className="inline-flex items-center gap-1.5 rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">
              <Printer aria-hidden className="h-3.5 w-3.5" />
              Print
            </button>
          </div>
        }
      />
      <ErrorNote error={report.error} />
      {report.loading && !data ? <p className="text-sm text-ink-3">Preparing the report…</p> : data && <ReportView r={data} />}
      {can("admin") && (
        <div data-print="hide">
          <ScheduledReports />
        </div>
      )}
    </div>
  );
}
