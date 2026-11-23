import { Check, Circle, Globe2, Play, Plus } from "lucide-react";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useAuth } from "../../auth/context";
import { CodeBlock } from "../../components/FixTabs";
import { NotAsvBanner, ResultBadge, ScopeModal } from "../../components/external";
import { OverflowMenu } from "../../components/OverflowMenu";
import { FindingsPanel } from "./ExternalFindings";
import { errMsg, inputCls } from "../../lib/externalUi";
import { Button, Card, Empty, ErrorNote, Modal, NameCell, None, NumCell, PageHeader, Pill, PillRow, Table, TextCell, type PillTone } from "../../components/ui";
import { externalApi, type ExtFindingGroup, type ExtOverview, type ExtTarget } from "../../externalApi";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useUrlState } from "../../lib/useUrlState";
import { useApi } from "../../lib/useApi";
import { useSort } from "../../lib/useSort";
import { PAGE_INFO } from "../../lib/pageInfo";

function TargetStatus({ t }: { t: ExtTarget }) {
  const [tone, text]: [PillTone, string] = t.verified
    ? ["good", t.kind === "domain" ? "Verified" : "Approved"]
    : t.approval_status === "requested"
      ? ["info", "Requested"]
      : t.approval_status === "rejected"
        ? ["critical", "Rejected"]
        : t.kind !== "domain"
          ? ["medium", "Needs approval"]
          : ["medium", "Waiting for proof"];
  return (
    <PillRow>
      <Pill tone={tone}>{text}</Pill>
      {t.default_password_checks && <Pill tone="medium" title="Default-password checks are on">Passwords</Pill>}
    </PillRow>
  );
}

function TargetRow({ t, systems, issues, admin, analyst, anyRunning, scanning, onChange }: { t: ExtTarget; systems: number; issues: number; admin: boolean; analyst: boolean; anyRunning: boolean; scanning: boolean; onChange: () => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [attest, setAttest] = useState("");
  const [consentOpen, setConsentOpen] = useState(false);
  const [consent, setConsent] = useState(false);
  const [removing, setRemoving] = useState(false);

  async function run(fn: () => Promise<unknown>, done?: string) {
    setBusy(true);
    setMsg(null);
    try {
      await fn();
      if (done) setMsg(done);
      onChange();
    } catch (e) {
      setMsg(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <li className="border-b border-line px-4 py-3 last:border-0">
      <div className="flex items-center gap-3">
        <div className="w-[300px] min-w-0 shrink-0">
          <NameCell name={t.value} sub={t.kind === "cidr" ? "IP range" : t.kind === "ip" ? "Single IP address" : "Domain and subdomains"} />
        </div>
        <div className="w-[170px] shrink-0">
          <TargetStatus t={t} />
        </div>
        <div className="w-[80px] shrink-0">
          <NumCell value={systems} />
        </div>
        <div className="w-[90px] shrink-0">
          <NumCell value={issues} />
        </div>
        <span className="flex-1" />
        {admin && t.kind === "domain" && !t.verified && (
          <Button variant="primary" disabled={busy} onClick={() => void run(async () => {
            const r = await externalApi.verify(t.id);
            if (!r.verified) throw new Error(r.error ?? "Not verified");
          }, "Verified.")}>
            Verify
          </Button>
        )}
        {analyst && t.verified && (
          <Button disabled={busy || anyRunning} title={anyRunning && !scanning ? "A scan is already running" : `Scan only ${t.value}`}
            onClick={() => void run(async () => { await externalApi.scanTarget(t.id); })}>
            <Play aria-hidden className="mr-1 inline h-3.5 w-3.5" />
            {scanning ? "Scanning…" : "Scan"}
          </Button>
        )}
        <OverflowMenu
          label={`More actions for ${t.value}`}
          items={[
            { label: open ? "Hide details" : t.verified ? "Details" : "How to prove it's yours", onSelect: () => setOpen(!open) },
            ...(admin ? [{ label: "Remove…", danger: true, disabled: busy, onSelect: () => setRemoving(true) }] : []),
          ]}
        />
      </div>
      {msg && <p role="status" className="mt-2 text-sm text-ink-2">{msg}</p>}
      {t.last_check_error && !t.verified && <p className="mt-1 text-xs text-ink-3">Last check: {t.last_check_error}</p>}
      {open && (
        <div className="mt-3 space-y-3 text-sm">
          {t.proof && (
            <div className="space-y-2">
              <p className="text-ink-2">Prove you control this domain with either option, then choose Verify. Subdomains of a verified domain are covered.</p>
              <p className="font-medium text-ink">Option 1: DNS TXT record on <code>{t.proof.txt_name}</code> (or on <code>{t.proof.txt_name_alt}</code>)</p>
              <CodeBlock code={t.proof.txt_value} label="TXT record value" />
              <p className="font-medium text-ink">Option 2: a file at <code>{t.proof.file_url}</code> containing only</p>
              <CodeBlock code={t.proof.file_content} label="verification file content" />
            </div>
          )}
          {t.kind !== "domain" && !t.verified && (
            <div className="space-y-2">
              <p className="text-ink-2">
                An IP address is scanned only when one of your verified domains points to it, or it belongs to your connected cloud accounts. Otherwise a platform owner
                must approve it after you confirm you are authorised to scan it.
              </p>
              {admin && t.approval_status !== "requested" && (
                <>
                  <label htmlFor={`att-${t.id}`} className="block text-sm font-medium text-ink-2">Authorisation statement</label>
                  <textarea id={`att-${t.id}`} rows={2} className={inputCls} value={attest} onChange={(e) => setAttest(e.target.value)}
                    placeholder="We own or are authorised to scan this address and allow Sentrigis to scan it." />
                  <Button disabled={busy || attest.trim().length < 20} onClick={() => void run(() => externalApi.requestApproval(t.id, attest), "Approval requested.")}>
                    Request approval
                  </Button>
                </>
              )}
              {t.approval_note && <p className="text-ink-2">Platform owner note: {t.approval_note}</p>}
            </div>
          )}
          {admin && (
            <div className="rounded border border-line bg-surface-2 p-3">
              <label className="flex items-start gap-2">
                <input type="checkbox" className="mt-1" checked={t.default_password_checks} disabled={busy}
                  onChange={(e) => (e.target.checked ? setConsentOpen(true) : void run(() => externalApi.setDefaultPasswords(t.id, false, false)))} />
                <span>
                  <span className="font-medium text-ink">Check for vendor default passwords (optional)</span>
                  <span className="block text-xs text-ink-3">
                    Off by default. Tries a few well-known default logins on HTTP Basic admin pages, slowly, and stops at the first success. The passwords tried are
                    never stored or shown.{t.consent_by && ` Enabled by ${t.consent_by} on ${fmtTime(t.consent_at!)}.`}
                  </span>
                </span>
              </label>
            </div>
          )}
        </div>
      )}
      <Modal open={removing} onClose={() => setRemoving(false)} title={`Remove ${t.value}?`}>
        <p className="text-sm text-ink-2">It will no longer be scanned. Issues already found for it stay in your history.</p>
        <div className="mt-4 flex justify-end gap-2">
          <Button onClick={() => setRemoving(false)}>Cancel</Button>
          <Button variant="danger" onClick={() => { setRemoving(false); void run(() => externalApi.removeTarget(t.id)); }}>Remove</Button>
        </div>
      </Modal>
      <Modal open={consentOpen} onClose={() => setConsentOpen(false)} title="Enable default-password checks">
        <p className="text-sm text-ink-2">
          The scanner will try a short built-in list of vendor-default credentials (at most a few attempts per login page) against {t.value}. This can lock accounts
          or raise alerts in your monitoring. Your consent is recorded in the audit log.
        </p>
        <label className="mt-3 flex items-start gap-2 text-sm">
          <input type="checkbox" className="mt-1" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
          <span>I am authorised to test this target and consent to default-password checks.</span>
        </label>
        <div className="mt-4 flex justify-end gap-2">
          <Button onClick={() => setConsentOpen(false)}>Cancel</Button>
          <Button variant="primary" disabled={!consent} onClick={() => { setConsentOpen(false); void run(() => externalApi.setDefaultPasswords(t.id, true, true)); setConsent(false); }}>
            Enable
          </Button>
        </div>
      </Modal>
    </li>
  );
}

const TABS = [
  { key: "overview", label: "Overview" },
  { key: "results", label: "Scan results" },
  { key: "systems", label: "Systems found" },
  { key: "targets", label: "Domains & IPs" },
] as const;
type TabKey = (typeof TABS)[number]["key"];

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

/** One plain sentence about what dominates the failing findings (only counts the API returned). */
function failSentence(groups: ExtFindingGroup[]): string {
  const top = [...groups].sort((a, b) => b.affected - a.affected).slice(0, 3);
  if (top.length === 0) return "";
  const parts = top.map((g) => `${g.title} (${plural(g.affected, "place")})`);
  const list = parts.length > 1 ? `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}` : parts[0];
  return `The biggest sources are ${list}.`;
}

function AddTargetModal({ open, onClose, onAdded, max }: { open: boolean; onClose: () => void; onAdded: () => void; max: number }) {
  const [value, setValue] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function add() {
    setBusy(true);
    setErr(null);
    try {
      await externalApi.addTarget(value);
      setValue("");
      onAdded();
      onClose();
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal open={open} onClose={onClose} title="Add domain or IP">
      <form onSubmit={(e) => { e.preventDefault(); if (value.trim()) void add(); }} className="space-y-3">
        <div>
          <label htmlFor="ext-target" className="mb-1 block text-sm font-medium text-ink-2">Domain or IP address</label>
          <input id="ext-target" className={inputCls} value={value} onChange={(e) => setValue(e.target.value)} placeholder="shop.example.com or 203.0.113.10" />
          <p className="mt-1 text-xs text-ink-3">You can also enter an IP address range (up to 256 addresses). You can add up to {max} in total. Only verified ones are scanned.</p>
        </div>
        <ErrorNote error={err} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={!value.trim() || busy}>Add</Button>
        </div>
      </form>
    </Modal>
  );
}

function ScheduleModal({ open, onClose, o, onSaved }: { open: boolean; onClose: () => void; o: ExtOverview | null | undefined; onSaved: () => void }) {
  const [hours, setHours] = useState(String(o?.schedule.interval_hours ?? 168));
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function save() {
    setBusy(true);
    setErr(null);
    try {
      await externalApi.setSchedule(true, Number(hours));
      onSaved();
      onClose();
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal open={open} onClose={onClose} title="Scan automatically">
      <div className="space-y-3">
        <label className="block text-sm text-ink-2">
          Scan every
          <select aria-label="Scan interval" className={`${inputCls} mt-1`} value={hours} onChange={(e) => setHours(e.target.value)}>
            <option value="24">day</option><option value="168">week</option><option value="336">2 weeks</option><option value="720">30 days</option>
          </select>
        </label>
        <ErrorNote error={err} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={busy} onClick={() => void save()}>Save</Button>
        </div>
      </div>
    </Modal>
  );
}

function ChecklistItem({ done, title, sub, action }: { done: boolean; title: string; sub: string; action?: { label: string; onClick: () => void } }) {
  return (
    <li className="flex items-start gap-3 py-2.5">
      {done ? <Check aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-good" /> : <Circle aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-ink-3" />}
      <div className="min-w-0 flex-1">
        <div className={`text-sm font-medium ${done ? "text-ink-2" : "text-ink"}`}>{title}<span className="sr-only">{done ? " (done)" : " (to do)"}</span></div>
        <div className="text-xs text-ink-3">{sub}</div>
      </div>
      {!done && action && <Button onClick={action.onClick}>{action.label}</Button>}
    </li>
  );
}

export default function AttackSurface() {
  const { can } = useAuth();
  const admin = can("admin");
  const [tabParam] = useUrlState("tab", "overview");
  const tab: TabKey = TABS.some((t) => t.key === tabParam) ? (tabParam as TabKey) : "overview";
  const [, setParams] = useSearchParams();
  /** Switching tabs drops the filters of the previous one. */
  const setTab = (k: TabKey) => setParams(k === "overview" ? {} : { tab: k }, { replace: true });
  const ov = useApi(externalApi.overview, [], 8000);
  const targets = useApi(externalApi.targets, []);
  const hosts = useApi(externalApi.hosts, [], 20000);
  const scans = useApi(externalApi.scans, [], 20000);
  const reports = useApi(externalApi.reports, []);
  const o = ov.data;
  const failing = o?.result === "fail";
  const failGroups = useApi(() => (failing ? externalApi.findingsGrouped({ status: "open", pre_asv: "fail" }) : Promise.resolve([])), [failing, o?.failing_findings]);
  const sortedHosts = useSort(
    hosts.data,
    {
      host: (h) => h.host,
      ports: (h) => h.ports.length,
      findings: (h) => h.findings,
      first: (h) => h.first_seen,
    },
    { key: "host", dir: "asc" },
    { ports: "desc", findings: "desc", first: "desc" },
  );
  const [err, setErr] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [scheduling, setScheduling] = useState(false);
  const [scoping, setScoping] = useState(false);
  // a running scan of a single target names it (its record lists only that target)
  const runningScan = scans.data?.find((x) => x.status === "running");
  const runningTarget = o?.running && runningScan?.trigger === "target" ? (runningScan.targets[0] ?? null) : null;

  function reloadAll() {
    ov.reload();
    targets.reload();
    scans.reload();
    hosts.reload();
    reports.reload();
  }
  async function act(fn: () => Promise<unknown>) {
    setErr(null);
    try {
      await fn();
      reloadAll();
    } catch (e) {
      setErr(errMsg(e));
    }
  }
  /** Scan results tab showing only what would fail a PCI scan. */
  function seeWhatToFix() {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set("tab", "results");
      next.set("pre_asv", "fail");
      return next;
    }, { replace: true });
  }

  const list = targets.data ?? [];
  // Systems and open issues per target, counted from the systems list the page already loads.
  const countFor = (t: ExtTarget) => {
    const mine = (hosts.data ?? []).filter((h) => (t.kind === "domain" ? h.host === t.value || h.host.endsWith(`.${t.value}`) : t.kind === "ip" ? h.ip === t.value || h.host === t.value : false));
    return { systems: mine.length, issues: mine.reduce((n, h) => n + h.findings, 0) };
  };
  const domains = list.filter((t) => t.kind === "domain");
  const unproven = list.filter((t) => !t.verified);
  const hasTargets = list.length > 0;
  const proven = hasTargets && unproven.length === 0;
  const scheduleOn = o?.schedule.enabled ?? false;
  const scoped = !!o?.scope.confirmed_at;
  const doneCount = [hasTargets, proven, scheduleOn, scoped].filter(Boolean).length;
  const latestReport = reports.data?.[0];

  const answerBadge = <ResultBadge result={o?.result ?? null} />;
  const headline = !o || o.result === null
    ? "Run your first scan to see where you stand"
    : o.result === "fail"
      ? `${plural(o.failing_findings, "issue")} would fail your next PCI scan`
      : "Nothing would fail your next PCI scan";
  const sentence = !o || o.result === null
    ? hasTargets ? "Only verified domains and IP addresses are scanned." : "Add a domain you own, prove it's yours, then scan it."
    : o.result === "fail" ? failSentence(failGroups.data ?? []) : "Your internet-facing systems look fine to the last scan.";

  return (
    <div className="space-y-4">
      <PageHeader
        title="Attack surface"
        info={{ title: PAGE_INFO.attackSurface.title, text: `${PAGE_INFO.attackSurface.text} The scan runs from outside and never exploits anything. It is a readiness check for a PCI ASV scan: only an Approved Scanning Vendor can issue an official ASV scan report or an Attestation of Scan Compliance.` }}
        subtitle="What attackers can see of your systems from the internet."
        actions={
          <>
            <span className="text-sm text-ink-3">{o?.last_scan ? `Last scan ${fmtAgo(o.last_scan.started_at)}` : o ? "No scan yet" : ""}</span>
            <Link to="/attack-surface/reports" className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">Reports</Link>
            {can("analyst") && (
              <Button variant="primary" disabled={o?.running} title={o?.running ? "A scan is already running" : "Scan every verified domain and IP address"} onClick={() => void act(externalApi.scanNow)}>
                <Play aria-hidden className="mr-1 inline h-3.5 w-3.5" />
                {o?.running ? "Scan running…" : "Scan now"}
              </Button>
            )}
          </>
        }
      />
      <div role="tablist" aria-label="Attack surface" className="flex flex-wrap gap-1 border-b border-line">
        {TABS.map((t) => (
          <button
            key={t.key}
            type="button"
            role="tab"
            aria-selected={tab === t.key}
            onClick={() => setTab(t.key)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${tab === t.key ? "border-accent font-semibold text-ink" : "border-transparent text-ink-2 hover:text-ink"}`}
          >
            {t.label}
          </button>
        ))}
      </div>
      {tab !== "overview" && <NotAsvBanner />}
      <ErrorNote error={err ?? ov.error ?? targets.error} />

      {tab === "overview" && (
        <div className="grid gap-4 lg:grid-cols-12">
          <section className="space-y-3 rounded-xl border border-line bg-surface-1 p-5 lg:col-span-7">
            <div>{answerBadge}</div>
            <h2 className="text-xl font-semibold tracking-tight text-ink">{headline}</h2>
            {sentence && <p className="text-sm text-ink-2">{sentence}</p>}
            <div className="flex flex-wrap gap-2 pt-1">
              {failing && <Button variant="primary" onClick={seeWhatToFix}>See what to fix</Button>}
              {latestReport ? (
                <a className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line" href={externalApi.reportPdfUrl(latestReport.id)}>Download report</a>
              ) : (
                <Link className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line" to="/attack-surface/reports">Download report</Link>
              )}
            </div>
            <NotAsvBanner />
          </section>
          <section className="rounded-xl border border-line bg-surface-1 p-5 lg:col-span-5">
            <div className="flex items-baseline justify-between">
              <h2 className="text-sm font-semibold text-ink">Finish setting up</h2>
              <span className="text-xs text-ink-3">{doneCount} of 4 done</span>
            </div>
            <ul className="mt-2 divide-y divide-line">
              <ChecklistItem done={hasTargets} title="Add your domains" sub={hasTargets ? list.slice(0, 3).map((t) => t.value).join(", ") + (list.length > 3 ? ` and ${list.length - 3} more` : "") : "Add a domain or IP address you own"}
                action={admin ? { label: "Add", onClick: () => setAdding(true) } : undefined} />
              <ChecklistItem done={proven} title="Prove you own them" sub={proven ? "Verified" : hasTargets ? `${unproven.length} of ${list.length} waiting for proof` : "Add a domain first"}
                action={hasTargets ? { label: "Verify", onClick: () => setTab("targets") } : undefined} />
              <ChecklistItem done={scheduleOn} title="Scan automatically every week" sub={scheduleOn ? `Every ${o?.schedule.interval_hours === 24 ? "day" : o?.schedule.interval_hours === 168 ? "week" : `${o?.schedule.interval_hours} hours`}` : "Find new problems without remembering to scan"}
                action={admin ? { label: "Turn on", onClick: () => setScheduling(true) } : undefined} />
              <ChecklistItem done={scoped} title="Confirm what's in scope" sub={scoped ? `Confirmed by ${o?.scope.confirmed_by}` : "Needed only before your first report"}
                action={{ label: "Confirm", onClick: () => setScoping(true) }} />
            </ul>
          </section>
        </div>
      )}

      {tab === "results" && <FindingsPanel />}

      {tab === "systems" && (
        <Card title={plural(hosts.data?.length ?? 0, "system") + " found on the internet"} actions={<span className="text-xs text-ink-3">From the last scan</span>}>
          <Table
            tableId="attack-surface"
            head={[
              { label: "System", sort: "host", w: 320 },
              { label: "Open ports", sort: "ports", w: 260 },
              { label: "Issues", sort: "findings", w: 100, align: "right" },
              { label: "First seen", sort: "first", w: 130 },
            ]}
            sort={sortedHosts.sort}
            onSort={sortedHosts.onSort}
            loading={hosts.loading}
            rowCount={hosts.data?.length ?? 0}
            noun="systems"
            pageSize={50}
            empty={<Empty icon={Globe2} title="No systems found yet">Verify a domain or IP address and run a scan.</Empty>}
          >
            {sortedHosts.rows.map((h) => (
              <tr key={h.id}>
                <td className="px-3 py-2"><NameCell name={h.host} sub={h.ip && h.ip !== h.host ? h.ip : undefined} /></td>
                <td className="px-3 py-2">
                  {h.ports.length === 0 ? <None /> : <TextCell mono title={h.ports.map((p) => `${p.port} ${p.service}`).join(", ")}>{h.ports.map((p) => p.port).join(", ")}</TextCell>}
                </td>
                <td className="px-3 py-2">
                  {h.findings > 0 ? <Link className="block text-right tabular-nums text-accent hover:underline" to={`/attack-surface?tab=results&host=${encodeURIComponent(h.host)}`}>{h.findings}</Link> : <NumCell value={0} />}
                </td>
                <td className="px-3 py-2"><TextCell muted>{fmtTime(h.first_seen).split(",")[0]}</TextCell></td>
              </tr>
            ))}
          </Table>
        </Card>
      )}

      {tab === "targets" && (
        <Card
          title="Your domains and IP addresses"
          actions={
            <>
              <span className="text-xs text-ink-3">Only verified ones are scanned.</span>
              {admin && <Button variant="primary" onClick={() => setAdding(true)}><Plus aria-hidden className="mr-1 inline h-3.5 w-3.5" />Add domain or IP</Button>}
            </>
          }
        >
          {list.length === 0 ? (
            <Empty icon={Globe2} title="Nothing added yet">Add a domain you own, then prove it with a DNS record or a file.</Empty>
          ) : (
            <>
            <div className="-mx-4 -mt-4 flex items-center gap-3 border-b border-line px-4 py-2 text-xs uppercase tracking-wide text-ink-3" aria-hidden>
              <span className="w-[300px] shrink-0">Domain or IP</span>
              <span className="w-[170px] shrink-0">Ownership</span>
              <span className="w-[80px] shrink-0 text-right">Systems</span>
              <span className="w-[90px] shrink-0 text-right">Open issues</span>
            </div>
            <ul className="-mx-4 -mb-4">{list.map((t) => <TargetRow key={t.id} t={t} systems={countFor(t).systems} issues={countFor(t).issues} admin={admin} analyst={can("analyst")} anyRunning={!!o?.running} scanning={runningTarget === t.value} onChange={() => { targets.reload(); ov.reload(); }} />)}</ul>
            </>
          )}
          {domains.length === 0 && list.length > 0 && <p className="mt-3 text-xs text-ink-3">Tip: adding the domains your IP addresses serve lets them be verified automatically.</p>}
        </Card>
      )}

      <AddTargetModal open={adding} onClose={() => setAdding(false)} onAdded={reloadAll} max={o?.limits.max_targets ?? 25} />
      {scheduling && <ScheduleModal open onClose={() => setScheduling(false)} o={o} onSaved={reloadAll} />}
      {o && <ScopeModal open={scoping} onClose={() => setScoping(false)} scope={o.scope} canEdit={admin} onSaved={reloadAll} />}
    </div>
  );
}
