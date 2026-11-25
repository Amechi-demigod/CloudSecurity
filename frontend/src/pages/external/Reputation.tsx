import { Globe2, Play } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../auth/context";
import { GradeBadge } from "../../components/reputation";
import { Button, Empty, ErrorNote, Stat } from "../../components/ui";
import { externalApi, reputationApi, type RepDomain, type RepFinding, type RepSummary } from "../../externalApi";
import { errMsg } from "../../lib/externalUi";
import { fmtAgo, fmtUntil } from "../../lib/format";
import { certStatus, emailFakeable, emailStatus, lookalikeStatus, lookalikes, newCerts, plural, toFix } from "../../lib/reputation";
import { useApi } from "../../lib/useApi";

interface RepData {
  summary: RepSummary;
  domains: RepDomain[];
  findings: RepFinding[];
}

/** Summary, the details behind each grade (one small request per verified domain) and the open findings. */
async function loadReputation(): Promise<RepData> {
  const summary = await reputationApi.summary();
  const [domains, findings] = await Promise.all([
    Promise.all(summary.domains.map((d) => reputationApi.domain(d.domain).catch(() => d))),
    reputationApi.findings({ status: "open" }),
  ]);
  return { summary, domains, findings };
}

const mins = (s: number) => (s < 90 ? `${s} seconds` : `${Math.ceil(s / 60)} minutes`);

function Row({ label, text }: { label: string; text: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-t border-line py-1.5 text-sm">
      <dt className="shrink-0 text-ink-3">{label}</dt>
      <dd className="min-w-0 text-right text-ink">{text}</dd>
    </div>
  );
}

function DomainCard({ d, findings }: { d: RepDomain; findings: RepFinding[] }) {
  const fix = toFix(d);
  return (
    <li>
      <Link
        to={`/attack-surface/reputation/${encodeURIComponent(d.domain)}`}
        className="block h-full rounded-xl border border-line bg-surface-1 p-4 transition hover:border-accent/60 hover:bg-surface-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        <div className="flex items-start gap-3">
          <GradeBadge grade={d.grade} />
          <div className="min-w-0">
            <h3 className="truncate text-base font-semibold text-ink">{d.domain}</h3>
            <p className="text-xs text-ink-2">{d.score === null ? "Not checked yet" : `Score ${d.score} · ${fix === 0 ? "nothing to fix" : `${fix} to fix`}`}</p>
          </div>
        </div>
        {d.score !== null && (
          <dl className="mt-3">
            <Row label="Email security" text={emailStatus(d, findings)} />
            <Row label="Lookalike domains" text={lookalikeStatus(d)} />
            <Row label="Certificates" text={certStatus(d, findings)} />
          </dl>
        )}
      </Link>
    </li>
  );
}

export default function ReputationPanel() {
  const { can } = useAuth();
  const { data, error, loading, reload } = useApi(loadReputation, [], 8000);
  const ov = useApi(externalApi.overview, []);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function checkNow() {
    setBusy(true);
    setMsg(null);
    try {
      await reputationApi.run();
      setMsg("Check started. Results appear here in a minute or two.");
      reload();
    } catch (e) {
      setMsg(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  if (!data) return loading ? <p className="py-8 text-center text-sm text-ink-3" role="status">Loading reputation checks…</p> : <ErrorNote error={error} />;
  const { summary, domains, findings } = data;
  const run = summary.last_run;
  const running = run?.status === "running";
  const left = summary.cooldown_seconds_left;
  const when = run ? fmtAgo(run.finished_at ?? run.started_at) : null;
  const sched = ov.data?.schedule;
  const next = sched ? (sched.enabled && sched.next_scan_at ? `Next check: ${fmtUntil(sched.next_scan_at)}` : "Automatic checks are off. Turn on automatic scans in Overview.") : "";
  const status = running ? "Check running… this takes a minute or two." : run ? `Last check ${run.status === "failed" ? "failed" : "done"} · ${plural(run.domains.length, "domain")} · ${when}` : "No check has run yet";

  const fakeable = domains.filter((d) => emailFakeable(d, findings));
  const lookalikeCount = domains.reduce((n, d) => n + lookalikes(d).length, 0);
  const withMail = domains.reduce((n, d) => n + lookalikes(d).filter((l) => l.mx.length > 0).length, 0);
  const certs = domains.reduce((n, d) => n + newCerts(d, findings).length, 0);
  const noneYet = domains.every((d) => d.score === null);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="text-sm text-ink-2" role="status">
          <p>{status}</p>
          {!running && next && <p className="text-ink-3">{next}</p>}
        </div>
        {can("analyst") && summary.domains.length > 0 && (
          <Button variant="primary" disabled={busy || running || left > 0} title={left > 0 ? `You can check again in ${mins(left)}` : "Check every verified domain now"} onClick={() => void checkNow()}>
            <Play aria-hidden className="mr-1 inline h-3.5 w-3.5" />
            {running ? "Checking…" : "Check now"}
          </Button>
        )}
      </div>
      {left > 0 && !running && can("analyst") && <p className="text-xs text-ink-3">A check was started recently. You can run another in {mins(left)}.</p>}
      {msg && <p role="status" className="rounded border border-line bg-surface-2 px-3 py-2 text-sm text-ink-2">{msg}</p>}
      {run && (run.status === "failed" || run.status === "partial") && run.message && <p className="text-sm text-ink-2">{run.message}</p>}
      <ErrorNote error={error} />

      {summary.domains.length === 0 ? (
        <section className="rounded-xl border border-line bg-surface-1">
          <Empty icon={Globe2} title="No verified domains yet" action={<Link to="/attack-surface?tab=targets" className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">Go to Domains &amp; IPs</Link>}>
            We only check domains you have proved are yours. Add a domain and prove it in Domains &amp; IPs, then come back here.
          </Empty>
        </section>
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Stat label="Domains checked" value={domains.length} sub="all proved yours" />
            <Stat label="Email can be faked" value={noneYet ? "-" : fakeable.length} sub={fakeable.length ? `${fakeable[0].domain}: ${emailFakeable(fakeable[0], findings)}` : noneYet ? "Waiting for the first check" : "No domain affected"} />
            <Stat label="Lookalike domains" value={noneYet ? "-" : lookalikeCount} sub={noneYet ? "Waiting for the first check" : `${withMail} can receive email`} />
            <Stat label="New certificates" value={noneYet ? "-" : certs} sub={noneYet ? "Waiting for the first check" : "from an issuer not seen before"} />
          </div>
          <ul className="grid gap-3 md:grid-cols-2 xl:grid-cols-3" aria-label="Domains">
            {domains.map((d) => <DomainCard key={d.domain} d={d} findings={findings} />)}
          </ul>
          <p className="text-xs text-ink-3">
            Grades: A is 90 or more, F is below 50.{summary.checks.blocklists_enabled ? "" : " Blocklist checks are not switched on."}
          </p>
        </>
      )}
    </div>
  );
}
