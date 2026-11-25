import { Check } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { FindingModal, GradeBadge } from "../../components/reputation";
import { Breadcrumbs, Button, Card, ErrorNote, SeverityBadge, Tag } from "../../components/ui";
import { reputationApi, type RepCategory, type RepFinding } from "../../externalApi";
import { fmtAgo } from "../../lib/format";
import { plural, toFix } from "../../lib/reputation";
import { useApi } from "../../lib/useApi";

const SECTIONS: { cat: RepCategory; title: string }[] = [
  { cat: "email", title: "Email security" },
  { cat: "lookalike", title: "Lookalike domains" },
  { cat: "certificate", title: "Certificates" },
  { cat: "blocklist", title: "Blocklists" },
];

const buttonLabel = (f: RepFinding) => (f.category === "email" || f.category === "blocklist" ? "How to fix" : f.category === "lookalike" && f.check_id === "rep.lookalike_registered" ? "Mark as ours" : "What to do");

/** Checks that came out fine, from the data behind the grade and the open findings. */
function passed(cat: RepCategory, d: Awaited<ReturnType<typeof loadDomain>>["domain"], open: RepFinding[]): string[] {
  const out: string[] = [];
  const bad = (...ids: string[]) => open.some((f) => ids.includes(f.check_id));
  const e = d.details?.email;
  if (cat === "email" && e) {
    if (e.spf && !bad("rep.spf_allow_all", "rep.spf_neutral", "rep.spf_multiple", "rep.spf_no_all", "rep.spf_too_many_lookups")) out.push("SPF is set");
    if (e.dmarc && !bad("rep.dmarc_invalid", "rep.dmarc_multiple", "rep.dmarc_policy_none")) out.push("DMARC is set");
    if ((e.dkim_selectors ?? []).length > 0) out.push("DKIM key found");
    if (e.mta_sts) out.push("MTA-STS is set");
    if (e.tls_rpt) out.push("TLS reporting is set");
  }
  if (cat === "lookalike" && d.details?.lookalikes && open.length === 0 && !d.details.lookalikes.note) out.push(`Checked ${plural(d.details.lookalikes.candidates, "possible lookalike")}: none registered`);
  if (cat === "certificate" && d.details?.certificates?.enabled && !d.details.certificates.error && open.length === 0) out.push(`${plural(d.details.certificates.count ?? 0, "certificate")} in the last ${d.details.certificates.days ?? 90} days, nothing unusual`);
  return out;
}

async function loadDomain(name: string) {
  const [domain, findings] = await Promise.all([reputationApi.domain(name), reputationApi.findings({ domain: name })]);
  return { domain, findings };
}

export default function ReputationDomain() {
  const { domain: name = "" } = useParams();
  const { data, error, loading, reload } = useApi(() => loadDomain(name), [name], 10000);
  const [chosen, setChosen] = useState<RepFinding | null>(null);
  const back = <Breadcrumbs items={[{ label: "Attack surface", to: "/attack-surface" }, { label: "Reputation", to: "/attack-surface?tab=reputation" }, { label: name }]} />;

  if (!data) {
    return (
      <div className="space-y-4">
        {back}
        {loading ? <p role="status" className="py-8 text-center text-sm text-ink-3">Loading…</p> : <ErrorNote error={error} />}
      </div>
    );
  }
  const { domain: d, findings } = data;
  const fix = toFix(d);
  const shown = findings.filter((f) => f.status !== "resolved");
  return (
    <div className="space-y-4">
      {back}
      <Link to="/attack-surface?tab=reputation" className="inline-block text-sm text-accent hover:underline">&larr; All domains</Link>
      <header className="flex flex-wrap items-center gap-4">
        <GradeBadge grade={d.grade} big />
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-ink">{d.domain}</h1>
          <p className="text-sm text-ink-2">
            {d.score === null ? "Not checked yet. Run a check from the Reputation tab." : `Score ${d.score} out of 100 · checked ${d.last_run_at ? fmtAgo(d.last_run_at) : "never"} · ${fix === 0 ? "nothing to fix" : `${plural(fix, "thing")} to fix`}`}
          </p>
        </div>
      </header>
      <ErrorNote error={error} />
      {SECTIONS.map(({ cat, title }) => {
        const rows = shown.filter((f) => f.category === cat);
        const ok = passed(cat, d, rows);
        if (cat === "blocklist" && rows.length === 0) return null;
        return (
          <Card key={cat} title={title}>
            <ul className="-my-2 divide-y divide-line">
              {rows.map((f) => (
                <li key={f.id} className="flex flex-wrap items-center gap-x-3 gap-y-2 py-2.5">
                  <SeverityBadge severity={f.severity} />
                  <span className="min-w-0 flex-1 basis-60 text-sm text-ink">{f.title}</span>
                  {f.status === "accepted" && <Tag tone="accent">Accepted</Tag>}
                  <Button onClick={() => setChosen(f)}>{f.status === "accepted" ? "Details" : buttonLabel(f)}<span className="sr-only">: {f.title}</span></Button>
                </li>
              ))}
              {ok.length > 0 && (
                <li className="flex items-start gap-2 py-2.5 text-sm text-ink-2">
                  <Check aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-good" />
                  <span><span className="font-medium text-ink">Passed:</span> {ok.join(", ")}</span>
                </li>
              )}
              {rows.length === 0 && ok.length === 0 && <li className="py-2.5 text-sm text-ink-3">{d.score === null ? "Not checked yet." : "Nothing to show."}</li>}
            </ul>
          </Card>
        );
      })}
      <FindingModal finding={chosen} onClose={() => setChosen(null)} onChanged={reload} />
    </div>
  );
}
