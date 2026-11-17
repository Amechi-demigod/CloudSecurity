import { FileText } from "lucide-react";
import { useState } from "react";
import { useAuth } from "../../auth/context";
import { NotAsvBanner, ResultBadge } from "../../components/external";
import { errMsg } from "../../lib/externalUi";
import { Button, Card, Empty, ErrorNote, PageHeader, Table, Tag } from "../../components/ui";
import { externalApi, type ExtReportData } from "../../externalApi";
import { fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";

function ReportView({ r }: { r: ExtReportData }) {
  return (
    <div className="space-y-4">
      <Card title="Part 1. Scan information">
        <dl className="grid gap-2 p-4 text-sm sm:grid-cols-2">
          <div><dt className="text-xs uppercase text-ink-3">Customer</dt><dd>{r.customer.name}</dd></div>
          <div><dt className="text-xs uppercase text-ink-3">Scan</dt><dd>{r.scan ? fmtTime(r.scan.started_at) : "-"}</dd></div>
          <div><dt className="text-xs uppercase text-ink-3">Targets</dt><dd>{r.scan?.targets.join(", ") || "-"}</dd></div>
        </dl>
      </Card>
      <Card title="Part 2. Component compliance summary">
        <Table head={["Host / IP", "Vulnerabilities", "Status"]} rowCount={r.components.length} empty={<Empty title="No components" />}>
          {r.components.map((c) => (
            <tr key={c.host}><td className="px-3 py-2 font-mono text-xs">{c.host}</td><td className="px-3 py-2 text-sm">{c.findings}</td>
              <td className="px-3 py-2"><Tag tone={c.result === "Pass" ? "good" : "critical"}>{c.result}</Tag></td></tr>
          ))}
        </Table>
      </Card>
      <Card title="Part 3a. Vulnerabilities noted for each component">
        <Table head={["Component", "Vulnerability", "Severity", "CVSS", "Status", "Exceptions / compensating controls"]} rowCount={r.vulnerabilities.length} empty={<Empty title="None noted" />}>
          {r.vulnerabilities.map((v) => (
            <tr key={v.ref}><td className="px-3 py-2 font-mono text-xs">{v.host}{v.port ? `:${v.port}` : ""}</td><td className="px-3 py-2 text-sm">{v.ref} {v.title}</td>
              <td className="px-3 py-2 text-xs capitalize">{v.severity}</td><td className="px-3 py-2 text-xs">{v.cvss.toFixed(1)}</td>
              <td className="px-3 py-2"><Tag tone={v.result === "Pass" ? "good" : "critical"}>{v.result}</Tag></td>
              <td className="px-3 py-2 text-xs text-ink-2">{v.exception ? `${v.exception.kind.replace("_", " ")}: ${v.exception.reason} (${v.exception.reviewed_by}: ${v.exception.note})` : v.reason ?? ""}</td></tr>
          ))}
        </Table>
      </Card>
      <Card title="Part 3b. Special notes">
        <div className="space-y-2 p-4 text-sm text-ink-2">
          {r.special_notes.length === 0 && <p>None noted.</p>}
          {r.special_notes.map((n) => <div key={n.key}><strong className="text-ink">{n.label}</strong><ul className="list-disc pl-6">{n.items.map((i, k) => <li key={k}>{i.host}{i.port ? `:${i.port}` : ""}: {i.item}</li>)}</ul></div>)}
        </div>
      </Card>
      <Card title="Part 3c. Scope declared by the customer">
        <p className="whitespace-pre-line p-4 text-sm text-ink-2">{r.scope.text || "Not declared yet."}</p>
        {r.scope.confirmed_by && <p className="px-4 pb-3 text-xs text-ink-3">Confirmed by {r.scope.confirmed_by}.</p>}
      </Card>
      <Card title="How the result is decided">
        <Table head={["Rule", "Result"]}>{r.rules.map((x) => <tr key={x.rule}><td className="px-3 py-2 text-sm">{x.rule}</td><td className="px-3 py-2 text-sm">{x.result}</td></tr>)}</Table>
      </Card>
    </div>
  );
}

export default function ExternalReports() {
  const { can } = useAuth();
  const preview = useApi(externalApi.preview, []);
  const reports = useApi(externalApi.reports, []);
  const [err, setErr] = useState<string | null>(null);
  const [viewing, setViewing] = useState<ExtReportData | null>(null);
  const p = preview.data;

  async function generate() {
    setErr(null);
    try {
      await externalApi.generateReport();
      reports.reload();
    } catch (e) {
      setErr(errMsg(e));
    }
  }
  return (
    <div className="space-y-4">
      <PageHeader title="Pre-ASV reports" subtitle="Your scan results in the layout of the PCI ASV scan report. Indicative only." actions={can("analyst") ? <Button variant="primary" onClick={() => void generate()}>Generate pre-ASV report</Button> : undefined} />
      <NotAsvBanner />
      <ErrorNote error={err ?? preview.error} />
      <Card title="Latest result">
        <div className="flex flex-wrap items-center gap-3 p-4">
          <ResultBadge result={p?.result ?? null} label={p?.result_label} />
          <span className="text-sm text-ink-2">{p?.scan ? `Based on the scan of ${fmtTime(p.scan.started_at)}.` : "Run a scan first."}</span>
          {!p?.scope.confirmed_by && <span className="text-sm text-sev-high">Confirm the scope declaration on Attack surface before generating a report.</span>}
        </div>
      </Card>
      <Card title="History">
        <Table head={["Generated", "By", "Result", "Download"]} loading={reports.loading} rowCount={reports.data?.length ?? 0} empty={<Empty icon={FileText} title="No reports yet">Generate the first pre-ASV report above.</Empty>}>
          {reports.data?.map((r) => (
            <tr key={r.id}>
              <td className="px-3 py-2 text-sm">{fmtTime(r.generated_at)}</td><td className="px-3 py-2 text-sm">{r.generated_by}</td>
              <td className="px-3 py-2"><ResultBadge result={r.result} label={r.result_label} /></td>
              <td className="space-x-3 px-3 py-2 text-sm">
                <a className="text-accent hover:underline" href={externalApi.reportPdfUrl(r.id)}>PDF</a>
                <button type="button" className="text-accent hover:underline" onClick={() => void externalApi.report(r.id).then(setViewing)}>View</button>
              </td>
            </tr>
          ))}
        </Table>
      </Card>
      {viewing && <div><div className="mb-2 flex items-center justify-between"><h2 className="text-lg font-semibold">Report of {fmtTime(viewing.generated_at)}</h2><Button onClick={() => setViewing(null)}>Close</Button></div><ReportView r={viewing} /></div>}
      {!viewing && p && p.scan && <div><h2 className="mb-2 text-lg font-semibold">Current view</h2><ReportView r={p} /></div>}
    </div>
  );
}
