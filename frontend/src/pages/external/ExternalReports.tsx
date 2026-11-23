import { FileText } from "lucide-react";
import { useState } from "react";
import { useAuth } from "../../auth/context";
import { NotAsvBanner, ResultBadge, ScopeModal } from "../../components/external";
import { errMsg } from "../../lib/externalUi";
import { Button, Card, Empty, ErrorNote, PageHeader, Table, Tag } from "../../components/ui";
import { externalApi, type ExtReportData } from "../../externalApi";
import { fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { SEV_RANK, rankOf, ts, useSort } from "../../lib/useSort";

const RESULT_RANK = rankOf(["fail", "pass"]); // failing first

function ReportView({ r }: { r: ExtReportData }) {
  const comps = useSort(
    r.components,
    { host: (c) => c.host, findings: (c) => c.findings, status: (c) => RESULT_RANK(c.result) },
    { key: "status", dir: "asc" },
    { findings: "desc" },
    "csort",
  );
  const vulns = useSort(
    r.vulnerabilities,
    {
      component: (v) => `${v.host}${v.port ? `:${v.port}` : ""}`,
      vulnerability: (v) => `${v.ref} ${v.title}`,
      severity: (v) => SEV_RANK[v.severity] ?? 0,
      cvss: (v) => v.cvss,
      status: (v) => RESULT_RANK(v.result),
      exceptions: (v) => (v.exception ? `${v.exception.kind}: ${v.exception.reason}` : v.reason),
    },
    { key: "severity", dir: "desc" },
    { severity: "desc", cvss: "desc" },
    "vsort",
  );
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
        <Table tableId="external-reports-1" head={[{ label: "Host / IP", sort: "host" }, { label: "Vulnerabilities", sort: "findings" }, { label: "Status", sort: "status" }]} sort={comps.sort} onSort={comps.onSort} rowCount={r.components.length} empty={<Empty title="No components" />}>
          {comps.rows.map((c) => (
            <tr key={c.host}><td className="px-3 py-2 font-mono text-xs">{c.host}</td><td className="px-3 py-2 text-sm">{c.findings}</td>
              <td className="px-3 py-2"><Tag tone={c.result === "Pass" ? "good" : "critical"}>{c.result}</Tag></td></tr>
          ))}
        </Table>
      </Card>
      <Card title="Part 3a. Vulnerabilities noted for each component">
        <Table tableId="external-reports-2" head={[{ label: "Component", sort: "component" }, { label: "Vulnerability", sort: "vulnerability" }, { label: "Severity", sort: "severity" }, { label: "CVSS", sort: "cvss" }, { label: "Status", sort: "status" }, { label: "Exceptions / compensating controls", sort: "exceptions" }]} sort={vulns.sort} onSort={vulns.onSort} rowCount={r.vulnerabilities.length} empty={<Empty title="None noted" />}>
          {vulns.rows.map((v) => (
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
  const [scoping, setScoping] = useState(false);
  const [viewing, setViewing] = useState<ExtReportData | null>(null);
  const p = preview.data;
  const history = useSort(
    reports.data,
    { generated: (r) => ts(r.generated_at), by: (r) => r.generated_by, result: (r) => RESULT_RANK(r.result) },
    { key: "generated", dir: "desc" },
    { generated: "desc" },
    "hsort",
  );

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
      <PageHeader title="Reports" subtitle="Your scan results in the layout of a PCI ASV scan report, to prepare for the real one." actions={can("analyst") ? <Button variant="primary" onClick={() => void generate()}>Create report</Button> : undefined} />
      <NotAsvBanner />
      <ErrorNote error={err ?? preview.error} />
      <Card title="Latest result">
        <div className="flex flex-wrap items-center gap-3 p-4">
          <ResultBadge result={p?.result ?? null} />
          <span className="text-sm text-ink-2">{p?.scan ? `Based on the scan of ${fmtTime(p.scan.started_at)}.` : "Run a scan first."}</span>
          {p && !p.scope.confirmed_by && (
            <span className="text-sm text-sev-high">
              Confirm what's in scope before your first report.{" "}
              <button type="button" className="text-accent underline" onClick={() => setScoping(true)}>Confirm</button>
            </span>
          )}
        </div>
      </Card>
      <Card title="History">
        <Table tableId="external-reports-3" head={[{ label: "Generated", sort: "generated" }, { label: "By", sort: "by" }, { label: "Result", sort: "result" }, "Download"]} sort={history.sort} onSort={history.onSort} loading={reports.loading} rowCount={reports.data?.length ?? 0} empty={<Empty icon={FileText} title="No reports yet">Create the first report above.</Empty>}>
          {history.rows.map((r) => (
            <tr key={r.id}>
              <td className="px-3 py-2 text-sm">{fmtTime(r.generated_at)}</td><td className="px-3 py-2 text-sm">{r.generated_by}</td>
              <td className="px-3 py-2"><ResultBadge result={r.result} /></td>
              <td className="space-x-3 px-3 py-2 text-sm">
                <a className="text-accent hover:underline" href={externalApi.reportPdfUrl(r.id)}>PDF</a>
                <button type="button" className="text-accent hover:underline" onClick={() => void externalApi.report(r.id).then(setViewing)}>View</button>
              </td>
            </tr>
          ))}
        </Table>
      </Card>
      {p && <ScopeModal open={scoping} onClose={() => setScoping(false)} scope={p.scope} canEdit={can("admin")} onSaved={preview.reload} />}
      {viewing && <div><div className="mb-2 flex items-center justify-between"><h2 className="text-lg font-semibold">Report of {fmtTime(viewing.generated_at)}</h2><Button onClick={() => setViewing(null)}>Close</Button></div><ReportView r={viewing} /></div>}
      {!viewing && p && p.scan && <div><h2 className="mb-2 text-lg font-semibold">Current view</h2><ReportView r={p} /></div>}
    </div>
  );
}
