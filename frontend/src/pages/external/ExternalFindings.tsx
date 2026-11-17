import { ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { NotAsvBanner, StatusTag } from "../../components/external";
import { Card, Empty, ErrorNote, PageHeader, Select, SeverityBadge, Table, Tag } from "../../components/ui";
import { externalApi } from "../../externalApi";
import { fmtAgo } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { useSortState } from "../../lib/useSort";
import { useUrlState } from "../../lib/useUrlState";

export default function ExternalFindings() {
  const [status, setStatus] = useUrlState("status", "open");
  const [severity, setSeverity] = useUrlState("severity");
  const [host] = useUrlState("host");
  // The server sorts the whole result (the list is capped), so the sort goes to the API.
  const sorted = useSortState(["ref", "severity", "title", "host", "cvss", "pre_asv", "status", "fix_by"], { key: "severity", dir: "desc" }, { severity: "desc", cvss: "desc", fix_by: "asc" });
  const { data, error, loading } = useApi(
    () => externalApi.findings({ status: status || undefined, severity: severity || undefined, host: host || undefined, sort: sorted.sort.key, dir: sorted.sort.dir }),
    [status, severity, host, sorted.sort.key, sorted.sort.dir],
  );
  return (
    <div className="space-y-4">
      <PageHeader title="Attack surface findings" subtitle="Weaknesses an attacker could see from the internet. Findings close by themselves when a later scan no longer sees them." />
      <NotAsvBanner />
      <ErrorNote error={error} />
      <div className="flex flex-wrap items-center gap-3">
        <Select label="Status" value={status} onChange={setStatus} options={[{ value: "", label: "All" }, "open", "disputed", "accepted", "resolved"]} />
        <Select label="Severity" value={severity} onChange={setSeverity} options={["", "critical", "high", "medium", "low", "info"]} />
        {host && <Tag>Host: {host}</Tag>}
        <span className="text-xs text-ink-3">{data ? `${data.length} findings` : ""}</span>
      </div>
      <Card>
        <Table
          head={[
            { label: "ID", sort: "ref" },
            { label: "Severity", sort: "severity" },
            { label: "Finding", sort: "title" },
            { label: "Host", sort: "host" },
            { label: "CVSS", sort: "cvss" },
            { label: "Pre-ASV", sort: "pre_asv" },
            { label: "Status", sort: "status" },
            { label: "Fix by", sort: "fix_by" },
          ]}
          sort={sorted.sort}
          onSort={sorted.onSort}
          loading={loading}
          rowCount={data?.length ?? 0}
          empty={<Empty icon={ShieldCheck} title="No findings">Nothing matches. Run a scan from Attack surface to re-check.</Empty>}
        >
          {data?.map((f) => (
            <tr key={f.id} className="hover:bg-surface-2">
              <td className="px-3 py-2 font-mono text-xs"><Link className="text-accent hover:underline" to={`/attack-surface/findings/${f.id}`}>{f.ref}</Link></td>
              <td className="px-3 py-2"><SeverityBadge severity={f.severity} /></td>
              <td className="px-3 py-2 text-sm">{f.title}</td>
              <td className="px-3 py-2 font-mono text-xs">{f.host}{f.port ? `:${f.port}` : ""}</td>
              <td className="px-3 py-2 text-xs">{f.cvss ? f.cvss.toFixed(1) : "-"}</td>
              <td className="px-3 py-2 text-xs">{f.status === "resolved" ? "-" : f.exempt ? "Exception" : f.fails ? (f.auto_fail ? "Automatic fail" : "Fail") : "Pass"}</td>
              <td className="px-3 py-2"><StatusTag status={f.status} /></td>
              <td className="px-3 py-2 text-xs text-ink-2">{f.fix_due ? (f.overdue_days ? `overdue ${f.overdue_days} d` : fmtAgo(f.fix_due).replace(" ago", "")) : "-"}</td>
            </tr>
          ))}
        </Table>
      </Card>
    </div>
  );
}
