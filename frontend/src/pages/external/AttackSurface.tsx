import { Globe2, Play, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../auth/context";
import { CodeBlock } from "../../components/FixTabs";
import { NotAsvBanner, ResultBadge } from "../../components/external";
import { errMsg, inputCls } from "../../lib/externalUi";
import { Button, Card, Empty, ErrorNote, Modal, PageHeader, Stat, Table, Tag } from "../../components/ui";
import { externalApi, type ExtTarget } from "../../externalApi";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { useSort } from "../../lib/useSort";
import { PAGE_INFO } from "../../lib/pageInfo";

function TargetStatus({ t }: { t: ExtTarget }) {
  if (t.verified) return <Tag tone="good">Verified{t.verified_method ? ` (${t.verified_method})` : ""}</Tag>;
  if (t.approval_status === "requested") return <Tag tone="accent">Approval requested</Tag>;
  if (t.approval_status === "rejected") return <Tag tone="critical">Approval rejected</Tag>;
  if (t.kind !== "domain") return <Tag tone="warn">Scanned only if proven</Tag>;
  return <Tag tone="warn">Not verified: never scanned</Tag>;
}

function TargetRow({ t, admin, analyst, anyRunning, scanning, onChange }: { t: ExtTarget; admin: boolean; analyst: boolean; anyRunning: boolean; scanning: boolean; onChange: () => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [attest, setAttest] = useState("");
  const [consentOpen, setConsentOpen] = useState(false);
  const [consent, setConsent] = useState(false);

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
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-sm text-ink">{t.value}</span>
        <Tag>{t.kind === "cidr" ? "range" : t.kind}</Tag>
        <TargetStatus t={t} />
        {t.default_password_checks && <Tag tone="warn">Default-password checks on</Tag>}
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
        <Button onClick={() => setOpen(!open)}>{open ? "Hide details" : "Details"}</Button>
        {admin && (
          <Button variant="danger" disabled={busy} title="Remove this target" onClick={() => void run(() => externalApi.removeTarget(t.id))}>
            <Trash2 aria-hidden className="inline h-3.5 w-3.5" /> <span className="sr-only">Remove {t.value}</span>
          </Button>
        )}
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
                An address is scanned only when a verified domain resolves to it or it is a public IP of your connected cloud inventory. Otherwise a platform owner
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

export default function AttackSurface() {
  const { can } = useAuth();
  const admin = can("admin");
  const ov = useApi(externalApi.overview, [], 8000);
  const targets = useApi(externalApi.targets, []);
  const hosts = useApi(externalApi.hosts, [], 20000);
  const scans = useApi(externalApi.scans, [], 20000);
  const sortedHosts = useSort(
    hosts.data,
    {
      host: (h) => h.host,
      ip: (h) => (h.ip ?? "").split(".").map((n) => n.padStart(3, "0")).join("."),
      ports: (h) => h.ports.length,
      software: (h) => [...new Set(h.software.map((s) => `${s.product} ${s.version}`))].join(", "),
      tls: (h) => h.tls_summary,
      findings: (h) => h.findings,
    },
    { key: "host", dir: "asc" },
    { ports: "desc", findings: "desc" },
  );
  const [value, setValue] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [scope, setScope] = useState<string | null>(null);
  const o = ov.data;
  // a running scan of a single target names it (its record lists only that target)
  const runningScan = scans.data?.find((x) => x.status === "running");
  const runningTarget = o?.running && runningScan?.trigger === "target" ? (runningScan.targets[0] ?? null) : null;

  async function act(fn: () => Promise<unknown>) {
    setErr(null);
    try {
      await fn();
      ov.reload();
      targets.reload();
      scans.reload();
      hosts.reload();
    } catch (e) {
      setErr(errMsg(e));
    }
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Attack surface"
        info={PAGE_INFO.attackSurface}
        subtitle="What an attacker sees of your internet-facing systems, scanned from outside without exploiting anything."
        actions={
          <>
            <Link to="/attack-surface/reports" className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">Reports</Link>
            {can("analyst") && (
            <Button variant="primary" disabled={o?.running} title={o?.running ? "A scan is already running" : "Scan every verified target"} onClick={() => void act(externalApi.scanNow)}>
              <Play aria-hidden className="mr-1 inline h-3.5 w-3.5" />
              {o?.running ? "Scan running…" : "Scan all"}
            </Button>
            )}
          </>
        }
      />
      <NotAsvBanner />
      <ErrorNote error={err ?? ov.error ?? targets.error} />
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Hosts" value={o?.hosts ?? "-"} />
        <Stat label="Open ports" value={o?.open_ports ?? "-"} />
        <Stat label="New since last scan" value={o?.new_since_last_scan ?? "-"} />
        <Stat label="Open findings" value={o?.open_findings ?? "-"} sub={o ? `${o.failing_findings} would fail` : undefined} to="/attack-surface/findings" />
        <Stat label="Pre-ASV result" value={o ? <ResultBadge result={o.result} label={o.result_label} /> : "-"} to="/attack-surface/reports" />
      </div>
      <Card
        title="Targets"
        actions={<span className="text-xs text-ink-3">Up to {o?.limits.max_targets ?? 25} targets; ranges up to a /24. Unverified targets are never scanned.</span>}
      >
        {admin && (
          <form className="flex flex-wrap items-end gap-2 border-b border-line px-4 py-3" onSubmit={(e) => { e.preventDefault(); void act(async () => { await externalApi.addTarget(value); setValue(""); }); }}>
            <div className="min-w-[16rem] flex-1">
              <label htmlFor="ext-target" className="mb-1 block text-sm font-medium text-ink-2">Domain, public IPv4 address or CIDR</label>
              <input id="ext-target" className={inputCls} value={value} onChange={(e) => setValue(e.target.value)} placeholder="shop.example.com or 203.0.113.0/28" />
            </div>
            <Button type="submit" variant="primary" disabled={!value.trim()}><Plus aria-hidden className="mr-1 inline h-3.5 w-3.5" />Add target</Button>
          </form>
        )}
        {targets.data && targets.data.length === 0 ? (
          <Empty icon={Globe2} title="No targets yet">Add a domain you own, then verify it with a DNS record or a file.</Empty>
        ) : (
          <ul>{targets.data?.map((t) => <TargetRow key={t.id} t={t} admin={admin} analyst={can("analyst")} anyRunning={!!o?.running} scanning={runningTarget === t.value} onChange={() => { targets.reload(); ov.reload(); }} />)}</ul>
        )}
      </Card>
      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Scope declaration">
          <div className="space-y-2 p-4">
            <p className="text-sm text-ink-2">List your in-scope internet-facing systems. It appears in the report (Part 3c) and must be confirmed before a report can be generated.</p>
            <textarea aria-label="Scope declaration" rows={5} className={inputCls} disabled={!admin} value={scope ?? o?.scope.text ?? ""} onChange={(e) => setScope(e.target.value)} />
            {o?.scope.confirmed_at ? <p className="text-xs text-ink-3">Confirmed by {o.scope.confirmed_by} on {fmtTime(o.scope.confirmed_at)}.</p> : <p className="text-xs text-sev-high">Not confirmed yet.</p>}
            {admin && (
              <div className="flex gap-2">
                <Button disabled={scope === null} onClick={() => void act(async () => { await externalApi.setScope(scope ?? "", false); setScope(null); })}>Save draft</Button>
                <Button variant="primary" onClick={() => void act(async () => { await externalApi.setScope(scope ?? o?.scope.text ?? "", true); setScope(null); })}>Confirm scope</Button>
              </div>
            )}
          </div>
        </Card>
        <Card title="Schedule">
          <div className="space-y-2 p-4 text-sm">
            <label className="flex items-center gap-2">
              <input type="checkbox" disabled={!admin} checked={o?.schedule.enabled ?? false} onChange={(e) => void act(() => externalApi.setSchedule(e.target.checked, null))} />
              Scan automatically every{" "}
              <select aria-label="Scan interval" disabled={!admin} className="rounded border border-line bg-surface-2 px-2 py-1" value={String(o?.schedule.interval_hours ?? 168)}
                onChange={(e) => void act(() => externalApi.setSchedule(null, Number(e.target.value)))}>
                <option value="24">day</option><option value="168">week</option><option value="336">2 weeks</option><option value="720">30 days</option>
              </select>
            </label>
            <p className="text-ink-3">
              {o?.last_scan ? `Last scan ${fmtAgo(o.last_scan.started_at)} (${o.last_scan.status}).` : "No scan yet."}{" "}
              {o?.schedule.next_scan_at && o.schedule.enabled ? `Next: ${fmtTime(o.schedule.next_scan_at)}.` : ""}
            </p>
          </div>
        </Card>
      </div>
      <Card title="Hosts">
        <Table
          head={[{ label: "Host", sort: "host" }, { label: "IP", sort: "ip" }, { label: "Open ports", sort: "ports" }, { label: "Detected software", sort: "software" }, { label: "TLS", sort: "tls" }, { label: "Findings", sort: "findings", align: "right" }]}
          sort={sortedHosts.sort}
          onSort={sortedHosts.onSort}
          loading={hosts.loading}
          rowCount={hosts.data?.length ?? 0}
          empty={<Empty icon={Globe2} title="No hosts discovered yet">Verify a target and run a scan.</Empty>}
        >
          {sortedHosts.rows.map((h) => (
            <tr key={h.id}>
              <td className="px-3 py-2 font-mono text-xs">{h.host}</td>
              <td className="px-3 py-2 font-mono text-xs">{h.ip}</td>
              <td className="px-3 py-2 text-xs">{h.ports.map((p) => `${p.port}/${p.service}`).join(", ") || "-"}</td>
              <td className="px-3 py-2 text-xs">{[...new Set(h.software.map((s) => `${s.product} ${s.version}`))].join(", ") || "-"}</td>
              <td className="px-3 py-2 text-xs">{h.tls_summary ?? "-"}</td>
              <td className="px-3 py-2 text-right"><Link className="text-accent hover:underline" to={`/attack-surface/findings?host=${encodeURIComponent(h.host)}`}>{h.findings}</Link></td>
            </tr>
          ))}
        </Table>
      </Card>
      <Card title="Recent scans">
        <ul className="divide-y divide-line text-sm">
          {scans.data?.slice(0, 6).map((s) => (
            <li key={s.id} className="px-4 py-2">
              <span className="font-medium">{fmtTime(s.started_at)}</span> · {s.trigger} · {s.status} · {s.hosts} hosts, {s.open_ports} ports, {s.findings_open} open findings
              {s.skipped.length > 0 && <details className="mt-1 text-xs text-ink-3"><summary>{s.skipped.length} not scanned</summary>{s.skipped.slice(0, 20).map((x) => <div key={x.value}>{x.value}: {x.reason}</div>)}</details>}
              {s.message && <div className="text-xs text-ink-3">{s.message}</div>}
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
