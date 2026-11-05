// Connectors & scans -> Collectors: dedicated directory collectors (a separate program on a Windows host,
// not an endpoint agent): list, add (pre-configured installer, gMSA setup), on-collector Test, rename, revoke.
import { AlertTriangle, Download, Server } from "lucide-react";
import { useState } from "react";
import {
  DC_WARNING,
  collectorApi,
  type CollectorDiagnostics,
  type DedicatedCollector,
  type DiagStep,
  type GmsaScripts,
} from "../directoryApi";
import { useDiagnostics } from "../lib/collectors";
import { errMsg } from "../lib/directory";
import { fmtAgo, fmtTime } from "../lib/format";
import { useApi } from "../lib/useApi";
import { CodeBox } from "./directoryShared";
import { Button, Card, Empty, ErrorNote, Field, Modal, Tag } from "./ui";

const RUN_AS_LABEL: Record<DedicatedCollector["run_as_kind"], string> = {
  computer_account: "computer account",
  gmsa: "gMSA",
  user: "user account",
  unknown: "unknown",
};

const STEP_STYLE: Record<DiagStep["status"], { cls: string; label: string }> = {
  pass: { cls: "border-good/60 text-good", label: "PASS" },
  warn: { cls: "border-sev-medium/60 text-sev-medium", label: "WARN" },
  fail: { cls: "border-sev-critical/60 text-sev-critical", label: "FAIL" },
  skip: { cls: "border-line text-ink-3", label: "SKIP" },
};

export function DcWarning({ name, compact = false }: { name?: string; compact?: boolean }) {
  return (
    <div role="alert" className="flex gap-2 rounded border border-sev-high/60 bg-sev-high/10 px-3 py-2 text-sm text-ink">
      <AlertTriangle aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-sev-high" />
      <span>
        <strong className="text-sev-high">{name ? `${name} runs on a domain controller.` : "This host is a domain controller."}</strong>{" "}
        {compact ? "We recommend a member server." : DC_WARNING}
      </span>
    </div>
  );
}

/** PASS / FAIL per step of the on-collector Test. */
export function DiagnosticsResult({ d }: { d: CollectorDiagnostics | Record<string, never> | null | undefined }) {
  if (!d || !("status" in d)) return null;
  if (d.status === "queued")
    return <p className="text-sm text-ink-2">Test queued: the collector picks it up within about a minute…</p>;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Tag tone={d.status === "succeeded" ? "good" : "critical"}>{d.status === "succeeded" ? "All checks passed" : "Checks failed"}</Tag>
        {d.transport && (
          <span className="text-ink-2">
            Transport: {d.transport === "sealed" ? "Kerberos signing & sealing (389)" : d.transport === "starttls" ? "StartTLS" : "LDAPS"}
          </span>
        )}
        {d.transport === "sealed" && <span className="text-ink-2">· signed+sealed: {d.signed_sealed ? "yes" : "no"}</span>}
        {d.identity && <span className="text-ink-3">· as {d.identity}</span>}
        <span className="text-xs text-ink-3">· {fmtTime(d.at)}</span>
      </div>
      <ol className="space-y-1" aria-label="Test steps">
        {d.steps.map((s) => (
          <li key={s.id} className="flex items-start gap-2 text-sm">
            <span className={`mt-0.5 inline-block w-12 shrink-0 rounded border px-1 text-center text-[11px] font-semibold ${STEP_STYLE[s.status].cls}`}>
              {STEP_STYLE[s.status].label}
            </span>
            <span className="min-w-0">
              <span className="font-medium text-ink">{s.label}</span>
              {s.detail && <span className="block break-words text-xs text-ink-3">{s.detail}</span>}
            </span>
          </li>
        ))}
      </ol>
    </div>
  );
}

function GmsaSetup({ domain }: { domain: string }) {
  const [gmsa, setGmsa] = useState("svc-collector");
  const [hosts, setHosts] = useState("COLLECTOR01");
  const scripts = useApi(() => collectorApi.setupScripts({ domain, gmsa, hosts }), [domain, gmsa, hosts]);
  const s: GmsaScripts | null = scripts.data;
  return (
    <div className="space-y-3">
      <p className="text-sm text-ink-2">
        <strong>Recommended:</strong> run the collector as a group Managed Service Account. Windows rotates its password automatically, nobody
        knows it, and only the collector computers can use it. The Kerberos bind is the same as with the computer account.
      </p>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Field label="gMSA name" id="gmsa-name" value={gmsa} maxLength={15} onChange={(e) => setGmsa(e.target.value)} hint="15 characters at most" />
        <Field label="Collector computers" id="gmsa-hosts" value={hosts} onChange={(e) => setHosts(e.target.value)} hint="Computer names, space separated" />
      </div>
      {s && (
        <>
          <h4 className="text-[13px] font-semibold text-ink">1 · KDS root key (once per forest)</h4>
          <p className="text-xs text-ink-3">
            Needs Enterprise Admins (or Domain Admins in the forest root). In production a new key is only usable after 10 hours (replication); do
            not backdate it outside a lab.
          </p>
          <CodeBox text={s.kds_root_key} />
          <h4 className="text-[13px] font-semibold text-ink">2 · Create the gMSA</h4>
          <CodeBox text={s.create_gmsa} />
          <h4 className="text-[13px] font-semibold text-ink">3 · Hardened OUs only: grant read</h4>
          <CodeBox text={s.grant_read} />
          <h4 className="text-[13px] font-semibold text-ink">4 · On each collector: install and test it</h4>
          <CodeBox text={s.install_gmsa} />
          <h4 className="text-[13px] font-semibold text-ink">5 · Run the service as the gMSA</h4>
          <CodeBox text={s.service_logon} note='Or install with -Gmsa. The installer grants "Log on as a service".' />
        </>
      )}
    </div>
  );
}

/** Add a collector: pre-configured installer (silent-installable), gMSA setup scripts, manual token. */
function AddCollector({ open, onClose, domain }: { open: boolean; onClose: () => void; domain: string }) {
  const [tab, setTab] = useState<"installer" | "gmsa" | "precheck">("installer");
  const [name, setName] = useState("Collector 1");
  const [arch, setArch] = useState<"amd64" | "arm64">("amd64");
  const [gmsa, setGmsa] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const info = useApi(collectorApi.installerInfo, []);
  const scripts = useApi(() => collectorApi.setupScripts({ domain, gmsa: "", hosts: "" }), [domain]);
  const avail = info.data?.arches[arch];

  async function download() {
    setBusy(true);
    setErr(null);
    try {
      const f = await collectorApi.downloadInstaller({ name: name.trim() || "collector", arch, gmsa: gmsa.trim() });
      const url = URL.createObjectURL(f.blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = f.filename;
      a.click();
      URL.revokeObjectURL(url);
      setDone(f.filename);
    } catch (ex) {
      setErr(errMsg(ex));
    } finally {
      setBusy(false);
    }
  }

  const tabCls = (t: string) =>
    `px-3 py-1 text-sm ${tab === t ? "bg-accent/15 font-semibold text-accent" : "text-ink-2 hover:bg-surface-2"}`;
  return (
    <Modal size="lg" open={open} onClose={onClose} title={`Add a collector${info.data ? ` (${info.data.service_display_name})` : ""}`}>
      <div className="space-y-3">
        <div className="inline-flex overflow-hidden rounded border border-line" role="tablist">
          <button type="button" role="tab" aria-selected={tab === "installer"} className={tabCls("installer")} onClick={() => setTab("installer")}>
            Installer
          </button>
          <button type="button" role="tab" aria-selected={tab === "gmsa"} className={tabCls("gmsa")} onClick={() => setTab("gmsa")}>
            gMSA (recommended)
          </button>
          <button type="button" role="tab" aria-selected={tab === "precheck"} className={tabCls("precheck")} onClick={() => setTab("precheck")}>
            Manual pre-check
          </button>
        </div>
        {tab === "installer" && (
          <div className="space-y-3">
            <p className="text-sm text-ink-2">
              Install it on a <strong>domain-joined member server</strong> that stays on (two collectors give failover). It only reads the directory
              and connects outbound: HTTPS to this server, LDAP 389 / Kerberos 88 to your domain controllers. Nothing listens.
            </p>
            <Field label="Name" id="col-name" value={name} maxLength={128} onChange={(e) => setName(e.target.value)} />
            <div className="flex flex-wrap gap-4 text-sm">
              {(["amd64", "arm64"] as const).map((a) => (
                <label key={a} className="flex items-center gap-2">
                  <input type="radio" checked={arch === a} onChange={() => setArch(a)} /> Windows {a === "amd64" ? "x64" : "Arm64"}
                </label>
              ))}
            </div>
            <Field
              label="Run as gMSA (optional)"
              id="col-gmsa"
              placeholder="CORP\svc-collector$"
              spellCheck={false}
              value={gmsa}
              onChange={(e) => setGmsa(e.target.value)}
              hint="Empty: LocalSystem, i.e. the computer account. See the gMSA tab to create one."
            />
            {avail && !avail.available && <ErrorNote error={avail.reason ?? "not available"} />}
            <ErrorNote error={err} />
            <Button variant="primary" onClick={download} disabled={busy || !avail?.available}>
              <Download aria-hidden className="mr-1 inline h-4 w-4" />
              {busy ? "Preparing…" : `Download installer${avail?.version ? ` (${avail.version})` : ""}`}
            </Button>
            {done && (
              <p className="text-sm text-good" role="status">
                {done} downloaded. It contains a single-use token valid for 24 hours: delete the folder after installing.
              </p>
            )}
            <CodeBox
              text={[
                "# On the collector host, in an elevated PowerShell, from the unzipped folder:",
                ".\\Install-Collector.ps1                 # interactive (warns on a domain controller)",
                ".\\Install-Collector.ps1 -Quiet          # silent (software deployment tools)",
                ".\\Install-Collector.ps1 -Quiet -Gmsa 'CORP\\svc-collector$'",
                "# Uninstall (removes the service, program files, credential and logs):",
                ".\\Uninstall-Collector.ps1",
              ].join("\n")}
            />
          </div>
        )}
        {tab === "gmsa" && <GmsaSetup domain={domain} />}
        {tab === "precheck" && (
          <div className="space-y-2">
            <p className="text-sm text-ink-2">
              Optional. The console&apos;s <strong>Test</strong> runs the same checks on the collector itself; this script is for checking by hand.
            </p>
            {scripts.data && <CodeBox text={scripts.data.precheck} note="Read-only: DNS, ports, a signed+sealed Kerberos bind and a 5-object read." />}
          </div>
        )}
      </div>
    </Modal>
  );
}

function CollectorRow({ c, isAdmin, onChanged }: { c: DedicatedCollector; isAdmin: boolean; onChanged: () => void }) {
  const [cmd, setCmd] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const live = useDiagnostics(c.id, cmd);
  const diag = live ?? (c.diagnostics as CollectorDiagnostics);
  const [showDiag, setShowDiag] = useState(false);

  async function act(fn: () => Promise<unknown>) {
    setErr(null);
    try {
      await fn();
      onChanged();
    } catch (ex) {
      setErr(errMsg(ex));
    }
  }
  return (
    <li className="space-y-2 rounded border border-line p-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Server aria-hidden className="h-4 w-4 text-ink-3" />
            <span className="font-medium text-ink">{c.name}</span>
            <Tag tone={c.state === "online" ? "good" : c.state === "revoked" ? "critical" : "warn"}>{c.state}</Tag>
            {c.is_domain_controller && <Tag tone="warn">domain controller</Tag>}
            {c.version && <span className="text-xs text-ink-3">v{c.version}</span>}
          </div>
          <div className="mt-0.5 text-xs text-ink-3">
            {c.dns_hostname || c.hostname || "not enrolled yet"} {c.domain && `· ${c.domain}`} · runs as{" "}
            <span className="font-mono text-ink-2">{c.run_as || "?"}</span> ({RUN_AS_LABEL[c.run_as_kind]}) · last seen{" "}
            {c.last_seen_at ? fmtAgo(c.last_seen_at) : "never"}
            {c.sources.length > 0 && ` · used by ${c.sources.map((s) => s.name).join(", ")}`}
          </div>
        </div>
        {isAdmin && c.status === "active" && (
          <div className="flex flex-wrap gap-2">
            <Button
              onClick={() =>
                act(async () => {
                  const r = await collectorApi.test(c.id, c.sources[0]?.id ?? null);
                  setCmd(r.command_id);
                  setShowDiag(true);
                })
              }
            >
              Test
            </Button>
            <Button onClick={() => act(async () => {
              const n = window.prompt("New name", c.name);
              if (n && n.trim()) await collectorApi.rename(c.id, n.trim());
            })}>Rename</Button>
            <Button variant="danger" onClick={() => window.confirm(`Revoke ${c.name}? It can no longer reach this server.`) && act(() => collectorApi.revoke(c.id))}>
              Revoke
            </Button>
          </div>
        )}
        {isAdmin && c.status === "revoked" && (
          <Button variant="danger" onClick={() => act(() => collectorApi.remove(c.id))}>
            Delete
          </Button>
        )}
      </div>
      {c.is_domain_controller && <DcWarning name={c.name} />}
      <ErrorNote error={err} />
      {"status" in (diag ?? {}) && (
        <div>
          <button type="button" className="text-xs text-accent hover:underline" onClick={() => setShowDiag(!showDiag)}>
            {showDiag ? "Hide" : "Show"} last test ({diag.status})
          </button>
          {showDiag && (
            <div className="mt-2">
              <DiagnosticsResult d={diag} />
            </div>
          )}
        </div>
      )}
    </li>
  );
}

export function CollectorsSection({ isAdmin, domain = "" }: { isAdmin: boolean; domain?: string }) {
  const list = useApi(collectorApi.list, [], 30000);
  const [adding, setAdding] = useState(false);
  return (
    <Card
      title={
        <span id="collectors" className="scroll-mt-20">
          Collectors
        </span>
      }
      actions={isAdmin ? <Button variant="primary" onClick={() => setAdding(true)}>Add collector</Button> : undefined}
    >
      <p className="mb-3 text-sm text-ink-2">
        Dedicated programs that read Active Directory from inside your network. They are not endpoint agents: they run no commands, scripts or
        remote sessions, and do not appear under Devices or IT assets.
      </p>
      <ErrorNote error={list.error} />
      {list.data && list.data.length === 0 && (
        <Empty icon={Server} title="No collectors yet">
          Add one on a domain-joined member server; Active Directory sources use it to read the directory.
        </Empty>
      )}
      <ul className="space-y-2">
        {(list.data ?? []).map((c) => (
          <CollectorRow key={c.id} c={c} isAdmin={isAdmin} onChanged={list.reload} />
        ))}
      </ul>
      <AddCollector open={adding} onClose={() => { setAdding(false); list.reload(); }} domain={domain} />
    </Card>
  );
}
