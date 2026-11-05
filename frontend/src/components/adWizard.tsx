// Connectors & scans -> Directories -> Add directory -> Active Directory: the guided setup.
// 1 Domain; 2 Collector: pick healthy dedicated collectors (first = primary, others failover), or download the
// pre-configured MSI and wait until the new collector enrolls (it is then selected automatically); 3 Test: the
// collector's diagnostics on the settings before anything is saved; 4 Save: the source is created and its first
// sync starts. Editing a source, service accounts and other options stay in the full form (DirectoryForm).
import { Check, Loader2, Server } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { collectorApi, directoryApi, type AdConfig, type DedicatedCollector, type DirectorySecurity, type DirectorySource } from "../directoryApi";
import { useDiagnostics } from "../lib/collectors";
import { RUN_COLOR, RUN_TEXT, errMsg, inputCls, useRun } from "../lib/directory";
import { fmtAgo } from "../lib/format";
import { useApi } from "../lib/useApi";
import { CollectorInstaller, DcWarning, DiagnosticsResult, GmsaSetup } from "./collectors";
import { Button, ErrorNote, Field, Tag } from "./ui";

const STEPS = ["Domain", "Collector", "Test", "Save"] as const;
const DOMAIN_RE = /^(?=.{3,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const RUN_AS: Record<DedicatedCollector["run_as_kind"], string> = {
  computer_account: "computer account, LocalSystem",
  gmsa: "gMSA",
  user: "user account",
  unknown: "unknown identity",
};
const TRANSPORT: Record<DirectorySecurity, { label: string; port: number }> = {
  sealed: { label: "Kerberos signing & sealing (389, no DC certificate needed)", port: 389 },
  ldaps: { label: "LDAPS (636) - needs a DC certificate the collector trusts", port: 636 },
  starttls: { label: "StartTLS (389) - needs a DC certificate", port: 389 },
};

const split = (s: string) =>
  s
    .split(/[\n,;]+/)
    .map((x) => x.trim())
    .filter(Boolean);

function Stepper({ step }: { step: number }) {
  return (
    <ol
      aria-label="Active Directory setup steps"
      // -top-5: flush with the top of the page's scroll area (main has py-5), so nothing shows above it.
      className="sticky -top-5 z-10 -mx-1 mb-4 flex flex-wrap items-center gap-x-2.5 gap-y-1.5 border-b border-line bg-surface-1 px-1 pb-3 pt-2"
    >
      {STEPS.map((t, i) => (
        <li key={t} aria-current={i === step ? "step" : undefined} className="flex items-center gap-2 text-sm">
          {i > 0 && <span aria-hidden className="text-ink-3">→</span>}
          <span
            className={`grid h-[22px] w-[22px] place-items-center rounded-full text-xs font-semibold ${
              i < step ? "bg-good/15 text-good" : i === step ? "bg-accent text-white" : "bg-surface-2 text-ink-3"
            }`}
          >
            {i < step ? <Check aria-hidden className="h-3.5 w-3.5" /> : i + 1}
          </span>
          <span className={i === step ? "font-semibold text-ink" : "text-ink-2"}>{t}</span>
        </li>
      ))}
    </ol>
  );
}

/** A collector that just came online (or was picked): host, identity, version, DC warning. */
function CollectorFacts({ c }: { c: DedicatedCollector }) {
  return (
    <div className="space-y-2 rounded border border-good/50 bg-good/5 px-3 py-2.5 text-sm" role="status">
      <div className="flex flex-wrap items-center gap-2">
        <Check aria-hidden className="h-4 w-4 text-good" />
        <strong className="text-ink">{c.name}</strong>
        <span className="text-ink-2">is online and selected</span>
        {c.version && <span className="text-xs text-ink-3">v{c.version}</span>}
      </div>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5 text-xs">
        <dt className="text-ink-3">Host</dt>
        <dd className="break-all text-ink-2">{c.dns_hostname || c.hostname}</dd>
        <dt className="text-ink-3">Domain</dt>
        <dd className="text-ink-2">{c.domain || "not domain-joined"}</dd>
        <dt className="text-ink-3">Runs as</dt>
        <dd className="text-ink-2">
          <span className="font-mono">{c.run_as || "?"}</span> ({RUN_AS[c.run_as_kind]})
        </dd>
      </dl>
      {c.is_domain_controller && <DcWarning name={c.name} />}
    </div>
  );
}

function Picker({ collectors, selected, onChange }: { collectors: DedicatedCollector[]; selected: string[]; onChange: (ids: string[]) => void }) {
  return (
    <ul className="space-y-1 rounded border border-line p-1.5" aria-label="Collectors">
      {collectors.map((c) => {
        const idx = selected.indexOf(c.id);
        return (
          <li key={c.id}>
            <label
              className={`flex flex-wrap items-center gap-2 rounded px-2 py-1.5 text-sm ${c.healthy ? "cursor-pointer hover:bg-surface-2" : "opacity-60"}`}
            >
              <input
                type="checkbox"
                disabled={!c.healthy && idx < 0}
                checked={idx >= 0}
                onChange={(e) => onChange(e.target.checked ? [...selected, c.id] : selected.filter((x) => x !== c.id))}
              />
              <span aria-hidden className={`inline-block h-2 w-2 rounded-full ${c.healthy ? "bg-good" : "bg-ink-3"}`} />
              <span className="font-medium text-ink">{c.name}</span>
              <span className="text-xs text-ink-3">
                {c.dns_hostname || c.hostname}
                {c.domain ? ` · ${c.domain}` : ""} · {c.run_as || "?"} ·{" "}
                {c.healthy ? "online" : c.last_seen_at ? `offline, seen ${fmtAgo(c.last_seen_at)}` : "never seen"}
              </span>
              {idx >= 0 && <Tag tone="accent">{idx === 0 ? "primary" : `failover ${idx}`}</Tag>}
              {c.is_domain_controller && <Tag tone="warn">domain controller</Tag>}
            </label>
          </li>
        );
      })}
    </ul>
  );
}

export function AdWizard({ onDone, onCancel }: { onDone: (s: DirectorySource) => void; onCancel: () => void }) {
  const [step, setStep] = useState(0);
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [servers, setServers] = useState("");
  const [baseDns, setBaseDns] = useState("");
  const [security, setSecurity] = useState<DirectorySecurity>("sealed");
  const [port, setPort] = useState(389);
  const [err, setErr] = useState<string | null>(null);
  const top = useRef<HTMLDivElement>(null);

  // ---- step 2: collectors, and the one being installed
  const list = useApi(collectorApi.list, [], 5000);
  const active = (list.data ?? []).filter((c) => c.status === "active");
  const healthy = active.filter((c) => c.healthy);
  const [installing, setInstalling] = useState(false);
  const [waitFor, setWaitFor] = useState<{ tokenId: string | null; known: string[] } | null>(null);
  const arrived = waitFor
    ? active.find((c) => (waitFor.tokenId ? c.enrollment_token_id === waitFor.tokenId : !waitFor.known.includes(c.id)))
    : undefined;
  const autoPicked = useRef<string | null>(null);
  useEffect(() => {
    if (arrived?.healthy && autoPicked.current !== arrived.id) {
      autoPicked.current = arrived.id;
      setPicked((p) => [arrived.id, ...p.filter((x) => x !== arrived.id)]);
    }
  }, [arrived]);
  const showInstaller = installing || (list.data !== null && healthy.length === 0);
  const primary = active.find((c) => c.id === picked[0]);
  const shownArrived = arrived?.healthy && picked.includes(arrived.id) ? arrived : undefined;
  // DC warnings for the chosen collectors (the one that just arrived shows its own).
  const otherDCs = active.filter((c) => picked.includes(c.id) && c.is_domain_controller && c.id !== shownArrived?.id);

  // ---- step 3: diagnostics on the primary collector, before saving
  const [cmd, setCmd] = useState<{ collector: string; command: string } | null>(null);
  const diagRaw = useDiagnostics(cmd?.collector ?? null, cmd?.command ?? null);
  const diag = diagRaw && cmd && diagRaw.command_id === cmd.command ? diagRaw : null;
  const testing = !!cmd && (!diag || diag.status === "queued");

  // ---- step 4: save, first sync
  const [saved, setSaved] = useState<DirectorySource | null>(null);
  const [busy, setBusy] = useState(false);
  const [runId, setRunId] = useState<string | null>(null);
  const { run, error: runErr } = useRun(runId);

  const dom = domain.trim().toLowerCase();
  function config(): AdConfig {
    return {
      domain: dom,
      servers: split(servers),
      port,
      security,
      base_dns: split(baseDns),
      scopes: ["computers", "users"],
      stale_days: 90,
      interval_hours: 6,
      auth: "computer_account",
      ca_pem: "",
    };
  }

  function go(s: number) {
    setErr(null);
    setStep(s);
    top.current?.scrollIntoView({ block: "nearest" });
  }

  async function runTest() {
    if (!picked[0]) return;
    setErr(null);
    setCmd(null);
    try {
      const r = await collectorApi.test(picked[0], null, config());
      setCmd({ collector: picked[0], command: r.command_id });
    } catch (ex) {
      setErr(errMsg(ex));
    }
  }

  function next(e: FormEvent) {
    e.preventDefault();
    if (step === 0) {
      if (!DOMAIN_RE.test(dom)) return setErr("Enter the domain's DNS name, such as corp.example.com.");
      if (!name.trim()) setName(dom);
      return go(1);
    }
    if (step === 1) {
      if (picked.length === 0) return setErr("Choose at least one online collector, or install one.");
      go(2);
      void runTest();
      return;
    }
    if (step === 2) return go(3);
  }

  async function save() {
    setBusy(true);
    setErr(null);
    try {
      const s = saved ?? (await directoryApi.createSource({ type: "ad", name: name.trim() || dom, config: config(), collector_ids: picked }));
      setSaved(s);
      try {
        const r = await directoryApi.syncNow(s.id);
        setRunId(r.id);
      } catch {
        /* already queued by the scheduler: it starts on its own */
      }
    } catch (ex) {
      setErr(errMsg(ex));
    } finally {
      setBusy(false);
    }
  }

  const label = "mb-1 block text-sm font-medium text-ink-2";
  return (
    <div ref={top} className="scroll-mt-4">
      <Stepper step={step} />
      <form onSubmit={next} aria-label="Add Active Directory" className="space-y-4">
        {step === 0 && (
          <div className="grid max-w-2xl grid-cols-1 gap-3 sm:grid-cols-2">
            <Field
              label="Domain (DNS name)"
              id="adw-domain"
              required
              autoFocus
              maxLength={253}
              placeholder="corp.example.com"
              spellCheck={false}
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              hint="One domain per source; add a source per domain or forest."
            />
            <Field label="Name" id="adw-name" maxLength={128} placeholder={dom || "e.g. Corporate AD"} value={name} onChange={(e) => setName(e.target.value)} />
          </div>
        )}

        {step === 1 && (
          <div className="space-y-3">
            <p className="text-sm text-ink-2">
              A collector is a small read-only program on a <strong>domain-joined member server</strong> inside your network. It connects outbound
              only (HTTPS to this console, LDAP / Kerberos to your domain controllers) and runs no commands or scripts.
            </p>
            {list.data === null && !list.error && <p className="text-sm text-ink-3">Loading collectors…</p>}
            <ErrorNote error={list.error} />
            {healthy.length > 0 && (
              <div>
                <span className={label}>Online collectors</span>
                <Picker collectors={active} selected={picked} onChange={setPicked} />
                <p className="mt-1 text-xs text-ink-3">The first one chosen is the primary; the others take over when it is offline.</p>
                {!installing && (
                  <button type="button" className="mt-1.5 text-sm text-accent hover:underline" onClick={() => setInstalling(true)}>
                    + Install another collector
                  </button>
                )}
              </div>
            )}
            {showInstaller && (
              <div className="space-y-3 rounded-lg border border-line p-3">
                <h4 className="flex items-center gap-2 text-sm font-semibold text-ink">
                  <Server aria-hidden className="h-4 w-4 text-ink-3" />
                  {healthy.length === 0 ? "No collector yet: install one" : "Install another collector"}
                </h4>
                <CollectorInstaller
                  idPrefix="adw"
                  defaultName={dom ? `${dom.split(".")[0].toUpperCase()} collector` : "Collector 1"}
                  onDownloaded={(d) => setWaitFor({ tokenId: d.tokenId, known: active.map((c) => c.id) })}
                />
                {waitFor && !arrived?.healthy && (
                  <div role="status" aria-live="polite" className="flex items-start gap-2 rounded border border-accent/40 bg-accent/5 px-3 py-2.5 text-sm">
                    <Loader2 aria-hidden className="mt-0.5 h-4 w-4 shrink-0 animate-spin text-accent" />
                    <span>
                      <strong className="text-ink">Waiting for the collector to come online…</strong>
                      <span className="block text-xs text-ink-2">
                        Install the file on the collector host. The collector enrolls and appears here within a minute; it is selected
                        automatically. You can leave this page open.
                      </span>
                    </span>
                  </div>
                )}
                <details className="rounded border border-line px-3 py-2">
                  <summary className="cursor-pointer text-sm font-medium text-ink-2">Production: run the collector as a gMSA (guide)</summary>
                  <div className="mt-2">
                    <GmsaSetup domain={dom} />
                  </div>
                </details>
              </div>
            )}
            {shownArrived && <CollectorFacts c={shownArrived} />}
            {otherDCs.length > 0 && <DcWarning name={otherDCs.map((c) => c.name).join(", ")} />}
          </div>
        )}

        {step === 2 && (
          <div className="space-y-3">
            <p className="text-sm text-ink-2">
              The collector checks, as its own identity, that it can find and reach your domain controllers, bind and read a few objects. Nothing is
              saved yet.
            </p>
            {primary && (
              <p className="text-sm text-ink-2">
                Testing <strong className="text-ink">{dom}</strong> on <strong className="text-ink">{primary.name}</strong> as{" "}
                <span className="font-mono text-ink">{primary.run_as || "?"}</span>.
              </p>
            )}
            {cmd && <DiagnosticsResult d={diag ?? { command_id: cmd.command, at: new Date().toISOString(), status: "queued", steps: [] }} />}
            {diag && diag.status !== "succeeded" && diag.status !== "queued" && (
              <p className="text-xs text-ink-3">
                Fix the failing step and test again (Advanced lets you list domain controllers or change the transport), or save anyway and fix it
                later.
              </p>
            )}
            <details className="rounded border border-line px-3 py-2" open={!!(servers || baseDns) || security !== "sealed"}>
              <summary className="cursor-pointer text-sm font-medium text-ink-2">Advanced: domain controllers, base DNs, transport</summary>
              <div className="mt-2 space-y-3">
                <div>
                  <label htmlFor="adw-servers" className={label}>
                    Domain controllers (optional)
                  </label>
                  <textarea id="adw-servers" rows={2} spellCheck={false} className={inputCls} placeholder="dc1.corp.example.com" value={servers} onChange={(e) => setServers(e.target.value)} />
                  <p className="mt-1 text-xs text-ink-3">One per line. Empty: found through DNS (_ldap._tcp.dc._msdcs).</p>
                </div>
                <div>
                  <label htmlFor="adw-bases" className={label}>
                    Base DNs (optional)
                  </label>
                  <textarea
                    id="adw-bases"
                    rows={2}
                    spellCheck={false}
                    className={inputCls}
                    placeholder={`OU=Workstations,${dom.split(".").map((p) => `DC=${p}`).join(",") || "DC=corp,DC=example,DC=com"}`}
                    value={baseDns}
                    onChange={(e) => setBaseDns(e.target.value)}
                  />
                  <p className="mt-1 text-xs text-ink-3">One per line. Empty: the whole domain.</p>
                </div>
                <fieldset>
                  <legend className={label}>Transport</legend>
                  <div className="space-y-1.5 text-sm">
                    {(Object.keys(TRANSPORT) as DirectorySecurity[]).map((t) => (
                      <label key={t} className="flex items-center gap-2">
                        <input
                          type="radio"
                          name="adw-transport"
                          checked={security === t}
                          onChange={() => {
                            setSecurity(t);
                            setPort(TRANSPORT[t].port);
                          }}
                        />
                        {TRANSPORT[t].label}
                      </label>
                    ))}
                    <label className="flex items-center gap-2">
                      Port
                      <input
                        type="number"
                        min={1}
                        max={65535}
                        aria-label="Port"
                        className="w-24 rounded border border-line bg-surface-2 px-2 py-1 text-sm text-ink"
                        value={port}
                        onChange={(e) => setPort(Number(e.target.value))}
                      />
                    </label>
                  </div>
                </fieldset>
                <Button onClick={() => void runTest()} disabled={testing}>
                  Test again with these settings
                </Button>
              </div>
            </details>
          </div>
        )}

        {step === 3 && (
          <div className="space-y-3">
            <dl className="grid max-w-2xl grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
              <dt className="text-ink-3">Name</dt>
              <dd className="text-ink">{name.trim() || dom}</dd>
              <dt className="text-ink-3">Domain</dt>
              <dd className="text-ink">{dom}</dd>
              <dt className="text-ink-3">Collectors</dt>
              <dd className="text-ink">
                {picked
                  .map((id, i) => `${active.find((c) => c.id === id)?.name ?? id} (${i === 0 ? "primary" : `failover ${i}`})`)
                  .join(", ")}
              </dd>
              <dt className="text-ink-3">Identity</dt>
              <dd className="text-ink">The collector&apos;s own (computer account or gMSA, Kerberos); no secret is stored</dd>
              <dt className="text-ink-3">Transport</dt>
              <dd className="text-ink">
                {TRANSPORT[security].label.split(" (")[0]}, port {port}
              </dd>
              <dt className="text-ink-3">Reads</dt>
              <dd className="text-ink">
                Computers and users{split(baseDns).length ? ` under ${split(baseDns).join("; ")}` : " in the whole domain"}, every 6 hours
              </dd>
              <dt className="text-ink-3">Last test</dt>
              <dd className={diag?.status === "succeeded" ? "text-good" : "text-sev-high"}>
                {diag?.status === "succeeded" ? "all checks passed" : diag ? "failed (saved anyway)" : "not run"}
              </dd>
            </dl>
            {!saved && <p className="text-xs text-ink-3">Change anything else (service account, schedule, objects) later with Edit on the source.</p>}
            {saved && (
              <div className="space-y-2 rounded border border-line p-3" role="status">
                <p className="text-sm text-ink">
                  <strong>{saved.name}</strong> is saved. {runId ? "The first sync has started:" : "The first sync starts within a minute."}
                </p>
                {runId && (
                  <div className="text-sm">
                    <ErrorNote error={runErr} />
                    {run && (
                      <>
                        <span className={`font-medium ${RUN_COLOR[run.status]}`}>{RUN_TEXT[run.status]}</span>
                        {run.device_hostname && <span className="text-ink-2"> on {run.device_hostname}</span>}
                        <span className="text-ink-3">
                          {run.status === "queued"
                            ? " · the collector picks it up within about a minute"
                            : ` · ${run.computers_seen.toLocaleString()} computers, ${run.users_seen.toLocaleString()} users so far`}
                        </span>
                        {run.error && <span className="block break-words text-xs text-ink-3">{run.error}</span>}
                      </>
                    )}
                  </div>
                )}
                <p className="text-sm">
                  <Link to="/it-assets/discovery" className="text-accent hover:underline">
                    Open Discovery
                  </Link>{" "}
                  <span className="text-ink-3">to see machines without an agent, stale accounts and admins at risk.</span>
                </p>
              </div>
            )}
          </div>
        )}

        <ErrorNote error={err} />
        <div className="flex flex-wrap items-center gap-2 border-t border-line pt-3">
          {step > 0 && !saved && (
            <Button onClick={() => go(step - 1)} disabled={busy}>
              Back
            </Button>
          )}
          {step < 3 && (
            <Button type="submit" variant="primary" disabled={(step === 1 && picked.length === 0) || (step === 2 && testing)}>
              {step === 2 ? (testing ? "Testing…" : diag?.status === "succeeded" ? "Next: save" : "Continue without a passing test") : "Next"}
            </Button>
          )}
          {step === 3 && !saved && (
            <Button variant="primary" onClick={() => void save()} disabled={busy}>
              {busy ? "Saving…" : "Save and start the first sync"}
            </Button>
          )}
          {saved ? (
            <Button onClick={() => onDone(saved)}>Done</Button>
          ) : (
            <Button onClick={onCancel} disabled={busy}>
              Cancel
            </Button>
          )}
        </div>
      </form>
    </div>
  );
}
