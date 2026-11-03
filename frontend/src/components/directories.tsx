// Connectors & scans -> Directories: add / edit / monitor directory sources (on-prem Active Directory).
import { Check, Copy, Network, RefreshCw } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { ApiError } from "../api";
import {
  directoryApi,
  type AdConfig,
  type Collector,
  type DirectoryAuth,
  type DirectoryScope,
  type DirectorySecurity,
  type DirectorySource,
  type SyncRun,
} from "../directoryApi";
import { fmtAgo, fmtHours, fmtTime, fmtUntil } from "../lib/format";
import { useApi } from "../lib/useApi";
import { Button, Card, ErrorNote, Field, Tag } from "./ui";

function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : e instanceof Error ? e.message : String(e);
}

const FINAL = new Set(["succeeded", "failed", "cancelled"]);

const RUN_TEXT: Record<string, string> = {
  queued: "Waiting for collector",
  running: "Syncing",
  succeeded: "Succeeded",
  failed: "Failed",
  cancelled: "Cancelled",
};
const RUN_COLOR: Record<string, string> = {
  queued: "text-accent",
  running: "text-accent",
  succeeded: "text-good",
  failed: "text-sev-high",
  cancelled: "text-ink-3",
};
const TRIGGER_TEXT: Record<string, string> = { scheduled: "Scheduled", manual: "Sync now", test: "Test" };

const inputCls =
  "block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40";

function runDuration(r: SyncRun): string | null {
  if (r.duration_ms == null) return null;
  const s = Math.round(r.duration_ms / 1000);
  return s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m`;
}

function StatCell({ label, value, sub, valueClass = "text-ink" }: { label: string; value: ReactNode; sub?: ReactNode; valueClass?: string }) {
  return (
    <div className="min-w-0 border-line py-1 sm:border-l sm:px-4 sm:first:border-l-0 sm:first:pl-0">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-ink-3">{label}</div>
      <div className={`mt-0.5 text-lg font-semibold ${valueClass}`}>{value}</div>
      {sub && <div className="text-xs text-ink-3">{sub}</div>}
    </div>
  );
}

function DirectoryMark({ size = 18 }: { size?: number }) {
  return (
    <span aria-hidden className="inline-grid shrink-0 place-items-center rounded bg-accent/15 text-accent" style={{ width: size, height: size }}>
      <Network style={{ width: size * 0.62, height: size * 0.62 }} />
    </span>
  );
}

// ----------------------------------------------------------------------------- pre-check script
const ps = (s: string) => s.replace(/'/g, "''");

/** Read-only PowerShell pre-check: DNS SRV, TCP, the DC certificate, a bind and a 5-object read. */
function precheckScript(o: { domain: string; servers: string[]; port: number; security: DirectorySecurity; baseDn: string }): string {
  const domain = o.domain.trim() || "corp.example.com";
  const servers = o.servers.length ? o.servers.map((s) => `'${ps(s)}'`).join(", ") : "";
  const base = o.baseDn.trim() || domain.split(".").map((p) => `DC=${p}`).join(",");
  return [
    "# Directory pre-check (read-only: it only resolves, connects and reads 5 objects; it changes nothing).",
    "# Run it on the collector in Windows PowerShell 5.1+.",
    "# Computer-account test (the default): run as SYSTEM, e.g. PsExec64.exe -s -i powershell.exe",
    "# Service-account test: answer y at the prompt and enter the read-only account.",
    `$Domain = '${ps(domain)}'`,
    `$Servers = @(${servers})   # empty = use the DC locator (DNS SRV)`,
    `$Port = ${o.port}`,
    `$StartTls = $${o.security === "starttls" ? "true" : "false"}`,
    `$BaseDn = '${ps(base)}'`,
    "function Pass($m) { Write-Host \"PASS  $m\" -ForegroundColor Green }",
    "function Fail($m) { Write-Host \"FAIL  $m\" -ForegroundColor Red }",
    "function Info($m) { Write-Host \"INFO  $m\" }",
    "",
    "# 1. Domain controller locator",
    "try {",
    "  $srv = @(Resolve-DnsName -Type SRV \"_ldap._tcp.dc._msdcs.$Domain\" -ErrorAction Stop | Where-Object { $_.Type -eq 'SRV' })",
    "  Pass \"DNS SRV: $($srv.Count) domain controller(s): $(($srv | Select-Object -First 5 -ExpandProperty NameTarget) -join ', ')\"",
    "  if (-not $Servers) { $Servers = @($srv | Sort-Object Priority, Weight | Select-Object -First 3 -ExpandProperty NameTarget) }",
    "} catch { Fail \"DNS SRV _ldap._tcp.dc._msdcs.$Domain : $($_.Exception.Message)\" }",
    "if (-not $Servers) { $Servers = @($Domain) }",
    "",
    "Add-Type -AssemblyName System.DirectoryServices.Protocols",
    "$cred = $null",
    "if ((Read-Host 'Test with a service account instead of this computer account? (y/N)') -eq 'y') {",
    "  $cred = Get-Credential -Message 'Read-only directory service account (UPN or DOMAIN\\name)'",
    "}",
    "",
    "foreach ($dc in $Servers) {",
    "  Info \"--- $($dc):$Port\"",
    "  # 2. Network",
    "  $t = Test-NetConnection -ComputerName $dc -Port $Port -WarningAction SilentlyContinue",
    "  if ($t.TcpTestSucceeded) { Pass \"TCP $Port reachable\" } else { Fail \"TCP $Port not reachable (firewall?)\"; continue }",
    "  # 3. Certificate of the domain controller (LDAPS)",
    "  if (-not $StartTls) {",
    "    try {",
    "      $script:tlsErr = 'None'",
    "      $tcp = New-Object Net.Sockets.TcpClient($dc, $Port)",
    "      $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, { param($s, $c, $ch, $e) $script:tlsErr = [string]$e; $true })",
    "      $ssl.AuthenticateAsClient($dc)",
    "      $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)",
    "      if ($script:tlsErr -eq 'None') { Pass \"certificate trusted: $($cert.Subject), expires $($cert.NotAfter.ToString('yyyy-MM-dd'))\" }",
    "      else { Fail \"certificate not trusted ($script:tlsErr): $($cert.Subject), issuer $($cert.Issuer)\" }",
    "      if ($cert.NotAfter -lt (Get-Date).AddDays(30)) { Fail \"certificate expires $($cert.NotAfter.ToString('yyyy-MM-dd'))\" }",
    "      $ssl.Dispose(); $tcp.Dispose()",
    "    } catch { Fail \"TLS handshake: $($_.Exception.Message)\" }",
    "  }",
    "  # 4. Bind and read 5 computer objects",
    "  try {",
    "    $conn = New-Object DirectoryServices.Protocols.LdapConnection((New-Object DirectoryServices.Protocols.LdapDirectoryIdentifier($dc, $Port)))",
    "    $conn.SessionOptions.ProtocolVersion = 3",
    "    $conn.SessionOptions.ReferralChasing = 'None'",
    "    $conn.Timeout = [TimeSpan]::FromSeconds(30)",
    "    if ($StartTls) { $conn.SessionOptions.StartTransportLayerSecurity($null) } else { $conn.SessionOptions.SecureSocketLayer = $true }",
    "    if ($cred) { $conn.AuthType = 'Basic'; $conn.Credential = $cred.GetNetworkCredential() } else { $conn.AuthType = 'Negotiate' }",
    "    $conn.Bind()",
    "    $who = if ($cred) { $cred.UserName } else { \"$($env:COMPUTERNAME)$ (this computer account)\" }",
    "    Pass \"bind as $who\"",
    "    $req = New-Object DirectoryServices.Protocols.SearchRequest($BaseDn, '(objectCategory=computer)', 'Subtree', @('cn'))",
    "    $req.SizeLimit = 5",
    "    try { $res = $conn.SendRequest($req) } catch [DirectoryServices.Protocols.DirectoryOperationException] { $res = $_.Exception.Response }",
    "    if ($res.Entries.Count -gt 0) { Pass \"read $($res.Entries.Count) computer object(s) under $($BaseDn): $(($res.Entries | ForEach-Object { $_.Attributes['cn'][0] }) -join ', ')\" }",
    "    else { Fail \"bound, but read no computer objects under $BaseDn (permissions or base DN?)\" }",
    "    $conn.Dispose()",
    "  } catch { Fail \"LDAP bind / search: $($_.Exception.Message)\" }",
    "}",
  ].join("\n");
}

function CodeBox({ text, note }: { text: string; note?: ReactNode }) {
  const pre = useRef<HTMLPreElement>(null);
  const [state, setState] = useState<"idle" | "copied" | "select">("idle");
  useEffect(() => {
    if (state !== "copied") return;
    const t = setTimeout(() => setState("idle"), 2500);
    return () => clearTimeout(t);
  }, [state]);
  function selectAll() {
    const el = pre.current;
    const sel = window.getSelection();
    if (!el || !sel) return;
    const range = document.createRange();
    range.selectNodeContents(el);
    sel.removeAllRanges();
    sel.addRange(range);
    setState("select");
  }
  async function copy() {
    if (!navigator.clipboard?.writeText) return selectAll();
    try {
      await navigator.clipboard.writeText(text);
      setState("copied");
    } catch {
      selectAll();
    }
  }
  return (
    <div>
      <div className="relative">
        <pre
          ref={pre}
          data-testid="directory-precheck"
          className="max-h-96 overflow-auto whitespace-pre-wrap rounded-xl bg-slate-900 py-3.5 pl-4 pr-24 font-mono text-[12px] leading-relaxed text-slate-200 ring-1 ring-inset ring-white/5"
        >
          {text.split("\n").map((line, i) => (
            <span key={i} className={line.trimStart().startsWith("#") ? "text-slate-400" : undefined}>
              {line}
              {"\n"}
            </span>
          ))}
        </pre>
        <button
          type="button"
          onClick={() => void copy()}
          className="absolute right-2.5 top-2.5 inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs font-semibold text-slate-200 hover:bg-slate-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {state === "copied" ? <Check aria-hidden className="h-3.5 w-3.5" /> : <Copy aria-hidden className="h-3.5 w-3.5" />}
          {state === "copied" ? "Copied" : "Copy"}
        </button>
      </div>
      <p role="status" aria-live="polite" className="mt-2 min-h-4 text-xs text-ink-3">
        {state === "copied" ? "Copied to the clipboard." : state === "select" ? "Your browser blocked the clipboard: the script is selected, press Ctrl+C." : note}
      </p>
    </div>
  );
}

// ----------------------------------------------------------------------------- run polling
/** Poll a sync run every 5 s until it ends. */
function useRun(runId: string | null) {
  const [run, setRun] = useState<SyncRun | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setRun(null);
    setError(null);
    if (!runId) return;
    let stop = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      try {
        const r = await directoryApi.run(runId);
        if (stop) return;
        setRun(r);
        if (FINAL.has(r.status)) return;
      } catch (e) {
        if (!stop) setError(errMsg(e));
      }
      if (!stop) timer = setTimeout(tick, 5000);
    };
    void tick();
    return () => {
      stop = true;
      if (timer) clearTimeout(timer);
    };
  }, [runId]);
  return { run, error };
}

function RunResult({ run, error }: { run: SyncRun | null; error: string | null }) {
  if (error) return <ErrorNote error={error} />;
  if (!run) return <p className="text-sm text-ink-3">Queuing the test…</p>;
  const done = FINAL.has(run.status);
  return (
    <div role="status" aria-live="polite" className={`rounded-lg border px-3 py-2.5 text-sm ${run.status === "failed" ? "border-sev-high/60 bg-sev-high/10" : run.status === "succeeded" ? "border-good/60 bg-good/10" : "border-line bg-surface-2"}`}>
      <div className="flex items-center gap-2 font-medium text-ink">
        {!done && <RefreshCw aria-hidden className="h-3.5 w-3.5 animate-spin text-accent" />}
        <span className={RUN_COLOR[run.status]}>{RUN_TEXT[run.status]}</span>
        {run.device_hostname && <span className="text-ink-3">on {run.device_hostname}</span>}
      </div>
      {run.status === "queued" && (
        <p className="mt-1 text-xs text-ink-3">Agents fetch commands about once a minute, so the collector picks the test up within ~1 minute.</p>
      )}
      {run.status === "running" && <p className="mt-1 text-xs text-ink-3">Connected collector is binding and reading a few objects…</p>}
      {run.status === "succeeded" && (
        <div className="mt-1 text-xs text-ink-2">
          Bound{run.server ? ` to ${run.server}` : ""} and read {run.computers_seen} computer(s) and {run.users_seen} user(s).
          {run.sample.length > 0 && (
            <span className="text-ink-3"> Sample: {run.sample.map((s) => s.name).join(", ")}</span>
          )}
        </div>
      )}
      {run.error && <p className="mt-1 break-words text-xs text-ink">{run.error}</p>}
    </div>
  );
}

// ----------------------------------------------------------------------------- form
interface FormState {
  name: string;
  domain: string;
  servers: string;
  baseDns: string;
  security: DirectorySecurity;
  port: number;
  caPem: string;
  computers: boolean;
  users: boolean;
  staleDays: number;
  intervalHours: number;
  collectors: string[];
  auth: DirectoryAuth;
  username: string;
  password: string;
}

const split = (s: string) =>
  s
    .split(/[\n,;]+/)
    .map((x) => x.trim())
    .filter(Boolean);

function initialForm(src: DirectorySource | null): FormState {
  const c = src?.config;
  return {
    name: src?.name ?? "",
    domain: c?.domain ?? "",
    servers: (c?.servers ?? []).join("\n"),
    baseDns: (c?.base_dns ?? []).join("\n"),
    security: c?.security ?? "ldaps",
    port: c?.port ?? 636,
    caPem: c?.ca_pem ?? "",
    computers: c ? c.scopes.includes("computers") : true,
    users: c ? c.scopes.includes("users") : true,
    staleDays: c?.stale_days ?? 90,
    intervalHours: c?.interval_hours ?? 6,
    collectors: src?.collector_device_ids ?? [],
    auth: c?.auth ?? "computer_account",
    username: "",
    password: "",
  };
}

function CollectorPicker({ collectors, selected, onChange, auth }: { collectors: Collector[] | null; selected: string[]; onChange: (ids: string[]) => void; auth: DirectoryAuth }) {
  if (collectors === null) return <p className="text-sm text-ink-3">Loading agents…</p>;
  if (collectors.length === 0)
    return (
      <p className="rounded border border-line bg-surface-2 px-3 py-2 text-sm text-ink-2">
        No agent can collect yet. Collectors are enrolled agents (version 1.3.0 or later) on a machine that can reach a domain controller; a
        domain-joined Windows server is ideal.
      </p>
    );
  return (
    <ul className="max-h-56 space-y-1 overflow-y-auto rounded border border-line p-1.5" aria-label="Collector agents">
      {collectors.map((c) => {
        const idx = selected.indexOf(c.id);
        const nonWindows = auth === "computer_account" && c.os_family !== "windows";
        return (
          <li key={c.id}>
            <label className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-sm hover:bg-surface-2">
              <input
                type="checkbox"
                checked={idx >= 0}
                onChange={(e) => onChange(e.target.checked ? [...selected, c.id] : selected.filter((x) => x !== c.id))}
              />
              <span aria-hidden className={`inline-block h-2 w-2 rounded-full ${c.healthy ? "bg-good" : "bg-ink-3"}`} />
              <span className="font-medium text-ink">{c.hostname}</span>
              <span className="text-xs text-ink-3">
                {c.os_family}
                {c.ad_domain ? ` · ${c.ad_domain}` : " · not domain-joined"} · {c.healthy ? "online" : c.last_seen_at ? `offline, seen ${fmtAgo(c.last_seen_at)}` : "offline"}
              </span>
              {idx >= 0 && selected.length > 1 && <Tag>{idx === 0 ? "primary" : `failover ${idx}`}</Tag>}
              {nonWindows && <Tag tone="warn">needs service account</Tag>}
            </label>
          </li>
        );
      })}
    </ul>
  );
}

/** Add or edit an Active Directory source: settings, collectors, auth, the pre-check script and "Test & save". */
export function DirectoryForm({ source, onDone, onCancel }: { source: DirectorySource | null; onDone: (s: DirectorySource) => void; onCancel: () => void }) {
  const [f, setF] = useState<FormState>(() => initialForm(source));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState<DirectorySource | null>(source);
  const [runId, setRunId] = useState<string | null>(null);
  const { run, error: runErr } = useRun(runId);
  const collectors = useApi(directoryApi.collectors, [], 30000);
  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => setF((x) => ({ ...x, [k]: v }));
  const id = source?.id ?? "new";

  const script = useMemo(
    () => precheckScript({ domain: f.domain, servers: split(f.servers), port: f.port, security: f.security, baseDn: split(f.baseDns)[0] ?? "" }),
    [f.domain, f.servers, f.port, f.security, f.baseDns],
  );
  const nonWindows = f.auth === "computer_account" && (collectors.data ?? []).some((c) => f.collectors.includes(c.id) && c.os_family !== "windows");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setErr(null);
    const scopes: DirectoryScope[] = [...(f.computers ? (["computers"] as const) : []), ...(f.users ? (["users"] as const) : [])];
    if (scopes.length === 0) return setErr("Choose computers, users or both.");
    if (f.collectors.length === 0) return setErr("Choose at least one collector agent.");
    const config: AdConfig = {
      domain: f.domain.trim().toLowerCase(),
      servers: split(f.servers),
      port: f.port,
      security: f.security,
      base_dns: split(f.baseDns),
      scopes,
      stale_days: f.staleDays,
      interval_hours: f.intervalHours,
      auth: f.auth,
      ca_pem: f.caPem.trim(),
    };
    const credential = f.auth === "service_account" && (f.username || f.password) ? { username: f.username.trim(), password: f.password } : null;
    if (credential && (!credential.username || !credential.password)) return setErr("Enter both the username and the password.");
    if (f.auth === "service_account" && !credential && !saved?.has_credential) return setErr("Enter the service account's username and password.");
    setBusy(true);
    try {
      const s = saved
        ? await directoryApi.updateSource(saved.id, {
            name: f.name.trim(),
            config,
            collector_device_ids: f.collectors,
            credential,
            clear_credential: f.auth === "computer_account" && saved.has_credential,
          })
        : await directoryApi.createSource({ type: "ad", name: f.name.trim(), config, collector_device_ids: f.collectors, credential });
      setSaved(s);
      set("password", "");
      const r = await directoryApi.test(s.id);
      setRunId(r.id);
    } catch (ex) {
      setErr(errMsg(ex));
    } finally {
      setBusy(false);
    }
  }

  const label = "mb-1 block text-sm font-medium text-ink-2";
  const testing = !!runId && (!run || !FINAL.has(run.status));

  return (
    <div className="grid grid-cols-1 gap-5 lg:grid-cols-[1fr_1.1fr]">
      <form className="min-w-0 space-y-3" onSubmit={submit} aria-label="Active Directory source">
        <Field label="Name" id={`ds-${id}-name`} required maxLength={128} placeholder="e.g. Corporate AD" value={f.name} onChange={(e) => set("name", e.target.value)} />
        <Field
          label="Domain (DNS name)"
          id={`ds-${id}-domain`}
          required
          maxLength={253}
          placeholder="corp.example.com"
          spellCheck={false}
          value={f.domain}
          onChange={(e) => set("domain", e.target.value)}
          hint="One domain per source. Add a source per domain or forest you want to discover."
        />
        <div>
          <span className={label}>Collector agents</span>
          <CollectorPicker collectors={collectors.data} selected={f.collectors} onChange={(v) => set("collectors", v)} auth={f.auth} />
          <p className="mt-1 text-xs text-ink-3">Syncs run on the first online collector in the order chosen; the others are failovers.</p>
        </div>
        <fieldset>
          <legend className={label}>Authentication</legend>
          <div className="space-y-1.5 text-sm">
            <label className="flex items-start gap-2">
              <input type="radio" name={`ds-${id}-auth`} className="mt-1" checked={f.auth === "computer_account"} onChange={() => set("auth", "computer_account")} />
              <span>
                <span className="font-medium text-ink">Collector&apos;s computer account</span>
                <span className="block text-xs text-ink-3">Kerberos from a domain-joined Windows collector. No secret is stored.</span>
              </span>
            </label>
            <label className="flex items-start gap-2">
              <input type="radio" name={`ds-${id}-auth`} className="mt-1" checked={f.auth === "service_account"} onChange={() => set("auth", "service_account")} />
              <span>
                <span className="font-medium text-ink">Read-only service account</span>
                <span className="block text-xs text-ink-3">For Linux, macOS or non-joined collectors. Stored encrypted, sent only to the collector over TLS, never shown again.</span>
              </span>
            </label>
          </div>
          {nonWindows && <p className="mt-1.5 text-xs text-sev-high">A selected collector is not Windows: the computer-account option needs a domain-joined Windows collector.</p>}
          {f.auth === "service_account" && (
            <div className="mt-2.5 grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field
                label="Username"
                id={`ds-${id}-user`}
                autoComplete="off"
                spellCheck={false}
                maxLength={256}
                placeholder={saved?.credential_username_hint ?? "svc-discovery@corp.example.com"}
                value={f.username}
                onChange={(e) => set("username", e.target.value)}
              />
              <Field
                label="Password"
                id={`ds-${id}-pass`}
                type="password"
                autoComplete="new-password"
                maxLength={256}
                placeholder={saved?.has_credential ? "Stored. Leave blank to keep it." : ""}
                value={f.password}
                onChange={(e) => set("password", e.target.value)}
              />
              {saved?.has_credential && (
                <p className="text-xs text-ink-3 sm:col-span-2">
                  Stored credential: {saved.credential_username_hint}. Leave both fields blank to keep it.
                </p>
              )}
            </div>
          )}
        </fieldset>
        <fieldset className="grid grid-cols-2 gap-3">
          <legend className={label}>Objects</legend>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={f.computers} onChange={(e) => set("computers", e.target.checked)} /> Computers
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={f.users} onChange={(e) => set("users", e.target.checked)} /> Users
          </label>
        </fieldset>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Stale after (days)" id={`ds-${id}-stale`} type="number" min={7} max={3650} value={f.staleDays} onChange={(e) => set("staleDays", Number(e.target.value))} />
          <Field label="Sync every (hours)" id={`ds-${id}-every`} type="number" min={1} max={168} value={f.intervalHours} onChange={(e) => set("intervalHours", Number(e.target.value))} />
        </div>
        <details className="rounded border border-line px-3 py-2" open={!!(f.servers || f.baseDns || f.caPem || f.security !== "ldaps")}>
          <summary className="cursor-pointer text-sm font-medium text-ink-2">Advanced: servers, base DNs, TLS</summary>
          <div className="mt-2 space-y-3">
            <div>
              <label htmlFor={`ds-${id}-servers`} className={label}>
                Domain controllers (optional)
              </label>
              <textarea id={`ds-${id}-servers`} rows={2} spellCheck={false} className={inputCls} placeholder="dc1.corp.example.com" value={f.servers} onChange={(e) => set("servers", e.target.value)} />
              <p className="mt-1 text-xs text-ink-3">One per line. Empty: the collector finds DCs through DNS (_ldap._tcp.dc._msdcs).</p>
            </div>
            <div>
              <label htmlFor={`ds-${id}-bases`} className={label}>
                Base DNs (optional)
              </label>
              <textarea id={`ds-${id}-bases`} rows={2} spellCheck={false} className={inputCls} placeholder="OU=Workstations,DC=corp,DC=example,DC=com" value={f.baseDns} onChange={(e) => set("baseDns", e.target.value)} />
              <p className="mt-1 text-xs text-ink-3">One per line. Empty: the whole domain.</p>
            </div>
            <div>
              <span className={label}>Transport</span>
              <div role="radiogroup" aria-label="Transport security" className="flex flex-wrap gap-4 text-sm">
                <label className="flex items-center gap-2">
                  <input type="radio" checked={f.security === "ldaps"} onChange={() => setF((x) => ({ ...x, security: "ldaps", port: x.port === 389 ? 636 : x.port }))} /> LDAPS (636)
                </label>
                <label className="flex items-center gap-2">
                  <input type="radio" checked={f.security === "starttls"} onChange={() => setF((x) => ({ ...x, security: "starttls", port: x.port === 636 ? 389 : x.port }))} /> StartTLS (389)
                </label>
                <label className="flex items-center gap-2">
                  Port
                  <input type="number" min={1} max={65535} aria-label="Port" className="w-24 rounded border border-line bg-surface-2 px-2 py-1 text-sm text-ink" value={f.port} onChange={(e) => set("port", Number(e.target.value))} />
                </label>
              </div>
              <p className="mt-1 text-xs text-ink-3">Plain, unencrypted LDAP is never used. Use 3269 for a Global Catalog over LDAPS.</p>
            </div>
            <div>
              <label htmlFor={`ds-${id}-ca`} className={label}>
                Extra CA certificate (optional, PEM)
              </label>
              <textarea id={`ds-${id}-ca`} rows={3} spellCheck={false} className={`${inputCls} font-mono text-xs`} placeholder="-----BEGIN CERTIFICATE-----" value={f.caPem} onChange={(e) => set("caPem", e.target.value)} />
              <p className="mt-1 text-xs text-ink-3">Trusted in addition to the collector&apos;s system roots, for a private enterprise CA.</p>
            </div>
          </div>
        </details>
        <ErrorNote error={err} />
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <Button type="submit" variant="primary" disabled={busy || testing}>
            {busy ? "Saving…" : testing ? "Testing…" : "Test & save"}
          </Button>
          <Button disabled={busy} onClick={() => (saved && !source ? onDone(saved) : onCancel())}>
            {saved && !source ? "Done" : "Cancel"}
          </Button>
          {saved && run && FINAL.has(run.status) && (
            <Button onClick={() => onDone(saved)}>{run.status === "succeeded" ? "Finish" : "Close (keep settings)"}</Button>
          )}
        </div>
        {runId && (
          <div className="pt-1">
            <RunResult run={run} error={runErr} />
            {saved && !source && <p className="mt-1.5 text-xs text-ink-3">The source is saved; the first full sync runs on schedule or with Sync now.</p>}
          </div>
        )}
      </form>
      <div className="min-w-0">
        <h3 className="mb-2 text-[13px] font-semibold text-ink">Optional · Pre-check on the collector</h3>
        <CodeBox
          text={script}
          note="Read-only: resolves domain controllers, checks the port and the DC certificate, binds and reads 5 computer objects. It never writes anything."
        />
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------- status card
function SourceCard({ src, isAdmin, onChanged }: { src: DirectorySource; isAdmin: boolean; onChanged: () => void }) {
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const runs = useApi(() => directoryApi.runs(src.id, 8), [src.id, src.last_sync_at, src.active_run?.status], src.active_run ? 5000 : undefined);
  const active = src.active_run;
  const healthy = src.collectors.filter((c) => c.healthy).length;

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    setErr(null);
    try {
      await fn();
      onChanged();
      runs.reload();
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  const lastValue = active ? RUN_TEXT[active.status] : src.last_sync_status ? RUN_TEXT[src.last_sync_status] : "Not yet";
  const lastClass = active ? RUN_COLOR[active.status] : src.last_sync_status ? RUN_COLOR[src.last_sync_status] : "text-ink-3";

  return (
    <Card className="mb-4">
      <div className="flex flex-wrap items-start justify-between gap-4 px-1">
        <div className="flex min-w-0 items-center gap-3">
          <DirectoryMark size={32} />
          <div className="min-w-0">
            <h3 className="text-base font-semibold text-ink">{src.name}</h3>
            <div className="flex flex-wrap items-center gap-x-1.5 text-[13px] text-ink-3">
              <span aria-hidden className={`inline-block h-2 w-2 rounded-full ${src.enabled ? "bg-good" : "bg-ink-3"}`} />
              <span>
                Active Directory · {src.config.domain} · {src.enabled ? "enabled" : "disabled"} ·{" "}
                {src.config.auth === "service_account" ? `service account ${src.credential_username_hint ?? ""}` : "computer account (Kerberos)"} ·{" "}
                {src.config.security === "ldaps" ? "LDAPS" : "StartTLS"} {src.config.port}
              </span>
            </div>
          </div>
        </div>
        {isAdmin && (
          <div className="flex flex-wrap items-center gap-2">
            <Button onClick={() => setEditing((v) => !v)} disabled={editing || busy}>
              Edit
            </Button>
            <Button
              disabled={busy}
              onClick={() => void act(() => directoryApi.updateSource(src.id, { enabled: !src.enabled }))}
            >
              {src.enabled ? "Disable" : "Enable"}
            </Button>
            <Button
              variant="danger"
              disabled={busy}
              onClick={() => {
                if (window.confirm(`Delete ${src.name}? Its synced computers, users and discovery issues are removed. IT assets already added stay.`))
                  void act(() => directoryApi.deleteSource(src.id));
              }}
            >
              Delete
            </Button>
            <Button variant="primary" disabled={busy || !src.enabled || !!active} onClick={() => void act(() => directoryApi.syncNow(src.id))}>
              <span className="inline-flex items-center gap-1.5">
                <RefreshCw aria-hidden className={`h-3.5 w-3.5 ${active ? "animate-spin" : ""}`} />
                {active ? "Syncing…" : "Sync now"}
              </span>
            </Button>
          </div>
        )}
      </div>
      <ErrorNote error={err} />
      <div className="mt-4 grid grid-cols-2 gap-y-3 px-1 sm:grid-cols-4">
        <StatCell
          label="Last sync"
          value={lastValue}
          valueClass={lastClass}
          sub={
            active ? (
              active.status === "queued" ? (
                `queued ${fmtAgo(active.queued_at)} on ${active.device_hostname ?? "collector"}`
              ) : (
                `${(active.computers_seen + active.users_seen).toLocaleString()} objects so far`
              )
            ) : src.last_sync_at ? (
              <span title={fmtTime(src.last_sync_at)}>{fmtAgo(src.last_sync_at)}</span>
            ) : undefined
          }
        />
        <StatCell label="Objects" value={(src.computers_count + src.users_count).toLocaleString()} sub={`${src.computers_count.toLocaleString()} computers · ${src.users_count.toLocaleString()} users`} />
        <StatCell
          label="Next sync"
          value={!src.enabled ? "Off" : src.next_sync_at ? fmtUntil(src.next_sync_at) : "—"}
          sub={src.enabled ? `every ${fmtHours(src.config.interval_hours)}` : "source disabled"}
        />
        <StatCell
          label="Collectors"
          value={`${healthy} / ${src.collectors.length} online`}
          valueClass={healthy === 0 ? "text-sev-high" : "text-ink"}
          sub={src.collectors.map((c) => c.hostname).join(", ")}
        />
      </div>
      {src.last_sync_error && !active && <p className="mt-3 break-words px-1 text-xs text-sev-high">{src.last_sync_error}</p>}
      {runs.data && runs.data.length > 0 && (
        <details className="mt-3 px-1">
          <summary className="cursor-pointer text-xs font-medium text-ink-3">Recent syncs ({runs.data.length})</summary>
          <ul className="mt-2 divide-y divide-line/60 text-xs">
            {runs.data.map((r) => (
              <li key={r.id} className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 py-1.5">
                <span className="w-32 shrink-0 text-ink-2" title={fmtTime(r.queued_at)}>
                  {new Date(r.queued_at).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })}
                </span>
                <span className="w-20 shrink-0 text-ink-3">{TRIGGER_TEXT[r.trigger] ?? r.trigger}</span>
                <span className={`w-36 shrink-0 font-medium ${RUN_COLOR[r.status]}`}>
                  {RUN_TEXT[r.status]}
                  {r.truncated && " (capped)"}
                </span>
                <span className="text-ink-2">
                  {r.computers_seen.toLocaleString()} computers · {r.users_seen.toLocaleString()} users
                  {runDuration(r) && ` · ${runDuration(r)}`}
                  {r.device_hostname && ` · ${r.device_hostname}`}
                </span>
                {r.error && <span className="basis-full break-words text-ink-3">{r.error}</span>}
              </li>
            ))}
          </ul>
        </details>
      )}
      {editing && (
        <div className="mt-4 border-t border-line px-1 pt-4">
          <h4 className="mb-3 text-[13px] font-semibold text-ink">Edit {src.name}</h4>
          <DirectoryForm
            source={src}
            onCancel={() => setEditing(false)}
            onDone={() => {
              setEditing(false);
              onChanged();
            }}
          />
        </div>
      )}
    </Card>
  );
}

// ----------------------------------------------------------------------------- section
export function DirectoriesSection({ isAdmin }: { isAdmin: boolean }) {
  const sources = useApi(directoryApi.sources, [], 10000);
  const [adding, setAdding] = useState(false);
  const list = sources.data ?? [];
  const loaded = sources.data !== null;
  useEffect(() => {
    if (loaded && window.location.hash === "#directories") document.getElementById("directories")?.scrollIntoView({ block: "start" });
  }, [loaded]);

  return (
    <section id="directories" aria-labelledby="directories-title" className="mt-6 scroll-mt-4">
      <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 id="directories-title" className="text-lg font-semibold tracking-tight text-ink">
            Directories
          </h2>
          <p className="mt-0.5 text-sm text-ink-2">
            Read-only discovery of the computers and users in your directory, collected by your own agents. Find machines without an agent,
            stale and disabled accounts.
          </p>
        </div>
        {isAdmin && list.length > 0 && !adding && (
          <Button onClick={() => setAdding(true)}>Add Active Directory</Button>
        )}
      </div>
      <ErrorNote error={sources.error} />
      {sources.data && list.length === 0 && !adding && (
        <Card className="mb-4">
          <div className="flex flex-wrap items-center justify-between gap-4 px-1 py-1">
            <div className="flex min-w-0 items-start gap-3">
              <DirectoryMark size={32} />
              <div className="min-w-0">
                <h3 className="text-base font-semibold text-ink">No directory connected</h3>
                <p className="mt-1 max-w-2xl text-sm text-ink-3">
                  Connect on-prem Active Directory: one of your enrolled agents reads computers and users over LDAPS (read-only, nothing is
                  written) and streams them here. Discovery then shows computers that sign in to the domain but have no agent.
                </p>
              </div>
            </div>
            {isAdmin ? (
              <Button variant="primary" onClick={() => setAdding(true)}>
                Add Active Directory
              </Button>
            ) : (
              <span className="text-xs text-ink-3">An organisation administrator can connect a directory.</span>
            )}
          </div>
        </Card>
      )}
      {adding && isAdmin && (
        <Card className="mb-4">
          <div className="px-1 py-1">
            <h3 className="text-base font-semibold text-ink">Add Active Directory</h3>
            <ol className="mb-4 mt-3 flex flex-wrap items-center gap-2.5" aria-label="Steps">
              {["Choose a collector agent", "Optionally run the pre-check on it", "Test & save"].map((t, i) => (
                <li key={t} className="flex items-center gap-2 text-sm text-ink-2">
                  {i > 0 && <span aria-hidden className="text-ink-3">→</span>}
                  <span className="grid h-[22px] w-[22px] place-items-center rounded-full bg-accent/10 text-xs font-semibold text-accent">{i + 1}</span>
                  {t}
                </li>
              ))}
            </ol>
            <DirectoryForm
              source={null}
              onCancel={() => setAdding(false)}
              onDone={() => {
                setAdding(false);
                sources.reload();
              }}
            />
          </div>
        </Card>
      )}
      {list.map((s) => (
        <SourceCard key={s.id} src={s} isAdmin={isAdmin} onChanged={sources.reload} />
      ))}
    </section>
  );
}
