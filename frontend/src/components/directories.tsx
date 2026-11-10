// Connectors & scans -> Directories: add / edit / monitor directory sources (on-prem Active Directory read by a
// collector agent; Microsoft Entra ID + Intune and Google Workspace read by the server).
import { Link } from "react-router-dom";
import { RefreshCw } from "lucide-react";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import {
  DIRECTORY_NAME,
  directoryApi,
  type AdConfig,
  type Collector,
  type DirectoryAuth,
  type DirectoryScope,
  type DirectorySecurity,
  type DirectorySource,
  type DirectoryType,
  type DedicatedCollector,
  collectorApi,
} from "../directoryApi";
import { useDiagnostics } from "../lib/collectors";
import { AdWizard } from "./adWizard";
import { DcWarning, DiagnosticsResult } from "./collectors";
import { FINAL, RUN_COLOR, RUN_TEXT, RUN_TEXT_SERVER, TRIGGER_TEXT, errMsg, inputCls, runDuration, useRun } from "../lib/directory";
import { fmtAgo, fmtHours, fmtTime, fmtUntil } from "../lib/format";
import { useApi } from "../lib/useApi";
import { EntraForm } from "./directoryEntra";
import { GoogleForm } from "./directoryGoogle";
import { CodeBox, DirectoryMark, RunResult, ScopeChips, StatCell } from "./directoryShared";
import { Button, Card, ErrorNote, Field, Tag } from "./ui";

type AdSource = Extract<DirectorySource, { type: "ad" }>;

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
    "# The console's Test runs these checks on the collector itself; this script is an optional manual tool.",
    "# Computer-account test: run as SYSTEM, e.g. PsExec64.exe -s -i powershell.exe (gMSA: a scheduled task as the gMSA)",
    "# Service-account test: answer y at the prompt and enter the read-only account.",
    `$Domain = '${ps(domain)}'`,
    `$Servers = @(${servers})   # empty = use the DC locator (DNS SRV)`,
    `$Port = ${o.port}`,
    `$StartTls = $${o.security === "starttls" ? "true" : "false"}`,
    `$Sealed = $${o.security === "sealed" ? "true" : "false"}   # Kerberos signing + sealing on 389: no certificate`,
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
    "  if ($t.TcpTestSucceeded) { Pass \"TCP $Port reachable\" } else { Fail \"TCP $Port not reachable (firewall, or a stale DC SRV record?)\"; continue }",
    "  # 3. Certificate of the domain controller (LDAPS)",
    "  if (-not $StartTls -and -not $Sealed) {",
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
    "    if ($Sealed) { $conn.SessionOptions.Signing = $true; $conn.SessionOptions.Sealing = $true }",
    "    elseif ($StartTls) { $conn.SessionOptions.StartTransportLayerSecurity($null) } else { $conn.SessionOptions.SecureSocketLayer = $true }",
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
  /** legacy source still on endpoint agents (until switched) */
  legacy: boolean;
  auth: DirectoryAuth;
  username: string;
  password: string;
}

const split = (s: string) =>
  s
    .split(/[\n,;]+/)
    .map((x) => x.trim())
    .filter(Boolean);

function initialForm(src: AdSource | null): FormState {
  const c = src?.config;
  return {
    name: src?.name ?? "",
    domain: c?.domain ?? "",
    servers: (c?.servers ?? []).join("\n"),
    baseDns: (c?.base_dns ?? []).join("\n"),
    security: c?.security ?? "sealed",
    port: c?.port ?? 389,
    caPem: c?.ca_pem ?? "",
    computers: c ? c.scopes.includes("computers") : true,
    users: c ? c.scopes.includes("users") : true,
    staleDays: c?.stale_days ?? 90,
    intervalHours: c?.interval_hours ?? 6,
    collectors: src?.legacy_collectors ? src.collector_device_ids : (src?.collector_ids ?? []),
    legacy: !!src?.legacy_collectors,
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

function DedicatedPicker({ collectors, selected, onChange }: { collectors: DedicatedCollector[] | null; selected: string[]; onChange: (ids: string[]) => void }) {
  if (collectors === null) return <p className="text-sm text-ink-3">Loading collectors…</p>;
  const usable = collectors.filter((c) => c.status === "active");
  if (usable.length === 0)
    return (
      <p className="rounded border border-line bg-surface-2 px-3 py-2 text-sm text-ink-2">
        No collector yet. Add one under <a href="#collectors" className="text-accent hover:underline">Collectors</a> (a small program on a
        domain-joined member server), then pick it here.
      </p>
    );
  return (
    <ul className="max-h-56 space-y-1 overflow-y-auto rounded border border-line p-1.5" aria-label="Collectors">
      {usable.map((c) => {
        const idx = selected.indexOf(c.id);
        return (
          <li key={c.id}>
            <label className="flex cursor-pointer flex-wrap items-center gap-2 rounded px-2 py-1.5 text-sm hover:bg-surface-2">
              <input
                type="checkbox"
                checked={idx >= 0}
                onChange={(e) => onChange(e.target.checked ? [...selected, c.id] : selected.filter((x) => x !== c.id))}
              />
              <span aria-hidden className={`inline-block h-2 w-2 rounded-full ${c.healthy ? "bg-good" : "bg-ink-3"}`} />
              <span className="font-medium text-ink">{c.name}</span>
              <span className="text-xs text-ink-3">
                {c.hostname || "not enrolled"}
                {c.domain ? ` · ${c.domain}` : ""} · {c.run_as || "?"} · {c.healthy ? "online" : c.last_seen_at ? `offline, seen ${fmtAgo(c.last_seen_at)}` : "offline"}
              </span>
              {idx >= 0 && selected.length > 1 && <Tag>{idx === 0 ? "primary" : `failover ${idx}`}</Tag>}
              {c.is_domain_controller && <Tag tone="warn">domain controller</Tag>}
            </label>
          </li>
        );
      })}
    </ul>
  );
}

/** Add or edit an Active Directory source: settings, collectors, auth, the pre-check script and "Test & save". */
function DirectoryForm({ source, onDone, onCancel }: { source: AdSource | null; onDone: (s: DirectorySource) => void; onCancel: () => void }) {
  const [f, setF] = useState<FormState>(() => initialForm(source));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saved, setSaved] = useState<DirectorySource | null>(source);
  const [runId, setRunId] = useState<string | null>(null);
  const { run, error: runErr } = useRun(runId);
  const collectors = useApi(directoryApi.collectors, [], 30000);
  const dedicated = useApi(collectorApi.list, [], 30000);
  const [diagFor, setDiagFor] = useState<{ collector: string; command: string } | null>(null);
  const diag = useDiagnostics(diagFor?.collector ?? null, diagFor?.command ?? null);
  const pickedDCs = (dedicated.data ?? []).filter((c) => !f.legacy && f.collectors.includes(c.id) && c.is_domain_controller);
  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => setF((x) => ({ ...x, [k]: v }));
  const id = source?.id ?? "new";

  const script = useMemo(
    () => precheckScript({ domain: f.domain, servers: split(f.servers), port: f.port, security: f.security, baseDn: split(f.baseDns)[0] ?? "" }),
    [f.domain, f.servers, f.port, f.security, f.baseDns],
  );
  const nonWindows = f.legacy && f.auth === "computer_account" && (collectors.data ?? []).some((c) => f.collectors.includes(c.id) && c.os_family !== "windows");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setErr(null);
    const scopes: DirectoryScope[] = [...(f.computers ? (["computers"] as const) : []), ...(f.users ? (["users"] as const) : [])];
    if (scopes.length === 0) return setErr("Choose computers, users or both.");
    if (f.collectors.length === 0) return setErr("Choose at least one collector.");
    if (f.security === "sealed" && f.auth === "service_account") return setErr("A service-account password is only sent inside TLS: choose LDAPS or StartTLS.");
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
            ...(f.legacy ? { collector_device_ids: f.collectors } : { collector_ids: f.collectors }),
            credential,
            clear_credential: f.auth === "computer_account" && saved.has_credential,
          })
        : await directoryApi.createSource({ type: "ad", name: f.name.trim(), config, collector_ids: f.collectors, credential });
      setSaved(s);
      set("password", "");
      if (s.legacy_collectors) {
        const r = await directoryApi.test(s.id);
        setRunId(r.id);
      } else {
        // Diagnostics ON the collector: DC locator, port, certificate, bind as its identity, 5-object read.
        const r = await collectorApi.test(f.collectors[0], s.id);
        setDiagFor({ collector: f.collectors[0], command: r.command_id });
      }
    } catch (ex) {
      setErr(errMsg(ex));
    } finally {
      setBusy(false);
    }
  }

  const label = "mb-1 block text-sm font-medium text-ink-2";
  const testing = (!!runId && (!run || !FINAL.has(run.status))) || (!!diagFor && (!diag || diag.status === "queued"));

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
          <span className={label}>{f.legacy ? "Collector agents (legacy)" : "Collectors"}</span>
          {f.legacy ? (
            <>
              <div role="note" className="mb-2 rounded border border-sev-medium/60 bg-sev-medium/10 px-3 py-2 text-sm">
                <strong>Legacy: uses endpoint agents</strong> — move to a dedicated collector. Dedicated collectors cannot run commands and
                support Kerberos signing &amp; sealing (no DC certificate). Objects, issues and history are kept.
                <div className="mt-1.5">
                  <Button onClick={() => setF((x) => ({ ...x, legacy: false, collectors: [] }))}>Switch to dedicated collectors</Button>
                </div>
              </div>
              <CollectorPicker collectors={collectors.data} selected={f.collectors} onChange={(v) => set("collectors", v)} auth={f.auth} />
            </>
          ) : (
            <DedicatedPicker collectors={dedicated.data} selected={f.collectors} onChange={(v) => set("collectors", v)} />
          )}
          <p className="mt-1 text-xs text-ink-3">Syncs run on the first online collector in the order chosen; the others are failovers.</p>
          {pickedDCs.length > 0 && (
            <div className="mt-2">
              <DcWarning name={pickedDCs.map((c) => c.name).join(", ")} />
            </div>
          )}
        </div>
        <fieldset>
          <legend className={label}>Authentication</legend>
          <div className="space-y-1.5 text-sm">
            <label className="flex items-start gap-2">
              <input type="radio" name={`ds-${id}-auth`} className="mt-1" checked={f.auth === "computer_account"} onChange={() => set("auth", "computer_account")} />
              <span>
                <span className="font-medium text-ink">Collector&apos;s identity: computer account or gMSA (recommended)</span>
                <span className="block text-xs text-ink-3">
                  Kerberos as the collector service&apos;s account: LocalSystem (the computer account) or a group Managed Service Account. No
                  secret is stored.
                </span>
              </span>
            </label>
            <label className="flex items-start gap-2">
              <input
                type="radio"
                name={`ds-${id}-auth`}
                className="mt-1"
                checked={f.auth === "service_account"}
                onChange={() => setF((x) => ({ ...x, auth: "service_account", ...(x.security === "sealed" ? { security: "ldaps", port: 636 } : {}) }))}
              />
              <span>
                <span className="font-medium text-ink">Read-only service account</span>
                <span className="block text-xs text-ink-3">For collectors that are not domain-joined. Stored encrypted, sent only to the collector, and only ever used inside TLS (LDAPS / StartTLS); never shown again.</span>
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
        <div>
          <span className={label}>Transport</span>
          <div role="radiogroup" aria-label="Transport security" className="space-y-1.5 text-sm">
            <label className={`flex items-start gap-2 ${f.legacy || f.auth === "service_account" ? "opacity-60" : ""}`}>
              <input
                type="radio"
                className="mt-1"
                disabled={f.legacy || f.auth === "service_account"}
                checked={f.security === "sealed"}
                onChange={() => setF((x) => ({ ...x, security: "sealed", port: 389 }))}
              />
              <span>
                <span className="font-medium text-ink">Kerberos signing &amp; sealing (port 389, no certificate needed)</span>
                <span className="block text-xs text-ink-3">
                  No DC certificate required. Signed and encrypted by Kerberos; works where DCs require LDAP signing. Never falls back to unsigned LDAP.
                  {f.auth === "service_account" && " Not for service-account passwords (TLS only)."}
                </span>
              </span>
            </label>
            <label className="flex items-center gap-2">
              <input type="radio" checked={f.security === "ldaps"} onChange={() => setF((x) => ({ ...x, security: "ldaps", port: x.port === 389 ? 636 : x.port }))} /> LDAPS (636) - needs a
              DC certificate the collector trusts
            </label>
            <label className="flex items-center gap-2">
              <input type="radio" checked={f.security === "starttls"} onChange={() => setF((x) => ({ ...x, security: "starttls", port: x.port === 636 ? 389 : x.port }))} /> StartTLS
              (389) - needs a DC certificate
            </label>
          </div>
        </div>
        <details className="rounded border border-line px-3 py-2" open={!!(f.servers || f.baseDns || f.caPem)}>
          <summary className="cursor-pointer text-sm font-medium text-ink-2">Advanced: servers, base DNs, port, CA</summary>
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
              <div className="flex flex-wrap gap-4 text-sm">
                <label className="flex items-center gap-2">
                  Port
                  <input type="number" min={1} max={65535} aria-label="Port" className="w-24 rounded border border-line bg-surface-2 px-2 py-1 text-sm text-ink" value={f.port} onChange={(e) => set("port", Number(e.target.value))} />
                </label>
              </div>
              <p className="mt-1 text-xs text-ink-3">Unsigned, unencrypted LDAP is never used. Global Catalog: 3268 sealed, 3269 over LDAPS.</p>
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
          {saved && diag && diag.status !== "queued" && <Button onClick={() => onDone(saved)}>{diag.status === "succeeded" ? "Finish" : "Close (keep settings)"}</Button>}
          {saved && run && FINAL.has(run.status) && (
            <Button onClick={() => onDone(saved)}>{run.status === "succeeded" ? "Finish" : "Close (keep settings)"}</Button>
          )}
        </div>
        {diagFor && (
          <div className="pt-1">
            <h4 className="mb-1.5 text-[13px] font-semibold text-ink">Test on the collector</h4>
            <DiagnosticsResult d={diag ?? { command_id: diagFor.command, at: new Date().toISOString(), status: "queued", steps: [] }} />
            {saved && !source && <p className="mt-1.5 text-xs text-ink-3">The source is saved; the first full sync runs on schedule or with Sync now.</p>}
          </div>
        )}
        {runId && (
          <div className="pt-1">
            <RunResult run={run} error={runErr} />
            {saved && !source && <p className="mt-1.5 text-xs text-ink-3">The source is saved; the first full sync runs on schedule or with Sync now.</p>}
          </div>
        )}
      </form>
      <div className="min-w-0">
        <h3 className="mb-2 text-[13px] font-semibold text-ink">Optional · Manual pre-check (Test runs it on the collector for you)</h3>
        <CodeBox
          text={script}
          note="Read-only: resolves domain controllers, checks the port and the DC certificate, binds and reads 5 computer objects. It never writes anything."
        />
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------- status card
function sourceSubtitle(src: DirectorySource): string {
  const state = src.enabled ? "enabled" : "disabled";
  if (src.type === "entra") {
    const parts = src.config.scopes.map((s) => ({ users: "users", devices: "devices", intune: "Intune", roles: "admin roles" })[s]).join(", ");
    return `${DIRECTORY_NAME.entra} · tenant ${src.config.tenant_id} · ${state} · read by the server via Microsoft Graph · ${parts}`;
  }
  if (src.type === "google") {
    const parts = src.config.scopes.join(", ");
    return `${DIRECTORY_NAME.google} · impersonating ${src.config.admin_email} · ${state} · read by the server · ${parts}`;
  }
  const c = src.config;
  return (
    `${DIRECTORY_NAME.ad} · ${c.domain} · ${state} · ` +
    `${c.auth === "service_account" ? `service account ${src.credential_username_hint ?? ""}` : "computer account (Kerberos)"} · ` +
    `${c.security === "ldaps" ? "LDAPS" : c.security === "sealed" ? "Kerberos signed+sealed" : "StartTLS"} ${c.port}`
  );
}

function SourceCard({ src, isAdmin, onChanged }: { src: DirectorySource; isAdmin: boolean; onChanged: () => void }) {
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const runs = useApi(() => directoryApi.runs(src.id, 8), [src.id, src.last_sync_at, src.active_run?.status], src.active_run ? 5000 : undefined);
  const active = src.active_run;
  const cols = src.legacy_collectors
    ? src.collectors.map((c) => ({ name: c.hostname, healthy: c.healthy, dc: false }))
    : (src.dedicated_collectors ?? []).map((c) => ({ name: c.name, healthy: c.healthy, dc: c.is_domain_controller }));
  const healthy = cols.filter((c) => c.healthy).length;
  const server = src.collection === "server";
  const runText = server ? RUN_TEXT_SERVER : RUN_TEXT;

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

  const lastValue = active ? runText[active.status] : src.last_sync_status ? runText[src.last_sync_status] : "Not yet";
  const lastClass = active ? RUN_COLOR[active.status] : src.last_sync_status ? RUN_COLOR[src.last_sync_status] : "text-ink-3";
  const objectsSub = server ? `${src.computers_count.toLocaleString()} device records · ${src.users_count.toLocaleString()} users` : `${src.computers_count.toLocaleString()} computers · ${src.users_count.toLocaleString()} users`;

  return (
    <Card className="mb-4">
      <div className="flex flex-wrap items-start justify-between gap-4 px-1">
        <div className="flex min-w-0 items-center gap-3">
          <DirectoryMark size={32} type={src.type} />
          <div className="min-w-0">
            <h3 className="text-base font-semibold text-ink">{src.name}</h3>
            <div className="flex flex-wrap items-center gap-x-1.5 text-[13px] text-ink-3">
              <span aria-hidden className={`inline-block h-2 w-2 rounded-full ${src.enabled ? "bg-good" : "bg-ink-3"}`} />
              <span>{sourceSubtitle(src)}</span>
            </div>
          </div>
        </div>
        {isAdmin && (
          <div className="flex flex-wrap items-center gap-2">
            <Button onClick={() => setEditing((v) => !v)} disabled={editing || busy}>
              Edit
            </Button>
            <Button disabled={busy} onClick={() => void act(() => directoryApi.updateSource(src.id, { enabled: !src.enabled }))}>
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
                server ? `queued ${fmtAgo(active.queued_at)}` : `queued ${fmtAgo(active.queued_at)} on ${active.device_hostname ?? "collector"}`
              ) : (
                `${(active.computers_seen + active.users_seen).toLocaleString()} objects so far`
              )
            ) : src.last_sync_at ? (
              <span title={fmtTime(src.last_sync_at)}>{fmtAgo(src.last_sync_at)}</span>
            ) : undefined
          }
        />
        <StatCell label="Objects" value={(src.computers_count + src.users_count).toLocaleString()} sub={objectsSub} />
        <StatCell
          label="Next sync"
          value={!src.enabled ? "Off" : src.next_sync_at ? fmtUntil(src.next_sync_at) : "—"}
          sub={src.enabled ? `every ${fmtHours(src.config.interval_hours)}` : "source disabled"}
        />
        {server ? (
          <StatCell
            label="Collection"
            value="Server-side"
            sub={src.type === "entra" ? `app ${src.config.client_id}` : src.type === "google" ? `key ${src.config.key_id}… · ${src.config.service_account_email}` : undefined}
          />
        ) : (
          <StatCell
            label="Collectors"
            value={`${healthy} / ${cols.length} online`}
            valueClass={healthy === 0 ? "text-sev-high" : "text-ink"}
            sub={cols.map((c) => c.name + (c.dc ? " (DC)" : "")).join(", ")}
          />
        )}
      </div>
      {src.legacy_collectors && (
        <div role="note" className="mt-3 rounded border border-sev-medium/60 bg-sev-medium/10 px-3 py-2 text-sm">
          <strong>Legacy: uses endpoint agents</strong> — move to a dedicated collector (Edit → Switch to dedicated collectors). Objects, issues
          and history are kept.
        </div>
      )}
      {!server && cols.some((c) => c.dc) && (
        <div className="mt-3">
          <DcWarning name={cols.filter((c) => c.dc).map((c) => c.name).join(", ")} compact />
        </div>
      )}
      {server && Object.keys(src.scope_status).length > 0 && (
        <div className="mt-3 px-1">
          <ScopeChips status={src.scope_status} />
        </div>
      )}
      {src.last_sync_error && !active && (
        <p className={`mt-3 break-words px-1 text-xs ${src.last_sync_status === "succeeded" ? "text-sev-medium" : "text-sev-high"}`}>{src.last_sync_error}</p>
      )}
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
                  {runText[r.status]}
                  {r.truncated && " (capped)"}
                </span>
                <span className="text-ink-2">
                  {r.trigger === "test" && r.checks.length > 0
                    ? `${r.checks.filter((c) => c.status === "ok").length} of ${r.checks.length} checks passed`
                    : `${r.computers_seen.toLocaleString()} ${server ? "device records" : "computers"} · ${r.users_seen.toLocaleString()} users`}
                  {runDuration(r) && ` · ${runDuration(r)}`}
                  {r.device_hostname && ` · ${r.device_hostname}`}
                  {server && r.server && ` · ${r.server}`}
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
          <SourceForm
            type={src.type}
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

function SourceForm({ type, source, onDone, onCancel }: { type: DirectoryType; source: DirectorySource | null; onDone: (s: DirectorySource) => void; onCancel: () => void }) {
  if (type === "entra") return <EntraForm source={source?.type === "entra" ? source : null} onDone={onDone} onCancel={onCancel} />;
  if (type === "google") return <GoogleForm source={source?.type === "google" ? source : null} onDone={onDone} onCancel={onCancel} />;
  return <DirectoryForm source={source?.type === "ad" ? source : null} onDone={onDone} onCancel={onCancel} />;
}

// ----------------------------------------------------------------------------- add a directory
interface DirectoryChoice {
  type: DirectoryType;
  title: string;
  blurb: string;
  how: string;
  steps: string[];
}

const CHOICES: DirectoryChoice[] = [
  {
    type: "ad",
    title: "Active Directory",
    blurb: "On-prem domain: computers and users, read-only.",
    how: "Read by a collector you install inside your network (guided: domain, collector, test, save)",
    steps: ["Domain", "Collector", "Test", "Save"],
  },
  {
    type: "entra",
    title: "Microsoft Entra ID + Intune",
    blurb: "Cloud users, joined / hybrid / registered devices, Intune compliance and admin roles.",
    how: "Read by the server through Microsoft Graph, with your Azure connector's app",
    steps: ["Choose the Azure connector", "Run the permission script", "Test & save"],
  },
  {
    type: "google",
    title: "Google Workspace",
    blurb: "Users, admin roles, Windows / macOS / Linux endpoints, ChromeOS and mobile devices.",
    how: "Read by the server with a service account (domain-wide delegation, read-only scopes)",
    steps: ["Create the service account", "Authorise its client ID in the Admin console", "Upload the key, Test & save"],
  },
];

function DirectoryChooser({ onPick }: { onPick: (t: DirectoryType) => void }) {
  return (
    <div role="list" aria-label="Directory types" className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
      {CHOICES.map((c) => (
        <button
          key={c.type}
          type="button"
          role="listitem"
          onClick={() => onPick(c.type)}
          className="group flex min-w-0 items-start gap-3 rounded-xl border border-line bg-surface-2/40 p-4 text-left transition hover:border-accent hover:bg-accent/5 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <DirectoryMark size={36} type={c.type} />
          <span className="min-w-0">
            <span className="block text-sm font-semibold text-ink group-hover:text-accent">{c.title}</span>
            <span className="mt-0.5 block text-xs text-ink-2">{c.blurb}</span>
            <span className="mt-1.5 block text-[11px] text-ink-3">{c.how}</span>
          </span>
        </button>
      ))}
    </div>
  );
}

// ----------------------------------------------------------------------------- section
export function DirectoriesSection({ isAdmin }: { isAdmin: boolean }) {
  const sources = useApi(directoryApi.sources, [], 10000);
  const [adding, setAdding] = useState<DirectoryType | "choose" | null>(null);
  const list = sources.data ?? [];
  const loaded = sources.data !== null;
  useEffect(() => {
    if (loaded && window.location.hash === "#directories") document.getElementById("directories")?.scrollIntoView({ block: "start" });
  }, [loaded]);
  const choice = CHOICES.find((c) => c.type === adding);

  return (
    <section id="directories" aria-labelledby="directories-title" className="mt-6 scroll-mt-4">
      <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 id="directories-title" className="text-lg font-semibold tracking-tight text-ink">
            Directories
          </h2>
          <p className="mt-0.5 text-sm text-ink-2">
            Read-only discovery of the computers, devices and users in your directories. Find machines without an agent, stale and disabled
            accounts, non-compliant devices and risky admin accounts.
          </p>
        </div>
        {isAdmin && list.length > 0 && !adding && (
          <div className="flex flex-wrap gap-2">
            <Button onClick={() => setAdding("choose")}>Add directory</Button>
            <Link to="/it-assets/discovery?add=network-scan" className="rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line">
              Add network scan
            </Link>
          </div>
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
                  Connect on-prem Active Directory (read by a collector inside your network), Microsoft Entra ID + Intune or Google Workspace
                  (read by the server over their APIs). Everything is read-only. Discovery then shows machines without an agent, stale and disabled
                  accounts, and admins at risk.
                </p>
              </div>
            </div>
            {isAdmin ? (
              <Button variant="primary" onClick={() => setAdding("choose")}>
                Add directory
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
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 className="text-base font-semibold text-ink">{choice ? `Add ${choice.title}` : "Add a directory"}</h3>
              {choice ? (
                <Button onClick={() => setAdding("choose")}>Other directory type</Button>
              ) : (
                <Button onClick={() => setAdding(null)}>Cancel</Button>
              )}
            </div>
            {!choice ? (
              <div className="mt-3">
                <DirectoryChooser onPick={setAdding} />
              </div>
            ) : choice.type === "ad" ? (
              <div className="mt-3">
                <AdWizard
                  onCancel={() => setAdding(null)}
                  onDone={() => {
                    setAdding(null);
                    sources.reload();
                  }}
                />
              </div>
            ) : (
              <>
                <ol className="mb-4 mt-3 flex flex-wrap items-center gap-2.5" aria-label="Steps">
                  {choice.steps.map((t, i) => (
                    <li key={t} className="flex items-center gap-2 text-sm text-ink-2">
                      {i > 0 && <span aria-hidden className="text-ink-3">→</span>}
                      <span className="grid h-[22px] w-[22px] place-items-center rounded-full bg-accent/10 text-xs font-semibold text-accent">{i + 1}</span>
                      {t}
                    </li>
                  ))}
                </ol>
                <SourceForm
                  type={choice.type}
                  source={null}
                  onCancel={() => setAdding(null)}
                  onDone={() => {
                    setAdding(null);
                    sources.reload();
                  }}
                />
              </>
            )}
          </div>
        </Card>
      )}
      {list.map((s) => (
        <SourceCard key={s.id} src={s} isAdmin={isAdmin} onChanged={sources.reload} />
      ))}
    </section>
  );
}
