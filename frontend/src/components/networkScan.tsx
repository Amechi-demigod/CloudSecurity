// Add / edit a network scan: 1 Collector, 2 Subnets, 3 SNMP credentials, 4 Port check, 5 Schedule and pace.
// Scans run on a dedicated collector; everything is read-only (no logins, no brute force, no exploits).
import { AlertTriangle, Check, Info, Network, RefreshCw, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { collectorApi, type DedicatedCollector } from "../directoryApi";
import { errMsg } from "../lib/directory";
import { fmtAgo } from "../lib/format";
import { contains, countAddresses, parseTarget, size, splitList } from "../lib/netTargets";
import { useApi } from "../lib/useApi";
import { networkApi, PORT_CHIPS, type CredentialIn, type NetCredential, type NetRun, type NetScan, type Suggestion } from "../networkApi";
import { Button, ErrorNote, Field, Tag } from "./ui";

const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const inputCls =
  "block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink placeholder:text-ink-3 focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40";

function Section({ n, title, children, hint }: { n: number; title: string; children: ReactNode; hint?: ReactNode }) {
  return (
    <section className="rounded-lg border border-line bg-surface-1 p-4" aria-labelledby={`ns-${n}`}>
      <h3 id={`ns-${n}`} className="flex items-center gap-2 text-sm font-semibold text-ink">
        <span className="grid h-[22px] w-[22px] place-items-center rounded-full bg-accent/10 text-xs font-semibold text-accent">{n}</span>
        {title}
      </h3>
      {hint && <p className="mt-1 text-xs text-ink-3">{hint}</p>}
      <div className="mt-3">{children}</div>
    </section>
  );
}

function Notice({ tone, children }: { tone: "warn" | "info"; children: ReactNode }) {
  const cls = tone === "warn" ? "border-sev-high/60 bg-sev-high/10" : "border-accent/40 bg-accent/10";
  const Icon = tone === "warn" ? AlertTriangle : Info;
  return (
    <div role={tone === "warn" ? "alert" : "note"} className={`flex gap-2 rounded border px-3 py-2 text-sm text-ink ${cls}`}>
      <Icon aria-hidden className={`mt-0.5 h-4 w-4 shrink-0 ${tone === "warn" ? "text-sev-high" : "text-accent"}`} />
      <div className="min-w-0">{children}</div>
    </div>
  );
}

function Select({ id, label, value, onChange, options }: { id: string; label: string; value: string; onChange: (v: string) => void; options: { value: string; label: string }[] }) {
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-sm font-medium text-ink-2">
        {label}
      </label>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value)} className={inputCls}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}

function Segmented<T extends string>({ label, value, onChange, options }: { label: string; value: T; onChange: (v: T) => void; options: { value: T; label: string }[] }) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex overflow-hidden rounded border border-line">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          className={`px-3 py-1.5 text-sm font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent ${
            value === o.value ? "bg-accent text-white" : "bg-surface-2 text-ink-2 hover:bg-line"
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

const stateTone = (s: string) => (s === "online" ? "good" : s === "offline" ? "warn" : "default");

export function CollectorPick({ collectors, value, onChange }: { collectors: DedicatedCollector[]; value: string; onChange: (v: string) => void }) {
  const c = collectors.find((x) => x.id === value);
  return (
    <div>
      <label htmlFor="ns-collector" className="mb-1 block text-sm font-medium text-ink-2">
        Collector that runs the scan
      </label>
      <select id="ns-collector" value={value} onChange={(e) => onChange(e.target.value)} className={inputCls}>
        <option value="">Choose a collector…</option>
        {collectors.map((x) => (
          <option key={x.id} value={x.id}>
            {x.name} — {x.state} · v{x.version || "?"} · {x.last_ip ?? "no IP yet"}
          </option>
        ))}
      </select>
      {c && (
        <p className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-ink-3">
          <Tag tone={stateTone(c.state)}>{c.state}</Tag>
          <span>version {c.version || "unknown"}</span>
          <span>IP {c.last_ip ?? "unknown"}</span>
          {c.last_seen_at && <span>seen {fmtAgo(c.last_seen_at)}</span>}
        </p>
      )}
    </div>
  );
}

interface Row {
  subnet: string;
  name: string;
  by: string[];
  addresses: number;
  checked: boolean;
}

function toRow(s: Suggestion, checked: boolean): Row {
  return { subnet: s.subnet, name: s.name, by: s.suggested_by_all?.length ? s.suggested_by_all : [s.suggested_by], addresses: s.addresses, checked };
}

export default function NetworkScanWizard({ scan, onCancel, onDone }: { scan?: NetScan; onCancel: () => void; onDone: (scanId: string) => void }) {
  const collectors = useApi(collectorApi.list, []);
  const creds = useApi(networkApi.credentials, []);
  const [name, setName] = useState(scan?.name ?? "");
  const [collectorId, setCollectorId] = useState(scan?.collector_id ?? "");
  const [rows, setRows] = useState<Row[]>(() =>
    (scan?.targets ?? []).map((t) => ({ subnet: t, name: scan?.target_notes[t]?.replace(/^.*?: /, "") || "Added by hand", by: scan?.target_notes[t] ? [scan.target_notes[t]] : ["Added by hand"], addresses: 0, checked: true })),
  );
  const [subnetInput, setSubnetInput] = useState("");
  const [exclude, setExclude] = useState((scan?.exclude ?? []).join("\n"));
  const [tab, setTab] = useState<"v3" | "v2c">("v3");
  const [v3, setV3] = useState({ username: "", level: "authPriv", auth_proto: "SHA256", auth_password: "", priv_proto: "AES128", priv_password: "" });
  const [community, setCommunity] = useState("");
  const [selectedCreds, setSelectedCreds] = useState<string[]>(scan?.credential_ids ?? []);
  const [portCheck, setPortCheck] = useState(scan?.port_check ?? true);
  const [schedule, setSchedule] = useState<"daily" | "weekly" | "manual">(scan?.schedule ?? "daily");
  const [time, setTime] = useState(scan?.schedule_time ?? "02:00");
  const [weekday, setWeekday] = useState(scan?.schedule_weekday ?? 0);
  const [pace, setPace] = useState<20 | 64>(scan?.concurrency ?? 20);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [testIp, setTestIp] = useState("");
  const [testRun, setTestRun] = useState<NetRun | null>(null);
  const [credErr, setCredErr] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const list = collectors.data ?? [];
  const active = list.filter((c) => c.status === "active");
  const collector = list.find((c) => c.id === collectorId);
  // Suggestions of the chosen collector (the newest network_subnets result), polled while a refresh is pending.
  const sugg = useApi(() => (collectorId ? networkApi.suggestions(collectorId) : Promise.resolve([])), [collectorId], refreshing ? 3000 : undefined);
  const set = sugg.data?.[0];
  useEffect(() => {
    if (refreshing && set && !set.pending) setRefreshing(false);
  }, [refreshing, set]);

  // Newly arrived suggestions are listed (unchecked) after the rows already there.
  useEffect(() => {
    if (!set) return;
    setRows((prev) => {
      const have = new Set(prev.map((r) => r.subnet));
      const add = set.items.filter((i) => !have.has(i.subnet)).map((i) => toRow(i, false));
      return add.length ? [...prev, ...add] : prev;
    });
  }, [set]);

  // Poll the one-address test.
  useEffect(() => {
    if (!testRun || testRun.status === "succeeded" || testRun.status === "failed" || testRun.status === "cancelled") return;
    const t = setInterval(() => {
      networkApi.run(testRun.id).then(setTestRun, () => undefined);
    }, 3000);
    return () => clearInterval(t);
  }, [testRun]);

  const targets = rows.filter((r) => r.checked).map((r) => r.subnet);
  const excl = splitList(exclude);
  const count = useMemo(() => countAddresses(targets, excl), [targets.join(","), excl.join(",")]); // eslint-disable-line react-hooks/exhaustive-deps

  // Another collector sits inside one of the chosen subnets while this one does not: it sees them directly.
  const better = useMemo(() => {
    if (!collector?.last_ip || targets.length === 0) return null;
    if (targets.some((t) => contains(t, collector.last_ip!))) return null;
    for (const o of active) {
      if (o.id === collector.id || !o.last_ip) continue;
      const t = targets.find((x) => contains(x, o.last_ip!));
      if (t) return { other: o, subnet: t };
    }
    return null;
  }, [collector, active, targets.join(",")]); // eslint-disable-line react-hooks/exhaustive-deps

  function addSubnet() {
    const v = subnetInput.trim();
    if (!v) return;
    const p = parseTarget(v);
    if (typeof p === "string") return setErr(p);
    if (size(p) > 65536) return setErr(`${v} is larger than /16 (65,536 addresses): split it`);
    setErr(null);
    setRows((prev) => (prev.some((r) => r.subnet === v) ? prev.map((r) => (r.subnet === v ? { ...r, checked: true } : r)) : [...prev, { subnet: v, name: "Added by hand", by: ["Added by hand"], addresses: size(p), checked: true }]));
    setSubnetInput("");
  }

  async function refreshSuggestions() {
    if (!collectorId) return;
    setErr(null);
    try {
      await networkApi.refreshSuggestions(collectorId);
      setRefreshing(true);
      sugg.reload();
    } catch (e) {
      setErr(errMsg(e));
    }
  }

  async function saveCredential() {
    setCredErr(null);
    const body: CredentialIn =
      tab === "v3"
        ? {
            name: `SNMPv3 ${v3.username}`,
            version: "v3",
            username: v3.username,
            level: v3.level as "authPriv",
            auth_proto: v3.auth_proto as "SHA",
            auth_password: v3.auth_password,
            priv_proto: v3.level === "authPriv" ? (v3.priv_proto as "AES128") : undefined,
            priv_password: v3.level === "authPriv" ? v3.priv_password : "",
          }
        : { name: "SNMPv2c community", version: "v2c", community };
    try {
      const c = await networkApi.createCredential(body);
      setSelectedCreds((p) => [...p, c.id]);
      setV3({ ...v3, auth_password: "", priv_password: "" });
      setCommunity("");
      creds.reload();
    } catch (e) {
      setCredErr(errMsg(e));
    }
  }

  async function removeCredential(c: NetCredential) {
    try {
      await networkApi.deleteCredential(c.id);
      setSelectedCreds((p) => p.filter((x) => x !== c.id));
      creds.reload();
    } catch (e) {
      setCredErr(errMsg(e));
    }
  }

  const notes = Object.fromEntries(rows.filter((r) => r.checked && r.by[0] !== "Added by hand").map((r) => [r.subnet, r.by[0]]));
  const body = () => ({
    name: name.trim() || `Network scan ${new Date().toLocaleDateString()}`,
    collector_id: collectorId,
    targets,
    exclude: excl,
    target_notes: notes,
    port_check: portCheck,
    concurrency: pace,
    credential_ids: selectedCreds,
    schedule,
    schedule_time: time,
    schedule_weekday: weekday,
  });
  const invalid = !collectorId || targets.length === 0 || !!count.error;

  async function save(runNow: boolean) {
    setBusy(true);
    setErr(null);
    try {
      if (scan) {
        await networkApi.editScan(scan.id, body());
        if (runNow) await networkApi.runScan(scan.id);
        onDone(scan.id);
      } else {
        const r = await networkApi.createScan({ ...body(), run_now: runNow });
        if (r.run_error) {
          setErr(`The scan is saved, but did not start: ${r.run_error}`);
        }
        onDone(r.id);
      }
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  async function test() {
    setBusy(true);
    setErr(null);
    setTestRun(null);
    try {
      setTestRun(await networkApi.test({ collector_id: collectorId, address: testIp.trim(), credential_ids: selectedCreds, port_check: portCheck }));
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  const credList = creds.data ?? [];
  const v3Valid = tab === "v3" ? v3.username && v3.auth_password.length >= 8 && (v3.level === "authNoPriv" || v3.priv_password.length >= 8) : community.length > 0;

  return (
    <div className="space-y-4">
      <p className="max-w-3xl text-sm text-ink-2">
        A network scan finds the devices on your networks, identifies switches, firewalls, access points and printers, and checks their firmware for known vulnerabilities.
        It is <strong className="font-semibold text-ink">read-only</strong>: it never logs in to a device, never guesses passwords and never tries an exploit.
      </p>
      <ErrorNote error={err} />

      <Section n={1} title="Collector" hint="The scan runs from a dedicated collector inside your network, so it needs to be able to reach the subnets below.">
        {collectors.data && active.length === 0 ? (
          <Notice tone="warn">No collector is enrolled. Add one under Connectors &amp; scans, then come back.</Notice>
        ) : (
          <div className="space-y-3">
            <div className="max-w-xl">
              <Field id="ns-name" label="Scan name" value={name} onChange={(e) => setName(e.target.value)} placeholder="HQ and branch networks" />
            </div>
            <div className="max-w-xl">
              <CollectorPick collectors={active} value={collectorId} onChange={setCollectorId} />
            </div>
            {better && (
              <Notice tone="warn">
                <strong>{better.other.name}</strong> ({better.other.last_ip}) sits inside {better.subnet}, while {collector?.name} ({collector?.last_ip}) does not. A collector on the
                same network sees devices directly (ARP, MAC addresses); from another network only routed hosts answer. Consider choosing {better.other.name}.
              </Notice>
            )}
          </div>
        )}
      </Section>

      <Section n={2} title="Subnets" hint="Suggested from your AD Sites and DHCP scopes. Tick the ones to scan, or add your own.">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <p className="text-xs text-ink-3">
            {set?.at ? `Suggestions read ${fmtAgo(set.at)} by ${set.collector_name}.` : collectorId ? "No suggestions yet for this collector." : "Choose a collector to see suggestions."}
            {set?.errors?.length ? <span className="ml-1 text-sev-high">{set.errors.join(" ")}</span> : null}
          </p>
          <Button onClick={() => void refreshSuggestions()} disabled={!collectorId || refreshing || collector?.state !== "online"} title="Ask the collector to read AD Sites and DHCP scopes">
            <span className="inline-flex items-center gap-1.5">
              <RefreshCw aria-hidden className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
              {refreshing ? "Reading…" : "Refresh suggestions"}
            </span>
          </Button>
        </div>
        <div className="overflow-x-auto rounded border border-line">
          <table className="w-full min-w-[34rem] text-left text-sm">
            <thead className="bg-surface-2 text-[11px] uppercase tracking-wide text-ink-3">
              <tr>
                <th className="w-8 px-3 py-2">
                  <span className="sr-only">Scan</span>
                </th>
                <th className="px-3 py-2">Subnet</th>
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Suggested by</th>
                <th className="px-3 py-2 text-right">Addresses</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rows.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-4 text-center text-xs text-ink-3">
                    No subnets yet. Refresh the suggestions or add a subnet below.
                  </td>
                </tr>
              )}
              {rows.map((r) => (
                <tr key={r.subnet}>
                  <td className="px-3 py-2">
                    <input type="checkbox" aria-label={`Scan ${r.subnet}`} checked={r.checked} onChange={(e) => setRows((p) => p.map((x) => (x.subnet === r.subnet ? { ...x, checked: e.target.checked } : x)))} />
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-ink">{r.subnet}</td>
                  <td className="px-3 py-2 text-ink-2">{r.name}</td>
                  <td className="px-3 py-2">
                    <span className="flex flex-wrap gap-1">
                      {r.by.map((b) => (
                        <Tag key={b} tone={b === "Added by hand" ? "default" : "accent"}>
                          {b}
                        </Tag>
                      ))}
                    </span>
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-right text-ink-2">{r.addresses ? r.addresses.toLocaleString() : (() => { const p = parseTarget(r.subnet); return typeof p === "string" ? "?" : size(p).toLocaleString(); })()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-3 flex flex-wrap items-end gap-2">
          <div className="min-w-[14rem] flex-1">
            <Field id="ns-add" label="Add a subnet or range" value={subnetInput} onChange={(e) => setSubnetInput(e.target.value)} placeholder="10.20.0.0/24 or 10.30.0.10-10.30.0.50" onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addSubnet())} />
          </div>
          <Button onClick={addSubnet} disabled={!subnetInput.trim()}>
            Add
          </Button>
        </div>
        <div className="mt-3">
          <label htmlFor="ns-exclude" className="mb-1 block text-sm font-medium text-ink-2">
            Never scan these addresses
          </label>
          <textarea id="ns-exclude" rows={2} value={exclude} onChange={(e) => setExclude(e.target.value)} placeholder="10.10.1.40, 10.10.20.200-10.10.20.220" className={inputCls} />
          <p className="mt-1 text-xs text-ink-3">
            Add fragile equipment here (old PLCs, medical devices, lab gear): addresses, CIDRs or ranges, separated by commas or new lines. A single subnet or range can be at most /16 (65,536 addresses); one
            scan at most 262,144.
          </p>
        </div>
        <p className={`mt-2 text-sm ${count.error ? "text-sev-critical" : "text-ink-2"}`} aria-live="polite">
          {count.error ?? `${count.total.toLocaleString()} addresses will be scanned.`}
        </p>
      </Section>

      <Section n={3} title="SNMP credentials" hint="Used to read the device name, model, firmware and interfaces. They are stored encrypted and are never shown again.">
        <div className="mb-3">
          <Segmented label="SNMP version" value={tab} onChange={setTab} options={[{ value: "v3", label: "SNMPv3 (recommended)" }, { value: "v2c", label: "SNMPv2c" }]} />
        </div>
        {tab === "v3" ? (
          <div className="grid max-w-3xl grid-cols-1 gap-3 sm:grid-cols-2">
            <Field id="v3-user" label="Username" value={v3.username} autoComplete="off" onChange={(e) => setV3({ ...v3, username: e.target.value })} />
            <Select id="v3-level" label="Security level" value={v3.level} onChange={(v) => setV3({ ...v3, level: v })} options={[{ value: "authPriv", label: "authPriv (authentication + encryption)" }, { value: "authNoPriv", label: "authNoPriv (authentication only)" }]} />
            <Select id="v3-auth" label="Authentication protocol" value={v3.auth_proto} onChange={(v) => setV3({ ...v3, auth_proto: v })} options={["SHA", "SHA256", "SHA512"].map((x) => ({ value: x, label: x }))} />
            <Field id="v3-authpw" label="Authentication password" type="password" autoComplete="new-password" value={v3.auth_password} onChange={(e) => setV3({ ...v3, auth_password: e.target.value })} hint="At least 8 characters." />
            {v3.level === "authPriv" && (
              <>
                <Select id="v3-priv" label="Privacy protocol" value={v3.priv_proto} onChange={(v) => setV3({ ...v3, priv_proto: v })} options={["AES128", "AES256"].map((x) => ({ value: x, label: x }))} />
                <Field id="v3-privpw" label="Privacy password" type="password" autoComplete="new-password" value={v3.priv_password} onChange={(e) => setV3({ ...v3, priv_password: e.target.value })} hint="At least 8 characters." />
              </>
            )}
          </div>
        ) : (
          <div className="max-w-xl space-y-3">
            <Field id="v2c" label="Community string" type="password" autoComplete="new-password" value={community} onChange={(e) => setCommunity(e.target.value)} />
            <Notice tone="warn">
              SNMPv2c sends the community string in clear text. Prefer SNMPv3 wherever the device supports it. The default communities <code>public</code> and <code>private</code> are tried
              automatically and reported as a finding; you do not need to enter them.
            </Notice>
          </div>
        )}
        <ErrorNote error={credErr} />
        <div className="mt-3">
          <Button onClick={() => void saveCredential()} disabled={!v3Valid}>
            Save credential
          </Button>
        </div>
        <div className="mt-4">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-ink-3">Saved credentials</h4>
          {credList.length === 0 ? (
            <p className="mt-1 text-sm text-ink-3">None yet. Without credentials the scan can still find devices by ping, ARP and open ports.</p>
          ) : (
            <ul className="mt-1 divide-y divide-line rounded border border-line">
              {credList.map((c) => (
                <li key={c.id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-sm">
                  <label className="flex min-w-0 items-center gap-2">
                    <input type="checkbox" checked={selectedCreds.includes(c.id)} onChange={(e) => setSelectedCreds((p) => (e.target.checked ? [...p, c.id] : p.filter((x) => x !== c.id)))} />
                    <span className="min-w-0 break-words font-medium text-ink">{c.name}</span>
                    <Tag tone={c.version === "v3" ? "good" : "warn"}>{c.version === "v3" ? "SNMPv3" : "SNMPv2c"}</Tag>
                    {c.version === "v3" && <span className="text-xs text-ink-3">{c.username_hint} · {c.level} · {c.auth_proto}{c.priv_proto && c.priv_proto !== "none" ? ` / ${c.priv_proto}` : ""}</span>}
                    <span className="text-xs text-ink-3">secret stored, not shown</span>
                  </label>
                  <button type="button" aria-label={`Delete ${c.name}`} onClick={() => void removeCredential(c)} className="rounded p-1 text-ink-3 hover:text-sev-critical focus:outline-none focus-visible:ring-2 focus-visible:ring-accent">
                    <Trash2 aria-hidden className="h-4 w-4" />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </Section>

      <Section n={4} title="Port check" hint="A light connection test of ten well-known ports on every device that answers. No data is sent beyond reading the first bytes a service offers.">
        <label className="flex items-center gap-2 text-sm font-medium text-ink">
          <input type="checkbox" checked={portCheck} onChange={(e) => setPortCheck(e.target.checked)} /> Check these ports
        </label>
        <div className="mt-2 flex flex-wrap gap-1.5" aria-label="Ports checked">
          {PORT_CHIPS.map((p) => (
            <span key={p} className={`rounded border px-2 py-0.5 font-mono text-xs ${portCheck ? "border-accent/50 text-ink" : "border-line text-ink-3 line-through"}`}>
              {p}
            </span>
          ))}
        </div>
      </Section>

      <Section n={5} title="Schedule and pace">
        <div className="flex flex-wrap items-end gap-4">
          <div>
            <div className="mb-1 text-sm font-medium text-ink-2">How often</div>
            <Segmented label="Schedule" value={schedule} onChange={setSchedule} options={[{ value: "daily", label: "Daily" }, { value: "weekly", label: "Weekly" }, { value: "manual", label: "Manual" }]} />
          </div>
          {schedule !== "manual" && (
            <>
              {schedule === "weekly" && <Select id="ns-day" label="Day" value={String(weekday)} onChange={(v) => setWeekday(Number(v))} options={WEEKDAYS.map((d, i) => ({ value: String(i), label: d }))} />}
              <div>
                <label htmlFor="ns-time" className="mb-1 block text-sm font-medium text-ink-2">
                  Time (UTC)
                </label>
                <input id="ns-time" type="time" value={time} onChange={(e) => setTime(e.target.value)} className={inputCls} />
              </div>
            </>
          )}
          <div>
            <div className="mb-1 text-sm font-medium text-ink-2">Pace</div>
            <Segmented label="Pace" value={String(pace) as "20" | "64"} onChange={(v) => setPace(v === "20" ? 20 : 64)} options={[{ value: "20", label: "Gentle · 20 at a time" }, { value: "64", label: "Normal · 64 at a time" }]} />
          </div>
        </div>
        <div className="mt-3">
          <Notice tone="info">
            Tell your network team before the first scan: they may see the scan in firewall and IDS logs. It will come from{" "}
            <strong>{collector ? `${collector.name}${collector.last_ip ? ` (${collector.last_ip})` : ""}` : "the collector you chose"}</strong>. Use Gentle for older equipment.
          </Notice>
        </div>
      </Section>

      {testRun && (
        <div className="rounded-lg border border-line bg-surface-1 p-4 text-sm" aria-live="polite">
          <div className="flex flex-wrap items-center gap-2">
            <Network aria-hidden className="h-4 w-4 text-accent" />
            <strong className="text-ink">Test of {testRun.targets[0]?.replace("/32", "")}</strong>
            <Tag tone={testRun.status === "succeeded" ? "good" : testRun.status === "failed" ? "critical" : "default"}>{testRun.status}</Tag>
          </div>
          <p className="mt-1 text-ink-2">
            {testRun.status === "queued" && "Queued: the collector picks it up within about a minute…"}
            {testRun.status === "running" && "Scanning…"}
            {testRun.status === "succeeded" && (testRun.devices_seen > 0 ? "The address answered. See it in Network devices." : "The address did not answer (check the collector can reach it).")}
            {testRun.status === "failed" && (testRun.error ?? "The test failed.")}
          </p>
        </div>
      )}

      <div className="flex flex-wrap items-end justify-between gap-3 border-t border-line pt-4">
        <div className="flex flex-wrap items-end gap-2">
          <div className="w-44">
            <Field id="ns-test" label="Test on one address" value={testIp} onChange={(e) => setTestIp(e.target.value)} placeholder="10.10.1.1" />
          </div>
          <Button onClick={() => void test()} disabled={busy || !collectorId || !testIp.trim() || collector?.state !== "online"} title="Scan only this address with the settings above">
            Test on one address
          </Button>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button onClick={onCancel}>Cancel</Button>
          <Button onClick={() => void save(false)} disabled={busy || invalid}>
            Save
          </Button>
          <Button variant="primary" onClick={() => void save(true)} disabled={busy || invalid || collector?.state !== "online"} title={collector?.state !== "online" ? "The collector is not online" : undefined}>
            <span className="inline-flex items-center gap-1.5">
              <Check aria-hidden className="h-4 w-4" />
              Save and scan now
            </span>
          </Button>
        </div>
      </div>
    </div>
  );
}
