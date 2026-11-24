// MSP staff only (docs/MSP.md): the bar shown while working inside a client, and the client switcher in the top
// bar. Nothing here renders for a client's own users: both are driven by `homeOrganization`, which /api/auth/me
// returns to MSP staff only.
import { Building2, Check, ChevronDown, Search } from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError } from "../api";
import { useAuth } from "../auth/context";
import { useApi } from "../lib/useApi";
import { riskSummary, switchClient } from "../lib/msp";
import { mspApi } from "../mspApi";

/** Dark bar above the top bar while MSP staff work inside a client. */
export function ClientBar() {
  const { organization, homeOrganization, actingAsClient } = useAuth();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  if (!homeOrganization || !actingAsClient || !organization) return null;
  return (
    <div role="region" aria-label="Client workspace" data-print="hide" className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 bg-slate-900 px-4 py-2 text-sm text-slate-100 md:px-6">
      <p>
        You are working in <b className="font-semibold text-white">{organization.name}</b> for {homeOrganization.name}. Only your team sees this bar.
      </p>
      <div className="flex items-center gap-3">
        {err && <span role="alert" className="text-xs text-red-300">{err}</span>}
        <button
          type="button"
          disabled={busy}
          onClick={() => {
            setBusy(true);
            setErr(null);
            switchClient(null).catch((e) => {
              setErr(e instanceof ApiError ? e.message : String(e));
              setBusy(false);
            });
          }}
          className="rounded font-medium text-white underline underline-offset-2 hover:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-white disabled:opacity-60"
        >
          Back to all clients
        </button>
      </div>
    </div>
  );
}

const ITEM = "flex w-full items-start gap-2 rounded px-3 py-2 text-left text-sm hover:bg-surface-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-60";

/** The organisation name in the top bar, as a button that opens a client switcher (MSP staff only). */
export function ClientSwitcher() {
  const { organization, homeOrganization, actingAsClient } = useAuth();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const search = useRef<HTMLInputElement>(null);
  const panel = useId();
  const navigate = useNavigate();
  // Loaded when the menu is first opened, then refreshed each time it opens.
  const { data, error, loading, reload } = useApi(() => (open ? mspApi.overviewAll() : Promise.resolve(null)), [open]);

  useEffect(() => {
    if (!open) return;
    search.current?.focus();
    const down = (e: MouseEvent) => !root.current?.contains(e.target as Node) && setOpen(false);
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        button.current?.focus();
      }
    };
    const focusOut = (e: FocusEvent) => {
      if (e.relatedTarget && !root.current?.contains(e.relatedTarget as Node)) setOpen(false);
    };
    const el = root.current;
    document.addEventListener("mousedown", down);
    document.addEventListener("keydown", key);
    el?.addEventListener("focusout", focusOut);
    return () => {
      document.removeEventListener("mousedown", down);
      document.removeEventListener("keydown", key);
      el?.removeEventListener("focusout", focusOut);
    };
  }, [open]);

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data ?? []).filter((c) => !needle || c.name.toLowerCase().includes(needle));
  }, [data, q]);

  if (!organization || !homeOrganization) return null;

  async function go(id: string | null) {
    setBusy(id ?? "home");
    setErr(null);
    try {
      await switchClient(id);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : String(e));
      setBusy(null);
    }
  }

  return (
    <div ref={root} className="relative mr-auto min-w-0">
      <button
        ref={button}
        type="button"
        aria-haspopup="true"
        aria-expanded={open}
        aria-controls={open ? panel : undefined}
        onClick={() => {
          setOpen((o) => !o);
          setQ("");
          setErr(null);
        }}
        className="flex max-w-full items-center gap-2 rounded-lg px-2 py-1 text-sm hover:bg-surface-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        <span aria-hidden className="flex h-6 w-6 shrink-0 items-center justify-center rounded bg-surface-2 text-xs font-semibold text-ink-2">
          {organization.name.slice(0, 1).toUpperCase()}
        </span>
        <span className="truncate font-medium text-ink">{organization.name}</span>
        <span className="sr-only">(current organisation, switch client)</span>
        <ChevronDown aria-hidden className="h-3.5 w-3.5 shrink-0 text-ink-3" />
      </button>
      {open && (
        <div id={panel} role="group" aria-label="Switch client" className="absolute left-0 z-30 mt-1 w-80 max-w-[calc(100vw-2rem)] rounded-lg border border-line bg-surface-1 p-2 shadow-xl">
          <label className="relative block">
            <span className="sr-only">Find a client</span>
            <Search aria-hidden className="pointer-events-none absolute left-2 top-2 h-4 w-4 text-ink-3" />
            <input
              ref={search}
              type="search"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Find a client"
              className="h-8 w-full rounded border border-line bg-surface-2 pl-8 pr-2 text-sm text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            />
          </label>
          {err && <p role="alert" className="mt-2 px-1 text-xs text-sev-critical">{err}</p>}
          <button type="button" className={`${ITEM} mt-1`} disabled={busy !== null} onClick={() => (actingAsClient ? void go(null) : (setOpen(false), navigate("/")))}>
            <Building2 aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-ink-3" />
            <span className="min-w-0 flex-1">
              <span className="block font-medium text-ink">{homeOrganization.name}</span>
              <span className="block text-xs text-ink-3">Your partner account · all clients</span>
            </span>
            {!actingAsClient && <Check aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-accent" />}
            {!actingAsClient && <span className="sr-only">(current)</span>}
          </button>
          <div className="mt-1 border-t border-line pt-1">
            <h3 className="px-3 py-1 text-xs font-medium uppercase tracking-wide text-ink-3">Clients</h3>
            {loading && !data && <p role="status" className="px-3 py-2 text-xs text-ink-3">Loading clients…</p>}
            {error && !data && (
              <div role="alert" className="px-3 py-2 text-xs text-sev-critical">
                Could not load clients. {error}{" "}
                <button type="button" className="underline" onClick={() => void reload()}>Retry</button>
              </div>
            )}
            {data && data.length === 0 && <p className="px-3 py-2 text-xs text-ink-3">No clients yet.</p>}
            {data && data.length > 0 && shown.length === 0 && <p className="px-3 py-2 text-xs text-ink-3">No client matches “{q}”.</p>}
            <ul className="max-h-64 overflow-y-auto">
              {shown.slice(0, 50).map((c) => {
                const current = actingAsClient && c.id === organization.id;
                return (
                  <li key={c.id}>
                    <button type="button" className={ITEM} disabled={busy !== null || c.status === "suspended"} aria-current={current ? "true" : undefined} onClick={() => (current ? setOpen(false) : void go(c.id))}>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate font-medium text-ink">{c.name}</span>
                        <span className="block truncate text-xs text-ink-3">{riskSummary(c)}</span>
                      </span>
                      {current && <Check aria-hidden className="mt-0.5 h-4 w-4 shrink-0 text-accent" />}
                      {current && <span className="sr-only">(current)</span>}
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
          {data && (
            <div className="mt-1 border-t border-line pt-1">
              <button type="button" className={`${ITEM} text-accent`} disabled={busy !== null} onClick={() => (actingAsClient ? void go(null) : (setOpen(false), navigate("/")))}>
                See all {data.length} {data.length === 1 ? "client" : "clients"}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
