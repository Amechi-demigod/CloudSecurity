import { Download } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { getFile } from "../api";

export type ExportFormat = "csv" | "json";

/**
 * "Export" button with a CSV / JSON menu for a list page. `buildUrl(format)` returns the export endpoint with the
 * page's current search and filters, so the file matches what is on screen. The file is fetched with the session
 * cookie and saved through a temporary download link; a short confirmation (role=status) follows.
 */
export function ExportMenu({ buildUrl, noun, count }: { buildUrl: (format: ExportFormat) => string; noun: string; count: number | undefined }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => {
    if (!open) return;
    const click = (e: MouseEvent) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        button.current?.focus();
      }
    };
    document.addEventListener("mousedown", click);
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("mousedown", click);
      document.removeEventListener("keydown", key);
    };
  }, [open]);
  useEffect(() => () => window.clearTimeout(timer.current), []);

  const say = (ok: boolean, text: string) => {
    setMessage({ ok, text });
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setMessage(null), 5000);
  };

  const pick = async (format: ExportFormat) => {
    setOpen(false);
    button.current?.focus();
    setBusy(true);
    try {
      const { blob, filename } = await getFile(buildUrl(format));
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      say(true, `Downloaded ${filename}${count !== undefined ? ` · ${count.toLocaleString()} ${noun}` : ""}`);
    } catch (e) {
      say(false, e instanceof Error && e.message ? `Could not export: ${e.message}` : "Could not export. Please try again.");
    } finally {
      setBusy(false);
    }
  };

  const itemCls = "flex w-full flex-col items-start gap-0.5 rounded px-2.5 py-2 text-left hover:bg-surface-2 focus:bg-surface-2 focus:outline-none";
  return (
    <div ref={root} className="relative">
      <button
        ref={button}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        disabled={busy}
        onClick={() => setOpen(!open)}
        className="inline-flex items-center gap-1.5 rounded border border-line bg-surface-2 px-3 py-1.5 text-sm font-medium text-ink hover:bg-line focus:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-60"
      >
        <Download aria-hidden className="h-4 w-4" />
        {busy ? "Exporting…" : "Export ▾"}
      </button>
      {open && (
        <div role="menu" className="absolute right-0 z-20 mt-1 w-72 rounded-lg border border-line bg-surface-1 p-1.5 shadow-lg">
          <button type="button" role="menuitem" autoFocus onClick={() => pick("csv")} className={itemCls}>
            <b className="text-sm font-semibold text-ink">CSV</b>
            <span className="text-xs text-ink-3">For Excel or Google Sheets</span>
          </button>
          <button type="button" role="menuitem" onClick={() => pick("json")} className={itemCls}>
            <b className="text-sm font-semibold text-ink">JSON</b>
            <span className="text-xs text-ink-3">For scripts and other tools</span>
          </button>
          <p className="mt-1 border-t border-line px-2.5 pb-1 pt-2 text-xs text-ink-3">
            Exports {count !== undefined ? `the ${count.toLocaleString()}` : "all"} {noun} that match your search and filters, with
            all columns.
          </p>
        </div>
      )}
      <div role="status" className="absolute right-0 top-full z-10 mt-1 whitespace-nowrap">
        {message && (
          <span className={`inline-block rounded px-3 py-1.5 text-sm font-medium ${message.ok ? "bg-sev-low/15 text-sev-low" : "bg-sev-critical/15 text-sev-critical"}`}>{message.text}</span>
        )}
      </div>
    </div>
  );
}
