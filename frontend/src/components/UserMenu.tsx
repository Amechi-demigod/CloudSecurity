import { useEffect, useId, useRef, useState, type FormEvent, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError } from "../api";
import { ROLE_LABEL, useAuth } from "../auth/context";
import { Button, Field, Modal } from "./ui";

const MIN_PASSWORD = 12;

export function ChangePasswordDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { changePassword } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  function close() {
    setCurrent("");
    setNext("");
    setConfirm("");
    setError(null);
    setDone(false);
    onClose();
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (next.length < MIN_PASSWORD) return setError(`The new password must be at least ${MIN_PASSWORD} characters.`);
    if (next !== confirm) return setError("The new passwords do not match.");
    setBusy(true);
    try {
      await changePassword(current, next);
      setDone(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open={open} onClose={close} title="Change password">
      {done ? (
        <div className="space-y-4">
          <p role="status" className="text-sm text-ink">
            Your password was changed. Other sessions for your account have been signed out.
          </p>
          <div className="flex justify-end">
            <Button variant="primary" onClick={close}>
              Done
            </Button>
          </div>
        </div>
      ) : (
        <form className="space-y-3" onSubmit={submit}>
          {error && (
            <div role="alert" className="rounded border border-sev-critical/60 bg-sev-critical/10 px-3 py-2 text-sm">
              {error}
            </div>
          )}
          <Field label="Current password" id="cp-current" type="password" autoComplete="current-password" required
            value={current} onChange={(e) => setCurrent(e.target.value)} />
          <Field label="New password" id="cp-new" type="password" autoComplete="new-password" required
            minLength={MIN_PASSWORD} hint={`At least ${MIN_PASSWORD} characters.`}
            value={next} onChange={(e) => setNext(e.target.value)} />
          <Field label="Confirm new password" id="cp-confirm" type="password" autoComplete="new-password" required
            value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          <div className="flex justify-end gap-2 pt-2">
            <Button onClick={close}>Cancel</Button>
            <Button type="submit" variant="primary" disabled={busy || !current || !next || !confirm}>
              {busy ? "Saving…" : "Change password"}
            </Button>
          </div>
        </form>
      )}
    </Modal>
  );
}

function initials(name: string, email: string) {
  const src = name.trim() || email;
  const parts = src.split(/[\s@._-]+/).filter(Boolean);
  return ((parts[0]?.[0] ?? "?") + (parts[1]?.[0] ?? "")).toUpperCase();
}

export default function UserMenu() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [pwOpen, setPwOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const menuId = useId();

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        buttonRef.current?.focus();
      }
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    rootRef.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus();
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  if (!user) return null;

  function onMenuKey(e: ReactKeyboardEvent) {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const items = Array.from(rootRef.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? []);
    const i = items.indexOf(document.activeElement as HTMLElement);
    const nextIdx = e.key === "ArrowDown" ? (i + 1) % items.length : (i - 1 + items.length) % items.length;
    items[nextIdx]?.focus();
  }

  async function signOut() {
    setOpen(false);
    await logout();
    navigate("/login", { replace: true });
  }

  return (
    <div className="relative" ref={rootRef}>
      <button
        ref={buttonRef}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={menuId}
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 rounded-md border border-transparent px-2 py-1 text-left hover:border-line hover:bg-surface-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        <span
          aria-hidden
          className="flex h-7 w-7 items-center justify-center rounded-full bg-accent/20 text-xs font-semibold text-accent"
        >
          {initials(user.name, user.email)}
        </span>
        <span className="hidden min-w-0 sm:block">
          <span className="block max-w-[12rem] truncate text-sm leading-tight text-ink">{user.name || user.email}</span>
          <span className="block text-[11px] leading-tight text-ink-3">{ROLE_LABEL[user.role]}</span>
        </span>
        <span aria-hidden className="text-xs text-ink-3">
          ▾
        </span>
        <span className="sr-only">Account menu for {user.email}</span>
      </button>
      {open && (
        <div
          id={menuId}
          role="menu"
          aria-label="Account"
          onKeyDown={onMenuKey}
          className="absolute right-0 z-30 mt-2 w-60 overflow-hidden rounded-lg border border-line bg-surface-1 shadow-2xl"
        >
          <div className="border-b border-line px-3 py-2.5">
            <div className="truncate text-sm font-medium text-ink">{user.name || user.email}</div>
            <div className="truncate text-xs text-ink-3">{user.email}</div>
            <div className="mt-1 inline-block rounded border border-accent/60 px-1.5 py-0.5 text-[11px] text-accent">
              {ROLE_LABEL[user.role]}
            </div>
          </div>
          <button
            role="menuitem"
            type="button"
            className="block w-full px-3 py-2 text-left text-sm text-ink-2 hover:bg-surface-2 hover:text-ink focus:bg-surface-2 focus:text-ink focus:outline-none"
            onClick={() => {
              setOpen(false);
              setPwOpen(true);
            }}
          >
            Change password
          </button>
          <button
            role="menuitem"
            type="button"
            className="block w-full px-3 py-2 text-left text-sm text-ink-2 hover:bg-surface-2 hover:text-ink focus:bg-surface-2 focus:text-ink focus:outline-none"
            onClick={() => {
              setOpen(false);
              navigate("/account/security");
            }}
          >
            Security (two-step verification)
          </button>
          <button
            role="menuitem"
            type="button"
            className="block w-full border-t border-line px-3 py-2 text-left text-sm text-ink-2 hover:bg-surface-2 hover:text-ink focus:bg-surface-2 focus:text-ink focus:outline-none"
            onClick={signOut}
          >
            Sign out
          </button>
        </div>
      )}
      <ChangePasswordDialog open={pwOpen} onClose={() => setPwOpen(false)} />
    </div>
  );
}
