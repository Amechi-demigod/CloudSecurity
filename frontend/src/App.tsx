import type { ReactNode } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { api, type Role } from "./api";
import { useAuth } from "./auth/context";
import UserMenu from "./components/UserMenu";
import { useApi } from "./lib/useApi";
import AttackPaths from "./pages/AttackPaths";
import Connectors from "./pages/Connectors";
import DashboardPage from "./pages/Dashboard";
import Findings from "./pages/Findings";
import Inventory from "./pages/Inventory";
import Notifications from "./pages/Notifications";
import Login from "./pages/Login";
import Threats from "./pages/Threats";
import Vulnerabilities from "./pages/Vulnerabilities";
import AuditLog from "./pages/admin/AuditLog";
import Users from "./pages/admin/Users";

const NAV: { to: string; label: string; role?: Role }[] = [
  { to: "/", label: "Dashboard" },
  { to: "/inventory", label: "Inventory" },
  { to: "/findings", label: "Posture findings" },
  { to: "/vulnerabilities", label: "Vulnerabilities" },
  { to: "/threats", label: "Runtime threats" },
  { to: "/attack-paths", label: "Attack paths" },
  { to: "/connectors", label: "Connectors & scans" },
  { to: "/notifications", label: "Notifications", role: "analyst" },
];

const ADMIN_NAV = [
  { to: "/admin/users", label: "Users" },
  { to: "/admin/audit-log", label: "Audit log" },
];

function navClass({ isActive }: { isActive: boolean }) {
  return `block rounded px-3 py-2 text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
    isActive ? "bg-surface-2 text-ink" : "text-ink-2 hover:bg-surface-2 hover:text-ink"
  }`;
}

function FullPageSpinner() {
  return (
    <div className="flex h-full items-center justify-center" role="status" aria-live="polite">
      <span aria-hidden className="h-6 w-6 animate-spin rounded-full border-2 border-line border-t-accent" />
      <span className="sr-only">Loading…</span>
    </div>
  );
}

/** Redirects to /login (remembering where the user was going) when signed out. */
function RequireAuth({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const location = useLocation();
  if (user === undefined) return <FullPageSpinner />;
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  return <>{children}</>;
}

function NotPermitted() {
  return (
    <div className="mx-auto mt-16 max-w-md rounded-lg border border-line bg-surface-1 p-6 text-center">
      <h1 className="text-lg font-semibold">Not permitted</h1>
      <p className="mt-2 text-sm text-ink-2">Your role does not allow access to this page. Ask an administrator if you need it.</p>
    </div>
  );
}

function RequireRole({ role, children }: { role: Role; children: ReactNode }) {
  const { can } = useAuth();
  return can(role) ? <>{children}</> : <NotPermitted />;
}

function Shell() {
  const { can, forbidden, dismissForbidden } = useAuth();
  const { data: health, error } = useApi(api.health, [], 15000);
  return (
    <div className="flex h-full">
      <nav aria-label="Main" className="flex w-56 shrink-0 flex-col border-r border-line bg-surface-1">
        <div className="flex items-center gap-2 px-4 py-4">
          <img src="/shield.svg" alt="" className="h-6 w-6" />
          <div>
            <div className="text-sm font-semibold leading-tight">CloudSecurity</div>
            <div className="text-[11px] text-ink-3">Runtime-first CNAPP</div>
          </div>
        </div>
        <ul className="flex-1 space-y-0.5 overflow-y-auto px-2">
          {NAV.filter((n) => !n.role || can(n.role)).map((n) => (
            <li key={n.to}>
              <NavLink to={n.to} end={n.to === "/"} className={navClass}>
                {n.label}
              </NavLink>
            </li>
          ))}
          {can("admin") && (
            <>
              <li className="px-3 pb-1 pt-4 text-[11px] font-semibold uppercase tracking-wide text-ink-3">Administration</li>
              {ADMIN_NAV.map((n) => (
                <li key={n.to}>
                  <NavLink to={n.to} className={navClass}>
                    {n.label}
                  </NavLink>
                </li>
              ))}
            </>
          )}
        </ul>
        <div className="space-y-1 border-t border-line px-4 py-3 text-[11px] text-ink-3">
          {error && <div className="text-sev-critical">API unreachable</div>}
          {health && (
            <>
              <div>
                Mode: <span className="text-ink-2">{health.simulation_mode ? "Simulated data" : "Live"}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span
                  className={`inline-block h-2 w-2 rounded-full ${health.simulator_running ? "animate-pulse bg-good" : "bg-ink-3"}`}
                />
                Runtime feed {health.simulator_running ? "live" : "idle"}
              </div>
              <div>Azure connector: {health.azure_configured ? "configured" : "not configured"}</div>
            </>
          )}
        </div>
      </nav>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-end gap-3 border-b border-line bg-surface-1 px-6 py-2">
          <UserMenu />
        </header>
        <main className="min-w-0 flex-1 overflow-y-auto px-6 py-5">
          {forbidden && (
            <div role="alert" className="mb-4 flex items-start justify-between gap-3 rounded border border-sev-high/60 bg-sev-high/10 px-3 py-2 text-sm">
              <span>{forbidden}</span>
              <button className="text-ink-3 hover:text-ink" onClick={dismissForbidden} aria-label="Dismiss">
                ✕
              </button>
            </div>
          )}
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/inventory" element={<Inventory />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/threats" element={<Threats />} />
            <Route path="/attack-paths" element={<AttackPaths />} />
            <Route path="/connectors" element={<Connectors />} />
            <Route path="/notifications" element={<RequireRole role="analyst"><Notifications /></RequireRole>} />
            <Route path="/admin/users" element={<RequireRole role="admin"><Users /></RequireRole>} />
            <Route path="/admin/audit-log" element={<RequireRole role="admin"><AuditLog /></RequireRole>} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/*"
        element={
          <RequireAuth>
            <Shell />
          </RequireAuth>
        }
      />
    </Routes>
  );
}
