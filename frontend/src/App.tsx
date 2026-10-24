import type { ReactNode } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { api, type Role } from "./api";
import { useAuth } from "./auth/context";
import UserMenu from "./components/UserMenu";
import { useApi } from "./lib/useApi";
import Approvals from "./pages/Approvals";
import AssetDetail from "./pages/assets/AssetDetail";
import Assets from "./pages/assets/Assets";
import AssetSettings from "./pages/assets/AssetSettings";
import Offboarding from "./pages/assets/Offboarding";
import AttackPaths from "./pages/AttackPaths";
import Connectors from "./pages/Connectors";
import AgentUpdates from "./pages/devices/AgentUpdates";
import DeviceDetail from "./pages/devices/DeviceDetail";
import Devices from "./pages/devices/Devices";
import Enrollment from "./pages/devices/Enrollment";
import Scripts from "./pages/devices/Scripts";
import DashboardPage from "./pages/Dashboard";
import Exposure from "./pages/Exposure";
import Findings from "./pages/Findings";
import Inventory from "./pages/Inventory";
import Notifications from "./pages/Notifications";
import Login from "./pages/Login";
import Security from "./pages/Security";
import Threats from "./pages/Threats";
import Vulnerabilities from "./pages/Vulnerabilities";
import AuditLog from "./pages/admin/AuditLog";
import OrganizationPage from "./pages/admin/Organization";
import Users from "./pages/admin/Users";
import Invite from "./pages/Invite";
import Organizations from "./pages/platform/Organizations";

const NAV: { to: string; label: string; role?: Role }[] = [
  { to: "/", label: "Dashboard" },
  { to: "/inventory", label: "Inventory" },
  { to: "/devices", label: "Devices" },
  { to: "/it-assets", label: "IT assets" },
  { to: "/findings", label: "Posture findings" },
  { to: "/vulnerabilities", label: "Vulnerabilities" },
  { to: "/threats", label: "Runtime threats" },
  { to: "/exposure", label: "Exposure" },
  { to: "/attack-paths", label: "Attack paths" },
  { to: "/connectors", label: "Connectors & scans" },
  { to: "/notifications", label: "Notifications", role: "analyst" },
];

const ADMIN_NAV: { to: string; label: string; badge?: "approvals" }[] = [
  { to: "/approvals", label: "Approvals", badge: "approvals" },
  { to: "/admin/organization", label: "Organisation" },
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

function RequirePlatformAdmin({ children }: { children: ReactNode }) {
  const { platformAdmin } = useAuth();
  return platformAdmin ? <>{children}</> : <NotPermitted />;
}

/** Which organisation the session works in (every page shows only its data). */
function OrgIndicator() {
  const { organization } = useAuth();
  if (!organization) return null;
  return (
    <div className="mr-auto flex min-w-0 items-center gap-2 text-sm" title={`You are working in ${organization.name}`}>
      <span aria-hidden className="flex h-6 w-6 items-center justify-center rounded bg-surface-2 text-xs font-semibold text-ink-2">
        {organization.name.slice(0, 1).toUpperCase()}
      </span>
      <span className="truncate font-medium text-ink">{organization.name}</span>
      <span className="sr-only">(current organisation)</span>
    </div>
  );
}

function Shell() {
  const { can, forbidden, dismissForbidden, platformAdmin } = useAuth();
  const { data: health, error } = useApi(api.health, [], 15000);
  const admin = can("admin");
  const { data: approvals } = useApi(() => (admin ? api.approvalSummary() : Promise.resolve(null)), [admin], admin ? 30000 : undefined);
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
                    <span className="flex items-center justify-between gap-2">
                      {n.label}
                      {n.badge === "approvals" && !!approvals?.actionable && (
                        <span
                          className="rounded-full bg-sev-high px-1.5 text-[11px] font-semibold leading-5 text-black"
                          aria-label={`${approvals.actionable} waiting for your approval`}
                        >
                          {approvals.actionable}
                        </span>
                      )}
                    </span>
                  </NavLink>
                </li>
              ))}
            </>
          )}
          {platformAdmin && (
            <>
              <li className="px-3 pb-1 pt-4 text-[11px] font-semibold uppercase tracking-wide text-ink-3">Platform</li>
              <li>
                <NavLink to="/platform/organizations" className={navClass}>
                  Organisations
                </NavLink>
              </li>
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
              <div>
                Cloud connectors:{" "}
                <span className="text-ink-2">
                  {[
                    health.azure_configured && "Azure",
                    health.aws_configured && "AWS",
                    health.gcp_configured && "GCP",
                  ]
                    .filter(Boolean)
                    .join(", ") || "none configured"}
                </span>
              </div>
            </>
          )}
        </div>
      </nav>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-end gap-3 border-b border-line bg-surface-1 px-6 py-2">
          <OrgIndicator />
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
            <Route path="/exposure" element={<Exposure />} />
            <Route path="/attack-paths" element={<AttackPaths />} />
            <Route path="/connectors" element={<Connectors />} />
            <Route path="/devices" element={<Devices />} />
            <Route path="/devices/enrollment" element={<RequireRole role="admin"><Enrollment /></RequireRole>} />
            <Route path="/devices/updates" element={<AgentUpdates />} />
            <Route path="/devices/scripts" element={<Scripts />} />
            <Route path="/devices/:id" element={<DeviceDetail />} />
            <Route path="/it-assets" element={<Assets />} />
            <Route path="/it-assets/offboarding" element={<Offboarding />} />
            <Route path="/it-assets/settings" element={<RequireRole role="admin"><AssetSettings /></RequireRole>} />
            <Route path="/it-assets/:id" element={<AssetDetail />} />
            <Route path="/notifications" element={<RequireRole role="analyst"><Notifications /></RequireRole>} />
            <Route path="/account/security" element={<Security />} />
            <Route path="/approvals" element={<RequireRole role="admin"><Approvals /></RequireRole>} />
            <Route path="/admin/organization" element={<RequireRole role="admin"><OrganizationPage /></RequireRole>} />
            <Route path="/admin/users" element={<RequireRole role="admin"><Users /></RequireRole>} />
            <Route path="/platform/organizations" element={<RequirePlatformAdmin><Organizations /></RequirePlatformAdmin>} />
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
      <Route path="/invite" element={<Invite />} />
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
