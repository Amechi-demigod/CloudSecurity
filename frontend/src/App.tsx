import {
  Bell,
  Boxes,
  Bug,
  Building2,
  CheckCheck,
  ClipboardCheck,
  Globe,
  Laptop,
  LayoutDashboard,
  Menu,
  Moon,
  Network,
  Package,
  PlugZap,
  Route as RouteIcon,
  ScrollText,
  Siren,
  Sun,
  Users2,
  type LucideIcon,
} from "lucide-react";
import { Fragment, useState, type ReactNode } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { api, type Role } from "./api";
import { useAuth } from "./auth/context";
import UserMenu from "./components/UserMenu";
import { useBrand } from "./lib/brand";
import { useTheme } from "./lib/theme";
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
import FindingDetail from "./pages/FindingDetail";
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

type NavItem = { to: string; label: string; icon: LucideIcon; role?: Role; badge?: "approvals" };

// Grouped by what the user is looking after; the order inside a group follows a typical triage.
const NAV_GROUPS: { title: string; items: NavItem[] }[] = [
  { title: "", items: [{ to: "/", label: "Dashboards", icon: LayoutDashboard }] },
  {
    title: "Cloud security",
    items: [
      { to: "/inventory", label: "Inventory", icon: Boxes },
      { to: "/exposure", label: "Exposure", icon: Globe },
      { to: "/findings", label: "Posture findings", icon: ClipboardCheck },
      { to: "/vulnerabilities", label: "Vulnerabilities", icon: Bug },
      { to: "/attack-paths", label: "Attack paths", icon: RouteIcon },
      { to: "/threats", label: "Runtime threats", icon: Siren },
    ],
  },
  {
    title: "Endpoints & assets",
    items: [
      { to: "/devices", label: "Devices", icon: Laptop },
      { to: "/it-assets", label: "IT assets", icon: Package },
    ],
  },
  {
    title: "Configuration",
    items: [
      { to: "/connectors", label: "Connectors & scans", icon: PlugZap },
      { to: "/notifications", label: "Notifications", icon: Bell, role: "analyst" },
    ],
  },
];

const ADMIN_NAV: NavItem[] = [
  { to: "/approvals", label: "Approvals", icon: CheckCheck, badge: "approvals" },
  { to: "/admin/organization", label: "Organisation", icon: Building2 },
  { to: "/admin/users", label: "Users", icon: Users2 },
  { to: "/admin/audit-log", label: "Audit log", icon: ScrollText },
];

function navClass({ isActive }: { isActive: boolean }) {
  return `flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
    isActive ? "bg-accent/15 font-medium text-ink" : "text-ink-2 hover:bg-surface-2 hover:text-ink"
  }`;
}

function NavSection({ title }: { title: string }) {
  return <li className="px-3 pb-1 pt-4 text-[11px] font-semibold uppercase tracking-wider text-ink-3">{title}</li>;
}

function ThemeToggle() {
  const [theme, toggle] = useTheme();
  const next = theme === "dark" ? "light" : "dark";
  const Icon = theme === "dark" ? Sun : Moon;
  return (
    <button
      type="button"
      onClick={toggle}
      title={`Switch to ${next} theme`}
      aria-label={`Switch to ${next} theme`}
      className="flex h-9 w-9 items-center justify-center rounded-lg text-ink-2 transition hover:bg-surface-2 hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
    >
      <Icon aria-hidden className="h-4 w-4" />
    </button>
  );
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
  const brand = useBrand();
  const { data: health, error } = useApi(api.health, [], 15000);
  const admin = can("admin");
  const { data: approvals } = useApi(() => (admin ? api.approvalSummary() : Promise.resolve(null)), [admin], admin ? 30000 : undefined);
  // Below the md breakpoint the sidebar is an overlay opened from the header's menu button.
  const [navOpen, setNavOpen] = useState(false);
  return (
    <div className="flex h-full" data-print="flow">
      {navOpen && <div className="fixed inset-0 z-30 bg-black/50 md:hidden" onClick={() => setNavOpen(false)} aria-hidden data-print="hide" />}
      <nav
        aria-label="Main"
        data-print="hide"
        onClick={(e) => (e.target as HTMLElement).closest("a") && setNavOpen(false)}
        className={`${navOpen ? "fixed inset-y-0 left-0 z-40 flex shadow-2xl" : "hidden"} w-60 shrink-0 flex-col border-r border-line bg-surface-1 md:static md:z-auto md:flex md:shadow-none`}
      >
        <div className="flex items-center gap-2.5 px-5 py-4">
          <img src="/shield.svg" alt="" className="h-7 w-7" />
          <div>
            <div className="text-sm font-bold leading-tight tracking-tight">{brand.name}</div>
            <div className="text-[11px] text-ink-3">{brand.tagline}</div>
          </div>
        </div>
        <ul className="flex-1 space-y-0.5 overflow-y-auto px-2 pb-3">
          {NAV_GROUPS.map((g) => {
            const items = g.items.filter((n) => !n.role || can(n.role));
            if (items.length === 0) return null;
            return (
              <Fragment key={g.title || "home"}>
                {g.title && <NavSection title={g.title} />}
                {items.map((n) => (
                  <li key={n.to}>
                    <NavLink to={n.to} end={n.to === "/"} className={navClass}>
                      <n.icon aria-hidden className="h-4 w-4 shrink-0" />
                      {n.label}
                    </NavLink>
                  </li>
                ))}
              </Fragment>
            );
          })}
          {admin && (
            <>
              <NavSection title="Administration" />
              {ADMIN_NAV.map((n) => (
                <li key={n.to}>
                  <NavLink to={n.to} className={navClass}>
                    <n.icon aria-hidden className="h-4 w-4 shrink-0" />
                    <span className="flex-1">{n.label}</span>
                    {n.badge === "approvals" && !!approvals?.actionable && (
                      <span
                        className="rounded-full bg-sev-high px-1.5 text-[11px] font-semibold leading-5 text-black"
                        aria-label={`${approvals.actionable} waiting for your approval`}
                      >
                        {approvals.actionable}
                      </span>
                    )}
                  </NavLink>
                </li>
              ))}
            </>
          )}
          {platformAdmin && (
            <>
              <NavSection title="Platform" />
              <li>
                <NavLink to="/platform/organizations" className={navClass}>
                  <Network aria-hidden className="h-4 w-4 shrink-0" />
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
      <div className="flex min-w-0 flex-1 flex-col" data-print="flow">
        <header className="flex items-center justify-end gap-2 border-b border-line bg-surface-1 px-4 py-2 md:px-6" data-print="hide">
          <button
            type="button"
            onClick={() => setNavOpen(true)}
            aria-label="Open the menu"
            className="flex h-9 w-9 items-center justify-center rounded-lg text-ink-2 hover:bg-surface-2 hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent md:hidden"
          >
            <Menu aria-hidden className="h-5 w-5" />
          </button>
          <OrgIndicator />
          <ThemeToggle />
          <UserMenu />
        </header>
        <main className="min-w-0 flex-1 overflow-y-auto px-4 py-5 md:px-6" data-print="flow">
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
            <Route path="/findings/:id" element={<FindingDetail />} />
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
