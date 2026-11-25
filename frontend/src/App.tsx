import { AlertTriangle, Building2, ChevronDown, Users as UsersIcon, LayoutDashboard, Lock, Menu, Monitor, Moon, Radar, Settings, ShieldCheck, Sun, type LucideIcon } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { Link, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { api, type ModuleKey, type Role } from "./api";
import { useAuth } from "./auth/context";
import { RequireModule } from "./components/ModuleLocked";
import { ClientBar, ClientSwitcher } from "./components/msp";
import UserMenu from "./components/UserMenu";
import { useBrand } from "./lib/brand";
import { PROVIDER_LABEL } from "./lib/format";
import { useModules } from "./lib/modules";
import { useTheme } from "./lib/theme";
import { useApi } from "./lib/useApi";
import Approvals from "./pages/Approvals";
import AssetDetail from "./pages/assets/AssetDetail";
import Assets from "./pages/assets/Assets";
import AssetSettings from "./pages/assets/AssetSettings";
import DeployAgent from "./pages/assets/DeployAgent";
import DeploymentDetail from "./pages/assets/DeploymentDetail";
import Deployments from "./pages/assets/Deployments";
import Discovery from "./pages/assets/Discovery";
import NetworkDeviceDetail from "./pages/network/NetworkDeviceDetail";
import NetworkDevices from "./pages/network/NetworkDevices";
import NetworkScans from "./pages/network/NetworkScans";
import Offboarding from "./pages/assets/Offboarding";
import AttackPaths from "./pages/AttackPaths";
import Compliance from "./pages/Compliance";
import ExecutiveReport from "./pages/ExecutiveReport";
import Connectors from "./pages/Connectors";
import AgentUpdates from "./pages/devices/AgentUpdates";
import DeviceDetail from "./pages/devices/DeviceDetail";
import RemoteViewer from "./pages/devices/RemoteViewer";
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
import VulnerabilityDetail from "./pages/VulnerabilityDetail";
import AuditLog from "./pages/admin/AuditLog";
import OrganizationPage from "./pages/admin/Organization";
import Users from "./pages/admin/Users";
import Invite from "./pages/Invite";
import Clients from "./pages/msp/Clients";
import Organizations from "./pages/platform/Organizations";
import ExternalReview from "./pages/platform/ExternalReview";
import AttackSurface from "./pages/external/AttackSurface";
import ExternalFindings from "./pages/external/ExternalFindings";
import ExternalFindingDetail from "./pages/external/ExternalFindingDetail";
import ReputationDomain from "./pages/external/ReputationDomain";
import ExternalReports from "./pages/external/ExternalReports";

type NavChild = {
  to: string;
  label: string;
  /** Other paths that belong to this item (detail pages and pages reached from it); they highlight it. */
  also?: string[];
  role?: Role;
  /** Needed module: without it the item is shown locked and opens the "not in your subscription" page. */
  module?: ModuleKey;
  /** The item is shown only when the organisation has at least one of these modules. */
  showWith?: ModuleKey[];
  admin?: boolean;
  badge?: "approvals";
};
type NavTop = { key: string; label: string; icon: LucideIcon; to?: string; also?: string[]; module?: ModuleKey; children?: NavChild[]; platform?: boolean };

// The menu: six places, grouped by the question the user is asking. Pages that stay reachable but are not menu
// items (Attack paths, Exposure, Approvals, Organisation, ...) are listed in `also` so their parent stays highlighted.
const NAV: NavTop[] = [
  { key: "overview", label: "Overview", icon: LayoutDashboard, to: "/" },
  {
    key: "issues",
    label: "Issues",
    icon: AlertTriangle,
    children: [
      { to: "/findings", label: "Cloud", also: ["/attack-paths"], module: "cloud" },
      { to: "/vulnerabilities", label: "Vulnerabilities", module: "vulnerabilities" },
      { to: "/attack-surface/findings", label: "Internet-facing", module: "external" },
      { to: "/threats", label: "Threats", module: "endpoints" },
    ],
  },
  {
    key: "assets",
    label: "Assets",
    icon: Monitor,
    children: [
      { to: "/inventory", label: "Cloud resources", also: ["/exposure"], module: "cloud" },
      { to: "/devices", label: "Computers & servers", also: ["/devices/enrollment", "/devices/scripts"], module: "endpoints" },
      { to: "/it-assets", label: "Hardware register", module: "assets" },
      { to: "/network-devices", label: "Network", also: ["/network-scans"], module: "assets" },
    ],
  },
  { key: "surface", label: "Attack surface", icon: Radar, to: "/attack-surface", module: "external" },
  {
    key: "compliance",
    label: "Compliance & reports",
    icon: ShieldCheck,
    children: [
      { to: "/compliance", label: "Compliance" },
      { to: "/executive-report", label: "Executive report" },
    ],
  },
  {
    key: "settings",
    label: "Settings",
    icon: Settings,
    children: [
      { to: "/connectors", label: "Connections" },
      { to: "/devices/updates", label: "Agents & updates", module: "endpoints" },
      { to: "/notifications", label: "Notifications", role: "analyst" },
      { to: "/admin/users", label: "People & approvals", also: ["/approvals", "/admin/organization"], admin: true, badge: "approvals" },
      { to: "/admin/audit-log", label: "Audit log", admin: true },
    ],
  },
  {
    key: "platform",
    label: "Platform",
    icon: Building2,
    platform: true,
    children: [
      { to: "/platform/organizations", label: "Organisations" },
      { to: "/platform/attack-surface", label: "Attack surface review" },
    ],
  },
];

// MSP staff in their own partner organisation: their clients, and the few settings that belong to the MSP itself
// (its team and audit log). Everything else belongs to a client and is reached by opening one.
const MSP_HOME_NAV: NavTop[] = [
  { key: "clients", label: "Clients", icon: UsersIcon, to: "/" },
  {
    key: "settings",
    label: "Settings",
    icon: Settings,
    children: [
      { to: "/notifications", label: "Notifications", role: "analyst" },
      { to: "/admin/users", label: "People & approvals", also: ["/approvals", "/admin/organization"], admin: true, badge: "approvals" },
      { to: "/admin/audit-log", label: "Audit log", admin: true },
    ],
  },
  NAV[NAV.length - 1],
];

/** How well a path matches an item (0: not at all); the longest match wins, so /devices/updates beats /devices. */
function matchLen(path: string, item: { to?: string; also?: string[] }): number {
  let best = 0;
  for (const base of [item.to, ...(item.also ?? [])]) {
    if (!base) continue;
    const hit = base === "/" ? path === "/" : path === base || path.startsWith(`${base}/`);
    if (hit) best = Math.max(best, base.length);
  }
  return best;
}

const itemCls = (active: boolean) =>
  `flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
    active ? "bg-accent/15 font-medium text-ink" : "text-ink-2 hover:bg-surface-2 hover:text-ink"
  }`;

function LockMark() {
  return (
    <>
      <Lock aria-hidden className="h-3.5 w-3.5 shrink-0 text-ink-3" />
      <span className="sr-only">(not in your subscription)</span>
    </>
  );
}

function SideNav({ approvals, onNavigate }: { approvals?: number; onNavigate: () => void }) {
  const { can, platformAdmin, homeOrganization, actingAsClient } = useAuth();
  const mspHome = !!homeOrganization && !actingAsClient;
  const { has } = useModules();
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const admin = can("admin");

  // What this user sees; locked children sink to the bottom of their group.
  const tops = (mspHome ? MSP_HOME_NAV : NAV).filter((t) => !t.platform || platformAdmin)
    .map((t) => {
      const children = t.children
        ?.filter((c) => (!c.role || can(c.role)) && (!c.admin || admin) && (!c.showWith || has(...c.showWith)))
        .map((c) => ({ ...c, locked: !!c.module && !has(c.module) }))
        .sort((x, y) => Number(x.locked) - Number(y.locked));
      return { ...t, children, locked: !!t.module && !has(t.module) };
    })
    .filter((t) => !t.children || t.children.length > 0);

  // The single best-matching leaf is the current page (aria-current); its group is the active group.
  let current = "";
  let currentLen = 0;
  for (const t of tops) {
    for (const leaf of t.children ?? [t]) {
      const n = matchLen(pathname, leaf);
      if (n > currentLen) {
        currentLen = n;
        current = leaf.to ?? "";
      }
    }
  }
  const activeGroup = tops.find((t) => t.children?.some((c) => c.to === current))?.key ?? "";

  // Groups the user opened by hand; the group holding the current page is always open.
  const [opened, setOpened] = useState<Record<string, boolean>>({});
  useEffect(() => {
    if (activeGroup) setOpened((o) => (o[activeGroup] ? o : { ...o, [activeGroup]: true }));
  }, [activeGroup]);

  const badge = (c: NavChild) =>
    c.badge === "approvals" && !!approvals ? (
      <span className="rounded-full bg-sev-high px-1.5 text-[11px] font-semibold leading-5 text-black" aria-label={`${approvals} waiting for your approval`}>
        {approvals}
      </span>
    ) : null;

  return (
    <ul className="flex-1 space-y-0.5 overflow-y-auto px-2 pb-3">
      {tops.map((t) => {
        const Icon = t.icon;
        if (!t.children) {
          const on = t.to === current;
          return (
            <li key={t.key}>
              <Link to={t.to!} aria-current={on ? "page" : undefined} className={itemCls(on)}>
                <Icon aria-hidden className={`h-4 w-4 shrink-0 ${t.locked ? "opacity-60" : ""}`} />
                <span className={`flex-1 ${t.locked ? "text-ink-3" : ""}`}>{t.label}</span>
                {t.locked && <LockMark />}
              </Link>
            </li>
          );
        }
        const isActive = t.key === activeGroup;
        const isOpen = isActive || !!opened[t.key];
        const panel = `nav-${t.key}`;
        const first = t.children.find((c) => !c.locked) ?? t.children[0];
        return (
          <li key={t.key}>
            <button
              type="button"
              aria-expanded={isOpen}
              aria-controls={panel}
              onClick={() => {
                if (isActive) {
                  setOpened((o) => ({ ...o, [t.key]: !isOpen }));
                } else if (isOpen) {
                  setOpened((o) => ({ ...o, [t.key]: false }));
                } else {
                  setOpened((o) => ({ ...o, [t.key]: true }));
                  navigate(first.to);
                  onNavigate();
                }
              }}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
                isActive ? "font-medium text-ink" : "text-ink-2 hover:bg-surface-2 hover:text-ink"
              }`}
            >
              <Icon aria-hidden className="h-4 w-4 shrink-0" />
              <span className="flex-1">{t.label}</span>
              <ChevronDown aria-hidden className={`h-3.5 w-3.5 shrink-0 text-ink-3 transition-transform ${isOpen ? "" : "-rotate-90"}`} />
            </button>
            {isOpen && (
              <ul id={panel} className="ml-[22px] mt-0.5 space-y-0.5 border-l border-line pl-2">
                {t.children.map((c) => {
                  const on = c.to === current;
                  return (
                    <li key={c.to}>
                      <Link to={c.to} aria-current={on ? "page" : undefined} className={itemCls(on)}>
                        <span className={`flex-1 ${c.locked ? "text-ink-3" : ""}`}>{c.label}</span>
                        {badge(c)}
                        {c.locked && <LockMark />}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            )}
          </li>
        );
      })}
    </ul>
  );
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
  const { organization, homeOrganization } = useAuth();
  if (!organization) return null;
  // MSP staff get a switcher; everybody else sees a plain name.
  if (homeOrganization) return <ClientSwitcher />;
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
  const { can, forbidden, dismissForbidden, platformAdmin, homeOrganization, actingAsClient } = useAuth();
  const mspHome = !!homeOrganization && !actingAsClient;
  const brand = useBrand();
  const { data: health, error } = useApi(api.health, [], 15000);
  // This organisation's connectors (console settings, or the environment for the default one).
  const showStatus = platformAdmin;
  const { data: connectors } = useApi(() => (showStatus ? api.connectors() : Promise.resolve(null)), [showStatus], 60000);
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
          <img src="/shield.svg" alt="" className="h-8 w-auto" />
          <div>
            <div className="text-sm font-bold leading-tight tracking-tight">{brand.name}</div>
            
          </div>
        </div>
        <SideNav approvals={approvals?.actionable} onNavigate={() => setNavOpen(false)} />
        <div className="space-y-1 border-t border-line px-4 py-3 text-[11px] text-ink-3">
          {error && <div className="text-sev-critical">API unreachable</div>}
          {platformAdmin && health && (
            <div className="space-y-0.5 text-[10px]">
              <div>
                Mode: <span className="text-ink-2">{health.simulation_mode ? "Simulated data" : "Live"}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className={`inline-block h-1.5 w-1.5 rounded-full ${health.simulator_running ? "animate-pulse bg-good" : "bg-ink-3"}`} />
                Runtime feed {health.simulator_running ? "live" : "idle"}
              </div>
              <div>
                Cloud connectors:{" "}
                <span className="text-ink-2">
                  {(connectors
                    ? connectors.filter((c) => c.name !== "simulated" && c.configured).map((c) => PROVIDER_LABEL[c.name] ?? c.name)
                    : [health.azure_configured && "Azure", health.aws_configured && "AWS", health.gcp_configured && "GCP"].filter(Boolean)
                  ).join(", ") || "none configured"}
                </span>
              </div>
            </div>
          )}
        </div>
      </nav>
      <div className="flex min-w-0 flex-1 flex-col" data-print="flow">
        <ClientBar />
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
            <Route path="/" element={mspHome ? <Clients /> : <DashboardPage />} />
            <Route path="/compliance" element={<Compliance />} />
            <Route path="/executive-report" element={<ExecutiveReport />} />
            <Route path="/inventory" element={<RequireModule module="cloud"><Inventory /></RequireModule>} />
            <Route path="/findings" element={<RequireModule module="cloud"><Findings /></RequireModule>} />
            <Route path="/findings/:id" element={<RequireModule module="cloud"><FindingDetail /></RequireModule>} />
            <Route path="/vulnerabilities" element={<RequireModule module="vulnerabilities"><Vulnerabilities /></RequireModule>} />
            <Route path="/vulnerabilities/:cveId" element={<RequireModule module="vulnerabilities"><VulnerabilityDetail /></RequireModule>} />
            <Route path="/threats" element={<RequireModule module="endpoints"><Threats /></RequireModule>} />
            <Route path="/exposure" element={<RequireModule module="cloud"><Exposure /></RequireModule>} />
            <Route path="/attack-paths" element={<RequireModule module="cloud"><AttackPaths /></RequireModule>} />
            <Route path="/connectors" element={<Connectors />} />
            <Route path="/devices" element={<RequireModule module="endpoints"><Devices /></RequireModule>} />
            <Route path="/devices/enrollment" element={<RequireModule module={["endpoints", "assets"]}><RequireRole role="admin"><Enrollment /></RequireRole></RequireModule>} />
            <Route path="/devices/updates" element={<RequireModule module="endpoints"><AgentUpdates /></RequireModule>} />
            <Route path="/devices/scripts" element={<RequireModule module="endpoints"><Scripts /></RequireModule>} />
            <Route path="/devices/:id" element={<RequireModule module="endpoints"><DeviceDetail /></RequireModule>} />
            <Route path="/devices/:id/remote/:sid" element={<RequireModule module="endpoints"><RequireRole role="analyst"><RemoteViewer /></RequireRole></RequireModule>} />
            <Route path="/network-devices" element={<RequireModule module="assets"><NetworkDevices /></RequireModule>} />
            <Route path="/network-devices/:id" element={<RequireModule module="assets"><NetworkDeviceDetail /></RequireModule>} />
            <Route path="/network-scans" element={<RequireModule module="assets"><NetworkScans /></RequireModule>} />
            <Route path="/it-assets" element={<RequireModule module="assets"><Assets /></RequireModule>} />
            <Route path="/it-assets/offboarding" element={<RequireModule module="assets"><Offboarding /></RequireModule>} />
            <Route path="/it-assets/discovery" element={<RequireModule module="assets"><Discovery /></RequireModule>} />
            <Route path="/it-assets/discovery/deploy" element={<RequireModule module="assets"><RequireRole role="admin"><DeployAgent /></RequireRole></RequireModule>} />
            <Route path="/it-assets/discovery/deployments" element={<RequireModule module="assets"><Deployments /></RequireModule>} />
            <Route path="/it-assets/discovery/deployments/:id" element={<RequireModule module="assets"><DeploymentDetail /></RequireModule>} />
            <Route path="/it-assets/settings" element={<RequireModule module="assets"><RequireRole role="admin"><AssetSettings /></RequireRole></RequireModule>} />
            <Route path="/it-assets/:id" element={<RequireModule module="assets"><AssetDetail /></RequireModule>} />
            <Route path="/attack-surface" element={<RequireModule module="external"><AttackSurface /></RequireModule>} />
            <Route path="/attack-surface/findings" element={<RequireModule module="external"><ExternalFindings /></RequireModule>} />
            <Route path="/attack-surface/findings/:id" element={<RequireModule module="external"><ExternalFindingDetail /></RequireModule>} />
            <Route path="/attack-surface/reputation/:domain" element={<RequireModule module="external"><ReputationDomain /></RequireModule>} />
            <Route path="/attack-surface/reports" element={<RequireModule module="external"><ExternalReports /></RequireModule>} />
            <Route path="/platform/attack-surface" element={<RequirePlatformAdmin><ExternalReview /></RequirePlatformAdmin>} />
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
