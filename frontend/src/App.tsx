import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { api } from "./api";
import { useApi } from "./components/ui";
import AttackPaths from "./pages/AttackPaths";
import Connectors from "./pages/Connectors";
import DashboardPage from "./pages/Dashboard";
import Findings from "./pages/Findings";
import Inventory from "./pages/Inventory";
import Threats from "./pages/Threats";
import Vulnerabilities from "./pages/Vulnerabilities";

const NAV = [
  { to: "/", label: "Dashboard" },
  { to: "/inventory", label: "Inventory" },
  { to: "/findings", label: "Posture findings" },
  { to: "/vulnerabilities", label: "Vulnerabilities" },
  { to: "/threats", label: "Runtime threats" },
  { to: "/attack-paths", label: "Attack paths" },
  { to: "/connectors", label: "Connectors & scans" },
];

export default function App() {
  const { data: health, error } = useApi(api.health, [], 15000);
  return (
    <div className="flex h-full">
      <nav className="flex w-56 shrink-0 flex-col border-r border-line bg-surface-1">
        <div className="flex items-center gap-2 px-4 py-4">
          <img src="/shield.svg" alt="" className="h-6 w-6" />
          <div>
            <div className="text-sm font-semibold leading-tight">CloudSecurity</div>
            <div className="text-[11px] text-ink-3">Runtime-first CNAPP</div>
          </div>
        </div>
        <ul className="flex-1 space-y-0.5 px-2">
          {NAV.map((n) => (
            <li key={n.to}>
              <NavLink
                to={n.to}
                end={n.to === "/"}
                className={({ isActive }) =>
                  `block rounded px-3 py-2 text-sm ${isActive ? "bg-surface-2 text-ink" : "text-ink-2 hover:bg-surface-2 hover:text-ink"}`
                }
              >
                {n.label}
              </NavLink>
            </li>
          ))}
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
      <main className="min-w-0 flex-1 overflow-y-auto px-6 py-5">
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/inventory" element={<Inventory />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/vulnerabilities" element={<Vulnerabilities />} />
          <Route path="/threats" element={<Threats />} />
          <Route path="/attack-paths" element={<AttackPaths />} />
          <Route path="/connectors" element={<Connectors />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}
