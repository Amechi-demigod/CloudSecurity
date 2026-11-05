import { useState } from "react";
import { Link, useLocation, useParams } from "react-router-dom";
import type { InstallerPlatform } from "../../api";
import { useAuth } from "../../auth/context";
import { RouteGuidance } from "../../components/deployGuidance";
import { CopyValue, SourceBadges } from "../../components/directoryShared";
import { Breadcrumbs, Button, Card, ErrorNote, PageHeader, Select, Stat, Table, Tag } from "../../components/ui";
import { directoryApi, ROUTE_LABEL, type DeploymentItem } from "../../directoryApi";
import { errMsg } from "../../lib/assets";
import { DEP_STATE_TONE, EXCLUDED_HINT, EXCLUDED_LABEL } from "../../lib/deploy";
import { fmtAgo, fmtTime } from "../../lib/format";
import { useApi } from "../../lib/useApi";
import { ProgressBar } from "./Deployments";

const STATUS: Record<DeploymentItem["status"], { label: string; tone: "good" | "default" | "warn" }> = {
  enrolled: { label: "enrolled", tone: "good" },
  pending: { label: "no agent yet", tone: "warn" },
  gone: { label: "left the directory", tone: "default" },
};

export default function DeploymentDetail() {
  const { id = "" } = useParams();
  const location = useLocation();
  const { can } = useAuth();
  const isAdmin = can("admin");
  const dep = useApi(() => directoryApi.deployment(id), [id], 60000);
  // The command-line token is handed over once by the create page (router state), never fetched again.
  const [token, setToken] = useState<string | null>((location.state as { token?: string | null } | null)?.token ?? null);
  const [downloading, setDownloading] = useState<InstallerPlatform | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("all");

  const d = dep.data;
  const active = d?.state === "active";

  async function download(platform: InstallerPlatform) {
    setDownloading(platform);
    setError(null);
    try {
      const { blob, filename, sha256 } = await directoryApi.deploymentInstaller(id, platform);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
      setNotice(`Saved ${filename}${sha256 ? ` (SHA-256 ${sha256})` : ""}. The token inside it is not shown again; revoke the deployment when the rollout is finished.`);
      dep.reload();
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setDownloading(null);
    }
  }

  async function revoke() {
    if (!d || !window.confirm(`Revoke ${d.name}? Its installers and tokens stop enrolling new devices. Devices already enrolled are not affected.`)) return;
    setError(null);
    try {
      await directoryApi.revokeDeployment(id);
      setToken(null);
      dep.reload();
    } catch (e) {
      setError(errMsg(e));
    }
  }

  const items = (d?.items ?? []).filter((i) => filter === "all" || i.status === filter || i.route === filter);
  const names = (route: string) => (d?.items ?? []).filter((i) => i.route === route && i.status === "pending").map((i) => i.name);
  const available = Object.fromEntries(Object.entries(d?.installers ?? {}).map(([k, v]) => [k, v.available])) as Partial<Record<InstallerPlatform, boolean>>;

  return (
    <div>
      <Breadcrumbs
        items={[
          { label: "IT assets", to: "/it-assets" },
          { label: "Discovery", to: "/it-assets/discovery" },
          { label: "Deployments", to: "/it-assets/discovery/deployments" },
          { label: d?.name ?? "Deployment" },
        ]}
      />
      <PageHeader
        title={d?.name ?? "Deployment"}
        subtitle={
          d
            ? `Created ${fmtTime(d.created_at)} by ${d.created_by ?? "unknown"}. ${active ? `Installers and tokens enroll until ${fmtTime(d.expires_at)}.` : d.state === "revoked" ? `Revoked ${d.revoked_at ? fmtTime(d.revoked_at) : ""} by ${d.revoked_by ?? "unknown"}.` : "Expired: start a new deployment for the remaining machines."}`
            : undefined
        }
        actions={
          d ? (
            <div className="flex items-center gap-2">
              <Tag tone={DEP_STATE_TONE[d.state]}>{d.state}</Tag>
              {isAdmin && active && (
                <Button variant="danger" onClick={() => void revoke()}>
                  Revoke
                </Button>
              )}
            </div>
          ) : undefined
        }
      />
      <ErrorNote error={dep.error ?? error} />
      {notice && (
        <div role="status" className="mb-4 flex items-start justify-between gap-3 rounded border border-good/60 bg-good/10 px-3 py-2 text-sm text-ink">
          <span className="break-all">{notice}</span>
          <button className="text-ink-3 hover:text-ink" onClick={() => setNotice(null)} aria-label="Dismiss">
            ✕
          </button>
        </div>
      )}
      {token && (
        <Card title="Command-line enrollment token" className="mb-4 border-accent/60" actions={<Button onClick={() => setToken(null)}>Done</Button>}>
          <p className="mb-2 text-sm text-ink-2">Copy it now: it is shown only once. Treat it like a password until the deployment expires or is revoked.</p>
          <CopyValue label="Token" value={token} />
        </Card>
      )}
      {d && (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat label="Enrolled" value={<ProgressBar p={d.progress} />} />
            <Stat label="No agent yet" value={d.progress.pending.toLocaleString()} sub={`after ${d.progress.age_days} day${d.progress.age_days === 1 ? "" : "s"}`} />
            <Stat
              label="Enrolled with this deployment"
              value={d.progress.enrolled_with_tokens.toLocaleString()}
              hint="Devices that used this deployment's installers or token (also machines that were not selected)"
            />
            <Stat label="Left the directory" value={d.progress.gone.toLocaleString()} />
          </div>
          <p className="mb-4 text-xs text-ink-3">
            A machine counts as enrolled when directory matching links it to an active agent device; matching runs after every directory sync and every 30 minutes.
          </p>

          {(d.routes ?? []).map((r) => (
            <Card key={r.route} className="mb-4" title={<span className="flex items-center gap-2">{ROUTE_LABEL[r.route]} <Tag tone="accent">{r.count}</Tag></span>}>
              <RouteGuidance
                facts={r}
                names={names(r.route)}
                onDownload={isAdmin && active ? (p) => void download(p) : undefined}
                downloading={downloading}
                available={available}
                serverUrl={d.server_url}
                token={token}
              />
            </Card>
          ))}

          <Card
            title="Machines"
            className="mb-4"
            actions={
              <Select
                label="Show"
                value={filter}
                onChange={setFilter}
                options={[
                  { value: "all", label: "All" },
                  { value: "pending", label: "No agent yet" },
                  { value: "enrolled", label: "Enrolled" },
                  { value: "gone", label: "Left the directory" },
                  ...(d.routes ?? []).map((r) => ({ value: r.route, label: ROUTE_LABEL[r.route] })),
                ]}
              />
            }
          >
            <Table head={["Machine", "Found in", "OS", "Route", "Status", "Agent device"]} rowCount={items.length}>
              {items.map((i) => (
                <tr key={i.computer_id}>
                  <td className="px-3 py-2">
                    <div className="font-medium text-ink">{i.name}</div>
                    <div className="max-w-xs truncate text-[11px] text-ink-3" title={i.ou}>
                      {i.ou || i.domain}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-xs">
                    <SourceBadges refs={i.kinds.map((k) => ({ id: i.computer_id, source_id: "", type: "", kind: k }))} />
                  </td>
                  <td className="px-3 py-2 text-xs text-ink-2">{i.os}</td>
                  <td className="px-3 py-2 text-xs text-ink-2">{ROUTE_LABEL[i.route]}</td>
                  <td className="px-3 py-2 text-xs">
                    <Tag tone={STATUS[i.status].tone}>{STATUS[i.status].label}</Tag>
                    {i.status === "pending" && <div className="mt-0.5 text-ink-3">{d.progress.age_days} days</div>}
                  </td>
                  <td className="px-3 py-2 text-xs">
                    {i.device_id ? (
                      <>
                        <Link to={`/devices/${i.device_id}`} className="text-accent hover:underline">
                          {i.device_hostname}
                        </Link>
                        <div className="text-ink-3">
                          enrolled {i.enrolled_at ? fmtAgo(i.enrolled_at) : ""}
                          {i.via_deployment ? " · this deployment" : ""}
                        </div>
                      </>
                    ) : (
                      <span className="text-ink-3">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </Table>
          </Card>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card title="Tokens and installers">
              {(d.tokens ?? []).length === 0 ? (
                <p className="text-sm text-ink-3">None yet: download an installer above{isAdmin ? "" : " (admins)"}.</p>
              ) : (
                <Table head={["Name", "Token", "Uses", "State"]}>
                  {(d.tokens ?? []).map((t) => (
                    <tr key={t.id}>
                      <td className="px-3 py-2 text-xs">
                        {t.name}
                        {t.package_platform && (
                          <div className="mt-0.5">
                            <Tag tone="accent">installer · {t.package_platform === "windows-msi" ? "Windows MSI" : "macOS pkg"}</Tag>
                          </div>
                        )}
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-ink-3">{t.token_prefix}…</td>
                      <td className="px-3 py-2 text-xs text-ink-2">
                        {t.use_count} / {t.max_uses ?? "∞"}
                      </td>
                      <td className="px-3 py-2 text-xs">
                        <Tag tone={t.state === "active" ? "good" : t.state === "revoked" ? "warn" : "default"}>{t.state}</Tag>
                      </td>
                    </tr>
                  ))}
                </Table>
              )}
            </Card>
            <Card title="Left out at creation">
              {Object.keys(d.excluded_counts).length === 0 ? (
                <p className="text-sm text-ink-3">Every selected machine was included.</p>
              ) : (
                <ul className="space-y-2 text-sm">
                  {Object.entries(d.excluded_counts).map(([k, n]) => (
                    <li key={k}>
                      <span className="font-medium text-ink">
                        {n} · {EXCLUDED_LABEL[k] ?? k}
                      </span>
                      <div className="text-xs text-ink-3">{EXCLUDED_HINT[k]}</div>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
