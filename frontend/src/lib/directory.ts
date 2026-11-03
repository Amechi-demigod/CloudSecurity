// Directory discovery helpers shared by Connectors & scans -> Directories and IT assets -> Discovery:
// run status texts, run polling, and the setup scripts of cloud directories.
import { useEffect, useState } from "react";
import { ApiError } from "../api";
import { directoryApi, type GraphPermission, type SyncRun } from "../directoryApi";

export function errMsg(e: unknown) {
  return e instanceof ApiError ? e.message : e instanceof Error ? e.message : String(e);
}

export const FINAL = new Set(["succeeded", "failed", "cancelled"]);

export const RUN_TEXT: Record<string, string> = {
  queued: "Waiting for collector",
  running: "Syncing",
  succeeded: "Succeeded",
  failed: "Failed",
  cancelled: "Cancelled",
};
/** Server-side (cloud) runs wait for a server worker, not a collector agent. */
export const RUN_TEXT_SERVER: Record<string, string> = { ...RUN_TEXT, queued: "Queued" };
export const RUN_COLOR: Record<string, string> = {
  queued: "text-accent",
  running: "text-accent",
  succeeded: "text-good",
  failed: "text-sev-high",
  cancelled: "text-ink-3",
};
export const TRIGGER_TEXT: Record<string, string> = { scheduled: "Scheduled", manual: "Sync now", test: "Test" };

export const inputCls =
  "block w-full rounded border border-line bg-surface-2 px-3 py-1.5 text-sm text-ink focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40";

export function runDuration(r: SyncRun): string | null {
  if (r.duration_ms == null) return null;
  const s = Math.round(r.duration_ms / 1000);
  return s < 60 ? `${s}s` : s < 3600 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m`;
}

/** Poll a sync run every 5 s until it ends. */
export function useRun(runId: string | null) {
  const [run, setRun] = useState<SyncRun | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setRun(null);
    setError(null);
    if (!runId) return;
    let stop = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      try {
        const r = await directoryApi.run(runId);
        if (stop) return;
        setRun(r);
        if (FINAL.has(r.status)) return;
      } catch (e) {
        if (!stop) setError(errMsg(e));
      }
      if (!stop) timer = setTimeout(tick, 5000);
    };
    void tick();
    return () => {
      stop = true;
      if (timer) clearTimeout(timer);
    };
  }, [runId]);
  return { run, error };
}

// ----------------------------------------------------------------------------- Entra ID permission scripts
const GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000";

/** Graph permissions the chosen parts need (optional enrichments included). */
export function neededPermissions(perms: GraphPermission[], scopes: string[]): GraphPermission[] {
  const s = new Set(scopes);
  return perms.filter((p) =>
    p.scope ? s.has(p.scope) : p.name === "AuditLog.Read.All" ? s.has("users") : p.name === "GroupMember.Read.All" ? s.has("roles") : true,
  );
}

/** Azure CLI (Cloud Shell, Bash): add the application permissions to the connector's app registration and grant admin consent. */
export function entraCliScript(o: { clientId: string; tenantId: string; perms: GraphPermission[] }): string {
  const app = o.clientId || "<application (client) ID of the Azure connector>";
  return [
    "# Adds READ-ONLY Microsoft Graph application permissions to the Azure connector's app registration",
    "# and grants admin consent. Run in Azure Cloud Shell (Bash) as a Global Administrator or Privileged",
    "# Role Administrator. It changes only this app's API permissions; nothing else in the tenant.",
    ...o.perms.map((p) => `#   ${p.name}: ${p.why}`),
    `TENANT="${o.tenantId || "<tenant ID>"}"`,
    `APP_ID="${app}"`,
    `GRAPH="${GRAPH_APP_ID}"   # Microsoft Graph`,
    `PERMS="${o.perms.map((p) => `${p.id}=Role`).join(" ")}"`,
    'if [ "$(az account show --query tenantId -o tsv)" != "$TENANT" ]; then',
    '  echo "Signed in to another tenant: run  az login --tenant $TENANT --allow-no-subscriptions  and paste this again"',
    "else",
    '  az ad app permission add --id "$APP_ID" --api "$GRAPH" --api-permissions $PERMS',
    '  az ad app permission admin-consent --id "$APP_ID"',
    "  # Check: the Graph application permissions now granted to the app",
    '  SP=$(az ad sp show --id "$APP_ID" --query id -o tsv)',
    '  az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals/$SP/appRoleAssignments" \\',
    "    --query \"value[?resourceDisplayName=='Microsoft Graph'].appRoleId\" -o tsv",
    "fi",
  ].join("\n");
}

/** Microsoft Graph PowerShell: the same grant as app role assignments (admin consent for application permissions). */
export function entraPowerShellScript(o: { clientId: string; tenantId: string; perms: GraphPermission[] }): string {
  const app = o.clientId || "<application (client) ID of the Azure connector>";
  return [
    "# Grants READ-ONLY Microsoft Graph application permissions to the Azure connector's app (admin consent).",
    "# Needs the Microsoft Graph PowerShell SDK: Install-Module Microsoft.Graph.Applications -Scope CurrentUser",
    "# Sign in as a Global Administrator or Privileged Role Administrator.",
    `Connect-MgGraph -TenantId '${o.tenantId || "<tenant ID>"}' -Scopes 'Application.Read.All','AppRoleAssignment.ReadWrite.All' -NoWelcome`,
    `$appId = '${app}'`,
    "$sp = Get-MgServicePrincipal -Filter \"appId eq '$appId'\"",
    `$graph = Get-MgServicePrincipal -Filter "appId eq '${GRAPH_APP_ID}'"`,
    "$wanted = @(",
    ...o.perms.map((p, i) => `  '${p.id}'${i < o.perms.length - 1 ? "," : ""}  # ${p.name}`),
    ")",
    "$have = (Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All).AppRoleId",
    "foreach ($role in $wanted | Where-Object { $have -notcontains $_ }) {",
    "  New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $graph.Id -AppRoleId $role | Out-Null",
    "}",
    "# Check: the Graph application permissions now granted to the app",
    "Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -All | Where-Object ResourceId -eq $graph.Id |",
    "  ForEach-Object { $id = $_.AppRoleId; ($graph.AppRoles | Where-Object Id -eq $id).Value }",
  ].join("\n");
}
