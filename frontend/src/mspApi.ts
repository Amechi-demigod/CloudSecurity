// Typed client for MSP accounts (/api/msp, docs/MSP.md): a partner's staff manage client organisations and
// switch into one to work in it. Only MSP staff can call these.
import { request, type ModuleKey } from "./api";
import type { Invitation, IssuedInvitation } from "./orgApi";

export interface MspInfo {
  organization: { id: string; name: string };
  role: string;
  /** Most clients the MSP may have; null = unlimited. */
  max_clients: number | null;
  clients: number;
  acting_as_client: boolean;
}

export interface MspClient {
  id: string;
  name: string;
  slug: string;
  status: "active" | "suspended";
  contact_email: string | null;
  modules: ModuleKey[];
  suspended_at: string | null;
  suspended_reason: string | null;
  /** False when Sentrigis (the platform owner) suspended it: the MSP cannot reactivate it. */
  can_reactivate: boolean;
  pending_invitations: number;
}

export interface ClientOverview {
  id: string;
  name: string;
  status: "active" | "suspended";
  modules: ModuleKey[];
  users: number | null;
  devices: number | null;
  assets: number | null;
  open_critical_findings: number | null;
  risk_score: number | null;
  last_scan_at: string | null;
  last_scan_status: string | null;
  error: string | null;
}

export interface Overview {
  clients: ClientOverview[];
  total_clients: number;
  truncated: boolean;
}

const json = (method: string, body?: unknown): RequestInit => ({ method, body: body === undefined ? undefined : JSON.stringify(body) });

/** One row of the Clients page: the overview numbers joined with the client's own record. */
export interface ClientRow extends ClientOverview {
  record: MspClient | null;
}

/** Every client with its numbers (the overview is paged by the server, 100 at a time). */
async function overviewAll(): Promise<ClientOverview[]> {
  const out: ClientOverview[] = [];
  for (let offset = 0; offset < 10_000; offset += 100) {
    const page = await request<Overview>(`/api/msp/overview?limit=100&offset=${offset}`);
    out.push(...page.clients);
    if (!page.truncated || page.clients.length === 0) break;
  }
  return out;
}

export const mspApi = {
  msp: () => request<MspInfo>("/api/msp"),
  /** Enter a client, or (null) go back to the MSP's own organisation. */
  switch: (organizationId: string | null) => request<MspInfo>("/api/msp/switch", json("POST", { organization_id: organizationId })),
  clients: () => request<MspClient[]>("/api/msp/clients"),
  overviewAll,
  rows: async (): Promise<ClientRow[]> => {
    const [overview, clients] = await Promise.all([overviewAll(), request<MspClient[]>("/api/msp/clients")]);
    const byId = new Map(clients.map((c) => [c.id, c]));
    return overview.map((o) => ({ ...o, record: byId.get(o.id) ?? null }));
  },
  createClient: (body: { name: string; contact_email: string; modules: ModuleKey[]; admin_email?: string }) =>
    request<{ client: MspClient; invitation: IssuedInvitation | null }>("/api/msp/clients", json("POST", body)),
  updateClient: (id: string, patch: { name?: string; contact_email?: string }) => request<MspClient>(`/api/msp/clients/${id}`, json("PATCH", patch)),
  setModules: (id: string, modules: ModuleKey[]) => request<MspClient>(`/api/msp/clients/${id}/modules`, json("PUT", { modules })),
  suspend: (id: string, reason: string) => request<MspClient>(`/api/msp/clients/${id}/suspend`, json("POST", { reason })),
  activate: (id: string) => request<MspClient>(`/api/msp/clients/${id}/activate`, json("POST", { reason: "" })),
  invitations: (id: string) => request<Invitation[]>(`/api/msp/clients/${id}/invitations`),
  invite: (id: string, email: string) => request<IssuedInvitation>(`/api/msp/clients/${id}/invitations`, json("POST", { email, role: "admin" })),
  resend: (id: string, invId: string) => request<IssuedInvitation>(`/api/msp/clients/${id}/invitations/${invId}/resend`, json("POST")),
};
