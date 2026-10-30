// Typed client for organisations: the current organisation (/api/organization),
// invitations (accepting one is public) and the platform console (/api/platform).
import { request, type Role, type SessionInfo } from "./api";

export interface Organization {
  id: string;
  name: string;
  slug: string;
  status: "active" | "suspended";
  is_default: boolean;
  contact_email: string | null;
  logo_url: string | null;
  plan: string | null;
  max_users: number | null;
  max_devices: number | null;
  created_at: string;
}

export interface Usage {
  users: number;
  devices: number;
  assets: number;
  scans: number;
}

export type OnboardingStepKey = "mfa" | "team" | "cloud" | "agent" | "scan" | "alerts";

/** The "Getting started" checklist: each step detected from the organisation's own data. */
export interface Onboarding {
  steps: { key: OnboardingStepKey; done: boolean }[];
  completed: number;
  total: number;
  is_default: boolean;
  dismissed: boolean;
  dismissed_at: string | null;
  dismissed_by: string | null;
}

export type InvitationState ="pending" | "accepted" | "expired" | "revoked";

export interface Invitation {
  id: string;
  email: string;
  role: Role;
  invited_by: string | null;
  created_at: string;
  expires_at: string;
  last_sent_at: string | null;
  sent_count: number;
  accepted_at: string | null;
  revoked_at: string | null;
  state: InvitationState;
}

export interface IssuedInvitation {
  invitation: Invitation;
  emailed: boolean;
  email_error: string | null;
  /** Only when the email was not sent: pass it on yourself (single use, expires). */
  invite_url: string | null;
}

export interface IngestToken {
  id: string;
  name: string;
  token_prefix: string;
  created_by: string | null;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export type Provider = "azure" | "aws" | "gcp";

export interface ConnectorConfig {
  provider: Provider;
  stored: boolean;
  enabled: boolean;
  config: Record<string, string | string[] | null>;
  secrets: Record<string, string | null>;
  updated_at: string | null;
  updated_by: string | null;
  from_environment: boolean;
  /** Save with `test`: what the connection test reached. */
  test_message?: string | null;
  /** Save with `start_first_scan`: the scan started because this provider had none yet. */
  first_scan_id?: string | null;
}

export interface PlatformOrg extends Organization {
  updated_at: string | null;
  suspended_at: string | null;
  suspended_reason: string | null;
  created_by: string | null;
  usage: Usage;
  pending_invitations: number;
}

export interface PlatformOrgDetail extends PlatformOrg {
  members: { id: string; email: string; name: string; role: Role; is_active: boolean; last_login_at: string | null }[];
  invitations: Invitation[];
}

export interface InvitationInfo {
  organization: string;
  email: string;
  role: Role;
  expires_at: string;
  sso_available: boolean;
}

export interface SignInRequired {
  sign_in_required: true;
  email: string;
  reason: string;
}

const json = (method: string, body?: unknown): RequestInit => ({ method, body: body === undefined ? undefined : JSON.stringify(body) });

export const orgApi = {
  // --- the session's organisation ---
  organization: () => request<Organization>("/api/organization"),
  updateOrganization: (patch: Partial<Pick<Organization, "name" | "contact_email" | "logo_url">>) =>
    request<Organization>("/api/organization", json("PATCH", patch)),
  usage: () => request<Usage>("/api/organization/usage"),
  onboarding: () => request<Onboarding>("/api/organization/onboarding"),
  dismissOnboarding: () => request<Onboarding>("/api/organization/onboarding/dismiss", json("POST")),
  invitations: () => request<Invitation[]>("/api/organization/invitations"),
  mailStatus: () => request<{ configured: boolean }>("/api/organization/invitations/mail"),
  invite: (email: string, role: Role) => request<IssuedInvitation>("/api/organization/invitations", json("POST", { email, role })),
  resendInvitation: (id: string) => request<IssuedInvitation>(`/api/organization/invitations/${id}/resend`, json("POST")),
  revokeInvitation: (id: string) => request<Invitation>(`/api/organization/invitations/${id}`, json("DELETE")),
  ingestTokens: () => request<IngestToken[]>("/api/organization/ingest-tokens"),
  createIngestToken: (name: string) =>
    request<IngestToken & { token: string }>("/api/organization/ingest-tokens", json("POST", { name })),
  revokeIngestToken: (id: string) => request<IngestToken>(`/api/organization/ingest-tokens/${id}`, json("DELETE")),
  connectors: () => request<ConnectorConfig[]>("/api/organization/connectors"),
  saveConnector: (
    provider: Provider,
    body: { enabled: boolean; config: Record<string, unknown>; secrets: Record<string, string>; test?: boolean; start_first_scan?: boolean },
  ) =>
    request<ConnectorConfig>(`/api/organization/connectors/${provider}`, json("PUT", body)),
  deleteConnector: (provider: Provider) => request<ConnectorConfig>(`/api/organization/connectors/${provider}`, json("DELETE")),

  // --- accepting an invitation (public) ---
  lookupInvitation: (token: string) =>
    request<InvitationInfo>("/api/invitations/lookup", { ...json("POST", { token }), skipAuthHandling: true }),
  acceptInvitation: (token: string, name: string, password: string) =>
    request<SessionInfo | SignInRequired>("/api/invitations/accept", {
      ...json("POST", { token, name, password }),
      skipAuthHandling: true,
    }),

  // --- platform console ---
  platformOrgs: () => request<PlatformOrg[]>("/api/platform/organizations"),
  platformOrg: (id: string) => request<PlatformOrgDetail>(`/api/platform/organizations/${id}`),
  platformMail: () => request<{ configured: boolean }>("/api/platform/mail"),
  createOrg: (body: { name: string; slug?: string; contact_email?: string; plan?: string; admin_email: string }) =>
    request<{ organization: PlatformOrg; invitation: IssuedInvitation }>("/api/platform/organizations", json("POST", body)),
  updateOrg: (id: string, patch: Partial<Pick<Organization, "name" | "contact_email" | "logo_url" | "plan" | "max_users" | "max_devices">>) =>
    request<PlatformOrg>(`/api/platform/organizations/${id}`, json("PATCH", patch)),
  suspendOrg: (id: string, reason: string) => request<PlatformOrg>(`/api/platform/organizations/${id}/suspend`, json("POST", { reason })),
  activateOrg: (id: string) => request<PlatformOrg>(`/api/platform/organizations/${id}/activate`, json("POST", {})),
  platformInvite: (id: string, email: string, role: Role) =>
    request<IssuedInvitation>(`/api/platform/organizations/${id}/invitations`, json("POST", { email, role })),
  platformResend: (orgId: string, invId: string) =>
    request<IssuedInvitation>(`/api/platform/organizations/${orgId}/invitations/${invId}/resend`, json("POST")),
};

export function isSignInRequired(r: SessionInfo | SignInRequired): r is SignInRequired {
  return "sign_in_required" in r;
}
