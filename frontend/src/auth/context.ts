import { createContext, useContext } from "react";
import type { Role, User } from "../api";

export const ROLE_RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 };

export const ROLE_LABEL: Record<Role, string> = { viewer: "Viewer", analyst: "Analyst", admin: "Admin" };

export interface AuthState {
  /** undefined while the initial /api/auth/me check is in flight */
  user: User | null | undefined;
  /** true when the last session ended because it expired (shown on the login page) */
  sessionExpired: boolean;
  login: (email: string, password: string) => Promise<User>;
  logout: () => Promise<void>;
  changePassword: (current: string, next: string) => Promise<void>;
  /** Does the current user have at least `role`? */
  can: (role: Role) => boolean;
  /** Last "not permitted" message from a 403, cleared by dismissForbidden. */
  forbidden: string | null;
  dismissForbidden: () => void;
}

export const AuthContext = createContext<AuthState | null>(null);

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}

export function hasRole(user: User | null | undefined, role: Role): boolean {
  return !!user && ROLE_RANK[user.role] >= ROLE_RANK[role];
}
