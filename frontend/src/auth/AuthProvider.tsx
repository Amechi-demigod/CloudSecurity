import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  ApiError,
  api,
  isMfaChallenge,
  setAuthHandlers,
  setCsrfToken,
  type OrganizationBrief,
  type Role,
  type SessionInfo,
  type User,
} from "../api";
import { AuthContext, hasRole, type AuthState } from "./context";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null | undefined>(undefined);
  const [organization, setOrganization] = useState<OrganizationBrief | null>(null);
  const [homeOrganization, setHomeOrganization] = useState<OrganizationBrief | null>(null);
  const [actingAsClient, setActingAsClient] = useState(false);
  const [platformAdmin, setPlatformAdmin] = useState(false);
  const [sessionExpired, setSessionExpired] = useState(false);
  const [forbidden, setForbidden] = useState<string | null>(null);
  const userRef = useRef(user);

  const adopt = useCallback((s: SessionInfo) => {
    setCsrfToken(s.csrf_token);
    setOrganization(s.organization ?? null);
    setHomeOrganization(s.home_organization ?? null);
    setActingAsClient(!!s.acting_as_client);
    setPlatformAdmin(!!s.platform_admin);
    setUser(s.user);
  }, []);

  useEffect(() => {
    userRef.current = user;
  }, [user]);

  // Initial session check.
  useEffect(() => {
    let cancelled = false;
    api
      .me()
      .then((s) => {
        if (cancelled) return;
        adopt(s);
      })
      .catch((e) => {
        if (cancelled) return;
        // The backend says "Session expired" when a cookie was sent but is no longer valid.
        if (e instanceof ApiError && e.status === 401 && /expired/i.test(e.message)) setSessionExpired(true);
        setUser(null);
      });
    return () => {
      cancelled = true;
    };
  }, [adopt]);

  // Global 401 / 403 handling for every API call.
  useEffect(() => {
    setAuthHandlers({
      unauthorized: () => {
        if (userRef.current) setSessionExpired(true);
        setCsrfToken(null);
        setUser(null);
      },
      forbidden: (message) => setForbidden(message),
    });
  }, []);

  const completeLogin = useCallback((s: SessionInfo) => {
    setCsrfToken(s.csrf_token);
    setSessionExpired(false);
    setForbidden(null);
    adopt(s);
  }, [adopt]);

  const refresh = useCallback(async () => {
    adopt(await api.me());
  }, [adopt]);

  const login = useCallback(
    async (email: string, password: string) => {
      const r = await api.login(email, password);
      if (!isMfaChallenge(r)) completeLogin(r);
      return r;
    },
    [completeLogin],
  );

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      setCsrfToken(null);
      setSessionExpired(false);
      setOrganization(null);
      setHomeOrganization(null);
      setActingAsClient(false);
      setPlatformAdmin(false);
      setUser(null);
    }
  }, []);

  const changePassword = useCallback(async (current: string, next: string) => {
    await api.changePassword(current, next);
  }, []);

  const value = useMemo<AuthState>(
    () => ({
      user,
      organization,
      homeOrganization,
      actingAsClient,
      platformAdmin,
      refresh,
      sessionExpired,
      login,
      completeLogin,
      logout,
      changePassword,
      can: (role: Role) => hasRole(user, role),
      forbidden,
      dismissForbidden: () => setForbidden(null),
    }),
    [user, organization, homeOrganization, actingAsClient, platformAdmin, refresh, sessionExpired, login, completeLogin, logout, changePassword, forbidden],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
