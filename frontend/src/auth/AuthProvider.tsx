import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ApiError, api, isMfaChallenge, setAuthHandlers, setCsrfToken, type Role, type SessionInfo, type User } from "../api";
import { AuthContext, hasRole, type AuthState } from "./context";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null | undefined>(undefined);
  const [sessionExpired, setSessionExpired] = useState(false);
  const [forbidden, setForbidden] = useState<string | null>(null);
  const userRef = useRef(user);

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
        setCsrfToken(s.csrf_token);
        setUser(s.user);
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
  }, []);

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
    setUser(s.user);
  }, []);

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
      setUser(null);
    }
  }, []);

  const changePassword = useCallback(async (current: string, next: string) => {
    await api.changePassword(current, next);
  }, []);

  const value = useMemo<AuthState>(
    () => ({
      user,
      sessionExpired,
      login,
      completeLogin,
      logout,
      changePassword,
      can: (role: Role) => hasRole(user, role),
      forbidden,
      dismissForbidden: () => setForbidden(null),
    }),
    [user, sessionExpired, login, completeLogin, logout, changePassword, forbidden],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
