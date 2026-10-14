import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, setAuthHandlers, setCsrfToken, type Role, type User } from "../api";
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
      .catch(() => {
        if (!cancelled) setUser(null);
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

  const login = useCallback(async (email: string, password: string) => {
    const s = await api.login(email, password);
    setCsrfToken(s.csrf_token);
    setSessionExpired(false);
    setForbidden(null);
    setUser(s.user);
    return s.user;
  }, []);

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
      logout,
      changePassword,
      can: (role: Role) => hasRole(user, role),
      forbidden,
      dismissForbidden: () => setForbidden(null),
    }),
    [user, sessionExpired, login, logout, changePassword, forbidden],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
