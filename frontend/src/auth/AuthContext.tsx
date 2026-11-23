import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api } from "../api/client";
import type { Me, Role, TokenResponse } from "../api/types";

type Status = "loading" | "anonymous" | "authenticated";

interface AuthValue {
  status: Status;
  me: Me | null;
  /** Why the user was sent back to the login screen, if the session ended on its own. */
  endedReason: string | null;
  login: (username: string, password: string, totp?: string) => Promise<void>;
  logout: () => Promise<void>;
  reloadMe: () => Promise<Me | null>;
  can: (...roles: Role[]) => boolean;
}

const Ctx = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>("loading");
  const [me, setMe] = useState<Me | null>(null);
  const [endedReason, setEndedReason] = useState<string | null>(null);

  const reloadMe = useCallback(async () => {
    try {
      const m = await api.get<Me>("/api/auth/me");
      setMe(m);
      setStatus("authenticated");
      return m;
    } catch {
      return null;
    }
  }, []);

  useEffect(() => {
    api.onAuthLost(() => {
      setMe(null);
      setStatus("anonymous");
      setEndedReason("Your session ended (expired or revoked). Sign in again.");
    });
    // A page reload loses the in-memory access token; the HttpOnly refresh cookie may still be valid.
    void (async () => {
      const t = await api.refresh();
      if (t) {
        const m = await reloadMe();
        if (!m) setStatus("anonymous");
      } else {
        setStatus("anonymous");
      }
    })();
    return () => api.onAuthLost(null);
  }, [reloadMe]);

  // Keep role / MFA freshness / restriction current: the server may change them at any time
  // (admin role change, step-up window lapsing). /api/auth/me is the source of truth.
  useEffect(() => {
    if (status !== "authenticated") return;
    const t = window.setInterval(() => {
      if (document.visibilityState === "visible") void reloadMe();
    }, 20_000);
    return () => window.clearInterval(t);
  }, [status, reloadMe]);

  const login = useCallback(
    async (username: string, password: string, totp?: string) => {
      const body: Record<string, string> = { username, password };
      if (totp) body.totp_code = totp;
      const t = await api.post<TokenResponse>("/api/auth/login", body, { anonymous: true });
      api.setSession(t);
      setEndedReason(null);
      await reloadMe();
    },
    [reloadMe],
  );

  const logout = useCallback(async () => {
    try {
      await api.post("/api/auth/logout");
    } finally {
      api.setSession(null);
      setMe(null);
      setEndedReason(null);
      setStatus("anonymous");
    }
  }, []);

  const value = useMemo<AuthValue>(
    () => ({
      status,
      me,
      endedReason,
      login,
      logout,
      reloadMe,
      can: (...roles: Role[]) => !!me && roles.includes(me.user.role),
    }),
    [status, me, endedReason, login, logout, reloadMe],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}
