import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import { ApiClient } from "./api";

interface AuthContextValue {
  api: ApiClient;
  token: string;
  twoFactorEnabled: boolean;
  login: (apiKey: string, totpCode: string) => Promise<void>;
  clearToken: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState("");
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(false);
  useEffect(() => {
    fetch("/api/v1/auth/status")
      .then((response) => response.json())
      .then((status: { two_factor_enabled: boolean }) => setTwoFactorEnabled(status.two_factor_enabled))
      .catch(() => setTwoFactorEnabled(false));
  }, []);
  async function login(apiKey: string, totpCode: string) {
    if (!twoFactorEnabled) {
      setToken(apiKey);
      return;
    }
    const response = await fetch("/api/v1/auth/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ api_key: apiKey, totp_code: totpCode }),
    });
    if (!response.ok) throw new Error("Invalid API key or verification code");
    const session = await response.json() as { token: string };
    setToken(session.token);
  }
  const value = useMemo(
    () => ({
      api: new ApiClient(token), token, twoFactorEnabled, login,
      clearToken: () => {
        if (twoFactorEnabled && token) {
          fetch("/api/v1/auth/logout", {
            method: "POST", headers: { Authorization: `Bearer ${token}` },
          }).catch(() => undefined);
        }
        setToken("");
      },
    }),
    [token, twoFactorEnabled],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("AuthProvider missing");
  return value;
}
