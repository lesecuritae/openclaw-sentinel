import React, { createContext, useContext, useMemo, useState } from "react";
import { ApiClient } from "./api";

interface AuthContextValue {
  api: ApiClient;
  token: string;
  setToken: (token: string) => void;
  clearToken: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState("");
  const value = useMemo(
    () => ({ api: new ApiClient(token), token, setToken, clearToken: () => setToken("") }),
    [token],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("AuthProvider missing");
  return value;
}
