import { useEffect, useState } from "react";
import { useAuth } from "../lib/auth";

export function OperationsPage({ kind }: { kind: "users" | "audit-log" | "reports/daily" }) {
  const { api } = useAuth();
  const [data, setData] = useState<unknown>(null);
  const [error, setError] = useState("");
  useEffect(() => { api.get(`/` + kind).then(setData).catch((e: Error) => setError(e.message)); }, [api, kind]);
  if (error) return <p role="alert" className="text-rose-300">{error}</p>;
  return <div className="space-y-6"><h2 className="text-3xl font-bold">{kind === "audit-log" ? "Audit Log" : kind === "reports/daily" ? "Reports" : "Users"}</h2><pre className="overflow-auto rounded-2xl border border-slate-800 bg-slate-900 p-6 text-sm text-emerald-300">{JSON.stringify(data, null, 2)}</pre></div>;
}
