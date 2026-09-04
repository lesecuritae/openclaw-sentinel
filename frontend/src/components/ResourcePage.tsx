import { useEffect, useState } from "react";
import { useAuth } from "../lib/auth";

export function ResourcePage({ title, path }: { title: string; path: string }) {
  const { api } = useAuth();
  const [data, setData] = useState<unknown>();
  const [error, setError] = useState("");
  useEffect(() => { api.get(path).then(setData).catch((reason: Error) => setError(reason.message)); }, [api, path]);
  return <section className="space-y-4"><h2 className="text-3xl font-bold">{title}</h2>
    {error && <p role="alert" className="rounded-lg bg-rose-950 p-4 text-rose-300">{error}</p>}
    {!error && data === undefined && <p className="text-slate-400">Loading…</p>}
    {data !== undefined && <pre className="overflow-auto rounded-xl border border-slate-800 bg-slate-900 p-5 text-sm text-cyan-100">{JSON.stringify(data, null, 2)}</pre>}
  </section>;
}
