import { useEffect, useState } from "react";
import { useAuth } from "../lib/auth";

type Incident = { id: string; status: string; priority: string; source: string; component: string; risk_score: number; updated_at: string };
type Response = { items: Incident[]; limit: number; offset: number };

export default function IncidentsPage() {
  const { api } = useAuth();
  const [data, setData] = useState<Response | null>(null);
  const [error, setError] = useState("");
  useEffect(() => { api.get<Response>("/incidents?limit=100&offset=0").then(setData).catch((e: Error) => setError(e.message)); }, [api]);
  if (error) return <p role="alert" className="text-rose-300">{error}</p>;
  if (!data) return <p className="text-slate-400">Loading incidents…</p>;
  const critical = data.items.filter((item) => item.priority === "kritisch").length;
  const open = data.items.filter((item) => item.status !== "geschlossen").length;
  return <div className="space-y-8"><h2 className="text-3xl font-bold">Incidents</h2>
    <div className="grid gap-4 sm:grid-cols-3">{[["Kritische Vorfälle", critical], ["Offene Warnungen", open], ["Verlauf", data.items.length]].map(([label, value]) => <article className="rounded-2xl border border-slate-800 bg-slate-900 p-6" key={label as string}><p className="text-sm text-slate-400">{label}</p><p className="mt-2 text-3xl font-bold text-rose-300">{value}</p></article>)}</div>
    <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6 overflow-x-auto"><table className="w-full text-left text-sm"><thead className="text-slate-400"><tr><th>ID</th><th>Komponente</th><th>Priorität</th><th>Status</th><th>Risiko</th><th>Aktualisiert</th></tr></thead><tbody>{data.items.map((item) => <tr className="border-t border-slate-800" key={item.id}><td className="py-3 font-mono">{item.id}</td><td>{item.source} / {item.component}</td><td>{item.priority}</td><td>{item.status}</td><td>{item.risk_score}</td><td>{new Date(item.updated_at).toLocaleString()}</td></tr>)}</tbody></table></section>
  </div>;
}
