import { useEffect, useState } from "react";
import { useAuth } from "../lib/auth";

type Action = { id: number; timestamp: string; ip: string; action: string; reason: string; result: string; expires_at: string | null; active: boolean };
export default function ActionsPage() {
  const { api } = useAuth();
  const [items, setItems] = useState<Action[]>([]);
  const [error, setError] = useState("");
  const load = () => api.get<{ actions: Action[] }>("/actions?limit=100").then((data) => setItems(data.actions)).catch((e: Error) => setError(e.message));
  useEffect(() => { load(); }, [api]);
  if (error) return <p role="alert" className="text-rose-300">{error}</p>;
  return <div className="space-y-8"><h2 className="text-3xl font-bold">Actions</h2><p className="text-slate-400">Provider executions are policy-bound, time-limited and audited.</p><section className="rounded-2xl border border-slate-800 bg-slate-900 p-6 overflow-x-auto"><table className="w-full text-left text-sm"><thead className="text-slate-400"><tr><th>Zeitpunkt</th><th>IP</th><th>Aktion</th><th>Grund</th><th>Ergebnis</th><th>Ablauf</th><th>Status</th></tr></thead><tbody>{items.map((item) => <tr className="border-t border-slate-800" key={item.id}><td className="py-3">{new Date(item.timestamp).toLocaleString()}</td><td>{item.ip}</td><td>{item.action}</td><td>{item.reason || "—"}</td><td>{item.result || "—"}</td><td>{item.expires_at ? new Date(item.expires_at).toLocaleString() : "—"}</td><td>{item.active ? "active" : "inactive"}</td></tr>)}</tbody></table></section></div>;
}
