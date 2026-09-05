import { useEffect, useState } from "react";
import { useAuth } from "../lib/auth";

type Incident = { id: string; component: string; risk_score: number; priority: string };
export default function AIAnalysisPage() {
  const { api } = useAuth();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [analysis, setAnalysis] = useState<unknown>(null);
  const [error, setError] = useState("");
  useEffect(() => { api.get<{ items: Incident[] }>("/incidents?limit=100&offset=0").then((data) => setIncidents(data.items)).catch((e: Error) => setError(e.message)); }, [api]);
  if (error) return <p role="alert" className="text-rose-300">{error}</p>;
  return <div className="space-y-8"><h2 className="text-3xl font-bold">AI Analysis</h2><p className="text-slate-400">Advisory analysis only. The analyst cannot change policies or execute actions.</p><section className="rounded-2xl border border-slate-800 bg-slate-900 p-6"><label className="block text-sm text-slate-400" htmlFor="incident">Incident</label><select id="incident" className="mt-2 rounded bg-slate-950 p-2" onChange={(e) => api.get(`/ai/incident/${e.target.value}`).then(setAnalysis).catch((reason: Error) => setError(reason.message))}><option value="">Select an incident</option>{incidents.map((item) => <option key={item.id} value={item.id}>{item.id} · {item.component} · risk {item.risk_score}</option>)}</select>{analysis && <pre className="mt-6 overflow-auto whitespace-pre-wrap text-sm text-emerald-300">{JSON.stringify(analysis, null, 2)}</pre>}</section></div>;
}
