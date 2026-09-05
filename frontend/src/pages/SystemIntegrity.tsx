import { useEffect, useState } from "react";
import { useAuth } from "../lib/auth";

type Finding = { id: number; kind: string; subject: string; status: string; severity: string; score: number; timestamp: string; details: Record<string, unknown> };
type Response = { summary: { total: number; open: number; high_severity: number }; findings: Finding[] };

export default function SystemIntegrityPage() {
  const { api } = useAuth();
  const [data, setData] = useState<Response | null>(null);
  const [error, setError] = useState("");
  useEffect(() => { api.get<Response>("/integrity?limit=100").then(setData).catch((e: Error) => setError(e.message)); }, [api]);
  if (error) return <p role="alert" className="text-rose-300">{error}</p>;
  if (!data) return <p className="text-slate-400">Loading integrity…</p>;
  return <div className="space-y-8"><h2 className="text-3xl font-bold">System Integrity</h2>
    <div className="grid gap-4 sm:grid-cols-3">{[["Findings", data.summary.total], ["Open", data.summary.open], ["High severity", data.summary.high_severity]].map(([label, value]) => <article className="rounded-2xl border border-slate-800 bg-slate-900 p-6" key={label as string}><p className="text-sm text-slate-400">{label}</p><p className="mt-2 text-3xl font-bold text-cyan-300">{value}</p></article>)}</div>
    <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6 overflow-x-auto"><table className="w-full text-left text-sm"><thead className="text-slate-400"><tr><th>Time</th><th>Kind</th><th>Subject</th><th>Status</th><th>Severity</th><th>Score</th></tr></thead><tbody>{data.findings.map((f) => <tr className="border-t border-slate-800" key={f.id}><td className="py-3">{new Date(f.timestamp).toLocaleString()}</td><td>{f.kind}</td><td>{f.subject}</td><td>{f.status}</td><td>{f.severity}</td><td>{f.score}</td></tr>)}</tbody></table></section>
  </div>;
}
