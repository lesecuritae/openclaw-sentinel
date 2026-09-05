import { useEffect, useState } from "react";
import { useAuth } from "../lib/auth";

type Rule = { priority?: number; condition?: Record<string, unknown>; action?: string };
type Data = { rules: Rule[]; thresholds: { allow_below: number; challenge_below: number }; actions: string[] };

export default function PoliciesPage() {
  const { api } = useAuth();
  const [data, setData] = useState<Data | null>(null);
  const [error, setError] = useState("");
  const [score, setScore] = useState(92);
  const [ip, setIp] = useState("1.2.3.4");
  const [preview, setPreview] = useState<Record<string, unknown> | null>(null);
  useEffect(() => { api.get<Data>("/policies").then(setData).catch((e: Error) => setError(e.message)); }, [api]);
  if (error) return <p role="alert" className="text-rose-300">{error}</p>;
  if (!data) return <p className="text-slate-400">Loading policies…</p>;
  return <div className="space-y-8"><h2 className="text-3xl font-bold">Policies</h2><p className="text-slate-400">Deterministic rules control prepared responses. No LLM can authorize a block.</p>
    <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6 overflow-x-auto"><table className="w-full text-left text-sm"><thead className="text-slate-400"><tr><th>Priorität</th><th>Bedingung</th><th>Aktion</th><th>Letzte Ausführung</th></tr></thead><tbody>{data.rules.map((rule, index) => <tr className="border-t border-slate-800" key={index}><td className="py-3">{rule.priority ?? 100}</td><td>{JSON.stringify(rule.condition ?? {})}</td><td>{rule.action ?? "allow"}</td><td>—</td></tr>)}{data.rules.length === 0 && <tr><td className="py-4 text-slate-400" colSpan={4}>Threshold policy active; no explicit rules configured.</td></tr>}</tbody></table></section>
    <div className="text-sm text-slate-400">Allow below {data.thresholds.allow_below}; challenge below {data.thresholds.challenge_below}. Actions: {data.actions.join(", ")}.</div>
    <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6"><h3 className="font-semibold">Policy tester (Dry Run)</h3><div className="mt-4 flex flex-wrap gap-3"><input aria-label="IP" value={ip} onChange={(e) => setIp(e.target.value)} className="rounded bg-slate-950 p-2" /><input aria-label="Risk Score" type="number" min={0} max={100} value={score} onChange={(e) => setScore(Number(e.target.value))} className="w-28 rounded bg-slate-950 p-2" /><button className="rounded bg-cyan-500 px-4 py-2 text-slate-950" onClick={() => api.post<Record<string, unknown>>("/policies/test", { risk_score: score, ip }).then(setPreview)}>Test policy</button></div>{preview && <pre className="mt-4 overflow-auto text-sm text-emerald-300">{JSON.stringify(preview, null, 2)}</pre>}</section>
  </div>;
}
