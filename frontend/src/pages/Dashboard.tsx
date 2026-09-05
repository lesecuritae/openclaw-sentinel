import { useEffect, useState } from "react";
import { useAuth } from "../lib/auth";

interface ServiceHealth { service: string; last_event: string; risk_score: number; warnings: number }
interface Summary { current_risk: number; events_24h: number; blocks_24h: number; challenges_24h: number; top_attackers: {ip: string; count: number}[]; affected_services: string[]; container_count: number; warnings_24h: number; service_health: ServiceHealth[] }

export default function DashboardPage() {
  const { api } = useAuth(); const [data, setData] = useState<Summary>(); const [error, setError] = useState("");
  useEffect(() => { let cancelled = false; let timer: NodeJS.Timeout | null = null; const load = () => { api.get<Summary>("/dashboard").then((d) => { if (!cancelled) setData(d); }).catch((e: Error) => { if (!cancelled) setError(e.message); }); }; load(); timer = setInterval(load, 30000); return () => { cancelled = true; if (timer) clearInterval(timer); }; }, [api]);
  if (error) return <p role="alert" className="text-rose-300">{error}</p>;
  if (!data) return <p className="text-slate-400">Loading dashboard…</p>;
  const cards = [["Current risk", data.current_risk], ["Events (24h)", data.events_24h], ["Warnings (24h)", data.warnings_24h], ["Containers observed", data.container_count], ["Blocks", data.blocks_24h], ["Challenges", data.challenges_24h]];
  return <div className="space-y-8"><h2 className="text-3xl font-bold">Security overview</h2>
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">{cards.map(([label, value]) => <article key={label} className="rounded-2xl border border-slate-800 bg-slate-900 p-6"><p className="text-sm text-slate-400">{label}</p><p className="mt-2 text-3xl font-bold text-cyan-300">{value}</p></article>)}</div>
    <div className="grid gap-6 lg:grid-cols-2"><section className="rounded-2xl border border-slate-800 bg-slate-900 p-6"><h3 className="font-semibold">Top attackers</h3>{data.top_attackers.length ? <ul className="mt-4 space-y-2">{data.top_attackers.map((row) => <li key={row.ip} className="flex justify-between"><code>{row.ip}</code><span>{row.count}</span></li>)}</ul> : <p className="mt-4 text-slate-400">No events recorded.</p>}</section>
    <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6"><h3 className="font-semibold">Affected services</h3>{data.affected_services.length ? <ul className="mt-4 space-y-2">{data.affected_services.map((service) => <li key={service}>{service}</li>)}</ul> : <p className="mt-4 text-slate-400">No services recorded.</p>}</section></div>
    <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6"><h3 className="font-semibold">Service monitoring</h3>{data.service_health.length ? <div className="mt-4 overflow-x-auto"><table className="w-full text-left text-sm"><thead className="text-slate-400"><tr><th>Service</th><th>Risk</th><th>Warnings</th><th>Last event</th></tr></thead><tbody>{data.service_health.map((row) => <tr className="border-t border-slate-800" key={row.service}><td className="py-3">{row.service}</td><td>{row.risk_score}</td><td>{row.warnings}</td><td>{new Date(row.last_event).toLocaleString()}</td></tr>)}</tbody></table></div> : <p className="mt-4 text-slate-400">No service events recorded.</p>}</section>
  </div>;
}
