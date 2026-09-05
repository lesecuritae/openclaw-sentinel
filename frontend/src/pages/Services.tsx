import { useEffect, useState } from "react";
import { useAuth } from "../lib/auth";

interface ServiceItem {
  service: string;
  observed_status: string;
  current_risk: number;
  rolling_window_hours: number;
  last_activity: string | null;
  last_event_type: string;
  event_count: number;
  warnings_24h: number;
}

interface ServicesResponse {
  services: ServiceItem[];
  rolling_window_hours: number;
  container_services: string[];
  warnings_summary: number;
  incidents_summary: number;
}

export default function ServicesPage() {
  const { api } = useAuth();
  const [data, setData] = useState<ServicesResponse | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      api.get<ServicesResponse>("/services?rolling_window_hours=24")
        .then((d) => { if (!cancelled) setData(d); })
        .catch((e: Error) => { if (!cancelled) setError(e.message); });
    };
    load();
    const id = setInterval(load, 30000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [api]);

  if (error) return <p role="alert" className="text-rose-300">{error}</p>;
  if (!data) return <p className="text-slate-400">Loading services…</p>;

  return (
    <div className="space-y-8">
      <h2 className="text-3xl font-bold">Services dashboard</h2>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <article className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
          <p className="text-sm text-slate-400">Services</p>
          <p className="mt-2 text-3xl font-bold text-cyan-300">{data.services.length}</p>
        </article>
        <article className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
          <p className="text-sm text-slate-400">Warnings (24h)</p>
          <p className="mt-2 text-3xl font-bold text-amber-300">{data.warnings_summary}</p>
        </article>
        <article className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
          <p className="text-sm text-slate-400">Incidents summary</p>
          <p className="mt-2 text-3xl font-bold text-rose-300">{data.incidents_summary}</p>
        </article>
        <article className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
          <p className="text-sm text-slate-400">Observing containers</p>
          <p className="mt-2 text-3xl font-bold text-emerald-300">{data.container_services.length}</p>
        </article>
      </div>
      <section className="rounded-2xl border border-slate-800 bg-slate-900 p-6">
        <h3 className="font-semibold">Service monitoring ({data.rolling_window_hours}h window)</h3>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-slate-400">
              <tr>
                <th>Service</th>
                <th>Observed status</th>
                <th>Current risk</th>
                <th>Last event type</th>
                <th>Last activity</th>
                <th>Events (window)</th>
                <th>Warnings</th>
              </tr>
            </thead>
            <tbody>
              {data.services.map((s) => (
                <tr className="border-t border-slate-800" key={s.service}>
                  <td className="py-3 font-medium">{s.service}</td>
                  <td className="py-3">{s.observed_status}</td>
                  <td className="py-3">{s.current_risk}</td>
                  <td className="py-3">{s.last_event_type}</td>
                  <td className="py-3">{s.last_activity ? new Date(s.last_activity).toLocaleString() : "—"}</td>
                  <td className="py-3">{s.event_count}</td>
                  <td className="py-3">{s.warnings_24h}</td>
                </tr>
              ))}
              {data.services.length === 0 && (
                <tr><td className="py-4 text-slate-400" colSpan={7}>No service events recorded.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
