import { useEffect, useState } from "react";
import { useAuth } from "../lib/auth";

interface ConfigResponse {
  value: Record<string, unknown>;
}

export function ConfigEditor({ name, title }: { name: string; title: string }) {
  const { api } = useAuth();
  const [text, setText] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    api.get<ConfigResponse>(`/config/${name}`)
      .then((response) => setText(JSON.stringify(response.value, null, 2)))
      .catch((reason: Error) => setError(reason.message));
  }, [api, name]);

  async function save() {
    setError("");
    setMessage("");
    try {
      const value = JSON.parse(text) as Record<string, unknown>;
      await api.put(`/config/${name}`, value);
      setMessage("Saved safely. Restart Sentinel to activate this configuration.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to save configuration");
    }
  }

  return <section className="space-y-4">
    <h2 className="text-3xl font-bold">{title}</h2>
    <p className="text-sm text-slate-400">Unknown fields and invalid thresholds are rejected by the backend.</p>
    {error && <p role="alert" className="rounded-lg bg-rose-950 p-4 text-rose-300">{error}</p>}
    {message && <p role="status" className="rounded-lg bg-emerald-950 p-4 text-emerald-300">{message}</p>}
    <textarea
      aria-label={`${title} JSON configuration`}
      className="min-h-[32rem] w-full rounded-xl border border-slate-700 bg-slate-900 p-5 font-mono text-sm text-cyan-100"
      onChange={(event) => setText(event.target.value)}
      spellCheck={false}
      value={text}
    />
    <button className="rounded-lg bg-cyan-600 px-5 py-2 font-semibold hover:bg-cyan-500" onClick={save} type="button">
      Save configuration
    </button>
  </section>;
}
