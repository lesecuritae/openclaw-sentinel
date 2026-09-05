import { useState } from "react";
import { ConfigEditor } from "../components/ConfigEditor";

const sections = [
  ["general", "General"], ["collectors", "Collectors"], ["intelligence", "Threat Intelligence"],
  ["policy", "Policies"], ["response", "Response"], ["llm", "LLM"], ["users", "Users"],
] as const;

export default function ConfigurationPage() {
  const [selected, setSelected] = useState("policy");
  const supported: Record<string, string> = { intelligence: "intelligence", policy: "policy" };
  return <div className="space-y-6"><h2 className="text-3xl font-bold">Configuration</h2><div className="flex flex-wrap gap-2">{sections.map(([key, label]) => <button key={key} onClick={() => setSelected(key)} className={`rounded px-3 py-2 text-sm ${selected === key ? "bg-cyan-600" : "bg-slate-800"}`}>{label}</button>)}</div>{supported[selected] ? <ConfigEditor name={supported[selected]} title={sections.find(([key]) => key === selected)?.[1] ?? selected} /> : <p className="rounded-xl border border-slate-800 bg-slate-900 p-6 text-slate-400">{sections.find(([key]) => key === selected)?.[1]} is configured through environment variables and deployment files.</p>}</div>;
}
