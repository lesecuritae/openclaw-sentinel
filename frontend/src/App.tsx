import React from "react";
import { Routes, Route, NavLink } from "react-router-dom";
import {
  ShieldCheck, Activity, AlertTriangle, Globe, Lock, FlaskConical,
  Cpu, Waves, Zap, Server, Menu, X, Layers
} from "lucide-react";
import DashboardPage from "./pages/Dashboard";
import LiveEventsPage from "./pages/LiveEvents";
import IncidentsPage from "./pages/Incidents";
import IPAnalysisPage from "./pages/IPAnalysis";
import RiskPolicyPage from "./pages/RiskPolicy";
import ThreatIntelPage from "./pages/ThreatIntel";
import HAProxyPage from "./pages/HAProxy";
import ChallengePage from "./pages/Challenge";
import LLMPage from "./pages/LLM";
import MCPPage from "./pages/MCP";
import ServicesPage from "./pages/Services";
import SystemIntegrityPage from "./pages/SystemIntegrity";
import PoliciesPage from "./pages/Policies";
import ActionsPage from "./pages/Actions";
import AIAnalysisPage from "./pages/AIAnalysis";
import { OperationsPage } from "./pages/Operations";
import ConfigurationPage from "./pages/Configuration";
import { useAuth } from "./lib/auth";

const navItems = [
  { to: "/", label: "Dashboard", icon: ShieldCheck },
  { to: "/events", label: "Live Events", icon: Activity },
  { to: "/incidents", label: "Incidents", icon: AlertTriangle },
  { to: "/ip-analysis", label: "IP Analysis", icon: Globe },
  { to: "/risk-policy", label: "Risk & Policy", icon: Lock },
  { to: "/threat-intel", label: "Threat Intel", icon: Zap },
  { to: "/haproxy", label: "HAProxy", icon: Server },
  { to: "/challenge", label: "Challenge", icon: FlaskConical },
  { to: "/llm", label: "LLM", icon: Cpu },
  { to: "/mcp", label: "MCP", icon: Waves },
  { to: "/services", label: "Services", icon: Layers },
  { to: "/integrity", label: "System Integrity", icon: ShieldCheck },
  { to: "/policies", label: "Policies", icon: Lock },
  { to: "/actions", label: "Actions", icon: AlertTriangle },
  { to: "/ai-analysis", label: "AI Analysis", icon: Cpu },
  { to: "/audit-log", label: "Audit Log", icon: Lock },
  { to: "/reports/daily", label: "Reports", icon: Activity },
  { to: "/users", label: "Users", icon: ShieldCheck },
  { to: "/configuration", label: "Configuration", icon: Lock },
];

export default function App() {
  const { token, twoFactorEnabled, login, clearToken } = useAuth();
  const [mobileOpen, setMobileOpen] = React.useState(false);

  if (!token) {
    return <Login onLogin={login} twoFactorEnabled={twoFactorEnabled} />;
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex">
      {/* Sidebar */}
      <aside className="hidden md:flex w-64 flex-col bg-slate-900 border-r border-slate-800 sticky top-0 h-screen">
        <div className="p-6 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-emerald-400 to-amber-500 flex items-center justify-center shadow-lg shadow-emerald-900/40">
              <ShieldCheck className="text-slate-950 w-6 h-6" />
            </div>
            <div>
              <h1 className="font-extrabold text-lg leading-tight tracking-tight text-slate-50">Sentinel</h1>
              <p className="text-[11px] text-slate-400 font-medium">Phase 4 Dashboard</p>
            </div>
          </div>
        </div>
        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? "bg-slate-800 text-emerald-300 shadow-inner shadow-emerald-900/20"
                    : "text-slate-300 hover:text-slate-50 hover:bg-slate-800/60"
                }`
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="p-4 border-t border-slate-800">
          <div className="text-xs text-slate-500">v0.4.5 · Secure mode</div>
          <button className="mt-3 text-sm text-slate-300 hover:text-white" onClick={clearToken}>Sign out</button>
        </div>
      </aside>

      {/* Mobile header */}
      <div className="md:hidden fixed top-0 left-0 right-0 z-50 bg-slate-900/90 backdrop-blur-md border-b border-slate-800 px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-6 h-6 text-emerald-400" />
          <span className="font-extrabold text-slate-50">Sentinel</span>
        </div>
        <button onClick={() => setMobileOpen(!mobileOpen)} className="text-slate-300" aria-label="Toggle menu">
          {mobileOpen ? <X /> : <Menu />}
        </button>
      </div>

      {/* Mobile nav overlay */}
      {mobileOpen && (
        <div className="md:hidden fixed inset-0 z-40 bg-slate-950/80 backdrop-blur-sm" onClick={() => setMobileOpen(false)} />
      )}
      <div className={`md:hidden fixed top-14 left-0 bottom-0 w-64 bg-slate-900 border-r border-slate-800 z-50 transform transition-transform ${mobileOpen ? "translate-x-0" : "-translate-x-full"}`}>
        <nav className="px-3 py-4 space-y-1">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              onClick={() => setMobileOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive ? "bg-slate-800 text-emerald-300" : "text-slate-300 hover:text-slate-50"
                }`
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
      </div>

      {/* Main */}
      <main className="flex-1 min-h-screen overflow-y-auto">
        <div className="max-w-6xl mx-auto px-4 md:px-8 py-8 md:py-10">
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/events" element={<LiveEventsPage />} />
            <Route path="/incidents" element={<IncidentsPage />} />
            <Route path="/ip-analysis" element={<IPAnalysisPage />} />
            <Route path="/risk-policy" element={<RiskPolicyPage />} />
            <Route path="/threat-intel" element={<ThreatIntelPage />} />
            <Route path="/haproxy" element={<HAProxyPage />} />
            <Route path="/challenge" element={<ChallengePage />} />
            <Route path="/llm" element={<LLMPage />} />
            <Route path="/mcp" element={<MCPPage />} />
            <Route path="/services" element={<ServicesPage />} />
            <Route path="/integrity" element={<SystemIntegrityPage />} />
            <Route path="/policies" element={<PoliciesPage />} />
            <Route path="/actions" element={<ActionsPage />} />
            <Route path="/ai-analysis" element={<AIAnalysisPage />} />
            <Route path="/audit-log" element={<OperationsPage kind="audit-log" />} />
            <Route path="/reports/daily" element={<OperationsPage kind="reports/daily" />} />
            <Route path="/users" element={<OperationsPage kind="users" />} />
            <Route path="/configuration" element={<ConfigurationPage />} />
          </Routes>
        </div>
        <footer className="max-w-6xl mx-auto px-4 md:px-8 py-6 text-xs text-slate-500 border-t border-slate-900">
          OpenClaw Sentinel Phase 4 Dashboard · Security-first design · No secrets in browser
        </footer>
      </main>
    </div>
  );
}

function Login({ onLogin, twoFactorEnabled }: { onLogin: (apiKey: string, totpCode: string) => Promise<void>; twoFactorEnabled: boolean }) {
  const [value, setValue] = React.useState("");
  const [totpCode, setTotpCode] = React.useState("");
  const [error, setError] = React.useState("");
  return <main className="min-h-screen bg-slate-950 grid place-items-center p-6">
    <form className="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 p-8" onSubmit={async (event) => { event.preventDefault(); setError(""); try { await onLogin(value, totpCode); } catch (reason) { setError(reason instanceof Error ? reason.message : "Login failed"); } }}>
      <ShieldCheck className="h-10 w-10 text-cyan-400" />
      <h1 className="mt-4 text-2xl font-bold">OpenClaw Sentinel</h1>
      <p className="mt-2 text-sm text-slate-400">The API key remains in memory and is cleared when this page is closed.</p>
      <label className="mt-6 block text-sm" htmlFor="api-key">API key</label>
      <input id="api-key" type="password" autoComplete="off" value={value} onChange={(event) => setValue(event.target.value)} className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-950 p-3" />
      {twoFactorEnabled && <><label className="mt-4 block text-sm" htmlFor="totp-code">Authenticator code</label><input id="totp-code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code" value={totpCode} onChange={(event) => setTotpCode(event.target.value.replace(/\D/g, ""))} className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-950 p-3" required /></>}
      {error && <p className="mt-4 text-sm text-rose-300" role="alert">{error}</p>}
      <button className="mt-4 w-full rounded-lg bg-cyan-500 p-3 font-semibold text-slate-950">Connect</button>
    </form>
  </main>;
}
