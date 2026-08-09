import { useState } from "react";
import { LogIn, UserPlus, Radar } from "lucide-react";
import { api } from "../lib/api";

export default function LoginPage({ onLoggedIn }) {
  const [mode, setMode] = useState("login"); // "login" or "signup"
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      if (mode === "login") {
        await api.login(username, password);
      } else {
        await api.signup(username, password);
      }
      onLoggedIn();
    } catch (err) {
      setError(err.message || "Something went wrong");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="console-bg min-h-screen flex items-center justify-center">
      <div className="w-full max-w-sm rounded-xl border border-bg-800 bg-bg-900/80 p-8 backdrop-blur">
        <div className="mb-6 flex items-center gap-2.5">
          <Radar size={22} className="text-cyan-400" />
          <div>
            <div className="text-sm font-semibold tracking-tight text-slate-300">
              Detection Digital Twin
            </div>
            <div className="font-mono text-[11px] text-slate-500">
              SOC detection-testing console
            </div>
          </div>
        </div>

        <div className="mb-6 flex rounded-md border border-bg-800 p-1">
          <button
            type="button"
            onClick={() => setMode("login")}
            className={`flex-1 rounded px-3 py-1.5 text-sm transition-colors ${
              mode === "login" ? "bg-cyan-500/15 text-cyan-400" : "text-slate-500"
            }`}
          >
            Log in
          </button>
          <button
            type="button"
            onClick={() => setMode("signup")}
            className={`flex-1 rounded px-3 py-1.5 text-sm transition-colors ${
              mode === "signup" ? "bg-cyan-500/15 text-cyan-400" : "text-slate-500"
            }`}
          >
            Sign up
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block text-xs text-slate-500">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyan-500"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-slate-500">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-2 text-sm text-slate-200 outline-none focus:border-cyan-500"
            />
          </div>

          {error && (
            <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="flex w-full items-center justify-center gap-2 rounded-md bg-cyan-500/15 px-3 py-2 text-sm font-medium text-cyan-400 transition-colors hover:bg-cyan-500/25 disabled:opacity-50"
          >
            {mode === "login" ? <LogIn size={14} /> : <UserPlus size={14} />}
            {loading ? "Please wait..." : mode === "login" ? "Log in" : "Create account"}
          </button>
        </form>
      </div>
    </div>
  );
}