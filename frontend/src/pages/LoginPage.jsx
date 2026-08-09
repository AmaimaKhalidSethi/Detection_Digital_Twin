import { useState } from "react";
import { Eye, EyeOff, LoaderCircle, Radar } from "lucide-react";
import { useAuth } from "../auth/AuthContext";

export default function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit(event) {
    event.preventDefault();
    if (!username.trim() || !password) {
      setError("Enter your username and password.");
      return;
    }
    setSubmitting(true);
    setError("");
    try {
      await login(username, password);
    } catch (err) {
      setError(err.message || "Unable to sign in.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="console-bg flex min-h-screen items-center justify-center px-6 py-10">
      <section className="w-full max-w-md rounded-xl border border-bg-800 bg-bg-900/95 p-7 shadow-2xl shadow-black/30">
        <div className="mb-8 flex items-start gap-3">
          <div className="rounded-lg border border-cyan-500/25 bg-cyan-500/10 p-2.5"><Radar size={22} className="text-cyan-400" /></div>
          <div>
            <h1 className="text-base font-semibold tracking-tight text-slate-200">Detection Digital Twin</h1>
            <p className="mt-0.5 font-mono text-[11px] text-slate-500">Secure SOC detection-testing console</p>
          </div>
        </div>
        <div className="mb-6 border-l-2 border-cyan-500/60 pl-3">
          <p className="text-sm font-medium text-slate-300">Secure platform access</p>
          <p className="mt-1 text-sm leading-5 text-slate-500">Sign in with your approved internal account to access environments, validation, and detection coverage.</p>
        </div>
        <form onSubmit={submit} className="space-y-4" noValidate>
          <label className="block text-sm text-slate-400">Email or username
            <input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" disabled={submitting}
              className="mt-1.5 w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-2.5 text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyan-500/70 focus:outline-none disabled:opacity-60" placeholder="analyst@example.internal" />
          </label>
          <label className="block text-sm text-slate-400">Password
            <span className="relative mt-1.5 block">
              <input value={password} onChange={(event) => setPassword(event.target.value)} type={showPassword ? "text" : "password"} autoComplete="current-password" disabled={submitting}
                className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-2.5 pr-11 text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyan-500/70 focus:outline-none disabled:opacity-60" placeholder="Enter your password" />
              <button type="button" onClick={() => setShowPassword((visible) => !visible)} className="absolute right-2 top-2 rounded p-1 text-slate-500 hover:text-slate-300" aria-label={showPassword ? "Hide password" : "Show password"}>
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </span>
          </label>
          {error && <p role="alert" className="rounded-md border border-red-500/25 bg-red-500/10 px-3 py-2 text-sm text-red-300">{error}</p>}
          <button type="submit" disabled={submitting} className="flex w-full items-center justify-center gap-2 rounded-md bg-cyan-500 px-4 py-2.5 text-sm font-semibold text-bg-950 transition-colors hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60">
            {submitting && <LoaderCircle size={16} className="animate-spin" />}{submitting ? "Authenticating…" : "Sign in securely"}
          </button>
        </form>
      </section>
    </main>
  );
}
