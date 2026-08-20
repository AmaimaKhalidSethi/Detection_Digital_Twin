import { useState } from "react";
import {
  Radar,
  LayoutDashboard,
  RefreshCw,
  FileCode2,
  FlaskConical,
  PlayCircle,
  Bell,
  Grid3x3,
  GitCommitHorizontal,
  ArrowRight,
  Activity,
  CheckCircle2,
  ShieldCheck,
  Terminal,
} from "lucide-react";

const FEATURES = [
  {
    icon: LayoutDashboard,
    title: "Overview",
    detail: "See a snapshot of your rules, coverage, and recent activity.",
  },
  {
    icon: RefreshCw,
    title: "Environment",
    detail: "Manage your connected Wazuh manager and sync settings.",
  },
  {
    icon: FileCode2,
    title: "Rules",
    detail: "Create, edit, and version Sigma detection rules.",
  },
  {
    icon: FlaskConical,
    title: "Testing",
    detail: "Run rules through structured tests before deployment.",
  },
  {
    icon: PlayCircle,
    title: "Attack",
    detail: "Simulate MITRE ATT&CK techniques and generate telemetry.",
  },
  {
    icon: Bell,
    title: "Alerts",
    detail: "See which alerts your rules triggered from live telemetry.",
  },
  {
    icon: Grid3x3,
    title: "Coverage",
    detail: "Visualize which MITRE techniques your rules actually cover.",
  },
  {
    icon: GitCommitHorizontal,
    title: "Drift",
    detail: "See when rule changes affect detection outcomes over time.",
  },
];

function FeatureCard({ icon: Icon, title, detail }) {
  const [flipped, setFlipped] = useState(false);

  return (
    <div
      className="h-36 cursor-pointer"
      onClick={() => setFlipped((current) => !current)}
      onMouseEnter={() => setFlipped(true)}
      onMouseLeave={() => setFlipped(false)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          setFlipped((current) => !current);
        }
      }}
      role="button"
      tabIndex={0}
      aria-label={`${title}: ${flipped ? "show feature title" : "show feature details"}`}
      style={{ perspective: "800px" }}
    >
      <div className="relative h-full w-full transition-transform duration-500" style={{ transformStyle: "preserve-3d", transform: flipped ? "rotateY(180deg)" : "rotateY(0deg)" }}>
        <div className="absolute inset-0 rounded-lg border border-bg-800 bg-bg-900/75 p-4" style={{ backfaceVisibility: "hidden" }}>
          <div className="mb-3 flex h-8 w-8 items-center justify-center rounded-md border border-cyan-500/20 bg-cyan-500/10">
            <Icon size={16} className="text-cyan-400" />
          </div>
          <p className="text-sm font-semibold text-slate-300">{title}</p>
          <p className="mt-2 font-mono text-[10px] uppercase tracking-wider text-slate-600">View details <span className="text-cyan-500">+</span></p>
        </div>
        <div className="absolute inset-0 flex items-center rounded-lg border border-cyan-500/30 bg-bg-800/80 p-4" style={{ backfaceVisibility: "hidden", transform: "rotateY(180deg)" }}>
          <p className="text-xs leading-relaxed text-slate-300">{detail}</p>
        </div>
      </div>
    </div>
  );
}

export default function LandingPage({ onLogin }) {
  return (
    <div className="console-bg min-h-screen overflow-hidden px-6 py-8 sm:py-12">
      <div className="mx-auto w-full max-w-6xl">
        <header className="mb-12 flex items-center justify-between border-b border-bg-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-md border border-cyan-500/40 bg-cyan-500/10">
              <Radar size={18} className="text-cyan-400" />
            </div>
            <div>
              <p className="text-sm font-semibold tracking-tight text-slate-200">Detection Digital Twin</p>
              <p className="font-mono text-[10px] uppercase tracking-widest text-slate-600">SOC detection-testing console</p>
            </div>
          </div>
          <div className="hidden items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-slate-600 sm:flex">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
            System ready
          </div>
        </header>

        <main className="grid items-center gap-12 lg:grid-cols-[0.85fr_1.15fr] lg:gap-16">
          <section>
            <div className="mb-5 flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-cyan-400">
              <ShieldCheck size={15} />
              Detection engineering workspace
            </div>
            <h1 className="max-w-xl text-4xl font-semibold leading-[1.08] tracking-tight text-slate-100 sm:text-5xl">
              Prove your detections before production does.
            </h1>
            <p className="mt-5 max-w-lg text-base leading-7 text-slate-400">
              Validate Sigma rules against a live Wazuh environment, simulate ATT&CK techniques, and see exactly where coverage breaks.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <button onClick={onLogin} className="inline-flex items-center gap-2 rounded-md bg-cyan-500 px-4 py-2.5 text-sm font-semibold text-bg-950 transition-colors hover:bg-cyan-400">
                Enter console <ArrowRight size={16} />
              </button>
              <span className="font-mono text-[11px] text-slate-600">Private workspace / authenticated access</span>
            </div>
            <div className="mt-10 grid max-w-lg grid-cols-3 border-y border-bg-800 py-4">
              <div><p className="text-xl font-semibold text-cyan-400">08</p><p className="mt-1 font-mono text-[10px] uppercase tracking-wider text-slate-600">Workspaces</p></div>
              <div className="border-l border-bg-800 pl-4"><p className="text-xl font-semibold text-cyan-400">01</p><p className="mt-1 font-mono text-[10px] uppercase tracking-wider text-slate-600">Wazuh link</p></div>
              <div className="border-l border-bg-800 pl-4"><p className="text-xl font-semibold text-cyan-400">100%</p><p className="mt-1 font-mono text-[10px] uppercase tracking-wider text-slate-600">Traceability</p></div>
            </div>
          </section>

          <section className="landing-preview rounded-xl border border-bg-800 bg-bg-950/80 p-3 shadow-2xl shadow-black/30 sm:p-4" aria-label="Console preview">
            <div className="flex items-center justify-between border-b border-bg-800 px-2 pb-3">
              <div className="flex items-center gap-2"><Terminal size={14} className="text-cyan-400" /><span className="font-mono text-[11px] text-slate-400">rule-validation / live</span></div>
              <span className="flex items-center gap-1.5 font-mono text-[10px] text-emerald-400"><Activity size={12} /> CONNECTED</span>
            </div>
            <div className="grid gap-3 p-2 sm:grid-cols-[1.15fr_0.85fr] sm:p-3">
              <div className="rounded-md border border-bg-800 bg-bg-900 p-4">
                <div className="mb-4 flex items-center justify-between"><span className="font-mono text-[10px] uppercase tracking-wider text-slate-500">Latest evaluation</span><CheckCircle2 size={15} className="text-emerald-400" /></div>
                <p className="font-mono text-xs text-slate-300">proc_creation_powershell</p>
                <p className="mt-1 font-mono text-[10px] text-slate-600">sigma / windows / execution</p>
                <div className="mt-6 space-y-3">
                  <div className="flex justify-between font-mono text-[10px]"><span className="text-slate-500">Telemetry matched</span><span className="text-emerald-400">42 events</span></div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-bg-800"><div className="h-full w-[78%] rounded-full bg-emerald-400" /></div>
                  <div className="flex justify-between font-mono text-[10px]"><span className="text-slate-500">Rule confidence</span><span className="text-cyan-400">78%</span></div>
                </div>
              </div>
              <div className="rounded-md border border-bg-800 bg-bg-900 p-4">
                <span className="font-mono text-[10px] uppercase tracking-wider text-slate-500">ATT&amp;CK coverage</span>
                <p className="mt-4 text-3xl font-semibold text-slate-200">14<span className="text-sm text-slate-600"> / 18</span></p>
                <p className="mt-1 font-mono text-[10px] text-slate-600">techniques mapped</p>
                <div className="mt-6 grid grid-cols-6 gap-1.5">{Array.from({ length: 18 }, (_, index) => <span key={index} className={`h-3 rounded-sm ${index < 14 ? "bg-cyan-400/80" : "bg-fuchsia-400/60"}`} />)}</div>
                <p className="mt-3 font-mono text-[10px] text-fuchsia-400">4 blind spots to investigate</p>
              </div>
            </div>
            <div className="border-t border-bg-800 px-2 pt-3 font-mono text-[10px] text-slate-600">&gt; simulation complete · 0.42s · evidence attached</div>
          </section>
        </main>

        <section className="mt-16 border-t border-bg-800 pt-6">
          <div className="mb-4 flex items-end justify-between"><div><p className="font-mono text-[10px] uppercase tracking-[0.2em] text-cyan-400">One workflow, eight surfaces</p><h2 className="mt-1 text-lg font-medium text-slate-300">From rule authoring to measurable coverage.</h2></div><span className="hidden font-mono text-[10px] text-slate-600 sm:block">BUILT FOR REPEATABLE ANALYSIS</span></div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">{FEATURES.map((feature) => <FeatureCard key={feature.title} {...feature} />)}</div>
        </section>
      </div>
    </div>
  );
}