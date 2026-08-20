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

function FlipCard({ icon: Icon, title, detail }) {
  const [flipped, setFlipped] = useState(false);

  return (
    <div
      className="h-28"
      style={{ perspective: "800px" }}
      onMouseEnter={() => setFlipped(true)}
      onMouseLeave={() => setFlipped(false)}
    >
      <div
        className="relative h-full w-full transition-transform duration-500"
        style={{
          transformStyle: "preserve-3d",
          transform: flipped ? "rotateY(180deg)" : "rotateY(0deg)",
        }}
      >
        {/* Front */}
        <div
          className="absolute inset-0 rounded-lg border border-bg-800 bg-bg-900/80 p-4"
          style={{ backfaceVisibility: "hidden" }}
        >
          <Icon size={20} className="text-cyan-400" />
          <p className="mt-2.5 text-sm font-semibold text-slate-300">{title}</p>
        </div>

        {/* Back */}
        <div
          className="absolute inset-0 flex items-center rounded-lg border border-cyan-500/30 bg-bg-800/80 p-4"
          style={{ backfaceVisibility: "hidden", transform: "rotateY(180deg)" }}
        >
          <p className="text-xs leading-relaxed text-slate-400">{detail}</p>
        </div>
      </div>
    </div>
  );
}

export default function LandingPage({ onLogin }) {
  return (
    <div className="console-bg flex min-h-screen items-center justify-center px-6 py-12">
      <div className="w-full max-w-3xl">
        {/* Header */}
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-lg border border-cyan-500/40 bg-cyan-500/10">
            <Radar size={22} className="text-cyan-400" />
          </div>
          <h1 className="text-xl font-semibold tracking-tight text-slate-200">
            Detection Digital Twin
          </h1>
          <p className="mx-auto mt-2 max-w-md text-sm text-slate-500">
            Secure SOC detection-testing console. Validate Sigma rules against a
            live Wazuh environment before they reach production.
          </p>
          <button
            onClick={onLogin}
            className="mt-5 rounded-md bg-cyan-500 px-5 py-2 text-sm font-semibold text-bg-950 transition-transform hover:scale-105"
          >
            Log in
          </button>
        </div>

        {/* Stats bar */}
        <div className="mb-6 flex justify-center gap-8 border-y border-bg-800 py-3">
          <div className="text-center">
            <p className="text-lg font-semibold text-cyan-400">8</p>
            <p className="text-[11px] text-slate-500">Features</p>
          </div>
          <div className="text-center">
            <p className="text-lg font-semibold text-cyan-400">1</p>
            <p className="text-[11px] text-slate-500">Live Wazuh instance</p>
          </div>
          <div className="text-center">
            <p className="text-lg font-semibold text-cyan-400">100%</p>
            <p className="text-[11px] text-slate-500">Sigma coverage</p>
          </div>
        </div>

        <p className="mb-3 text-center font-mono text-[11px] text-slate-600">
          Hover a card for details
        </p>

        {/* Feature grid */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {FEATURES.map((f) => (
            <FlipCard key={f.title} icon={f.icon} title={f.title} detail={f.detail} />
          ))}
        </div>
      </div>
    </div>
  );
}