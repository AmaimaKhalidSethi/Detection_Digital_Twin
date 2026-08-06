import { useState } from "react";
import { FileCode2, PlayCircle, Bell, FlaskConical, Grid3x3, Radar, GitCommitHorizontal, LayoutDashboard } from "lucide-react";
import RulesLibraryPage from "./pages/RulesLibraryPage";
import RuleTestingPage from "./pages/RuleTestingPage";
import SimulatePage from "./pages/SimulatePage";
import AlertsPage from "./pages/AlertsPage";
import CoveragePage from "./pages/CoveragePage";
import DriftPage from "./pages/DriftPage";
import OverviewPage from "./pages/OverviewPage";

const TABS = [
  { id: "overview", label: "Overview", icon: LayoutDashboard, component: OverviewPage },
  { id: "library", label: "Rule Library", icon: FileCode2, component: RulesLibraryPage },
  { id: "testing", label: "Rule Testing", icon: FlaskConical, component: RuleTestingPage },
  { id: "simulate", label: "Simulate", icon: PlayCircle, component: SimulatePage },
  { id: "alerts", label: "Alerts", icon: Bell, component: AlertsPage },
  { id: "coverage", label: "Coverage", icon: Grid3x3, component: CoveragePage },
  { id: "drift", label: "Drift", icon: GitCommitHorizontal, component: DriftPage },
];

export default function App() {
  const [active, setActive] = useState("overview");
  const ActiveComponent = TABS.find((t) => t.id === active).component;

  return (
    <div className="console-bg min-h-screen">
      <header className="border-b border-bg-800 bg-bg-900/80 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-2.5">
            <Radar size={20} className="text-cyan-400" />
            <div>
              <div className="text-sm font-semibold tracking-tight text-slate-300">
                Detection Digital Twin
              </div>
              <div className="font-mono text-[11px] text-slate-500">
                SOC detection-testing console
              </div>
            </div>
          </div>
          <nav className="flex gap-1">
            {TABS.map((tab) => {
              const Icon = tab.icon;
              const isActive = tab.id === active;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActive(tab.id)}
                  className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm transition-colors ${
                    isActive
                      ? "bg-cyan-500/15 text-cyan-400"
                      : "text-slate-500 hover:bg-bg-800 hover:text-slate-300"
                  }`}
                >
                  <Icon size={14} />
                  {tab.label}
                </button>
              );
            })}
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-8">
        <ActiveComponent />
      </main>

      <footer className="mx-auto max-w-6xl px-6 pb-8 pt-2">
        <p className="font-mono text-[11px] text-slate-500">
          FR/NFR references throughout map to the project's SRS/SDD document.
        </p>
      </footer>
    </div>
  );
}
