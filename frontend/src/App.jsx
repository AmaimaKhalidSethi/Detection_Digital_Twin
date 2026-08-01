import { useState } from "react";
import { FileCode2, PlayCircle, Bell, Grid3x3, Radar } from "lucide-react";
import RulesPage from "./pages/RulesPage";
import SimulatePage from "./pages/SimulatePage";
import AlertsPage from "./pages/AlertsPage";
import CoveragePage from "./pages/CoveragePage";

const TABS = [
  { id: "rules", label: "Rules", icon: FileCode2, component: RulesPage },
  { id: "simulate", label: "Simulate", icon: PlayCircle, component: SimulatePage },
  { id: "alerts", label: "Alerts", icon: Bell, component: AlertsPage },
  { id: "coverage", label: "Coverage", icon: Grid3x3, component: CoveragePage },
];

export default function App() {
  const [active, setActive] = useState("rules");
  const ActiveComponent = TABS.find((t) => t.id === active).component;

  return (
    <div className="console-bg min-h-screen">
      <header className="border-b border-graphite-700 bg-graphite-900/80 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-2.5">
            <Radar size={20} className="text-signal-400" />
            <div>
              <div className="text-sm font-semibold tracking-tight text-graphite-100">
                Detection Digital Twin
              </div>
              <div className="font-mono text-[11px] text-graphite-500">
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
                      ? "bg-signal-500/15 text-signal-400"
                      : "text-graphite-400 hover:bg-graphite-800 hover:text-graphite-200"
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
        <p className="font-mono text-[11px] text-graphite-600">
          FR/NFR references throughout map to the project's SRS/SDD document.
        </p>
      </footer>
    </div>
  );
}
