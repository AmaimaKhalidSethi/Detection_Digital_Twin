import { useState } from "react";
import { FileCode2, PlayCircle, Bell, FlaskConical, Grid3x3, Radar, GitCommitHorizontal, LayoutDashboard, RefreshCw, LogOut, LoaderCircle } from "lucide-react";
import { useAuth } from "./auth/AuthContext";
import LandingPage from "./pages/LandingPage";
import LoginPage from "./pages/LoginPage";
import RulesLibraryPage from "./pages/RulesLibraryPage";
import RuleTestingPage from "./pages/RuleTestingPage";
import SimulatePage from "./pages/SimulatePage";
import AlertsPage from "./pages/AlertsPage";
import CoveragePage from "./pages/CoveragePage";
import DriftPage from "./pages/DriftPage";
import EnvironmentPage from "./pages/EnvironmentPage";
import OverviewPage from "./pages/OverviewPage";

const GROUPS = [
  {
    label: "System",
    tabs: [
      { id: "overview", label: "Overview", icon: LayoutDashboard, component: OverviewPage },
      { id: "environment", label: "Environment", icon: RefreshCw, component: EnvironmentPage },
    ]
  },
  {
    label: "Library",
    tabs: [
      { id: "library", label: "Rules", icon: FileCode2, component: RulesLibraryPage },
      { id: "testing", label: "Testing", icon: FlaskConical, component: RuleTestingPage },
    ]
  },
  {
    label: "Simulation",
    tabs: [
      { id: "simulate", label: "Attack", icon: PlayCircle, component: SimulatePage },
      { id: "alerts", label: "Alerts", icon: Bell, component: AlertsPage },
    ]
  },
  {
    label: "Reconcile",
    tabs: [
      { id: "coverage", label: "Coverage", icon: Grid3x3, component: CoveragePage },
      { id: "drift", label: "Drift", icon: GitCommitHorizontal, component: DriftPage },
    ]
  }
];

export default function App() {
  const { user, status, logout } = useAuth();
  const [active, setActive] = useState("overview");
  const [showLogin, setShowLogin] = useState(false);

  // Find the active component from all groups
  const activeTabObj = GROUPS.flatMap(g => g.tabs).find((t) => t.id === active);
  const ActiveComponent = activeTabObj ? activeTabObj.component : OverviewPage;

  if (status === "checking") {
    return (
      <div className="console-bg flex min-h-screen items-center justify-center text-sm text-slate-500">
        <LoaderCircle size={18} className="mr-2 animate-spin text-cyan-400" /> 
        Checking secure session…
      </div>
    );
  }

  if (status !== "authenticated") {
    if (!showLogin) {
      return <LandingPage onLogin={() => setShowLogin(true)} />;
    }
    return <LoginPage />;
  }

  return (
    <div className="console-bg min-h-screen">
      <header className="border-b border-bg-800 bg-bg-900/80 backdrop-blur">
        <div className="mx-auto flex max-w-6xl flex-col gap-4 px-6 py-4 md:flex-row md:items-center md:justify-between">
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
          
          <nav className="flex flex-wrap items-center gap-2">
            {GROUPS.map((group) => (
              <div key={group.label} className="flex items-center gap-1 bg-bg-950/60 p-1 rounded-lg border border-bg-800">
                <span className="px-1.5 font-mono text-[8px] uppercase tracking-wider text-slate-500 font-bold">
                  {group.label}
                </span>
                {group.tabs.map((tab) => {
                  const Icon = tab.icon;
                  const isActive = tab.id === active;
                  return (
                    <button
                      key={tab.id}
                      onClick={() => setActive(tab.id)}
                      className={`flex items-center gap-1 rounded-md px-2 py-1 text-xs font-mono transition-colors ${
                        isActive
                          ? "bg-cyan-500/15 text-cyan-400 font-semibold"
                          : "text-slate-500 hover:text-slate-300"
                      }`}
                    >
                      <Icon size={12} />
                      {tab.label}
                    </button>
                  );
                })}
              </div>
            ))}
            
            <span className="mx-1 hidden h-5 w-px bg-bg-800 md:block" />
            <span className="hidden font-mono text-[11px] text-slate-500 md:inline">{user.username}</span>
            <button onClick={logout} className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-mono text-slate-500 transition-colors hover:bg-bg-800 hover:text-slate-300">
              <LogOut size={12} /> Logout
            </button>
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