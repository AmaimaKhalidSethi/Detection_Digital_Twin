import { useEffect, useState } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { GitCommitHorizontal, AlertTriangle, CheckCircle, EyeOff, RefreshCw, Download, ShieldCheck } from "lucide-react";
import { api } from "../lib/api";
import {
  Panel,
  Badge,
  Button,
  EmptyState,
  ErrorNote,
} from "../components/ui";

export default function DriftPage() {
  const [activeTab, setActiveTab] = useState("regression");
  const [drift, setDrift] = useState([]);
  const [loading, setLoading] = useState(true);
  const [updatingId, setUpdatingId] = useState(null);

  const [productionDrift, setProductionDrift] = useState(null);
  const [productionLoading, setProductionLoading] = useState(true);
  const [productionError, setProductionError] = useState("");
  const [history, setHistory] = useState([]);
  const [configurationDrift, setConfigurationDrift] = useState(null);

  const loadDrift = async () => {
    setLoading(true);
    try {
      const data = await api.drift();
      setDrift(data);
    } catch (error) {
      console.error("Failed to load drift:", error);
    } finally {
      setLoading(false);
    }
  };

  const loadProductionDrift = async () => {
    setProductionLoading(true);
    setProductionError("");
    try {
      setProductionDrift(await api.productionDrift());
      setHistory(await api.productionDriftHistory());
      setConfigurationDrift(await api.configurationDrift());
    } catch (error) {
      setProductionError(error.message);
    } finally {
      setProductionLoading(false);
    }
  };

  useEffect(() => {
    loadDrift();
    loadProductionDrift();
  }, []);

  const handleUpdateStatus = async (detectionResultId, status) => {
    setUpdatingId(detectionResultId);
    try {
      await api.updateDriftStatus(detectionResultId, status);
      await loadDrift();
    } catch (error) {
      window.alert(`Failed to update drift status: ${error.message}`);
    } finally {
      setUpdatingId(null);
    }
  };

  const handleManualSync = async () => {
    setProductionLoading(true);
    try {
      await api.syncEnvironment();
      await loadProductionDrift();
    } catch (error) {
      setProductionError(error.message);
    } finally {
      setProductionLoading(false);
    }
  };

  // Determine if snapshot data is stale (older than 1 hour)
  const lastSyncTime = history[0] ? new Date(history[0].created_at) : null;
  const isStale = lastSyncTime ? (new Date() - lastSyncTime) > 3600 * 1000 : false;

  return (
    <div className="space-y-6">
      {/* Header with quick stats */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100">Drift & Reconciliation Lab</h1>
          <p className="text-xs text-slate-500 font-mono">Observe delta configurations and local twin deviations over time.</p>
        </div>
        <div className="flex items-center gap-2">
          {lastSyncTime && (
            <span className="font-mono text-[10px] text-slate-500">
              Last Synced: {lastSyncTime.toLocaleString()}
            </span>
          )}
          <Button variant="secondary" onClick={handleManualSync} disabled={productionLoading}>
            <RefreshCw size={12} className={productionLoading ? "animate-spin" : ""} />
            Sync Wazuh Now
          </Button>
        </div>
      </div>

      {/* Stale data warning */}
      {isStale && lastSyncTime && (
        <div className="flex items-start gap-3 rounded-lg border border-amber-500/25 bg-amber-500/10 p-4 text-amber-200">
          <AlertTriangle size={16} className="mt-0.5 shrink-0 text-amber-400" />
          <div>
            <div className="text-xs font-semibold">Snapshot Data is Stale</div>
            <div className="mt-1 font-mono text-[10px] text-amber-400/80">
              The last Wazuh production comparison occurred on {lastSyncTime.toLocaleString()}. 
              The backend synchronization daemon checks automatically every hour. Use "Sync Wazuh Now" for real-time comparison.
            </div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-bg-800 bg-bg-950 p-1 rounded-t-lg">
        {[
          { id: "regression", label: "Rule Regression" },
          { id: "configuration", label: "Configuration Drift" },
          { id: "coverage", label: "Coverage Drift" },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            className={`px-4 py-2 font-mono text-xs font-medium transition-colors border-b-2 ${
              activeTab === t.id
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-slate-500 hover:text-slate-300"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab: Rule Regression */}
      {activeTab === "regression" && (
        <Panel title="Rule Firing Regressions" eyebrow="Twin internal regression tracker">
          {loading ? (
            <p className="text-sm text-slate-500">Loading regressions...</p>
          ) : drift.length === 0 ? (
            <EmptyState
              title="No regression drift detected"
              hint="Re-run simulation testing after editing a rule to check for regressions."
            />
          ) : (
            <ul className="divide-y divide-bg-800">
              {drift.map((d) => (
                <li key={d.detection_result_id} className="flex flex-col gap-3 py-4 md:flex-row md:items-center">
                  <GitCommitHorizontal size={16} className="shrink-0 text-fuchsia-400 hidden md:block" />
                  
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-slate-200">{d.rule_title}</span>
                      <Badge tone={d.status === "active" ? "danger" : d.status === "suppressed" ? "slate" : "success"}>
                        {d.status}
                      </Badge>
                    </div>

                    <div className="mt-1 font-mono text-[11px] text-slate-500">
                      was <span className="text-slate-400">{d.previous_result ? "firing" : "not firing"}</span> &rarr; now <span className="text-slate-400">{d.current_result ? "firing" : "not firing"}</span>
                    </div>

                    <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10px] text-slate-600">
                      <span>Technique: {d.technique_id}</span>
                      <span>Detected: {d.detected_at ? new Date(d.detected_at).toLocaleString() : "Unknown"}</span>
                    </div>
                  </div>

                  {/* Lifecycle Control Buttons */}
                  <div className="flex flex-wrap items-center gap-1.5 self-end md:self-auto">
                    {d.status === "active" && (
                      <>
                        <Button
                          variant="secondary"
                          onClick={() => handleUpdateStatus(d.detection_result_id, "acknowledged")}
                          disabled={updatingId === d.detection_result_id}
                        >
                          Acknowledge
                        </Button>
                        <Button
                          variant="secondary"
                          onClick={() => handleUpdateStatus(d.detection_result_id, "suppressed")}
                          disabled={updatingId === d.detection_result_id}
                        >
                          Suppress
                        </Button>
                      </>
                    )}
                    {d.status === "acknowledged" && (
                      <>
                        <Button
                          variant="primary"
                          onClick={() => handleUpdateStatus(d.detection_result_id, "resolved")}
                          disabled={updatingId === d.detection_result_id}
                        >
                          Resolve
                        </Button>
                        <Button
                          variant="secondary"
                          onClick={() => handleUpdateStatus(d.detection_result_id, "active")}
                          disabled={updatingId === d.detection_result_id}
                        >
                          Reopen
                        </Button>
                      </>
                    )}
                    {d.status === "suppressed" && (
                      <>
                        <Button
                          variant="secondary"
                          onClick={() => handleUpdateStatus(d.detection_result_id, "acknowledged")}
                          disabled={updatingId === d.detection_result_id}
                        >
                          Acknowledge
                        </Button>
                        <Button
                          variant="secondary"
                          onClick={() => handleUpdateStatus(d.detection_result_id, "active")}
                          disabled={updatingId === d.detection_result_id}
                        >
                          Reopen
                        </Button>
                      </>
                    )}
                    {d.status === "resolved" && (
                      <Button
                        variant="secondary"
                        onClick={() => handleUpdateStatus(d.detection_result_id, "active")}
                        disabled={updatingId === d.detection_result_id}
                      >
                        Reopen
                      </Button>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      )}

      {/* Tab: Configuration Drift */}
      {activeTab === "configuration" && (
        <Panel title="Wazuh Rule Configuration Drift" eyebrow="Configuration delta comparisons">
          {!configurationDrift || configurationDrift.status === "insufficient_history" ? (
            <EmptyState
              title="Need two sync snapshots"
              hint="Wait for the background scheduled worker to run, or trigger 'Sync Wazuh Now' to compare configuration states."
            />
          ) : configurationDrift.changes.length === 0 ? (
            <EmptyState title="No configuration drift detected" hint="All active rules match the previous snapshot." />
          ) : (
            <ul className="divide-y divide-bg-800">
              {configurationDrift.changes.map((change) => (
                <li key={`${change.rule_id}-${change.category}`} className="flex items-center justify-between gap-3 py-3">
                  <span className="font-mono text-xs text-slate-300">
                    Rule {change.rule_id}
                  </span>
                  <Badge tone={change.category === "added" ? "success" : change.category === "removed" ? "danger" : "amber"}>
                    {change.category}
                  </Badge>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      )}

      {/* Tab: Coverage Drift */}
      {activeTab === "coverage" && (
        <div className="space-y-6">
          <Panel title="Twin vs. Production Coverage Drift" eyebrow="Live telemetry reconciliation">
            <div className="space-y-4">
              {productionLoading ? (
                <p className="text-sm text-slate-500">Comparing coverage matrices...</p>
              ) : productionError ? (
                <ErrorNote message={productionError} />
              ) : !productionDrift?.wazuh_reachable ? (
                <ErrorNote message="Wazuh manager unreachable — check connection settings." />
              ) : (
                <div className="space-y-6">
                  {/* Stats Cards */}
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                    {[
                      ["Twin Verified Techniques", productionDrift.twin_verified_count, "e879f9"],
                      ["Wazuh Active Rules", productionDrift.production_active_count, "22d3ee"],
                      ["Covered in Both", productionDrift.covered_both.length, "a3e635"],
                    ].map(([label, value, color]) => (
                      <div key={label} className="rounded-md border border-bg-800 bg-bg-900/40 p-4">
                        <div className="font-mono text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
                        <div className="mt-1 flex items-baseline gap-2">
                          <div className="text-2xl font-bold text-slate-200">{value}</div>
                          <div className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: `#${color}` }} />
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Split details */}
                  <div className="space-y-3">
                    <div className="rounded-lg border border-bg-800 bg-bg-950 p-4">
                      <div className="flex items-center gap-2 border-b border-bg-800 pb-2 mb-3">
                        <ShieldCheck size={14} className="text-cyan-400" />
                        <span className="text-xs font-mono font-bold text-slate-300">
                          Active Wazuh Coverage Gaps (Twin Verified but Absent in Production)
                        </span>
                      </div>
                      {productionDrift.twin_only.length === 0 ? (
                        <p className="text-xs text-slate-500">No active gaps found. All twin verified techniques are present in production.</p>
                      ) : (
                        <div className="flex flex-wrap gap-2">
                          {productionDrift.twin_only.map((tid) => (
                            <Badge key={tid} tone="amber">{tid}</Badge>
                          ))}
                        </div>
                      )}
                    </div>

                    <div className="rounded-lg border border-bg-800 bg-bg-950 p-4">
                      <div className="flex items-center gap-2 border-b border-bg-800 pb-2 mb-3">
                        <AlertTriangle size={14} className="text-fuchsia-400" />
                        <span className="text-xs font-mono font-bold text-slate-300">
                          Unverified Production Coverage (Active in Wazuh but not twin-tested)
                        </span>
                      </div>
                      {productionDrift.production_only.length === 0 ? (
                        <p className="text-xs text-slate-500">No unverified rules. All active production techniques have been tested.</p>
                      ) : (
                        <div className="flex flex-wrap gap-2">
                          {productionDrift.production_only.map((tid) => (
                            <Badge key={tid}>{tid}</Badge>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </Panel>

          {/* Recharts Area Chart */}
          {history.length > 0 && (
            <Panel title="Historical Coverage Drift Trend" eyebrow="Reconciliation history logs">
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <div className="font-mono text-[10px] text-slate-500">Comparison trend logs over time.</div>
                  <a
                    href="http://127.0.0.1:8123/drift/production/export"
                    download
                    className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 hover:underline font-mono"
                  >
                    <Download size={12} />
                    Export CSV Report
                  </a>
                </div>

                <ResponsiveContainer width="100%" height={240}>
                  <AreaChart data={[...history].reverse()}>
                    <CartesianGrid stroke="#162031" strokeDasharray="3 3" />
                    <XAxis
                      dataKey="created_at"
                      tickFormatter={(v) => new Date(v).toLocaleTimeString()}
                      stroke="#475569"
                      fontSize={9}
                    />
                    <YAxis stroke="#475569" fontSize={9} />
                    <Tooltip
                      contentStyle={{
                        background: "#0f172a",
                        border: "1px solid #1e293b",
                        borderRadius: "6px",
                        fontSize: 11,
                        fontFamily: "monospace",
                      }}
                      labelFormatter={(v) => new Date(v).toLocaleString()}
                    />
                    <Area
                      type="monotone"
                      dataKey="production_active_count"
                      stroke="#22d3ee"
                      fill="#22d3ee"
                      fillOpacity={0.08}
                      name="Wazuh Active"
                    />
                    <Area
                      type="monotone"
                      dataKey="twin_verified_count"
                      stroke="#e879f9"
                      fill="#e879f9"
                      fillOpacity={0.08}
                      name="Twin Verified"
                    />
                    <Area
                      type="monotone"
                      dataKey="covered_both_count"
                      stroke="#a3e635"
                      fill="#a3e635"
                      fillOpacity={0.12}
                      name="Covered by both"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </Panel>
          )}
        </div>
      )}
    </div>
  );
}