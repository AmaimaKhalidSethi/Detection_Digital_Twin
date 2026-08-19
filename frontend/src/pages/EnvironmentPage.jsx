import { useEffect, useMemo, useState } from "react";
import { Plus, RefreshCw, CheckCircle, AlertTriangle, Shield, Layers, HelpCircle, HardDrive } from "lucide-react";
import { api } from "../lib/api";
import { Panel, Badge, Button, EmptyState, ErrorNote } from "../components/ui";

const statusTone = {
  VALIDATED: "signal",
  DETECTION_GAP: "alert",
  UNAVAILABLE: "amber",
  ERROR: "amber",
};

function formatSysmonEvent(event) {
  const lines = ["Process Create:"];
  const ts = event.timestamp || new Date().toISOString().replace("T", " ").slice(0, 23);
  lines.push(`UtcTime: ${ts}`);
  lines.push(`Image: ${event.Image || "C:\\Windows\\System32\\cmd.exe"}`);
  lines.push(`CommandLine: ${event.CommandLine || "cmd.exe /c echo hello"}`);
  lines.push(`User: ${event.User || "NT AUTHORITY\\SYSTEM"}`);
  lines.push(`ProcessId: ${event.ProcessId || 1024}`);
  lines.push(`ParentImage: ${event.ParentImage || "C:\\Windows\\explorer.exe"}`);
  lines.push(`ParentCommandLine: ${event.ParentCommandLine || "explorer.exe"}`);
  lines.push(`ParentProcessId: ${event.ParentProcessId || 512}`);
  return lines.join("\n");
}

function formatAuditdEvent(event) {
  const ts = Math.floor(Date.now() / 1000);
  const comm = event.comm || "bash";
  const exe = event.exe || "/usr/bin/bash";
  return `type=SYSCALL msg=audit(${ts}.123:999): arch=c000003e syscall=59 success=yes exit=0 ppid=${event.ParentProcessId || 120} pid=${event.ProcessId || 240} auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 comm="${comm}" exe="${exe}"`;
}

export default function EnvironmentPage() {
  const [activeTab, setActiveTab] = useState("overview");
  const [environments, setEnvironments] = useState([]);
  const [selectedEnvironmentId, setSelectedEnvironmentId] = useState(null);
  const [endpoints, setEndpoints] = useState([]);
  const [snapshots, setSnapshots] = useState([]);
  const [validationRuns, setValidationRuns] = useState([]);
  const [detectionGaps, setDetectionGaps] = useState([]);
  const [simulatableTechniques, setSimulatableTechniques] = useState([]);
  
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState(null);
  const [syncResult, setSyncResult] = useState(null);

  const [envName, setEnvName] = useState("");
  const [envDescription, setEnvDescription] = useState("");
  
  // Validation Lab inputs
  const [selectedSimTechnique, setSelectedSimTechnique] = useState("");
  const [telemetry, setTelemetry] = useState("");
  const [sourceType, setSourceType] = useState("sysmon");
  const [expectedDetection, setExpectedDetection] = useState("DETECT");
  const [techniqueId, setTechniqueId] = useState("");
  const [endpointId, setEndpointId] = useState("");
  const [validationMessage, setValidationMessage] = useState("");
  const [simLoading, setSimLoading] = useState(false);

  const selectedEnvironment = useMemo(
    () => environments.find((env) => env.id === selectedEnvironmentId) || environments[0] || null,
    [environments, selectedEnvironmentId],
  );

  useEffect(() => {
    loadEnvironments();
    loadSimulatableTechniques();
  }, []);

  useEffect(() => {
    if (selectedEnvironment) {
      loadEnvironmentDetails(selectedEnvironment.id);
    } else {
      setEndpoints([]);
      setValidationRuns([]);
      setDetectionGaps([]);
      setSnapshots([]);
    }
  }, [selectedEnvironment]);

  const loadEnvironments = async () => {
    setLoading(true);
    setError(null);
    try {
      const envs = await api.listEnvironments();
      setEnvironments(envs || []);
      if (envs && envs.length > 0) {
        setSelectedEnvironmentId((current) => current || envs[0].id);
      }
    } catch (err) {
      setError(err.message || "Failed to load environments");
    } finally {
      setLoading(false);
    }
  };

  const loadSimulatableTechniques = async () => {
    try {
      const techs = await api.listSimulatableTechniques();
      setSimulatableTechniques(techs || []);
      if (techs && techs.length > 0) {
        setSelectedSimTechnique(techs[0]);
      }
    } catch (err) {
      console.error("Failed to load simulatable techniques", err);
    }
  };

  const loadEnvironmentDetails = async (environmentId) => {
    setActionLoading(true);
    setError(null);
    try {
      const [endpointsData, validationRunsData, detectionGapsData, snapshotsData] = await Promise.all([
        api.listEnvironmentEndpoints(environmentId),
        api.listValidationRuns(environmentId),
        api.listDetectionGaps(environmentId),
        api.listEnvironmentSnapshots(),
      ]);
      setEndpoints(endpointsData || []);
      setValidationRuns(validationRunsData || []);
      setDetectionGaps(detectionGapsData || []);
      setSnapshots((snapshotsData || []).filter((snapshot) => snapshot.environment_name === selectedEnvironment?.name));
      if (endpointsData && endpointsData.length > 0 && !endpointId) {
        setEndpointId(endpointsData[0].id);
      }
    } catch (err) {
      setError(err.message || "Failed to load environment details");
    } finally {
      setActionLoading(false);
    }
  };

  const handleCreateEnvironment = async () => {
    if (!envName.trim()) {
      setError("Environment name is required.");
      return;
    }
    setActionLoading(true);
    setError(null);
    try {
      const created = await api.createEnvironment({ name: envName.trim(), description: envDescription.trim() });
      await loadEnvironments();
      setSelectedEnvironmentId(created.id);
      setEnvName("");
      setEnvDescription("");
      setActiveTab("overview");
    } catch (err) {
      setError(err.message || "Failed to create environment");
    } finally {
      setActionLoading(false);
    }
  };

  const handleSyncEnvironment = async () => {
    setActionLoading(true);
    setError(null);
    setSyncResult(null);
    try {
      const result = await api.syncEnvironment();
      setSyncResult(result);
      await loadEnvironments();
    } catch (err) {
      setError(err.message || "Failed to synchronize environment");
    } finally {
      setActionLoading(false);
    }
  };

  const handleLoadSimulationTelemetry = async () => {
    if (!selectedSimTechnique) return;
    setSimLoading(true);
    setError(null);
    try {
      const result = await api.runSimulation(selectedSimTechnique);
      if (result && result.events && result.events.length > 0) {
        const primaryEvent = result.events[0];
        const source = primaryEvent.source_type || "sysmon";
        setSourceType(source);
        
        let formatted = "";
        if (source === "sysmon") {
          formatted = formatSysmonEvent(primaryEvent);
        } else {
          formatted = formatAuditdEvent(primaryEvent);
        }
        setTelemetry(formatted);
        setTechniqueId(selectedSimTechnique);
      } else {
        setError("Simulation completed but returned no telemetry events.");
      }
    } catch (err) {
      setError(`Failed to fetch simulation telemetry: ${err.message}`);
    } finally {
      setSimLoading(false);
    }
  };

  const handleRunValidation = async () => {
    if (!selectedEnvironment) {
      setError("Select an environment before running validation.");
      return;
    }
    if (!telemetry.trim()) {
      setError("Telemetry input is required for validation.");
      return;
    }
    setActionLoading(true);
    setError(null);
    setValidationMessage("");
    try {
      const payload = {
        environment_id: selectedEnvironment.id,
        endpoint_id: endpointId || undefined,
        technique_id: techniqueId.trim() || undefined,
        expected_detection: expectedDetection,
        telemetry: telemetry.trim(),
        source_type: sourceType,
      };
      const result = await api.createValidationRun(payload);
      setValidationMessage(`Validation run registered with ID: ${result.id}. Classification: ${result.final_classification || "PENDING"}`);
      setTelemetry("");
      setTechniqueId("");
      await loadEnvironmentDetails(selectedEnvironment.id);
    } catch (err) {
      setError(err.message || "Failed to create validation run");
    } finally {
      setActionLoading(false);
    }
  };

  if (loading) {
    return <EmptyState title="Loading environment UI..." />;
  }

  return (
    <div className="space-y-6">
      {/* Header and Sync controls */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100">Environment Verification Lab</h1>
          <p className="text-xs text-slate-500 font-mono">Simulate attacks, validate telemetry against rules, and sync detection snapshots.</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" onClick={handleSyncEnvironment} disabled={actionLoading}>
            <RefreshCw size={12} className={actionLoading ? "animate-spin" : ""} />
            Sync Wazuh
          </Button>
          <select
            className="rounded-md border border-bg-800 bg-bg-950 px-3 py-1.5 text-xs font-mono text-slate-200"
            value={selectedEnvironment?.id || ""}
            onChange={(event) => setSelectedEnvironmentId(event.target.value)}
          >
            {environments.map((env) => (
              <option key={env.id} value={env.id}>
                {env.name}
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && <ErrorNote message={error} />}
      
      {syncResult && (
        <div className="rounded-md border border-cyan-500/30 bg-cyan-500/5 p-4 font-mono text-xs text-cyan-200 flex items-start gap-3">
          <CheckCircle size={16} className="text-cyan-400 shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold">Sync Successful for {syncResult.environment}</div>
            <div className="mt-1 grid grid-cols-2 gap-x-8 gap-y-1 text-cyan-400/80">
              <div>Agents Synced: {syncResult.agents_synced}</div>
              <div>Rules Synced: {syncResult.rules_synced}</div>
              <div>Rules Added: {syncResult.rules_added}</div>
              <div>Rules Removed: {syncResult.rules_removed}</div>
            </div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-bg-800 bg-bg-950 p-1 rounded-t-lg">
        {[
          { id: "overview", label: "Overview" },
          { id: "endpoints", label: "Endpoints" },
          { id: "validation", label: "Validation Lab" },
          { id: "history", label: "Verification History" },
          { id: "gaps", label: "Detection Gaps" },
          { id: "sync", label: "Sync Logs" },
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

      {/* Tab Content */}
      <div className="space-y-6">
        {/* TAB: Overview */}
        {activeTab === "overview" && (
          <div className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
            <Panel title="Active Environment Details" eyebrow="Twin metadata">
              {selectedEnvironment ? (
                <div className="space-y-4">
                  <div>
                    <h3 className="text-md font-semibold text-slate-200">{selectedEnvironment.name}</h3>
                    <p className="mt-1 text-sm text-slate-400">{selectedEnvironment.description || "No description provided."}</p>
                  </div>
                  <div className="grid grid-cols-2 gap-4 border-t border-bg-800 pt-4 text-xs font-mono">
                    <div>
                      <div className="text-slate-500 uppercase tracking-wider">Lab Status</div>
                      <div className="mt-1 text-slate-300">{selectedEnvironment.status}</div>
                    </div>
                    <div>
                      <div className="text-slate-500 uppercase tracking-wider">Last Sync Snapshot</div>
                      <div className="mt-1 text-slate-300">{selectedEnvironment.last_sync_at ? new Date(selectedEnvironment.last_sync_at).toLocaleString() : "Never"}</div>
                    </div>
                  </div>
                </div>
              ) : (
                <EmptyState title="No environment selected" />
              )}
            </Panel>

            <Panel title="Create New Environment" eyebrow="Add target digital twin">
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">Environment Name</label>
                  <input
                    value={envName}
                    onChange={(event) => setEnvName(event.target.value)}
                    className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-2 text-sm text-slate-200 font-mono"
                    placeholder="Wazuh Lab Environment"
                  />
                </div>
                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">Description</label>
                  <textarea
                    value={envDescription}
                    onChange={(event) => setEnvDescription(event.target.value)}
                    className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-2 text-sm text-slate-200"
                    rows={3}
                    placeholder="Describe the environment scope, agents, or wazuh managers"
                  />
                </div>
                <Button onClick={handleCreateEnvironment} disabled={actionLoading || !envName.trim()}>
                  <Plus size={12} /> Register Environment
                </Button>
              </div>
            </Panel>
          </div>
        )}

        {/* TAB: Endpoints */}
        {activeTab === "endpoints" && (
          <Panel title="Target Endpoints & Agents" eyebrow={`${endpoints.length} connected endpoints`}>
            {endpoints.length === 0 ? (
              <EmptyState title="No endpoints found" hint="Run sync with Wazuh to fetch agent inventory." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-bg-800 font-mono text-[10px] uppercase text-slate-500">
                      <th className="py-2.5 px-3">Hostname</th>
                      <th className="py-2.5 px-3">Agent ID</th>
                      <th className="py-2.5 px-3">OS</th>
                      <th className="py-2.5 px-3">Agent Version</th>
                      <th className="py-2.5 px-3">Status</th>
                      <th className="py-2.5 px-3">Last Seen</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-bg-800 text-xs">
                    {endpoints.map((ep) => (
                      <tr key={ep.id} className="hover:bg-bg-950/40 text-slate-300">
                        <td className="py-3 px-3 font-semibold text-slate-200">{ep.hostname}</td>
                        <td className="py-3 px-3 font-mono text-[11px] text-slate-400">{ep.agent_id || "N/A"}</td>
                        <td className="py-3 px-3">{ep.operating_system || "Unknown"}</td>
                        <td className="py-3 px-3 font-mono text-[11px] text-slate-400">{ep.agent_version || "—"}</td>
                        <td className="py-3 px-3">
                          <Badge tone={ep.agent_status === "active" ? "signal" : ep.agent_status === "stale" ? "amber" : "neutral"}>
                            {ep.agent_status}
                          </Badge>
                        </td>
                        <td className="py-3 px-3 font-mono text-[11px] text-slate-500">
                          {ep.last_seen ? new Date(ep.last_seen).toLocaleString() : "Never"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        )}

        {/* TAB: Validation Lab */}
        {activeTab === "validation" && (
          <div className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
            <Panel title="Run Ingest & Validate" eyebrow="Simulated verification lab">
              <div className="space-y-4">
                {/* Simulation Autofill Dropdown */}
                <div className="rounded-lg border border-bg-800 bg-bg-900/20 p-4 space-y-3">
                  <div className="flex items-center gap-1.5 text-xs font-mono font-bold text-slate-300">
                    <Shield size={14} className="text-cyan-400" />
                    <span>Autofill with Simulation Telemetry</span>
                  </div>
                  
                  <div className="flex gap-2">
                    <select
                      className="flex-1 rounded-md border border-bg-800 bg-bg-950 px-3 py-1.5 text-xs font-mono text-slate-200"
                      value={selectedSimTechnique}
                      onChange={(e) => setSelectedSimTechnique(e.target.value)}
                    >
                      {simulatableTechniques.map((tech) => (
                        <option key={tech} value={tech}>
                          {tech}
                        </option>
                      ))}
                    </select>
                    
                    <Button variant="secondary" onClick={handleLoadSimulationTelemetry} disabled={simLoading || !selectedSimTechnique}>
                      <RefreshCw size={12} className={simLoading ? "animate-spin" : ""} />
                      Simulate & Load
                    </Button>
                  </div>
                  
                  <p className="text-[10px] text-slate-500 font-mono">
                    Select a Technique ID to run a live local simulation. This will format and load mock logs into the validator.
                  </p>
                </div>

                <div className="space-y-2">
                  <label className="block text-xs font-mono text-slate-400">Telemetry Ingest Log Body</label>
                  <textarea
                    value={telemetry}
                    onChange={(event) => setTelemetry(event.target.value)}
                    className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-2 text-xs font-mono text-slate-200"
                    rows={8}
                    placeholder="Paste syslog, sysmon process blocks, or auditd syscall lines..."
                  />
                </div>

                <div className="grid gap-4 md:grid-cols-3">
                  <div>
                    <label className="block text-xs font-mono text-slate-400 mb-1">Source Type</label>
                    <select
                      value={sourceType}
                      onChange={(event) => setSourceType(event.target.value)}
                      className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-1.5 text-xs text-slate-200 font-mono"
                    >
                      <option value="sysmon">Sysmon</option>
                      <option value="auditd">Auditd</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-mono text-slate-400 mb-1">Expected Result</label>
                    <select
                      value={expectedDetection}
                      onChange={(event) => setExpectedDetection(event.target.value)}
                      className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-1.5 text-xs text-slate-200 font-mono"
                    >
                      <option value="DETECT">DETECT</option>
                      <option value="NO_DETECT">NO_DETECT</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-mono text-slate-400 mb-1">Technique ID</label>
                    <input
                      value={techniqueId}
                      onChange={(event) => setTechniqueId(event.target.value)}
                      className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-1.5 text-xs text-slate-200 font-mono"
                      placeholder="e.g. T1059.003"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <label className="block text-xs font-mono text-slate-400">Target Endpoint Association</label>
                  <select
                    value={endpointId}
                    onChange={(event) => setEndpointId(event.target.value)}
                    className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-1.5 text-xs text-slate-200"
                  >
                    <option value="">None (Generic Simulation)</option>
                    {endpoints.map((endpoint) => (
                      <option key={endpoint.id} value={endpoint.id}>
                        {endpoint.hostname} {endpoint.agent_status ? `· ${endpoint.agent_status}` : ""}
                      </option>
                    ))}
                  </select>
                </div>

                <Button onClick={handleRunValidation} disabled={actionLoading || !telemetry.trim()} variant="primary">
                  Verify against Wazuh Rules
                </Button>

                {validationMessage && (
                  <div className="rounded-md border border-cyan-500/30 bg-cyan-500/5 p-3 font-mono text-xs text-cyan-200">
                    {validationMessage}
                  </div>
                )}
              </div>
            </Panel>

            <Panel title="Verification Guide" eyebrow="Wazuh digital twin rules">
              <div className="space-y-4 text-xs text-slate-400">
                <div className="flex gap-2">
                  <Layers size={16} className="text-cyan-400 shrink-0" />
                  <div>
                    <span className="font-semibold text-slate-200">Wazuh Logtest Simulation</span>
                    <p className="mt-1 text-[11px]">This validates if telemetry is correctly decoded and triggers wazuh rules on the manager.</p>
                  </div>
                </div>
                <div className="flex gap-2">
                  <CheckCircle size={16} className="text-emerald-400 shrink-0" />
                  <div>
                    <span className="font-semibold text-slate-200">Positive & Negative Controls</span>
                    <p className="mt-1 text-[11px]">DDT runs benign baseline tests to compute false positive ratios and filter out shape mismatches.</p>
                  </div>
                </div>
                <div className="flex gap-2">
                  <HelpCircle size={16} className="text-amber-400 shrink-0" />
                  <div>
                    <span className="font-semibold text-slate-200">Ownership Checks</span>
                    <p className="mt-1 text-[11px]">The digital twin verifies telemetry records against rules associated with the same target environment.</p>
                  </div>
                </div>
              </div>
            </Panel>
          </div>
        )}

        {/* TAB: Verification History */}
        {activeTab === "history" && (
          <Panel title="Verification Runs History" eyebrow={`${validationRuns.length} verification results`}>
            {validationRuns.length === 0 ? (
              <EmptyState title="No verification logs yet" hint="Create validation runs inside the validation lab." />
            ) : (
              <div className="space-y-3">
                {validationRuns.map((run) => (
                  <div key={run.id} className="rounded-lg border border-bg-800 bg-bg-950 p-4">
                    <div className="flex items-center justify-between gap-3 border-b border-bg-900 pb-2 mb-3">
                      <div>
                        <div className="text-sm font-semibold text-slate-200">{run.technique_id || "Generic Telemetry Run"}</div>
                        <div className="font-mono text-[10px] text-slate-500">{new Date(run.started_at).toLocaleString()}</div>
                      </div>
                      <Badge tone={statusTone[run.status] || "neutral"}>{run.status}</Badge>
                    </div>

                    <div className="grid gap-3 grid-cols-1 md:grid-cols-3 text-xs text-slate-400 font-mono">
                      <div>
                        <div className="text-[10px] text-slate-600">EXPECTED / TWIN</div>
                        <div className="mt-0.5 text-slate-300">
                          {run.expected_detection} / {run.twin_observed_detection || "NONE"}
                        </div>
                      </div>
                      <div>
                        <div className="text-[10px] text-slate-600">WAZUH OBSERVED</div>
                        <div className="mt-0.5 text-slate-300">{run.observed_detection || "NONE"}</div>
                      </div>
                      <div>
                        <div className="text-[10px] text-slate-600">VERIFICATION CLASS</div>
                        <div className="mt-0.5 font-bold text-slate-200">{run.final_classification || "UNKNOWN"}</div>
                      </div>
                    </div>

                    {run.matched_rule_id && (
                      <div className="mt-2 text-xs font-mono text-slate-400">
                        <span className="text-slate-600">Triggered Rule:</span> {run.matched_rule_id}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </Panel>
        )}

        {/* TAB: Detection Gaps */}
        {activeTab === "gaps" && (
          <Panel title="Identified Detection Gaps" eyebrow="Open security gaps in Wazuh">
            {detectionGaps.length === 0 ? (
              <EmptyState title="No gaps identified" hint="Wazuh digital twin validates and populates gaps on failures." />
            ) : (
              <div className="space-y-3">
                {detectionGaps.map((gap) => (
                  <div key={gap.id} className="rounded-lg border border-bg-800 bg-bg-950 p-4">
                    <div className="flex items-center justify-between gap-3 border-b border-bg-900 pb-2 mb-3">
                      <div className="text-sm font-semibold text-slate-200">Technique: {gap.technique_id}</div>
                      <Badge tone="alert">{gap.status}</Badge>
                    </div>
                    <div className="space-y-2 text-xs">
                      <div>
                        <span className="font-mono text-slate-500">Reason:</span>
                        <p className="mt-0.5 text-slate-300">{gap.reason}</p>
                      </div>
                      <div>
                        <span className="font-mono text-slate-500">Action Plan:</span>
                        <p className="mt-0.5 text-slate-300 font-mono text-[11px] bg-bg-900/60 p-2 rounded border border-bg-800">
                          {gap.recommendation}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        )}

        {/* TAB: Sync Logs */}
        {activeTab === "sync" && (
          <Panel title="Environment Sync History" eyebrow="Wazuh Manager Snapshots">
            {snapshots.length === 0 ? (
              <EmptyState title="No sync logs found" hint="Run sync with Wazuh to generate snapshots." />
            ) : (
              <div className="space-y-4">
                {snapshots.map((snapshot) => (
                  <div key={snapshot.id} className="rounded-lg border border-bg-800 bg-bg-950 p-4 font-mono text-xs text-slate-400">
                    <div className="flex justify-between items-center border-b border-bg-900 pb-2 mb-3">
                      <div>
                        <span className="text-slate-200 font-semibold">{snapshot.environment_name} Snapshot</span>
                        <div className="text-[10px] text-slate-500 mt-0.5">{new Date(snapshot.timestamp).toLocaleString()}</div>
                      </div>
                      <Badge tone={snapshot.metadata?.manager_reachable ? "signal" : "alert"}>
                        {snapshot.metadata?.manager_reachable ? "Manager Connected" : "Unreachable"}
                      </Badge>
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      <div className="bg-bg-900/40 p-2.5 rounded border border-bg-800">
                        <div className="text-[10px] text-slate-500">RULE INVENTORY</div>
                        <div className="text-md font-bold text-slate-300 mt-1">{snapshot.metadata?.rule_count ?? 0} Rules</div>
                        <div className="text-[10px] text-slate-500 mt-1">
                          Enabled: {snapshot.metadata?.enabled_rule_count ?? 0}
                        </div>
                      </div>
                      
                      <div className="bg-bg-900/40 p-2.5 rounded border border-bg-800">
                        <div className="text-[10px] text-slate-500">MITRE COVERAGE</div>
                        <div className="text-md font-bold text-slate-300 mt-1">{snapshot.metadata?.technique_count ?? 0} Techs</div>
                      </div>

                      <div className="bg-bg-900/40 p-2.5 rounded border border-bg-800">
                        <div className="text-[10px] text-slate-500">CONNECTED AGENTS</div>
                        <div className="text-md font-bold text-slate-300 mt-1">{snapshot.metadata?.agent_count ?? 0} Agents</div>
                        <div className="text-[10px] text-slate-500 mt-1">
                          Active: {snapshot.metadata?.active_agent_count ?? 0}
                        </div>
                      </div>

                      <div className="bg-bg-900/40 p-2.5 rounded border border-bg-800">
                        <div className="text-[10px] text-slate-500">SYNC METRICS</div>
                        <div className="text-[10px] text-slate-400 mt-1">
                          Rules Added: {snapshot.metadata?.sync_stats?.rules_added ?? 0}
                        </div>
                        <div className="text-[10px] text-slate-400">
                          Rules Changed: {snapshot.metadata?.sync_stats?.rules_changed ?? 0}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        )}
      </div>
    </div>
  );
}