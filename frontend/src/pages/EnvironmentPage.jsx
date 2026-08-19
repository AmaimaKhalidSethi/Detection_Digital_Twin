import { useEffect, useMemo, useState } from "react";
import { Plus, RefreshCw, CheckCircle, AlertTriangle } from "lucide-react";
import { api } from "../lib/api";
import { Panel, Badge, Button, EmptyState, ErrorNote } from "../components/ui";

const statusTone = {
  VALIDATED: "signal",
  DETECTION_GAP: "alert",
  UNAVAILABLE: "amber",
  ERROR: "amber",
};

export default function EnvironmentPage() {
  const [environments, setEnvironments] = useState([]);
  const [selectedEnvironmentId, setSelectedEnvironmentId] = useState(null);
  const [endpoints, setEndpoints] = useState([]);
  const [snapshots, setSnapshots] = useState([]);
  const [validationRuns, setValidationRuns] = useState([]);
  const [detectionGaps, setDetectionGaps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState(null);
  const [syncResult, setSyncResult] = useState(null);

  const [envName, setEnvName] = useState("");
  const [envDescription, setEnvDescription] = useState("");
  const [telemetry, setTelemetry] = useState("");
  const [expectedDetection, setExpectedDetection] = useState("DETECT");
  const [techniqueId, setTechniqueId] = useState("");
  const [endpointId, setEndpointId] = useState("");
  const [validationMessage, setValidationMessage] = useState("");

  const selectedEnvironment = useMemo(
    () => environments.find((env) => env.id === selectedEnvironmentId) || environments[0] || null,
    [environments, selectedEnvironmentId],
  );

  useEffect(() => {
    loadEnvironments();
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
      if (environments.length > 0) {
        setSelectedEnvironmentId(environments[0].id);
      }
    } catch (err) {
      setError(err.message || "Failed to synchronize environment");
    } finally {
      setActionLoading(false);
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
      };
      const result = await api.createValidationRun(payload);
      setValidationMessage(`Validation run created: ${result.id}`);
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
      <Panel
        title="Environment & Wazuh sync"
        eyebrow="Twin environment management"
        actions={
          <div className="flex flex-wrap gap-2">
            <Button variant="secondary" onClick={handleSyncEnvironment} disabled={actionLoading}>
              <RefreshCw size={14} /> Sync with Wazuh
            </Button>
            <Button variant="secondary" onClick={loadEnvironments} disabled={actionLoading}>
              <RefreshCw size={14} /> Refresh
            </Button>
          </div>
        }
      >
        {error && <ErrorNote message={error} />}
        {syncResult && (
          <div className="mb-4 rounded-md border border-cyan-500/30 bg-cyan-500/5 p-3 font-mono text-sm text-cyan-200">
            <div>Sync completed: {syncResult.environment}</div>
            <div>{syncResult.agents_synced} agents, {syncResult.rules_synced} rules synchronized.</div>
          </div>
        )}

        <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="space-y-4">
            <div className="space-y-2">
              <label className="font-medium text-slate-200">Environment</label>
              <select
                className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-2 text-sm text-slate-200"
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
            {selectedEnvironment ? (
              <div className="rounded-md border border-bg-800 bg-bg-950 p-4">
                <div className="font-semibold text-slate-200">{selectedEnvironment.name}</div>
                <div className="mt-2 text-sm text-slate-500">{selectedEnvironment.description || "No description"}</div>
                <div className="mt-3 grid grid-cols-2 gap-3 text-sm text-slate-400">
                  <div>
                    <div className="font-mono text-[11px] uppercase tracking-widest text-slate-500">Status</div>
                    <div>{selectedEnvironment.status}</div>
                  </div>
                  <div>
                    <div className="font-mono text-[11px] uppercase tracking-widest text-slate-500">Last sync</div>
                    <div>{selectedEnvironment.last_sync_at || "never"}</div>
                  </div>
                </div>
              </div>
            ) : (
              <EmptyState title="No environment selected" hint="Create an environment to get started with Wazuh sync." />
            )}
          </div>

          <div className="space-y-4">
            <Panel title="Create environment" eyebrow="New twin environment">
              <div className="space-y-3">
                <label className="block text-sm text-slate-200">Name</label>
                <input
                  value={envName}
                  onChange={(event) => setEnvName(event.target.value)}
                  className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-2 text-sm text-slate-200"
                  placeholder="Home Detection Lab"
                />
                <label className="block text-sm text-slate-200">Description</label>
                <textarea
                  value={envDescription}
                  onChange={(event) => setEnvDescription(event.target.value)}
                  className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-2 text-sm text-slate-200"
                  rows={3}
                  placeholder="Optional environment description"
                />
                <Button onClick={handleCreateEnvironment} disabled={actionLoading || !envName.trim()}>
                  <Plus size={14} /> Create environment
                </Button>
              </div>
            </Panel>
          </div>
        </div>
      </Panel>

      <Panel title="Validation run" eyebrow="Wazuh logtest validation">
        <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="space-y-4">
            <div className="space-y-2">
              <label className="block text-sm text-slate-200">Telemetry / log sample</label>
              <textarea
                value={telemetry}
                onChange={(event) => setTelemetry(event.target.value)}
                className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-2 text-sm text-slate-200"
                rows={6}
                placeholder="Paste a Wazuh-compatible log line or event document"
              />
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <label className="block text-sm text-slate-200">Expected detection</label>
                <select
                  value={expectedDetection}
                  onChange={(event) => setExpectedDetection(event.target.value)}
                  className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-2 text-sm text-slate-200"
                >
                  <option value="DETECT">DETECT</option>
                  <option value="NO_DETECT">NO_DETECT</option>
                </select>
              </div>
              <div className="space-y-2">
                <label className="block text-sm text-slate-200">Technique ID</label>
                <input
                  value={techniqueId}
                  onChange={(event) => setTechniqueId(event.target.value)}
                  className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-2 text-sm text-slate-200"
                  placeholder="e.g. T1059"
                />
              </div>
            </div>

            <div className="space-y-2">
              <label className="block text-sm text-slate-200">Endpoint</label>
              <select
                value={endpointId}
                onChange={(event) => setEndpointId(event.target.value)}
                className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-2 text-sm text-slate-200"
              >
                <option value="">None</option>
                {endpoints.map((endpoint) => (
                  <option key={endpoint.id} value={endpoint.id}>
                    {endpoint.hostname} {endpoint.agent_status ? `· ${endpoint.agent_status}` : ""}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="space-y-3 rounded-md border border-bg-800 bg-bg-950 p-4">
            <div className="flex items-center gap-2 text-sm font-medium text-slate-200">
              <CheckCircle size={16} className="text-cyan-400" />
              <span>Validation status</span>
            </div>
            <p className="text-sm text-slate-400">Run telemetry through Wazuh `/logtest` and store server-derived detection results.</p>
            <div className="grid gap-2 text-sm text-slate-300">
              <div>
                <div className="font-mono text-[10px] uppercase tracking-widest text-slate-500">Selected environment</div>
                <div>{selectedEnvironment?.name || "—"}</div>
              </div>
              <div>
                <div className="font-mono text-[10px] uppercase tracking-widest text-slate-500">Endpoints</div>
                <div>{endpoints.length}</div>
              </div>
              <div>
                <div className="font-mono text-[10px] uppercase tracking-widest text-slate-500">Recent runs</div>
                <div>{validationRuns.length}</div>
              </div>
            </div>
            <Button onClick={handleRunValidation} disabled={actionLoading || !selectedEnvironment || !telemetry.trim()}>
              Run validation
            </Button>
            {validationMessage && (
              <div className="rounded-md border border-cyan-500/30 bg-cyan-500/5 p-3 font-mono text-sm text-cyan-200">
                {validationMessage}
              </div>
            )}
          </div>
        </div>
      </Panel>

      <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
        <Panel title="Validation runs" eyebrow={`${validationRuns.length} recent results`}>
          {validationRuns.length === 0 ? (
            <EmptyState title="No validation runs yet" hint="Run validation to see Wazuh-backed results." />
          ) : (
            <div className="space-y-3">
              {validationRuns.map((run) => (
                <div key={run.id} className="rounded-md border border-bg-800 bg-bg-950 p-3">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <div className="font-medium text-slate-200">{run.technique_id || "Validation run"}</div>
                      <div className="font-mono text-[11px] text-slate-500">{new Date(run.started_at).toLocaleString()}</div>
                    </div>
                    <Badge tone={statusTone[run.status] || "neutral"}>{run.status}</Badge>
                  </div>
                    <div className="mt-3 grid gap-2 text-sm text-slate-400">
                      <div>Expected: {run.expected_detection || "unknown"}</div>
                      <div>Twin: {run.twin_observed_detection || "not evaluated"}</div>
                      <div>Observed: {run.observed_detection || "unknown"}</div>
                      <div>Final: <span className="font-medium text-slate-200">{run.final_classification || run.status}</span></div>
                      {run.matched_rule_id ? <div>Matched rule: {run.matched_rule_id}</div> : null}
                      {run.telemetry_hash ? <div className="break-all font-mono text-[11px]">Telemetry hash: {run.telemetry_hash}</div> : null}
                    </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Detection gaps" eyebrow="Open investigation items">
          {detectionGaps.length === 0 ? (
            <EmptyState title="No gaps found" hint="Normalized validation runs will expose gaps automatically." />
          ) : (
            <div className="space-y-3">
              {detectionGaps.map((gap) => (
                <div key={gap.id} className="rounded-md border border-bg-800 bg-bg-950 p-3">
                  <div className="flex items-center justify-between gap-3">
                    <div className="font-medium text-slate-200">{gap.technique_id || "Technique unknown"}</div>
                    <Badge tone="alert">{gap.status}</Badge>
                  </div>
                  <div className="mt-2 text-sm text-slate-400">{gap.reason}</div>
                  <div className="mt-2 font-mono text-[11px] text-slate-500">{gap.recommendation}</div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      <Panel title="Environment snapshots" eyebrow="Latest sync metadata">
        {snapshots.length === 0 ? (
          <EmptyState title="No snapshots available" hint="Run Wazuh sync to capture environment metadata." />
        ) : (
          <div className="space-y-3">
            {snapshots.map((snapshot) => (
              <div key={snapshot.id} className="rounded-md border border-bg-800 bg-bg-950 p-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <div className="font-medium text-slate-200">{snapshot.environment_name}</div>
                    <div className="font-mono text-[11px] text-slate-500">{new Date(snapshot.timestamp).toLocaleString()}</div>
                  </div>
                  <Badge tone={snapshot.metadata?.manager_reachable ? "signal" : "alert"}>
                    {snapshot.metadata?.manager_reachable ? "reachable" : "unreachable"}
                  </Badge>
                </div>
                <div className="mt-3 grid grid-cols-2 gap-3 text-sm text-slate-400">
                  <div>Agents: {snapshot.metadata?.agent_count ?? "—"}</div>
                  <div>Active: {snapshot.metadata?.active_agent_count ?? "—"}</div>
                  <div>Rules: {snapshot.metadata?.rule_count ?? "—"}</div>
                  <div>Techniques: {snapshot.metadata?.technique_count ?? "—"}</div>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}