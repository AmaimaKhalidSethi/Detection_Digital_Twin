import { useEffect, useState } from "react";
import { Play, Zap, Terminal } from "lucide-react";
import { api } from "../lib/api";
import { Panel, Badge, Button, EmptyState, ErrorNote } from "../components/ui";

export default function SimulatePage() {
  const [techniques, setTechniques] = useState([]);
  const [techniqueMeta, setTechniqueMeta] = useState({});
  const [selectedTechnique, setSelectedTechnique] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState(null);
  const [simResult, setSimResult] = useState(null);
  const [evalResult, setEvalResult] = useState(null);

  useEffect(() => {
    (async () => {
      const [sims, meta] = await Promise.all([
        api.listSimulatableTechniques(),
        api.listTechniques(),
      ]);
      setTechniques(sims);
      setSelectedTechnique(sims[0] || "");
      const metaMap = {};
      meta.forEach((m) => (metaMap[m.technique_id] = m));
      setTechniqueMeta(metaMap);
    })();
  }, []);

  const handleRun = async () => {
    setError(null);
    setRunning(true);
    setSimResult(null);
    setEvalResult(null);
    try {
      const sim = await api.runSimulation(selectedTechnique);
      setSimResult(sim);
      const ev = await api.evaluate(sim.simulation_run_id);
      setEvalResult(ev);
    } catch (err) {
      setError(err.message);
    } finally {
      setRunning(false);
    }
  };

  const meta = techniqueMeta[selectedTechnique];
  const unmatchedRules = evalResult?.results?.filter((rule) => !rule.matched) ?? [];
  const renderFailureReason = (rule) => {
    if (rule.parse_error) {
      return `Rule failed to parse: ${rule.parse_error}`;
    }

    const failure = rule.failure_reasons?.[0];
    if (!failure) {
      return "Rule did not match this event.";
    }

    if (failure.type === "field_missing") {
      return `field '${failure.field}' was not present in this event`;
    }

    if (failure.type === "value_mismatch") {
      return `field '${failure.field}' was '${failure.actual}', rule expected '${failure.expected}'`;
    }

    return "Rule did not match this event.";
  };

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
      <Panel title="Run a technique" eyebrow="Attack simulation" className="lg:col-span-2 lg:self-start">
        <div className="space-y-3">
          <label className="block font-mono text-[11px] uppercase tracking-widest text-slate-500">
            MITRE ATT&amp;CK technique
          </label>
          <select
            value={selectedTechnique}
            onChange={(e) => setSelectedTechnique(e.target.value)}
            className="w-full rounded-md border border-bg-800 bg-bg-950 px-3 py-2 text-sm text-slate-300 outline-none focus:border-cyan-500"
          >
            {techniques.map((t) => (
              <option key={t} value={t}>
                {t} {techniqueMeta[t] ? `— ${techniqueMeta[t].name}` : ""}
              </option>
            ))}
          </select>

          {meta && (
            <div className="rounded-md border border-bg-800 bg-bg-950 px-3 py-2">
              <Badge tone="amber">{meta.tactic}</Badge>
              <p className="mt-1 text-xs text-slate-300">{meta.name}</p>
            </div>
          )}

          <Button onClick={handleRun} disabled={running || !selectedTechnique} className="inline-flex items-center gap-2">
            <Play size={14} />
            {running ? "Running..." : "Simulate + evaluate"}
          </Button>
          <ErrorNote message={error} />
          <p className="font-mono text-[11px] leading-relaxed text-slate-500">
            Generates the telemetry a benign execution of this technique
            would produce, then evaluates every active rule against it.
          </p>
        </div>
      </Panel>

      <Panel title="Generated telemetry" eyebrow="Synthetic event" className="lg:col-span-3">
        {!simResult ? (
          <EmptyState title="No simulation run yet" hint="Pick a technique and run it." />
        ) : (
          <div className="space-y-4">
            <div className="flex items-center gap-2 font-mono text-xs text-slate-500">
              <Terminal size={14} />
              run {simResult.simulation_run_id.slice(0, 8)} — {simResult.event_count} event(s)
            </div>
            <div className="space-y-2">
              {simResult.events.map((ev, i) => (
                <div key={i} className="overflow-x-auto rounded-md border border-bg-800 bg-bg-950 p-3 font-mono text-xs text-slate-300">
                  {Object.entries(ev)
                    .filter(([k]) => !["event_id", "simulation_run_id", "technique_id"].includes(k))
                    .map(([k, v]) => (
                      <div key={k} className="whitespace-pre-wrap break-all">
                        <span className="text-slate-500">{k}:</span> {String(v)}
                      </div>
                    ))}
                </div>
              ))}
            </div>

            {evalResult && (
              <div
                className={`rounded-md border px-4 py-3 ${
                  evalResult.alerts_generated > 0
                    ? "border-cyan-500/40 bg-cyan-500/10"
                    : "border-fuchsia-500/40 bg-fuchsia-500/10"
                }`}
              >
                <div className="flex items-center gap-2">
                  <Zap size={14} className={evalResult.alerts_generated > 0 ? "text-cyan-400" : "text-fuchsia-400"} />
                  <span className="text-sm font-medium text-slate-300">
                    {evalResult.alerts_generated > 0
                      ? `Detected — ${evalResult.alerts_generated} rule(s) fired`
                      : "Not detected — no rule fired on this telemetry"}
                  </span>
                </div>
                <p className="mt-1 font-mono text-[11px] text-slate-500">
                  {evalResult.rules_evaluated} active rule(s) evaluated against this run.
                </p>
                <details className="mt-4 rounded-md border border-bg-800 bg-bg-950 text-sm text-slate-300">
                  <summary className="cursor-pointer px-3 py-2 font-medium text-slate-300 outline-none focus:outline-none">
                    Show why
                  </summary>
                  <div className="space-y-3 border-t border-bg-800 px-3 py-3">
                    {unmatchedRules.length === 0 ? (
                      <div className="rounded-md bg-bg-900 p-3 text-slate-300">
                        All evaluated rules matched.
                      </div>
                    ) : (
                      unmatchedRules.map((rule) => (
                        <div key={rule.rule_version_id} className="rounded-md border border-bg-800 bg-bg-900 p-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge tone="amber">{rule.rule_version_id}</Badge>
                            <span
                              className={`text-xs font-mono ${rule.parse_error ? "text-rose-300" : "text-slate-300"}`}
                            >
                              {renderFailureReason(rule)}
                            </span>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </details>
              </div>
            )}
          </div>
        )}
      </Panel>
    </div>
  );
}
