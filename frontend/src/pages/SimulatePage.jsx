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

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
      <Panel title="Run a technique" eyebrow="FR-05" className="lg:col-span-2 lg:self-start">
        <div className="space-y-3">
          <label className="block font-mono text-[11px] uppercase tracking-widest text-graphite-400">
            MITRE ATT&amp;CK technique
          </label>
          <select
            value={selectedTechnique}
            onChange={(e) => setSelectedTechnique(e.target.value)}
            className="w-full rounded-md border border-graphite-600 bg-graphite-950 px-3 py-2 text-sm text-graphite-100 outline-none focus:border-signal-500"
          >
            {techniques.map((t) => (
              <option key={t} value={t}>
                {t} {techniqueMeta[t] ? `— ${techniqueMeta[t].name}` : ""}
              </option>
            ))}
          </select>

          {meta && (
            <div className="rounded-md border border-graphite-700 bg-graphite-950 px-3 py-2">
              <Badge tone="amber">{meta.tactic}</Badge>
              <p className="mt-1 text-xs text-graphite-300">{meta.name}</p>
            </div>
          )}

          <Button onClick={handleRun} disabled={running || !selectedTechnique} className="inline-flex items-center gap-2">
            <Play size={14} />
            {running ? "Running..." : "Simulate + evaluate"}
          </Button>
          <ErrorNote message={error} />
          <p className="font-mono text-[11px] leading-relaxed text-graphite-500">
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
            <div className="flex items-center gap-2 font-mono text-xs text-graphite-400">
              <Terminal size={14} />
              run {simResult.simulation_run_id.slice(0, 8)} — {simResult.event_count} event(s)
            </div>
            <div className="space-y-2">
              {simResult.events.map((ev, i) => (
                <div key={i} className="overflow-x-auto rounded-md border border-graphite-700 bg-graphite-950 p-3 font-mono text-xs text-graphite-200">
                  {Object.entries(ev)
                    .filter(([k]) => !["event_id", "simulation_run_id", "technique_id"].includes(k))
                    .map(([k, v]) => (
                      <div key={k} className="whitespace-pre-wrap break-all">
                        <span className="text-graphite-500">{k}:</span> {String(v)}
                      </div>
                    ))}
                </div>
              ))}
            </div>

            {evalResult && (
              <div
                className={`rounded-md border px-4 py-3 ${
                  evalResult.alerts_generated > 0
                    ? "border-signal-500/40 bg-signal-500/10"
                    : "border-amber-500/40 bg-amber-500/10"
                }`}
              >
                <div className="flex items-center gap-2">
                  <Zap size={14} className={evalResult.alerts_generated > 0 ? "text-signal-400" : "text-amber-400"} />
                  <span className="text-sm font-medium text-graphite-100">
                    {evalResult.alerts_generated > 0
                      ? `Detected — ${evalResult.alerts_generated} rule(s) fired`
                      : "Not detected — no rule fired on this telemetry"}
                  </span>
                </div>
                <p className="mt-1 font-mono text-[11px] text-graphite-400">
                  {evalResult.rules_evaluated} active rule(s) evaluated against this run.
                </p>
              </div>
            )}
          </div>
        )}
      </Panel>
    </div>
  );
}
