import { useEffect, useState } from "react";
import { GitCommitHorizontal } from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { api } from "../lib/api";
import { Panel, Badge, Button, EmptyState, ErrorNote } from "../components/ui";

export default function DriftPage() {
  const [drift, setDrift] = useState([]);
  const [loading, setLoading] = useState(true);
  const [productionDrift, setProductionDrift] = useState(null);
  const [productionLoading, setProductionLoading] = useState(true);
  const [productionError, setProductionError] = useState("");
  const [history, setHistory] = useState([]);
  const [configurationDrift, setConfigurationDrift] = useState(null);

  useEffect(() => {
    api.drift().then((d) => {
      setDrift(d);
      setLoading(false);
    });
  }, []);

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
    loadProductionDrift();
  }, []);

  return (
    <div className="space-y-6">
      <Panel title="Drift report" eyebrow="Drift detection">
        {loading ? (
          <p className="text-sm text-slate-500">Loading...</p>
        ) : drift.length === 0 ? (
          <EmptyState
            title="No drift detected"
            hint="Re-run a simulation after editing a rule to check for regressions."
          />
        ) : (
          <ul className="divide-y divide-bg-800">
            {drift.map((d) => (
              <li key={d.rule_version_id} className="flex items-center gap-3 py-3">
                <GitCommitHorizontal size={16} className="text-fuchsia-400" />
                <div>
                  <div className="text-sm text-slate-300">{d.rule_title}</div>
                  <div className="font-mono text-[11px] text-slate-500">
                    was {d.previous_result ? "firing" : "not firing"}, now{" "}
                    {d.current_result ? "firing" : "not firing"}
                  </div>
                </div>
                <Badge tone="amber">changed</Badge>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Configuration drift" eyebrow="Wazuh inventory snapshots">
        {!configurationDrift || configurationDrift.status === "insufficient_history" ? (
          <EmptyState title="Need two Wazuh sync snapshots" hint="Run Environment sync twice to compare rule configuration." />
        ) : configurationDrift.changes.length === 0 ? (
          <EmptyState title="No configuration drift detected" />
        ) : (
          <ul className="divide-y divide-bg-800">
            {configurationDrift.changes.map((change) => (
              <li key={`${change.rule_id}-${change.category}`} className="flex items-center justify-between gap-3 py-3">
                <span className="font-mono text-sm text-slate-300">Rule {change.rule_id}</span>
                <Badge tone="amber">{change.category}</Badge>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Production comparison" eyebrow="Twin vs. real Wazuh">
        <div className="space-y-4">
          <Button variant="secondary" onClick={loadProductionDrift}>
            Refresh comparison
          </Button>

          {productionLoading ? (
            <p className="text-sm text-slate-500">Loading...</p>
          ) : productionError ? (
            <ErrorNote message={productionError} />
          ) : !productionDrift?.wazuh_reachable ? (
            <ErrorNote message={"Wazuh manager unreachable \u2014 check WAZUH_BASE_URL and network connectivity."} />
          ) : (
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              {[
                ["Twin verified", productionDrift.twin_verified_count],
                ["Wazuh active", productionDrift.production_active_count],
                ["Covered by both", productionDrift.covered_both.length],
              ].map(([label, value]) => (
                <div key={label} className="rounded-md border border-bg-800 bg-bg-900 p-3">
                  <div className="font-mono text-[11px] uppercase tracking-widest text-slate-500">{label}</div>
                  <div className="mt-1 text-xl font-medium text-slate-300">{value}</div>
                </div>
              ))}
            </div>
          )}

          {productionDrift?.wazuh_reachable && (
            <div className="space-y-2">
              <details className="rounded-md border border-bg-800 p-3">
                <summary className="cursor-pointer text-sm text-slate-300">
                  Blind spots in production (twin verified, Wazuh has no active rule)
                </summary>
                <div className="mt-3 flex flex-wrap gap-2">
                  {productionDrift.twin_only.map((techniqueId) => (
                    <Badge key={techniqueId} tone="amber">{techniqueId}</Badge>
                  ))}
                </div>
              </details>

              <details className="rounded-md border border-bg-800 p-3">
                <summary className="cursor-pointer text-sm text-slate-300">
                  Not yet verified by twin (active in Wazuh)
                </summary>
                <div className="mt-3 flex flex-wrap gap-2">
                  {productionDrift.production_only.map((techniqueId) => (
                    <Badge key={techniqueId}>{techniqueId}</Badge>
                  ))}
                </div>
              </details>
            </div>
          )}

          {history.length > 0 && (
            <div>
              <div className="mb-2 font-mono text-[11px] uppercase tracking-widest text-slate-500">
                Coverage over time
              </div>
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={[...history].reverse()}>
                  <CartesianGrid stroke="#1a2740" strokeDasharray="3 3" />
                  <XAxis
                    dataKey="created_at"
                    tickFormatter={(value) => new Date(value).toLocaleTimeString()}
                    stroke="#64748b"
                    fontSize={10}
                  />
                  <YAxis stroke="#64748b" fontSize={10} />
                  <Tooltip
                    contentStyle={{ background: "#111a29", border: "1px solid #1a2740", fontSize: 12 }}
                    labelFormatter={(value) => new Date(value).toLocaleString()}
                  />
                  <Area type="monotone" dataKey="production_active_count" stroke="#22d3ee" fill="#22d3ee" fillOpacity={0.15} name="Wazuh active" />
                  <Area type="monotone" dataKey="twin_verified_count" stroke="#e879f9" fill="#e879f9" fillOpacity={0.15} name="Twin verified" />
                  <Area type="monotone" dataKey="covered_both_count" stroke="#a3e635" fill="#a3e635" fillOpacity={0.2} name="Covered by both" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}
