import { useEffect, useState } from "react";
import { GitCommitHorizontal } from "lucide-react";
import { api } from "../lib/api";
import { Panel, Badge, Button, EmptyState, ErrorNote } from "../components/ui";

export default function DriftPage() {
  const [drift, setDrift] = useState([]);
  const [loading, setLoading] = useState(true);
  const [productionDrift, setProductionDrift] = useState(null);
  const [productionLoading, setProductionLoading] = useState(true);
  const [productionError, setProductionError] = useState("");

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
          <p className="text-sm text-graphite-400">Loading...</p>
        ) : drift.length === 0 ? (
          <EmptyState
            title="No drift detected"
            hint="Re-run a simulation after editing a rule to check for regressions."
          />
        ) : (
          <ul className="divide-y divide-graphite-700">
            {drift.map((d) => (
              <li key={d.rule_version_id} className="flex items-center gap-3 py-3">
                <GitCommitHorizontal size={16} className="text-amber-400" />
                <div>
                  <div className="text-sm text-graphite-100">{d.rule_title}</div>
                  <div className="font-mono text-[11px] text-graphite-500">
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

      <Panel title="Production comparison" eyebrow="Twin vs. real Wazuh">
        {productionLoading ? (
          <p className="text-sm text-graphite-400">Loading...</p>
        ) : productionError ? (
          <ErrorNote message={productionError} />
        ) : !productionDrift?.wazuh_reachable ? (
          <ErrorNote message="Wazuh manager unreachable — check WAZUH_BASE_URL and network connectivity." />
        ) : (
          <div className="space-y-4">
            <Button variant="secondary" onClick={loadProductionDrift}>
              Refresh comparison
            </Button>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              {[
                ["Twin verified", productionDrift.twin_verified_count],
                ["Wazuh active", productionDrift.production_active_count],
                ["Covered by both", productionDrift.covered_both.length],
              ].map(([label, value]) => (
                <div key={label} className="rounded-md border border-graphite-700 bg-graphite-900 p-3">
                  <div className="font-mono text-[11px] uppercase tracking-widest text-graphite-500">{label}</div>
                  <div className="mt-1 text-xl font-medium text-graphite-100">{value}</div>
                </div>
              ))}
            </div>

            <div className="space-y-2">
              <details className="rounded-md border border-graphite-700 p-3">
                <summary className="cursor-pointer text-sm text-graphite-100">
                  Blind spots in production (twin verified, Wazuh has no active rule)
                </summary>
                <div className="mt-3 flex flex-wrap gap-2">
                  {productionDrift.twin_only.map((techniqueId) => (
                    <Badge key={techniqueId} tone="amber">{techniqueId}</Badge>
                  ))}
                </div>
              </details>

              <details className="rounded-md border border-graphite-700 p-3">
                <summary className="cursor-pointer text-sm text-graphite-100">
                  Not yet verified by twin (active in Wazuh)
                </summary>
                <div className="mt-3 flex flex-wrap gap-2">
                  {productionDrift.production_only.map((techniqueId) => (
                    <Badge key={techniqueId}>{techniqueId}</Badge>
                  ))}
                </div>
              </details>
            </div>
          </div>
        )}
      </Panel>
    </div>
  );
}
