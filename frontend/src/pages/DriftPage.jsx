import { useEffect, useState } from "react";
import { GitCommitHorizontal } from "lucide-react";
import { api } from "../lib/api";
import { Panel, Badge, EmptyState } from "../components/ui";

export default function DriftPage() {
  const [drift, setDrift] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.drift().then((d) => {
      setDrift(d);
      setLoading(false);
    });
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
    </div>
  );
}
