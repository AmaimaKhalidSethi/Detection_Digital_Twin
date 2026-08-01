import { useEffect, useState } from "react";
import { GitCommitHorizontal } from "lucide-react";
import { api } from "../lib/api";
import { Panel, Badge, EmptyState } from "../components/ui";

function CoverageCell({ row }) {
  const state = !row.has_rule ? "none" : row.rule_passes ? "covered" : "failing";
  const styles = {
    none: "border-graphite-700 bg-graphite-900 text-graphite-500",
    failing: "border-amber-500/50 bg-amber-500/10 text-amber-400",
    covered: "border-signal-500/50 bg-signal-500/10 text-signal-400",
  };
  const labels = { none: "no rule", failing: "rule present, not firing", covered: "covered" };
  return (
    <div
      className={`flex flex-col justify-between rounded-md border p-3 ${styles[state]}`}
      title={labels[state]}
    >
      <div className="font-mono text-xs font-medium">{row.technique_id}</div>
      <div className="mt-2 text-[11px] leading-snug">{row.name}</div>
      <div className="mt-2 font-mono text-[10px] uppercase tracking-wide opacity-80">
        {labels[state]}
      </div>
    </div>
  );
}

export default function CoveragePage() {
  const [coverage, setCoverage] = useState([]);
  const [drift, setDrift] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.coverage(), api.drift()]).then(([c, d]) => {
      setCoverage(c);
      setDrift(d);
      setLoading(false);
    });
  }, []);

  const grouped = coverage.reduce((acc, row) => {
    acc[row.tactic] = acc[row.tactic] || [];
    acc[row.tactic].push(row);
    return acc;
  }, {});

  const coveredCount = coverage.filter((r) => r.rule_passes).length;

  return (
    <div className="space-y-6">
      <Panel
        title="ATT&CK coverage matrix"
        eyebrow={`${coveredCount} / ${coverage.length} techniques covered`}
      >
        {loading ? (
          <p className="text-sm text-graphite-400">Loading...</p>
        ) : coverage.length === 0 ? (
          <EmptyState title="No techniques in the curated library yet" />
        ) : (
          <div className="space-y-5">
            {Object.entries(grouped).map(([tactic, rows]) => (
              <div key={tactic}>
                <div className="mb-2 font-mono text-[11px] uppercase tracking-widest text-graphite-400">
                  {tactic}
                </div>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
                  {rows.map((row) => (
                    <CoverageCell key={row.technique_id} row={row} />
                  ))}
                </div>
              </div>
            ))}
            <div className="flex flex-wrap gap-4 border-t border-graphite-700 pt-3 font-mono text-[11px] text-graphite-400">
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-sm bg-signal-500" /> covered
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-sm bg-amber-500" /> rule present, not firing
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-sm bg-graphite-600" /> blind spot — no rule
              </span>
            </div>
          </div>
        )}
      </Panel>

      <Panel title="Drift report" eyebrow="FR-10">
        {drift.length === 0 ? (
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
