import { useEffect, useState } from "react";
import { Download } from "lucide-react";
import { api } from "../lib/api";
import { Panel, Badge, Button, EmptyState } from "../components/ui";

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
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.coverage().then((c) => {
      setCoverage(c);
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
        actions={
          <Button variant="secondary" className="inline-flex items-center gap-2" onClick={async () => {
            const layer = await api.navigatorLayer();
            const blob = new Blob([JSON.stringify(layer, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");
            link.href = url;
            link.download = "coverage-navigator-layer.json";
            link.click();
            URL.revokeObjectURL(url);
          }}>
            <Download size={14} />Export layer
          </Button>
        }
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

    </div>
  );
}
