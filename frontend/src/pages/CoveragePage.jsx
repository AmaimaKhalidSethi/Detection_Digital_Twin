import { useEffect, useState } from "react";
import { Download } from "lucide-react";
import { api } from "../lib/api";
import { Panel, Badge, Button, EmptyState } from "../components/ui";

function CoverageCell({ row, driftReachable, coveredBoth, twinOnly, productionOnly }) {
  let state = "none";
  if (driftReachable && coveredBoth.has(row.technique_id)) {
    state = "both";
  } else if (driftReachable && twinOnly.has(row.technique_id)) {
    state = "twin_only";
  } else if (driftReachable && productionOnly.has(row.technique_id)) {
    state = "production_only";
  } else if (row.rule_passes) {
    state = "verified_unconfirmed_prod";
  } else if (row.has_rule) {
    state = "failing";
  }

  const styles = {
    both: "border-cyan-500 bg-cyan-500 text-bg-950",
    twin_only: "border-fuchsia-500 bg-fuchsia-500 text-bg-950",
    production_only: "border-cyan-500/50 bg-cyan-500/10 text-cyan-400",
    verified_unconfirmed_prod: "border-cyan-500/40 bg-cyan-500/40 text-bg-950",
    failing: "border-fuchsia-500/30 bg-fuchsia-500/5 text-fuchsia-400",
    none: "border-bg-800 bg-bg-800 text-slate-500",
  };
  const labels = {
    both: "verified + Wazuh active",
    twin_only: "twin verified — Wazuh blind spot",
    production_only: "Wazuh active — twin unverified",
    verified_unconfirmed_prod: "twin verified (Wazuh status unknown)",
    failing: "rule present, not confirmed",
    none: "no rule",
  };

  return (
    <div
      className={`flex aspect-square items-center justify-center rounded border font-mono text-[9px] ${styles[state]}`}
      title={`${row.technique_id} — ${row.name} — ${labels[state]}`}
    >
      {row.technique_id}
    </div>
  );
}

export default function CoveragePage() {
  const [coverage, setCoverage] = useState([]);
  const [drift, setDrift] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.coverage(), api.productionDrift()]).then(([c, d]) => {
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
  const driftReachable = drift ? drift.wazuh_reachable : false;
  const coveredBothSet = new Set(drift ? drift.covered_both : []);
  const twinOnlySet = new Set(drift ? drift.twin_only : []);
  const productionOnlySet = new Set(drift ? drift.production_only : []);

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
            {!driftReachable && (
              <div className="mb-4 rounded border border-fuchsia-500/30 bg-fuchsia-500/5 px-3 py-2 font-mono text-xs text-fuchsia-400">
                Wazuh unreachable — showing twin-verified coverage only, production comparison unavailable.
              </div>
            )}
            {Object.entries(grouped).map(([tactic, rows]) => (
              <div key={tactic}>
                <div className="mb-2 font-mono text-[11px] uppercase tracking-widest text-graphite-400">
                  {tactic}
                </div>
                <div className="grid grid-cols-[repeat(auto-fill,minmax(44px,1fr))] gap-1">
                  {rows.map((row) => (
                    <CoverageCell
                      key={row.technique_id}
                      row={row}
                      driftReachable={driftReachable}
                      coveredBoth={coveredBothSet}
                      twinOnly={twinOnlySet}
                      productionOnly={productionOnlySet}
                    />
                  ))}
                </div>
              </div>
            ))}
            <div className="flex flex-wrap gap-4 border-t border-bg-800 pt-3 font-mono text-[11px] text-slate-500">
              <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm bg-cyan-500" /> verified + Wazuh active</span>
              <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm bg-fuchsia-500" /> blind spot in production</span>
              <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm border border-cyan-500/50 bg-cyan-500/10" /> Wazuh active, twin unverified</span>
              <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm border border-fuchsia-500/30 bg-fuchsia-500/5" /> rule present, not confirmed</span>
              <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm bg-bg-800" /> no rule</span>
            </div>
          </div>
        )}
      </Panel>

    </div>
  );
}
