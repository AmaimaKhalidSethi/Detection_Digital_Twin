import { useEffect, useState } from "react";
import { Download, SlidersHorizontal, Search, Info, ShieldCheck, AlertTriangle } from "lucide-react";
import { api } from "../lib/api";
import { Panel, Badge, Button, EmptyState } from "../components/ui";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

const statusTone = {
  VALIDATED: "signal",
  DETECTION_GAP: "alert",
  UNAVAILABLE: "amber",
  ERROR: "amber",
};

function CoverageCell({ row, driftReachable, coveredBoth, twinOnly, productionOnly, onSelect }) {
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
    both: "border-cyan-500 bg-cyan-500 text-bg-950 cursor-pointer hover:scale-105 transition-transform",
    twin_only: "border-fuchsia-500 bg-fuchsia-500 text-bg-950 cursor-pointer hover:scale-105 transition-transform",
    production_only: "border-cyan-500/50 bg-cyan-500/10 text-cyan-400 cursor-pointer hover:scale-105 transition-transform",
    verified_unconfirmed_prod: "border-cyan-500/40 bg-cyan-500/40 text-bg-950 cursor-pointer hover:scale-105 transition-transform",
    failing: "border-fuchsia-500/30 bg-fuchsia-500/5 text-fuchsia-400 cursor-pointer hover:scale-105 transition-transform",
    none: "border-bg-800 bg-bg-800 text-slate-500 cursor-pointer hover:bg-bg-700/40",
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
      onClick={() => onSelect(row)}
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
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);

  // Filters state
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedTactic, setSelectedTactic] = useState("all");
  const [selectedStatus, setSelectedStatus] = useState("all");

  // Drawer state
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const [selectedTechRuns, setSelectedTechRuns] = useState([]);
  const [loadingRuns, setLoadingRuns] = useState(false);

  useEffect(() => {
    Promise.all([api.coverage(), api.productionDrift(), api.listRules()]).then(([c, d, r]) => {
      setCoverage(c || []);
      setDrift(d);
      setRules(r || []);
      setLoading(false);
    });
  }, []);

  const handleSelectTechnique = async (techRow) => {
    setSelectedTechnique(techRow);
    setLoadingRuns(true);
    try {
      const runs = await api.listValidationRuns();
      setSelectedTechRuns((runs || []).filter((r) => r.technique_id === techRow.technique_id));
    } catch (err) {
      console.error("Failed to load validation runs for technique", err);
    } finally {
      setLoadingRuns(false);
    }
  };

  const driftReachable = drift ? drift.wazuh_reachable : false;
  const coveredBothSet = new Set(drift ? drift.covered_both : []);
  const twinOnlySet = new Set(drift ? drift.twin_only : []);
  const productionOnlySet = new Set(drift ? drift.production_only : []);

  // Compute counters
  const totalTechniques = coverage.length;
  const wazuhConfigured = coverage.filter((r) => r.has_rule).length;
  const twinVerified = coverage.filter((r) => r.rule_passes).length;
  const observedWazuh = driftReachable ? coveredBothSet.size + productionOnlySet.size : 0;

  // Filtered coverage list
  const filteredCoverage = coverage.filter((row) => {
    const matchesSearch =
      row.technique_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      row.name.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesTactic = selectedTactic === "all" || row.tactic.toLowerCase() === selectedTactic.toLowerCase();
    
    let matchesStatus = true;
    if (selectedStatus === "verified") {
      matchesStatus = row.rule_passes;
    } else if (selectedStatus === "unverified") {
      matchesStatus = !row.rule_passes;
    } else if (selectedStatus === "has_rule") {
      matchesStatus = row.has_rule;
    } else if (selectedStatus === "gaps") {
      matchesStatus = (row.has_rule && !row.rule_passes) || twinOnlySet.has(row.technique_id);
    }

    return matchesSearch && matchesTactic && matchesStatus;
  });

  const grouped = filteredCoverage.reduce((acc, row) => {
    acc[row.tactic] = acc[row.tactic] || [];
    acc[row.tactic].push(row);
    return acc;
  }, {});

  const tacticStats = Object.entries(grouped).map(([tactic, rows]) => ({
    tactic,
    total: rows.length,
    verified: rows.filter((r) => r.rule_passes).length,
  }));

  // Unique tactics list for filter dropdown
  const tacticsList = Array.from(new Set(coverage.map((r) => r.tactic))).sort();

  // Find rules mapped to selected technique
  const mappedRules = selectedTechnique
    ? rules.filter((rule) =>
        rule.latest_version?.technique_mappings?.some((m) => m.technique_id === selectedTechnique.technique_id)
      )
    : [];

  return (
    <div className="relative min-h-[85vh] space-y-6">
      {/* Header and Stats */}
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100">ATT&CK Technique Matrix</h1>
          <p className="text-xs text-slate-500 font-mono">
            Visualize simulation status and reconcile digital twin definitions with Wazuh manager rules.
          </p>
        </div>
        <Button
          variant="secondary"
          className="inline-flex items-center gap-2 font-mono text-xs self-start md:self-auto"
          onClick={async () => {
            const layer = await api.navigatorLayer();
            const blob = new Blob([JSON.stringify(layer, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");
            link.href = url;
            link.download = "coverage-navigator-layer.json";
            link.click();
            URL.revokeObjectURL(url);
          }}
        >
          <Download size={12} /> Export Layer
        </Button>
      </div>

      {/* Counters Grid */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          ["Total Techniques", totalTechniques, "slate-500"],
          ["Wazuh Configured", wazuhConfigured, "amber-500"],
          ["Twin Verified", twinVerified, "cyan-400"],
          ["Observed Wazuh Detection", driftReachable ? observedWazuh : "Offline", "emerald-400"],
        ].map(([label, value, colorClass]) => (
          <div key={label} className="rounded-md border border-bg-800 bg-bg-900/40 p-4">
            <div className="font-mono text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
            <div className={`mt-1 text-xl font-bold text-${colorClass}`}>{value}</div>
          </div>
        ))}
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-col gap-3 rounded-lg border border-bg-800 bg-bg-950 p-4 sm:flex-row sm:items-center">
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 shrink-0">
          <SlidersHorizontal size={14} className="text-cyan-400" />
          <span>Filters</span>
        </div>

        <div className="relative flex-1">
          <Search size={14} className="absolute left-3 top-2.5 text-slate-500" />
          <input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-md border border-bg-800 bg-bg-900 pl-9 pr-3 py-1.5 text-xs text-slate-200 font-mono focus:border-cyan-500/50 outline-none"
            placeholder="Search Technique ID or Name..."
          />
        </div>

        <select
          value={selectedTactic}
          onChange={(e) => setSelectedTactic(e.target.value)}
          className="rounded-md border border-bg-800 bg-bg-900 px-3 py-1.5 text-xs font-mono text-slate-300"
        >
          <option value="all">All Tactics</option>
          {tacticsList.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>

        <select
          value={selectedStatus}
          onChange={(e) => setSelectedStatus(e.target.value)}
          className="rounded-md border border-bg-800 bg-bg-900 px-3 py-1.5 text-xs font-mono text-slate-300"
        >
          <option value="all">All Verification Statuses</option>
          <option value="verified">Twin Verified</option>
          <option value="unverified">Unverified</option>
          <option value="has_rule">Has Mapped Rule</option>
          <option value="gaps">Gaps / Blind Spots</option>
        </select>
      </div>

      {/* Matrix Panel */}
      <Panel title="ATT&CK Coverage Matrix" eyebrow={`${filteredCoverage.length} techniques matching filters`}>
        {loading ? (
          <p className="text-sm text-slate-500">Loading coverage data...</p>
        ) : filteredCoverage.length === 0 ? (
          <EmptyState title="No matching techniques found" hint="Try adjusting your filter options." />
        ) : (
          <div className="space-y-6">
            {!driftReachable && (
              <div className="rounded border border-amber-500/20 bg-amber-500/5 px-3 py-2 font-mono text-xs text-amber-400/90 flex items-center gap-2">
                <AlertTriangle size={14} />
                Wazuh unreachable — displaying local twin-verified results only.
              </div>
            )}

            {/* Dynamic Recharts Chart */}
            {tacticStats.length > 0 && (
              <div>
                <ResponsiveContainer width="100%" height={Math.max(160, tacticStats.length * 28)}>
                  <BarChart data={tacticStats} layout="vertical" margin={{ left: 16 }}>
                    <CartesianGrid stroke="#162031" strokeDasharray="3 3" horizontal={false} />
                    <XAxis type="number" stroke="#475569" fontSize={9} />
                    <YAxis dataKey="tactic" type="category" stroke="#475569" fontSize={9} width={130} />
                    <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", fontSize: 11 }} />
                    <Bar dataKey="total" fill="#1e293b" name="Total in tactic" radius={[0, 4, 4, 0]} />
                    <Bar dataKey="verified" fill="#22d3ee" name="Twin verified" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}

            {/* Matrix Cells */}
            <div className="space-y-5 border-t border-bg-800 pt-5">
              {Object.entries(grouped).map(([tactic, rows]) => (
                <div key={tactic}>
                  <div className="mb-2 font-mono text-[10px] uppercase tracking-wider text-slate-500">
                    {tactic} ({rows.length})
                  </div>
                  <div className="grid grid-cols-[repeat(auto-fill,minmax(50px,1fr))] gap-1">
                    {rows.map((row) => (
                      <CoverageCell
                        key={row.technique_id}
                        row={row}
                        driftReachable={driftReachable}
                        coveredBoth={coveredBothSet}
                        twinOnly={twinOnlySet}
                        productionOnly={productionOnlySet}
                        onSelect={handleSelectTechnique}
                      />
                    ))}
                  </div>
                </div>
              ))}
            </div>

            {/* Legend */}
            <div className="flex flex-wrap gap-4 border-t border-bg-800 pt-4 font-mono text-[10px] text-slate-500">
              <span className="flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 rounded bg-cyan-500" /> verified + Wazuh active
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 rounded bg-fuchsia-500" /> production blind spot (twin verified only)
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 rounded border border-cyan-500/50 bg-cyan-500/10" /> production active (twin unverified)
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 rounded border border-fuchsia-500/30 bg-fuchsia-500/5" /> mapped rule (not confirmed)
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 rounded bg-bg-800" /> unmapped technique
              </span>
            </div>
          </div>
        )}
      </Panel>

      {/* DETAIL DRAWER */}
      {selectedTechnique && (
        <div className="fixed inset-y-0 right-0 z-50 w-full max-w-md border-l border-bg-800 bg-bg-950 p-6 shadow-2xl overflow-y-auto flex flex-col justify-between">
          <div className="space-y-6">
            <div className="flex items-start justify-between border-b border-bg-800 pb-4">
              <div>
                <span className="font-mono text-[10px] text-cyan-400 uppercase tracking-widest">{selectedTechnique.tactic}</span>
                <h3 className="text-sm font-bold text-slate-100">{selectedTechnique.technique_id} — {selectedTechnique.name}</h3>
              </div>
              <Button variant="secondary" onClick={() => setSelectedTechnique(null)} className="text-xs">
                Close
              </Button>
            </div>

            {/* Status section */}
            <div>
              <div className="font-mono text-[10px] text-slate-500 uppercase tracking-wider mb-2">Twin Verification Status</div>
              <Badge tone={selectedTechnique.rule_passes ? "signal" : selectedTechnique.has_rule ? "amber" : "neutral"}>
                {selectedTechnique.rule_passes ? "Twin Verified" : selectedTechnique.has_rule ? "Rule Mapped (Failing Validation)" : "No Rule Mapped"}
              </Badge>
            </div>

            {/* Mapped rules */}
            <div>
              <div className="font-mono text-[10px] text-slate-500 uppercase tracking-wider mb-2">Digital Twin Mapped Rules</div>
              {mappedRules.length === 0 ? (
                <p className="text-xs text-slate-500 font-mono">No rules currently mapped to this technique.</p>
              ) : (
                <div className="space-y-2">
                  {mappedRules.map((rule) => (
                    <div key={rule.id} className="rounded border border-bg-800 bg-bg-900 p-3 space-y-1">
                      <div className="text-xs font-semibold text-slate-200">{rule.title}</div>
                      <div className="font-mono text-[10px] text-slate-500">ID: {rule.id}</div>
                      <div className="flex justify-between items-center font-mono text-[9px] text-slate-600 mt-1 pt-1.5 border-t border-bg-800">
                        <span>Level: {rule.level || "unknown"}</span>
                        <span>Source: {rule.source || "declared"}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Validation history */}
            <div>
              <div className="font-mono text-[10px] text-slate-500 uppercase tracking-wider mb-2">Logtest Validation Runs</div>
              {loadingRuns ? (
                <p className="text-xs text-slate-500 font-mono">Querying history...</p>
              ) : selectedTechRuns.length === 0 ? (
                <p className="text-xs text-slate-500 font-mono">No validation runs registered for this technique.</p>
              ) : (
                <div className="space-y-2">
                  {selectedTechRuns.map((run) => (
                    <div key={run.id} className="rounded border border-bg-800 bg-bg-900/60 p-3 space-y-1 text-xs">
                      <div className="flex justify-between items-center border-b border-bg-800 pb-1 mb-1.5">
                        <span className="font-mono text-[10px] text-slate-500">{new Date(run.started_at).toLocaleDateString()}</span>
                        <Badge tone={statusTone[run.status] || "neutral"}>{run.status}</Badge>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-[10px] font-mono text-slate-400">
                        <div>Expected: {run.expected_detection}</div>
                        <div>Observed: {run.observed_detection || "NONE"}</div>
                      </div>
                      <div className="text-[10px] font-mono text-slate-400 mt-1">
                        <span className="text-slate-600">Classification:</span> {run.final_classification || "PENDING"}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
          
          <div className="mt-6 pt-4 border-t border-bg-800 flex justify-end">
            <Button variant="secondary" onClick={() => setSelectedTechnique(null)} className="w-full text-xs font-mono">
              Dismiss Details
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
