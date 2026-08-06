import { useState, useEffect, useCallback } from "react";
import { api } from "../lib/api";
import { Panel, Badge, Button, EmptyState, ErrorNote } from "../components/ui";

function Stat({ label, value }) {
  return (
    <div className="rounded-md border border-bg-800 px-4 py-3">
      <div className="font-mono text-[11px] uppercase tracking-widest text-slate-500">
        {label}
      </div>
      <div className="mt-1 font-mono text-2xl text-slate-300">{value}</div>
    </div>
  );
}

export default function OverviewPage() {
  const [coverage, setCoverage] = useState(null);
  const [drift, setDrift] = useState(null);
  const [history, setHistory] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([api.coverage(), api.productionDrift(), api.productionDriftHistory()])
      .then(([coverageData, driftData, historyData]) => {
        setCoverage(coverageData);
        setDrift(driftData);
        setHistory(historyData);
      })
      .catch((err) => setError(err.message || "Failed to load overview data"))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (loading && !coverage) {
    return <EmptyState title="Loading overview..." />;
  }

  const verifiedCount = coverage ? coverage.filter((row) => row.rule_passes).length : 0;
  const productionBlindSpots = drift && drift.wazuh_reachable ? drift.twin_only.length : null;

  return (
    <div className="space-y-6">
      <Panel
        eyebrow="DETECTION DIGITAL TWIN"
        title="Overview"
        actions={<Button variant="secondary" onClick={load}>Refresh</Button>}
      >
        {error && <ErrorNote message={error} />}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat label="Total techniques" value={coverage ? coverage.length : "—"} />
          <Stat label="Twin verified" value={verifiedCount} />
          <Stat label="Production blind spots" value={productionBlindSpots === null ? "—" : productionBlindSpots} />
          <Stat
            label="Wazuh active"
            value={drift && drift.wazuh_reachable ? drift.production_active_count : "—"}
          />
        </div>
      </Panel>

      <Panel eyebrow="TWIN VS. REAL WAZUH" title="Recent production comparisons">
        {drift && !drift.wazuh_reachable && (
          <ErrorNote message="Wazuh manager unreachable on last comparison." />
        )}
        {!history || history.length === 0 ? (
          <EmptyState
            title="No comparison history yet"
            hint="Run a production drift comparison from the Drift page to start building history."
          />
        ) : (
          <div className="space-y-1 font-mono text-xs">
            {history.slice(0, 5).map((row) => (
              <div
                key={row.created_at}
                className="flex items-center justify-between rounded border border-bg-800 px-3 py-2"
              >
                <span className="text-slate-500">
                  {new Date(row.created_at).toLocaleString()}
                </span>
                <div className="flex items-center gap-3">
                  <Badge tone={row.wazuh_reachable ? "signal" : "alert"}>
                    {row.wazuh_reachable ? "reachable" : "unreachable"}
                  </Badge>
                  <span className="text-slate-300">
                    {row.twin_only_count} blind spot{row.twin_only_count === 1 ? "" : "s"}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
