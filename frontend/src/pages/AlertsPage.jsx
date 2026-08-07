import { useEffect, useState } from "react";
import { AlertTriangle, Sparkles } from "lucide-react";
import { api } from "../lib/api";
import { Panel, Badge, Button, EmptyState } from "../components/ui";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [explanations, setExplanations] = useState({});

  useEffect(() => {
    api.listAlerts().then((a) => {
      setAlerts(a);
      setLoading(false);
    });
  }, []);

  const handleExplain = async (alertId) => {
    const explanation = await api.explainAlert(alertId);
    setExplanations((current) => ({ ...current, [alertId]: explanation }));
  };

  return (
    <Panel title="Alert feed" eyebrow={`${alerts.length} alert(s)`}>
      {loading ? (
        <p className="text-sm text-slate-500">Loading...</p>
      ) : alerts.length === 0 ? (
        <EmptyState title="No alerts yet" hint="Run a simulation that a rule detects." />
      ) : (
        <ul className="divide-y divide-bg-800">
          {alerts.map((a) => (
            <li key={a.alert_id} className="flex flex-col gap-3 py-3">
              <div className="flex items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <AlertTriangle size={16} className="text-rose-400" />
                  <div>
                    <div className="text-sm text-slate-300">{a.rule_title}</div>
                    <div className="text-xs text-slate-500">
                      Author: {a.rule_author || "Unknown"}
                    </div>
                    <div className="font-mono text-[11px] text-slate-500">
                      {new Date(a.evaluated_at).toLocaleString()}
                    </div>
                  </div>
                </div>
                {a.technique_id && <Badge tone="alert">{a.technique_id}</Badge>}
              </div>
              <div className="flex items-center justify-between gap-3">
                <Button variant="secondary" className="inline-flex items-center gap-2" onClick={() => handleExplain(a.alert_id)}>
                  <Sparkles size={14} />Explain match
                </Button>
                {explanations[a.alert_id] ? (
                  <div className="max-w-2xl rounded-md border border-bg-800 bg-bg-950 px-3 py-2 font-mono text-[11px] text-slate-500">
                    {explanations[a.alert_id].explanation}
                  </div>
                ) : null}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
