import { useEffect, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { api } from "../lib/api";
import { Panel, Badge, EmptyState } from "../components/ui";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listAlerts().then((a) => {
      setAlerts(a);
      setLoading(false);
    });
  }, []);

  return (
    <Panel title="Alert feed" eyebrow={`${alerts.length} alert(s)`}>
      {loading ? (
        <p className="text-sm text-graphite-400">Loading...</p>
      ) : alerts.length === 0 ? (
        <EmptyState title="No alerts yet" hint="Run a simulation that a rule detects." />
      ) : (
        <ul className="divide-y divide-graphite-700">
          {alerts.map((a) => (
            <li key={a.alert_id} className="flex items-center justify-between gap-4 py-3">
              <div className="flex items-center gap-3">
                <AlertTriangle size={16} className="text-alert-400" />
                <div>
                  <div className="text-sm text-graphite-100">{a.rule_title}</div>
                  <div className="font-mono text-[11px] text-graphite-500">
                    {new Date(a.evaluated_at).toLocaleString()}
                  </div>
                </div>
              </div>
              {a.technique_id && <Badge tone="alert">{a.technique_id}</Badge>}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
