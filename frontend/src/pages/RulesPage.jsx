import { useEffect, useState } from "react";
import { FileUp, ShieldCheck, Trash2 } from "lucide-react";
import { api } from "../lib/api";
import { Panel, Badge, Button, EmptyState, ErrorNote } from "../components/ui";

const PLACEHOLDER_YAML = `title: My detection rule
status: test
description: What this rule detects
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
    condition: selection
level: medium
tags:
    - attack.execution
    - attack.t1059.001
`;

export default function RulesPage() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [yamlText, setYamlText] = useState(PLACEHOLDER_YAML);
  const [uploadError, setUploadError] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [selected, setSelected] = useState(null);

  const refresh = async () => {
    setLoading(true);
    try {
      setRules(await api.listRules());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  const handleUpload = async (e) => {
    e.preventDefault();
    setUploadError(null);
    setUploading(true);
    try {
      await api.uploadRule(yamlText);
      setYamlText(PLACEHOLDER_YAML);
      await refresh();
    } catch (err) {
      setUploadError(err.message);
    } finally {
      setUploading(false);
    }
  };

  const handleDelete = async (ruleId) => {
    await api.deleteRule(ruleId);
    if (selected === ruleId) setSelected(null);
    await refresh();
  };

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
      <Panel
        title="Upload Sigma rule"
        eyebrow="FR-01 / FR-02"
        className="lg:col-span-2 lg:self-start"
      >
        <form onSubmit={handleUpload} className="space-y-3">
          <textarea
            value={yamlText}
            onChange={(e) => setYamlText(e.target.value)}
            spellCheck={false}
            rows={16}
            className="w-full resize-y rounded-md border border-graphite-600 bg-graphite-950 px-3 py-2 font-mono text-xs text-graphite-100 outline-none focus:border-signal-500"
          />
          <ErrorNote message={uploadError} />
          <Button type="submit" disabled={uploading} className="inline-flex items-center gap-2">
            <FileUp size={14} />
            {uploading ? "Validating..." : "Validate & upload"}
          </Button>
          <p className="font-mono text-[11px] leading-relaxed text-graphite-500">
            Parsed and validated with pySigma. Rejected rules return the
            underlying Sigma error (schema, unsupported logsource, or
            unparseable condition) instead of failing silently.
          </p>
        </form>
      </Panel>

      <Panel
        title="Rule library"
        eyebrow={`${rules.length} rule${rules.length === 1 ? "" : "s"}`}
        className="lg:col-span-3"
      >
        {loading ? (
          <p className="text-sm text-graphite-400">Loading...</p>
        ) : rules.length === 0 ? (
          <EmptyState
            title="No rules uploaded yet"
            hint="Upload a Sigma rule on the left to start building coverage."
          />
        ) : (
          <ul className="divide-y divide-graphite-700">
            {rules.map((r) => (
              <li key={r.rule_id} className="flex items-start justify-between gap-4 py-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <ShieldCheck size={14} className="shrink-0 text-signal-400" />
                    <span className="truncate text-sm text-graphite-100">{r.title}</span>
                    <Badge>v{r.version_number}</Badge>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-1.5">
                    {(r.mitre_techniques || []).length === 0 ? (
                      <span className="font-mono text-[11px] text-graphite-500">no MITRE tags</span>
                    ) : (
                      r.mitre_techniques.map((t) => (
                        <Badge key={t} tone="signal">
                          {t}
                        </Badge>
                      ))
                    )}
                  </div>
                </div>
                <button
                  onClick={() => handleDelete(r.rule_id)}
                  className="shrink-0 rounded p-1.5 text-graphite-500 hover:bg-alert-500/10 hover:text-alert-400"
                  aria-label={`Delete ${r.title}`}
                >
                  <Trash2 size={14} />
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
