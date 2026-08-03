import { useEffect, useMemo, useState } from "react";
import { ChevronLeft, ChevronRight, FileUp, PlayCircle, Search, ShieldCheck, Sparkles, Trash2 } from "lucide-react";
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
  const [selectedRuleId, setSelectedRuleId] = useState(null);
  const [selectedRuleDetail, setSelectedRuleDetail] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [testResult, setTestResult] = useState(null);
  const [suggestionResult, setSuggestionResult] = useState(null);
  const pageSize = 6;

  const refresh = async () => {
    setLoading(true);
    try {
      const data = await api.searchRules(searchQuery, { status: statusFilter === "all" ? "" : statusFilter });
      setRules(data);
      if (selectedRuleId && !data.some((rule) => rule.rule_id === selectedRuleId)) {
        setSelectedRuleId(null);
        setSelectedRuleDetail(null);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
  }, [searchQuery, statusFilter]);

  useEffect(() => {
    setPage(1);
  }, [searchQuery, statusFilter]);

  const totalPages = Math.max(1, Math.ceil(rules.length / pageSize));
  const pagedRules = useMemo(() => rules.slice((page - 1) * pageSize, page * pageSize), [rules, page]);

  const selectRule = async (ruleId) => {
    setSelectedRuleId(ruleId);
    setTestResult(null);
    setSuggestionResult(null);
    const detail = await api.getRule(ruleId);
    setSelectedRuleDetail(detail);
  };

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
    if (selectedRuleId === ruleId) {
      setSelectedRuleId(null);
      setSelectedRuleDetail(null);
    }
    await refresh();
  };

  const handleTestRule = async (ruleId) => {
    const result = await api.testRule(ruleId);
    setTestResult(result);
  };

  const handleSuggestTechniques = async (ruleId) => {
    const result = await api.suggestTechniques(ruleId);
    setSuggestionResult(result);
  };

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1.2fr_0.8fr]">
      <Panel title="Upload Sigma rule" eyebrow="Rule import" className="lg:self-start">
        <form onSubmit={handleUpload} className="space-y-3">
          <textarea
            value={yamlText}
            onChange={(e) => setYamlText(e.target.value)}
            spellCheck={false}
            rows={16}
            className="w-full resize-y rounded-md border border-graphite-600 bg-graphite-950 px-3 py-2 font-mono text-xs text-graphite-100 outline-none focus:border-signal-500"
          />
          <p className="font-mono text-[11px] leading-relaxed text-graphite-500">
            When uploaded, the rule is validated with pySigma and saved as a new rule version.
          </p>
          <ErrorNote message={uploadError} />
          <Button type="submit" disabled={uploading} className="inline-flex items-center gap-2">
            <FileUp size={14} />
            {uploading ? "Validating..." : "Validate & upload"}
          </Button>
          <p className="font-mono text-[11px] leading-relaxed text-graphite-500">
            Parsed and validated with pySigma. Rejected rules return the underlying Sigma error instead of failing silently.
          </p>
        </form>
      </Panel>

      <Panel title="Rule library" eyebrow={`${rules.length} rule${rules.length === 1 ? "" : "s"}`}>
        <div className="space-y-3">
          <div className="flex flex-col gap-2 sm:flex-row">
            <label className="flex items-center gap-2 rounded-md border border-graphite-700 bg-graphite-950 px-3 py-2 text-sm text-graphite-300">
              <Search size={14} className="text-graphite-500" />
              <input
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by title or description"
                className="w-full bg-transparent outline-none"
              />
            </label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-md border border-graphite-700 bg-graphite-950 px-3 py-2 text-sm text-graphite-200"
            >
              <option value="all">All statuses</option>
              <option value="active">Active</option>
              <option value="draft">Draft</option>
              <option value="test">Test</option>
            </select>
          </div>

          {loading ? (
            <p className="text-sm text-graphite-400">Loading...</p>
          ) : rules.length === 0 ? (
            <EmptyState title="No matching rules" hint="Try a different search term or upload a new rule." />
          ) : (
            <>
              <ul className="divide-y divide-graphite-700">
                {pagedRules.map((r) => {
                  const isSelected = selectedRuleId === r.rule_id;
                  return (
                    <li key={r.rule_id} className={`py-3 ${isSelected ? "rounded-md bg-signal-500/10" : ""}`}>
                      <div className="flex items-start justify-between gap-3">
                        <button className="min-w-0 text-left" onClick={() => selectRule(r.rule_id)}>
                          <div className="flex items-center gap-2">
                            <ShieldCheck size={14} className="shrink-0 text-signal-400" />
                            <span className="truncate text-sm text-graphite-100">{r.title}</span>
                            <Badge>{r.status}</Badge>
                            <Badge>v{r.version_number}</Badge>
                          </div>
                          <div className="mt-1 flex flex-wrap gap-1.5">
                            {(r.mitre_techniques || []).length === 0 ? (
                              <span className="font-mono text-[11px] text-graphite-500">no MITRE tags</span>
                            ) : (
                              r.mitre_techniques.map((technique) => (
                                <Badge key={technique} tone="signal">
                                  {technique}
                                </Badge>
                              ))
                            )}
                          </div>
                        </button>
                        <button
                          onClick={() => handleDelete(r.rule_id)}
                          className="shrink-0 rounded p-1.5 text-graphite-500 hover:bg-alert-500/10 hover:text-alert-400"
                          aria-label={`Delete ${r.title}`}
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </li>
                  );
                })}
              </ul>

              <div className="flex items-center justify-between border-t border-graphite-700 pt-3">
                <div className="font-mono text-[11px] text-graphite-500">
                  Showing {(page - 1) * pageSize + 1}-{Math.min(page * pageSize, rules.length)} of {rules.length}
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="secondary" onClick={() => setPage((current) => Math.max(1, current - 1))} disabled={page === 1} className="inline-flex items-center gap-1">
                    <ChevronLeft size={14} />Prev
                  </Button>
                  <Button variant="secondary" onClick={() => setPage((current) => Math.min(totalPages, current + 1))} disabled={page >= totalPages} className="inline-flex items-center gap-1">
                    Next<ChevronRight size={14} />
                  </Button>
                </div>
              </div>
            </>
          )}
        </div>
      </Panel>

      <Panel title="Rule detail" eyebrow={selectedRuleDetail ? selectedRuleDetail.rule_id.slice(0, 8) : "Select a rule"}>
        {!selectedRuleDetail ? (
          <EmptyState title="Choose a rule to inspect it" hint="The details panel shows the latest version, author, and testing results." />
        ) : (
          <div className="space-y-3">
            <div>
              <div className="text-sm text-graphite-100">{selectedRuleDetail.title}</div>
              <div className="mt-1 flex flex-wrap gap-2">
                <Badge>{selectedRuleDetail.status}</Badge>
                {selectedRuleDetail.versions?.[0]?.author ? <Badge tone="amber">{selectedRuleDetail.versions[0].author}</Badge> : null}
              </div>
            </div>
            <div className="rounded-md border border-graphite-700 bg-graphite-950 p-3 font-mono text-[11px] text-graphite-400">
              <div className="text-graphite-300">Latest version: {selectedRuleDetail.versions?.[selectedRuleDetail.versions.length - 1]?.version_number ?? "-"}</div>
              <div className="mt-2 whitespace-pre-wrap break-all">{selectedRuleDetail.versions?.[selectedRuleDetail.versions.length - 1]?.yaml_content ?? "No YAML available."}</div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button onClick={() => handleTestRule(selectedRuleDetail.rule_id)} className="inline-flex items-center gap-2">
                <PlayCircle size={14} />Test rule
              </Button>
              <Button variant="secondary" onClick={() => handleSuggestTechniques(selectedRuleDetail.rule_id)} className="inline-flex items-center gap-2">
                <Sparkles size={14} />Suggest techniques
              </Button>
            </div>
            {testResult && (
              <div className="rounded-md border border-graphite-700 bg-graphite-950 p-3 text-sm text-graphite-300">
                <div className="font-medium text-graphite-100">Test outcome</div>
                <div className="mt-1 font-mono text-[11px] text-graphite-400">
                  Matched: {testResult.matched_techniques.join(", ") || "none"}
                </div>
              </div>
            )}
            {suggestionResult && (
              <div className="rounded-md border border-graphite-700 bg-graphite-950 p-3 text-sm text-graphite-300">
                <div className="font-medium text-graphite-100">Suggestions</div>
                <div className="mt-1 flex flex-wrap gap-2">
                  {(suggestionResult.suggestions || []).length === 0 ? (
                    <span className="font-mono text-[11px] text-graphite-400">No suggestions available.</span>
                  ) : (
                    suggestionResult.suggestions.map((technique) => <Badge key={technique} tone="amber">{technique}</Badge>)
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </Panel>
    </div>
  );
}
