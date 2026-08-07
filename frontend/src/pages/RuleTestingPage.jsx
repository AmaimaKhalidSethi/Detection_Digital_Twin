import { useEffect, useState } from "react";
import { PlayCircle, Search, ShieldCheck, Sparkles } from "lucide-react";
import { api } from "../lib/api";
import { Badge, Button, EmptyState, ErrorNote, Panel } from "../components/ui";

export default function RuleTestingPage() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedRuleId, setSelectedRuleId] = useState(null);
  const [selectedRuleDetail, setSelectedRuleDetail] = useState(null);
  const [testResult, setTestResult] = useState(null);
  const [suggestionResult, setSuggestionResult] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const refresh = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await api.searchRules(searchQuery);
        setRules(data);
        if (selectedRuleId && !data.some((rule) => rule.rule_id === selectedRuleId)) {
          setSelectedRuleId(null);
          setSelectedRuleDetail(null);
        }
      } catch (requestError) {
        setError(requestError.message);
      } finally {
        setLoading(false);
      }
    };

    refresh();
  }, [searchQuery]);

  const selectRule = async (ruleId) => {
    setSelectedRuleId(ruleId);
    setSelectedRuleDetail(null);
    setTestResult(null);
    setSuggestionResult(null);
    setError(null);
    try {
      setSelectedRuleDetail(await api.getRule(ruleId));
    } catch (requestError) {
      setError(requestError.message);
    }
  };

  const handleTestRule = async () => {
    if (!selectedRuleDetail) return;
    setError(null);
    try {
      setTestResult(await api.testRule(selectedRuleDetail.rule_id));
    } catch (requestError) {
      setError(requestError.message);
    }
  };

  const handleSuggestTechniques = async () => {
    if (!selectedRuleDetail) return;
    setError(null);
    try {
      setSuggestionResult(await api.suggestTechniques(selectedRuleDetail.rule_id));
    } catch (requestError) {
      setError(requestError.message);
    }
  };

  const latestVersion = (selectedRuleDetail?.versions || []).at(-1);
  const techniques = latestVersion?.mitre_techniques || [];

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1.2fr_0.8fr]">
      <Panel title="Rule picker" eyebrow={`${rules.length} rule${rules.length === 1 ? "" : "s"}`} className="lg:self-start">
        <div className="space-y-3">
          <label className="flex items-center gap-2 rounded-md border border-bg-800 bg-bg-950 px-3 py-2 text-sm text-slate-300">
            <Search size={14} className="text-slate-500" />
            <input
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              placeholder="Search by title or description"
              className="w-full bg-transparent outline-none"
            />
          </label>

          {loading ? (
            <p className="text-sm text-slate-500">Loading...</p>
          ) : rules.length === 0 ? (
            <EmptyState title="No matching rules" hint="Try a different search term." />
          ) : (
            <ul className="divide-y divide-bg-800">
              {rules.map((rule) => (
                <li key={rule.rule_id} className="py-2">
                  <button
                    type="button"
                    onClick={() => selectRule(rule.rule_id)}
                    className={`w-full rounded-md px-2 py-2 text-left ${selectedRuleId === rule.rule_id ? "bg-cyan-500/10" : "hover:bg-bg-800"}`}
                  >
                    <div className="flex items-center gap-2">
                      <ShieldCheck size={14} className="shrink-0 text-cyan-400" />
                      <span className="truncate text-sm text-slate-300">{rule.title}</span>
                      <Badge>{rule.status}</Badge>
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1.5 pl-6">
                      {(rule.mitre_techniques || []).map((technique) => (
                        <Badge key={technique} tone="signal">{technique}</Badge>
                      ))}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </Panel>

      <Panel title="Rule testing" eyebrow={selectedRuleDetail ? selectedRuleDetail.rule_id.slice(0, 8) : "Select a rule"}>
        {!selectedRuleDetail ? (
          <EmptyState title="Choose a rule to test it" hint="Select a rule from the picker to run tests or request MITRE suggestions." />
        ) : (
          <div className="space-y-3">
            <div>
              <div className="text-sm text-slate-300">{selectedRuleDetail.title}</div>
              <div className="mt-1 flex flex-wrap gap-2">
                <Badge>{selectedRuleDetail.status}</Badge>
                {techniques.map((technique) => <Badge key={technique} tone="signal">{technique}</Badge>)}
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button onClick={handleTestRule} className="inline-flex items-center gap-2">
                <PlayCircle size={14} />Test rule
              </Button>
              <Button variant="secondary" onClick={handleSuggestTechniques} className="inline-flex items-center gap-2">
                <Sparkles size={14} />Suggest techniques
              </Button>
            </div>
            <ErrorNote message={error} />
            {testResult && (
              <div className="rounded-md border border-bg-800 bg-bg-950 p-3 text-sm text-slate-300">
                <div className="font-medium text-slate-300">Test outcome</div>
                <div className="mt-1 font-mono text-[11px] text-slate-500">
                  Matched: {testResult.matched_techniques.join(", ") || "none"}
                </div>
              </div>
            )}
            {suggestionResult && (
              <div className="rounded-md border border-bg-800 bg-bg-950 p-3 text-sm text-slate-300">
                <div className="font-medium text-slate-300">Suggestions</div>
                <div className="mt-1 flex flex-wrap gap-2">
                  {(suggestionResult.suggestions || []).length === 0 ? (
                    <span className="font-mono text-[11px] text-slate-500">No suggestions available.</span>
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
