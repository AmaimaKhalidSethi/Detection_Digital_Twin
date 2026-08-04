import { useEffect, useMemo, useState } from "react";
import { ArchiveIcon, ChevronLeft, ChevronRight, Pencil, Search, ShieldCheck } from "lucide-react";
import { api } from "../lib/api";
import { Badge, Button, EmptyState, ErrorNote, Panel } from "../components/ui";
import RuleEditorPage from "./RuleEditorPage";

const PAGE_SIZE = 6;

export default function RulesLibraryPage() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [editor, setEditor] = useState(null);
  const [error, setError] = useState(null);

  const refresh = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.searchRules(searchQuery, {
        status: statusFilter === "all" ? "" : statusFilter,
      });
      setRules(data);
    } catch (requestError) {
      setError(requestError.message);
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

  const totalPages = Math.max(1, Math.ceil(rules.length / PAGE_SIZE));
  const pagedRules = useMemo(
    () => rules.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE),
    [rules, page],
  );

  const handleEdit = async (ruleId) => {
    setError(null);
    try {
      const detail = await api.getRule(ruleId);
      const latestVersion = (detail.versions || []).reduce(
        (latest, version) => (!latest || version.version_number > latest.version_number ? version : latest),
        null,
      );
      setEditor({ ruleId, initialYaml: latestVersion?.yaml_content ?? "" });
    } catch (requestError) {
      setError(requestError.message);
    }
  };

  const handleArchive = async (ruleId) => {
    if (!window.confirm("Archive this rule? It will be hidden but its version history is kept.")) {
      return;
    }

    setError(null);
    try {
      await api.deleteRule(ruleId);
      await refresh();
    } catch (requestError) {
      setError(requestError.message);
    }
  };

  if (editor) {
    return (
      <RuleEditorPage
        ruleId={editor.ruleId}
        initialYaml={editor.initialYaml}
        onSaved={async () => {
          await refresh();
          setEditor(null);
        }}
        onCancel={() => setEditor(null)}
      />
    );
  }

  return (
    <Panel
      title="Rule library"
      eyebrow={`${rules.length} rule${rules.length === 1 ? "" : "s"}`}
      actions={<Button onClick={() => setEditor({ ruleId: null, initialYaml: null })}>New rule</Button>}
    >
      <div className="space-y-3">
        <div className="flex flex-col gap-2 sm:flex-row">
          <label className="flex items-center gap-2 rounded-md border border-graphite-700 bg-graphite-950 px-3 py-2 text-sm text-graphite-300">
            <Search size={14} className="text-graphite-500" />
            <input
              value={searchQuery}
              onChange={(event) => setSearchQuery(event.target.value)}
              placeholder="Search by title or description"
              className="w-full bg-transparent outline-none"
            />
          </label>
          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
            className="rounded-md border border-graphite-700 bg-graphite-950 px-3 py-2 text-sm text-graphite-200"
          >
            <option value="all">All statuses</option>
            <option value="active">Active</option>
            <option value="draft">Draft</option>
            <option value="test">Test</option>
          </select>
        </div>

        <ErrorNote message={error} />

        {loading ? (
          <p className="text-sm text-graphite-400">Loading...</p>
        ) : rules.length === 0 ? (
          <EmptyState title="No matching rules" hint="Try a different search term or create a new rule." />
        ) : (
          <>
            <ul className="divide-y divide-graphite-700">
              {pagedRules.map((rule) => (
                <li key={rule.rule_id} className="py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <ShieldCheck size={14} className="shrink-0 text-signal-400" />
                        <span className="truncate text-sm text-graphite-100">{rule.title}</span>
                        <Badge>{rule.status}</Badge>
                        <Badge>v{rule.version_number}</Badge>
                      </div>
                      <div className="mt-1 flex flex-wrap gap-1.5">
                        {(rule.mitre_techniques || []).length === 0 ? (
                          <span className="font-mono text-[11px] text-graphite-500">no MITRE tags</span>
                        ) : (
                          rule.mitre_techniques.map((technique) => (
                            <Badge key={technique} tone="signal">{technique}</Badge>
                          ))
                        )}
                      </div>
                    </div>
                    <div className="flex shrink-0 items-center gap-1">
                      <button
                        type="button"
                        onClick={() => handleEdit(rule.rule_id)}
                        className="rounded p-1.5 text-graphite-500 hover:bg-signal-500/10 hover:text-signal-400"
                        aria-label={`Edit ${rule.title}`}
                      >
                        <Pencil size={14} />
                      </button>
                      <button
                        type="button"
                        onClick={() => handleArchive(rule.rule_id)}
                        className="rounded p-1.5 text-graphite-500 hover:bg-alert-500/10 hover:text-alert-400"
                        aria-label={`Archive ${rule.title}`}
                      >
                        <ArchiveIcon size={14} />
                      </button>
                    </div>
                  </div>
                </li>
              ))}
            </ul>

            <div className="flex items-center justify-between border-t border-graphite-700 pt-3">
              <div className="font-mono text-[11px] text-graphite-500">
                Showing {(page - 1) * PAGE_SIZE + 1}-{Math.min(page * PAGE_SIZE, rules.length)} of {rules.length}
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
  );
}
