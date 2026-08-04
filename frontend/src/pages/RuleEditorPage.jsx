import { useEffect, useState } from "react";
import Editor from "@monaco-editor/react";
import { api } from "../lib/api";
import { Panel, Badge, Button, ErrorNote } from "../components/ui";
import { PLACEHOLDER_YAML } from "./RulesPage";

export default function RuleEditorPage({ ruleId = null, initialYaml = "", onSaved, onCancel }) {
  const [yamlText, setYamlText] = useState(initialYaml || PLACEHOLDER_YAML);
  const [validationState, setValidationState] = useState({
    status: "pending",
    valid: false,
    errors: [],
    techniques: [],
  });
  const [saveError, setSaveError] = useState(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setYamlText(initialYaml || PLACEHOLDER_YAML);
  }, [initialYaml]);

  useEffect(() => {
    setValidationState({ status: "pending", valid: false, errors: [], techniques: [] });

    const timer = window.setTimeout(async () => {
      try {
        const result = await api.validateRule(yamlText);
        setValidationState({
          status: "done",
          valid: result.valid,
          errors: result.errors || [],
          techniques: result.mitre_techniques || [],
        });
      } catch (error) {
        setValidationState({
          status: "done",
          valid: false,
          errors: [error.message],
          techniques: [],
        });
      }
    }, 500);

    return () => window.clearTimeout(timer);
  }, [yamlText]);

  const handleSave = async () => {
    if (validationState.status === "pending" || !validationState.valid) {
      return;
    }

    setSaving(true);
    setSaveError(null);
    try {
      if (ruleId) {
        await api.updateRule(ruleId, yamlText);
      } else {
        await api.uploadRule(yamlText);
      }
      onSaved?.();
    } catch (error) {
      setSaveError(error.message);
    } finally {
      setSaving(false);
    }
  };

  const isSaveDisabled = saving || validationState.status === "pending" || !validationState.valid;

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-graphite-700 bg-graphite-950 p-2">
        <Editor
          height="480px"
          language="yaml"
          theme="vs-dark"
          defaultValue={initialYaml || PLACEHOLDER_YAML}
          value={yamlText}
          onChange={(value) => setYamlText(value ?? "")}
          options={{
            tabSize: 4,
            insertSpaces: true,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
          }}
        />
      </div>

      <Panel title="Validation" eyebrow={ruleId ? "Edit rule" : "New rule"}>
        {validationState.status === "pending" ? (
          <div className="font-mono text-[11px] text-graphite-400">Validating YAML…</div>
        ) : validationState.valid ? (
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone="signal">Valid Sigma rule</Badge>
            {validationState.techniques.length === 0 ? (
              <span className="font-mono text-[11px] text-graphite-500">No MITRE techniques detected.</span>
            ) : (
              validationState.techniques.map((technique) => (
                <Badge key={technique}>{technique}</Badge>
              ))
            )}
          </div>
        ) : (
          <div className="space-y-2">
            {validationState.errors.map((error) => (
              <ErrorNote key={error} message={error} />
            ))}
          </div>
        )}
      </Panel>

      {saveError ? <ErrorNote message={saveError} /> : null}

      <div className="flex items-center justify-end gap-2">
        <Button type="button" variant="secondary" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="button" onClick={handleSave} disabled={isSaveDisabled}>
          {saving ? "Saving..." : "Save"}
        </Button>
      </div>
    </div>
  );
}
