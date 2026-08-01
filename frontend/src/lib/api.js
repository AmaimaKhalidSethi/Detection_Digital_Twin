const BASE_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8123";

async function request(path, options = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const isJson = res.headers.get("content-type")?.includes("application/json");
  const body = isJson ? await res.json() : null;
  if (!res.ok) {
    const message =
      body?.detail?.errors?.join("; ") ||
      (typeof body?.detail === "string" ? body.detail : null) ||
      `Request failed (${res.status})`;
    throw new Error(message);
  }
  return body;
}

export const api = {
  listRules: () => request("/rules"),
  getRule: (ruleId) => request(`/rules/${ruleId}`),
  uploadRule: (yamlContent) =>
    request("/rules", { method: "POST", body: JSON.stringify({ yaml_content: yamlContent }) }),
  updateRule: (ruleId, yamlContent) =>
    request(`/rules/${ruleId}`, { method: "PUT", body: JSON.stringify({ yaml_content: yamlContent }) }),
  deleteRule: (ruleId) => request(`/rules/${ruleId}`, { method: "DELETE" }),

  listTechniques: () => request("/mitre/techniques"),
  listSimulatableTechniques: () => request("/simulator/techniques"),
  runSimulation: (techniqueId) =>
    request("/simulations", { method: "POST", body: JSON.stringify({ technique_id: techniqueId }) }),
  listSimulations: () => request("/simulations"),

  evaluate: (simulationRunId) =>
    request("/evaluate", { method: "POST", body: JSON.stringify({ simulation_run_id: simulationRunId }) }),

  listAlerts: () => request("/alerts"),
  coverage: () => request("/coverage"),
  drift: () => request("/drift"),
};
