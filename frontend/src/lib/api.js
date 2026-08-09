const BASE_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8123";
let authToken = localStorage.getItem("ddt_token") || null;

async function request(path, options = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
    },
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
  login: (username, password) =>
    request("/login", { method: "POST", body: JSON.stringify({ username, password }) }).then((res) => {
      authToken = res.token;
      localStorage.setItem("ddt_token", res.token);
      localStorage.setItem("ddt_username", res.username);
      return res;
    }),
  signup: (username, password) =>
    request("/signup", { method: "POST", body: JSON.stringify({ username, password }) }).then((res) => {
      authToken = res.token;
      localStorage.setItem("ddt_token", res.token);
      localStorage.setItem("ddt_username", res.username);
      return res;
    }),
  logout: () => {
    authToken = null;
    localStorage.removeItem("ddt_token");
    localStorage.removeItem("ddt_username");
  },
  isLoggedIn: () => !!authToken,

  listRules: () => request("/rules"),
  searchRules: (q = "", filters = {}) => {
    const params = new URLSearchParams();
    if (q) params.set("q", q);
    if (filters.tactic) params.set("tactic", filters.tactic);
    if (filters.platform) params.set("platform", filters.platform);
    if (filters.status) params.set("status", filters.status);
    const suffix = params.toString() ? `?${params.toString()}` : "";
    return request(`/rules/search${suffix}`);
  },
  getRule: (ruleId) => request(`/rules/${ruleId}`),
  uploadRule: (yamlContent) =>
    request("/rules", { method: "POST", body: JSON.stringify({ yaml_content: yamlContent }) }),
  validateRule: (yamlContent) =>
    request("/rules/validate", { method: "POST", body: JSON.stringify({ yaml_content: yamlContent }) }),
  updateRule: (ruleId, yamlContent) =>
    request(`/rules/${ruleId}`, { method: "PUT", body: JSON.stringify({ yaml_content: yamlContent }) }),
  deleteRule: (ruleId) => request(`/rules/${ruleId}`, { method: "DELETE" }),
  testRule: (ruleId) => request(`/rules/${ruleId}/test`, { method: "POST" }),
  suggestTechniques: (ruleId) => request(`/rules/${ruleId}/suggest-techniques`, { method: "POST" }),

  listTechniques: () => request("/mitre/techniques"),
  listSimulatableTechniques: () => request("/simulator/techniques"),
  runSimulation: (techniqueId) =>
    request("/simulations", { method: "POST", body: JSON.stringify({ technique_id: techniqueId }) }),
  listSimulations: () => request("/simulations"),

  evaluate: (simulationRunId) =>
    request("/evaluate", { method: "POST", body: JSON.stringify({ simulation_run_id: simulationRunId }) }),

  listAlerts: () => request("/alerts"),
  explainAlert: (alertId) => request(`/alerts/${alertId}/explain`),
  coverage: () => request("/coverage"),
  navigatorLayer: () => request("/coverage/navigator-layer"),
  drift: () => request("/drift"),
  productionDrift: () => request("/drift/production"),
  productionDriftHistory: () => request("/drift/production/history"),
};