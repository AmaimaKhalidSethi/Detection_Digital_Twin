const BASE_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8123";

function readCookie(name) {
  if (typeof document === "undefined") return null;
  const prefix = `${encodeURIComponent(name)}=`;
  const cookie = document.cookie.split("; ").find((value) => value.startsWith(prefix));
  return cookie ? decodeURIComponent(cookie.slice(prefix.length)) : null;
}

// The session itself stays in an HttpOnly cookie.  This non-secret token is
// deliberately readable by the app for the double-submit CSRF check, and must
// be restored after a browser refresh so authenticated writes continue to work.
let csrfToken = readCookie("ddt_csrf");
let unauthorizedHandler = null;

export function setCsrfToken(token) {
  csrfToken = token || null;
}

export function setUnauthorizedHandler(handler) {
  unauthorizedHandler = handler;
}

async function request(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (!options.headers?.Authorization && !["GET", "HEAD", "OPTIONS"].includes(method) && csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }
  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    credentials: "include",
    headers,
  });
  const isJson = res.headers.get("content-type")?.includes("application/json");
  const body = isJson ? await res.json() : null;
  if (!res.ok) {
    if (res.status === 401) {
      csrfToken = null;
      unauthorizedHandler?.();
    }
    const message =
      body?.detail?.errors?.join("; ") ||
      (typeof body?.detail === "string" ? body.detail : null) ||
      `Request failed (${res.status})`;
    throw new Error(message);
  }
  return body;
}

export const api = {
  login: (username, password) => request("/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }),
  me: () => request("/auth/me"),
  logout: () => request("/auth/logout", { method: "POST" }),
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

  listEnvironments: () => request("/environments"),
  createEnvironment: (body) => request("/environments", { method: "POST", body: JSON.stringify(body) }),
  listEnvironmentEndpoints: (environmentId) => request(`/environments/${environmentId}/endpoints`),
  syncEnvironment: () => request("/environment/sync", { method: "POST" }),
  listEnvironmentSnapshots: () => request("/environment/snapshots"),

  createValidationRun: (body) => request("/validation-runs", { method: "POST", body: JSON.stringify(body) }),
  listValidationRuns: (environmentId) => request(`/validation-runs${environmentId ? `?environment_id=${environmentId}` : ""}`),
  listDetectionGaps: (environmentId) => request(`/detection-gaps${environmentId ? `?environment_id=${environmentId}` : ""}`),
};
