# Detection Digital Twin — Controlled Evolution Plan

## Baseline
- Current backend test baseline: 53 passed, 1 warning.
- Current implementation already provides rule ingestion, simulation, evaluation, coverage, drift, and Wazuh integration.
- The safest evolution path is additive: introduce environment-state models and validation workflow around the existing engine rather than replacing it.

## 1. Existing architecture
- Backend entrypoint: [backend/app/main.py](../backend/app/main.py)
  - FastAPI app with rule upload/validation, simulation, evaluation, alerts, coverage, drift, and health endpoints.
  - Uses background jobs for full-matrix evaluation.
- Persistence: [backend/app/models/db.py](../backend/app/models/db.py)
  - SQLAlchemy models for detection rules, rule versions, technique maps, simulations, generated logs, detection results, drift records, jobs, and production drift snapshots.
- Wazuh integration: [backend/app/wazuh/client.py](../backend/app/wazuh/client.py)
  - Small failure-tolerant client with auth, manager info lookup, and enabled-rule technique extraction.
- MITRE and telemetry: existing simulation and coverage pipeline remain the core prediction layer.
- Frontend: [frontend/src/App.jsx](../frontend/src/App.jsx) and [frontend/src/lib/api.js](../frontend/src/lib/api.js)
  - React tabs for overview, rules, testing, simulation, alerts, coverage, and drift.

## 2. Existing database schema
Current tables and ORM objects:
- users
- detection_rules
- rule_versions
- rule_technique_map
- jobs
- production_drift_snapshots
- simulation_runs
- generated_logs
- detection_results
- drift_report

Existing schema is already working and should remain intact. The upgrade path should be additive and compatible with the current SQLite-backed setup.

## 3. Existing Wazuh functionality
The current Wazuh client already supports:
- authentication via environment variables and token caching
- manager info lookup
- enabled-rule inventory with MITRE technique extraction

Important constraints:
- The client is intentionally tolerant of missing/invalid configuration.
- It does not assume that Wazuh is reachable.
- It should remain the single integration entrypoint for environment synchronization.

## 4. Existing API endpoints
Current API surface in [backend/app/main.py](../backend/app/main.py):
- /mitre/techniques
- /simulator/techniques
- /simulator/coverage-gaps
- /rules/validate
- /rules
- /rules/{rule_id}
- /rules/search
- /simulations
- /jobs/full-matrix-evaluation
- /jobs/{job_id}
- /rules/{rule_id}/suggest-techniques
- /rules/{rule_id}/test
- /evaluate
- /alerts
- /alerts/{alert_id}/explain
- /coverage
- /coverage/navigator-layer
- /drift/production
- /drift/production/history
- /drift
- /health

These routes should remain available and unchanged where possible.

## 5. Existing tests
Current coverage includes:
- rule evaluation
- AI layer behavior
- atomic/synthetic simulation flow
- matcher coverage
- drift/coverage regression tests

The protected baseline is the existing 53-pass suite.

## 6. Files that must change
Planned implementation touches:
- [backend/app/models/db.py](../backend/app/models/db.py)
  - Add new tables for environment, endpoint, telemetry source, detection platform, environment snapshot, validation run, and detection gap.
- [backend/app/wazuh/client.py](../backend/app/wazuh/client.py)
  - Extend with environment synchronization helpers while preserving existing methods.
- [backend/app/main.py](../backend/app/main.py)
  - Add environment CRUD and sync endpoints.
  - Add snapshot and validation-run endpoints.
  - Add expected-vs-observed comparison and gap tracking.
- [frontend/src/lib/api.js](../frontend/src/lib/api.js)
  - Add new client methods for environment and validation data.
- [frontend/src/App.jsx](../frontend/src/App.jsx)
  - Add an Environment tab or section.
- New UI components/pages under [frontend/src/pages](../frontend/src/pages)
  - Environment overview and validation results views.

## 7. Files that should NOT change
These should remain intact to preserve current functionality:
- Existing detection engine modules under [backend/app/detection_engine](../backend/app/detection_engine)
- Existing simulator modules under [backend/app/telemetry](../backend/app/telemetry)
- Existing MITRE loader and data files under [backend/app/mitre](../backend/app/mitre)
- Existing tests under [backend/tests](../backend/tests)
- The core rule validation and evaluator behavior
- The current SQLite database strategy

## 8. New database models required
Additive models only:
- Environment
  - id, name, description, status, created_at, last_sync_at
- Endpoint
  - id, environment_id, hostname, operating_system, agent_id, agent_status, last_seen, metadata
- TelemetrySource
  - id, endpoint_id, source_type, status, version, metadata
- DetectionPlatform
  - id, environment_id, platform_type, version, manager_url, status, last_sync_at
- EnvironmentSnapshot
  - id, environment_id, snapshot_timestamp, metadata
- ValidationRun
  - id, environment_id, endpoint_id, technique_id, simulation_id, expected_detection, observed_detection, status, started_at, completed_at, evidence
- DetectionGap
  - id, environment_id, technique_id, validation_run_id, severity, reason, recommendation, status, created_at, resolved_at

These models should be additive and nullable where appropriate so existing data remains intact.

## 9. New API endpoints required
Recommended endpoints:
- GET /environments
- POST /environments
- GET /environments/{environment_id}
- POST /environment/sync
- GET /environment/snapshots
- GET /validation-runs
- POST /validation-runs
- GET /detection-gaps
- POST /detection-gaps/{gap_id}/resolve

The synchronization endpoint should be tolerant of partial Wazuh availability and should never fail the whole twin update because one optional component is unavailable.

## 10. New frontend components required
Minimal UI additions:
- Environment summary card
- Endpoint list view
- Detection platform and telemetry source status panel
- Validation results list
- Drift/gap summary cards
- Optional snapshot history view

The frontend should remain an extension of the current experience rather than a redesign.

## 11. Migration strategy
1. Keep the current database and tables intact.
2. Use additive SQLAlchemy models and safe initialization logic in [backend/app/models/db.py](../backend/app/models/db.py).
3. Add compatibility migrations for new tables only when needed.
4. Avoid destructive resets or database recreation on startup.
5. Preserve existing records by using create-all plus guarded column-alteration logic where necessary.

## 12. Testing strategy
Implement tests in the following order:
- Environment model basics
  - create environment
  - create endpoint
  - endpoint belongs to environment
- Synchronization behavior
  - Wazuh unavailable
  - Wazuh partially available
  - successful sync
  - snapshot creation
- Validation logic
  - expected detect / observed detect
  - expected detect / observed no-detect
  - unavailable environment
  - malformed Wazuh response
- Drift and gaps
  - rule drift
  - environment drift
  - behavioral drift
  - detection gap creation and resolution
- Security
  - no arbitrary command execution
  - credentials never persisted in plaintext

After each phase, run the backend suite and confirm that the existing 53-pass baseline remains intact.

## 13. Risks
- Wazuh API shape may differ across deployments, so the sync layer must be defensive.
- The current project uses SQLite, so the schema should remain simple and additive.
- Over-modeling the environment could make the prototype feel like an enterprise SOC platform; the scope should stay intentionally small.
- Real endpoint validation should remain safely constrained to predefined Atomic Red Team tests and should not expose arbitrary execution.
- The current simulation pipeline is valuable and should remain the core prediction layer rather than being replaced.

## Implementation order
1. Repository audit and baseline verification (done)
2. Add environment, endpoint, telemetry source, and detection platform models
3. Add environment persistence and API routes
4. Add Wazuh synchronization and environment snapshot support
5. Add validation run and expected-vs-observed comparison
6. Add behavioral drift and detection gap workflow
7. Add frontend visualization for environment and validation status
8. Add regression tests and documentation
