# Detection Digital Twin — Test Log

## Project
- FastAPI backend + React/Vite frontend
- Testing Sigma detection rules against a real Wazuh server
- Branch: main

## Environment Setup
- Backend runs on: http://127.0.0.1:8123
- Frontend runs on: http://127.0.0.1:5173
- Must use 127.0.0.1 (not localhost) for cookie-based auth to work correctly

## Features Tested & Working
- Login / authentication
- Wazuh environment sync
- Rule upload
- Simulation (attack technique simulation + synthetic telemetry generation)
- Detection evaluation
- Coverage report
- Alerts list
- Drift report (production vs twin coverage) — CONFIRMED WORKING (see Bugs Fixed below)
- Drift delete — CONFIRMED WORKING (see Bugs Fixed below)

## Features Added (Working)
- **Alert delete**: DELETE /alerts/{id} endpoint + trash icon with confirmation in UI — tested and working

## Bugs Fixed
- **Rule duplicate bug (FIXED)**: Editing a rule was creating a duplicate entry instead of updating in place in Rule Library.
  - Root cause: `rebuild_rule_search_index()` in `backend/app/ai/rule_search.py` was joining `DetectionRule` with ALL `RuleVersion` rows (not just the latest), so a rule with 2 versions produced 2 separate search index rows — making it appear twice in the Rule Library / search results.
  - Fix: Changed the query to loop over each `DetectionRule` and only index its `latest_version`, instead of joining across all versions.
  - Verified: created a fresh rule, edited it (v1 → v2), and confirmed only 1 entry now shows in Rule Library after the fix (previously showed 2).

- **Drift not detecting rule version changes (FIXED)**: Editing a rule's detection logic, re-simulating, and re-evaluating still showed "No drift detected" even after the duplicate-rule fix.
  - Root cause: `build_drift_report()` in `backend/app/detection_engine/analysis.py` grouped evaluation history by `(rule_version_id, technique_id)`. Since editing a rule creates a new `version_id`, v1 and v2 were treated as unrelated rules, so there were never 2+ entries in the same group to compare.
  - Fix:
    - `backend/app/main.py` — `/drift` endpoint now also fetches and includes `rule_id` (via the RuleVersion's `rule_id`) in the history records, not just `rule_version_id`.
    - `backend/app/detection_engine/analysis.py` — `build_drift_report()` now groups by `rule_id` instead of `rule_version_id`, so v1 and v2 of the same rule are correctly compared against each other.
  - Verified end-to-end: created "Lab Host Activity Rule" (v1, matched T1059.003 telemetry via `host|contains: 'LAB-WIN10'`), edited it to target a nonexistent host (v2, correctly did not match on re-simulation), and confirmed Drift page showed: "Lab Host Activity Rule — was firing, now not firing — Technique: T1059.003 — changed".

- **Drift delete button not working (FIXED)**: Clicking "Delete" on a drift entry returned "Failed to delete drift: Not Found".
  - Root cause: The frontend (`api.js` → `deleteDrift`) called `DELETE /drift/{detectionResultId}`, but no matching backend endpoint existed — only a GET `/drift` route was implemented.
  - Fix: Added a new `DELETE /drift/{detection_result_id}` endpoint in `backend/app/main.py` (mirrors the existing `/alerts/{alert_id}` delete endpoint) that deletes the corresponding `DetectionResult` row.
  - Verified: Delete button on Drift page now works correctly.
