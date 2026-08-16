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
- Drift report (production vs twin coverage)

## Features Added (Working)
- **Alert delete**: DELETE /alerts/{id} endpoint + trash icon with confirmation in UI — tested and working
- **Drift CSV export**: GET /drift/production/export endpoint (StreamingResponse CSV) + "Export report (CSV)" button on Drift page — needs final re-verification (earlier had a blank-page issue from a leftover BASE_URL import, since reverted)

## Environment Tab — Reviewed
- "Sync with Wazuh" pulls live agents/rules/active techniques from Wazuh and stores a snapshot
- "Create environment" allows a separate twin environment (not needed unless multiple labs required)
- Validation run (Wazuh Logtest) — recent runs are showing status **UNAVAILABLE**, needs investigation
- Detection gaps panel — currently shows "No gaps found"
- Environment snapshots — history of each sync, shows Agent/Rule/Technique counts

## Known Issues (Open)
1. **Rule editing bug**: Editing an existing rule creates a duplicate instead of updating in place — under investigation (backend endpoints, RuleEditor.jsx, RuleLibrary.jsx, and api.js all reviewed and appear correct on their own; root cause not yet found)
2. **Suggest techniques**: "Suggest techniques" button on Rule Testing page returns "No suggestions available" — not working
3. **Validation run status**: showing "UNAVAILABLE" in recent runs — needs investigation
4. **reportlab crash**: Backend crashed earlier with `ModuleNotFoundError: No module named 'reportlab'` (caused by opening a terminal without activating .venv) — fix in progress: activate .venv, then `pip install reportlab`, restart uvicorn

