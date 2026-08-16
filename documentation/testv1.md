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



