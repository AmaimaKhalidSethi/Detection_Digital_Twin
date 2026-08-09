# Detection Digital Twin

A SOC / detection-engineering platform that imports Sigma detection rules, real MITRE
ATT&CK data, and telemetry, runs attack simulations safely against a digital twin instead
of production, measures ATT&CK coverage and blind spots, and continuously compares the
twin's verified coverage against a real, live Wazuh production instance to surface
configuration and coverage drift.

## How this maps to the assignment

| Requirement | Status |
|---|---|
| Import detection rules | Done — Sigma rules, versioned, soft-deletable |
| Import MITRE ATT&CK mappings | Done — real STIX data via `mitreattack-python` |
| Import telemetry / log schemas | Partial — synthetic + Atomic Red Team telemetry generation is done; ingestion of real raw Sysmon/auditd log text is written (`app/telemetry/parsers/`) but not yet wired to an endpoint |
| Run attack simulations safely, outside production | Done |
| Measure ATT&CK coverage, find blind spots | Done — `/coverage` |
| Continuously compare production detections against the twin, detect drift | Done — `/drift/production` + `/drift/production/history`, against a real Wazuh lab |
| Estimate detection effectiveness (false-positive rate) | Partial — `generate_benign_baseline()` exists but has no endpoint yet |

## Architecture

- **Backend**: FastAPI + SQLite (SQLAlchemy). A hand-written Sigma condition-tree matcher
  (`app/detection_engine/matcher.py`) built on top of pySigma's parser — not a
  `wazuh-logtest` wrapper.
- **Frontend**: React + Vite, Tailwind, Monaco-based rule editor.
- **Authentication**: short-lived JWT sessions in HttpOnly cookies, with a
  controlled local user bootstrap and CSRF protection for browser writes.

### Core detection engine
- Custom `RuleMatcher` evaluates Sigma AND/OR/NOT condition trees, wildcards, and
  keyword-only leaves against normalized events, and reports *why* a rule matched or
  failed.
- Currently supports `logsource.product` in `{windows, linux}` and
  `logsource.category` in `{process_creation, registry_event, network_connection}`. Rules
  outside that scope are not evaluated.

### MITRE ATT&CK
Real STIX data via `mitreattack-python` (`app/mitre/attack_data_loader.py`) — not a
hardcoded technique list.

### Telemetry / simulation
- Hand-written synthetic simulations for select techniques
  (`app/telemetry/generators/synthetic_log_generator.py`).
- Atomic Red Team-backed simulation for everything else vendored locally under
  `vendor/atomic-red-team/atomics/` (git-pulled via `scripts/vendor_atomics.py`; not
  committed to the repo — see Setup).
- **Known limitation**: Atomic-derived events currently carry only a generic
  process-creation shape (`Image`, `CommandLine`, `ProcessId`) with the `Image` path fixed
  per executor (`cmd.exe` / `powershell.exe` / `/bin/sh` / `/bin/bash`) regardless of the
  actual technique. Rules that match broadly on the executor path alone, without checking
  `CommandLine` content, will false-positive-confirm against unrelated techniques that
  happen to share an executor. Network-based rules (`logsource.category:
  network_connection`) are especially affected, since Atomic-derived events don't yet
  populate connection fields like `DestinationIp`. Full-matrix evaluation results should be
  spot-checked against this before being reported as fully independent confirmations.

### Coverage & drift
- `/coverage`: for every ATT&CK technique, whether any active rule targets it and whether
  that specific (rule, technique) pair has been brute-force-verified against real telemetry
  for that technique.
- `/drift` (twin-internal regression): flags a rule whose result against a *given
  technique's* telemetry changed between two evaluation runs.
- `/drift/production` (**twin vs. real Wazuh**): pulls the twin's verified coverage and
  the real, currently-active technique coverage from a live Wazuh manager (via
  `app/wazuh/client.py`, REST API on port 55000), and returns three sets: covered by both,
  verified by the twin but absent from production (real blind spots), and active in
  production but not yet verified by the twin. Every call is also persisted with a
  timestamp, queryable via `/drift/production/history`, satisfying the "continuously
  compares" requirement.
- `POST /jobs/full-matrix-evaluation`: background job that runs every active rule against
  every simulatable technique and records brute-force confirmations. This is what actually
  grows `/coverage`'s verified count — run it after importing new rules or adding new
  simulations.

### Wazuh integration
`app/wazuh/client.py` — a failure-tolerant client for the Wazuh manager REST API (JWT auth,
token refresh, never raises). Currently used for `GET /rules` (active technique coverage).
Wazuh's `PUT /logtest` endpoint (feed a raw log line, get back Wazuh's real rule verdict +
MITRE mapping) is confirmed reachable and documented but not yet wired in — natural next
step for true event-level behavioral drift, not just rule-configuration drift.

## Setup

### Prerequisites
- Python 3.13, Node.js, a running Wazuh manager (v4.14.x tested) reachable on port 55000.

### Backend
```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
pip install mitreattack-python
```
> `mitreattack-python` is a hard dependency of `app/mitre/attack_data_loader.py` but is
> not yet listed in `requirements.txt` — add it manually until that's fixed.

Vendor the external rule/technique corpora (one-time, pulls from GitHub):
```powershell
python scripts\vendor_atomics.py
python scripts\vendor_sigmahq_rules.py
```

Create `backend\.env` (gitignored):

WAZUH_BASE_URL=https://<your-wazuh-manager-ip>:55000
WAZUH_USERNAME=wazuh
WAZUH_PASSWORD=<your-password>

An LLM API key (`GROQ_API_KEY` / `GEMINI_API_KEY` / `OPENAI_API_KEY`) is optional — without
one, AI-suggested technique mappings degrade to a no-op stub rather than failing.

Authentication is enabled by default. Add the settings from `backend/.env.example` to the
existing `backend/.env` without removing Wazuh or AI settings, then create the first internal
administrator from a terminal (the password is prompted for and never printed):
```powershell
python -m scripts.create_user admin@example.internal --role admin
```
For HTTPS deployments set `AUTH_COOKIE_SECURE=true`. `JWT_SECRET` must be a unique random
value of at least 32 characters and must remain server-side.

Run the API:
```powershell
uvicorn app.main:app --reload
```

### Frontend
```powershell
cd frontend
npm install
npm run dev
```

### Tests
```powershell
cd backend
python -m pytest
```
71 tests total, all passing once the vendored corpora and `mitreattack-python` are present.

## Detection quality notes

An earlier full-matrix evaluation run produced 130 "verified" techniques, of which 194 of
230 underlying confirmations traced back to two leftover test/placeholder rules with overly
broad conditions (`Image|endswith: '\powershell.exe'` with no other constraint). These were
identified, archived, and the run repeated, producing a real, defensible count of 34
verified techniques. This is disclosed here deliberately: the false-positive-confirmation
class of bug (broad rule conditions matching coincidentally across unrelated techniques'
synthetic telemetry) is a real, general risk for any brute-force verification system and
worth checking for periodically, not just once.
