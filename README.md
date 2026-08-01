# Detection Digital Twin — SOC Digital Twin Platform

A working MVP of the project described in `documentation/Detection_Digital_Twin_SRS_SDD.docx`.

## What's real here

- **Detection engine** (`backend/app/detection_engine/matcher.py`) evaluates
  real [pySigma](https://github.com/SigmaHQ/pySigma)-parsed Sigma rules
  directly against normalized event dicts. pySigma itself is a parser/
  converter, not an evaluator, so this module is the missing piece, built
  directly on pySigma's real condition-tree object model.
- **Starter rule** (`backend/rules/`) is an unmodified rule pulled from the
  public [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) repository.
- **Telemetry schema** mirrors real Sysmon Event ID 1 and Linux auditd
  SYSCALL/EXECVE field names, so community Sigma rules work unmodified.
- **14 automated tests pass**, including an integration test that uploads
  the real SigmaHQ rule, simulates its technique, and confirms it fires
  with zero false positives on a benign baseline.
- **React + Tailwind frontend** (Vite) — Rules / Simulate / Alerts /
  Coverage pages, verified running end-to-end in a real browser.

## Running it

### Backend
```bash
cd backend
python3 -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8123
```
API docs at http://127.0.0.1:8123/docs (FastAPI's auto-generated Swagger UI).

Run the test suite:
```bash
pytest tests/ -v
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Open http://127.0.0.1:5173. The frontend expects the backend at
`http://127.0.0.1:8123` (override with a `.env` file: `VITE_API_URL=...`).

## Known limitations (be upfront about these in your report/demo)

- MITRE ATT&CK data (`backend/app/mitre/data.py`) is a small curated table
  matching the 8 simulated techniques, not the full ATT&CK STIX bundle.
  Swapping in `mitreattack-python` for the complete dataset is a documented
  stretch goal (Section 8 of the SDD) and doesn't require changing any
  other module.
- SQLite is used for simplicity; the SDD's Postgres/Docker deployment path
  (Section 9) is not wired up here.
- Auth (FR-12) is not implemented — there's no login; all endpoints are
  open. Fine for a local demo, not for anything else.
- The starter rule library ships with one real SigmaHQ rule; the SDD's
  target of 15-25 curated techniques (Section 14) means adding more real
  Sigma rules + matching simulations to `synthetic_log_generator.py`.
- Two real bugs were caught and fixed during end-to-end browser testing
  (see git-history-style notes in `detection_engine/analysis.py` and
  `main.py`'s `/coverage` endpoint): both coverage and drift detection
  originally compared a rule's *latest* evaluation regardless of which
  technique was simulated, which could make a working rule look broken
  just because you'd tested it against an unrelated technique afterward.
  Both are now scoped per-technique and covered by regression tests.

## Project layout

See `documentation/Detection_Digital_Twin_SRS_SDD.docx` Section 11 for the
full intended directory structure and Section 13 for the module-by-module
code plan this implementation follows.
