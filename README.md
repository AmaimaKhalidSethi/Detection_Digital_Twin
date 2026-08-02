# Detection Digital Twin

Detection Digital Twin is a local SOC detection engineering prototype for testing Sigma rules against simulated ATT&CK telemetry. It combines a FastAPI backend, a React/Vite frontend, and a lightweight evaluation pipeline so you can upload rules, run simulations, inspect coverage, and review AI-assisted explanations.

## What the project does

- Validates and stores Sigma rules with rule-version tracking
- Evaluates rules against normalized telemetry using a real pySigma condition-tree-based matcher
- Simulates ATT&CK-style attack techniques and runs rule evaluations against them
- Builds coverage and drift reports scoped per rule and per technique
- Supports AI-assisted technique suggestions and alert explanations through provider-agnostic backends such as Groq, Gemini, or OpenAI
- Provides a browser-based UI for rules, simulations, alerts, and coverage

## Current status

The implementation is a working MVP and has been verified locally:

- Backend test suite: 29 passed
- Frontend production build: successful

## Tech stack

- Backend: FastAPI, SQLAlchemy, pySigma, pytest
- Frontend: React, Vite, Tailwind CSS, Recharts, lucide-react
- Data: SQLite for local development

## Quick start

### 1. Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

On macOS/Linux, use:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If you want to use the optional AI features, create a local environment file from the repo root before starting the backend:

```powershell
Copy-Item .env.example .env
```

```bash
cp .env.example .env
```

Then edit the new `.env` file and add one or more API keys for Groq, Gemini, or OpenAI. The backend loads these values automatically through `python-dotenv`.

Start the API:

```powershell
uvicorn app.main:app --reload --port 8123
```

The API will be available at:

- Swagger UI: http://127.0.0.1:8123/docs
- OpenAPI schema: http://127.0.0.1:8123/openapi.json

Run the backend tests:

```powershell
pytest tests/ -v
```

### 2. Frontend

```powershell
cd frontend
npm install
npm run dev
```
Then open http://127.0.0.1:5173.

The frontend expects the backend at http://127.0.0.1:8123 by default. You can override that with a frontend environment file if needed:

```env
VITE_API_URL=http://127.0.0.1:8123
```

### 3. Optional AI features

AI suggestions and alert explanations are optional. If you want to enable them, add one of the following keys to the local `.env` file created above:

```env
GROQ_API_KEY=your-groq-key
# or
GEMINI_API_KEY=your-gemini-key
# or
OPENAI_API_KEY=your-openai-key
```

If no key is configured, the AI features remain disabled and the app continues to work normally.

## Project structure

```text
backend/
  app/
    ai/
    detection_engine/
    models/
    telemetry/
    mitre/
  rules/
  tests/
frontend/
  src/
    components/
    pages/
    lib/
```

## Notes and limitations

- The ATT&CK dataset in the project is a curated local subset for the MVP and is not a full STIX export.
- SQLite is used for local development and demo scenarios.
- Authentication and production-grade deployment controls are not implemented yet.
- The starter rule set is intentionally small; expanding it with more Sigma rules and simulations will improve coverage breadth.

## Documentation

The original product requirements and system design notes are in the documentation folder, including the SRS/SDD document referenced by the earlier prototype.
