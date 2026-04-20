# Best Practices Doctor

Local-first static analysis desktop app for Laravel/PHP and React/Inertia projects.

Best Practices Doctor (BPD) combines:

- Python FastAPI backend (`backend/`)
- React + Vite frontend (`frontend/`)
- Tauri desktop shell (`tauri/`)
- MCP bridge for agent workflows (`bpdoctor-mcp/`)

## Current Snapshot (April 20, 2026)

- Runtime rules (manual registry): `245`
- Rule families:
  - Laravel: `106`
  - React: `119`
  - PHP: `20`
- API routes in `backend/api/routes.py`: `46`
- Ruleset profiles in `backend/rulesets/`:
  - `startup`: 194 total / 141 enabled
  - `balanced`: 207 total / 205 enabled
  - `strict`: 246 total / 246 enabled

## Key Capabilities

- AST-first analysis (Tree-sitter)
- Stage-based pipeline:
  - `detect_project -> build_facts -> run_rules -> scoring -> reporting`
- Context-aware calibration (Laravel + React context matrices)
- Fingerprint-stable findings and baseline diffing
- Auto-fix suggestions with strategy/risk metadata
- Triage scoring (`impact x risk x effort x context`)
- Stage artifact cache for faster rescans
- SSE live progress stream (`/api/scan/{job_id}/events`)
- MCP tools for scan loops, finding navigation, explain/suggest/group workflows

## Project Layout

```text
Best-Practices-Doctor/
|-- backend/
|   |-- api/routes.py
|   |-- analysis/
|   |-- core/
|   |   |-- pipeline/
|   |   `-- rule_engine.py
|   |-- rules/
|   |   |-- laravel/
|   |   |-- react/
|   |   `-- php/
|   |-- rulesets/
|   |   |-- startup.yaml
|   |   |-- balanced.yaml
|   |   |-- strict.yaml
|   |   |-- laravel_context_matrix.yaml
|   |   `-- react_context_matrix.yaml
|   `-- schemas/
|-- frontend/
|-- tauri/
|-- bpdoctor-mcp/
`-- docs/
```

## Local Development

### 1. Start everything (recommended)

```powershell
./dev.ps1
```

### 2. Or run services manually

Backend:

```powershell
cd backend
python main.py
```

Frontend:

```powershell
cd frontend
npm run dev
```

MCP bridge:

```powershell
cd bpdoctor-mcp
npm run dev
```

## Running Tests

Backend:

```powershell
cd backend
python -m pytest -q
```

Frontend:

```powershell
cd frontend
npm run test
```

Frontend build check:

```powershell
cd frontend
npm run build
```

## API Notes

- Health: `GET /api/health`
- Start scan: `POST /api/scan`
- Scan status/report: `GET /api/scan/{job_id}`
- Live progress (SSE): `GET /api/scan/{job_id}/events`
- Rule profiles: `GET /api/rulesets`, `PUT /api/rulesets/active`
- Finding intelligence:
  - `GET /api/scan/{job_id}/findings/{fingerprint}/explain`
  - `GET /api/scan/{job_id}/findings/{fingerprint}/suggest-fix`
  - `GET /api/scan/{job_id}/triage`
  - `POST /api/scan/{job_id}/findings/{fingerprint}/status`
  - `POST /api/findings/{fingerprint}/feedback`
  - `GET /api/feedback/summary`

## Contributor Docs

- Full architecture/context reference: [docs/PROJECT_CONTEXT_FULL.md](docs/PROJECT_CONTEXT_FULL.md)
- Laravel profile-aware calibration notes: [docs/laravel-profile-aware-analysis.md](docs/laravel-profile-aware-analysis.md)
- Laravel context matrix guide: [docs/laravel-context-matrix.md](docs/laravel-context-matrix.md)

## License

MIT. See [LICENSE](LICENSE).
