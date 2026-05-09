# Best Practices Doctor

Local-first static analysis desktop app for Laravel/PHP and React/Inertia projects.

Best Practices Doctor (BPD) combines:

- Python FastAPI backend (`backend/`)
- React + Vite frontend (`frontend/`)
- Tauri desktop shell (`tauri/`)
- MCP bridge for agent workflows (`bpdoctor-mcp/`)

## Current Snapshot (May 10, 2026)

- Runtime rules (manual registry): `325`
- Rule families:
  - Laravel: `145`
  - React: `143`
  - PHP: `30`
  - DevOps: `8`
- API routes in `backend/api/routes.py`: `59`
- Ruleset profiles in `backend/rulesets/`:
  - `startup`: 239 total / 127 enabled
  - `balanced`: 269 total / 244 enabled
  - `strict`: 333 total / 333 enabled

## Key Capabilities

- AST-first analysis (Tree-sitter)
- Stage-based pipeline:
  - `detect_project -> build_facts -> run_rules -> scoring -> reporting`
- Context-aware calibration (Laravel + React context matrices)
- Fingerprint-stable findings and baseline diffing
- Auto-fix suggestions with strategy/risk metadata
- Triage scoring (`impact x risk x effort x context`)
- Stage artifact cache for faster rescans
- Project Intelligence Map (structure tree + focused graph + dependency inspector)
- Deterministic Project Explainer (endpoint flows, dependency index, execution traces)
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

### Quick Start

From the repository root:

```powershell
npm start
```

That command performs a quick setup check, installs missing Node/Python dependencies,
starts the Tauri desktop app, starts the FastAPI backend, and starts the MCP bridge.

For a first-time machine, you can run setup explicitly:

```powershell
npm run setup
npm start
```

You can also double-click `setup.cmd` once, then `start.cmd` on Windows.

### Useful Commands

```powershell
npm start          # start the full local app
npm run dev:clean  # free common ports first, then start
npm run web        # browser-only mode, no Tauri/Rust desktop shell
npm run web:clean  # browser-only mode after freeing ports
npm run desktop    # Tauri dev without rebuilding the Python sidecar
npm run build:desktop
```

### Prerequisites For A New PC

- Node.js 20 LTS or newer
- Python 3.11 or newer
- Rust/Cargo from `rustup` if you want to build or run the Tauri desktop shell

If Rust is not installed yet, use `npm run web` for browser-only development.

`npm run setup` creates `backend/.venv`, installs backend dependencies there,
and installs dependencies for `frontend/`, `tauri/`, and `bpdoctor-mcp/`.

### Manual Service Commands

Backend:

```powershell
cd backend
.\.venv\Scripts\python.exe main.py
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
- Project intelligence:
  - `GET /api/scan/{job_id}/project-map`
  - `GET /api/project-map` (latest completed scan alias)
  - `GET /api/scan/{job_id}/project-explainer`
  - `GET /api/project-explainer` (latest completed scan alias)

## Contributor Docs

- Full architecture/context reference: [docs/PROJECT_CONTEXT_FULL.md](docs/PROJECT_CONTEXT_FULL.md)
- Laravel profile-aware calibration notes: [docs/laravel-profile-aware-analysis.md](docs/laravel-profile-aware-analysis.md)
- Laravel context matrix guide: [docs/laravel-context-matrix.md](docs/laravel-context-matrix.md)
- Scanner false-positive catalog: [docs/SCANNER_FALSE_POSITIVES.md](docs/SCANNER_FALSE_POSITIVES.md)

## License

MIT. See [LICENSE](LICENSE).
